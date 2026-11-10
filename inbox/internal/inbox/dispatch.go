package inbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	dispatchContract = "jackboy.dispatch/v2"
	dispatchPath     = "/api/public/jackboy/dispatch"
	callbackContract = "jackboy.dispatch-callback/v2"
	callbackPath     = "/api/public/omni/callback"
	dispatchMaxBody  = 8192
)

var (
	dispatchClientRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	dispatchTimeRE   = regexp.MustCompile(`^[0-9]{10}$`)
	dispatchNonceRE  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	dispatchHexRE    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// DispatchConfig is independent of the legacy bearer/handshake and worker gates.
type DispatchConfig struct {
	Enabled        bool
	ClientID       string
	Secret         string
	CallbackURL    string
	CallbackClient string
	CallbackSecret string
}

type dispatchScope struct {
	OwnerID       string `json:"ownerId"`
	ProjectID     string `json:"projectId"`
	GrantID       string `json:"grantId"`
	JobID         string `json:"jobId"`
	Repo          string `json:"repo"`
	Kind          string `json:"kind"`
	PayloadDigest string `json:"payloadDigest"`
}

type dispatchJob struct {
	Scope  dispatchScope `json:"scope"`
	Status string        `json:"status"`
}

type dispatchState struct {
	Nonces map[string]bool        `json:"nonces"`
	Jobs   map[string]dispatchJob `json:"jobs"`
}

// DispatchServer stores receipts separately from the executable legacy queue.
// Neither submit nor cancel can wake or authorize a worker.
type DispatchServer struct {
	config  DispatchConfig
	dir     string
	allowed map[string]bool
	http    *http.Client
}

func NewDispatchServer(dataDir string, config DispatchConfig, allowed map[string]bool) (*DispatchServer, error) {
	if config.Enabled {
		u, err := url.Parse(config.CallbackURL)
		if !dispatchClientRE.MatchString(config.ClientID) || len(config.Secret) < 32 ||
			!dispatchClientRE.MatchString(config.CallbackClient) || len(config.CallbackSecret) < 32 ||
			err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
			u.Path != callbackPath || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, fmt.Errorf("invalid scoped dispatch credentials or HTTPS callback configuration")
		}
	}
	dir := filepath.Join(dataDir, "dispatch-v2")
	if err := prepareDataDir(dir); err != nil {
		return nil, fmt.Errorf("dispatch storage: %w", err)
	}
	repos := make(map[string]bool, len(allowed))
	for repo, enabled := range allowed {
		repos[repo] = enabled
	}
	return &DispatchServer{
		config: config, dir: dir, allowed: repos,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (s *DispatchServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.audit("dispatch_received", "", "", 0); err != nil {
		log.Print("dispatch audit unavailable")
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	code, body, nonce := s.handle(r)
	if err := s.audit("dispatch_result", "", "", code); err != nil {
		log.Print("dispatch result audit unavailable")
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if code == http.StatusOK || code == http.StatusAccepted {
		w.Header().Set("X-Jackboy-Proof", HMACHex(s.config.Secret,
			fmt.Sprintf("%s\nresponse\n%s\n%d\n%s", dispatchContract, nonce, code, body)))
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func dispatchError(code int, reason string) (int, []byte, string) {
	body, _ := json.Marshal(map[string]string{"error": reason})
	return code, body, ""
}

func (s *DispatchServer) handle(r *http.Request) (int, []byte, string) {
	if !s.config.Enabled {
		return dispatchError(http.StatusServiceUnavailable, "dispatch_disabled")
	}
	if r.Method != http.MethodPost || r.URL.Path != dispatchPath || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return dispatchError(http.StatusBadRequest, "invalid_endpoint")
	}
	client := r.Header.Get("X-Jackboy-Client")
	ts := r.Header.Get("X-Jackboy-Timestamp")
	nonce := r.Header.Get("X-Jackboy-Nonce")
	signature := r.Header.Get("X-Jackboy-Signature")
	if client != s.config.ClientID || !dispatchTimeRE.MatchString(ts) || !dispatchNonceRE.MatchString(nonce) {
		return dispatchError(http.StatusUnauthorized, "authentication_failed")
	}
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(seconds, 0)).Abs() > time.Minute {
		return dispatchError(http.StatusUnauthorized, "authentication_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, dispatchMaxBody+1))
	if err != nil || len(raw) > dispatchMaxBody {
		return dispatchError(http.StatusBadRequest, "invalid_body")
	}
	expected := HMACHex(s.config.Secret, strings.Join([]string{dispatchContract, "POST", dispatchPath, client, ts, nonce, string(raw)}, "\n"))
	if !dispatchHexRE.MatchString(signature) || subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return dispatchError(http.StatusUnauthorized, "authentication_failed")
	}

	// Serialize across goroutines AND reopened stores/processes. The nonce is
	// synced before any state change, and callback ordering shares this lock.
	lock, err := s.lock("state.lock")
	if err != nil {
		return dispatchError(http.StatusServiceUnavailable, "storage_unavailable")
	}
	defer unlockDispatch(lock)
	state, err := s.readState()
	if err != nil {
		return dispatchError(http.StatusServiceUnavailable, "storage_unavailable")
	}
	if state.Nonces[nonce] {
		return dispatchError(http.StatusConflict, "nonce_replayed")
	}
	state.Nonces[nonce] = true
	if err := s.writeState(state); err != nil {
		return dispatchError(http.StatusServiceUnavailable, "storage_unavailable")
	}
	fields, err := strictDispatchObject(raw, "contract", "action", "ownerId", "projectId", "grantId", "jobId", "repo", "kind", "payloadDigest")
	if err != nil || fields["contract"] != dispatchContract {
		return dispatchError(http.StatusBadRequest, "invalid_request")
	}
	scope := dispatchScope{fields["ownerId"], fields["projectId"], fields["grantId"], fields["jobId"], fields["repo"], fields["kind"], fields["payloadDigest"]}
	action := fields["action"]
	if !uuidRe.MatchString(scope.OwnerID) || !uuidRe.MatchString(scope.ProjectID) ||
		!uuidRe.MatchString(scope.GrantID) || !uuidRe.MatchString(scope.JobID) ||
		!repoRe.MatchString(scope.Repo) || len(scope.Repo) > 200 ||
		(scope.Kind != "build" && scope.Kind != "test") || !dispatchHexRE.MatchString(scope.PayloadDigest) ||
		(action != "submit" && action != "status" && action != "cancel") {
		return dispatchError(http.StatusBadRequest, "invalid_request")
	}
	if !s.allowed[scope.Repo] {
		return dispatchError(http.StatusForbidden, "repository_not_allowed")
	}
	job, exists := state.Jobs[scope.JobID]
	if exists && job.Scope != scope {
		return dispatchError(http.StatusConflict, "scope_conflict")
	}
	if !exists {
		if action != "submit" {
			return dispatchError(http.StatusNotFound, "job_not_found")
		}
		job = dispatchJob{Scope: scope, Status: "quarantined"}
	}
	if action == "cancel" {
		job.Status = "cancelled"
	}
	state.Jobs[scope.JobID] = job
	if err := s.writeState(state); err != nil {
		return dispatchError(http.StatusServiceUnavailable, "storage_unavailable")
	}
	if err := s.audit("dispatch_"+action, job.Scope.JobID, job.Status, 0); err != nil {
		return dispatchError(http.StatusServiceUnavailable, "audit_unavailable")
	}
	if action != "status" {
		if err := s.callback(r.Context(), job); err != nil {
			log.Print("dispatch callback failed; receipt retained for an idempotent retry")
			return dispatchError(http.StatusServiceUnavailable, "callback_unavailable")
		}
	}
	code := http.StatusOK
	if action == "submit" {
		code = http.StatusAccepted
	}
	body, _ := json.Marshal(struct {
		Contract     string `json:"contract"`
		RequestNonce string `json:"requestNonce"`
		Job          struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"job"`
	}{dispatchContract, nonce, struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}{scope.JobID, job.Status}})
	return code, body, nonce
}

// Unlike encoding/json's struct decoder, reject duplicate, case-folded and
// unknown keys as well as trailing data, invalid UTF-8 and non-string values.
func strictDispatchObject(raw []byte, keys ...string) (map[string]string, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("object required")
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	result := make(map[string]string, len(keys))
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, fmt.Errorf("unknown field")
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate field")
		}
		token, err = dec.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return nil, fmt.Errorf("string required")
		}
		result[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF || len(result) != len(keys) {
		return nil, fmt.Errorf("incomplete or trailing data")
	}
	return result, nil
}

func (s *DispatchServer) callback(ctx context.Context, job dispatchJob) error {
	if err := s.audit("callback_attempt", job.Scope.JobID, job.Status, 0); err != nil {
		return err
	}
	err := s.sendCallback(ctx, job)
	code := http.StatusOK
	if err != nil {
		code = http.StatusBadGateway
	}
	if auditErr := s.audit("callback_result", job.Scope.JobID, job.Status, code); auditErr != nil {
		return auditErr
	}
	return err
}

func (s *DispatchServer) sendCallback(ctx context.Context, job dispatchJob) error {
	body, err := json.Marshal(struct {
		Contract      string `json:"contract"`
		OwnerID       string `json:"ownerId"`
		ProjectID     string `json:"projectId"`
		GrantID       string `json:"grantId"`
		JobID         string `json:"jobId"`
		Repo          string `json:"repo"`
		PayloadDigest string `json:"payloadDigest"`
		Status        string `json:"status"`
	}{callbackContract, job.Scope.OwnerID, job.Scope.ProjectID, job.Scope.GrantID,
		job.Scope.JobID, job.Scope.Repo, job.Scope.PayloadDigest, job.Status})
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce, ts := hex.EncodeToString(random[:]), strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Omni-Contract", callbackContract)
	req.Header.Set("X-Omni-Client", s.config.CallbackClient)
	req.Header.Set("X-Omni-Timestamp", ts)
	req.Header.Set("X-Omni-Nonce", nonce)
	req.Header.Set("X-Omni-Signature", HMACHex(s.config.CallbackSecret,
		strings.Join([]string{callbackContract, "POST", callbackPath, s.config.CallbackClient, ts, nonce, string(body)}, "\n")))
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("callback transport unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, dispatchMaxBody+1))
	if err != nil || len(raw) > dispatchMaxBody || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("callback response unavailable")
	}
	proof := HMACHex(s.config.CallbackSecret, strings.Join([]string{callbackContract, "response", nonce, "200", string(raw)}, "\n"))
	if subtle.ConstantTimeCompare([]byte(resp.Header.Get("X-Omni-Proof")), []byte(proof)) != 1 {
		return fmt.Errorf("callback proof invalid")
	}
	ack, err := strictDispatchObject(raw, "contract", "requestNonce", "status")
	if err != nil || ack["contract"] != callbackContract || ack["requestNonce"] != nonce || ack["status"] != job.Status {
		return fmt.Errorf("callback acknowledgement invalid")
	}
	return nil
}

func (s *DispatchServer) lock(name string) (*os.File, error) {
	f, err := s.privateFile(name, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlockDispatch(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func (s *DispatchServer) readState() (dispatchState, error) {
	var state dispatchState
	f, err := s.privateFile("state.json", os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return dispatchState{Nonces: map[string]bool{}, Jobs: map[string]dispatchJob{}}, nil
	}
	if err != nil {
		return state, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return state, err
	}
	if state.Nonces == nil || state.Jobs == nil {
		return state, fmt.Errorf("dispatch state incomplete")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return state, fmt.Errorf("dispatch state has trailing data")
	}
	for nonce, used := range state.Nonces {
		if !dispatchNonceRE.MatchString(nonce) || !used {
			return state, fmt.Errorf("invalid persisted dispatch nonce")
		}
	}
	for id, job := range state.Jobs {
		if id != job.Scope.JobID || (job.Status != "quarantined" && job.Status != "cancelled") {
			return state, fmt.Errorf("invalid dispatch receipt")
		}
	}
	return state, nil
}

func (s *DispatchServer) writeState(state dispatchState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	return s.syncDirectory()
}

func (s *DispatchServer) syncDirectory() error {
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *DispatchServer) audit(event, jobID, status string, code int) error {
	lock, err := s.lock("audit.lock")
	if err != nil {
		return err
	}
	defer unlockDispatch(lock)
	f, err := s.privateFile("audit.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(struct {
		Time   string `json:"time"`
		Event  string `json:"event"`
		JobID  string `json:"jobId,omitempty"`
		Status string `json:"status,omitempty"`
		HTTP   int    `json:"http,omitempty"`
	}{time.Now().UTC().Format(time.RFC3339Nano), event, jobID, status, code}); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return s.syncDirectory()
}

func (s *DispatchServer) privateFile(name string, flags int) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(s.dir, name), flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok ||
			uint64(stat.Uid) != uint64(os.Geteuid()) || stat.Nlink != 1 {
			err = fmt.Errorf("dispatch file must be private, service-owned and regular")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

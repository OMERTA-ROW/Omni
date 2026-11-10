package inbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	dispatchV3Contract = "jackboy.dispatch/v3"
	callbackV3Contract = "jackboy.dispatch-callback/v3"
	dispatchV3MaxBody  = 40960
)

type v3Result struct {
	Passed    bool   `json:"passed"`
	Summary   string `json:"summary"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
}

type v3Job struct {
	Scope     dispatchScope `json:"scope"`
	Payload   string        `json:"payload"`
	ExpiresAt int64         `json:"expiresAt"`
	Status    string        `json:"status"`
	Result    *v3Result     `json:"result,omitempty"`
}

type v3Event struct {
	Job       v3Job `json:"job"`
	Attempt   int   `json:"attempt"`
	NextAt    int64 `json:"nextAt"`
	CreatedAt int64 `json:"createdAt"`
}

type v3DeadLetter struct {
	JobID     string `json:"jobId"`
	Status    string `json:"status"`
	Attempt   int    `json:"attempt"`
	CreatedAt int64  `json:"createdAt"`
	DeadAt    int64  `json:"deadAt"`
	Reason    string `json:"reason"`
}

type v3State struct {
	Nonces      map[string]dispatchNonceTime `json:"nonces"`
	Jobs        map[string]v3Job             `json:"jobs"`
	Outbox      []v3Event                    `json:"outbox"`
	DeadLetters []v3DeadLetter               `json:"deadLetters"`
}

// DispatchV3 never places jobs in the legacy queue. Its runner only claims
// digest-verified, unexpired v3 approvals and reuses Worker.Process unchanged.
type DispatchV3 struct {
	storage *DispatchServer
	worker  *Worker
	mu      sync.Mutex
	active  map[string]context.CancelFunc
}

func (s *DispatchServer) EnableV3(worker *Worker) error {
	storage := *s
	storage.v3 = nil
	storage.dir = filepath.Join(filepath.Dir(s.dir), "dispatch-v3")
	if err := prepareDataDir(storage.dir); err != nil {
		return err
	}
	s.v3 = &DispatchV3{storage: &storage, worker: worker, active: map[string]context.CancelFunc{}}
	return nil
}

// RunV3 starts only the separately gated v3 executor and durable callback sender.
func (s *DispatchServer) RunV3(ctx context.Context) {
	if s.v3 == nil || !s.config.Enabled {
		return
	}
	s.v3.run(ctx)
}

func payloadDigest(scope dispatchScope, payload string) string {
	keys := []string{"contract", "ownerId", "projectId", "grantId", "jobId", "repo", "kind", "instructions"}
	values := []string{"jackboy.dispatch-payload/v2", scope.OwnerID, scope.ProjectID, scope.GrantID,
		scope.JobID, scope.Repo, scope.Kind, payload}
	var body strings.Builder
	body.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString(stringifyString(key))
		body.WriteByte(':')
		body.WriteString(stringifyString(values[i]))
	}
	body.WriteByte('}')
	digest := sha256.Sum256([]byte(body.String()))
	return hex.EncodeToString(digest[:])
}

// JSON.stringify leaves HTML and U+2028/U+2029 unescaped; Go's JSON encoder does
// not. Serialize strings exactly, including literal backslash-u sequences.
func stringifyString(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func (v *DispatchV3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := v.storage
	w.Header().Set("Cache-Control", "no-store")
	code, body, nonce := v.handle(r)
	w.Header().Set("Content-Type", "application/json")
	if code == 200 || code == 202 {
		w.Header().Set("X-Jackboy-Proof", HMACHex(s.config.Secret,
			fmt.Sprintf("%s\nresponse\n%s\n%d\n%s", dispatchV3Contract, nonce, code, body)))
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (v *DispatchV3) handle(r *http.Request) (int, []byte, string) {
	s := v.storage
	if !s.config.Enabled {
		return dispatchError(503, "dispatch_disabled")
	}
	if r.Method != "POST" || r.URL.Path != dispatchPath || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return dispatchError(400, "invalid_endpoint")
	}
	client, ts, nonce := r.Header.Get("X-Jackboy-Client"), r.Header.Get("X-Jackboy-Timestamp"), r.Header.Get("X-Jackboy-Nonce")
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if client != s.config.ClientID || !dispatchTimeRE.MatchString(ts) || !dispatchNonceRE.MatchString(nonce) ||
		err != nil || time.Since(time.Unix(seconds, 0)).Abs() > time.Minute {
		return dispatchError(401, "authentication_failed")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, dispatchV3MaxBody+1))
	if err != nil || len(raw) > dispatchV3MaxBody {
		return dispatchError(400, "invalid_body")
	}
	signature := r.Header.Get("X-Jackboy-Signature")
	want := HMACHex(s.config.Secret, strings.Join([]string{dispatchV3Contract, "POST", dispatchPath, client, ts, nonce, string(raw)}, "\n"))
	if !dispatchHexRE.MatchString(signature) || subtle.ConstantTimeCompare([]byte(signature), []byte(want)) != 1 {
		return dispatchError(401, "authentication_failed")
	}
	if err := s.audit("v3_dispatch_received", "", "", 0); err != nil {
		log.Print("v3 audit unavailable")
		return dispatchError(503, "audit_unavailable")
	}
	code, body, responseNonce := v.authenticated(raw, nonce, seconds)
	if err := s.audit("v3_dispatch_result", "", "", code); err != nil {
		log.Print("v3 result audit unavailable")
		return dispatchError(503, "audit_unavailable")
	}
	return code, body, responseNonce
}

func v3Fields(raw []byte) (map[string]string, int64, error) {
	// Extract the one numeric field, then delegate exact string-key validation
	// to the same duplicate/unknown-key rejecting parser used by v2.
	if !utf8.Valid(raw) {
		return nil, 0, fmt.Errorf("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, 0, fmt.Errorf("object required")
	}
	fields := map[string]string{}
	var expires int64
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key := keyToken.(string)
		if _, exists := fields[key]; exists {
			return nil, 0, fmt.Errorf("duplicate field")
		}
		value, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		if key == "expiresAt" {
			number, ok := value.(json.Number)
			if !ok {
				return nil, 0, fmt.Errorf("integer expiry required")
			}
			expires, err = number.Int64()
			if err != nil {
				return nil, 0, err
			}
			fields[key] = number.String()
		} else {
			text, ok := value.(string)
			if !ok {
				return nil, 0, fmt.Errorf("string required")
			}
			fields[key] = text
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, fmt.Errorf("trailing data")
	}
	copyRaw, _ := json.Marshal(fields)
	keys := []string{"contract", "action", "ownerId", "projectId", "grantId", "jobId", "repo", "kind", "payloadDigest"}
	if fields["action"] == "submit" {
		keys = append(keys, "payload", "expiresAt")
	}
	checked, err := strictDispatchObject(copyRaw, keys...)
	return checked, expires, err
}

func (v *DispatchV3) authenticated(raw []byte, nonce string, timestamp int64) (int, []byte, string) {
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		return dispatchError(503, "storage_unavailable")
	}
	defer unlockDispatch(lock)
	state, err := v.read()
	if err != nil {
		return dispatchError(503, "storage_unavailable")
	}
	if _, used := state.Nonces[nonce]; used {
		return dispatchError(409, "nonce_replayed")
	}
	state.Nonces[nonce] = dispatchNonceTime(timestamp)
	if err := v.write(state); err != nil {
		return dispatchError(503, "storage_unavailable")
	}
	fields, expiry, err := v3Fields(raw)
	if err != nil || fields["contract"] != dispatchV3Contract {
		return dispatchError(400, "invalid_request")
	}
	scope := dispatchScope{fields["ownerId"], fields["projectId"], fields["grantId"], fields["jobId"], fields["repo"], fields["kind"], fields["payloadDigest"]}
	action := fields["action"]
	if !uuidRe.MatchString(scope.OwnerID) || !uuidRe.MatchString(scope.ProjectID) || !uuidRe.MatchString(scope.GrantID) ||
		!uuidRe.MatchString(scope.JobID) || !repoRe.MatchString(scope.Repo) || len(scope.Repo) > 200 ||
		(scope.Kind != "build" && scope.Kind != "test") || !dispatchHexRE.MatchString(scope.PayloadDigest) ||
		(action != "submit" && action != "status" && action != "cancel") {
		return dispatchError(400, "invalid_request")
	}
	if !v.storage.allowed[scope.Repo] {
		return dispatchError(403, "repository_not_allowed")
	}
	job, exists := state.Jobs[scope.JobID]
	if exists && job.Scope != scope {
		return dispatchError(409, "scope_conflict")
	}
	if action == "submit" {
		payload := fields["payload"]
		if len(payload) > 6*1024 || expiry <= time.Now().Unix() || expiry > time.Now().Add(30*time.Minute).Unix() ||
			payloadDigest(scope, payload) != scope.PayloadDigest {
			return dispatchError(400, "invalid_payload_or_expiry")
		}
		if exists && (job.Payload != payload || job.ExpiresAt != expiry) {
			return dispatchError(409, "scope_conflict")
		}
		if !exists {
			status := "quarantined"
			if v.worker.Enabled {
				status = "approved"
			}
			job = v3Job{Scope: scope, Payload: payload, ExpiresAt: expiry, Status: status}
			// There is no "approved" callback status: report running only at
			// claim, or quarantined when execution is disabled.
			if status == "quarantined" {
				state.Outbox = append(state.Outbox, newV3Event(job))
			}
		}
	} else if !exists {
		return dispatchError(404, "job_not_found")
	}
	if job.ExpiresAt <= time.Now().Unix() && (job.Status == "approved" || job.Status == "quarantined") {
		job.Status = "expired"
		state.Outbox = append(state.Outbox, newV3Event(job))
	}
	if action == "cancel" && (job.Status == "approved" || job.Status == "quarantined" || job.Status == "running") {
		job.Status = "cancelled"
		state.Outbox = append(state.Outbox, newV3Event(job))
	}
	state.Jobs[scope.JobID] = job
	if err := v.storage.audit("v3_dispatch_"+action, scope.JobID, job.Status, 0); err != nil {
		return dispatchError(503, "audit_unavailable")
	}
	if err := v.write(state); err != nil {
		return dispatchError(503, "storage_unavailable")
	}
	if job.Status == "cancelled" {
		v.mu.Lock()
		if cancel := v.active[scope.JobID]; cancel != nil {
			cancel()
		}
		v.mu.Unlock()
	}
	code := 200
	if action == "submit" {
		code = 202
	}
	body, _ := json.Marshal(map[string]any{"contract": dispatchV3Contract, "requestNonce": nonce,
		"job": map[string]string{"id": scope.JobID, "status": job.Status}})
	return code, body, nonce
}

func newV3Event(job v3Job) v3Event {
	job.Payload = ""
	return v3Event{Job: job, CreatedAt: time.Now().Unix()}
}

func (v *DispatchV3) read() (v3State, error) {
	var state v3State
	f, err := v.storage.privateFile("state.json", os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return v3State{Nonces: map[string]dispatchNonceTime{}, Jobs: map[string]v3Job{}, Outbox: []v3Event{}, DeadLetters: []v3DeadLetter{}}, nil
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
	if state.Nonces == nil || state.Jobs == nil || state.Outbox == nil {
		return state, fmt.Errorf("incomplete v3 state")
	}
	// Older v3 state has no dead-letter list or event creation timestamps.
	if state.DeadLetters == nil {
		state.DeadLetters = []v3DeadLetter{}
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return state, fmt.Errorf("trailing v3 state")
	}
	for id, job := range state.Jobs {
		if id != job.Scope.JobID || !uuidRe.MatchString(id) || !uuidRe.MatchString(job.Scope.OwnerID) ||
			!uuidRe.MatchString(job.Scope.ProjectID) || !uuidRe.MatchString(job.Scope.GrantID) ||
			!repoRe.MatchString(job.Scope.Repo) || len(job.Scope.Repo) > 200 ||
			(job.Scope.Kind != "build" && job.Scope.Kind != "test") || job.ExpiresAt <= 0 ||
			len(job.Payload) > 6144 || payloadDigest(job.Scope, job.Payload) != job.Scope.PayloadDigest ||
			!strings.Contains("|approved|quarantined|running|cancelled|completed|failed|expired|", "|"+job.Status+"|") {
			return state, fmt.Errorf("invalid v3 job")
		}
		if err := validateV3Result(job); err != nil {
			return state, err
		}
	}
	for nonce, ts := range state.Nonces {
		if !dispatchNonceRE.MatchString(nonce) || ts <= 0 {
			return state, fmt.Errorf("invalid v3 nonce")
		}
	}
	for _, event := range state.Outbox {
		job, exists := state.Jobs[event.Job.Scope.JobID]
		if !exists || event.Job.Scope != job.Scope || event.Job.Payload != "" || event.Job.ExpiresAt != job.ExpiresAt ||
			event.Attempt < 0 || event.Attempt > 8 || event.NextAt < 0 || event.CreatedAt < 0 ||
			!strings.Contains("|quarantined|cancelled|running|completed|failed|expired|", "|"+event.Job.Status+"|") {
			return state, fmt.Errorf("invalid v3 callback")
		}
		if err := validateV3Result(event.Job); err != nil {
			return state, err
		}
	}
	for _, event := range state.DeadLetters {
		if _, exists := state.Jobs[event.JobID]; !exists || event.Attempt < 0 || event.Attempt > 8 ||
			event.CreatedAt <= 0 || event.DeadAt < event.CreatedAt ||
			(event.Reason != "max_attempts" && event.Reason != "max_age") ||
			!strings.Contains("|quarantined|cancelled|running|completed|failed|expired|", "|"+event.Status+"|") {
			return state, fmt.Errorf("invalid v3 dead letter")
		}
	}
	return state, nil
}

func validateV3Result(job v3Job) error {
	terminal := job.Status == "completed" || job.Status == "failed"
	if terminal != (job.Result != nil) {
		return fmt.Errorf("invalid v3 result state")
	}
	if job.Result != nil && (len([]rune(job.Result.Summary)) > 500 || len(job.Result.Output) > 6144 ||
		!utf8.ValidString(job.Result.Output) || job.Result.Passed != (job.Status == "completed")) {
		return fmt.Errorf("invalid v3 result")
	}
	return nil
}

func (v *DispatchV3) write(state v3State) error {
	for nonce, ts := range state.Nonces {
		if int64(ts) < time.Now().Add(-5*time.Minute).Unix() {
			delete(state.Nonces, nonce)
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(v.storage.dir, ".state-")
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
	if err := os.Rename(f.Name(), filepath.Join(v.storage.dir, "state.json")); err != nil {
		return err
	}
	return v.storage.syncDirectory()
}

func (v *DispatchV3) run(ctx context.Context) {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	// One runner owns execution and recovery; other processes must not claim
	// jobs or overwrite running state. Request handlers still share state.lock.
	owner, err := v.storage.privateFile("runner.lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		log.Print("v3 runner storage unavailable")
		return
	}
	defer owner.Close()
	if err := syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Print("v3 runner already owned or unavailable")
		return
	}
	defer syscall.Flock(int(owner.Fd()), syscall.LOCK_UN)
	if err := v.recover(); err != nil {
		log.Print("v3 recovery failed; execution stopped")
		return
	}
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := v.deliver(ctx); err != nil {
				log.Print("v3 callback delivery pending")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stop(); <-callbackDone }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := v.execute(ctx); err != nil {
			log.Print("v3 execution storage/audit failure; runner stopped")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (v *DispatchV3) recover() error {
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		return err
	}
	defer unlockDispatch(lock)
	state, err := v.read()
	if err != nil {
		return err
	}
	changed := false
	for id, job := range state.Jobs {
		if job.Status == "running" || job.Status == "approved" {
			job.Status = "quarantined"
			state.Jobs[id] = job
			state.Outbox = append(state.Outbox, newV3Event(job))
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return v.write(state)
}

func (v *DispatchV3) execute(parent context.Context) error {
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		return err
	}
	state, err := v.read()
	if err != nil {
		unlockDispatch(lock)
		return err
	}
	var selected *v3Job
	changed := false
	for id, job := range state.Jobs {
		if job.Status != "approved" && job.Status != "quarantined" {
			continue
		}
		if job.ExpiresAt <= time.Now().Unix() {
			job.Status = "expired"
			state.Jobs[id] = job
			state.Outbox = append(state.Outbox, newV3Event(job))
			changed = true
			continue
		}
		if !v.storage.allowed[job.Scope.Repo] && job.Status == "approved" {
			job.Status = "quarantined"
			state.Jobs[id] = job
			state.Outbox = append(state.Outbox, newV3Event(job))
			changed = true
			continue
		}
		if job.Status == "approved" && v.worker.Enabled && selected == nil {
			job.Status = "running"
			state.Jobs[id] = job
			state.Outbox = append(state.Outbox, newV3Event(job))
			copy := job
			selected = &copy
			changed = true
		}
	}
	if !changed {
		unlockDispatch(lock)
		return nil
	}
	if err := v.storage.audit("v3_claim", "", "", 0); err != nil {
		unlockDispatch(lock)
		return err
	}
	if err := v.write(state); err != nil {
		unlockDispatch(lock)
		return err
	}
	if selected == nil {
		unlockDispatch(lock)
		return nil
	}
	job := *selected
	ctx, cancel := context.WithDeadline(parent, time.Unix(job.ExpiresAt, 0))
	v.mu.Lock()
	v.active[job.Scope.JobID] = cancel
	v.mu.Unlock()
	unlockDispatch(lock)
	// Observe cancellation written by another process, not only this handler.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l, err := v.storage.lock("state.lock")
				if err != nil {
					cancel()
					return
				}
				st, err := v.read()
				unlockDispatch(l)
				if err != nil || st.Jobs[job.Scope.JobID].Status != "running" {
					cancel()
					return
				}
			}
		}
	}()
	kind := "test"
	patch := ""
	if job.Scope.Kind == "build" {
		kind, patch = "code", job.Payload
	}
	result := v.worker.Process(ctx, &Job{ID: job.Scope.JobID, Kind: kind, Repo: job.Scope.Repo, Patch: patch})
	cancel()
	<-watchDone
	v.mu.Lock()
	delete(v.active, job.Scope.JobID)
	v.mu.Unlock()
	lock, err = v.storage.lock("state.lock")
	if err != nil {
		return err
	}
	defer unlockDispatch(lock)
	state, err = v.read()
	if err != nil {
		return err
	}
	current := state.Jobs[job.Scope.JobID]
	if current.Status != "running" {
		return nil
	}
	if parent.Err() != nil {
		current.Status = "quarantined"
	} else if current.ExpiresAt <= time.Now().Unix() {
		current.Status = "expired"
	} else {
		current.Status = "failed"
		if result.Status == "completed" && result.Tests != nil && result.Tests.Passed {
			current.Status = "completed"
		}
		current.Result = safeV3Result(result)
	}
	state.Jobs[job.Scope.JobID] = current
	state.Outbox = append(state.Outbox, newV3Event(current))
	if err := v.storage.audit("v3_result", current.Scope.JobID, current.Status, 0); err != nil {
		return err
	}
	return v.write(state)
}

var (
	secretAssignment = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:secret|token|password|api[_-]?key|authorization|database[_-]?url)[a-z0-9_]*)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	secretBearer     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]+`)
	secretToken      = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b`)
	secretPEM        = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)`)
	secretURL        = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+:[^/\s@]+@`)
	secretOpaque     = regexp.MustCompile(`\b(?:AKIA[A-Z0-9]{16}|[A-Za-z0-9_+/=-]{40,})\b`)
)

func redactV3(text string) string {
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if len(value) >= 8 && (strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") ||
			strings.Contains(upper, "KEY") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "DATABASE_URL")) {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
	}
	text = secretPEM.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	text = secretAssignment.ReplaceAllString(text, "${1}=[REDACTED]")
	text = secretBearer.ReplaceAllString(text, "Bearer [REDACTED]")
	text = secretToken.ReplaceAllString(text, "[REDACTED]")
	text = secretURL.ReplaceAllString(text, "${1}[REDACTED]@")
	return secretOpaque.ReplaceAllString(text, "[REDACTED]")
}

func safeV3Result(result Result) *v3Result {
	summary := strings.ToValidUTF8(redactV3(result.Summary), "\uFFFD")
	output := ""
	if result.Tests != nil {
		output = strings.ToValidUTF8(redactV3(result.Tests.Output), "\uFFFD")
	}
	truncated := len([]rune(summary)) > 500 || len(output) > 6144 || strings.Contains(output, "truncated at 64 KiB")
	if len([]rune(summary)) > 500 {
		summary = string([]rune(summary)[:500])
	}
	if len(output) > 6144 {
		output = output[:6144]
		for !utf8.ValidString(output) {
			output = output[:len(output)-1]
		}
	}
	return &v3Result{Passed: result.Status == "completed" && result.Tests != nil && result.Tests.Passed,
		Summary: summary, Output: output, Truncated: truncated}
}

func (v *DispatchV3) deliver(ctx context.Context) error {
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		return err
	}
	defer unlockDispatch(lock)
	state, err := v.read()
	if err != nil || len(state.Outbox) == 0 {
		return err
	}
	migrated := false
	for i := range state.Outbox {
		if state.Outbox[i].CreatedAt == 0 {
			state.Outbox[i].CreatedAt = time.Now().Unix()
			migrated = true
		}
	}
	if migrated {
		// Persist a conservative first-observed age once, never reset it on restart.
		if err := v.write(state); err != nil {
			return err
		}
	}
	blocked := map[string]bool{}
	var deliveryErr error
	for i := 0; i < len(state.Outbox); {
		if ctx.Err() != nil {
			return errors.Join(deliveryErr, ctx.Err())
		}
		event := state.Outbox[i]
		id := event.Job.Scope.JobID
		if blocked[id] {
			i++
			continue
		}
		reason := v3DeadLetterReason(event)
		if reason == "" && event.NextAt > time.Now().Unix() {
			blocked[id] = true
			i++
			continue
		}
		if reason == "" {
			if err := v.storage.audit("v3_callback_attempt", id, event.Job.Status, 0); err != nil {
				return err
			}
			sendErr := v.send(ctx, event.Job)
			event.Attempt++
			code := 200
			if sendErr != nil {
				code = 502
				event.NextAt = time.Now().Add(time.Second << event.Attempt).Unix()
				reason = v3DeadLetterReason(event)
				deliveryErr = errors.Join(deliveryErr, sendErr)
			}
			if err := v.storage.audit("v3_callback_result", id, event.Job.Status, code); err != nil {
				return err
			}
			if sendErr != nil && reason == "" {
				state.Outbox[i] = event
				blocked[id] = true
				if err := v.write(state); err != nil {
					return err
				}
				i++
				continue
			}
		}
		if reason != "" {
			if err := v.storage.audit("v3_callback_dead_letter_"+reason, id, event.Job.Status, 502); err != nil {
				return err
			}
			state.DeadLetters = append(state.DeadLetters, v3DeadLetter{
				JobID: id, Status: event.Job.Status, Attempt: event.Attempt,
				CreatedAt: event.CreatedAt, DeadAt: time.Now().Unix(), Reason: reason,
			})
		}
		state.Outbox = append(state.Outbox[:i], state.Outbox[i+1:]...)
		if err := v.write(state); err != nil {
			return err
		}
	}
	return deliveryErr
}

func v3DeadLetterReason(event v3Event) string {
	if event.Attempt >= 8 {
		return "max_attempts"
	}
	if time.Now().Unix()-event.CreatedAt >= int64((24*time.Hour)/time.Second) {
		return "max_age"
	}
	return ""
}

func (v *DispatchV3) send(ctx context.Context, job v3Job) error {
	type callbackBody struct {
		Contract      string    `json:"contract"`
		OwnerID       string    `json:"ownerId"`
		ProjectID     string    `json:"projectId"`
		GrantID       string    `json:"grantId"`
		JobID         string    `json:"jobId"`
		Repo          string    `json:"repo"`
		PayloadDigest string    `json:"payloadDigest"`
		Status        string    `json:"status"`
		Result        *v3Result `json:"result,omitempty"`
	}
	var result *v3Result
	if job.Result != nil {
		result = safeV3Result(Result{Status: job.Status, Summary: job.Result.Summary,
			Tests: &Tests{Passed: job.Result.Passed, Output: job.Result.Output}})
		result.Truncated = result.Truncated || job.Result.Truncated
	}
	envelope := callbackBody{callbackV3Contract, job.Scope.OwnerID, job.Scope.ProjectID, job.Scope.GrantID, job.Scope.JobID,
		job.Scope.Repo, job.Scope.PayloadDigest, job.Status, result}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	// Escaping quotes/control characters can expand 6 KiB of output beyond
	// the wire limit. Shorten only the callback copy, preserving stored results.
	for len(body) > dispatchMaxBody && result != nil && len(result.Output) > 0 {
		runes := []rune(result.Output)
		result.Output = string(runes[:len(runes)*3/4])
		result.Truncated = true
		body, err = json.Marshal(envelope)
		if err != nil {
			return err
		}
	}
	if len(body) > dispatchMaxBody {
		return fmt.Errorf("v3 callback body too large")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	nonce, ts := hex.EncodeToString(random[:]), strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, "POST", v.storage.config.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Omni-Contract", callbackV3Contract)
	req.Header.Set("X-Omni-Client", v.storage.config.CallbackClient)
	req.Header.Set("X-Omni-Timestamp", ts)
	req.Header.Set("X-Omni-Nonce", nonce)
	req.Header.Set("X-Omni-Signature", HMACHex(v.storage.config.CallbackSecret,
		strings.Join([]string{callbackV3Contract, "POST", callbackPath, v.storage.config.CallbackClient, ts, nonce, string(body)}, "\n")))
	resp, err := v.storage.http.Do(req)
	if err != nil {
		return fmt.Errorf("v3 callback transport unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, dispatchMaxBody+1))
	if err != nil || len(raw) > dispatchMaxBody || resp.StatusCode != 200 {
		return fmt.Errorf("v3 callback response unavailable")
	}
	proof := HMACHex(v.storage.config.CallbackSecret, strings.Join([]string{callbackV3Contract, "response", nonce, "200", string(raw)}, "\n"))
	if subtle.ConstantTimeCompare([]byte(resp.Header.Get("X-Omni-Proof")), []byte(proof)) != 1 {
		return fmt.Errorf("v3 callback proof invalid")
	}
	ack, err := strictDispatchObject(raw, "contract", "requestNonce", "status")
	if err != nil || ack["contract"] != callbackV3Contract || ack["requestNonce"] != nonce || ack["status"] != job.Status {
		return fmt.Errorf("v3 callback acknowledgement invalid")
	}
	return nil
}

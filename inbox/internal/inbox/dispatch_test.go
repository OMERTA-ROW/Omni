package inbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	dispatchTestSecret = "synthetic-dispatch-secret-0123456789"
	callbackTestSecret = "synthetic-callback-secret-0123456789"
)

func dispatchTestScope() dispatchScope {
	return dispatchScope{
		OwnerID: "11111111-1111-4111-8111-111111111111", ProjectID: "22222222-2222-4222-8222-222222222222",
		GrantID: "33333333-3333-4333-8333-333333333333", JobID: jobID,
		Repo: "OMERTA-ROW/Omni", Kind: "build", PayloadDigest: strings.Repeat("a", 64),
	}
}

func dispatchTestBody(action string, scope dispatchScope) []byte {
	raw, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Action   string `json:"action"`
		dispatchScope
	}{dispatchContract, action, scope})
	return raw
}

// Independently reproduce the canonical strings in Jackboy's two TS handlers,
// instead of using the inbox signing helpers to validate their own output.
func jackboyTestHMAC(secret, canonical string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

func dispatchTestRequest(raw []byte, nonce string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, dispatchPath, bytes.NewReader(raw))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r.Header.Set("X-Jackboy-Client", "jackboy-test")
	r.Header.Set("X-Jackboy-Timestamp", ts)
	r.Header.Set("X-Jackboy-Nonce", nonce)
	r.Header.Set("X-Jackboy-Signature", jackboyTestHMAC(dispatchTestSecret,
		"jackboy.dispatch/v2\nPOST\n/api/public/jackboy/dispatch\njackboy-test\n"+ts+"\n"+nonce+"\n"+string(raw)))
	return r
}

func serveDispatch(s http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func dispatchFixture(t *testing.T, callback http.HandlerFunc) *DispatchServer {
	t.Helper()
	if callback == nil {
		callback = func(w http.ResponseWriter, r *http.Request) {
			verifyJackboyCallback(t, w, r)
		}
	}
	tls := httptest.NewTLSServer(callback)
	t.Cleanup(tls.Close)
	cfg := DispatchConfig{
		Enabled: true, ClientID: "jackboy-test", Secret: dispatchTestSecret,
		CallbackURL: tls.URL + callbackPath, CallbackClient: "omni-test", CallbackSecret: callbackTestSecret,
	}
	s, err := NewDispatchServer(privateTempDir(t), cfg, map[string]bool{"OMERTA-ROW/Omni": true})
	if err != nil {
		t.Fatal(err)
	}
	s.http.Transport = tls.Client().Transport
	return s
}

func verifyJackboyCallback(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
		w.WriteHeader(500)
		return
	}
	client, ts, nonce := r.Header.Get("X-Omni-Client"), r.Header.Get("X-Omni-Timestamp"), r.Header.Get("X-Omni-Nonce")
	canonical := "jackboy.dispatch-callback/v2\nPOST\n/api/public/omni/callback\n" + client + "\n" + ts + "\n" + nonce + "\n" + string(raw)
	want := jackboyTestHMAC(callbackTestSecret, canonical)
	fields, err := strictDispatchObject(raw, "contract", "ownerId", "projectId", "grantId", "jobId", "repo", "payloadDigest", "status")
	if err != nil || r.TLS == nil || r.Method != "POST" || r.URL.Path != callbackPath ||
		r.URL.RawQuery != "" || r.Header.Get("X-Omni-Contract") != callbackContract ||
		client != "omni-test" || !dispatchTimeRE.MatchString(ts) || !dispatchNonceRE.MatchString(nonce) ||
		!hmac.Equal([]byte(r.Header.Get("X-Omni-Signature")), []byte(want)) {
		t.Errorf("callback does not match Jackboy handler: %v", err)
		w.WriteHeader(401)
		return
	}
	scope := dispatchTestScope()
	if fields["ownerId"] != scope.OwnerID || fields["projectId"] != scope.ProjectID ||
		fields["grantId"] != scope.GrantID || fields["jobId"] != scope.JobID ||
		fields["repo"] != scope.Repo || fields["payloadDigest"] != scope.PayloadDigest ||
		fields["contract"] != callbackContract || (fields["status"] != "quarantined" && fields["status"] != "cancelled") {
		t.Error("callback scope mismatch")
		w.WriteHeader(400)
		return
	}
	body, _ := json.Marshal(map[string]string{"contract": callbackContract, "requestNonce": nonce, "status": fields["status"]})
	w.Header().Set("X-Omni-Proof", jackboyTestHMAC(callbackTestSecret, "jackboy.dispatch-callback/v2\nresponse\n"+nonce+"\n200\n"+string(body)))
	_, _ = w.Write(body)
}

func verifyJackboyResponse(t *testing.T, w *httptest.ResponseRecorder, nonce, status string) {
	t.Helper()
	if w.Code != 200 && w.Code != 202 {
		t.Fatalf("dispatch failed: %d %s", w.Code, w.Body)
	}
	want := jackboyTestHMAC(dispatchTestSecret,
		fmt.Sprintf("jackboy.dispatch/v2\nresponse\n%s\n%d\n%s", nonce, w.Code, w.Body.String()))
	if !hmac.Equal([]byte(w.Header().Get("X-Jackboy-Proof")), []byte(want)) {
		t.Fatal("proof does not match Jackboy client verifier")
	}
	var response struct {
		Contract     string `json:"contract"`
		RequestNonce string `json:"requestNonce"`
		Job          struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"job"`
	}
	decoder := json.NewDecoder(w.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Contract != dispatchContract || response.RequestNonce != nonce ||
		response.Job.ID != jobID || response.Job.Status != status {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestDispatchSubmitStatusCancelAndTerminalIdempotency(t *testing.T) {
	var calls atomic.Int32
	s := dispatchFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		verifyJackboyCallback(t, w, r)
	})
	for i, action := range []string{"submit", "submit", "status", "cancel", "cancel", "submit", "status"} {
		nonce := fmt.Sprintf("%032x", i+1)
		raw := dispatchTestBody(action, dispatchTestScope())
		w := serveDispatch(s, dispatchTestRequest(raw, nonce))
		status := "quarantined"
		if i >= 3 {
			status = "cancelled"
		}
		wantCode := 200
		if action == "submit" {
			wantCode = 202
		}
		if w.Code != wantCode {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body)
		}
		verifyJackboyResponse(t, w, nonce, status)
	}
	if calls.Load() != 5 {
		t.Fatalf("expected submit/cancel callbacks only, got %d", calls.Load())
	}
	// No record reaches the executable queue, even with the worker gate on.
	legacy, err := NewStore(filepath.Dir(s.dir))
	if err != nil {
		t.Fatal(err)
	}
	(&Worker{Enabled: true, Store: legacy}).drain(context.Background())
	if job, err := legacy.Claim(); err != nil || job != nil {
		t.Fatalf("receipt entered legacy queue: %+v, %v", job, err)
	}
}

func TestDispatchRejectsAuthenticationAndSchemaErrors(t *testing.T) {
	s := dispatchFixture(t, nil)
	valid := dispatchTestBody("submit", dispatchTestScope())
	tests := []struct {
		name string
		body []byte
		edit func(*http.Request)
		code int
	}{
		{"signature", valid, func(r *http.Request) { r.Header.Set("X-Jackboy-Signature", strings.Repeat("0", 64)) }, 401},
		{"client", valid, func(r *http.Request) { r.Header.Set("X-Jackboy-Client", "other") }, 401},
		{"stale", valid, func(r *http.Request) {
			r.Header.Set("X-Jackboy-Timestamp", strconv.FormatInt(time.Now().Add(-61*time.Second).Unix(), 10))
		}, 401},
		{"future", valid, func(r *http.Request) {
			r.Header.Set("X-Jackboy-Timestamp", strconv.FormatInt(time.Now().Add(61*time.Second).Unix(), 10))
		}, 401},
		{"bad_timestamp", valid, func(r *http.Request) { r.Header.Set("X-Jackboy-Timestamp", "123") }, 401},
		{"bad_nonce", valid, func(r *http.Request) { r.Header.Set("X-Jackboy-Nonce", "not-a-nonce") }, 401},
		{"unknown_field", append(bytes.Clone(bytes.TrimSuffix(valid, []byte("}"))), []byte(`,"command":"never execute"}`)...), nil, 400},
		{"duplicate_field", append(bytes.Clone(bytes.TrimSuffix(valid, []byte("}"))), []byte(`,"kind":"test"}`)...), nil, 400},
		{"case_folded", bytes.Replace(valid, []byte(`"ownerId"`), []byte(`"OwnerId"`), 1), nil, 400},
		{"null", bytes.Replace(valid, []byte(`"build"`), []byte(`null`), 1), nil, 400},
		{"missing_field", bytes.Replace(valid, []byte(`"kind":"build",`), nil, 1), nil, 400},
		{"trailing_json", append(bytes.Clone(valid), []byte(`{}`)...), nil, 400},
		{"wrong_contract", bytes.Replace(valid, []byte(dispatchContract), []byte("other"), 1), nil, 400},
		{"invalid_uuid", bytes.Replace(valid, []byte(jobID), []byte("not-a-uuid"), 1), nil, 400},
		{"invalid_kind", bytes.Replace(valid, []byte(`"build"`), []byte(`"shell"`), 1), nil, 400},
		{"invalid_action", dispatchTestBody("run", dispatchTestScope()), nil, 400},
		{"bad_digest", bytes.Replace(valid, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("A", 64)), 1), nil, 400},
		{"repo_not_allowed", bytes.Replace(valid, []byte("OMERTA-ROW/Omni"), []byte("someone/else"), 1), nil, 403},
		{"oversize", []byte(strings.Repeat(" ", 8193)), nil, 400},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := dispatchTestRequest(tc.body, fmt.Sprintf("%032x", i+100))
			if tc.edit != nil {
				tc.edit(req)
			}
			w := serveDispatch(s, req)
			if w.Code != tc.code {
				t.Fatalf("got %d %s, want %d", w.Code, w.Body, tc.code)
			}
			if w.Header().Get("X-Jackboy-Proof") != "" {
				t.Fatal("rejection has success proof")
			}
		})
	}
}

func TestDispatchScopeConflictsAndMissingJobs(t *testing.T) {
	s := dispatchFixture(t, nil)
	valid := dispatchTestBody("submit", dispatchTestScope())
	if w := serveDispatch(s, dispatchTestRequest(valid, fmt.Sprintf("%032x", 1))); w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for i, field := range []string{"grant", "digest", "owner", "project", "kind", "repo"} {
		scope := dispatchTestScope()
		switch field {
		case "grant":
			scope.GrantID = "44444444-4444-4444-8444-444444444444"
		case "digest":
			scope.PayloadDigest = strings.Repeat("b", 64)
		case "owner":
			scope.OwnerID = "44444444-4444-4444-8444-444444444444"
		case "project":
			scope.ProjectID = "44444444-4444-4444-8444-444444444444"
		case "kind":
			scope.Kind = "test"
		case "repo":
			scope.Repo = "OMERTA-ROW/Other"
			s.allowed[scope.Repo] = true
		}
		for j, action := range []string{"submit", "status", "cancel"} {
			w := serveDispatch(s, dispatchTestRequest(dispatchTestBody(action, scope), fmt.Sprintf("%032x", 100+i*3+j)))
			if w.Code != 409 {
				t.Fatalf("%s %s: %d %s", field, action, w.Code, w.Body)
			}
		}
	}
	for i, action := range []string{"status", "cancel"} {
		scope := dispatchTestScope()
		scope.JobID = "44444444-4444-4444-8444-444444444444"
		w := serveDispatch(s, dispatchTestRequest(dispatchTestBody(action, scope), fmt.Sprintf("%032x", 200+i)))
		if w.Code != 404 {
			t.Fatalf("missing %s: %d", action, w.Code)
		}
	}
}

func TestDispatchNoncePersistsAcrossReopenAndConcurrentRequests(t *testing.T) {
	s := dispatchFixture(t, nil)
	raw := dispatchTestBody("submit", dispatchTestScope())
	nonce := strings.Repeat("c", 32)
	if w := serveDispatch(s, dispatchTestRequest(raw, nonce)); w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	reopened, err := NewDispatchServer(filepath.Dir(s.dir), s.config, s.allowed)
	if err != nil {
		t.Fatal(err)
	}
	reopened.http.Transport = s.http.Transport
	for _, server := range []*DispatchServer{s, reopened} {
		if w := serveDispatch(server, dispatchTestRequest(raw, nonce)); w.Code != 409 {
			t.Fatalf("replayed nonce accepted: %d %s", w.Code, w.Body)
		}
	}
	var successes, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			server := s
			if i%2 == 0 {
				server = reopened
			}
			w := serveDispatch(server, dispatchTestRequest(raw, strings.Repeat("d", 32)))
			switch w.Code {
			case 202:
				successes.Add(1)
			case 409:
				conflicts.Add(1)
			default:
				t.Errorf("concurrent request: %d %s", w.Code, w.Body)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 || conflicts.Load() != 7 {
		t.Fatalf("single-use failed: successes=%d conflicts=%d", successes.Load(), conflicts.Load())
	}
	if _, err := reopened.readState(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchCallbacksFailClosedAndRetainReceipt(t *testing.T) {
	for _, problem := range []string{"bad_proof", "wrong_nonce", "wrong_status", "unknown_field", "oversize", "http_error", "redirect", "untrusted_tls", "timeout"} {
		t.Run(problem, func(t *testing.T) {
			var calls atomic.Int32
			s := dispatchFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if problem == "timeout" {
					time.Sleep(50 * time.Millisecond)
				}
				if problem == "redirect" {
					http.Redirect(w, r, "/must-not-follow", http.StatusTemporaryRedirect)
					return
				}
				if problem == "http_error" {
					w.WriteHeader(503)
					return
				}
				nonce, status := r.Header.Get("X-Omni-Nonce"), "quarantined"
				if problem == "wrong_nonce" {
					nonce = strings.Repeat("0", 32)
				}
				if problem == "wrong_status" {
					status = "cancelled"
				}
				body := fmt.Sprintf(`{"contract":%q,"requestNonce":%q,"status":%q}`, callbackContract, nonce, status)
				if problem == "unknown_field" {
					body = strings.TrimSuffix(body, "}") + `,"extra":""}`
				}
				if problem == "oversize" {
					body += strings.Repeat(" ", 8193)
				}
				proof := jackboyTestHMAC(callbackTestSecret, callbackContract+"\nresponse\n"+r.Header.Get("X-Omni-Nonce")+"\n200\n"+body)
				if problem == "bad_proof" {
					proof = strings.Repeat("0", 64)
				}
				w.Header().Set("X-Omni-Proof", proof)
				_, _ = io.WriteString(w, body)
			})
			if problem == "untrusted_tls" {
				s.http.Transport = http.DefaultTransport
			}
			if problem == "timeout" {
				s.http.Timeout = 20 * time.Millisecond
			}
			w := serveDispatch(s, dispatchTestRequest(dispatchTestBody("submit", dispatchTestScope()), strings.Repeat("e", 32)))
			if w.Code != 503 || (problem != "untrusted_tls" && problem != "timeout" && calls.Load() != 1) {
				t.Fatalf("callback failure not enforced: %d calls=%d", w.Code, calls.Load())
			}
			state, err := s.readState()
			if err != nil || state.Jobs[jobID].Status != "quarantined" {
				t.Fatalf("receipt not retained: %+v %v", state, err)
			}
		})
	}
}

func TestDispatchTestKindAndCancelledReceiptSurviveReopen(t *testing.T) {
	s := dispatchFixture(t, nil)
	scope := dispatchTestScope()
	scope.Kind = "test"
	for i, action := range []string{"submit", "cancel"} {
		w := serveDispatch(s, dispatchTestRequest(dispatchTestBody(action, scope), fmt.Sprintf("%032x", i+1)))
		if w.Code != 200 && w.Code != 202 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body)
		}
	}
	reopened, err := NewDispatchServer(filepath.Dir(s.dir), s.config, s.allowed)
	if err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("%032x", 3)
	w := serveDispatch(reopened, dispatchTestRequest(dispatchTestBody("status", scope), nonce))
	verifyJackboyResponse(t, w, nonce, "cancelled")
}

func TestDispatchAuthenticatesRawBytesAndConsumesRejectedNonces(t *testing.T) {
	s := dispatchFixture(t, nil)
	raw := dispatchTestBody("submit", dispatchTestScope())
	nonce := strings.Repeat("a", 32)
	req := dispatchTestRequest(raw, nonce)
	req.Body = io.NopCloser(bytes.NewReader(append(bytes.Clone(raw), ' ')))
	if w := serveDispatch(s, req); w.Code != 401 {
		t.Fatalf("signature did not bind exact raw bytes: %d", w.Code)
	}
	// A bad signature cannot burn someone else's nonce.
	if w := serveDispatch(s, dispatchTestRequest(raw, nonce)); w.Code != 202 {
		t.Fatalf("unsigned request burned nonce: %d", w.Code)
	}
	nonce = strings.Repeat("b", 32)
	bad := append(bytes.Clone(bytes.TrimSuffix(raw, []byte("}"))), []byte(`,"extra":""}`)...)
	if w := serveDispatch(s, dispatchTestRequest(bad, nonce)); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	if w := serveDispatch(s, dispatchTestRequest(raw, nonce)); w.Code != 409 {
		t.Fatalf("authenticated rejected request nonce reused: %d", w.Code)
	}
	padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), dispatchMaxBody-len(raw))...)
	if w := serveDispatch(s, dispatchTestRequest(padded, strings.Repeat("c", 32))); w.Code != 202 {
		t.Fatalf("exact 8192 byte body rejected: %d %s", w.Code, w.Body)
	}
}

func TestDispatchRejectsLinkedFiles(t *testing.T) {
	for _, file := range []string{"state.json", "state.lock", "audit.jsonl", "audit.lock"} {
		for _, kind := range []string{"symlink", "hardlink"} {
			t.Run(file+"_"+kind, func(t *testing.T) {
				s := dispatchFixture(t, nil)
				target := filepath.Join(privateTempDir(t), "target")
				content := []byte(`{"nonces":{},"jobs":{}}`)
				if err := os.WriteFile(target, content, 0o600); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hardlink" {
					link = os.Link
				}
				if err := link(target, filepath.Join(s.dir, file)); err != nil {
					t.Fatal(err)
				}
				w := serveDispatch(s, dispatchTestRequest(dispatchTestBody("submit", dispatchTestScope()), strings.Repeat("a", 32)))
				if w.Code != 503 {
					t.Fatalf("unsafe file accepted: %d", w.Code)
				}
				after, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(after, content) {
					t.Fatal("linked target modified")
				}
			})
		}
	}
}

func TestDispatchConfigurationAndDisabledEndpoint(t *testing.T) {
	s := dispatchFixture(t, nil)
	for _, change := range []func(*DispatchConfig){
		func(c *DispatchConfig) { c.Secret = "short" },
		func(c *DispatchConfig) { c.ClientID = "bad client" },
		func(c *DispatchConfig) { c.CallbackSecret = "short" },
		func(c *DispatchConfig) { c.CallbackClient = "" },
		func(c *DispatchConfig) { c.CallbackURL = "http://example.test" + callbackPath },
		func(c *DispatchConfig) { c.CallbackURL = "https://user:pass@example.test" + callbackPath },
		func(c *DispatchConfig) { c.CallbackURL = "https://example.test/wrong" },
		func(c *DispatchConfig) { c.CallbackURL = "https://example.test" + callbackPath + "?query" },
		func(c *DispatchConfig) { c.CallbackURL = "https://example.test" + callbackPath + "#fragment" },
	} {
		config := s.config
		change(&config)
		if _, err := NewDispatchServer(privateTempDir(t), config, s.allowed); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	disabled, err := NewDispatchServer(privateTempDir(t), DispatchConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := serveDispatch(disabled, dispatchTestRequest(dispatchTestBody("submit", dispatchTestScope()), strings.Repeat("a", 32)))
	if w.Code != 503 {
		t.Fatalf("disabled dispatch: %d", w.Code)
	}
	legacy, h := newServer(t)
	if w := serveDispatch(h, httptest.NewRequest("POST", dispatchPath, nil)); w.Code != 503 {
		t.Fatalf("unconfigured dispatch: %d", w.Code)
	}
	legacy.Dispatch = disabled
	if w := serveDispatch(legacy.Handler(), httptest.NewRequest("POST", dispatchPath, nil)); w.Code != 503 {
		t.Fatalf("wired disabled dispatch: %d", w.Code)
	}
}

func TestDispatchAuditAndStorageFailClosed(t *testing.T) {
	s := dispatchFixture(t, nil)
	raw := dispatchTestBody("submit", dispatchTestScope())
	w := serveDispatch(s, dispatchTestRequest(raw, strings.Repeat("a", 32)))
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	rawAudit, err := os.ReadFile(filepath.Join(s.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dispatch_received", "dispatch_submit", "dispatch_result", "callback_attempt", "callback_result"} {
		if !bytes.Contains(rawAudit, []byte(want)) {
			t.Errorf("missing audit event %s", want)
		}
	}
	for _, secret := range []string{dispatchTestSecret, callbackTestSecret, "X-Jackboy-Signature", dispatchTestScope().PayloadDigest} {
		if bytes.Contains(rawAudit, []byte(secret)) {
			t.Fatal("sensitive/raw data in audit")
		}
	}
	for _, name := range []string{"state.json", "state.lock", "audit.jsonl", "audit.lock"} {
		info, err := os.Stat(filepath.Join(s.dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("nonprivate dispatch file %s: %v %v", name, info, err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.dir, "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	w = serveDispatch(s, dispatchTestRequest(raw, strings.Repeat("b", 32)))
	if w.Code != 503 {
		t.Fatalf("corrupt store accepted: %d", w.Code)
	}
	if err := os.Chmod(filepath.Join(s.dir, "audit.jsonl"), 0o400); err != nil {
		t.Fatal(err)
	}
	w = serveDispatch(s, dispatchTestRequest(raw, strings.Repeat("c", 32)))
	if w.Code != 503 {
		t.Fatalf("audit failure accepted: %d", w.Code)
	}
}

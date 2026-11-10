package inbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func v3Body(action, payload string, expiry int64, kind string) []byte {
	scope := dispatchTestScope()
	scope.Kind = kind
	scope.PayloadDigest = payloadDigest(scope, payload)
	fields := map[string]any{
		"contract": dispatchV3Contract, "action": action,
		"ownerId": scope.OwnerID, "projectId": scope.ProjectID, "grantId": scope.GrantID,
		"jobId": scope.JobID, "repo": scope.Repo, "kind": scope.Kind, "payloadDigest": scope.PayloadDigest,
	}
	if action == "submit" {
		fields["payload"], fields["expiresAt"] = payload, expiry
	}
	raw, _ := json.Marshal(fields)
	return raw
}

func v3Request(raw []byte, nonce string) *http.Request {
	req := dispatchTestRequest(raw, nonce)
	ts := req.Header.Get("X-Jackboy-Timestamp")
	req.Header.Set("X-Jackboy-Signature", jackboyTestHMAC(dispatchTestSecret,
		dispatchV3Contract+"\nPOST\n"+dispatchPath+"\njackboy-test\n"+ts+"\n"+nonce+"\n"+string(raw)))
	return req
}

func v3Fixture(t *testing.T, enabled bool) (*DispatchServer, *DispatchV3) {
	t.Helper()
	s := dispatchFixture(t, nil)
	w := shellWorker(t)
	useTestSandbox(t, w)
	w.Enabled = enabled
	if err := s.EnableV3(w); err != nil {
		t.Fatal(err)
	}
	return s, s.v3
}

func v3Snapshot(t *testing.T, v *DispatchV3) v3State {
	t.Helper()
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlockDispatch(lock)
	state, err := v.read()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestV3DigestMatchesNodeJSONSerialization(t *testing.T) {
	// Generated with Node crypto.createHash and Jackboy's exact JSON.stringify
	// field order, including HTML, literal escapes and Unicode separators.
	for _, tc := range []struct{ payload, want string }{
		{"run tests", "4e067ab0eaae888179670d8ca175bf4d68e43575ce2fa3978d307995fe1c00f9"},
		{"<tag>& \"quoted\"\nline\t\\u2028\u2028\u2029\U0001f9ea", "c060581b5d7c7a3895cbb5b5e5d2acc199f20dfe79371caed0a257139b052f07"},
		{"", "f8773bafc239e93492fd6b1ed9dc4a29775e6f9d928b4a24cab4e7dd0def23ed"},
	} {
		if got := payloadDigest(dispatchTestScope(), tc.payload); got != tc.want {
			t.Fatalf("digest mismatch: got %s want %s", got, tc.want)
		}
	}
}

func TestV3RejectsDigestExpiryAndSchemaErrors(t *testing.T) {
	s, _ := v3Fixture(t, true)
	valid := v3Body("submit", "run tests", time.Now().Add(10*time.Minute).Unix(), "test")
	var wrongExpiry map[string]any
	if err := json.Unmarshal(valid, &wrongExpiry); err != nil {
		t.Fatal(err)
	}
	wrongExpiry["expiresAt"] = "1234567890"
	stringExpiry, _ := json.Marshal(wrongExpiry)
	for i, tc := range []struct {
		name string
		body []byte
	}{
		{"digest", bytes.Replace(valid, []byte(`"payload":"run tests"`), []byte(`"payload":"different"`), 1)},
		{"expired", v3Body("submit", "run tests", time.Now().Unix()-1, "test")},
		{"too_far", v3Body("submit", "run tests", time.Now().Add(31*time.Minute).Unix(), "test")},
		{"too_large", v3Body("submit", strings.Repeat("x", 6145), time.Now().Add(time.Minute).Unix(), "test")},
		{"unknown", append(bytes.Clone(bytes.TrimSuffix(valid, []byte("}"))), []byte(`,"command":"bad"}`)...)},
		{"duplicate", append(bytes.Clone(bytes.TrimSuffix(valid, []byte("}"))), []byte(`,"payload":"run tests"}`)...)},
		{"string_expiry", stringExpiry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serveDispatch(s, v3Request(tc.body, fmt.Sprintf("%032x", i+1)))
			if w.Code != 400 {
				t.Fatalf("bad submit: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestV3OffGateProofIsolationAndExpiry(t *testing.T) {
	s, v := v3Fixture(t, false)
	expiry := time.Now().Add(time.Minute).Unix()
	raw := v3Body("submit", "run tests", expiry, "test")
	nonce := strings.Repeat("a", 32)
	w := serveDispatch(s, v3Request(raw, nonce))
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	want := jackboyTestHMAC(dispatchTestSecret, fmt.Sprintf("%s\nresponse\n%s\n202\n%s", dispatchV3Contract, nonce, w.Body.String()))
	if w.Header().Get("X-Jackboy-Proof") != want {
		t.Fatal("v3 response proof mismatch")
	}
	state := v3Snapshot(t, v)
	if state.Jobs[jobID].Status != "quarantined" || len(state.Outbox) != 1 {
		t.Fatalf("worker-off submitted approval: %+v", state)
	}
	v.worker.Enabled = true
	if err := v.execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, v); state.Jobs[jobID].Status != "quarantined" {
		t.Fatal("enabling worker released held job")
	}
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		t.Fatal(err)
	}
	state, err = v.read()
	if err != nil {
		t.Fatal(err)
	}
	job := state.Jobs[jobID]
	job.ExpiresAt = time.Now().Unix() - 1
	job.Status = "approved"
	state.Jobs[jobID] = job
	for i := range state.Outbox {
		state.Outbox[i].Job.ExpiresAt = job.ExpiresAt
	}
	if err := v.write(state); err != nil {
		t.Fatal(err)
	}
	unlockDispatch(lock)
	if err := v.execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, v); state.Jobs[jobID].Status != "expired" {
		t.Fatal("expired job claimed")
	}
	// v2 still has its exact response and quarantine-only behavior.
	v2raw := dispatchTestBody("submit", dispatchTestScope())
	v2nonce := strings.Repeat("b", 32)
	verifyJackboyResponse(t, serveDispatch(s, dispatchTestRequest(v2raw, v2nonce)), v2nonce, "quarantined")
}

func TestV3ExecutesSandboxedTestAndBuild(t *testing.T) {
	for _, kind := range []string{"test", "build", "failing_build"} {
		t.Run(kind, func(t *testing.T) {
			s, v := v3Fixture(t, true)
			repo := gitRepo(t)
			v.worker.CloneURL = func(string) string { return "file://" + repo }
			payload := "run tests"
			wireKind := kind
			if kind == "build" || kind == "failing_build" {
				wireKind = "build"
				payload = strings.Replace(breakPatch, "a - b", "b + a", 1)
			}
			if kind == "failing_build" {
				payload = breakPatch
			}
			expiry := time.Now().Add(5 * time.Minute).Unix()
			w := serveDispatch(s, v3Request(v3Body("submit", payload, expiry, wireKind), strings.Repeat("a", 32)))
			if w.Code != 202 || !strings.Contains(w.Body.String(), "approved") {
				t.Fatalf("not approved: %d %s", w.Code, w.Body)
			}
			if err := v.execute(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := v3Snapshot(t, v)
			job := state.Jobs[jobID]
			expected := "completed"
			if kind == "failing_build" {
				expected = "failed"
			}
			if job.Status != expected || job.Result == nil || job.Result.Passed != (expected == "completed") {
				t.Fatalf("execution failed: %+v", job)
			}
			if len(state.Outbox) != 2 || state.Outbox[0].Job.Status != "running" || state.Outbox[1].Job.Status != expected {
				t.Fatalf("missing ordered callbacks: %+v", state.Outbox)
			}
			legacy, err := NewStore(filepath.Dir(s.dir))
			if err != nil {
				t.Fatal(err)
			}
			if j, err := legacy.Claim(); err != nil || j != nil {
				t.Fatal("v3 job entered legacy queue")
			}
		})
	}
}

func TestV3CancelStopsRunningSandbox(t *testing.T) {
	s, v := v3Fixture(t, true)
	repo := gitRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "sleep_test.go"), []byte("package x\nimport(\"testing\";\"time\";\"os\";\"path/filepath\")\nfunc TestSleep(t *testing.T){if err:=os.WriteFile(filepath.Join(os.Getenv(\"HOME\"),\"v3-slow-started\"),nil,0600);err!=nil{t.Fatal(err)};time.Sleep(time.Minute)}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "slow fixture")
	v.worker.CloneURL = func(string) string { return "file://" + repo }
	expiry := time.Now().Add(5 * time.Minute).Unix()
	raw := v3Body("submit", "run tests", expiry, "test")
	if w := serveDispatch(s, v3Request(raw, strings.Repeat("a", 32))); w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	done := make(chan error, 1)
	go func() { done <- v.execute(context.Background()) }()
	deadline := time.After(30 * time.Second)
	var workspace string
	for {
		entries, err := os.ReadDir("/tmp")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "omni-shell-") {
				dir := filepath.Join("/tmp", entry.Name())
				if _, err := os.Stat(filepath.Join(dir, "v3-slow-started")); err == nil {
					workspace = dir
				}
			}
		}
		if workspace != "" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("sandboxed test never started")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// A second handler has no in-memory active context; the running worker must
	// also observe the durable cancellation through its state watcher.
	other, err := NewDispatchServer(filepath.Dir(s.dir), s.config, s.allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.EnableV3(v.worker); err != nil {
		t.Fatal(err)
	}
	w := serveDispatch(other, v3Request(v3Body("cancel", "run tests", expiry, "test"), strings.Repeat("b", 32)))
	if w.Code != 200 {
		t.Fatalf("cancel failed: %d %s", w.Code, w.Body)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not stop runner")
	}
	if state := v3Snapshot(t, v); state.Jobs[jobID].Status != "cancelled" {
		t.Fatal("completion overwrote cancellation")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatal("cancelled sandbox workspace was not cleaned up")
	}
}

func TestV3ResultRedactionAndTruncation(t *testing.T) {
	t.Setenv("OMNI_CALLBACK_SECRET", "synthetic-super-secret")
	text := "synthetic-super-secret API_KEY=abc123 password: hunter2 Bearer abc.xyz ghp_1234567890 sk-1234567890 postgres://user:pass@db/test\n"
	r := safeV3Result(Result{Status: "failed", Summary: text + strings.Repeat("x", 600),
		Tests: &Tests{Output: text + strings.Repeat("\U0001f9ea", 3000)}})
	if r.Passed || !r.Truncated || len([]rune(r.Summary)) > 500 || len(r.Output) > 6144 || !utf8.ValidString(r.Output) {
		t.Fatalf("bad result limits: %+v", r)
	}
	for _, secret := range []string{"synthetic-super-secret", "abc123", "hunter2", "abc.xyz", "ghp_1234567890", "sk-1234567890", "user:pass"} {
		if strings.Contains(r.Output+r.Summary, secret) {
			t.Fatalf("secret leaked: %s", secret)
		}
	}
}

func TestV3CallbackProofRetryAndDurableAcknowledgement(t *testing.T) {
	s, v := v3Fixture(t, false)
	var attempts atomic.Int32
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		client, ts, nonce := r.Header.Get("X-Omni-Client"), r.Header.Get("X-Omni-Timestamp"), r.Header.Get("X-Omni-Nonce")
		want := jackboyTestHMAC(callbackTestSecret, callbackV3Contract+"\nPOST\n"+callbackPath+"\n"+client+"\n"+ts+"\n"+nonce+"\n"+string(raw))
		if r.Header.Get("X-Omni-Contract") != callbackV3Contract || r.Header.Get("X-Omni-Signature") != want {
			t.Error("callback signature mismatch")
		}
		var body struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		ack, _ := json.Marshal(map[string]string{"contract": callbackV3Contract, "requestNonce": nonce, "status": body.Status})
		proof := jackboyTestHMAC(callbackTestSecret, callbackV3Contract+"\nresponse\n"+nonce+"\n200\n"+string(ack))
		if attempts.Add(1) == 1 {
			proof = "bad"
		}
		w.Header().Set("X-Omni-Proof", proof)
		_, _ = w.Write(ack)
	}))
	defer tls.Close()
	v.storage.config.CallbackURL = tls.URL + callbackPath
	v.storage.http.Transport = tls.Client().Transport
	w := serveDispatch(s, v3Request(v3Body("submit", "run tests", time.Now().Add(time.Minute).Unix(), "test"), strings.Repeat("a", 32)))
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if err := v.deliver(context.Background()); err == nil {
		t.Fatal("bad callback proof accepted")
	}
	state := v3Snapshot(t, v)
	if len(state.Outbox) != 1 || state.Outbox[0].Attempt != 1 || state.Outbox[0].NextAt <= time.Now().Unix() {
		t.Fatal("failed callback lost or not backed off")
	}
	if err := v.deliver(context.Background()); err != nil || attempts.Load() != 1 {
		t.Fatal("backoff ignored")
	}
	// Reattach a fresh handler/runner to the same persisted state.
	callbackConfig := v.storage.config
	if err := s.EnableV3(v.worker); err != nil {
		t.Fatal(err)
	}
	v = s.v3
	v.storage.config = callbackConfig
	state = v3Snapshot(t, v)
	lock, err := v.storage.lock("state.lock")
	if err != nil {
		t.Fatal(err)
	}
	state.Outbox[0].NextAt = 0
	if err := v.write(state); err != nil {
		t.Fatal(err)
	}
	unlockDispatch(lock)
	if err := v.deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, v); len(state.Outbox) != 0 || state.Jobs[jobID].Status != "quarantined" {
		t.Fatal("ack removed result or failed to remove delivery")
	}
}

func TestV3ReplayAndRestartQuarantine(t *testing.T) {
	s, v := v3Fixture(t, true)
	raw := v3Body("submit", "run tests", time.Now().Add(time.Minute).Unix(), "test")
	nonce := strings.Repeat("a", 32)
	if w := serveDispatch(s, v3Request(raw, nonce)); w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if err := v.recover(); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, v); state.Jobs[jobID].Status != "quarantined" {
		t.Fatal("restart released historical approval")
	}
	if err := s.EnableV3(v.worker); err != nil {
		t.Fatal(err)
	}
	v = s.v3
	if w := serveDispatch(s, v3Request(raw, nonce)); w.Code != 409 {
		t.Fatal("replayed v3 nonce accepted")
	}
	// Prove the stored nonce is the signed request timestamp.
	state := v3Snapshot(t, v)
	ts := strconv.FormatInt(int64(state.Nonces[nonce]), 10)
	if !dispatchTimeRE.MatchString(ts) {
		t.Fatal("nonce timestamp missing")
	}
}

func TestV3QueuedCancelStatusAndImmutableApproval(t *testing.T) {
	s, v := v3Fixture(t, true)
	expiry := time.Now().Add(time.Minute).Unix()
	for i, action := range []string{"submit", "status", "cancel", "submit", "cancel"} {
		w := serveDispatch(s, v3Request(v3Body(action, "run tests", expiry, "test"), fmt.Sprintf("%032x", i+1)))
		wantStatus, wantCode := "approved", 200
		if i >= 2 {
			wantStatus = "cancelled"
		}
		if action == "submit" {
			wantCode = 202
		}
		if w.Code != wantCode || !strings.Contains(w.Body.String(), `"`+wantStatus+`"`) {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body)
		}
		nonce := fmt.Sprintf("%032x", i+1)
		proof := jackboyTestHMAC(dispatchTestSecret, fmt.Sprintf("%s\nresponse\n%s\n%d\n%s", dispatchV3Contract, nonce, w.Code, w.Body))
		if w.Header().Get("X-Jackboy-Proof") != proof {
			t.Fatal("action response proof mismatch")
		}
	}
	if err := v.execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, v); state.Jobs[jobID].Status != "cancelled" {
		t.Fatal("cancelled job was executed")
	}
}

func TestV3UnauthenticatedRequestsDoNotWrite(t *testing.T) {
	for _, mode := range []string{"disabled", "signature", "timestamp", "nonce", "client", "oversize", "v2_signature"} {
		t.Run(mode, func(t *testing.T) {
			s, v := v3Fixture(t, true)
			body := v3Body("submit", "run tests", time.Now().Add(time.Minute).Unix(), "test")
			r := v3Request(body, strings.Repeat("a", 32))
			code := 401
			switch mode {
			case "disabled":
				s.config.Enabled = false
				code = 503
			case "signature":
				r.Header.Set("X-Jackboy-Signature", strings.Repeat("0", 64))
			case "timestamp":
				r.Header.Set("X-Jackboy-Timestamp", strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10))
			case "nonce":
				r.Header.Set("X-Jackboy-Nonce", "bad")
			case "client":
				r.Header.Set("X-Jackboy-Client", "wrong")
			case "oversize":
				r = v3Request([]byte(strings.Repeat("x", dispatchMaxBody+1)), strings.Repeat("a", 32))
				code = 400
			case "v2_signature":
				r = dispatchTestRequest(body, strings.Repeat("a", 32))
			}
			if w := serveDispatch(s, r); w.Code != code {
				t.Fatalf("got %d want %d", w.Code, code)
			}
			for _, dir := range []string{s.dir, v.storage.dir} {
				files, err := os.ReadDir(dir)
				if err != nil || len(files) != 0 {
					t.Fatalf("unauthenticated request wrote storage: %v %v", files, err)
				}
			}
		})
	}
}

func TestV3TerminalCallbackBoundsRedactionAndProof(t *testing.T) {
	_, v := v3Fixture(t, false)
	t.Setenv("OMNI_GIT_TOKEN", "synthetic-callback-secret")
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil || len(raw) > dispatchMaxBody || bytes.Contains(raw, []byte("synthetic-callback-secret")) {
			t.Errorf("unsafe callback envelope: size=%d err=%v", len(raw), err)
		}
		var body struct {
			Contract string    `json:"contract"`
			Status   string    `json:"status"`
			Result   *v3Result `json:"result"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.Result == nil {
			t.Error("missing callback result")
			w.WriteHeader(400)
			return
		}
		if !body.Result.Truncated || !body.Result.Passed || len(body.Result.Output) > 6144 || len([]rune(body.Result.Summary)) > 500 {
			t.Errorf("invalid callback result: %+v", body.Result)
		}
		client, ts, nonce := r.Header.Get("X-Omni-Client"), r.Header.Get("X-Omni-Timestamp"), r.Header.Get("X-Omni-Nonce")
		want := jackboyTestHMAC(callbackTestSecret, callbackV3Contract+"\nPOST\n"+callbackPath+"\n"+client+"\n"+ts+"\n"+nonce+"\n"+string(raw))
		if r.Header.Get("X-Omni-Signature") != want {
			t.Error("terminal signature mismatch")
		}
		ack, _ := json.Marshal(map[string]string{"contract": callbackV3Contract, "requestNonce": nonce, "status": body.Status})
		w.Header().Set("X-Omni-Proof", jackboyTestHMAC(callbackTestSecret, callbackV3Contract+"\nresponse\n"+nonce+"\n200\n"+string(ack)))
		_, _ = w.Write(ack)
	}))
	defer tls.Close()
	v.storage.config.CallbackURL = tls.URL + callbackPath
	v.storage.http.Transport = tls.Client().Transport
	job := v3Job{Scope: dispatchTestScope(), Status: "completed",
		Result: &v3Result{Passed: true, Summary: "synthetic-callback-secret", Output: strings.Repeat("\x01", 6144)}}
	if err := v.send(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if len(job.Result.Output) != 6144 || job.Result.Truncated {
		t.Fatal("callback preparation mutated retained result")
	}
}

func v3OutboxFixture(t *testing.T, v *DispatchV3) v3State {
	t.Helper()
	state := v3Snapshot(t, v)
	for i := 1; i <= 2; i++ {
		scope := dispatchTestScope()
		scope.JobID = fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
		payload := "private signed instructions"
		scope.PayloadDigest = payloadDigest(scope, payload)
		job := v3Job{Scope: scope, Payload: payload, ExpiresAt: time.Now().Add(time.Minute).Unix(), Status: "quarantined"}
		state.Jobs[scope.JobID] = job
		state.Outbox = append(state.Outbox, newV3Event(job))
		if i == 1 {
			job.Status = "cancelled"
			state.Jobs[scope.JobID] = job
			state.Outbox = append(state.Outbox, newV3Event(job))
		}
	}
	if err := v.write(state); err != nil {
		t.Fatal(err)
	}
	return state
}

func v3CallbackFixture(t *testing.T, v *DispatchV3, accept func(string, string) bool) {
	t.Helper()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			JobID  string `json:"jobId"`
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if !accept(body.JobID, body.Status) {
			w.WriteHeader(422)
			return
		}
		nonce := r.Header.Get("X-Omni-Nonce")
		ack, _ := json.Marshal(map[string]string{"contract": callbackV3Contract, "requestNonce": nonce, "status": body.Status})
		w.Header().Set("X-Omni-Proof", jackboyTestHMAC(callbackTestSecret, callbackV3Contract+"\nresponse\n"+nonce+"\n200\n"+string(ack)))
		_, _ = w.Write(ack)
	}))
	t.Cleanup(tls.Close)
	v.storage.config.CallbackURL = tls.URL + callbackPath
	v.storage.http.Transport = tls.Client().Transport
}

func TestV3CallbackRetriesDoNotBlockOtherJobs(t *testing.T) {
	_, v := v3Fixture(t, false)
	state := v3OutboxFixture(t, v)
	first, other := state.Outbox[0].Job.Scope.JobID, state.Outbox[2].Job.Scope.JobID
	calls := make(chan string, 10)
	v3CallbackFixture(t, v, func(id, status string) bool {
		calls <- id + ":" + status
		return id != first
	})
	if err := v.deliver(context.Background()); err == nil {
		t.Fatal("permanent rejection was not reported")
	}
	if got := <-calls; got != first+":quarantined" {
		t.Fatalf("first callback: %s", got)
	}
	if got := <-calls; got != other+":quarantined" {
		t.Fatalf("unrelated due callback blocked: %s", got)
	}
	state = v3Snapshot(t, v)
	if len(state.Outbox) != 2 || state.Outbox[0].Attempt != 1 || state.Outbox[1].Attempt != 0 {
		t.Fatalf("per-job order lost: %+v", state.Outbox)
	}
	if err := v.deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatal("later event bypassed same-job backoff")
	}
	// A persisted backoff remains isolated after reopening the store.
	s := v.storage
	reopened, err := NewDispatchServer(filepath.Dir(s.dir), s.config, s.allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableV3(v.worker); err != nil {
		t.Fatal(err)
	}
	if state := v3Snapshot(t, reopened.v3); len(state.Outbox) != 2 {
		t.Fatal("pending callbacks lost on reopen")
	}
}

func TestV3CallbackDeadLetterLimits(t *testing.T) {
	for _, limit := range []string{"attempts", "age", "existing_cap"} {
		t.Run(limit, func(t *testing.T) {
			_, v := v3Fixture(t, false)
			state := v3OutboxFixture(t, v)
			first := state.Outbox[0].Job.Scope.JobID
			switch limit {
			case "attempts":
				state.Outbox[0].Attempt = 7
			case "age":
				state.Outbox[0].CreatedAt = time.Now().Add(-24 * time.Hour).Unix()
				state.Outbox[0].NextAt = time.Now().Add(time.Hour).Unix()
			case "existing_cap":
				state.Outbox[0].Attempt = 8
			}
			if err := v.write(state); err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int32
			v3CallbackFixture(t, v, func(id, status string) bool {
				if id == first && status == "quarantined" {
					attempts.Add(1)
					return false
				}
				return true
			})
			err := v.deliver(context.Background())
			if (limit == "attempts") != (err != nil) {
				t.Fatalf("unexpected delivery error: %v", err)
			}
			state = v3Snapshot(t, v)
			if len(state.Outbox) != 0 || len(state.DeadLetters) != 1 {
				t.Fatalf("dead letter blocked later callbacks: %+v", state)
			}
			dead := state.DeadLetters[0]
			wantReason, wantAttempt, wantCalls := "max_attempts", 8, int32(0)
			if limit == "age" {
				wantReason, wantAttempt = "max_age", 0
			}
			if limit == "attempts" {
				wantCalls = 1
			}
			if dead.JobID != first || dead.Reason != wantReason || dead.Attempt != wantAttempt || attempts.Load() != wantCalls {
				t.Fatalf("bad dead letter: %+v calls=%d", dead, attempts.Load())
			}
			raw, _ := json.Marshal(dead)
			if bytes.Contains(raw, []byte("payload")) || bytes.Contains(raw, []byte("private signed instructions")) {
				t.Fatal("dead letter contains payload")
			}
			audit, err := os.ReadFile(filepath.Join(v.storage.dir, "audit.jsonl"))
			if err != nil || !bytes.Contains(audit, []byte("v3_callback_dead_letter_"+wantReason)) ||
				bytes.Contains(audit, []byte("private signed instructions")) {
				t.Fatalf("missing or unsafe dead-letter audit: %s %v", audit, err)
			}
			if state.Jobs[first].Payload != "private signed instructions" {
				t.Fatal("dead lettering removed original job")
			}
			if err := v.deliver(context.Background()); err != nil || attempts.Load() != wantCalls {
				t.Fatal("dead letter was retried")
			}
			state.DeadLetters[0].Reason = "invalid"
			if err := v.write(state); err != nil {
				t.Fatal(err)
			}
			if _, err := v.read(); err == nil {
				t.Fatal("corrupt dead letter accepted with empty outbox")
			}
		})
	}
}

func TestV3OldOutboxGetsDurableAge(t *testing.T) {
	_, v := v3Fixture(t, false)
	state := v3OutboxFixture(t, v)
	for i := range state.Outbox {
		state.Outbox[i].CreatedAt = 0
		state.Outbox[i].NextAt = time.Now().Add(time.Hour).Unix()
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	delete(old, "deadLetters")
	var events []map[string]any
	if err := json.Unmarshal(old["outbox"], &events); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		delete(event, "createdAt")
	}
	old["outbox"], _ = json.Marshal(events)
	raw, _ = json.Marshal(old)
	if err := os.WriteFile(filepath.Join(v.storage.dir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	if err := v.deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	state = v3Snapshot(t, v)
	for _, event := range state.Outbox {
		if event.CreatedAt < before || event.CreatedAt > time.Now().Unix() {
			t.Fatalf("missing conservative migration timestamp: %+v", event)
		}
	}
	if len(state.DeadLetters) != 0 {
		t.Fatal("legacy event discarded during migration")
	}
	raw, err = os.ReadFile(filepath.Join(v.storage.dir, "state.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"createdAt":`)) {
		t.Fatal("migration age not persisted")
	}
}

func TestV3PermanentCallbackStopsAfterEightAttempts(t *testing.T) {
	_, v := v3Fixture(t, false)
	state := v3OutboxFixture(t, v)
	first := state.Outbox[0].Job.Scope.JobID
	var attempts atomic.Int32
	v3CallbackFixture(t, v, func(id, status string) bool {
		if id == first && status == "quarantined" {
			attempts.Add(1)
			return false
		}
		return true
	})
	for n := 1; n <= 8; n++ {
		state = v3Snapshot(t, v)
		state.Outbox[0].NextAt = 0
		if err := v.write(state); err != nil {
			t.Fatal(err)
		}
		if err := v.deliver(context.Background()); err == nil || attempts.Load() != int32(n) {
			t.Fatalf("attempt %d: calls=%d err=%v", n, attempts.Load(), err)
		}
	}
	state = v3Snapshot(t, v)
	if len(state.Outbox) != 0 || len(state.DeadLetters) != 1 || state.DeadLetters[0].Attempt != 8 {
		t.Fatal("permanent failure was not capped at eight attempts")
	}
	if err := v.deliver(context.Background()); err != nil || attempts.Load() != 8 {
		t.Fatal("ninth attempt made for a dead letter")
	}
}

func TestV3EscapedSixKiBPayloadAndSeparateBodyLimits(t *testing.T) {
	// A patch-shaped 6 KiB payload whose quotes/newlines expand on the wire.
	prefix := "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n"
	payload := prefix + strings.Repeat("+\"\n", (6144-len(prefix))/3)
	payload += strings.Repeat("\n", 6144-len(payload))
	s, _ := v3Fixture(t, false)
	body := v3Body("submit", payload, time.Now().Add(time.Minute).Unix(), "build")
	if len(payload) != 6144 || len(body) <= dispatchMaxBody {
		t.Fatal("fixture does not exercise expanded JSON payload")
	}
	if w := serveDispatch(s, v3Request(body, strings.Repeat("a", 32))); w.Code != 202 {
		t.Fatalf("escaped patch rejected: %d %s", w.Code, w.Body)
	}
	for _, size := range []int{dispatchV3MaxBody, dispatchV3MaxBody + 1} {
		padded := append(bytes.Clone(body), bytes.Repeat([]byte(" "), size-len(body))...)
		want := 202
		if size > dispatchV3MaxBody {
			want = 400
		}
		if w := serveDispatch(s, v3Request(padded, fmt.Sprintf("%032x", size))); w.Code != want {
			t.Fatalf("v3 body size %d: %d %s", size, w.Code, w.Body)
		}
	}
	v2 := dispatchTestBody("submit", dispatchTestScope())
	for _, size := range []int{dispatchMaxBody, dispatchMaxBody + 1} {
		padded := append(bytes.Clone(v2), bytes.Repeat([]byte(" "), size-len(v2))...)
		want := 202
		if size > dispatchMaxBody {
			want = 400
		}
		if w := serveDispatch(s, dispatchTestRequest(padded, fmt.Sprintf("%032x", size))); w.Code != want {
			t.Fatalf("v2 body size %d: %d %s", size, w.Code, w.Body)
		}
	}
}

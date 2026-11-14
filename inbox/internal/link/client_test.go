package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"omni.local/inbox/internal/inbox"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const project = "11111111-1111-4111-8111-111111111111"
const jobID = "44444444-4444-4444-8444-444444444444"

func audit(Event) error { return nil }
func TestCrossLanguage(t *testing.T) {
	origin := os.Getenv("LINK_TEST_URL")
	if origin == "" {
		t.Skip("run through Jackboy integration suite for real TLS/database/runner")
	}
	pem, err := os.ReadFile(os.Getenv("LINK_TEST_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("invalid test CA")
	}
	events := []Event{}
	stateDir := t.TempDir()
	stateRoot, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	stateStore := NewFileHandshakeStateStore(stateRoot, stateDir)
	newClient := func() *Client {
		c, err := New(origin, "omni-review", project, strings.Repeat("b", 64), strings.Repeat("s", 64), func(e Event) error { events = append(events, e); return nil })
		if err != nil {
			t.Fatal(err)
		}
		c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
		c.HandshakeStore = stateStore
		return c
	}
	firstClient := newClient()
	if _, err := firstClient.Connect(context.Background()); err != nil {
		t.Fatal("initial cross-language handshake:", err)
	}
	secondClient := newClient()
	if _, err := secondClient.Connect(context.Background()); err != nil {
		t.Fatal("cross-language handshake reuse:", err)
	}
	if firstClient.session == "" || firstClient.session != secondClient.session {
		t.Fatal("independent clients did not reuse the Jackboy session")
	}
	stateBytes, err := os.ReadFile(filepath.Join(stateDir, handshakeStateFile))
	var persisted HandshakeState
	if err != nil || json.Unmarshal(stateBytes, &persisted) != nil || !uuid.MatchString(persisted.HandshakeID) ||
		strings.Contains(string(stateBytes), firstClient.session) {
		t.Fatalf("invalid cross-language persisted handshake state: %s (%v)", stateBytes, err)
	}
	initialHandshakeID := persisted.HandshakeID
	thirdClient := newClient()
	if _, err := thirdClient.Connect(context.Background()); err != nil {
		t.Fatal("cross-language signed-conflict rotation:", err)
	}
	stateBytes, err = os.ReadFile(filepath.Join(stateDir, handshakeStateFile))
	if err != nil || json.Unmarshal(stateBytes, &persisted) != nil || !uuid.MatchString(persisted.HandshakeID) ||
		persisted.HandshakeID == initialHandshakeID || thirdClient.session == firstClient.session ||
		strings.Contains(string(stateBytes), thirdClient.session) {
		t.Fatalf("signed conflict did not rotate persisted handshake state: %s (%v)", stateBytes, err)
	}
	c := thirdClient
	for _, action := range []string{"submit", "run", "status"} {
		r, e := c.Do(context.Background(), action, jobID)
		if e != nil {
			t.Fatal(action, e)
		}
		if action == "status" && (r.Job.Status != "completed" || r.Job.Result == nil || !r.Job.Result.Passed) {
			t.Fatalf("missing actual result: %+v", r.Job)
		}
	}
	if len(events) < 6 {
		t.Fatal("missing audit events")
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), c.session) || strings.Contains(string(data), c.Secret) {
		t.Fatal("secret leaked to audit")
	}
	t.Log("verified TLS, mutual proof, scoped session, dispatch, real subprocess result and OMNI audit")
}
func TestOriginRestrictions(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=1", "https://example.com#fragment"} {
		if _, err := New(origin, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), audit); err == nil {
			t.Fatal(origin)
		}
	}
}
func TestRecoveryAndIdempotency(t *testing.T) {
	var handshakes, submits atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(data, &input)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		n := r.Header.Get("X-Omni-Nonce")
		ts := r.Header.Get("X-Omni-Timestamp")
		if r.Header.Get("X-Omni-Signature") != inbox.HMACHex(strings.Repeat("s", 64), RequestMessage(ts, n, token, string(data))) {
			t.Error("bad request signature")
		}
		out := Reply{Contract: Contract, RequestNonce: n}
		if input["action"] == "handshake" {
			handshakes.Add(1)
			out.SessionToken = strings.Repeat("a", 64)
			out.ExpiresAt = time.Now().Add(4 * time.Minute)
			out.Ready = true
			out.Capabilities = []string{"protocol.self-test", "jobs.read", "jobs.cancel"}
		} else {
			n := submits.Add(1)
			if input["jobId"] != jobID {
				t.Error("job ID changed")
			}
			if n == 1 {
				w.WriteHeader(401)
				return
			}
			if n == 2 {
				w.WriteHeader(503)
				return
			}
			out.Job = &Job{ID: jobID, Status: "queued"}
		}
		body, _ := json.Marshal(out)
		w.Header().Set("X-Omni-Proof", inbox.HMACHex(strings.Repeat("s", 64), Contract+"\nresponse\n"+n+"\n200\n"+string(body)))
		w.Write(body)
	}))
	defer server.Close()
	c, _ := New(server.URL, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), audit)
	c.HTTP = server.Client()
	r, err := c.Do(context.Background(), "submit", jobID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Job.Status != "queued" || handshakes.Load() != 2 || submits.Load() != 3 {
		t.Fatal("recovery mismatch")
	}
}
func TestRejectProofRedirectAndAuditFailure(t *testing.T) {
	for _, mode := range []string{"proof", "redirect", "audit"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "redirect" {
					w.Header().Set("Location", "https://example.com")
					w.WriteHeader(307)
					return
				}
				w.Write([]byte(`{"contract":"omni.link/v2"}`))
			}))
			defer server.Close()
			sink := audit
			if mode == "audit" {
				sink = func(Event) error { return fmt.Errorf("audit offline") }
			}
			c, _ := New(server.URL, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), sink)
			c.HTTP = server.Client()
			if _, err := c.Do(context.Background(), "submit", jobID); err == nil {
				t.Fatal("expected rejection")
			}
			expected := int32(1)
			if mode == "audit" {
				expected = 0
			}
			if calls.Load() != expected {
				t.Fatal("unexpected network request")
			}
		})
	}
}
func TestRejectUnscopedCommands(t *testing.T) {
	c, _ := New("https://example.com", "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), audit)
	for _, action := range []string{"code", "shell", "merge", "deploy"} {
		if _, err := c.Do(context.Background(), action, jobID); err == nil {
			t.Fatal(action)
		}
	}
}

func TestSafetyReadsJackboyActivationSnapshot(t *testing.T) {
	var handshakes, safetyCalls atomic.Int32
	events := []Event{}
	secret := strings.Repeat("s", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var input map[string]string
		if err := json.Unmarshal(data, &input); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		nonce := r.Header.Get("X-Omni-Nonce")
		if r.Header.Get("X-Omni-Signature") != inbox.HMACHex(secret, RequestMessage(r.Header.Get("X-Omni-Timestamp"), nonce, token, string(data))) {
			t.Error("bad request signature")
		}
		out := Reply{Contract: Contract, RequestNonce: nonce}
		if input["action"] == "handshake" {
			handshakes.Add(1)
			if token != strings.Repeat("b", 64) {
				t.Error("handshake did not use bootstrap credential")
			}
			out.SessionToken = strings.Repeat("a", 64)
			out.ExpiresAt = time.Now().Add(4 * time.Minute)
			out.Ready = true
			out.Capabilities = []string{"protocol.self-test", "jobs.read", "jobs.cancel"}
		} else {
			safetyCalls.Add(1)
			if input["action"] != "safety" || input["projectId"] != project || len(input) != 2 || token != strings.Repeat("a", 64) {
				t.Errorf("unexpected safety request: %#v", input)
			}
			out.Safety = validSafetySnapshot(time.Now())
		}
		body, err := json.Marshal(out)
		if err != nil {
			t.Errorf("encode response: %v", err)
			http.Error(w, "bad response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Omni-Proof", inbox.HMACHex(secret, Contract+"\nresponse\n"+nonce+"\n200\n"+string(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	c, err := New(server.URL, "omni", project, strings.Repeat("b", 64), secret, func(e Event) error {
		events = append(events, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = server.Client()
	snapshot, err := c.Safety(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if handshakes.Load() != 1 || safetyCalls.Load() != 1 ||
		snapshot.KillSwitch == nil || !*snapshot.KillSwitch ||
		snapshot.EmergencyStop == nil || !*snapshot.EmergencyStop ||
		snapshot.CodeEnabled == nil || *snapshot.CodeEnabled ||
		snapshot.Authorization == nil || snapshot.AutonomousAllowed == nil || *snapshot.AutonomousAllowed ||
		snapshot.BlockedBy == nil || *snapshot.BlockedBy != "emergency_stop_engaged" ||
		snapshot.ActivePermits == nil || *snapshot.ActivePermits != 0 {
		t.Fatalf("unexpected safety snapshot: %+v", snapshot)
	}
	if len(events) < 3 || events[len(events)-1].State != "safety_checked" {
		t.Fatalf("missing safety audit event: %+v", events)
	}
}

func TestSafetyRejectsExpiredOrIncompleteSnapshots(t *testing.T) {
	now := time.Now()
	for _, mutate := range []func(*Safety){
		func(s *Safety) { s.ValidUntil = now },
		func(s *Safety) { s.EmergencyStop = nil },
		func(s *Safety) { s.Contract = "wrong" },
	} {
		snapshot := validSafetySnapshot(now)
		mutate(snapshot)
		if err := snapshot.validate(now); err == nil {
			t.Fatalf("accepted invalid safety snapshot: %+v", snapshot)
		}
	}
	for _, field := range []string{"authorization", "blockedBy"} {
		data, err := json.Marshal(validSafetySnapshot(now))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, field)
		data, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot Safety
		if err := json.Unmarshal(data, &snapshot); err == nil {
			t.Fatalf("accepted snapshot missing %q", field)
		}
	}
}

func validSafetySnapshot(now time.Time) *Safety {
	return &Safety{
		Contract:                 "omni.safety/v1",
		CheckedAt:                now,
		ValidUntil:               now.Add(20 * time.Second),
		KillSwitch:               boolPointer(true),
		EmergencyStop:            boolPointer(true),
		CodeEnabled:              boolPointer(false),
		Authorization:            &SafetyAuthorization{ExpiresAt: now.Add(time.Hour)},
		AutonomousAllowed:        boolPointer(false),
		BlockedBy:                stringPointer("emergency_stop_engaged"),
		ManualDiagnosticsAllowed: boolPointer(false),
		ActivePermits:            intPointer(0),
	}
}

func TestSafetySnapshotFutureClockSkew(t *testing.T) {
	now := time.Now()
	for _, offset := range []time.Duration{60 * time.Second, 60*time.Second + time.Nanosecond, 24 * time.Hour} {
		snapshot := validSafetySnapshot(now.Add(offset))
		err := snapshot.validate(now)
		if (err == nil) != (offset <= 60*time.Second) {
			t.Fatalf("clock skew %v: %v", offset, err)
		}
	}
}

func TestHandshakeLockRemainsAnchoredAfterDirectoryReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first := NewFileHandshakeStateStore(root, dir)
	guard, err := first.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := os.Rename(dir, dir+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	second := NewFileHandshakeStateStore(root, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	other, err := second.Lock(ctx)
	if other != nil {
		_ = other.Close()
		t.Fatal("replacement directory bypassed the original state lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected contention on anchored lock, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, handshakeLockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock touched replacement directory: %v", err)
	}
}

func TestHandshakeLockRejectsSymlink(t *testing.T) {
	root, store, dir := testHandshakeStore(t)
	defer root.Close()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, handshakeLockFile)); err != nil {
		t.Fatal(err)
	}
	guard, err := store.Lock(context.Background())
	if guard != nil {
		_ = guard.Close()
	}
	if err == nil {
		t.Fatal("symlink lock accepted")
	}
}

func boolPointer(value bool) *bool       { return &value }
func stringPointer(value string) *string { return &value }
func intPointer(value int) *int          { return &value }

func TestFreshClientsReuseOneHandshakeSession(t *testing.T) {
	dir := t.TempDir()
	root1, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root1.Close()
	root2, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root2.Close()
	store1 := NewFileHandshakeStateStore(root1, dir)
	store2 := NewFileHandshakeStateStore(root2, dir)
	secret := strings.Repeat("s", 64)
	token := strings.Repeat("a", 64)
	expires := time.Now().Add(4 * time.Minute)
	var mu sync.Mutex
	ids := []string{}
	nonces := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var input map[string]string
		if err := json.Unmarshal(data, &input); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		n := r.Header.Get("X-Omni-Nonce")
		if input["action"] != "handshake" || input["projectId"] != project ||
			!handshakeIDPattern.MatchString(input["handshakeId"]) ||
			r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) ||
			r.Header.Get("X-Omni-Signature") != inbox.HMACHex(secret, RequestMessage(r.Header.Get("X-Omni-Timestamp"), n, strings.Repeat("b", 64), string(data))) {
			t.Errorf("invalid handshake request: %#v", input)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		persisted, err := os.ReadFile(filepath.Join(dir, handshakeStateFile))
		if err != nil {
			t.Errorf("state was not committed before handshake: %v", err)
			http.Error(w, "state missing", http.StatusInternalServerError)
			return
		}
		var state HandshakeState
		if json.Unmarshal(persisted, &state) != nil || state.HandshakeID != input["handshakeId"] {
			t.Errorf("request ID not committed before handshake: %s", persisted)
			http.Error(w, "state mismatch", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		ids = append(ids, input["handshakeId"])
		if nonces[n] {
			t.Errorf("reused nonce %q", n)
		}
		nonces[n] = true
		mu.Unlock()
		writeHandshakeSuccess(w, n, secret, token, expires)
	}))
	defer server.Close()

	clients := make([]*Client, 2)
	clients[0] = testClient(t, server, store1, audit)
	clients[1] = testClient(t, server, store2, audit)
	start := make(chan struct{})
	errs := make(chan error, len(clients))
	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			<-start
			_, err := c.Connect(context.Background())
			errs <- err
		}(c)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			files, _ := os.ReadDir(dir)
			t.Fatalf("%v; state directory contains %v", err, files)
		}
	}
	if len(ids) != 2 || ids[0] != ids[1] || clients[0].session != token || clients[1].session != token {
		t.Fatalf("clients did not reuse the same session: ids=%v", ids)
	}
	stateBytes, err := os.ReadFile(filepath.Join(dir, handshakeStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateBytes), token) {
		t.Fatal("bearer session token persisted")
	}
	info, err := os.Stat(filepath.Join(dir, handshakeStateFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("handshake state file is not mode 0600: %v %v", info, err)
	}
}

func TestNewHandshakeIDUsesUUIDFormat(t *testing.T) {
	id, err := newHandshakeID()
	if err != nil {
		t.Fatal(err)
	}
	if !uuid.MatchString(id) || id[14] != '4' || (id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b') {
		t.Fatalf("handshake ID is not a UUIDv4: %q", id)
	}
}

func TestExpiredHandshakeIDRotatesOnlyOnSignedConflict(t *testing.T) {
	root, store, dir := testHandshakeStore(t)
	defer root.Close()
	oldID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	guard, err := store.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Save(HandshakeState{HandshakeID: oldID, ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("s", 64)
	token := strings.Repeat("a", 64)
	expires := time.Now().Add(4 * time.Minute)
	var mu sync.Mutex
	ids, nonces := []string{}, map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var input map[string]string
		if err := json.Unmarshal(data, &input); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		n := r.Header.Get("X-Omni-Nonce")
		mu.Lock()
		ids = append(ids, input["handshakeId"])
		if nonces[n] {
			t.Errorf("reused nonce %q", n)
		}
		nonces[n] = true
		attempt := len(ids)
		mu.Unlock()
		if attempt == 1 {
			writeHandshakeConflict(w, n, secret)
			return
		}
		stateBytes, err := os.ReadFile(filepath.Join(dir, handshakeStateFile))
		var state HandshakeState
		if err != nil || json.Unmarshal(stateBytes, &state) != nil || state.HandshakeID != input["handshakeId"] {
			t.Errorf("rotated ID was not committed before retry: %s (%v)", stateBytes, err)
			http.Error(w, "state mismatch", http.StatusInternalServerError)
			return
		}
		writeHandshakeSuccess(w, n, secret, token, expires)
	}))
	defer server.Close()
	c := testClient(t, server, store, audit)
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != oldID || ids[1] == oldID || !handshakeIDPattern.MatchString(ids[1]) || len(nonces) != 2 {
		t.Fatalf("wrong conflict rotation: ids=%v nonces=%v", ids, nonces)
	}
}

func TestHandshakeFailuresReuseCommittedID(t *testing.T) {
	root, store, dir := testHandshakeStore(t)
	defer root.Close()
	secret := strings.Repeat("s", 64)
	token := strings.Repeat("a", 64)
	expires := time.Now().Add(4 * time.Minute)
	var mu sync.Mutex
	ids, nonces := []string{}, map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var input map[string]string
		if err := json.Unmarshal(data, &input); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		n := r.Header.Get("X-Omni-Nonce")
		mu.Lock()
		ids = append(ids, input["handshakeId"])
		if nonces[n] {
			t.Errorf("reused nonce %q", n)
		}
		nonces[n] = true
		attempt := len(ids)
		mu.Unlock()
		stateBytes, err := os.ReadFile(filepath.Join(dir, handshakeStateFile))
		var state HandshakeState
		if err != nil || json.Unmarshal(stateBytes, &state) != nil || state.HandshakeID != input["handshakeId"] {
			t.Errorf("handshake ID was not persisted: %s (%v)", stateBytes, err)
			http.Error(w, "state mismatch", http.StatusInternalServerError)
			return
		}
		if attempt == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		if attempt == 2 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"handshake_id_expired_or_conflict"}`))
			return
		}
		writeHandshakeSuccess(w, n, secret, token, expires)
	}))
	defer server.Close()

	first := testClient(t, server, store, audit)
	if _, err := first.Connect(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected transport failure, got %v", err)
	}
	second := testClient(t, server, store, audit)
	if _, err := second.Connect(context.Background()); err == nil {
		t.Fatal("expected unsigned conflict failure")
	}
	auditFailure := func(e Event) error {
		if e.State == "connected" {
			return errors.New("audit unavailable")
		}
		return nil
	}
	third := testClient(t, server, store, auditFailure)
	if _, err := third.Connect(context.Background()); err == nil {
		t.Fatal("expected connected audit failure")
	}
	fourth := testClient(t, server, store, audit)
	if _, err := fourth.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 || ids[0] != ids[1] || ids[1] != ids[2] || ids[2] != ids[3] || len(nonces) != 4 {
		t.Fatalf("generic failures rotated the handshake ID: ids=%v nonces=%v", ids, nonces)
	}
	stateBytes, err := os.ReadFile(filepath.Join(dir, handshakeStateFile))
	if err != nil || strings.Contains(string(stateBytes), token) {
		t.Fatalf("invalid persisted state after failure: %s (%v)", stateBytes, err)
	}
}

func testHandshakeStore(t *testing.T) (*os.Root, *FileHandshakeStateStore, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	return root, NewFileHandshakeStateStore(root, dir), dir
}

func testClient(t *testing.T, server *httptest.Server, store HandshakeStateStore, sink func(Event) error) *Client {
	t.Helper()
	c, err := New(server.URL, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), sink)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = server.Client()
	c.HandshakeStore = store
	return c
}

func writeHandshakeSuccess(w http.ResponseWriter, nonce, secret, token string, expires time.Time) {
	out := Reply{
		Contract:     Contract,
		RequestNonce: nonce,
		SessionToken: token,
		ExpiresAt:    expires,
		Capabilities: []string{"protocol.self-test", "jobs.read", "jobs.cancel"},
		Ready:        true,
	}
	body, _ := json.Marshal(out)
	w.Header().Set("X-Omni-Proof", inbox.HMACHex(secret, Contract+"\nresponse\n"+nonce+"\n200\n"+string(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeHandshakeConflict(w http.ResponseWriter, nonce, secret string) {
	out := map[string]string{"contract": Contract, "requestNonce": nonce, "error": "handshake_id_expired_or_conflict"}
	body, _ := json.Marshal(out)
	w.Header().Set("X-Omni-Proof", inbox.HMACHex(secret, Contract+"\nresponse\n"+nonce+"\n409\n"+string(body)))
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write(body)
}

func TestUntrustedTLSIsRejected(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	c, _ := New(server.URL, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), audit)
	if _, err := c.Connect(context.Background()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("sent credentials over untrusted TLS")
	}
}

func replyServer(t *testing.T, onHandshake func(), onOp func(action string, w http.ResponseWriter) (handled bool)) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(data, &input)
		n := r.Header.Get("X-Omni-Nonce")
		out := Reply{Contract: Contract, RequestNonce: n}
		status := 200
		if input["action"] == "handshake" {
			if onHandshake != nil {
				onHandshake()
			}
			out.SessionToken = strings.Repeat("a", 64)
			out.ExpiresAt = time.Now().Add(4 * time.Minute)
			out.Ready = true
			out.Capabilities = []string{"protocol.self-test", "jobs.read", "jobs.cancel"}
		} else {
			if onOp(input["action"], w) {
				return
			}
			out.Job = &Job{ID: input["jobId"], Status: "queued"}
			status = 202
		}
		body, _ := json.Marshal(out)
		w.Header().Set("X-Omni-Proof", inbox.HMACHex(strings.Repeat("s", 64), Contract+"\nresponse\n"+n+"\n"+fmt.Sprint(status)+"\n"+string(body)))
		w.WriteHeader(status)
		w.Write(body)
	}))
}
func scaled(t *testing.T, s *httptest.Server) *Client {
	c, err := New(s.URL, "omni", project, strings.Repeat("b", 64), strings.Repeat("s", 64), audit)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = s.Client()
	c.requestLimit, c.handshakeLimit = 300*time.Millisecond, 2*time.Second
	return c
}
func TestTimeoutConstants(t *testing.T) {
	if HandshakeTimeout != 10*time.Second || RequestTimeout != 5*time.Second {
		t.Fatal("timeouts changed")
	}
	c := &Client{}
	if c.limit("handshake") != 10*time.Second || c.limit("submit") != 5*time.Second || c.limit("status") != 5*time.Second || c.limit("cancel") != 5*time.Second {
		t.Fatal("wrong default limits")
	}
	c.requestLimit, c.handshakeLimit = time.Hour, time.Hour
	if c.limit("handshake") != HandshakeTimeout || c.limit("run") != RequestTimeout {
		t.Fatal("limits must not exceed caps")
	}
}
func TestSlowHandshakeSucceedsWithinHandshakeTimeout(t *testing.T) {
	var ops atomic.Int32
	s := replyServer(t, func() { time.Sleep(900 * time.Millisecond) }, func(string, http.ResponseWriter) bool { ops.Add(1); return false })
	defer s.Close()
	c := scaled(t, s) // 900ms exceeds the 300ms request limit but not the 2s handshake limit
	r, err := c.Do(context.Background(), "submit", jobID)
	if err != nil || r.Job.Status != "queued" || ops.Load() != 1 {
		t.Fatal(err, ops.Load())
	}
}
func TestHandshakeTimeoutFailsBeforeAnyJobRequest(t *testing.T) {
	var ops atomic.Int32
	s := replyServer(t, func() { time.Sleep(3 * time.Second) }, func(string, http.ResponseWriter) bool { ops.Add(1); return false })
	defer s.Close()
	c := scaled(t, s)
	start := time.Now()
	_, err := c.Do(context.Background(), "submit", jobID)
	if err == nil || ops.Load() != 0 {
		t.Fatal("handshake timeout must fail and send no job request", err, ops.Load())
	}
	if d := time.Since(start); d < 1900*time.Millisecond || d > 2800*time.Millisecond {
		t.Fatal("handshake limit not applied", d)
	}
}
func TestJobRequestsKeepShortTimeout(t *testing.T) {
	var ops atomic.Int32
	s := replyServer(t, nil, func(string, http.ResponseWriter) bool { ops.Add(1); time.Sleep(900 * time.Millisecond); return false })
	defer s.Close()
	c := scaled(t, s)
	start := time.Now()
	if _, err := c.Do(context.Background(), "status", jobID); err == nil {
		t.Fatal("slow job request must time out at the request limit")
	}
	// Each attempt is cut at ~300ms, not 2s: 3 existing same-ID attempts finish well under one handshake limit.
	if d := time.Since(start); d > 1900*time.Millisecond || ops.Load() != 3 {
		t.Fatal(d, ops.Load())
	}
}
func TestLostSubmitResponseDoesNotCreateDuplicateJob(t *testing.T) {
	var created, seen atomic.Int32
	known := map[string]bool{}
	var mu = make(chan struct{}, 1)
	s := replyServer(t, nil, func(action string, w http.ResponseWriter) bool {
		mu <- struct{}{}
		if !known[jobID] {
			known[jobID] = true
			created.Add(1)
		}
		<-mu
		if seen.Add(1) == 1 {
			time.Sleep(900 * time.Millisecond) // response lost to the client's request timeout
		}
		return false
	})
	defer s.Close()
	c := scaled(t, s)
	r, err := c.Do(context.Background(), "submit", jobID)
	if err != nil || r.Job.ID != jobID || created.Load() != 1 || seen.Load() != 2 {
		t.Fatal(err, created.Load(), seen.Load())
	}
}

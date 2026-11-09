package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"omni.local/inbox/internal/inbox"
	"os"
	"strings"
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
	c, err := New(origin, "omni-review", project, strings.Repeat("b", 64), strings.Repeat("s", 64), func(e Event) error { events = append(events, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
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

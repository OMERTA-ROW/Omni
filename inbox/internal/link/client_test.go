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

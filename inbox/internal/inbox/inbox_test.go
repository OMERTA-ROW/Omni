package inbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	key    = "k-0123456789abcdef0123456789abcdef"
	secret = "test-secret"
	jobID  = "11111111-2222-4333-8444-555555555555"
)

// Same vector is asserted in Jackboy's src/lib/omni-link.test.ts.
func TestSharedVector(t *testing.T) {
	if got := HMACHex(secret, "jackboy-omni-vector"); got != "8797526ca23119cd7fe313d6c824069756534bdb50782ea449d7cf62f1374d91" {
		t.Fatalf("vector mismatch: %s", got)
	}
}

func newServer(t *testing.T) (*Server, http.Handler) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{APIKey: key, Secret: secret, Version: "test", AllowedRepos: map[string]bool{"OMERTA-ROW/Omni": true}, Store: st}
	return s, s.Handler()
}

func do(h http.Handler, method, path, auth, idem, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if idem != "" {
		r.Header.Set("Idempotency-Key", idem)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRejectsMissingOrWrongBearer(t *testing.T) {
	_, h := newServer(t)
	if c := do(h, "POST", "/jackboy/jobs", "", "", "{}").Code; c != 401 {
		t.Fatalf("no auth: %d", c)
	}
	if c := do(h, "POST", "/jackboy/jobs", "Bearer wrong", "", "{}").Code; c != 401 {
		t.Fatalf("wrong auth: %d", c)
	}
}

func TestHandshakeProvesSharedSecret(t *testing.T) {
	_, h := newServer(t)
	ch := strings.Repeat("a", 64)
	w := do(h, "POST", "/jackboy/handshake", "Bearer "+key, "", `{"challenge":"`+ch+`"}`)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["contract"] != "omni.handshake/v1" || out["proof"] != HMACHex(secret, ch) {
		t.Fatalf("bad handshake %d %v", w.Code, out)
	}
}

func TestJobsAreIdempotentAndRepoAllowlisted(t *testing.T) {
	s, h := newServer(t)
	body := `{"contract":"omni.job/v1","jobId":"` + jobID + `","kind":"test","repo":"OMERTA-ROW/Omni","instructions":"run tests"}`
	if w := do(h, "POST", "/jackboy/jobs", "Bearer "+key, jobID, body); w.Code != 202 || !strings.Contains(w.Body.String(), `"duplicate":false`) {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", "/jackboy/jobs", "Bearer "+key, jobID, body); !strings.Contains(w.Body.String(), `"duplicate":true`) {
		t.Fatalf("second: %s", w.Body)
	}
	if c := do(h, "POST", "/jackboy/jobs", "Bearer "+key, "other", body).Code; c != 400 {
		t.Fatalf("idempotency mismatch: %d", c)
	}
	bad := strings.Replace(body, "OMERTA-ROW/Omni", "someone/else", 1)
	if c := do(h, "POST", "/jackboy/jobs", "Bearer "+key, jobID, bad).Code; c != 403 {
		t.Fatalf("repo allowlist: %d", c)
	}
	if j, _ := s.Store.Get(jobID); j.Status != "queued" {
		t.Fatalf("status %s", j.Status)
	}
}

// gitRepo creates a local repository with a tiny Go module and one passing test.
func gitRepo(t *testing.T) string {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	d := t.TempDir()
	write := func(p, s string) { os.WriteFile(filepath.Join(d, p), []byte(s), 0o644) }
	write("go.mod", "module x\n\ngo 1.21\n")
	write("x.go", "package x\n\nfunc Add(a, b int) int { return a + b }\n")
	write("x_test.go", "package x\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) { if Add(1, 2) != 3 { t.Fatal(\"bad\") } }\n")
	for _, a := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"}} {
		c := exec.Command("git", a...)
		c.Dir = d
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", a, out)
		}
	}
	return d
}

func worker(t *testing.T, repo string, cb string) *Worker {
	st, _ := NewStore(t.TempDir())
	return &Worker{Store: st, Secret: secret, CallbackURL: cb, CloneURL: func(string) string { return "file://" + repo }, TestTimeout: 2 * time.Minute}
}

const breakPatch = `--- a/x.go
+++ b/x.go
@@ -1,3 +1,3 @@
 package x
 
-func Add(a, b int) int { return a + b }
+func Add(a, b int) int { return a - b }
`

func TestWorkerAppliesPatchAndReportsRealTests(t *testing.T) {
	repo := gitRepo(t)
	w := worker(t, repo, "")
	ok := w.Process(context.Background(), &Job{ID: jobID, Kind: "code", Repo: "OMERTA-ROW/Omni", Patch: strings.Replace(breakPatch, "a - b", "b + a", 1)})
	if ok.Status != "completed" || ok.Tests == nil || !ok.Tests.Passed || !strings.Contains(ok.DiffStat, "x.go") {
		t.Fatalf("expected pass: %+v", ok)
	}
	bad := w.Process(context.Background(), &Job{ID: jobID, Kind: "code", Repo: "OMERTA-ROW/Omni", Patch: breakPatch})
	if bad.Status != "failed" || bad.Tests == nil || bad.Tests.Passed {
		t.Fatalf("expected failing tests: %+v", bad)
	}
	none := w.Process(context.Background(), &Job{ID: jobID, Kind: "code", Repo: "OMERTA-ROW/Omni"})
	if none.Status != "failed" || none.Tests != nil {
		t.Fatalf("code job without patch must fail honestly: %+v", none)
	}
}

func TestEndToEndQueueToSignedCallback(t *testing.T) {
	repo := gitRepo(t)
	got := make(chan Result, 4)
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if Sign(secret, r.Header.Get("X-Omni-Timestamp"), r.Header.Get("X-Omni-Nonce"), string(b)) != r.Header.Get("X-Omni-Signature") {
			http.Error(w, "bad sig", 401)
			return
		}
		var res Result
		json.Unmarshal(b, &res)
		got <- res
	}))
	defer cb.Close()
	w := worker(t, repo, cb.URL)
	w.Store.Put(Job{ID: jobID, Kind: "test", Repo: "OMERTA-ROW/Omni"})
	w.drain(context.Background())
	if r := <-got; r.Status != "running" {
		t.Fatalf("first callback %s", r.Status)
	}
	if r := <-got; r.Status != "completed" || r.Tests == nil || !r.Tests.Passed {
		t.Fatalf("final callback %+v", r)
	}
	if j, _ := w.Store.Get(jobID); !j.Reported {
		t.Fatal("result not marked reported")
	}
}

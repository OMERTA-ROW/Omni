package inbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const resultContract = "omni.job-result/v1"

// Worker picks up queued jobs, applies the supplied patch in a fresh isolated checkout,
// runs the repository's Go tests and reports the real outcome to Jackboy.
// It never pushes, merges or deploys.
type Worker struct {
	Store       *Store
	Secret      string
	CallbackURL string // fixed by OMNI configuration; a job can never redirect callbacks
	GitToken    string // optional read token for private repositories
	TestTimeout time.Duration
	CloneURL    func(repo string) string // overridable in tests
	HTTP        *http.Client
	Wake        chan struct{}
}

// Run processes jobs until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	if err := w.Store.RequeueStale(); err != nil {
		log.Printf("requeue: %v", err)
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		w.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-w.Wake:
		}
	}
}

func (w *Worker) drain(ctx context.Context) {
	w.reportPending(ctx)
	for ctx.Err() == nil {
		j, err := w.Store.Claim()
		if err != nil || j == nil {
			return
		}
		w.report(ctx, Result{Contract: resultContract, JobID: j.ID, Status: "running", Summary: "OMNI started the job"})
		res := w.Process(ctx, j)
		if _, err := w.Store.Update(j.ID, func(x *Job) { x.Status, x.Result = res.Status, &res }); err != nil {
			log.Printf("save %s: %v", j.ID, err)
		}
		w.reportPending(ctx)
	}
}

// reportPending delivers finished results; failures stay unreported and are retried next pass.
func (w *Worker) reportPending(ctx context.Context) {
	jobs, _ := w.Store.Unreported()
	for _, j := range jobs {
		if j.Result != nil && w.report(ctx, *j.Result) == nil {
			w.Store.Update(j.ID, func(x *Job) { x.Reported = true })
		}
	}
}

// Process runs one job and returns its real result.
func (w *Worker) Process(ctx context.Context, j *Job) Result {
	r := Result{Contract: resultContract, JobID: j.ID}
	fail := func(msg string) Result { r.Status, r.Summary = "failed", msg; return r }
	if strings.TrimSpace(j.Patch) == "" && j.Kind == "code" {
		return fail("No patch was supplied and OMNI has no code-writing model configured yet, so nothing was changed.")
	}
	dir, err := os.MkdirTemp("", "omni-job-")
	if err != nil {
		return fail("could not create a workspace: " + err.Error())
	}
	defer os.RemoveAll(dir)
	clone := w.CloneURL
	if clone == nil {
		clone = func(repo string) string { return "https://github.com/" + repo + ".git" }
	}
	args := []string{}
	if w.GitToken != "" {
		args = append(args, "-c", "http.extraHeader=Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+w.GitToken)))
	}
	args = append(args, "clone", "--depth", "1", clone(j.Repo), dir)
	if out, err := run(ctx, "", 2*time.Minute, "git", args...); err != nil {
		return fail("clone failed: " + trim(out, 1500))
	}
	if strings.TrimSpace(j.Patch) != "" {
		pf := filepath.Join(os.TempDir(), "omni-"+j.ID+".patch")
		if err := os.WriteFile(pf, []byte(j.Patch), 0o600); err != nil {
			return fail("could not stage patch")
		}
		defer os.Remove(pf)
		if out, err := run(ctx, dir, time.Minute, "git", "apply", "--check", pf); err != nil {
			return fail("patch does not apply: " + trim(out, 1500))
		}
		if out, err := run(ctx, dir, time.Minute, "git", "apply", pf); err != nil {
			return fail("patch apply failed: " + trim(out, 1500))
		}
		stat, _ := run(ctx, dir, time.Minute, "git", "diff", "--stat")
		r.DiffStat = trim(stat, 4000)
	}
	passed, output := w.runTests(ctx, dir)
	r.Tests = &Tests{Passed: passed, Output: trim(output, 8000)}
	if passed {
		r.Status, r.Summary = "completed", "Patch applied in an isolated checkout and tests passed. Nothing was pushed."
	} else {
		r.Status, r.Summary = "failed", "Tests failed or none could run. Nothing was pushed."
	}
	return r
}

// runTests runs `go test ./...` in every Go module of the checkout.
func (w *Worker) runTests(ctx context.Context, dir string) (bool, string) {
	timeout := w.TestTimeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	var mods []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == "go.mod" {
			mods = append(mods, filepath.Dir(p))
		}
		return nil
	})
	if len(mods) == 0 {
		return false, "No Go module found, so no tests ran."
	}
	var all strings.Builder
	ok := true
	for _, m := range mods {
		rel, _ := filepath.Rel(dir, m)
		out, err := run(ctx, m, timeout, "go", "test", "./...")
		fmt.Fprintf(&all, "$ (%s) go test ./...\n%s\n", rel, out)
		if err != nil {
			ok = false
		}
	}
	return ok, all.String()
}

func run(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GOFLAGS=-mod=readonly")
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	err := cmd.Run()
	return b.String(), err
}

// report sends a signed result to Jackboy, retrying up to three times.
func (w *Worker) report(ctx context.Context, r Result) error {
	if w.CallbackURL == "" {
		return fmt.Errorf("no callback URL configured")
	}
	body, err := jsonMarshal(r)
	if err != nil {
		return err
	}
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		nb := make([]byte, 16)
		rand.Read(nb)
		nonce, ts := hex.EncodeToString(nb), strconv.FormatInt(time.Now().Unix(), 10)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.CallbackURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Omni-Timestamp", ts)
		req.Header.Set("X-Omni-Nonce", nonce)
		req.Header.Set("X-Omni-Signature", Sign(w.Secret, ts, nonce, string(body)))
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		last = fmt.Errorf("callback HTTP %d", resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != 429 {
			return last
		}
	}
	return last
}

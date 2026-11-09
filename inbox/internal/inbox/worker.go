package inbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const resultContract = "omni.job-result/v1"
const maxShellOutput = 64 << 10

// Worker picks up queued jobs, applies the supplied patch in a fresh isolated checkout,
// runs the repository's Go tests and reports the real outcome to Jackboy.
// It never pushes, merges or deploys.
type Worker struct {
	Store         *Store
	Secret        string
	CallbackURL   string // fixed by OMNI configuration; a job can never redirect callbacks
	GitToken      string // optional read token for private repositories
	TestTimeout   time.Duration
	CloneURL      func(repo string) string // overridable in tests
	ShellUser     string
	ShellUID      uint32
	ShellGID      uint32
	ShellExecPath string
	HTTP          *http.Client
	Wake          chan struct{}
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
	if j.Kind == "shell" {
		return w.processShell(ctx, j, r)
	}
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

func (w *Worker) processShell(ctx context.Context, j *Job, r Result) Result {
	fail := func(msg string) Result {
		r.Status, r.Summary = "failed", msg
		r.Shell = &ShellResult{ExitCode: -1, Stderr: msg}
		return r
	}
	dir, err := os.MkdirTemp("/tmp", "omni-shell-")
	if err != nil {
		return fail("could not create a workspace")
	}
	defer os.RemoveAll(dir)
	if j.Repo != "" {
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
	}
	timeout := time.Duration(j.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Minute
	}
	started := time.Now()
	sr, err := w.runShell(ctx, dir, j.Command, timeout)
	if err != nil && sr.ExitCode == -1 && sr.Stderr == "" {
		sr.Stderr = err.Error()
	}
	sr.DurationMs = time.Since(started).Milliseconds()
	r.Shell = &sr
	switch {
	case err != nil && sr.TimedOut:
		r.Status, r.Summary = "failed", "Shell command timed out."
	case err != nil:
		r.Status, r.Summary = "failed", fmt.Sprintf("Shell command exited with code %d.", sr.ExitCode)
	default:
		r.Status, r.Summary = "completed", "Shell command completed successfully."
	}
	return r
}

func (w *Worker) runShell(ctx context.Context, dir, command string, timeout time.Duration) (ShellResult, error) {
	result := ShellResult{ExitCode: -1}
	if w.ShellUID == 0 || w.ShellGID == 0 {
		return result, fmt.Errorf("shell sandbox user is unavailable")
	}
	userInfo, err := user.LookupId(strconv.FormatUint(uint64(w.ShellUID), 10))
	if err != nil || w.ShellUser == "" || userInfo.Username != w.ShellUser {
		return result, fmt.Errorf("omni-sandbox user is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmdName, args := "/bin/sh", []string{"-c", command}
	helperUsed := false
	sameIdentity := uint32(os.Geteuid()) == w.ShellUID && uint32(os.Getegid()) == w.ShellGID
	if sameIdentity {
		cmdName, args = "/bin/sh", []string{"-c", command}
	} else if os.Geteuid() == 0 {
		setpriv, err := exec.LookPath("setpriv")
		if err != nil {
			return result, fmt.Errorf("setpriv unavailable")
		}
		cmdName = setpriv
		args = []string{"--reuid=" + strconv.FormatUint(uint64(w.ShellUID), 10), "--regid=" + strconv.FormatUint(uint64(w.ShellGID), 10), "--clear-groups", "--no-new-privs", "--", "/bin/sh", "-c", command}
	} else if uint32(os.Geteuid()) != w.ShellUID || uint32(os.Getegid()) != w.ShellGID {
		if w.ShellExecPath == "" || w.ShellUser != "omni-sandbox" {
			return result, fmt.Errorf("omni-sandbox privilege helper unavailable")
		}
		cmdName = w.ShellExecPath
		args = []string{"--run", dir, strconv.FormatUint(uint64(w.ShellUID), 10), strconv.FormatUint(uint64(w.ShellGID), 10), command}
		helperUsed = true
	}
	cmd := exec.CommandContext(ctx, cmdName, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + dir,
		"TMPDIR=" + dir,
		"LANG=C.UTF-8",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if helperUsed {
			return syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 8 * time.Second
	stdout, stderr := &boundedBuffer{limit: maxShellOutput}, &boundedBuffer{limit: maxShellOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	result.Stdout, result.Stderr = stdout.String(), stderr.String()
	result.Truncated = stdout.truncated || stderr.truncated
	result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if helperUsed {
		if cleanupErr := w.cleanupShellWorkspace(dir); cleanupErr != nil {
			if result.Stderr == "" {
				result.Stderr = cleanupErr.Error()
			}
			if err == nil {
				err = cleanupErr
				result.ExitCode = -1
			}
		}
	}
	switch {
	case err == nil:
		result.ExitCode = 0
	case result.TimedOut:
		result.ExitCode = 124
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		}
	}
	return result, err
}

func (w *Worker) cleanupShellWorkspace(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.ShellExecPath, "--cleanup", dir)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("workspace cleanup failed: %s", trim(string(out), 500))
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining > len(p) {
		remaining = len(p)
	}
	if remaining > 0 {
		_, _ = b.Buffer.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = b.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
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

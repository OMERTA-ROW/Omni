package inbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v: %s", err, out)
	}
}

func TestDisabledWorkerDoesNotClaimExecuteOrReport(t *testing.T) {
	s, _ := newServer(t)
	if _, _, err := s.Store.Put(Job{ID: jobID, Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Store: s.Store}
	// A zero-value worker returns even with a live context, without touching
	// the queue, cloning a repository, or issuing a result callback.
	w.Run(context.Background())
	w.drain(context.Background())
	w.reportPending(context.Background())
	j, err := s.Store.Get(jobID)
	if err != nil || j.Status != "queued" || j.Reported {
		t.Fatalf("disabled worker changed job: %+v, %v", j, err)
	}
}

func TestRestartQuarantinesHistoricalJobsEvenWithWorkerEnabled(t *testing.T) {
	for _, status := range []string{"queued", "running", "completed", "failed", "quarantined"} {
		t.Run(status, func(t *testing.T) {
			dir := privateTempDir(t)
			s, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Put(Job{ID: jobID, Kind: "test"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Update(jobID, func(j *Job) { j.Status = status }); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			w := &Worker{Enabled: true, Store: reopened}
			w.drain(context.Background())
			j, err := reopened.Get(jobID)
			want := status
			if status == "queued" || status == "running" {
				want = "quarantined"
			}
			if err != nil || j.Status != want {
				t.Fatalf("restart: %+v, %v; want %s", j, err, want)
			}
			if _, created, err := reopened.Put(Job{ID: jobID, Kind: "test"}); err != nil || created {
				t.Fatalf("duplicate must not release quarantine: created=%v err=%v", created, err)
			}
			if claimed, err := reopened.Claim(); err != nil || claimed != nil {
				t.Fatalf("historical job claimed: %+v, %v", claimed, err)
			}
			freshID := "22222222-2222-4333-8444-555555555555"
			if _, _, err := reopened.Put(Job{ID: freshID, Kind: "test"}); err != nil {
				t.Fatal(err)
			}
			if claimed, err := reopened.Claim(); err != nil || claimed == nil || claimed.ID != freshID {
				t.Fatalf("fresh submission not claimable: %+v, %v", claimed, err)
			}
		})
	}
}

func TestPrivateDataDirectory(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "jobs")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory: %v, %v", info, err)
	}
	if _, _, err := s.Put(Job{ID: jobID}); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(dir, jobID+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private job record: %v, %v", info, err)
	}
}

func TestDataDirectoryFailsClosed(t *testing.T) {
	base := privateTempDir(t)
	if err := os.Symlink(base, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"relative", "/", base + "/../jobs", filepath.Join(base, "link"), filepath.Join(base, "link", "jobs"), file, filepath.Join(base, "missing", "jobs")} {
		if _, err := NewStore(dir); err == nil {
			t.Errorf("accepted unsafe data directory %q", dir)
		}
	}
}

func TestUnreadableHistoricalRecordsBlockStartup(t *testing.T) {
	for _, kind := range []string{"malformed", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTempDir(t)
			file := filepath.Join(dir, jobID+".json")
			switch kind {
			case "malformed":
				if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				target := filepath.Join(privateTempDir(t), "target")
				if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hardlink" {
					link = os.Link
				}
				if err := link(target, file); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewStore(dir); err == nil {
				t.Fatal("startup accepted an unsafe historical record")
			}
		})
	}
}

func TestCodeAndTestJobsCannotInheritSecrets(t *testing.T) {
	for _, name := range []string{"OMNI_API_KEY", "OMNI_CALLBACK_SECRET", "API_KEY", "DATABASE_URL", "RAILWAY_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GOENV", "GOTOOLCHAIN", "GOFLAGS"} {
		t.Setenv(name, "must-not-reach-job")
	}
	for _, kind := range []string{"code", "test"} {
		t.Run(kind, func(t *testing.T) {
			repo := gitRepo(t)
			w := worker(t, repo, "")
			test := fmt.Sprintf(`package x
import ("os"; "strings"; "testing")
func TestEnvironment(t *testing.T) {
 for _, entry := range os.Environ() {
  key := strings.SplitN(entry, "=", 2)[0]
  if strings.HasPrefix(key, "OMNI_") || strings.HasPrefix(key, "RAILWAY_") || strings.Contains(key, "TOKEN") || strings.Contains(key, "SECRET") || key == "API_KEY" || key == "DATABASE_URL" {
   t.Fatalf("forbidden environment name: %%s", key)
  }
  if strings.Contains(entry, "must-not-reach-job") { t.Fatal("secret value leaked") }
 }
 home := os.Getenv("HOME")
 if !strings.HasPrefix(home, "/tmp/omni-shell-") || os.Getenv("TERM") != "dumb" || os.Getenv("GOFLAGS") != "-mod=readonly" || os.Getenv("GOPATH") != home+"/.gopath" || os.Getenv("GOCACHE") != home+"/.gocache" { t.Fatal("invalid job environment") }
 if os.Geteuid() != %d || os.Getegid() != %d || os.Geteuid() == 0 { t.Fatal("wrong sandbox identity") }
}
`, w.ShellUID, w.ShellGID)
			if err := os.WriteFile(filepath.Join(repo, "environment_test.go"), []byte(test), 0o644); err != nil {
				t.Fatal(err)
			}
			runGit(t, repo, "add", ".")
			runGit(t, repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "environment fixture")
			j := &Job{ID: jobID, Kind: kind, Repo: "OMERTA-ROW/Omni"}
			if kind == "code" {
				j.Patch = strings.Replace(breakPatch, "a - b", "b + a", 1)
			}
			result := w.Process(context.Background(), j)
			if result.Status != "completed" || result.Tests == nil || !result.Tests.Passed {
				t.Fatalf("scrubbed job failed: %+v", result)
			}
		})
	}
}

func useTestSandbox(t *testing.T, w *Worker) {
	t.Helper()
	// Linux container coverage exercises the real setuid helper and distinct
	// sandbox account; native tests use the current unprivileged test account.
	u, err := user.Lookup("omni-sandbox")
	if err != nil {
		return
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	w.ShellUser, w.ShellUID, w.ShellGID = u.Username, uint32(uid), uint32(gid)
	w.ShellExecPath = "/usr/local/bin/omni-shell-exec"
}

func TestTestJobsFailWithoutSandboxIdentity(t *testing.T) {
	dir := privateTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, output := (&Worker{}).runTests(context.Background(), dir)
	if ok || !strings.Contains(output, "sandbox") {
		t.Fatalf("tests ran without sandbox identity: %v %s", ok, output)
	}
}

func TestTestJobsHonorDeadline(t *testing.T) {
	repo := gitRepo(t)
	w := worker(t, repo, "")
	w.TestTimeout = time.Nanosecond
	result := w.Process(context.Background(), &Job{ID: jobID, Kind: "test", Repo: "OMERTA-ROW/Omni"})
	if result.Status != "failed" || result.Tests == nil || result.Tests.Passed {
		t.Fatalf("deadline ignored: %+v", result)
	}
}

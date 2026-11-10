package inbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Tests holds real test-run evidence.
type Tests struct {
	Passed bool   `json:"passed"`
	Output string `json:"output"`
}

// Result is the omni.job-result/v1 payload reported back to Jackboy.
type Result struct {
	Contract string       `json:"contract"`
	JobID    string       `json:"jobId"`
	Status   string       `json:"status"`
	Summary  string       `json:"summary"`
	PRURL    *string      `json:"prUrl"`
	Tests    *Tests       `json:"tests"`
	Shell    *ShellResult `json:"shell,omitempty"`
	DiffStat string       `json:"diffStat,omitempty"`
}

// ShellResult contains bounded output and execution details for a shell job.
type ShellResult struct {
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"durationMs"`
	TimedOut   bool   `json:"timedOut"`
	Truncated  bool   `json:"truncated"`
}

// Job is one durable unit of work.
type Job struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Repo           string    `json:"repo"`
	Instructions   string    `json:"instructions"`
	Patch          string    `json:"patch,omitempty"`
	Command        string    `json:"command,omitempty"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
	Status         string    `json:"status"` // queued, running, quarantined, completed, failed
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Result         *Result   `json:"result,omitempty"`
	Reported       bool      `json:"reported"`
}

// Store keeps one JSON file per job; writes are atomic (temp file + rename) so restarts never lose jobs.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates the data directory if needed.
func NewStore(dir string) (*Store, error) {
	if err := prepareDataDir(dir); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	if err := s.QuarantinePending(); err != nil {
		return nil, err
	}
	return s, nil
}

func prepareDataDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return fmt.Errorf("OMNI_DATA_DIR must be a normalized absolute directory, not /")
	}
	parent := filepath.Dir(dir)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return fmt.Errorf("OMNI_DATA_DIR parent must exist without symlinks")
	}
	if info, err := os.Lstat(dir); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
			return fmt.Errorf("OMNI_DATA_DIR must be a real directory owned by the service user")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect OMNI_DATA_DIR: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create OMNI_DATA_DIR: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure OMNI_DATA_DIR: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".writable-")
	if err != nil {
		return fmt.Errorf("OMNI_DATA_DIR is not writable by the service user: %w", err)
	}
	closeErr := probe.Close()
	removeErr := os.Remove(probe.Name())
	if closeErr != nil || removeErr != nil {
		return fmt.Errorf("verify OMNI_DATA_DIR: %w", errors.Join(closeErr, removeErr))
	}
	return nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) write(j *Job) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".job-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
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
	if err := os.Rename(f.Name(), s.path(j.ID)); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) read(id string) (*Job, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var j Job
	return &j, json.Unmarshal(b, &j)
}

// Put stores a new queued job. It is idempotent: an existing id returns the stored job and created=false.
func (s *Store) Put(j Job) (*Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, err := s.read(j.ID); err == nil {
		return old, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	now := time.Now().UTC()
	j.Status, j.CreatedAt, j.UpdatedAt = "queued", now, now
	return &j, true, s.write(&j)
}

// Get returns a job by id.
func (s *Store) Get(id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}

// Update applies fn to a stored job and saves it.
func (s *Store) Update(id string, fn func(*Job)) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.read(id)
	if err != nil {
		return nil, err
	}
	fn(j)
	j.UpdatedAt = time.Now().UTC()
	return j, s.write(j)
}

// Claim marks the oldest queued job running and returns it, or nil when the queue is empty.
// Historical pending jobs are quarantined when the store is opened.
func (s *Store) Claim() (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs, err := s.all()
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if j.Status == "queued" {
			j.Status, j.UpdatedAt = "running", time.Now().UTC()
			return j, s.write(j)
		}
	}
	return nil, nil
}

// Unreported returns finished jobs whose result has not been delivered to Jackboy yet.
func (s *Store) Unreported() ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs, err := s.all()
	var out []*Job
	for _, j := range jobs {
		if (j.Status == "completed" || j.Status == "failed") && !j.Reported {
			out = append(out, j)
		}
	}
	return out, err
}

// QuarantinePending requires fresh approval/submission with a new job ID before
// any historical pending work can run again.
func (s *Store) QuarantinePending() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs, err := s.all()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.Status == "running" || j.Status == "queued" {
			j.Status, j.UpdatedAt = "quarantined", time.Now().UTC()
			if err := s.write(j); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) all() ([]*Job, error) {
	names, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var jobs []*Job
	for _, n := range names {
		info, err := os.Lstat(n)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
			return nil, fmt.Errorf("job record must be a regular, unlinked file: %s", filepath.Base(n))
		}
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		var j Job
		if err := json.Unmarshal(b, &j); err != nil || !uuidRe.MatchString(j.ID) || filepath.Base(n) != j.ID+".json" {
			return nil, fmt.Errorf("invalid job record: %s", filepath.Base(n))
		}
		jobs = append(jobs, &j)
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].CreatedAt.Before(jobs[b].CreatedAt) })
	return jobs, nil
}

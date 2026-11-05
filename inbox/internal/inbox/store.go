package inbox

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Tests holds real test-run evidence.
type Tests struct {
	Passed bool   `json:"passed"`
	Output string `json:"output"`
}

// Result is the omni.job-result/v1 payload reported back to Jackboy.
type Result struct {
	Contract string  `json:"contract"`
	JobID    string  `json:"jobId"`
	Status   string  `json:"status"`
	Summary  string  `json:"summary"`
	PRURL    *string `json:"prUrl"`
	Tests    *Tests  `json:"tests"`
	DiffStat string  `json:"diffStat,omitempty"`
}

// Job is one durable unit of work.
type Job struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Repo         string    `json:"repo"`
	Instructions string    `json:"instructions"`
	Patch        string    `json:"patch,omitempty"`
	Status       string    `json:"status"` // queued, running, completed, failed
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Result       *Result   `json:"result,omitempty"`
	Reported     bool      `json:"reported"`
}

// Store keeps one JSON file per job; writes are atomic (temp file + rename) so restarts never lose jobs.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates the data directory if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) write(j *Job) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(j.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(j.ID))
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
// Jobs left "running" by a crash are re-queued on start by RequeueStale.
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

// RequeueStale returns interrupted running jobs to the queue.
func (s *Store) RequeueStale() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs, err := s.all()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.Status == "running" {
			j.Status = "queued"
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
		b, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		var j Job
		if json.Unmarshal(b, &j) == nil {
			jobs = append(jobs, &j)
		}
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].CreatedAt.Before(jobs[b].CreatedAt) })
	return jobs, nil
}

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	sandboxUID = 65534
	chunkBytes = 4096
)

type request struct {
	Type    string `json:"type"`
	JobID   string `json:"jobId"`
	Command string `json:"command"`
	Limits  limits `json:"limits"`
}

type limits struct {
	TimeoutSec      int `json:"timeoutSec"`
	CPUSec          int `json:"cpuSec"`
	MemoryMB        int `json:"memoryMb"`
	Processes       int `json:"maxProcesses"`
	FileMB          int `json:"fileSizeMb"`
	Output          int `json:"outputCapBytes"`
	WorkspaceMB     int `json:"workspaceMb"`
	WorkspaceInodes int `json:"workspaceInodes"`
}

type message struct {
	Type      string   `json:"type"`
	JobID     string   `json:"jobId,omitempty"`
	Stream    string   `json:"stream,omitempty"`
	Text      string   `json:"text,omitempty"`
	ExitCode  int      `json:"exitCode,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	UID       int      `json:"uid,omitempty"`
	NetworkOK bool     `json:"networkIsolated,omitempty"`
	EnvNames  []string `json:"envNames,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type runningJob struct {
	cmd      *exec.Cmd
	killOnce sync.Once
	reason   string
	mu       sync.Mutex
	budget   *outputBudget
	emitter  *emitter
	streams  sync.WaitGroup
}

type outputBudget struct {
	mu   sync.Mutex
	used int
	cap  int
	cut  bool
}

type emitter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (e *emitter) send(m message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := json.NewEncoder(e.w).Encode(m); err != nil {
		return err
	}
	return e.w.Flush()
}

func main() {
	workspaceMB, workspaceInodes := 128, 8192
	if len(os.Args) == 4 && os.Args[1] == "--workspace" {
		parsedMB, errMB := strconv.Atoi(os.Args[2])
		parsedInodes, errInodes := strconv.Atoi(os.Args[3])
		if errMB != nil || errInodes != nil || parsedMB < 16 || parsedMB > 512 || parsedInodes < 256 || parsedInodes > 32768 {
			os.Exit(2)
		}
		workspaceMB, workspaceInodes = parsedMB, parsedInodes
	}
	if err := mountWorkspace(workspaceMB, workspaceInodes); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(message{Type: "error", Error: "bounded workspace unavailable"})
		os.Exit(1)
	}

	probe := runProbe()
	if err := json.NewEncoder(os.Stdout).Encode(message{
		Type:      "ready",
		UID:       probe.uid,
		NetworkOK: probe.networkOK,
		EnvNames:  probe.envNames,
		ExitCode:  probe.exitCode,
	}); err != nil {
		os.Exit(1)
	}

	e := &emitter{w: bufio.NewWriter(os.Stdout)}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16*1024)
	var mu sync.Mutex
	active := map[string]*runningJob{}
	var wg sync.WaitGroup

	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = e.send(message{Type: "error", Error: "invalid request"})
			continue
		}
		switch req.Type {
		case "run":
			mu.Lock()
			if _, exists := active[req.JobID]; exists || len(active) != 0 {
				mu.Unlock()
				_ = e.send(message{Type: "error", JobID: req.JobID, Error: "session executor busy"})
				continue
			}
			job, err := startJob(req, e)
			if err != nil {
				mu.Unlock()
				_ = e.send(message{Type: "done", JobID: req.JobID, ExitCode: -1, Error: "command could not start"})
				continue
			}
			active[req.JobID] = job
			mu.Unlock()
			wg.Add(1)
			go func(req request, job *runningJob) {
				defer wg.Done()
				code, reason := runJob(req, job)
				mu.Lock()
				delete(active, req.JobID)
				mu.Unlock()
				_ = e.send(message{Type: "done", JobID: req.JobID, ExitCode: code, Reason: reason})
			}(req, job)
		case "cancel":
			mu.Lock()
			job := active[req.JobID]
			mu.Unlock()
			if job != nil {
				job.cancel("cancelled")
			}
		case "shutdown":
			mu.Lock()
			for _, job := range active {
				job.cancel("cancelled")
			}
			mu.Unlock()
			wg.Wait()
			return
		default:
			_ = e.send(message{Type: "error", JobID: req.JobID, Error: "unknown request"})
		}
	}
	mu.Lock()
	for _, job := range active {
		job.cancel("cancelled")
	}
	mu.Unlock()
	wg.Wait()
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		os.Exit(1)
	}
}

func mountWorkspace(sizeMB, inodes int) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("supervisor must be namespace root")
	}
	for _, mountpoint := range []string{"/workspace", "/tmp"} {
		if err := os.MkdirAll(mountpoint, 0o700); err != nil {
			return err
		}
		options := fmt.Sprintf("size=%dm,nr_inodes=%d,nodev,nosuid", sizeMB, inodes)
		cmd := exec.Command("/usr/bin/mount", "-t", "tmpfs", "-o", options, "tmpfs", mountpoint)
		cmd.Env = cleanEnv()
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("mount bounded %s: %w: %s", mountpoint, err, strings.TrimSpace(string(output)))
		}
	}
	if err := os.Chmod("/tmp", 0o1777); err != nil {
		return err
	}
	return os.Chmod("/workspace", 0o1777)
}

type probeResult struct {
	uid       int
	networkOK bool
	envNames  []string
	exitCode  int
}

func runProbe() probeResult {
	r := probeResult{uid: -1, exitCode: 1}
	networks, err := netInterfaces()
	if err != nil {
		return r
	}
	r.networkOK = true
	for _, iface := range networks {
		if iface != "lo" {
			r.networkOK = false
		}
	}
	if conn, dialErr := net.DialTimeout("tcp", "192.0.2.1:80", 500*time.Millisecond); dialErr == nil {
		r.networkOK = false
		_ = conn.Close()
	}

	cmd := exec.Command("/usr/bin/id", "-u")
	cmd.Env = cleanEnv()
	cmd.Dir = "/workspace"
	cmd.SysProcAttr = childAttributes()
	output, err := cmd.Output()
	if err != nil {
		return r
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return r
	}
	r.uid = uid
	for _, entry := range os.Environ() {
		if index := strings.IndexByte(entry, '='); index > 0 {
			r.envNames = append(r.envNames, entry[:index])
		}
	}
	sort.Strings(r.envNames)
	if uid > 0 && r.networkOK {
		r.exitCode = 0
	}
	return r
}

func netInterfaces() ([]string, error) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines[2:] {
		if index := strings.IndexByte(line, ':'); index >= 0 {
			names = append(names, strings.TrimSpace(line[:index]))
		}
	}
	return names, nil
}

func childAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
		Credential: &syscall.Credential{
			Uid:         sandboxUID,
			Gid:         sandboxUID,
			NoSetGroups: true,
		},
	}
}

func cleanEnv() []string {
	return []string{
		"HOME=/workspace",
		"LANG=C.UTF-8",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TERM=dumb",
	}
}

func startJob(req request, e *emitter) (*runningJob, error) {
	if req.JobID == "" || strings.TrimSpace(req.Command) == "" ||
		req.Limits.TimeoutSec < 1 || req.Limits.CPUSec < 1 ||
		req.Limits.MemoryMB < 64 || req.Limits.Processes < 1 ||
		req.Limits.FileMB < 1 || req.Limits.Output < 1 {
		return nil, fmt.Errorf("invalid job")
	}
	args := []string{
		"--cpu=" + strconv.Itoa(req.Limits.CPUSec),
		"--as=" + strconv.Itoa(req.Limits.MemoryMB*1024*1024),
		"--nproc=" + strconv.Itoa(req.Limits.Processes),
		"--fsize=" + strconv.Itoa(req.Limits.FileMB*1024*1024),
		"--nofile=128",
		"--core=0",
		"--",
		"/bin/sh", "-c", req.Command,
	}
	cmd := exec.Command("/usr/bin/prlimit", args...)
	cmd.Dir = "/workspace"
	cmd.Env = cleanEnv()
	cmd.SysProcAttr = childAttributes()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	job := &runningJob{cmd: cmd, emitter: e, budget: &outputBudget{cap: req.Limits.Output}}
	job.streams.Add(2)
	go func() { defer job.streams.Done(); stream(stdout, "stdout", req, job) }()
	go func() { defer job.streams.Done(); stream(stderr, "stderr", req, job) }()
	return job, nil
}

func stream(r io.Reader, streamName string, req request, job *runningJob) {
	buf := make([]byte, chunkBytes)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			budget := job.budget
			budget.mu.Lock()
			remaining := budget.cap - budget.used
			if remaining > 0 {
				count := min(n, remaining)
				budget.used += count
				_ = job.emitter.send(message{Type: "output", JobID: req.JobID, Stream: streamName, Text: string(buf[:count])})
			}
			if budget.used >= budget.cap && !budget.cut {
				budget.cut = true
				job.cancel("output_cap")
			}
			budget.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func runJob(req request, job *runningJob) (int, string) {
	done := make(chan error, 1)
	go func() { done <- job.cmd.Wait() }()
	timer := time.NewTimer(time.Duration(req.Limits.TimeoutSec) * time.Second)
	defer timer.Stop()
	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-timer.C:
		timedOut = true
		job.cancel("timeout")
		waitErr = <-done
	}
	job.streams.Wait()
	if timedOut {
		return -1, "timeout"
	}
	job.mu.Lock()
	reason := job.reason
	job.mu.Unlock()
	if reason != "" {
		return -1, reason
	}
	if waitErr == nil {
		return 0, ""
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), ""
	}
	return -1, "command failed"
}

func (j *runningJob) cancel(reason string) {
	j.killOnce.Do(func() {
		j.mu.Lock()
		j.reason = reason
		j.mu.Unlock()
		if j.cmd.Process != nil {
			_ = syscall.Kill(-j.cmd.Process.Pid, syscall.SIGKILL)
		}
	})
}

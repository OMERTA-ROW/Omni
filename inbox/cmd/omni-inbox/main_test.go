package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWorkerFlagRequiresExactTrue(t *testing.T) {
	for _, value := range []string{"", "false", "TRUE", "1", " true", "true "} {
		t.Setenv("OMNI_WORKER_ENABLED", value)
		if workerEnabled() {
			t.Fatalf("worker enabled for %q", value)
		}
	}
	t.Setenv("OMNI_WORKER_ENABLED", "true")
	if !workerEnabled() {
		t.Fatal("explicit true did not enable worker")
	}
}

func TestExecutionConfigFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		worker, shell bool
		wantErr       bool
	}{
		{false, false, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	} {
		if err := validateExecutionConfig(tc.worker, tc.shell); (err != nil) != tc.wantErr {
			t.Fatalf("worker=%t shell=%t: got error %v", tc.worker, tc.shell, err)
		}
	}
}

func TestExecutionStartupHold(t *testing.T) {
	if os.Getenv("OMNI_TEST_STARTUP_HOLD") == "1" {
		main()
		return
	}
	for _, name := range []string{"OMNI_WORKER_ENABLED", "OMNI_SHELL_ENABLED"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutionStartupHold$")
			cmd.Env = []string{
				"OMNI_TEST_STARTUP_HOLD=1",
				"OMNI_API_KEY=" + strings.Repeat("a", 32),
				"OMNI_CALLBACK_SECRET=" + strings.Repeat("b", 32),
				"OMNI_ALLOWED_REPOS=example/repo",
				"OMNI_DATA_DIR=" + t.TempDir(),
				name + "=true",
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || err == nil || !strings.Contains(string(output), "execution is unavailable") {
				t.Fatalf("startup should refuse %s: error=%v context=%v output=%s", name, err, ctx.Err(), output)
			}
		})
	}
}

func TestDataDirectorySelection(t *testing.T) {
	t.Setenv("OMNI_DATA_DIR", "/explicit/jobs")
	if dir, err := dataDirectory(); err != nil || dir != "/explicit/jobs" {
		t.Fatalf("explicit directory: %q, %v", dir, err)
	}
	for _, value := range []string{"", "/data"} {
		t.Setenv("OMNI_DATA_DIR", value)
		info, statErr := os.Lstat("/data")
		dir, err := dataDirectory()
		if statErr == nil && info.IsDir() {
			if err != nil || dir != "/data" {
				t.Fatalf("mounted default: %q, %v", dir, err)
			}
		} else if err == nil {
			t.Fatalf("missing volume silently defaulted to %q", dir)
		}
	}
}

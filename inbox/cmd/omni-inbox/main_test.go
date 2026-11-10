package main

import (
	"os"
	"testing"
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

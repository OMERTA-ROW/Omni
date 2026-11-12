package companion

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandNames(t *testing.T) {
	var out, err bytes.Buffer
	if Run([]string{"version"}, "evolution", &out, &err) != 0 || !strings.Contains(out.String(), "0.0.0-source") {
		t.Fatal("version missing")
	}
	out.Reset()
	err.Reset()
	if Run(nil, "omni", &out, &err) != 2 || out.Len() != 0 {
		t.Fatal("omni pretended to connect")
	}
	if Run([]string{"omni"}, "evolution", &out, &err) != 2 {
		t.Fatal("fallback must stay blocked")
	}
}
func TestHelp(t *testing.T) {
	var out, err bytes.Buffer
	if Run([]string{"help"}, "evolution", &out, &err) != 0 {
		t.Fatal("help")
	}
	for _, command := range []string{"doctor", "connect", "login", "nexus", "agents", "update", "version", "dock", "evolution omni"} {
		if !strings.Contains(out.String(), command) {
			t.Fatal(command)
		}
	}
}
func TestBlockedCommandsDoNotEchoSecrets(t *testing.T) {
	for _, name := range []string{"login", "connect", "nexus", "agents", "update", "omni", "unknown"} {
		t.Run(name, func(t *testing.T) {
			var out, err bytes.Buffer
			if Run([]string{name, "--token", "private-fixture"}, "evolution", &out, &err) != 2 {
				t.Fatal("not blocked")
			}
			if strings.Contains(out.String()+err.String(), "private-fixture") {
				t.Fatal("echoed input")
			}
		})
	}
}
func TestDoctor(t *testing.T) {
	t.Setenv("PATH", "")
	var out, err bytes.Buffer
	if Run([]string{"doctor", "--json"}, "evolution", &out, &err) != 0 {
		t.Fatal("doctor")
	}
	var r DoctorReport
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Platform != runtime.GOOS+"/"+runtime.GOARCH || r.SignedRelease || r.Credentials != "DISABLED; no secure-key adapter" || len(r.EvolutionConflicts) != 0 {
		t.Fatal(r)
	}
}
func TestRejectsUnknownFlags(t *testing.T) {
	for _, args := range [][]string{{"version", "--token"}, {"doctor", "--scan"}, {"install", "--dir", "x", "--approve", "--approve"}, {"uninstall", "--dir", "x", "--with-omni"}} {
		var out, err bytes.Buffer
		if Run(args, "evolution", &out, &err) != 2 {
			t.Fatal(args)
		}
	}
}
func TestCommandConflictDetection(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"evolution", "omni"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not executed"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"evolution", "omni"} {
		if len(FindCommands(name, dir, runtime.GOOS)) != 1 {
			t.Fatal(name)
		}
	}
}
func TestWindowsCommandExtensions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "omni.cmd"), []byte("inert"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(FindCommands("omni", dir, "windows")) != 1 {
		t.Fatal("Windows alias collision")
	}
}
func TestEmptyPATHDoesNotInspectWorkingDirectory(t *testing.T) {
	if len(FindCommands("evolution", "", runtime.GOOS)) != 0 {
		t.Fatal("empty PATH searched cwd")
	}
}

func TestWindowsPowerShellAndEffectivePathExtensions(t *testing.T) {
	dir := t.TempDir()
	for _, filename := range []string{"OMNI.PS1", "evolution.PY", "omni.not-an-extension"} {
		if err := os.WriteFile(filepath.Join(dir, filename), []byte("never executed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	quoted := "\"" + dir + "\""
	if got := findCommandsWithExtensions("omni", quoted, "windows", ".PY;../../outside"); len(got) != 1 || filepath.Base(got[0]) != "OMNI.PS1" {
		t.Fatal(got)
	}
	if got := findCommandsWithExtensions("evolution", quoted, "windows", ".PY"); len(got) != 1 || filepath.Base(got[0]) != "evolution.PY" {
		t.Fatal(got)
	}
}

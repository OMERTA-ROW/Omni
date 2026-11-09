package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(125)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	serviceUID, err := accountUID("omni")
	if err != nil {
		return 0, err
	}
	if os.Geteuid() != 0 || uint32(os.Getuid()) != serviceUID {
		return 0, fmt.Errorf("shell helper privilege check failed")
	}
	sandbox, err := user.Lookup("omni-sandbox")
	if err != nil {
		return 0, fmt.Errorf("omni-sandbox account not found")
	}
	sandboxUID, err := strconv.ParseUint(sandbox.Uid, 10, 32)
	if err != nil || sandboxUID == 0 {
		return 0, fmt.Errorf("invalid omni-sandbox uid")
	}
	sandboxGID, err := strconv.ParseUint(sandbox.Gid, 10, 32)
	if err != nil || sandboxGID == 0 {
		return 0, fmt.Errorf("invalid omni-sandbox gid")
	}
	if len(args) == 2 && args[0] == "--cleanup" {
		if err := removeWorkspace(args[1], serviceUID); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if len(args) != 5 || args[0] != "--run" || strings.TrimSpace(args[4]) == "" {
		return 0, fmt.Errorf("invalid shell helper request")
	}
	requestedUID, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil || requestedUID != sandboxUID {
		return 0, fmt.Errorf("invalid shell uid")
	}
	requestedGID, err := strconv.ParseUint(args[3], 10, 32)
	if err != nil || requestedGID != sandboxGID {
		return 0, fmt.Errorf("invalid shell gid")
	}
	if err := prepareWorkspace(args[1], serviceUID, uint32(sandboxUID), uint32(sandboxGID)); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := setChildSubreaper(); err != nil {
		return 0, fmt.Errorf("could not contain shell descendants: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv",
		"--reuid="+strconv.FormatUint(sandboxUID, 10),
		"--regid="+strconv.FormatUint(sandboxGID, 10),
		"--clear-groups",
		"--no-new-privs",
		"--",
		"/bin/sh", "-c", args[4],
	)
	cmd.Dir = args[1]
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + args[1],
		"TMPDIR=" + args[1],
		"LANG=C.UTF-8",
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	runErr := cmd.Run()
	killAndReapChildren()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("could not start shell: %w", runErr)
	}
	return 0, nil
}

func accountUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("%s account not found", name)
	}
	id, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid %s id", name)
	}
	return uint32(id), nil
}

func workspace(path string, serviceUID uint32) error {
	if filepath.Clean(path) != path || filepath.Dir(path) != "/tmp" || !strings.HasPrefix(filepath.Base(path), "omni-shell-") {
		return fmt.Errorf("invalid shell workspace")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("shell workspace is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != serviceUID {
		return fmt.Errorf("shell workspace owner mismatch")
	}
	return nil
}

func prepareWorkspace(path string, serviceUID, sandboxUID, sandboxGID uint32) error {
	if err := workspace(path, serviceUID); err != nil {
		return err
	}
	err := filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path {
			return nil
		}
		return os.Lchown(current, int(sandboxUID), int(sandboxGID))
	})
	if err != nil {
		return fmt.Errorf("could not prepare shell workspace: %w", err)
	}
	if err := os.Chown(path, int(serviceUID), int(sandboxGID)); err != nil {
		return fmt.Errorf("could not set shell workspace group: %w", err)
	}
	if err := os.Chmod(path, 0o770); err != nil {
		return fmt.Errorf("could not open shell workspace: %w", err)
	}
	return nil
}

func removeWorkspace(path string, serviceUID uint32) error {
	if err := workspace(path, serviceUID); err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("could not remove shell workspace: %w", err)
	}
	return nil
}

func setChildSubreaper() error {
	const prSetChildSubreaper = 36
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func killAndReapChildren() {
	childrenPath := filepath.Join("/proc/self/task", strconv.Itoa(os.Getpid()), "children")
	for attempt := 0; attempt < 100; attempt++ {
		data, err := os.ReadFile(childrenPath)
		if err != nil || len(strings.TrimSpace(string(data))) == 0 {
			return
		}
		for _, value := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(value)
			if err == nil && pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

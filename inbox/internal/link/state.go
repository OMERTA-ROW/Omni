package link

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
)

const (
	handshakeStateFile = "handshake-state.json"
	handshakeLockFile  = "handshake-state.lock"
)

var handshakeIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type HandshakeState struct {
	HandshakeID string    `json:"handshakeId"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type HandshakeStateGuard interface {
	Load() (*HandshakeState, error)
	Save(HandshakeState) error
	Close() error
}

type HandshakeStateStore interface {
	Lock(context.Context) (HandshakeStateGuard, error)
}

// FileHandshakeStateStore keeps only the opaque handshake ID and expiry under a
// caller-validated private directory. The caller owns root's lifetime.
type FileHandshakeStateStore struct {
	root *os.Root
	dir  string
	mu   sync.Mutex
}

func NewFileHandshakeStateStore(root *os.Root, dir string) *FileHandshakeStateStore {
	return &FileHandshakeStateStore{root: root, dir: dir}
}

type fileHandshakeStateGuard struct {
	root  *os.Root
	lock  *os.File
	store *FileHandshakeStateStore
}

func (s *FileHandshakeStateStore) Lock(ctx context.Context) (HandshakeStateGuard, error) {
	if s == nil || s.root == nil || !filepath.IsAbs(s.dir) {
		return nil, errors.New("handshake state directory unavailable")
	}
	s.mu.Lock()
	keepStoreLock := false
	defer func() {
		if !keepStoreLock {
			s.mu.Unlock()
		}
	}()
	if info, err := s.root.Lstat(handshakeLockFile); err == nil &&
		(!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("handshake state lock must be a private regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("handshake state lock unavailable")
	}
	lock, err := s.root.OpenFile(handshakeLockFile, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("handshake state lock open failed: %w", err)
	}
	if err := lock.Chmod(0600); err != nil {
		_ = lock.Close()
		return nil, errors.New("handshake state lock permissions unavailable")
	}
	info, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("handshake state lock stat failed: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = lock.Close()
		return nil, errors.New("handshake state lock must be a private regular file")
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			keepStoreLock = true
			return &fileHandshakeStateGuard{root: s.root, lock: lock, store: s}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = lock.Close()
			return nil, fmt.Errorf("handshake state lock failed: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (g *fileHandshakeStateGuard) Load() (*HandshakeState, error) {
	info, err := g.root.Lstat(handshakeStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("handshake state unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("handshake state must be a private regular file")
	}
	f, err := g.root.OpenFile(handshakeStateFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("handshake state unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || len(data) > 2048 {
		return nil, errors.New("handshake state unreadable")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state HandshakeState
	if err := dec.Decode(&state); err != nil {
		return nil, errors.New("handshake state invalid")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("handshake state invalid")
	}
	if err := validateHandshakeState(state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (g *fileHandshakeStateGuard) Save(state HandshakeState) error {
	if err := validateHandshakeState(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("handshake state encode failed")
	}
	suffix, err := nonce()
	if err != nil {
		return fmt.Errorf("handshake state temporary name unavailable")
	}
	temp := handshakeStateFile + "." + suffix + ".tmp"
	f, err := g.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("handshake state write unavailable")
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = g.root.Remove(temp)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return errors.New("handshake state permissions unavailable")
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return errors.New("handshake state write failed")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errors.New("handshake state sync failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("handshake state close failed")
	}
	if err := g.root.Rename(temp, handshakeStateFile); err != nil {
		return errors.New("handshake state replace failed")
	}
	removeTemp = false
	dir, err := g.root.Open(".")
	if err != nil {
		return errors.New("handshake state directory sync unavailable")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.New("handshake state directory sync failed")
	}
	return nil
}

func (g *fileHandshakeStateGuard) Close() error {
	unlockErr := syscall.Flock(int(g.lock.Fd()), syscall.LOCK_UN)
	closeErr := g.lock.Close()
	g.store.mu.Unlock()
	if unlockErr != nil || closeErr != nil {
		return errors.New("handshake state lock release failed")
	}
	return nil
}

func validateHandshakeState(state HandshakeState) error {
	if !handshakeIDPattern.MatchString(state.HandshakeID) || state.ExpiresAt.IsZero() {
		return errors.New("handshake state invalid")
	}
	return nil
}

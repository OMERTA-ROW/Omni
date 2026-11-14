// Explicit one-shot client; no daemon, polling scheduler, or legacy worker startup.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"omni.local/inbox/internal/link"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 3 && !(len(os.Args) == 2 && (os.Args[1] == "handshake" || os.Args[1] == "safety")) {
		return fmt.Errorf("usage: omni-link handshake|safety OR omni-link <submit|run|status|cancel> <job-uuid>")
	}
	dir := os.Getenv("OMNI_LINK_AUDIT_DIR")
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("OMNI_LINK_AUDIT_DIR must be an existing private absolute directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("audit directory must be private (0700), not a symlink")
	}
	// os.Root confines file operations even if a path is changed concurrently.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("audit directory unavailable")
	}
	defer root.Close()
	if stat, e := root.Lstat("link.jsonl"); e == nil && (!stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0) {
		return fmt.Errorf("audit file must be a private regular file")
	}
	log, err := root.OpenFile("link.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("audit unavailable")
	}
	defer log.Close()
	audit := func(event link.Event) error {
		b, _ := json.Marshal(event)
		if _, e := log.Write(append(b, '\n')); e != nil {
			return fmt.Errorf("audit write failed")
		}
		return log.Sync()
	}
	c, err := link.New(os.Getenv("JACKBOY_LINK_ORIGIN"), os.Getenv("OMNI_LINK_CLIENT_ID"), os.Getenv("OMNI_LINK_PROJECT_ID"), os.Getenv("OMNI_LINK_BOOTSTRAP_KEY"), os.Getenv("OMNI_LINK_HMAC_SECRET"), audit)
	if err != nil {
		return err
	}
	c.HandshakeStore = link.NewFileHandshakeStateStore(root, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Args[1] == "handshake" {
		state, err := c.Connect(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(state)
	}
	if os.Args[1] == "safety" {
		state, err := c.Safety(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(state)
	}
	reply, err := c.Do(ctx, os.Args[1], os.Args[2])
	if err != nil {
		return err
	}
	// Never print bootstrap keys, signatures, session tokens or raw server bodies.
	return json.NewEncoder(os.Stdout).Encode(reply.Job)
}

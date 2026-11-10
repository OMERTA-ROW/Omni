// Command omni-inbox runs OMNI's authenticated job inbox and worker for Jackboy.
//
// Required environment:
//
//	OMNI_API_KEY          bearer token Jackboy sends (same value as Jackboy's OMNI_API_KEY)
//	OMNI_CALLBACK_SECRET  shared HMAC secret (same value as Jackboy's OMNI_CALLBACK_SECRET)
//	OMNI_ALLOWED_REPOS    comma-separated owner/repo names OMNI may work on
//
// Optional: JACKBOY_CALLBACK_URL, OMNI_DATA_DIR (default /data, must exist),
// OMNI_WORKER_ENABLED (exactly true to execute), OMNI_GIT_TOKEN, PORT (default 8080).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"omni.local/inbox/internal/inbox"
)

const version = "0.1.0"

func main() {
	key, secret := os.Getenv("OMNI_API_KEY"), os.Getenv("OMNI_CALLBACK_SECRET")
	if len(key) < 32 || len(secret) < 32 {
		log.Fatal("OMNI_API_KEY and OMNI_CALLBACK_SECRET must each be at least 32 characters")
	}
	allowed := map[string]bool{}
	for _, r := range strings.Split(os.Getenv("OMNI_ALLOWED_REPOS"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			allowed[r] = true
		}
	}
	if len(allowed) == 0 {
		log.Fatal("OMNI_ALLOWED_REPOS is empty; refusing to accept jobs for any repository")
	}
	dataDir, err := dataDirectory()
	if err != nil {
		log.Fatal(err)
	}
	workerEnabled := workerEnabled()
	shellEnabled := os.Getenv("OMNI_SHELL_ENABLED") == "true"
	shellUser, shellUID, shellGID := "", uint32(0), uint32(0)
	shellExecPath := ""
	if shellEnabled || workerEnabled {
		u, err := user.Lookup("omni-sandbox")
		if err != nil {
			log.Fatal("execution requires the omni-sandbox user")
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil || uid == 0 {
			log.Fatal("omni-sandbox must be a non-root user")
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil || gid == 0 {
			log.Fatal("omni-sandbox must have a non-root group")
		}
		shellUser, shellUID, shellGID = u.Username, uint32(uid), uint32(gid)
		shellExecPath = "/usr/local/bin/omni-shell-exec"
	}
	store, err := inbox.NewStore(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("OMNI_DATA_DIR=%q", dataDir)
	dispatch, err := inbox.NewDispatchServer(dataDir, inbox.DispatchConfig{
		Enabled:        os.Getenv("OMNI_DISPATCH_ENABLED") == "true",
		ClientID:       os.Getenv("OMNI_DISPATCH_CLIENT_ID"),
		Secret:         os.Getenv("OMNI_DISPATCH_HMAC_SECRET"),
		CallbackURL:    os.Getenv("JACKBOY_DISPATCH_CALLBACK_URL"),
		CallbackClient: os.Getenv("OMNI_DISPATCH_CALLBACK_CLIENT_ID"),
		CallbackSecret: os.Getenv("OMNI_DISPATCH_CALLBACK_SECRET"),
	}, allowed)
	if err != nil {
		log.Fatal(err)
	}
	wake := make(chan struct{}, 1)
	srv := &inbox.Server{APIKey: key, Secret: secret, Version: version, ShellEnabled: shellEnabled, AllowedRepos: allowed, Store: store, Wake: wake, Dispatch: dispatch}
	wk := &inbox.Worker{Enabled: workerEnabled, Store: store, Secret: secret, CallbackURL: env("JACKBOY_CALLBACK_URL", "https://jackboy-dev-control.lovable.app/api/public/omni/callback"), GitToken: os.Getenv("OMNI_GIT_TOKEN"), ShellUser: shellUser, ShellUID: shellUID, ShellGID: shellGID, ShellExecPath: shellExecPath, Wake: wake}
	if err := dispatch.EnableV3(wk); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go dispatch.RunV3(ctx)
	if workerEnabled {
		go wk.Run(ctx)
	} else {
		log.Print("worker execution disabled (OMNI_WORKER_ENABLED is not true)")
	}
	hs := &http.Server{Addr: ":" + env("PORT", "8080"), Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	log.Printf("omni-inbox %s listening on %s", version, hs.Addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func dataDirectory() (string, error) {
	if dir := os.Getenv("OMNI_DATA_DIR"); dir != "" && dir != "/data" {
		return dir, nil
	}
	info, err := os.Lstat("/data")
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("OMNI_DATA_DIR defaults to /data: mount that writable directory or configure an explicit absolute path")
	}
	return "/data", nil
}

func workerEnabled() bool {
	return os.Getenv("OMNI_WORKER_ENABLED") == "true"
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

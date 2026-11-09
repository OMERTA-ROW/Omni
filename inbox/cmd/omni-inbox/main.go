// Command omni-inbox runs OMNI's authenticated job inbox and worker for Jackboy.
//
// Required environment:
//
//	OMNI_API_KEY          bearer token Jackboy sends (same value as Jackboy's OMNI_API_KEY)
//	OMNI_CALLBACK_SECRET  shared HMAC secret (same value as Jackboy's OMNI_CALLBACK_SECRET)
//	OMNI_ALLOWED_REPOS    comma-separated owner/repo names OMNI may work on
//
// Optional: JACKBOY_CALLBACK_URL, OMNI_DATA_DIR (default ./omni-data), OMNI_GIT_TOKEN, PORT (default 8080).
package main

import (
	"context"
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
	dataDir := env("OMNI_DATA_DIR", "omni-data")
	shellEnabled := os.Getenv("OMNI_SHELL_ENABLED") == "true"
	shellUser, shellUID, shellGID := "", uint32(0), uint32(0)
	shellExecPath := ""
	if shellEnabled {
		u, err := user.Lookup("omni-sandbox")
		if err != nil {
			log.Fatal("OMNI_SHELL_ENABLED requires the omni-sandbox user")
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
	wake := make(chan struct{}, 1)
	srv := &inbox.Server{APIKey: key, Secret: secret, Version: version, ShellEnabled: shellEnabled, AllowedRepos: allowed, Store: store, Wake: wake}
	wk := &inbox.Worker{Store: store, Secret: secret, CallbackURL: env("JACKBOY_CALLBACK_URL", "https://jackboy-dev-control.lovable.app/api/public/omni/callback"), GitToken: os.Getenv("OMNI_GIT_TOKEN"), ShellUser: shellUser, ShellUID: shellUID, ShellGID: shellGID, ShellExecPath: shellExecPath, Wake: wake}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go wk.Run(ctx)
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

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

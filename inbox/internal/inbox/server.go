package inbox

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

const (
	handshakeContract = "omni.handshake/v1"
	jobContract       = "omni.job/v1"
	maxBody           = 256 << 10
)

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	repoRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)
)

// Server is the authenticated job inbox Jackboy calls.
type Server struct {
	APIKey       string // bearer Jackboy sends (OMNI_API_KEY)
	Secret       string // shared HMAC secret (OMNI_CALLBACK_SECRET)
	Version      string
	ShellEnabled bool
	AllowedRepos map[string]bool // only these owner/repo names are accepted
	Store        *Store
	Wake         chan struct{} // optional: nudges the worker
	Dispatch     http.Handler  // independent, receipt-only scoped dispatch lane
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("POST /jackboy/handshake", s.auth(s.handshake))
	m.HandleFunc("POST /jackboy/jobs", s.auth(s.jobs))
	m.HandleFunc("GET /jackboy/jobs/{id}", s.auth(s.status))
	if s.Dispatch != nil {
		m.Handle("POST "+dispatchPath, s.Dispatch)
	} else {
		m.HandleFunc("POST "+dispatchPath, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "dispatch disabled", http.StatusServiceUnavailable)
		})
	}
	return m
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + s.APIKey
		if s.APIKey == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handshake(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge string `json:"challenge"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.Challenge) < 32 || len(in.Challenge) > 200 {
		http.Error(w, "challenge required", http.StatusBadRequest)
		return
	}
	capabilities := []string{"jobs", "patch-apply", "go-test", "signed-callback"}
	if s.ShellEnabled {
		capabilities = append(capabilities, "shell-exec")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"contract":     handshakeContract,
		"version":      s.Version,
		"capabilities": capabilities,
		"proof":        HMACHex(s.Secret, in.Challenge),
	})
}

func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Contract     string `json:"contract"`
		JobID        string `json:"jobId"`
		Kind         string `json:"kind"`
		Repo         string `json:"repo"`
		Instructions string `json:"instructions"`
		Patch        string `json:"patch"`
		Command      string `json:"command"`
		Timeout      *int   `json:"timeoutSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	switch {
	case in.Contract != jobContract:
		http.Error(w, "wrong contract", http.StatusBadRequest)
		return
	case !uuidRe.MatchString(in.JobID) || r.Header.Get("Idempotency-Key") != in.JobID:
		http.Error(w, "jobId must be a UUID matching Idempotency-Key", http.StatusBadRequest)
		return
	case in.Kind == "shell" && !s.ShellEnabled:
		http.Error(w, "shell jobs disabled", http.StatusForbidden)
		return
	case in.Kind != "code" && in.Kind != "test" && in.Kind != "shell":
		http.Error(w, "kind must be code, test, or shell", http.StatusBadRequest)
		return
	case in.Kind == "shell" && (strings.TrimSpace(in.Command) == "" || len(in.Command) > 16000):
		http.Error(w, "shell command required (maximum 16000 bytes)", http.StatusBadRequest)
		return
	case in.Kind == "shell" && in.Timeout != nil && (*in.Timeout < 1 || *in.Timeout > 3600):
		http.Error(w, "timeoutSeconds must be between 1 and 3600", http.StatusBadRequest)
		return
	case in.Kind != "shell" && (!repoRe.MatchString(in.Repo) || !s.AllowedRepos[in.Repo]):
		http.Error(w, "repository not allowed", http.StatusForbidden)
		return
	case in.Kind == "shell" && in.Repo != "" && (!repoRe.MatchString(in.Repo) || !s.AllowedRepos[in.Repo]):
		http.Error(w, "repository not allowed", http.StatusForbidden)
		return
	}
	timeoutSeconds := 0
	if in.Kind == "shell" {
		timeoutSeconds = 60
		if in.Timeout != nil {
			timeoutSeconds = *in.Timeout
		}
	}
	j, created, err := s.Store.Put(Job{ID: in.JobID, Kind: in.Kind, Repo: in.Repo, Instructions: trim(in.Instructions, 4000), Patch: in.Patch, Command: in.Command, TimeoutSeconds: timeoutSeconds})
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if created && s.Wake != nil {
		select {
		case s.Wake <- struct{}{}:
		default:
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "ref": j.ID, "duplicate": !created, "status": j.Status})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !uuidRe.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	j, err := s.Store.Get(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": j.ID, "status": j.Status, "result": j.Result})
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Package link implements OMNI-initiated, project-scoped Jackboy protocol sessions.
// It does not launch the legacy inbox worker or access any GitHub credential.
package link

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"omni.local/inbox/internal/inbox"
)

const Path = "/api/public/omni/link"
const Contract = "omni.link/v2"

// HandshakeTimeout bounds the session-creating handshake only. It is read-only on the
// Jackboy side (creates a short-lived session) and was observed taking 3-5s+. All other
// operations (submit, run, status, cancel) keep the stricter RequestTimeout.
const HandshakeTimeout = 10 * time.Second
const RequestTimeout = 5 * time.Second

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var clientID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var ErrSession = errors.New("session rejected; reconnect required")
var ErrHandshakeConflict = errors.New("Jackboy handshake ID conflict")
var ErrUnavailable = errors.New("link unavailable; outcome must be reconciled using the same job ID")

type Event struct {
	At    time.Time `json:"at"`
	State string    `json:"state"`
	JobID string    `json:"jobId,omitempty"`
}
type Job struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Result *struct {
		Passed bool   `json:"passed"`
		Checks int    `json:"checks"`
		Runner string `json:"runner"`
	} `json:"result,omitempty"`
}
type Reply struct {
	Contract     string    `json:"contract"`
	RequestNonce string    `json:"requestNonce"`
	SessionToken string    `json:"sessionToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Ready        bool      `json:"ready"`
	Job          *Job      `json:"job,omitempty"`
	Safety       *Safety   `json:"safety,omitempty"`
}
type SafetyAuthorization struct {
	ExpiresAt time.Time `json:"expiresAt"`
}
type Safety struct {
	Contract                 string               `json:"contract"`
	CheckedAt                time.Time            `json:"checkedAt"`
	ValidUntil               time.Time            `json:"validUntil"`
	KillSwitch               *bool                `json:"killSwitch"`
	EmergencyStop            *bool                `json:"emergencyStop"`
	CodeEnabled              *bool                `json:"codeEnabled"`
	Authorization            *SafetyAuthorization `json:"authorization"`
	AutonomousAllowed        *bool                `json:"autonomousAllowed"`
	BlockedBy                *string              `json:"blockedBy"`
	ManualDiagnosticsAllowed *bool                `json:"manualDiagnosticsAllowed"`
	ActivePermits            *int                 `json:"activePermits"`
}

func (s *Safety) UnmarshalJSON(data []byte) error {
	type snapshot Safety
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, field := range []string{
		"contract", "checkedAt", "validUntil", "killSwitch", "emergencyStop",
		"codeEnabled", "authorization", "autonomousAllowed", "blockedBy",
		"manualDiagnosticsAllowed", "activePermits",
	} {
		if _, ok := fields[field]; !ok {
			return errors.New("Jackboy safety snapshot field missing")
		}
	}
	var decoded snapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = Safety(decoded)
	return nil
}

func (s *Safety) validate(now time.Time) error {
	if s == nil || s.Contract != "omni.safety/v1" ||
		s.CheckedAt.IsZero() || s.ValidUntil.IsZero() ||
		s.KillSwitch == nil || s.EmergencyStop == nil || s.CodeEnabled == nil ||
		s.AutonomousAllowed == nil || s.ManualDiagnosticsAllowed == nil ||
		s.ActivePermits == nil || *s.ActivePermits < 0 {
		return errors.New("Jackboy safety snapshot invalid")
	}
	if s.Authorization != nil && s.Authorization.ExpiresAt.IsZero() {
		return errors.New("Jackboy safety authorization invalid")
	}
	if !s.ValidUntil.After(s.CheckedAt) || s.ValidUntil.Sub(s.CheckedAt) > 30*time.Second {
		return errors.New("Jackboy safety snapshot validity invalid")
	}
	if s.CheckedAt.After(now.Add(60 * time.Second)) {
		return errors.New("Jackboy safety snapshot exceeds clock skew")
	}
	if !s.ValidUntil.After(now) {
		return errors.New("Jackboy safety snapshot expired; check again")
	}
	return nil
}

type Client struct {
	BaseURL, ClientID, ProjectID, Bootstrap, Secret string
	HTTP                                            *http.Client
	Audit                                           func(Event) error
	HandshakeStore                                  HandshakeStateStore
	mu                                              sync.Mutex
	session                                         string
	expires                                         time.Time
	// Test hooks: zero means HandshakeTimeout / RequestTimeout. Values above those caps are ignored.
	handshakeLimit, requestLimit time.Duration
}

func (c *Client) limit(action string) time.Duration {
	max, set := RequestTimeout, c.requestLimit
	if action == "handshake" {
		max, set = HandshakeTimeout, c.handshakeLimit
	}
	if set > 0 && set < max {
		return set
	}
	return max
}

func New(base, id, project, bootstrap, secret string, audit func(Event) error) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("Jackboy origin must be an HTTPS origin without path, credentials, query or fragment")
	}
	if !clientID.MatchString(id) || !uuid.MatchString(project) || len(bootstrap) < 32 || len(secret) < 32 || bootstrap == secret || audit == nil {
		return nil, errors.New("scoped link configuration and audit sink required")
	}
	return &Client{BaseURL: u.Scheme + "://" + u.Host, ClientID: id, ProjectID: project, Bootstrap: bootstrap, Secret: secret, Audit: audit}, nil
}
func (c *Client) event(state, job string) error {
	return c.Audit(Event{At: time.Now().UTC(), State: state, JobID: job})
}
func RequestMessage(ts, nonce, token, body string) string {
	hash := sha256.Sum256([]byte(token))
	return Contract + "\nPOST\n" + Path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(hash[:]) + "\n" + body
}
func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (c *Client) send(ctx context.Context, action, job, token, handshakeID string) (*Reply, error) {
	input := map[string]string{"action": action, "projectId": c.ProjectID}
	if job != "" {
		input["jobId"] = job
	}
	if action == "handshake" && handshakeID != "" {
		if !handshakeIDPattern.MatchString(handshakeID) {
			return nil, errors.New("handshake ID invalid")
		}
		input["handshakeId"] = handshakeID
	}
	if action == "submit" {
		input["kind"] = "protocol.self-test"
	}
	body, _ := json.Marshal(input)
	n, err := nonce()
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+Path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Omni-Client", c.ClientID)
	req.Header.Set("X-Omni-Nonce", n)
	req.Header.Set("X-Omni-Timestamp", ts)
	req.Header.Set("X-Omni-Signature", inbox.HMACHex(c.Secret, RequestMessage(ts, n, token, string(body))))
	client := http.Client{Timeout: 5 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	// Credential-bearing requests may never follow redirects, including same-origin redirects.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if limit := c.limit(action); client.Timeout == 0 || client.Timeout > limit {
		client.Timeout = limit
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(data) > 32768 {
		return nil, ErrUnavailable
	}
	if resp.StatusCode == 401 {
		return nil, ErrSession
	}
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return nil, ErrUnavailable
	}
	if resp.StatusCode == http.StatusConflict && action == "handshake" {
		if responseProofValid(c.Secret, n, resp.StatusCode, data, resp.Header.Get("X-Omni-Proof")) {
			var conflict struct {
				Contract     string `json:"contract"`
				RequestNonce string `json:"requestNonce"`
				Error        string `json:"error"`
			}
			if json.Unmarshal(data, &conflict) == nil &&
				conflict.Contract == Contract && conflict.RequestNonce == n &&
				conflict.Error == "handshake_id_expired_or_conflict" {
				return nil, ErrHandshakeConflict
			}
		}
		return nil, fmt.Errorf("Jackboy rejected request (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("Jackboy rejected request (HTTP %d)", resp.StatusCode)
	}
	if !responseProofValid(c.Secret, n, resp.StatusCode, data, resp.Header.Get("X-Omni-Proof")) {
		return nil, errors.New("Jackboy response proof invalid")
	}
	var out Reply
	if json.Unmarshal(data, &out) != nil || out.Contract != Contract || out.RequestNonce != n {
		return nil, errors.New("Jackboy response contract invalid")
	}
	if action == "safety" {
		if out.Job != nil || out.Safety == nil {
			return nil, errors.New("Jackboy safety response invalid")
		}
		if err := out.Safety.validate(time.Now()); err != nil {
			return nil, err
		}
	} else if action != "handshake" && (out.Job == nil || out.Job.ID != job) {
		return nil, errors.New("Jackboy returned a mismatched job")
	}
	if out.Job != nil {
		switch out.Job.Status {
		case "queued", "running", "completed", "failed", "cancelled", "timed_out":
		default:
			return nil, errors.New("invalid job status")
		}
	}
	return &out, nil
}
func responseProofValid(secret, nonce string, status int, body []byte, proof string) bool {
	want := inbox.HMACHex(secret, Contract+"\nresponse\n"+nonce+"\n"+strconv.Itoa(status)+"\n"+string(body))
	return subtle.ConstantTimeCompare([]byte(want), []byte(proof)) == 1
}

func newHandshakeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	raw := hex.EncodeToString(b)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}

func (c *Client) connect(ctx context.Context) (result error) {
	if c.session != "" && time.Until(c.expires) > 5*time.Second {
		return nil
	}
	c.session = ""
	if err := c.event("connecting", ""); err != nil {
		return err
	}
	var guard HandshakeStateGuard
	var state *HandshakeState
	if c.HandshakeStore != nil {
		var err error
		guard, err = c.HandshakeStore.Lock(ctx)
		if err != nil {
			return err
		}
		defer func() {
			if guard != nil {
				if err := guard.Close(); result == nil && err != nil {
					result = err
				}
			}
		}()
		state, err = guard.Load()
		if err != nil {
			return err
		}
		if state == nil {
			id, err := newHandshakeID()
			if err != nil {
				return fmt.Errorf("handshake ID generation failed")
			}
			state = &HandshakeState{HandshakeID: id, ExpiresAt: time.Now().Add(5 * time.Minute)}
			if err := guard.Save(*state); err != nil {
				return err
			}
		}
	}
	handshakeID := ""
	if state != nil {
		handshakeID = state.HandshakeID
	}
	r, err := c.send(ctx, "handshake", "", c.Bootstrap, handshakeID)
	if errors.Is(err, ErrHandshakeConflict) && guard != nil {
		id, idErr := newHandshakeID()
		if idErr != nil {
			return errors.New("handshake ID rotation failed")
		}
		state = &HandshakeState{HandshakeID: id, ExpiresAt: time.Now().Add(5 * time.Minute)}
		if err := guard.Save(*state); err != nil {
			return err
		}
		r, err = c.send(ctx, "handshake", "", c.Bootstrap, state.HandshakeID)
	}
	if err != nil {
		if e := c.event("disconnected", ""); e != nil {
			return e
		}
		return err
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.SessionToken) || time.Until(r.ExpiresAt) <= 0 || time.Until(r.ExpiresAt) > 5*time.Minute+5*time.Second || !r.Ready {
		return errors.New("Jackboy session not ready or expiry invalid")
	}
	expected := map[string]bool{"protocol.self-test": true, "jobs.read": true, "jobs.cancel": true}
	if len(r.Capabilities) != len(expected) {
		return errors.New("unexpected Jackboy capabilities")
	}
	for _, cap := range r.Capabilities {
		if !expected[cap] {
			return errors.New("unexpected Jackboy capabilities")
		}
		delete(expected, cap)
	}
	if guard != nil {
		state.ExpiresAt = r.ExpiresAt
		if err := guard.Save(*state); err != nil {
			return err
		}
	}
	if err := c.event("connected", ""); err != nil {
		return err
	}
	if guard != nil {
		closeErr := guard.Close()
		guard = nil
		if closeErr != nil {
			return closeErr
		}
	}
	c.session, c.expires = r.SessionToken, r.ExpiresAt
	return nil
}

// Do retries only fixed, idempotent protocol operations using the SAME job ID.
// A lost run response is reconciled by Jackboy's atomic claim; it cannot rerun.
func (c *Client) Do(ctx context.Context, action, job string) (*Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if action != "status" && action != "submit" && action != "run" && action != "cancel" {
		return nil, errors.New("unsupported action")
	}
	if !uuid.MatchString(job) {
		return nil, errors.New("job ID must be a lowercase UUID")
	}
	if err := c.event("request_"+action, job); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
		if err := c.connect(ctx); err != nil {
			return nil, err
		}
		r, err := c.send(ctx, action, job, c.session, "")
		if err == nil {
			if e := c.event(r.Job.Status, job); e != nil {
				return nil, e
			}
			return r, nil
		}
		if e := c.event("disconnected", job); e != nil {
			return nil, e
		}
		if errors.Is(err, ErrSession) {
			c.session = ""
			continue
		}
		if !errors.Is(err, ErrUnavailable) {
			return nil, err
		}
	}
	return nil, ErrUnavailable
}

// Safety reads Jackboy's unified activation controls without changing them or requesting a permit.
func (c *Client) Safety(ctx context.Context) (*Safety, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.event("request_safety", ""); err != nil {
		return nil, err
	}
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	r, err := c.send(ctx, "safety", "", c.session, "")
	if err != nil {
		if e := c.event("disconnected", ""); e != nil {
			return nil, e
		}
		if errors.Is(err, ErrSession) {
			c.session = ""
		}
		return nil, err
	}
	if err := c.event("safety_checked", ""); err != nil {
		return nil, err
	}
	return r.Safety, nil
}

// Connection is safe to display or persist. Session credentials never leave Client.
type Connection struct {
	State        string    `json:"state"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Capabilities []string  `json:"capabilities"`
}

func (c *Client) Connect(ctx context.Context) (*Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	return &Connection{State: "authenticated", ExpiresAt: c.expires, Capabilities: []string{"protocol.self-test", "jobs.read", "jobs.cancel"}}, nil
}

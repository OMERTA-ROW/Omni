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
}
type Client struct {
	BaseURL, ClientID, ProjectID, Bootstrap, Secret string
	HTTP                                            *http.Client
	Audit                                           func(Event) error
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
func (c *Client) send(ctx context.Context, action, job, token string) (*Reply, error) {
	input := map[string]string{"action": action, "projectId": c.ProjectID}
	if job != "" {
		input["jobId"] = job
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
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("Jackboy rejected request (HTTP %d)", resp.StatusCode)
	}
	proof := inbox.HMACHex(c.Secret, Contract+"\nresponse\n"+n+"\n"+strconv.Itoa(resp.StatusCode)+"\n"+string(data))
	if subtle.ConstantTimeCompare([]byte(proof), []byte(resp.Header.Get("X-Omni-Proof"))) != 1 {
		return nil, errors.New("Jackboy response proof invalid")
	}
	var out Reply
	if json.Unmarshal(data, &out) != nil || out.Contract != Contract || out.RequestNonce != n {
		return nil, errors.New("Jackboy response contract invalid")
	}
	if action != "handshake" && (out.Job == nil || out.Job.ID != job) {
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
func (c *Client) connect(ctx context.Context) error {
	if c.session != "" && time.Until(c.expires) > 5*time.Second {
		return nil
	}
	c.session = ""
	if err := c.event("connecting", ""); err != nil {
		return err
	}
	r, err := c.send(ctx, "handshake", "", c.Bootstrap)
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
	if err := c.event("connected", ""); err != nil {
		return err
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
		r, err := c.send(ctx, action, job, c.session)
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

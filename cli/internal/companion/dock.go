package companion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

const (
	dockProtocol   = "omni.dock/v1"
	dockPrefix     = "OMNI-DOCK-V1"
	dockPairPath   = "/api/public/omni/dock/pair"
	dockStatusPath = "/api/public/omni/dock/heartbeat"
	dockJobsPath   = "/api/public/omni/dock/jobs"
	dockStopPath   = "/api/public/omni/dock/stop"
	dockBodyLimit  = 8192
	dockReplyLimit = 65536
	dockKeyFile    = "private-key.pem"
	dockStateFile  = "device.json"
)

var (
	dockNoncePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	dockPairCodePattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{10}$`)
	dockRepoPattern     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	dockUUIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type dockPublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dockRFC7638JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dockDeviceState struct {
	Origin   string `json:"origin"`
	DeviceID string `json:"deviceId"`
}

type dockPairBody struct {
	Protocol     string        `json:"protocol"`
	Code         string        `json:"code"`
	Label        string        `json:"label"`
	Platform     string        `json:"platform"`
	PublicKey    dockPublicJWK `json:"publicKey"`
	AppVersion   string        `json:"appVersion,omitempty"`
	Capabilities []string      `json:"capabilities"`
}

type dockHeartbeatBody struct {
	AppVersion   string   `json:"appVersion,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type dockJobBody struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Agent        string `json:"agent"`
	Project      string `json:"project"`
	Repository   string `json:"repository,omitempty"`
	Instructions string `json:"instructions"`
}

func dockDirectory() (string, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("user config directory unavailable")
	}
	return filepath.Join(config, "evolution", "dock"), nil
}

func prepareDockDirectory(path string) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return errors.New("dock config directory could not be created")
		}
		parentInfo, err = os.Lstat(parent)
	}
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("dock parent config path must be a real directory")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return errors.New("dock config directory could not be created")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("dock config path must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.New("dock config directory permissions could not be secured")
	}
	return nil
}

func writeDockFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("dock file already exists or could not be created")
	}
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(data)
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("dock file could not be written securely")
	}
	return nil
}

func readDockFile(path string, max int64) ([]byte, error) {
	dir := filepath.Dir(path)
	parentInfo, err := os.Lstat(filepath.Dir(dir))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("dock parent config path is invalid")
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("dock config directory is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("dock file is missing or invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("dock file could not be read")
	}
	return data, nil
}

func saveDockKey(dir string, key *ecdsa.PrivateKey) error {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.New("dock key could not be encoded")
	}
	return writeDockFile(filepath.Join(dir, dockKeyFile), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}))
}

func loadDockKey(dir string) (*ecdsa.PrivateKey, error) {
	data, err := readDockFile(filepath.Join(dir, dockKeyFile), 4096)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("dock key file is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("dock key must be ECDSA P-256")
	}
	return key, nil
}

func saveDockState(dir string, state dockDeviceState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("dock device state could not be encoded")
	}
	return writeDockFile(filepath.Join(dir, dockStateFile), append(data, '\n'))
}

func loadDockState(dir string) (dockDeviceState, error) {
	var state dockDeviceState
	data, err := readDockFile(filepath.Join(dir, dockStateFile), 4096)
	if err != nil {
		return state, err
	}
	if json.Unmarshal(data, &state) != nil || !dockUUIDPattern.MatchString(state.DeviceID) {
		return state, errors.New("dock device state is invalid")
	}
	if _, err := dockOrigin(state.Origin); err != nil {
		return state, errors.New("saved dock origin is invalid")
	}
	return state, nil
}

func dockOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.ForceQuery || strings.ContainsAny(value, "?#") {
		return "", errors.New("dock URL must be an HTTPS origin without credentials, path, query or fragment")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func dockPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return "unknown"
	}
}

func dockStringLength(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func validDockPairCode(value string) bool {
	if dockStringLength(value) < 10 || dockStringLength(value) > 16 {
		return false
	}
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' {
			return -1
		}
		return r
	}, strings.ToUpper(value))
	normalized = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(normalized)
	return dockPairCodePattern.MatchString(normalized)
}

func newDockKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("dock key could not be generated")
	}
	return key, nil
}

func dockJWK(key *ecdsa.PrivateKey) dockPublicJWK {
	return dockPublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

func marshalDockPairBody(code, label string, jwk dockPublicJWK) ([]byte, error) {
	body, err := json.Marshal(dockPairBody{
		Protocol: dockProtocol, Code: code, Label: strings.TrimSpace(label),
		Platform: dockPlatform(), PublicKey: jwk, AppVersion: Version,
		Capabilities: []string{},
	})
	if err != nil {
		return nil, errors.New("pairing request could not be encoded")
	}
	if len(body) > dockBodyLimit {
		return nil, errors.New("dock request body exceeds 8192 bytes")
	}
	return body, nil
}

func dockSafetyCode(jwk dockPublicJWK) (string, error) {
	canonical, err := json.Marshal(dockRFC7638JWK{jwk.Crv, jwk.Kty, jwk.X, jwk.Y})
	if err != nil {
		return "", errors.New("dock key fingerprint could not be encoded")
	}
	hash := sha256.Sum256(canonical)
	value := new(big.Int).SetBytes(hash[:4]).Uint64() % 1_000_000
	code := fmt.Sprintf("%06d", value)
	return code[:3] + " " + code[3:], nil
}

func dockNonce() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("dock nonce could not be generated")
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	if !dockNoncePattern.MatchString(nonce) {
		return "", errors.New("generated dock nonce is invalid")
	}
	return nonce, nil
}

func dockSigningString(method, path, device, timestamp, nonce string, body []byte) string {
	hash := sha256.Sum256(body)
	return strings.Join([]string{
		dockPrefix,
		strings.ToUpper(method),
		path,
		device,
		timestamp,
		nonce,
		hex.EncodeToString(hash[:]),
	}, "\n")
}

func encodeDockSignature(r, s *big.Int) string {
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func signDockRequest(key *ecdsa.PrivateKey, method, path, device, timestamp, nonce string, body []byte) (string, error) {
	message := dockSigningString(method, path, device, timestamp, nonce, body)
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", errors.New("dock request could not be signed")
	}
	return encodeDockSignature(r, s), nil
}

func newDockHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postDock(client *http.Client, endpoint, device string, key *ecdsa.PrivateKey, body []byte, now time.Time) ([]byte, int, error) {
	if len(body) > dockBodyLimit {
		return nil, 0, errors.New("dock request body exceeds 8192 bytes")
	}
	nonce, err := dockNonce()
	if err != nil {
		return nil, 0, err
	}
	timestamp := fmt.Sprintf("%d", now.UnixMilli())
	path := endpoint
	if parsed, parseErr := url.Parse(endpoint); parseErr == nil {
		path = parsed.EscapedPath()
	}
	signature, err := signDockRequest(key, "POST", path, device, timestamp, nonce, body)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("dock request URL is invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-omni-dock-device", device)
	request.Header.Set("x-omni-dock-timestamp", timestamp)
	request.Header.Set("x-omni-dock-nonce", nonce)
	request.Header.Set("x-omni-dock-signature", signature)

	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("dock request failed or was redirected")
	}
	defer response.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(response.Body, dockReplyLimit+1))
	if err != nil {
		return nil, response.StatusCode, errors.New("dock response could not be read")
	}
	if len(reply) > dockReplyLimit {
		return nil, response.StatusCode, errors.New("dock response exceeds 65536 bytes")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(reply, &failure) == nil && regexp.MustCompile(`^[a-z_]{1,40}$`).MatchString(failure.Reason) {
			return nil, response.StatusCode, fmt.Errorf("dock request refused (HTTP %d, %s)", response.StatusCode, failure.Reason)
		}
		return nil, response.StatusCode, fmt.Errorf("dock request refused (HTTP %d)", response.StatusCode)
	}
	return reply, response.StatusCode, nil
}

func dockEndpoint(origin, path string) (string, error) {
	base, err := dockOrigin(origin)
	if err != nil {
		return "", err
	}
	return base + path, nil
}

func dockPost(origin, path, device string, key *ecdsa.PrivateKey, body []byte) ([]byte, error) {
	endpoint, err := dockEndpoint(origin, path)
	if err != nil {
		return nil, err
	}
	reply, _, err := postDock(newDockHTTPClient(), endpoint, device, key, body, time.Now())
	return reply, err
}

func runDock(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		return invalid(errOut)
	}
	switch args[0] {
	case "pair":
		return runDockPair(args[1:], out, errOut)
	case "status", "stop", "forget":
		if len(args) != 1 {
			return invalid(errOut)
		}
		switch args[0] {
		case "status":
			return runDockStatus(out, errOut)
		case "stop":
			return runDockStop(out, errOut)
		default:
			return runDockForget(out, errOut)
		}
	case "propose":
		return runDockPropose(args[1:], out, errOut)
	default:
		return invalid(errOut)
	}
}

func runDockPair(args []string, out, errOut io.Writer) int {
	f, pos, ok := flags(args, map[string]bool{"--url": true, "--code": true, "--label": true})
	if !ok || len(pos) != 0 || f["--url"] == "" || f["--code"] == "" || f["--label"] == "" {
		return invalid(errOut)
	}
	origin, err := dockOrigin(f["--url"])
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	if !validDockPairCode(f["--code"]) ||
		dockStringLength(strings.TrimSpace(f["--label"])) < 1 ||
		dockStringLength(strings.TrimSpace(f["--label"])) > 60 {
		return invalid(errOut)
	}
	dir, err := dockDirectory()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := prepareDockDirectory(dir); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	for _, name := range []string{dockKeyFile, dockStateFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			fmt.Fprintln(errOut, "A dock key or device already exists; run evolution dock forget before pairing another device.")
			return 1
		} else if !os.IsNotExist(err) {
			fmt.Fprintln(errOut, "Dock key storage could not be checked.")
			return 1
		}
	}
	key, err := newDockKey()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := saveDockKey(dir, key); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	jwk := dockJWK(key)
	body, err := marshalDockPairBody(f["--code"], f["--label"], jwk)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	reply, err := dockPost(origin, dockPairPath, "pair", key, body)
	if err != nil {
		fmt.Fprintln(errOut, "Pairing request failed:", err)
		fmt.Fprintln(errOut, "The dedicated key is retained locally; use evolution dock forget if you need to discard it.")
		return 1
	}
	var result struct {
		DeviceID string `json:"deviceId"`
		Status   string `json:"status"`
		Safety   string `json:"safetyCode"`
	}
	safety, safetyErr := dockSafetyCode(jwk)
	if json.Unmarshal(reply, &result) != nil || !dockUUIDPattern.MatchString(result.DeviceID) ||
		result.Status != "awaiting_approval" || safetyErr != nil || result.Safety != safety {
		fmt.Fprintln(errOut, "Pairing response was invalid; the dedicated key is retained locally.")
		return 1
	}
	if err := saveDockState(dir, dockDeviceState{Origin: origin, DeviceID: result.DeviceID}); err != nil {
		fmt.Fprintln(errOut, "Pairing succeeded but device state could not be saved securely; the dedicated key is retained locally.")
		return 1
	}
	fmt.Fprintf(out, "Paired device awaiting owner approval.\nSafety code: %s\nCompare this with the Docking Bay before the owner approves the device.\n", safety)
	return 0
}

func readDockIdentity() (string, dockDeviceState, *ecdsa.PrivateKey, error) {
	dir, err := dockDirectory()
	if err != nil {
		return "", dockDeviceState{}, nil, err
	}
	state, err := loadDockState(dir)
	if err != nil {
		return "", state, nil, errors.New("no paired dock device; run evolution dock pair first")
	}
	key, err := loadDockKey(dir)
	if err != nil {
		return "", state, nil, errors.New("paired dock key is unavailable or invalid")
	}
	return dir, state, key, nil
}

func runDockStatus(out, errOut io.Writer) int {
	_, state, key, err := readDockIdentity()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	reply, err := dockPost(state.Origin, dockStatusPath, state.DeviceID, key, []byte("{}"))
	if err != nil {
		fmt.Fprintln(errOut, "Dock status failed:", err)
		return 1
	}
	var result struct {
		Status        string   `json:"status"`
		Permissions   []string `json:"permissions"`
		EmergencyStop string   `json:"emergencyStop"`
		Executor      string   `json:"executor"`
	}
	if json.Unmarshal(reply, &result) != nil {
		fmt.Fprintln(errOut, "Dock status response was invalid.")
		return 1
	}
	if result.Status != "paired" && result.Status != "awaiting_approval" {
		result.Status = "unknown"
	}
	permissions := make([]string, 0, len(result.Permissions))
	for _, permission := range result.Permissions {
		switch permission {
		case "status.read", "log.read", "jobs.propose", "stop.engage", "files.transfer":
			permissions = append(permissions, permission)
		}
	}
	if result.EmergencyStop != "engaged" && result.EmergencyStop != "released" {
		result.EmergencyStop = "unavailable"
	}
	if result.Executor != "none" {
		result.Executor = "unavailable"
	}
	fmt.Fprintf(out, "Status: %s\nPermissions: %s\nEmergency Stop: %s\nExecutor: %s\n",
		result.Status, strings.Join(permissions, ", "), result.EmergencyStop, result.Executor)
	return 0
}

func runDockPropose(args []string, out, errOut io.Writer) int {
	f, pos, ok := flags(args, map[string]bool{
		"--kind": true, "--project": true, "--repo": true, "--instructions": true,
	})
	if !ok || len(pos) != 0 || f["--kind"] == "" || f["--project"] == "" || f["--repo"] == "" || f["--instructions"] == "" {
		return invalid(errOut)
	}
	validKind := false
	for _, kind := range []string{"code.generate", "code.edit", "code.test", "code.debug", "agent.handoff"} {
		validKind = validKind || f["--kind"] == kind
	}
	instructions := strings.TrimSpace(f["--instructions"])
	if !validKind || dockStringLength(strings.TrimSpace(f["--project"])) < 1 ||
		dockStringLength(strings.TrimSpace(f["--project"])) > 120 ||
		!dockRepoPattern.MatchString(f["--repo"]) || len(f["--repo"]) > 200 ||
		dockStringLength(instructions) < 3 || dockStringLength(instructions) > 4000 {
		return invalid(errOut)
	}
	if _, count := RedactSecrets([]byte(instructions)); count > 0 {
		fmt.Fprintln(errOut, "Instructions look like they may contain a secret; nothing was sent.")
		return 2
	}
	body, err := createDockJobBody(f["--kind"], strings.TrimSpace(f["--project"]), f["--repo"], instructions)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	_, state, key, err := readDockIdentity()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	reply, err := dockPost(state.Origin, dockJobsPath, state.DeviceID, key, body)
	if err != nil {
		fmt.Fprintln(errOut, "Job proposal failed:", err)
		return 1
	}
	var result struct {
		TaskID string `json:"taskId"`
		State  string `json:"state"`
	}
	if json.Unmarshal(reply, &result) != nil || result.State != "held" ||
		!dockUUIDPattern.MatchString(result.TaskID) {
		fmt.Fprintln(errOut, "Job proposal response was invalid.")
		return 1
	}
	fmt.Fprintf(out, "Proposal %s is %s in OMNI. Nothing was run.\n", result.TaskID, result.State)
	return 0
}

func runDockStop(out, errOut io.Writer) int {
	_, state, key, err := readDockIdentity()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	reply, err := dockPost(state.Origin, dockStopPath, state.DeviceID, key, []byte("{}"))
	if err != nil {
		fmt.Fprintln(errOut, "Emergency Stop request failed:", err)
		return 1
	}
	var result struct {
		EmergencyStop string `json:"emergencyStop"`
	}
	if json.Unmarshal(reply, &result) != nil || result.EmergencyStop != "engaged" {
		fmt.Fprintln(errOut, "Emergency Stop response was invalid.")
		return 1
	}
	fmt.Fprintln(out, "Emergency Stop engaged. This device cannot release it.")
	return 0
}

func runDockForget(out, errOut io.Writer) int {
	dir, err := dockDirectory()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := forgetDockFiles(dir); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintln(out, "Local dock key and device state removed. The server-side device is not revoked.")
	return 0
}

func forgetDockFiles(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("dock config path is invalid; no files removed")
	}
	parentInfo, err := os.Lstat(filepath.Dir(dir))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("dock parent config path is invalid; no files removed")
	}
	for _, name := range []string{dockKeyFile, dockStateFile} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("dock state contains a non-regular file; no files removed")
		}
	}
	for _, name := range []string{dockKeyFile, dockStateFile} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.New("dock key or state could not be removed")
		}
	}
	return nil
}

func newDockUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("job identifier could not be generated")
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func createDockJobBody(kind, project, repository, instructions string) ([]byte, error) {
	id, err := newDockUUID()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(dockJobBody{
		ID: id, Kind: kind, Agent: "jackboy", Project: project,
		Repository: repository, Instructions: instructions,
	})
	if err != nil {
		return nil, errors.New("job proposal could not be encoded")
	}
	if len(body) > dockBodyLimit {
		return nil, errors.New("dock request body exceeds 8192 bytes")
	}
	return body, nil
}

package companion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockSigningStringAndBodyHash(t *testing.T) {
	body := []byte(`{"a":1}`)
	got := dockSigningString("post", "/api/public/omni/dock/jobs", "device-1", "1700000000000", "Abcdefghijklmnop", body)
	want := "OMNI-DOCK-V1\nPOST\n/api/public/omni/dock/jobs\ndevice-1\n1700000000000\nAbcdefghijklmnop\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
	if got != want {
		t.Fatalf("canonical signing string mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestDockRawSignatureKnownVector(t *testing.T) {
	rBytes, _ := hex.DecodeString("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
	sBytes, _ := hex.DecodeString("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
	wantRaw := append(append([]byte{}, rBytes...), sBytes...)
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)
	if got := encodeDockSignature(r, s); got != base64.RawURLEncoding.EncodeToString(wantRaw) {
		t.Fatalf("raw r||s encoding mismatch: %q", got)
	}
	digest := sha256.Sum256([]byte("sample"))
	xBytes, _ := hex.DecodeString("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
	yBytes, _ := hex.DecodeString("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		t.Fatal("RFC 6979 P-256/SHA-256 known signature did not verify")
	}
}

func TestSignDockRequestProducesVerifiableRawP256Signature(t *testing.T) {
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"protocol":"omni.dock/v1"}`)
	nonce := "abcdefghijklmnop"
	timestamp := "1700000000000"
	message := dockSigningString("POST", dockPairPath, "pair", timestamp, nonce, body)
	encoded, err := signDockRequest(key, "POST", dockPairPath, "pair", timestamp, nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature is not raw r||s: %d bytes, %v", len(signature), err)
	}
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256([]byte(message))
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("signature did not verify against the canonical request")
	}
}

func TestDockSafetyCodeUsesRFC7638Thumbprint(t *testing.T) {
	jwk := dockPublicJWK{
		Kty: "EC", Crv: "P-256",
		X: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
		Y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
	}
	got, err := dockSafetyCode(jwk)
	if err != nil || got != "566 896" {
		t.Fatalf("safety code = %q, want 566 896 (err %v)", got, err)
	}
}

func TestDockPairCodeValidationAndBody(t *testing.T) {
	for _, code := range []string{"ABCDE-FGHIJ", " abcd efghi j ", "ILO01-23456"} {
		if !validDockPairCode(code) {
			t.Errorf("rejected valid pairing code %q", code)
		}
	}
	for _, code := range []string{"", "ABCDE-ABCD", "ABCDE-ABCDU", "ABCDE-ABCD?", "A B C D E F G H I J"} {
		if validDockPairCode(code) {
			t.Errorf("accepted invalid pairing code %q", code)
		}
	}
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	originalCode := " abcd efghi j "
	body, err := marshalDockPairBody(originalCode, " test device ", dockJWK(key))
	if err != nil {
		t.Fatal(err)
	}
	var pair map[string]json.RawMessage
	if err := json.Unmarshal(body, &pair); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"protocol", "code", "label", "platform", "publicKey", "appVersion", "capabilities"} {
		if _, ok := pair[field]; !ok {
			t.Errorf("pair body missing %q", field)
		}
	}
	if string(pair["code"]) != `" abcd efghi j "` || string(pair["protocol"]) != `"omni.dock/v1"` {
		t.Fatalf("pair code/protocol changed: %s", body)
	}
}

func TestDockNonceFormat(t *testing.T) {
	for range 50 {
		nonce, err := dockNonce()
		if err != nil || !dockNoncePattern.MatchString(nonce) {
			t.Fatalf("invalid nonce %q: %v", nonce, err)
		}
	}
	for _, invalid := range []string{"short", strings.Repeat("a", 65), "abcdefghijklmnop+"} {
		if dockNoncePattern.MatchString(invalid) {
			t.Fatalf("accepted invalid nonce %q", invalid)
		}
	}
}

func TestDockStoragePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evolution", "dock")
	if err := prepareDockDirectory(dir); err != nil {
		t.Fatal(err)
	}
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveDockKey(dir, key); err != nil {
		t.Fatal(err)
	}
	if err := saveDockState(dir, dockDeviceState{Origin: "https://example.test", DeviceID: "123e4567-e89b-42d3-a456-426614174000"}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		dir: 0o700, filepath.Join(dir, dockKeyFile): 0o600, filepath.Join(dir, dockStateFile): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s permissions = %04o, want %04o", filepath.Base(path), got, want)
		}
	}
	loaded, err := loadDockKey(dir)
	if err != nil || loaded.D.Cmp(key.D) != 0 {
		t.Fatalf("saved key did not round-trip: %v", err)
	}
}

func TestDockStorageRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "evolution")
	if err := os.Symlink(target, parent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	dir := filepath.Join(parent, "dock")
	if err := prepareDockDirectory(dir); err == nil {
		t.Fatal("created dock storage through a symlinked parent")
	}
	if _, err := os.Stat(filepath.Join(target, "dock")); !os.IsNotExist(err) {
		t.Fatal("symlink target was modified")
	}
}

func TestDockOriginRequiresHTTPSOrigin(t *testing.T) {
	for _, invalid := range []string{
		"http://example.test", "https://example.test/path", "https://user:pass@example.test",
		"https://example.test?x=1", "https://example.test/#fragment",
	} {
		if _, err := dockOrigin(invalid); err == nil {
			t.Errorf("accepted invalid dock URL %q", invalid)
		}
	}
	if got, err := dockOrigin("https://example.test/"); err != nil || got != "https://example.test" {
		t.Fatalf("origin normalization = %q, %v", got, err)
	}
}

func TestDockRefusesRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/destination" {
			redirected = true
			return
		}
		http.Redirect(w, r, "/destination", http.StatusFound)
	}))
	defer server.Close()
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := postDock(newDockHTTPClient(), server.URL+"/dock", "device", key, []byte("{}"), time.Now())
	if err == nil || status != http.StatusFound || redirected {
		t.Fatalf("redirect was not refused: status=%d err=%v followed=%v", status, err, redirected)
	}
}

func TestDockRejectsOversizedRequestAndResponse(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write(bytes.Repeat([]byte("x"), dockReplyLimit+1))
	}))
	defer server.Close()
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := postDock(newDockHTTPClient(), server.URL, "device", key, bytes.Repeat([]byte("x"), dockBodyLimit+1), time.Now()); err == nil {
		t.Fatal("oversized request body accepted")
	}
	if requests != 0 {
		t.Fatal("oversized request was sent")
	}
	_, _, err = postDock(newDockHTTPClient(), server.URL, "device", key, []byte("{}"), time.Now())
	if err == nil || !strings.Contains(err.Error(), "65536 bytes") {
		t.Fatalf("oversized response not refused: %v", err)
	}
}

func TestDockProposeNeverSendsAutonomous(t *testing.T) {
	body, err := createDockJobBody("code.test", "demo", "OWNER/REPO", "Run the focused tests")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan map[string]json.RawMessage, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		received <- payload
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"taskId":"123e4567-e89b-42d3-a456-426614174000","state":"held"}`))
	}))
	defer server.Close()
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := postDock(newDockHTTPClient(), server.URL+dockJobsPath, "device", key, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	payload := <-received
	if _, found := payload["autonomous"]; found {
		t.Fatal("job proposal included autonomous")
	}
	if string(payload["agent"]) != `"jackboy"` || string(payload["kind"]) != `"code.test"` {
		t.Fatalf("unexpected proposal fields: %s", body)
	}
}

func TestDockProposeRefusesSecretLikeInstructions(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runDockPropose([]string{
		"--kind", "code.test", "--project", "demo", "--repo", "OWNER/REPO",
		"--instructions", "Use token ghp_123456789012345678901234567890123456",
	}, &out, &errOut)
	if code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "secret") {
		t.Fatalf("secret-like proposal was not refused: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestDockForgetOnlyRemovesDockFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evolution", "dock")
	if err := prepareDockDirectory(dir); err != nil {
		t.Fatal(err)
	}
	key, err := newDockKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveDockKey(dir, key); err != nil {
		t.Fatal(err)
	}
	if err := saveDockState(dir, dockDeviceState{Origin: "https://example.test", DeviceID: "123e4567-e89b-42d3-a456-426614174000"}); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := forgetDockFiles(dir); err != nil {
		t.Fatalf("forget failed: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("forget removed unrelated file")
	}
	if _, err := os.Stat(filepath.Join(dir, dockKeyFile)); !os.IsNotExist(err) {
		t.Fatal("private key remains after forget")
	}
}

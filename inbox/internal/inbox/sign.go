// Package inbox is OMNI's job inbox and worker for jobs sent by Jackboy.
package inbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HMACHex returns hex(HMAC-SHA256(secret, message)).
func HMACHex(secret, message string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}

// Sign produces the X-Omni-Signature value Jackboy verifies: sha256=HMAC(secret, ts.nonce.body).
func Sign(secret, ts, nonce, body string) string {
	return "sha256=" + HMACHex(secret, ts+"."+nonce+"."+body)
}

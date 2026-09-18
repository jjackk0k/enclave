// envelope.go — PER-HOP ENVELOPE ENCRYPTION, ported byte-exact from the platform's
// engine/envelope.mjs (READ THAT FIRST — it is the spec). The governed envelopes were
// HMAC-authenticated but CLEARTEXT; this layer AEAD-seals the CONTENT end-to-end
// agent↔listener. Encrypt-then-MAC is preserved: the existing HMAC formulas now
// authenticate the CIPHERTEXT (the push HMAC covers sha256 of the SEALED body), and
// the listener verifies HMAC BEFORE any decryption runs — no decryption oracle.
//
// BYTE CONTRACT (must match engine/envelope.mjs exactly — the parity vectors in
// envelope_test.go prove it against the Node engine itself, both directions):
//   key  = HKDF-SHA256(ikm = token, salt = 'varvel-envelope-v1',
//                      info = 'varvel-env:' + agentId, 32 bytes)
//   blob = 'VE' || 0x01 || nonce(12) || ciphertext || tag(16)   (chacha20-poly1305,
//          fresh random nonce per seal, NO AAD, no cipher-level replay state — the
//          HMAC layer's strict seq owns replay, key-rotation-safe)
//   str  = 'enc1:' + base64url(blob)  — base64url WITHOUT padding (RFC 4648 §5),
//          matching Node's Buffer.toString('base64url') exactly.
//   The empty reply (idle/deny, the 204-uniform doctrine) is NEVER sealed.
//
// HKDF info separation: 'varvel-env:' is DISJOINT from the pivot mesh's 'varvel-link:'
// domain — a relay parent's link keys can never derive this key (HMAC is one-way from
// the token), so the parent forwards OPAQUE ciphertext. See engine/envelope.mjs.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	envVersion = 1
	envKeyLen  = 32 // HKDF output / chacha20poly1305 key
	envNonceLn = 12 // chacha20-poly1305 nonce
	envTagLen  = 16 // poly1305 tag
	envPrefix  = "enc1:"

	envKeySalt = "varvel-envelope-v1" // HKDF salt (domain pin, not a secret)
	envKeyInfo = "varvel-env:"        // HKDF info prefix — DISJOINT from 'varvel-link:'
)

// envMagic is the blob self-description header: 'VE' + version byte.
var envMagic = []byte{0x56, 0x45, envVersion}

// EnvelopeError is the typed failure — callers audit Code and fail closed. Codes
// mirror engine/envelope.mjs: 'key' (derivation inputs), 'shape' (malformed
// blob/string), 'open' (tag mismatch — tamper or wrong key), 'seal' (seal inputs).
type EnvelopeError struct {
	Msg  string
	Code string
}

func (e *EnvelopeError) Error() string { return e.Msg }

func envErr(code, msg string) *EnvelopeError { return &EnvelopeError{Msg: msg, Code: code} }

// deriveEncKey mirrors engine/envelope.mjs deriveEncKey: HKDF-SHA256 keyed by the
// agent TOKEN, info-separated per agent id. One-way: envelopes carry only
// nonce||ct||tag — no token material is recoverable from them.
func deriveEncKey(token, agentID string) ([]byte, error) {
	if token == "" {
		return nil, envErr("key", "deriveEncKey: token required")
	}
	if agentID == "" {
		return nil, envErr("key", "deriveEncKey: agent id required")
	}
	r := hkdf.New(sha256.New, []byte(token), []byte(envKeySalt), []byte(envKeyInfo+agentID))
	key := make([]byte, envKeyLen)
	if _, err := io.ReadFull(r, key); err != nil { // cannot happen for 32 bytes of SHA256-HKDF
		return nil, envErr("key", "deriveEncKey: hkdf read: "+err.Error())
	}
	return key, nil
}

// isSealedBytes is the self-description check on DECODED content bytes (an http /r body).
func isSealedBytes(buf []byte) bool {
	if len(buf) < len(envMagic)+envNonceLn+envTagLen {
		return false
	}
	for i, b := range envMagic {
		if buf[i] != b {
			return false
		}
	}
	return true
}

// sealBytes AEAD-seals plaintext: random 12B nonce per call; output = MAGIC||nonce||ct||tag.
func sealBytes(key, plaintext []byte) ([]byte, error) {
	if len(key) != envKeyLen {
		return nil, envErr("seal", "sealBytes: a 32-byte encKey is required (deriveEncKey)")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, envErr("seal", "sealBytes: "+err.Error())
	}
	nonce := make([]byte, envNonceLn)
	if _, err := rand.Read(nonce); err != nil {
		return nil, envErr("seal", "sealBytes: nonce: "+err.Error())
	}
	out := make([]byte, 0, len(envMagic)+envNonceLn+len(plaintext)+envTagLen)
	out = append(out, envMagic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil // no AAD — Node parity
}

// openBytes AEAD-opens a sealed blob. 'shape' on a malformed blob, 'open' on a tag
// mismatch (tamper / wrong key) — NO plaintext or partial detail leaves on failure
// (no oracle), exactly like the Node original.
func openBytes(key, blob []byte) ([]byte, error) {
	if len(key) != envKeyLen {
		return nil, envErr("key", "openBytes: a 32-byte encKey is required (deriveEncKey)")
	}
	if !isSealedBytes(blob) {
		return nil, envErr("shape", "openBytes: not a sealed envelope blob")
	}
	nonce := blob[len(envMagic) : len(envMagic)+envNonceLn]
	ct := blob[len(envMagic)+envNonceLn:]
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, envErr("key", "openBytes: "+err.Error())
	}
	plain, err := aead.Open(nil, nonce, ct, nil) // ct = ciphertext||tag (Seal layout)
	if err != nil {
		return nil, envErr("open", "envelope open failed (tamper or wrong key)")
	}
	return plain, nil
}

// ——— sealed STRING form (the sealed http /c task-reply body) ———

func isSealedString(s string) bool { return len(s) >= len(envPrefix) && s[:len(envPrefix)] == envPrefix }

// sealString: 'enc1:' + base64url(blob) — RawURLEncoding = Node base64url (no padding).
func sealString(key []byte, s string) (string, error) {
	blob, err := sealBytes(key, []byte(s))
	if err != nil {
		return "", err
	}
	return envPrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

func openString(key []byte, s string) (string, error) {
	if !isSealedString(s) {
		return "", envErr("shape", "openString: not a sealed envelope string")
	}
	blob, err := base64.RawURLEncoding.DecodeString(s[len(envPrefix):])
	if err != nil {
		return "", envErr("shape", "openString: bad base64url: "+err.Error())
	}
	plain, err := openBytes(key, blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

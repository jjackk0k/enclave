// envelope_test.go — unit coverage for the envelope port PLUS the core parity proof:
// cross-decryption against the REAL Node engine (engine/envelope.mjs), driven live
// through agents/native/harness/enc-vectors.mjs:
//
//	DOWN  (Node → Go): the harness emits the derived key + Node-sealed blobs/strings
//	      for a fixed token+agentId+payload set; THIS test derives the same key and
//	      OPENS every one. Plaintext detection verdicts must agree too.
//	UP    (Go → Node): THIS test seals the same payload set, writes a vector file
//	      (repo .tmp — the payload-artifact rule), and the harness OPENS each one
//	      with the Node engine (exit 1 on any mismatch).
//
// Skipped cleanly when no node runtime is on PATH (the unit half stays hermetic).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	envVecToken = "a1b2c3d4e5f60718293a4b5c6d7e8f90" // harness-fixed vector constants
	envVecID    = "f00ba7cafe01"
)

func envTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := deriveEncKey(envVecToken, envVecID)
	if err != nil {
		t.Fatalf("deriveEncKey: %v", err)
	}
	return key
}

func TestEnvelopeKeyDerivation(t *testing.T) {
	key := envTestKey(t)
	if len(key) != 32 {
		t.Fatalf("key len %d, want 32", len(key))
	}
	// Deterministic + agent-scoped + token-bound (engine/envelope.mjs hierarchy rules).
	again, _ := deriveEncKey(envVecToken, envVecID)
	if !bytes.Equal(key, again) {
		t.Fatal("same token+id must derive the same key")
	}
	otherID, _ := deriveEncKey(envVecToken, "agent02")
	if bytes.Equal(key, otherID) {
		t.Fatal("different agent id must derive a different key")
	}
	otherTok, _ := deriveEncKey("ffffffffffffffffffffffffffffffff", envVecID)
	if bytes.Equal(key, otherTok) {
		t.Fatal("different token must derive a different key")
	}
	if _, err := deriveEncKey("", envVecID); err == nil {
		t.Fatal("empty token must fail")
	}
	if _, err := deriveEncKey(envVecToken, ""); err == nil {
		t.Fatal("empty agent id must fail")
	}
}

func TestEnvelopeBlobLayoutAndRoundTrip(t *testing.T) {
	key := envTestKey(t)
	pt := []byte("governed wire content")
	blob, err := sealBytes(key, pt)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}
	// Layout: 'VE'||0x01||nonce(12)||ct||tag(16) — engine/envelope.mjs byte contract.
	if len(blob) != 3+12+len(pt)+16 {
		t.Fatalf("blob len %d, want %d", len(blob), 3+12+len(pt)+16)
	}
	if blob[0] != 0x56 || blob[1] != 0x45 || blob[2] != 0x01 {
		t.Fatalf("bad magic/version: % x", blob[:3])
	}
	if !isSealedBytes(blob) {
		t.Fatal("own sealed blob must self-describe")
	}
	opened, err := openBytes(key, blob)
	if err != nil {
		t.Fatalf("openBytes: %v", err)
	}
	if !bytes.Equal(opened, pt) {
		t.Fatalf("round trip: got %q want %q", opened, pt)
	}
	// Fresh nonce per seal: two seals of the same plaintext differ.
	blob2, _ := sealBytes(key, pt)
	if bytes.Equal(blob, blob2) {
		t.Fatal("nonce reuse: two seals produced identical blobs")
	}
	// Wrong key => 'open', tamper => 'open', truncation => 'shape'.
	otherTok, _ := deriveEncKey("ffffffffffffffffffffffffffffffff", envVecID)
	_, err = openBytes(otherTok, blob)
	assertEnvCode(t, err, "open")
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = openBytes(key, tampered)
	assertEnvCode(t, err, "open")
	_, err = openBytes(key, blob[:len(blob)-4]) // long enough to parse, tag broken
	assertEnvCode(t, err, "open")
	_, err = openBytes(key, blob[:3+12+16-1]) // below the minimum blob size
	assertEnvCode(t, err, "shape")
	_, err = openBytes(key, []byte("plaintext body"))
	assertEnvCode(t, err, "shape")
	// Seal/open input discipline.
	if _, err := sealBytes([]byte("short"), pt); envCode(err) != "seal" {
		t.Fatalf("short key seal: %v", err)
	}
	if _, err := openBytes([]byte("short"), blob); envCode(err) != "key" {
		t.Fatalf("short key open: %v", err)
	}
	// Plaintext detection.
	if isSealedBytes(pt) || isSealedBytes(nil) {
		t.Fatal("plaintext must not self-describe as sealed")
	}
}

func TestEnvelopeStringForm(t *testing.T) {
	key := envTestKey(t)
	s, err := sealString(key, "hello ümläut ☃")
	if err != nil {
		t.Fatalf("sealString: %v", err)
	}
	if !isSealedString(s) || !strings.HasPrefix(s, "enc1:") {
		t.Fatalf("sealed string must carry the enc1: prefix: %q", s)
	}
	// base64url WITHOUT padding, Node-exact: decode the payload and check the blob.
	raw, err := base64.RawURLEncoding.DecodeString(s[len("enc1:"):])
	if err != nil {
		t.Fatalf("string payload must be raw base64url: %v", err)
	}
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("base64url alphabet violated (or padding present): %q", s)
	}
	if !isSealedBytes(raw) {
		t.Fatal("decoded string payload must be a sealed blob")
	}
	back, err := openString(key, s)
	if err != nil {
		t.Fatalf("openString: %v", err)
	}
	if back != "hello ümläut ☃" {
		t.Fatalf("string round trip: %q", back)
	}
	if isSealedString("enc1") || isSealedString("") || isSealedString("enc2:x") {
		t.Fatal("plaintext / near-miss prefixes must not read as sealed strings")
	}
	if _, err := openString(key, "not sealed"); envCode(err) != "shape" {
		t.Fatalf("openString plaintext: %v", err)
	}
}

func envCode(err error) string {
	var ee *EnvelopeError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ""
}

func assertEnvCode(t *testing.T, err error, code string) {
	t.Helper()
	if envCode(err) != code {
		t.Fatalf("want EnvelopeError code %q, got %v", code, err)
	}
}

// ——— the parity proof against the live Node engine ———

type envVectorDoc struct {
	Token   string `json:"token"`
	AgentID string `json:"agentId"`
	KeyHex  string `json:"keyHex"`
	Vectors []struct {
		Name     string `json:"name"`
		PlainHex string `json:"plainHex"`
		BlobHex  string `json:"blobHex"`
		String   string `json:"string,omitempty"` // blob-only vectors omit the string form
	} `json:"vectors"`
	Plaintext []struct {
		Name          string `json:"name"`
		Hex           string `json:"hex"`
		Utf8          string `json:"utf8"`
		IsSealedBytes bool   `json:"isSealedBytes"`
		IsSealedStr   bool   `json:"isSealedString"`
	} `json:"plaintext"`
}

func TestEnvelopeNodeParity(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node runtime not on PATH — live cross-decryption parity proof skipped (unit half above is hermetic)")
	}
	harness := filepath.Join("harness", "enc-vectors.mjs")

	// DOWN: Node seals, Go opens.
	out, err := exec.Command(node, harness, "emit").Output()
	if err != nil {
		t.Fatalf("harness emit: %v", err)
	}
	var doc envVectorDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("harness emit JSON: %v", err)
	}
	key := envTestKey(t)
	if hex.EncodeToString(key) != doc.KeyHex {
		t.Fatalf("HKDF key mismatch: go %x node %s", key, doc.KeyHex)
	}
	for _, v := range doc.Vectors {
		plain, err := hex.DecodeString(v.PlainHex)
		if err != nil {
			t.Fatalf("%s: bad plainHex: %v", v.Name, err)
		}
		blob, err := hex.DecodeString(v.BlobHex)
		if err != nil {
			t.Fatalf("%s: bad blobHex: %v", v.Name, err)
		}
		opened, err := openBytes(key, blob)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("Node→Go blob %s: open err=%v match=%v", v.Name, err, bytes.Equal(opened, plain))
		}
		if v.String != "" {
			got, err := openString(key, v.String)
			if err != nil || string(plain) != got {
				t.Fatalf("Node→Go string %s: open err=%v match=%v", v.Name, err, string(plain) == got)
			}
		}
		t.Logf("Node→Go opened %-12s blob(%db)%s", v.Name, len(blob), map[bool]string{true: " + string", false: ""}[v.String != ""])
	}
	// Plaintext detection parity: Node's verdicts must hold on the Go side.
	for _, p := range doc.Plaintext {
		if p.Hex != "" {
			b, _ := hex.DecodeString(p.Hex)
			if isSealedBytes(b) != p.IsSealedBytes {
				t.Fatalf("plaintext %s: isSealedBytes disagreement (node=%v)", p.Name, p.IsSealedBytes)
			}
		}
		if isSealedBytes([]byte(p.Utf8)) != p.IsSealedBytes {
			t.Fatalf("plaintext %s: isSealedBytes(utf8) disagreement", p.Name)
		}
		if isSealedString(p.Utf8) != p.IsSealedStr {
			t.Fatalf("plaintext %s: isSealedString disagreement", p.Name)
		}
	}

	// UP: Go seals, Node opens. Same fixed payload set, same file shape.
	up := envVectorDoc{Token: envVecToken, AgentID: envVecID}
	for _, v := range doc.Vectors {
		plain, _ := hex.DecodeString(v.PlainHex)
		blob, err := sealBytes(key, plain)
		if err != nil {
			t.Fatalf("go seal %s: %v", v.Name, err)
		}
		uv := struct {
			Name     string `json:"name"`
			PlainHex string `json:"plainHex"`
			BlobHex  string `json:"blobHex"`
			String   string `json:"string,omitempty"`
		}{Name: v.Name, PlainHex: v.PlainHex, BlobHex: hex.EncodeToString(blob)}
		if v.String != "" {
			uv.String, err = sealString(key, string(plain))
			if err != nil {
				t.Fatalf("go sealString %s: %v", v.Name, err)
			}
		}
		up.Vectors = append(up.Vectors, uv)
	}
	for _, p := range doc.Plaintext {
		up.Plaintext = append(up.Plaintext, p) // echo the detection set back for Node to re-check
	}
	tmpDir := filepath.Join("..", "..", ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf(".tmp: %v", err)
	}
	f, err := os.CreateTemp(tmpDir, "go-enc-vectors-*.json")
	if err != nil {
		t.Fatalf("vector file: %v", err)
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(up); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
	f.Close()
	cmd := exec.Command(node, harness, "open", f.Name())
	rep, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go→Node open FAILED: %v\n%s", err, rep)
	}
	t.Logf("Go→Node: %s", bytes.TrimSpace(rep))
}

// ja4_test.go — the Go JA4 observer leg validated two ways:
//
//  1. The OFFICIAL FoxIO worked example (JA4.md "Example" + rust tls.rs test vector),
//     the same object-level vector varvel/test/fporacle.test.mjs pins for the Node
//     oracle: t13d1516h2_8daaf6152771_e5627efa2ab1.
//  2. WIRE-BYTE parity with the Node oracle: the exact hand-crafted ClientHello
//     buffer from test/fporacle.test.mjs (GREASE in ciphers/extensions/sigalgs, SNI
//     example.com, ALPN h2+http/1.1) must parse and fingerprint IDENTICALLY in both
//     implementations: t13d0304h2_54093f43ad55_ef5f37ab036a. Cross-implementation
//     vectors are the point — same bytes in, same string out, on both sides.
package ja4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The official JA4.md worked example (object form — what parseClientHello yields).
func TestOfficialWorkedExample(t *testing.T) {
	ch := &ClientHello{
		Version: 0x0304,
		Ciphers: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions: []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		SNI:      "example.com",
		HasSNI:   true,
		ALPN:     []string{"h2"},
		SigAlgs:  []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}
	if got := JA4(ch); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("official JA4.md worked example: got %s", got)
	}
}

// The Node oracle's section derivations, pinned in Go too (test/fporacle.test.mjs):
// hash12('002f,1301,c02f') = 54093f43ad55; hash12('000d,002b_0403,0804') = ef5f37ab036a.
func TestHash12SectionDerivations(t *testing.T) {
	if got := Hash12("002f,1301,c02f"); got != "54093f43ad55" {
		t.Fatalf("b-section derivation: got %s", got)
	}
	if got := Hash12("000d,002b_0403,0804"); got != "ef5f37ab036a" {
		t.Fatalf("c-section derivation: got %s", got)
	}
	if got := Hash12(""); got != "000000000000" {
		t.Fatalf("empty-section convention: got %s (want literal zeros, never sha256(''))", got)
	}
}

// clientHelloFixture is byte-identical to clientHelloBuf() in test/fporacle.test.mjs:
// ciphers [1301 c02f 002f + GREASE 0a0a]; extensions [GREASE 1a1a, SNI example.com,
// ALPN h2+http/1.1, supported_versions 0304+0303, sigalgs 0403 0804 + GREASE 0a0a].
func clientHelloFixture(t *testing.T) []byte {
	t.Helper()
	u16 := func(vs ...int) []byte {
		out := make([]byte, 0, len(vs)*2)
		for _, v := range vs {
			out = append(out, byte(v>>8), byte(v))
		}
		return out
	}
	extRec := func(typ int, data []byte) []byte {
		return bytes.Join([][]byte{u16(typ, len(data)), data}, nil)
	}
	sni := []byte("example.com")
	exts := bytes.Join([][]byte{
		extRec(0x1a1a, nil),
		extRec(0x0000, bytes.Join([][]byte{u16(3 + len(sni)), {0x00}, u16(len(sni)), sni}, nil)),
		extRec(0x0010, bytes.Join([][]byte{u16(12), {2}, []byte("h2"), {8}, []byte("http/1.1")}, nil)),
		extRec(0x002b, bytes.Join([][]byte{{4}, u16(0x0304, 0x0303)}, nil)),
		extRec(0x000d, bytes.Join([][]byte{u16(6), u16(0x0403, 0x0804, 0x0a0a)}, nil)),
	}, nil)
	ciphers := u16(0x1301, 0xc02f, 0x002f, 0x0a0a)
	body := bytes.Join([][]byte{
		u16(0x0303), bytes.Repeat([]byte{0x11}, 32), {0},
		u16(len(ciphers)), ciphers,
		{1, 0},
		u16(len(exts)), exts,
	}, nil)
	hs := bytes.Join([][]byte{{1}, {byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body}, nil)
	return bytes.Join([][]byte{{22, 3, 1}, u16(len(hs)), hs}, nil)
}

func TestWireByteParityWithNodeOracle(t *testing.T) {
	parsed := ParseClientHello(clientHelloFixture(t))
	if parsed == nil {
		t.Fatal("fixture ClientHello failed to parse")
	}
	if parsed.Version != 0x0304 {
		t.Fatalf("true version: got %04x want 0304", parsed.Version)
	}
	if parsed.SNI != "example.com" || !parsed.HasSNI {
		t.Fatalf("sni: got %q present=%v", parsed.SNI, parsed.HasSNI)
	}
	if len(parsed.ALPN) != 2 || parsed.ALPN[0] != "h2" || parsed.ALPN[1] != "http/1.1" {
		t.Fatalf("alpn: got %v", parsed.ALPN)
	}
	// The Node oracle's exact string for these bytes (test/fporacle.test.mjs).
	if got := JA4(parsed); got != "t13d0304h2_54093f43ad55_ef5f37ab036a" {
		t.Fatalf("wire-byte parity: got %s want t13d0304h2_54093f43ad55_ef5f37ab036a (Node oracle)", got)
	}
}

func TestFailClosed(t *testing.T) {
	for _, junk := range [][]byte{
		nil, {}, {1, 2, 3}, {22, 3, 1, 0, 2, 9, 9}, {23, 3, 3, 0, 1, 0},
	} {
		if ParseClientHello(junk) != nil {
			t.Fatalf("garbage parsed: %x", junk)
		}
	}
	if JA4(nil) != "" {
		t.Fatal("JA4(nil) must be empty, never a guess")
	}
	if !IsGrease(0x0a0a) || !IsGrease(0xfafa) || IsGrease(0x1301) || IsGrease(0x0a0b) {
		t.Fatal("GREASE filter misbehaving")
	}
	if AlpnCode("") != "00" || AlpnCode("h2") != "h2" {
		t.Fatal("alpn code misbehaving")
	}
	// Non-ASCII edge byte: JA4.md hex rule (0x20 0x61 -> '21').
	if got := AlpnCode(string(mustHex(t, "2061"))); got != "21" {
		t.Fatalf("alpn hex rule: got %s want 21", got)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

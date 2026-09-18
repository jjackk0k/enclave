// Package ja4 is the pure-Go client-JA4 observer leg for the VARVEL native agent.
//
// It is a FAITHFUL PORT of the platform's own oracle, varvel/engine/fingerprint.mjs
// (parseClientHello + ja4), implementing the FoxIO JA4 spec
// (https://github.com/FoxIO-LLC/ja4, technical_details/JA4.md) from raw ClientHello
// bytes: TLS-over-TCP only, GREASE (RFC 8701) filtered exactly where the spec says,
// the JA4+ empty-section convention ('000000000000', never sha256('')), and the
// JA4.md ALPN edge-byte hex rule. Cross-implementation parity with the Node oracle is
// pinned by test vectors in ja4_test.go (same input bytes -> same fingerprint string).
//
// THE HONESTY CONTRACT (same as the platform oracle): a fingerprint is a MEASUREMENT,
// never a verdict. This package REPORTS what a defender's JA4 stack would see; it never
// claims undetectability. Fail-closed by contract: nil on anything unexpected.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// ClientHello is the parsed wire shape JA4 keys on.
type ClientHello struct {
	Version    uint16   // true version: highest non-GREASE supported_versions offer, else legacy_version
	Ciphers    []uint16 // as presented
	Extensions []uint16 // types as presented (duplicates kept, first data wins)
	SNI        string   // first DNS host name from ext 0x0000 ("" when absent)
	HasSNI     bool     // SNI extension PRESENT (JA4 keys on presence, not the value)
	ALPN       []string // protocol_name_list from ext 0x0010
	SigAlgs    []uint16 // signature_algorithms ext 0x000d, as presented
}

// Hash12 is the JA4+ section hash: first 12 lowercase-hex chars of sha256; an EMPTY
// input is the literal "000000000000" (JA4.md for _b_/_c_; the published CSV rows).
func Hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// IsGrease reports whether v is an RFC 8701 GREASE value (0x?a?a, both bytes equal).
func IsGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == (v>>8)&0xff
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12&0xf], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]})
}

// TLS version -> JA4 2-char code (JA4.md table; TCP TLS only, no DTLS codes).
func versionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

// AlpnCode is the JA4 _a_ ALPN code: first + last char of the FIRST ALPN value ("00"
// when absent). When either edge byte is not ASCII alphanumeric, JA4.md hex-encodes
// the value and takes the first/last hex chars instead.
func AlpnCode(first string) string {
	if first == "" {
		return "00"
	}
	b := []byte(first)
	alnum := func(c byte) bool {
		return c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5a || c >= 0x61 && c <= 0x7a
	}
	f, l := b[0], b[len(b)-1]
	if alnum(f) && alnum(l) {
		return string([]byte{f, l})
	}
	h := hex.EncodeToString(b)
	return h[:1] + h[len(h)-1:]
}

type countingReader struct {
	b   []byte
	off int
}

func (r *countingReader) u8() (int, bool) {
	if r.off+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return int(v), true
}

func (r *countingReader) u16() (uint16, bool) {
	if r.off+2 > len(r.b) {
		return 0, false
	}
	v := uint16(r.b[r.off])<<8 | uint16(r.b[r.off+1])
	r.off += 2
	return v, true
}

func (r *countingReader) u24() (int, bool) {
	if r.off+3 > len(r.b) {
		return 0, false
	}
	v := int(r.b[r.off])<<16 | int(r.b[r.off+1])<<8 | int(r.b[r.off+2])
	r.off += 3
	return v, true
}

func (r *countingReader) take(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

// ParseClientHello parses ONE TLS record's worth of bytes (extra trailing bytes are
// ignored, mirroring the Node oracle) into a ClientHello, or nil on anything
// unexpected — fail-closed, never a guess, never a panic.
func ParseClientHello(buf []byte) *ClientHello {
	// --- record framing ---
	if len(buf) < 5 {
		return nil
	}
	r := &countingReader{b: buf}
	contentType, ok := r.u8()
	if !ok || contentType != 22 { // handshake records only
		return nil
	}
	if _, ok = r.u16(); !ok { // legacy record version
		return nil
	}
	recLen, ok := r.u16()
	if !ok {
		return nil
	}
	recBody, ok := r.take(int(recLen))
	if !ok {
		return nil
	}
	// --- handshake framing: client_hello(1) ---
	hs := &countingReader{b: recBody}
	hsType, ok := hs.u8()
	if !ok || hsType != 1 {
		return nil
	}
	hsLen, ok := hs.u24()
	if !ok {
		return nil
	}
	body, ok := hs.take(hsLen)
	if !ok || len(body) < 34 {
		return nil
	}
	// --- hello body ---
	h := &countingReader{b: body}
	legacyVersion, ok := h.u16()
	if !ok {
		return nil
	}
	if _, ok = h.take(32); !ok { // random
		return nil
	}
	sidLen, ok := h.u8()
	if !ok {
		return nil
	}
	if _, ok = h.take(sidLen); !ok {
		return nil
	}
	cipherLen, ok := h.u16()
	if !ok || cipherLen < 2 || cipherLen%2 != 0 {
		return nil
	}
	cipherBytes, ok := h.take(int(cipherLen))
	if !ok {
		return nil
	}
	ch := &ClientHello{Version: legacyVersion}
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		ch.Ciphers = append(ch.Ciphers, uint16(cipherBytes[i])<<8|uint16(cipherBytes[i+1]))
	}
	compLen, ok := h.u8()
	if !ok || compLen < 1 {
		return nil
	}
	if _, ok = h.take(compLen); !ok {
		return nil
	}
	// --- extension block: exact-fit required (trailing junk = not ours) ---
	extTypes, extData, ok := parseExtensions(h)
	if !ok {
		return nil
	}
	ch.Extensions = extTypes

	// SNI (0x0000): first DNS host name; JA4 keys on extension PRESENCE.
	if d, present := extData[0x0000]; present {
		ch.HasSNI = true
		if name, ok := parseSNI(d); ok {
			ch.SNI = name
		} else {
			return nil
		}
	}
	// ALPN (0x0010): protocol_name_list = listLen(2) [len(1) bytes]*.
	if d, present := extData[0x0010]; present {
		alpn, ok := parseALPN(d)
		if !ok {
			return nil
		}
		ch.ALPN = alpn
	}
	// supported_versions (0x002b), CLIENT form: listLen(1) + versions(2)*; the true
	// version is the highest non-GREASE offer.
	if d, present := extData[0x002b]; present {
		if v, ok := parseSupportedVersions(d); ok {
			if v != 0 {
				ch.Version = v
			}
		} else {
			return nil
		}
	}
	// signature_algorithms (0x000d): listLen(2) + algorithms(2)*.
	if d, present := extData[0x000d]; present {
		sa, ok := parseSigAlgs(d)
		if !ok {
			return nil
		}
		ch.SigAlgs = sa
	}
	return ch
}

// Extension-block walk: [type(2) len(2) data]*, exact-fit required. Returns the types
// in presented order + first-data-per-type map; no block at all (pre-TLS1.3 legal) is
// an empty result, not an error.
func parseExtensions(h *countingReader) ([]uint16, map[uint16][]byte, bool) {
	types := []uint16{}
	data := map[uint16][]byte{}
	if h.off == len(h.b) {
		return types, data, true
	}
	extLen, ok := h.u16()
	if !ok {
		return nil, nil, false
	}
	if h.off+int(extLen) != len(h.b) {
		return nil, nil, false
	}
	end := h.off + int(extLen)
	for h.off+4 <= end {
		typ, _ := h.u16()
		l, _ := h.u16()
		if h.off+int(l) > end {
			return nil, nil, false
		}
		d, _ := h.take(int(l))
		types = append(types, typ)
		if _, dup := data[typ]; !dup {
			data[typ] = d
		}
	}
	if h.off != end {
		return nil, nil, false
	}
	return types, data, true
}

func parseSNI(d []byte) (string, bool) {
	r := &countingReader{b: d}
	listLen, ok := r.u16()
	if !ok || r.off+int(listLen) != len(d) {
		return "", false
	}
	name := ""
	for r.off < len(d) {
		nameType, ok1 := r.u8()
		nameLen, ok2 := r.u16()
		if !ok1 || !ok2 {
			return "", false
		}
		nb, ok3 := r.take(int(nameLen))
		if !ok3 {
			return "", false
		}
		if nameType == 0 && name == "" {
			name = string(nb)
		}
	}
	return name, true
}

func parseALPN(d []byte) ([]string, bool) {
	r := &countingReader{b: d}
	listLen, ok := r.u16()
	if !ok || r.off+int(listLen) != len(d) {
		return nil, false
	}
	out := []string{}
	for r.off < len(d) {
		l, ok := r.u8()
		if !ok {
			return nil, false
		}
		p, ok := r.take(l)
		if !ok {
			return nil, false
		}
		out = append(out, string(p))
	}
	return out, true
}

func parseSupportedVersions(d []byte) (uint16, bool) {
	r := &countingReader{b: d}
	l, ok := r.u8()
	if !ok || l < 2 || l%2 != 0 || r.off+l != len(d) {
		return 0, false
	}
	best := uint16(0)
	for i := 0; i < l; i += 2 {
		v, _ := r.u16()
		if !IsGrease(v) && v > best {
			best = v
		}
	}
	return best, true
}

func parseSigAlgs(d []byte) ([]uint16, bool) {
	r := &countingReader{b: d}
	l, ok := r.u16()
	if !ok || l < 2 || l%2 != 0 || r.off+int(l) != len(d) {
		return nil, false
	}
	out := []uint16{}
	for i := 0; i < int(l); i += 2 {
		v, _ := r.u16()
		out = append(out, v)
	}
	return out, true
}

func min2(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string([]rune{rune('0' + n/10), rune('0' + n%10)})
}

// JA4 renders the FoxIO JA4 fingerprint: t + ver(2) + sni(d/i) + cipherCount(2) +
// extCount(2) + alpn(2) _ hash12(sorted cipher hex) _ hash12(sorted ext hex excl.
// SNI+ALPN '_' sigalgs as presented). nil in -> "" out (fail-closed).
func JA4(ch *ClientHello) string {
	if ch == nil {
		return ""
	}
	ciphers := []uint16{}
	for _, v := range ch.Ciphers {
		if !IsGrease(v) {
			ciphers = append(ciphers, v)
		}
	}
	exts := []uint16{}
	for _, v := range ch.Extensions {
		if !IsGrease(v) {
			exts = append(exts, v)
		}
	}
	sigalgs := []uint16{}
	for _, v := range ch.SigAlgs {
		if !IsGrease(v) {
			sigalgs = append(sigalgs, v)
		}
	}
	first := ""
	if len(ch.ALPN) > 0 {
		first = ch.ALPN[0]
	}
	a := "t" + versionCode(ch.Version)
	if ch.HasSNI {
		a += "d"
	} else {
		a += "i"
	}
	a += min2(len(ciphers)) + min2(len(exts)) + AlpnCode(first)

	cipherHex := make([]string, 0, len(ciphers))
	for _, v := range ciphers {
		cipherHex = append(cipherHex, hex4(v))
	}
	sort.Strings(cipherHex)
	b := Hash12(strings.Join(cipherHex, ","))

	// The extension hash list EXCLUDES SNI (0000) and ALPN (0010) — already in _a_.
	extHex := make([]string, 0, len(exts))
	for _, v := range exts {
		extHex = append(extHex, hex4(v))
	}
	sort.Strings(extHex)
	kept := extHex[:0]
	for _, hx := range extHex {
		if hx != "0000" && hx != "0010" {
			kept = append(kept, hx)
		}
	}
	sigHex := make([]string, 0, len(sigalgs))
	for _, v := range sigalgs {
		sigHex = append(sigHex, hex4(v))
	}
	cIn := strings.Join(kept, ",")
	if len(sigHex) > 0 { // no sigalgs -> the string ends WITHOUT the underscore (JA4.md)
		cIn += "_" + strings.Join(sigHex, ",")
	}
	return a + "_" + b + "_" + Hash12(cIn)
}

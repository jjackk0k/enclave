// ja4_capture_test.go — the centerpiece measurement: what does THIS binary's
// ClientHello actually look like on the wire, per -tls-profile, rendered into the
// industry-standard JA4 by our own observer leg (agents/native/ja4, the Go port of
// engine/fingerprint.mjs). Pure loopback, no server half needed: the ClientHello is a
// cleartext record — capture the first record off the wire, fingerprint it, done.
//
// Asserted, not claimed:
//   (a) go-native JA4 != chrome JA4 (the profile flag demonstrably changes the wire);
//   (b) the chrome profile matches the DOCUMENTED Chrome-on-Windows JA4 shape —
//       t13d15XXh2_8daaf6152771_* : TLS1.3, SNI present, 15 ciphers (the stable
//       Chrome cipher list whose sorted-list hash is 8daaf6152771), ALPN h2 first.
//       References: FoxIO JA4 issue #31 (Chrome 120 measured
//       t13d1517h2_8daaf6152771_b1ff8ab2d16f — same _b_, +1 extension from ECH), and
//       the replicated current-Chrome row t13d1516h2_8daaf6152771_* (see
//       docs/NATIVE.md for the full citation list). The _c_ section drifts per Chrome
//       version (extension set churn) — it is REPORTED exactly, never asserted equal
//       to a stale published string;
//   (c) ALPN offered per profile is measured from the captured bytes (h2 first in
//       both profiles by construction; negotiated behavior is measured Node-side in
//       the harness against a real TLS server — see test/native-agent.test.mjs).
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"varvel-agent/ja4"
)

// captureHello runs dialFn against a one-shot loopback listener and returns the raw
// first TLS record (the ClientHello). The dial is EXPECTED to fail (the listener
// closes after one record) — the bytes are the measurement, not the handshake.
func captureHello(t *testing.T, dialFn func(addr string) error) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 5)
		if _, err := readFull(conn, hdr); err != nil {
			done <- result{nil, err}
			return
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		body := make([]byte, recLen)
		if _, err := readFull(conn, body); err != nil {
			done <- result{nil, err}
			return
		}
		done <- result{append(hdr, body...), nil}
	}()
	_ = dialFn(ln.Addr().String()) // handshake failure is expected and irrelevant
	r := <-done
	if r.err != nil {
		t.Fatalf("capture: %v", r.err)
	}
	return r.b
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func dialGoNative(addr string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "ja4-capture.test",
		InsecureSkipVerify: true, //nolint:gosec // capture leg: no server half exists
		NextProtos:         alpnFor(ProfileGoNative),
	})
	if err != nil {
		return err
	}
	return conn.Close()
}

func dialChrome(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         "ja4-capture.test",
		InsecureSkipVerify: true, //nolint:gosec // capture leg: no server half exists
		NextProtos:         alpnFor(ProfileChrome),
	}, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		conn.Close()
		return err
	}
	return uconn.Close()
}

func TestJA4ProfilesDiffer(t *testing.T) {
	goParsed := ja4.ParseClientHello(captureHello(t, dialGoNative))
	if goParsed == nil {
		t.Fatal("go-native ClientHello did not parse")
	}
	chromeParsed := ja4.ParseClientHello(captureHello(t, dialChrome))
	if chromeParsed == nil {
		t.Fatal("chrome-profile ClientHello did not parse")
	}
	goFP := ja4.JA4(goParsed)
	chromeFP := ja4.JA4(chromeParsed)
	t.Logf("MEASURED go-native JA4: %s", goFP)
	t.Logf("MEASURED chrome    JA4: %s", chromeFP)
	t.Logf("go-native alpn=%v ciphers=%d exts=%d", goParsed.ALPN, len(goParsed.Ciphers), len(goParsed.Extensions))
	t.Logf("chrome    alpn=%v ciphers=%d exts=%d", chromeParsed.ALPN, len(chromeParsed.Ciphers), len(chromeParsed.Extensions))

	if goFP == chromeFP {
		t.Fatal("profiles must differ on the wire — the -tls-profile flag changed nothing")
	}

	// (b) the chrome profile must carry the documented Chrome-on-Windows shape.
	if chromeParsed.Version != 0x0304 {
		t.Fatalf("chrome profile: TLS1.3 expected, got %04x", chromeParsed.Version)
	}
	if !chromeParsed.HasSNI {
		t.Fatal("chrome profile: SNI expected (sni=ja4-capture.test)")
	}
	if len(chromeParsed.ALPN) == 0 || chromeParsed.ALPN[0] != "h2" {
		t.Fatalf("chrome profile: ALPN h2 first expected, got %v", chromeParsed.ALPN)
	}
	if !regexp.MustCompile(`^t13d15\d{2}h2_8daaf6152771_[0-9a-f]{12}$`).MatchString(chromeFP) {
		t.Fatalf("chrome profile JA4 %s does not match the documented Chrome-on-Windows shape t13d15XXh2_8daaf6152771_* (see header comment for citations)", chromeFP)
	}
	// (a) sharpened: go-native must NOT accidentally wear the Chrome cipher-list hash.
	if regexp.MustCompile(`_8daaf6152771_`).MatchString(goFP) {
		t.Fatalf("go-native JA4 %s wears the Chrome cipher hash — the contrast leg is broken", goFP)
	}
	// (c) ALPN offers, measured (not assumed).
	if len(goParsed.ALPN) == 0 || goParsed.ALPN[0] != "h2" {
		t.Fatalf("go-native profile: ALPN h2 first expected (net/http h2 enabled), got %v", goParsed.ALPN)
	}
	fmt.Println("ja4 capture: measured both profiles — see test log (-v)")
}

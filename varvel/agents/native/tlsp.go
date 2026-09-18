// tlsp.go — the TLS ClientHello control layer: the reason this tier exists.
//
// Pure Node/PowerShell agents cannot choose their ClientHello — Node's is whatever
// OpenSSL/BoringSSL-as-linked emits, and Schannel's is the OS's. This agent's
// -tls-profile flag picks the wire shape explicitly:
//
//   chrome    (DEFAULT) — uTLS (github.com/refraction-networking/utls, pinned) with
//             HelloChrome_Auto: the ClientHello of current desktop Chrome (cipher
//             order, extension set+order, ALPN h2+http/1.1, GREASE) on an otherwise
//             ordinary Go HTTP stack. Fetched at BUILD time only; the shipped binary
//             is static.
//   go-native — the contrast leg: Go's stock crypto/tls ClientHello. Measured in the
//             JA4 tests as the control the chrome profile is asserted AGAINST.
//
// HONESTY: a matching JA4 string is string equality with a reference, never a claim
// of indistinguishability (the fporacle doctrine). The JA4 is MEASURED by the
// platform oracle (engine/fingerprint.mjs) and by this module's own ja4 package;
// both directions are asserted in tests.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	ProfileChrome   = "chrome"
	ProfileGoNative = "go-native"
)

// utlsID maps a profile name to its uTLS ClientHelloID. HelloChrome_Auto tracks the
// newest Chrome the pinned uTLS ships; the exact JA4 it emits is MEASURED, never
// assumed (see ja4_capture_test.go and docs/NATIVE.md).
func utlsID(profile string) (utls.ClientHelloID, error) {
	switch profile {
	case ProfileChrome:
		return utls.HelloChrome_Auto, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("profile %q has no uTLS ClientHelloID", profile)
}

// alpnFor returns the ALPN offer list per profile. Chrome offers h2 then http/1.1;
// Go's stock stack does the same when HTTP/2 is enabled — the WIRE truth of what each
// profile actually offered/negotiated is captured in the JA4 evidence, not assumed.
func alpnFor(profile string) []string {
	return []string{"h2", "http/1.1"}
}

// httpClient builds the agent's HTTP client for the given channel URL + TLS profile.
// Plain http:// URLs never touch this layer (the channel's reference listener is
// plaintext HTTP); https:// URLs dial through the selected profile.
func httpClient(rawURL, profile string, insecure bool) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("bad -url: %w", err)
	}
	if u.Scheme != "https" {
		// Plaintext leg: an ordinary transport. Profile is irrelevant on this wire —
		// there is no ClientHello to shape (honest no-op, noted at launch).
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	switch profile {
	case ProfileGoNative:
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure, NextProtos: alpnFor(profile)}, //nolint:gosec // lab flag, documented
			},
		}, nil
	case ProfileChrome:
		id, err := utlsID(profile)
		if err != nil {
			return nil, err
		}
		// net/http CANNOT drive h2 over a uTLS conn: with a custom TLS dialer it only
		// reads ALPN state from a concrete *tls.Conn (Go 1.26 transport.go:1795), so a
		// uTLS conn always degrades to HTTP/1.1 — written onto a connection the server
		// already selected h2 on (measured, then fixed, in tlsp_test.go). The honest
		// fix is a purpose RoundTripper: dial the chrome-profile hello, read the
		// negotiated ALPN, then speak exactly that protocol.
		return &http.Client{Timeout: 30 * time.Second, Transport: &profileRoundTripper{id: id, insecure: insecure, alpn: alpnFor(profile)}}, nil
	}
	return nil, fmt.Errorf("unknown -tls-profile %q (want %q or %q)", profile, ProfileChrome, ProfileGoNative)
}

// profileRoundTripper speaks the channel wire over a uTLS (chrome-profile) ClientHello.
// Each RoundTrip dials fresh: NO connection pooling on this leg (documented in
// docs/NATIVE.md — the honest cost of keeping the ALPN-selected protocol correct:
// h2 via x/net/http2 when the server picks it, HTTP/1.1 when it doesn't).
type profileRoundTripper struct {
	id       utls.ClientHelloID
	insecure bool
	alpn     []string
}

func (rt *profileRoundTripper) dial(ctx context.Context, addr string) (net.Conn, utls.ConnectionState, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, utls.ConnectionState{}, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: rt.insecure, //nolint:gosec // lab flag, documented
		NextProtos:         rt.alpn,
	}, rt.id)
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, utls.ConnectionState{}, fmt.Errorf("utls handshake: %w", err)
	}
	return uconn, uconn.ConnectionState(), nil
}

func (rt *profileRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr += ":443"
	}
	conn, state, err := rt.dial(req.Context(), addr)
	if err != nil {
		return nil, err
	}
	if state.NegotiatedProtocol == "h2" {
		return rt.roundTripH2(conn, req)
	}
	return rt.roundTripHTTP1(conn, req)
}

// h2 leg: one client conn over the freshly-dialed uTLS conn (NewClientConn is the
// x/net/http2 API for exactly this BYO-conn shape).
func (rt *profileRoundTripper) roundTripH2(conn net.Conn, req *http.Request) (*http.Response, error) {
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// HTTP/1.1 leg: write the request onto the pre-dialed conn, read the response.
// Connection: close — no pooling on this leg.
func (rt *profileRoundTripper) roundTripHTTP1(conn net.Conn, req *http.Request) (*http.Response, error) {
	req.Close = true
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// connClosingBody ties the connection's life to the response body's (no pooling).
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}

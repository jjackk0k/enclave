// shapehttp.go — the ORDERED-HEADER HTTP/1.1 emitter: the mechanism that makes the
// native agent's shaped wire JA4H-correct.
//
// WHY net/http CANNOT DO THIS: JA4H (engine/fingerprint.mjs) hashes the request's
// header NAMES IN WIRE ORDER. Go's net/http writes Host and User-Agent itself and
// then emits every remaining header ALPHABETICALLY (Header.writeSubset collects and
// sorts the keys — request.go's write path), and it canonicalizes name case. No
// RoundTripper wrapper can change that: the sort happens inside Request.write, below
// the RoundTripper seam. tlsp.go already solved the sibling problem for TLS (a
// purpose RoundTripper that owns the connection); this file does the same for the
// HTTP layer — a purpose emitter that dials, SERIALIZES THE REQUEST BY HAND (request
// line, then the header pairs in exactly the order shape.wireHeaders built, then the
// body), and parses the reply with http.ReadResponse. Header order and case on the
// wire are therefore byte-exact what engine/malleable.expectedWireHeaders specifies —
// the same string the platform oracle's expectedJa4h is computed over.
//
// HTTPS LEG (honest, measured): an ordered HTTP/1.1 byte stream only exists if the
// negotiated protocol IS http/1.1, so the shaped https leg constrains ALPN to
// ["http/1.1"] (uTLS chrome hello / stock crypto/tls per -tls-profile, same dial
// discipline as tlsp.go). Consequence, reported not hidden: on a shaped https leg the
// JA4 _a_ section's ALPN digit reads h1 (not the h2 the unshaped chrome leg offers),
// and there is still no connection pooling — one fresh handshake per request.
// The reference channel listener is plaintext HTTP/1.1, where none of this bites.
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
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// shapedALPN is the honest constraint of the ordered emitter: HTTP/1.1 only.
var shapedALPN = []string{"http/1.1"}

// doShapedRequest emits ONE shaped request with the given headers in EXACTLY the
// given order and case, and returns the parsed response. The connection is never
// pooled: the caller drains and closes the body (connClosingBody ties the conn's
// life to it). method != GET appends content-length LAST (the expectedWireHeaders
// position).
func doShapedRequest(ctx context.Context, tlsProfile string, tlsInsecure bool, method, rawURL string, pairs [][2]string, body []byte) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("shaped request: bad url: %w", err)
	}
	if method != http.MethodGet {
		pairs = append(pairs, [2]string{"content-length", strconv.Itoa(len(body))})
	}
	conn, err := dialShaped(ctx, u.Scheme, u.Host, tlsProfile, tlsInsecure)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second)) // httpClient's Timeout parity
	}
	if err := writeOrderedRequest(conn, method, u, pairs, body); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("shaped request: read response: %w", err)
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// writeOrderedRequest is the serializer: request line, then `name: value` for every
// pair IN ORDER (no sorting, no canonicalization — the whole point), blank line, body.
func writeOrderedRequest(w io.Writer, method string, u *url.URL, pairs [][2]string, body []byte) error {
	bw := bufio.NewWriter(w)
	uri := u.RequestURI()
	if uri == "" {
		uri = "/"
	}
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", method, uri); err != nil {
		return err
	}
	for _, p := range pairs {
		// The pairs come from shape.wireHeaders: lowercase names, real values. No
		// sanitization beyond the wire-forbidden bytes — the template is platform data.
		name := strings.ReplaceAll(strings.ReplaceAll(p[0], "\r", ""), "\n", "")
		value := strings.ReplaceAll(strings.ReplaceAll(p[1], "\r", ""), "\n", "")
		if _, err := fmt.Fprintf(bw, "%s: %s\r\n", name, value); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := bw.Write(body); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// dialShaped dials the shaped leg: plain TCP for http://, else TLS with ALPN
// constrained to http/1.1 (see the file header for why — and what it costs the JA4).
func dialShaped(ctx context.Context, scheme, addr, tlsProfile string, insecure bool) (net.Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("shaped request: empty dial address")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if scheme != "https" {
		return conn, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if tlsProfile == ProfileGoNative {
		tc := tls.Client(conn, &tls.Config{ //nolint:gosec // lab flag, documented
			ServerName:         host,
			InsecureSkipVerify: insecure,
			NextProtos:         shapedALPN,
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake (go-native, shaped): %w", err)
		}
		return tc, nil
	}
	id, err := utlsID(tlsProfile) // chrome — the default; unknown names error honestly
	if err != nil {
		conn.Close()
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{ //nolint:gosec // lab flag, documented
		ServerName:         host,
		InsecureSkipVerify: insecure,
		NextProtos:         shapedALPN,
	}, id)
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("utls handshake (shaped): %w", err)
	}
	return uconn, nil
}

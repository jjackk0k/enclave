// tlsp_test.go — the https leg end to end, in-process: each profile's http.Client
// against a REAL HTTP/2-capable TLS server (httptest with EnableHTTP2). Asserts the
// exchange completes and RECORDS the negotiated protocol the server observed — the
// measured answer to "does the chrome profile actually speak h2 through uTLS".
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSRoundTripPerProfile(t *testing.T) {
	var sawProto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Proto // "HTTP/2.0" or "HTTP/1.1" — the negotiated truth, server-side
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	for _, profile := range []string{ProfileGoNative, ProfileChrome} {
		sawProto = ""
		client, err := httpClient(srv.URL, profile, true) // httptest's cert is self-signed: lab leg
		if err != nil {
			t.Fatalf("%s: httpClient: %v", profile, err)
		}
		resp, err := client.Get(srv.URL + "/c")
		if err != nil {
			t.Fatalf("%s: round trip failed: %v", profile, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: status %d", profile, resp.StatusCode)
		}
		t.Logf("MEASURED negotiated protocol, profile %s: %s", profile, sawProto)
		if sawProto != "HTTP/2.0" {
			t.Fatalf("%s: expected HTTP/2.0 against an h2 server, got %s", profile, sawProto)
		}
	}
}

// The plaintext leg stays plaintext: http:// URLs never touch the profile layer.
func TestHTTPLegIgnoresProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	client, err := httpClient(srv.URL, ProfileChrome, false)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL + "/c")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestBadProfileRefused(t *testing.T) {
	if _, err := httpClient("https://127.0.0.1:1", "netscape-navigator", false); err == nil {
		t.Fatal("unknown profile must be a loud refusal, never a silent default")
	}
}

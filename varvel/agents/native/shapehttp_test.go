// shapehttp_test.go — the ORDERED-EMITTER proof battery:
//
//   (1) WIRE BYTES: a raw loopback TCP listener captures the exact request the
//       shaped emission path (wire.go pull/push -> shapehttp.go doShapedRequest)
//       puts on the wire; the header block must match the profile template order
//       BYTE-FOR-BYTE (JA4H hashes header names in wire order — order is the claim).
//   (2) SHAPED ROUND TRIP: pull/push/pad against a stub enforcing the real intake
//       rules, on the profile's shaped paths, strict agent-global seq intact.
//   (3) JA4H ORACLE PARITY (node-driven, skipped without a node runtime): the
//       captured wire headers are fingerprinted by the PLATFORM ORACLE
//       (engine/fingerprint.mjs via harness/shape-observe.mjs judge mode) and
//       asserted byte-equal against the profile's expectedJa4h — the shapegrade
//       claimed-vs-measured contract, closed over the Go emission path.
//   (4) batch-dwell targeting against the pinned Node vectors.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// captureServer is a raw TCP listener that records each request's bytes and answers
// with the canned response for its method (204 for GET, 200 for POST — the channel's
// idle/accepted shapes). One connection per request: the ordered emitter never pools.
type captureServer struct {
	ln   net.Listener
	mu   sync.Mutex
	reqs []capturedRequest
}

type capturedRequest struct {
	method  string
	uri     string
	head    string // the raw request head (request line + header block), \r\n-joined
	headers [][2]string
	body    []byte
}

func startCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cs := &captureServer{ln: ln}
	go cs.serve()
	t.Cleanup(func() { ln.Close() })
	return cs
}

func (cs *captureServer) url() string { return "http://" + cs.ln.Addr().String() }

func (cs *captureServer) serve() {
	for {
		conn, err := cs.ln.Accept()
		if err != nil {
			return
		}
		go cs.handle(conn)
	}
}

func (cs *captureServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) != 3 {
		return
	}
	req := capturedRequest{method: parts[0], uri: parts[1]}
	var head strings.Builder
	head.WriteString(line)
	contentLength := 0
	for {
		hl, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(hl)
		trimmed := strings.TrimRight(hl, "\r\n")
		if trimmed == "" {
			break
		}
		kv := strings.SplitN(trimmed, ": ", 2)
		if len(kv) != 2 {
			return
		}
		req.headers = append(req.headers, [2]string{kv[0], kv[1]})
		if strings.EqualFold(kv[0], "content-length") {
			contentLength, _ = strconv.Atoi(kv[1])
		}
	}
	if contentLength > 0 {
		req.body = make([]byte, contentLength)
		if _, err := io.ReadFull(br, req.body); err != nil {
			return
		}
	}
	req.head = head.String()
	cs.mu.Lock()
	cs.reqs = append(cs.reqs, req)
	cs.mu.Unlock()
	if req.method == http.MethodPost {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
		return
	}
	io.WriteString(conn, "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
}

func (cs *captureServer) captured() []capturedRequest {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]capturedRequest(nil), cs.reqs...)
}

// (1) WIRE BYTES: the emitted header block, byte-for-byte against the template order.
func TestShapedWireBytesMatchTemplateOrder(t *testing.T) {
	cs := startCaptureServer(t)
	shape, err := shapeByName("cdn-asset")
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{URL: cs.url(), ID: vecID, Token: vecToken, Shape: shape, ShapeAt: 1, Rand: func() float64 { return 0 }}
	sc := a.shapeWire()

	if _, _, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), false, nil, sc); err != nil {
		t.Fatalf("shaped pull: %v", err)
	}
	if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), vecTaskID, []byte("shaped-result"), false, nil, sc); err != nil {
		t.Fatalf("shaped push: %v", err)
	}
	reqs := cs.captured()
	if len(reqs) != 2 {
		t.Fatalf("captured %d requests, want pull+push", len(reqs))
	}

	// GET: request line on a pull-path template + cache-buster, then the EXACT order.
	getReq := reqs[0]
	if !strings.HasPrefix(getReq.uri, "/assets/js/app.min.js?v=") {
		t.Fatalf("shaped pull path: %q (rand=0 picks template[0] + queryKey)", getReq.uri)
	}
	gotGet := headerNames(getReq.headers)
	if strings.Join(gotGet, ",") != strings.Join(wantWireOrder["cdn-asset"].get, ",") {
		t.Fatalf("GET wire order:\n got  %v\n want %v", gotGet, wantWireOrder["cdn-asset"].get)
	}
	// The request line + FIRST TWO header lines are host/connection — byte-exact head.
	host := strings.TrimPrefix(cs.url(), "http://")
	wantHeadPrefix := "GET " + getReq.uri + " HTTP/1.1\r\nhost: " + host + "\r\nconnection: keep-alive\r\nuser-agent: "
	if !strings.HasPrefix(getReq.head, wantHeadPrefix) {
		t.Fatalf("wire head prefix wrong:\n got  %q\n want %q…", getReq.head, wantHeadPrefix)
	}
	if !strings.Contains(getReq.head, "\r\nsec-fetch-mode: cors\r\n") {
		t.Fatal("the runtime-appended sec-fetch-mode: cors must be on the wire")
	}
	if strings.Contains(strings.ToLower(getReq.head), "content-length") {
		t.Fatal("a GET carries no content-length (expectedWireHeaders parity)")
	}

	// POST: x-task between x-seq and x-auth, content-length LAST, body intact.
	postReq := reqs[1]
	if !strings.HasPrefix(postReq.uri, "/api/telemetry?v=") {
		t.Fatalf("shaped push path: %q (pushPaths[0] + queryKey)", postReq.uri)
	}
	gotPost := headerNames(postReq.headers)
	if strings.Join(gotPost, ",") != strings.Join(wantWireOrder["cdn-asset"].post, ",") {
		t.Fatalf("POST wire order:\n got  %v\n want %v", gotPost, wantWireOrder["cdn-asset"].post)
	}
	if gotPost[len(gotPost)-1] != "content-length" {
		t.Fatalf("content-length must be LAST on a push: %v", gotPost)
	}
	if string(postReq.body) != "shaped-result" {
		t.Fatalf("push body: %q", postReq.body)
	}
	if !strings.HasSuffix(postReq.head, "content-length: 13\r\n\r\n") {
		t.Fatalf("content-length must close the header block: %q", postReq.head[len(postReq.head)-40:])
	}
}

// (2) SHAPED ROUND TRIP: a stub enforcing the real intake rules on the SHAPED paths.
func TestShapedPullPushPadAgainstStub(t *testing.T) {
	lastSeq := int64(0)
	var seenPaths []string
	var sawPad bool
	shape, _ := shapeByName("telemetry-beacon")
	pullOK := map[string]bool{}
	for _, p := range shape.HTTP.PullPaths {
		pullOK[p] = true
	}
	pushOK := map[string]bool{}
	for _, p := range shape.HTTP.PushPaths {
		pushOK[p] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("x-agent")
		seq, err := strconv.ParseInt(r.Header.Get("x-seq"), 10, 64)
		if err != nil || seq <= lastSeq {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		auth := r.Header.Get("x-auth")
		switch {
		case r.Method == http.MethodGet && pullOK[r.URL.Path]:
			seenPaths = append(seenPaths, "GET "+r.URL.Path)
			if auth == padAuth(vecToken, id, seq) {
				sawPad = true
				lastSeq = seq
				w.WriteHeader(http.StatusNoContent) // pads are 204 by contract
				return
			}
			if auth != pullAuth(vecToken, id, seq) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			lastSeq = seq
			w.WriteHeader(http.StatusNoContent) // idle
		case r.Method == http.MethodPost && pushOK[r.URL.Path]:
			body, _ := io.ReadAll(r.Body)
			if auth != pushAuth(vecToken, id, seq, r.Header.Get("x-task"), body) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			lastSeq = seq
			seenPaths = append(seenPaths, "POST "+r.URL.Path)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	a := &Agent{URL: srv.URL, ID: vecID, Token: vecToken, Shape: shape, ShapeAt: 1}
	sc := a.shapeWire()
	if _, _, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), false, nil, sc); err != nil {
		t.Fatalf("shaped pull: %v", err)
	}
	if err := pad(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), false, sc); err != nil {
		t.Fatalf("shaped pad: %v", err)
	}
	if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), vecTaskID, []byte("r"), false, nil, sc); err != nil {
		t.Fatalf("shaped push: %v", err)
	}
	if !sawPad {
		t.Fatal("the pad envelope must carry the ':pad' HMAC context")
	}
	// every request landed on a template path — no bare /c /r escaped the shape.
	if len(seenPaths) != 3 {
		t.Fatalf("stub saw %v", seenPaths)
	}
	for _, p := range seenPaths {
		m, path := p[:strings.Index(p, " ")], p[strings.Index(p, " ")+1:]
		if m == "GET" && !pullOK[path] {
			t.Fatalf("pull off-template: %s", p)
		}
		if m == "POST" && !pushOK[path] {
			t.Fatalf("push off-template: %s", p)
		}
	}
	// pads consume the agent-global seq like any envelope (sim-agent _pad parity).
	if got := a.nextSeq(); got != 4 {
		t.Fatalf("seq after pull+pad+push: got %d want 4", got)
	}
}

// (4) batch-dwell targeting against the pinned Node vectors (shape_test.go owns the
// window-math vectors; these pin the LOOP's target selection on top of them).
func TestBatchDwellTarget(t *testing.T) {
	a := &Agent{Token: winVecToken, Shape: &ShapeProfile{Name: "dwell", Batch: &ShapeBatch{WindowMs: 30000}}, ShapeAt: winVecAnchor}
	// inside window 0, before its flush (+15190): dwell to it.
	if got := a.batchDwellTarget(winVecAnchor + 100); got != 1700000015190 {
		t.Fatalf("target inside window 0: got %d want 1700000015190 (Node-computed)", got)
	}
	// exactly AT window 0's flush: the window's point has passed — aim at window 1's.
	if got := a.batchDwellTarget(1700000015190); got != 1700000041558 {
		t.Fatalf("target at flush boundary: got %d want 1700000041558 (Node-computed)", got)
	}
	// deep inside window 1: its flush.
	if got := a.batchDwellTarget(winVecAnchor + 40000); got != 1700000041558 {
		t.Fatalf("target inside window 1: got %d want 1700000041558 (Node-computed)", got)
	}
	// window 3's flush (+27883 inside window 3 => 1700000117883).
	if got := a.batchDwellTarget(winVecAnchor + 95000); got != 1700000117883 {
		t.Fatalf("target inside window 3: got %d want 1700000117883 (Node-computed)", got)
	}
	// anchor 0 falls back to 'now' (the sim agent's shapeAt || Date.now()): the flush
	// is then now + this window's seeded offset (windowFlushAt(token, NOW, …, 0)).
	a2 := &Agent{Token: winVecToken, Shape: &ShapeProfile{Name: "d", Batch: &ShapeBatch{WindowMs: 30000}}}
	if got := a2.batchDwellTarget(winVecAnchor + 100); got != winVecAnchor+100+15190 {
		t.Fatalf("zero anchor anchors at now: got %d want %d (now + offset0)", got, winVecAnchor+100+15190)
	}
}

// (3) JA4H ORACLE PARITY: the captured wire headers, fingerprinted by the platform's
// own Node oracle and asserted byte-equal against expectedJa4h. Skipped cleanly
// without a node runtime (the byte-order half above is hermetic).
func TestShapedJa4hOracleParity(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node runtime not on PATH — live JA4H oracle parity proof skipped (wire-byte half above is hermetic)")
	}
	harness := filepath.Join("harness", "shape-observe.mjs")
	tmpDir := filepath.Join("..", "..", ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"cdn-asset", "telemetry-beacon", "software-update"} {
		t.Run(profile, func(t *testing.T) {
			cs := startCaptureServer(t)
			shape, err := shapeByName(profile)
			if err != nil {
				t.Fatal(err)
			}
			a := &Agent{URL: cs.url(), ID: vecID, Token: vecToken, Shape: shape, ShapeAt: 1, Rand: func() float64 { return 0 }}
			sc := a.shapeWire()
			if _, _, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), false, nil, sc); err != nil {
				t.Fatalf("shaped pull: %v", err)
			}
			if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), vecTaskID, []byte("x"), false, nil, sc); err != nil {
				t.Fatalf("shaped push: %v", err)
			}
			reqs := cs.captured()
			if len(reqs) != 2 {
				t.Fatalf("captured %d requests, want 2", len(reqs))
			}
			for i, method := range []string{"GET", "POST"} {
				capDoc := map[string]any{
					"method": method, "httpVersion": "1.1", "path": reqs[i].uri,
					"headers": reqs[i].headers,
				}
				f, err := os.CreateTemp(tmpDir, "go-shape-capture-*.json")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(f.Name())
				if err := json.NewEncoder(f).Encode(capDoc); err != nil {
					t.Fatal(err)
				}
				f.Close()
				rep, err := exec.Command(node, harness, "judge", profile, f.Name()).CombinedOutput()
				if err != nil {
					t.Fatalf("JA4H oracle parity FAILED (%s %s): %v\n%s", profile, method, err, rep)
				}
				var verdict struct {
					Observed string `json:"observed"`
					Claimed  string `json:"claimed"`
					Match    bool   `json:"match"`
				}
				if err := json.Unmarshal(rep, &verdict); err != nil || !verdict.Match {
					t.Fatalf("judge report: %v (%v)", strings.TrimSpace(string(rep)), err)
				}
				t.Logf("JA4H parity %s %s: observed %s == claimed %s", profile, method, verdict.Observed, verdict.Claimed)
			}
		})
	}
}

// The https leg of the ordered emitter: ALPN is constrained to http/1.1 so the
// ordered byte stream is real (documented JA4 tradeoff — see shapehttp.go header).
func TestShapedHTTPSLegConstrainsALPN(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resp, err := doShapedRequest(context.Background(), ProfileGoNative, true, http.MethodGet, srv.URL, [][2]string{{"host", strings.TrimPrefix(srv.URL, "https://")}, {"connection", "keep-alive"}}, nil)
	if err != nil {
		t.Fatalf("shaped https (go-native) request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("the shaped https leg must speak HTTP/1.x, got %s", resp.Proto)
	}
}

// compile-time guard: the emitter's content-length position contract.
func TestShapedEmitterContentLengthPosition(t *testing.T) {
	cs := startCaptureServer(t)
	resp, err := doShapedRequest(context.Background(), ProfileChrome, false, http.MethodPost, cs.url()+"/x",
		[][2]string{{"host", strings.TrimPrefix(cs.url(), "http://")}, {"connection", "keep-alive"}, {"x-agent", vecID}}, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	reqs := cs.captured()
	if len(reqs) != 1 {
		t.Fatalf("captured %d", len(reqs))
	}
	names := headerNames(reqs[0].headers)
	if names[len(names)-1] != "content-length" {
		t.Fatalf("content-length must be appended LAST by the emitter, got %v", names)
	}
}

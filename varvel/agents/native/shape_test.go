// shape_test.go — the shaping-pack port's proof battery:
//
//   · BATCH-WINDOW MATH parity vectors, computed ONCE by the Node engine
//     (engine/malleable.mjs windowIndexAt/windowOffsetMs/windowFlushAt over the
//     wire_test.go vector token) and pinned here — same seed => same window
//     boundaries in Go and Node, or this test says so.
//   · WIRE HEADER ORDER pins: the exact ordered header-name list per profile/method
//     that engine/malleable.expectedWireHeaders builds (the string shapegrade's
//     expectedJa4h is computed over). The Go builder must emit the identical order —
//     JA4H hashes header names in wire order, so an order slip IS a fingerprint slip.
//   · resolution semantics (plain-clear, clamps, unknown-name refusal), cadence
//     sampler bounds, path rendering.
//
// The JA4H byte-equality proof against the LIVE Node oracle is in shapehttp_test.go
// (drives harness/shape-observe.mjs over the compiled wire emission path).
package main

import (
	"net/http"
	"strings"
	"testing"
)

// Node-generated vectors (engine/malleable.mjs, verbatim — generator inline in the
// report; token is the wire_test.go vector constant, anchor 1700000000000):
//
//	node -e "import('./engine/malleable.mjs').then(m => …)" (varvel repo root)
const (
	winVecToken  = vecToken // the shared-secret seed, same constant as the wire vectors
	winVecAnchor = int64(1700000000000)
)

func TestWindowMathNodeParity(t *testing.T) {
	// windowIndexAt(anchor, 30000, now):
	idxCases := []struct {
		now  int64
		want int64
	}{
		{winVecAnchor, 0},
		{winVecAnchor + 1, 0},
		{winVecAnchor + 29999, 0},
		{winVecAnchor + 30000, 1},
		{winVecAnchor + 30001, 1},
		{winVecAnchor + 95000, 3},
	}
	for _, c := range idxCases {
		if got := windowIndexAt(winVecAnchor, 30000, c.now); got != c.want {
			t.Fatalf("windowIndexAt(anchor,30000,%d): got %d want %d (Node-computed)", c.now, got, c.want)
		}
	}
	// windowOffsetMs / windowFlushAt(token, anchor, 30000, i):
	flushCases := []struct {
		idx        int64
		wantOffset int64
		wantFlush  int64
	}{
		{0, 15190, 1700000015190},
		{1, 11558, 1700000041558},
		{2, 16466, 1700000076466},
		{3, 27883, 1700000117883},
		{4, 16362, 1700000136362},
		{5, 4121, 1700000154121},
	}
	for _, c := range flushCases {
		if got := windowOffsetMs(winVecToken, 30000, c.idx); got != c.wantOffset {
			t.Fatalf("windowOffsetMs(token,30000,%d): got %d want %d (Node-computed)", c.idx, got, c.wantOffset)
		}
		if got := windowFlushAt(winVecToken, winVecAnchor, 30000, c.idx); got != c.wantFlush {
			t.Fatalf("windowFlushAt(token,anchor,30000,%d): got %d want %d (Node-computed)", c.idx, got, c.wantFlush)
		}
	}
	// a second window size, same seed (guards the frac*window float path):
	small := []struct {
		idx        int64
		wantOffset int64
		wantFlush  int64
	}{
		{0, 2531, 1700000002531},
		{1, 1926, 1700000006926},
		{2, 2744, 1700000012744},
	}
	for _, c := range small {
		if got := windowOffsetMs(winVecToken, 5000, c.idx); got != c.wantOffset {
			t.Fatalf("windowOffsetMs(token,5000,%d): got %d want %d (Node-computed)", c.idx, got, c.wantOffset)
		}
		if got := windowFlushAt(winVecToken, winVecAnchor, 5000, c.idx); got != c.wantFlush {
			t.Fatalf("windowFlushAt(token,anchor,5000,%d): got %d want %d (Node-computed)", c.idx, got, c.wantFlush)
		}
	}
}

// The exact ordered header-name lists engine/malleable.expectedWireHeaders builds —
// the order the oracle's expectedJa4h is computed over (Node-quoted in the report).
var wantWireOrder = map[string]struct {
	get  []string
	post []string
}{
	"cdn-asset": {
		get:  []string{"host", "connection", "user-agent", "accept", "accept-language", "accept-encoding", "cache-control", "pragma", "x-agent", "x-seq", "x-auth", "sec-fetch-mode"},
		post: []string{"host", "connection", "user-agent", "accept", "accept-language", "accept-encoding", "cache-control", "pragma", "x-agent", "x-seq", "x-task", "x-auth", "sec-fetch-mode", "content-length"},
	},
	"software-update": {
		get:  []string{"host", "connection", "user-agent", "accept", "accept-encoding", "x-agent", "x-seq", "x-auth", "accept-language", "sec-fetch-mode"},
		post: []string{"host", "connection", "user-agent", "accept", "accept-encoding", "x-agent", "x-seq", "x-task", "x-auth", "accept-language", "sec-fetch-mode", "content-length"},
	},
	"telemetry-beacon": {
		get:  []string{"host", "connection", "user-agent", "accept", "accept-language", "accept-encoding", "x-agent", "x-seq", "x-auth", "sec-fetch-mode"},
		post: []string{"host", "connection", "user-agent", "accept", "accept-language", "accept-encoding", "x-agent", "x-seq", "x-task", "x-auth", "sec-fetch-mode", "content-length"},
	},
}

func headerNames(pairs [][2]string) []string {
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p[0]
	}
	return out
}

func TestWireHeadersOrderMatchesExpectedWireHeaders(t *testing.T) {
	fixed := func() float64 { return 0 } // deterministic template/UA pick (index 0)
	for name, want := range wantWireOrder {
		shape, err := shapeByName(name)
		if err != nil || shape == nil {
			t.Fatalf("%s: shapeByName: %v", name, err)
		}
		gotGet := headerNames(shape.wireHeaders(http.MethodGet, "127.0.0.1:8971", vecID, 7, "AUTH", "", false, fixed))
		if strings.Join(gotGet, ",") != strings.Join(want.get, ",") {
			t.Fatalf("%s GET order:\n got  %v\n want %v (expectedWireHeaders)", name, gotGet, want.get)
		}
		gotPost := headerNames(shape.wireHeaders(http.MethodPost, "127.0.0.1:8971", vecID, 8, "AUTH", vecTaskID, false, fixed))
		// content-length is appended by the emitter at write time — simulate its position.
		gotPost = append(gotPost, "content-length")
		if strings.Join(gotPost, ",") != strings.Join(want.post, ",") {
			t.Fatalf("%s POST order:\n got  %v\n want %v (expectedWireHeaders)", name, gotPost, want.post)
		}
		// The template fill: {ua} becomes the picked UA; auth headers carry real values.
		pairs := shape.wireHeaders(http.MethodGet, "127.0.0.1:8971", vecID, 7, "AUTH", "", false, fixed)
		vals := map[string]string{}
		for _, p := range pairs {
			vals[p[0]] = p[1]
		}
		if vals["host"] != "127.0.0.1:8971" || vals["x-agent"] != vecID || vals["x-seq"] != "7" || vals["x-auth"] != "AUTH" {
			t.Fatalf("%s: value fill wrong: %v", name, vals)
		}
		if vals["user-agent"] != shape.HTTP.UAPool[0] {
			t.Fatalf("%s: {ua} fill: got %q want pool[0] %q", name, vals["user-agent"], shape.HTTP.UAPool[0])
		}
	}
	// enc parity: the capability flag lands AFTER x-auth (sim-agent insertion order).
	shape, _ := shapeByName("telemetry-beacon")
	got := headerNames(shape.wireHeaders(http.MethodGet, "h", vecID, 1, "AUTH", "", true, nil))
	i := func(n string) int {
		for k, v := range got {
			if v == n {
				return k
			}
		}
		return -1
	}
	if i("x-varvel-enc") != i("x-auth")+1 {
		t.Fatalf("enc flag must land immediately after x-auth: %v", got)
	}
	// A template carrying sec-fetch-mode gets it FORCED to cors in place.
	custom := &ShapeProfile{Name: "sfm", HTTP: &ShapeHTTP{
		PullPaths: []string{"/p"}, QueryKey: "v",
		Headers: [][2]string{{"user-agent", "u"}, {"sec-fetch-mode", "navigate"}},
		UAPool: []string{"u"},
	}}
	pairs := custom.wireHeaders(http.MethodGet, "h", vecID, 1, "A", "", false, nil)
	if string(pairs[3][1]) != "cors" || pairs[3][0] != "sec-fetch-mode" {
		t.Fatalf("sec-fetch-mode must be forced to cors in template position: %v", pairs)
	}
}

func TestResolveShapePayloadSemantics(t *testing.T) {
	// plain clear (the channel's {name:'plain'} delivery):
	s, at, ok := resolveShapePayload(`{"name":"plain"}`)
	if !ok || s != nil || at != 0 {
		t.Fatalf("plain must resolve to the clear: shape=%v at=%d ok=%v", s, at, ok)
	}
	// a full channel delivery (callback.mjs shapeHeaders() compact JSON form):
	raw := `{"name":"dwell","cadence":{"intervalMs":5000,"jitterPct":0.1,"jitterMs":0,"burst":{"chance":0,"minN":0,"maxN":0,"gapMs":0}},"batch":{"windowMs":2500},"padding":{"perCycle":3},"http":{"pullPaths":["/lb/pull"],"pushPaths":["/lb/push"],"queryKey":"q","headers":[["user-agent","{ua}"],["accept","*/*"]],"uaPool":["lab/1.0"]},"at":1700000000123}`
	s, at, ok = resolveShapePayload(raw)
	if !ok || s == nil {
		t.Fatalf("full payload must resolve: %v %v", s, ok)
	}
	if s.Name != "dwell" || s.Cadence.IntervalMs != 5000 || s.Batch.WindowMs != 2500 || s.Padding.PerCycle != 3 {
		t.Fatalf("resolved fields wrong: %+v", s)
	}
	if at != 1700000000123 {
		t.Fatalf("anchor must ride the payload: %d", at)
	}
	if s.HTTP == nil || s.HTTP.PullPaths[0] != "/lb/pull" || s.HTTP.Headers[0][1] != "{ua}" || s.HTTP.UAPool[0] != "lab/1.0" {
		t.Fatalf("http template wrong: %+v", s.HTTP)
	}
	// clamps (shapeProfile() parity): windowMs floored at 1000, perCycle capped at 8,
	// jitterPct capped at 0.9, interval floored at 200.
	s, _, ok = resolveShapePayload(`{"name":"c","cadence":{"intervalMs":5,"jitterPct":4},"batch":{"windowMs":10},"padding":{"perCycle":99}}`)
	if !ok || s.Cadence.IntervalMs != 200 || s.Cadence.JitterPct != 0.9 || s.Batch.WindowMs != 1000 || s.Padding.PerCycle != 8 {
		t.Fatalf("clamps wrong: %+v", s)
	}
	// malformed payload: ok=false — the caller keeps the current shape (sim catch{}).
	if _, _, ok = resolveShapePayload(`{not json`); ok {
		t.Fatal("malformed payload must not resolve")
	}
	// unknown library name: honest refusal, never a silent reshape.
	if _, err := shapeByName("carrier-pigeon"); err == nil {
		t.Fatal("unknown -shape name must fail loudly")
	}
	if s, err := shapeByName("plain"); err != nil || s != nil {
		t.Fatalf("-shape plain = no shape: %v %v", s, err)
	}
	if s, err := shapeByName("cdn-asset"); err != nil || s == nil || s.HTTP == nil {
		t.Fatalf("library resolution: %v %v", s, err)
	}
}

func TestNextGapBounds(t *testing.T) {
	c := &ShapeCadence{IntervalMs: 4000, JitterPct: 0.4}
	for i := 0; i < 2000; i++ {
		r := float64(i%1000) / 1000.0
		gap, burst := nextGap(c, func() float64 { return r })
		// interval*(1 ± 0.4) => [2400, 5600], floor 200.
		if burst != 1 || gap < 2399 || gap > 5601 {
			t.Fatalf("gap out of band: %d (burst %d) at r=%v", gap, burst, r)
		}
	}
	// burst branch: chance 1 forces a burst of minN..maxN at gapMs.
	b := &ShapeCadence{IntervalMs: 4000, Burst: ShapeBurst{Chance: 1, MinN: 2, MaxN: 4, GapMs: 400}}
	seq := []float64{0.5, 0.0, 0.999}
	for _, r := range seq {
		gap, burst := nextGap(b, func() float64 { return r })
		if gap != 400 || burst < 2 || burst > 4 {
			t.Fatalf("burst sample wrong: gap=%d burst=%d at r=%v", gap, burst, r)
		}
	}
	// exact endpoints of the burst count formula: n = minN + floor(r*(maxN-minN+1)).
	gap, burst := nextGap(b, func() float64 { return 0.999 })
	_ = gap
	if burst != 4 {
		t.Fatalf("r=0.999 must give maxN: %d", burst)
	}
	if _, burst = nextGap(b, func() float64 { return 0.0 }); burst != 2 {
		t.Fatalf("r=0 must give minN: %d", burst)
	}
	// absolute jitter path (jitterPct 0): interval ± jitterMs, floor 200.
	j := &ShapeCadence{IntervalMs: 300, JitterMs: 250}
	gap, _ = nextGap(j, func() float64 { return 1.0 }) // 300 + 250
	if gap != 550 {
		t.Fatalf("absolute jitter: got %d want 550", gap)
	}
	gap, _ = nextGap(j, func() float64 { return 0.0 }) // 300 - 250 = 50 → the 200ms floor
	if gap != 200 {
		t.Fatalf("floor: got %d want 200", gap)
	}
}

func TestPickPath(t *testing.T) {
	shape, _ := shapeByName("cdn-asset")
	p := shape.pickPath(shape.HTTP.PullPaths, func() float64 { return 0 })
	if !strings.HasPrefix(p, "/assets/js/app.min.js?v=") || len(p) != len("/assets/js/app.min.js?v=")+8 {
		t.Fatalf("pickPath shape: %q (template + queryKey + 4 bytes hex)", p)
	}
	// cache-buster entropy: two picks differ.
	p2 := shape.pickPath(shape.HTTP.PullPaths, func() float64 { return 0 })
	if p == p2 {
		t.Fatal("cache-buster must vary per pick")
	}
	var nilShape *ShapeProfile
	if got := nilShape.pickPath(nil, nil); got != "" {
		t.Fatalf("nil shape must pick nothing: %q", got)
	}
}

// Adoption semantics on the Agent: channel header -> shape set / cleared / re-anchored.
func TestAdoptShapeHeader(t *testing.T) {
	a := &Agent{Token: vecToken}
	a.Logf = func(string, ...any) {}
	h := http.Header{}
	a.adoptShapeHeader(h) // no header: nothing happens
	if a.Shape != nil {
		t.Fatal("no header must not shape the agent")
	}
	h.Set("x-varvel-shape", `{"name":"cdn-asset","cadence":{"intervalMs":4000,"jitterPct":0.4},"http":{"pullPaths":["/assets/js/app.min.js"],"pushPaths":["/api/telemetry"],"queryKey":"v","headers":[["user-agent","{ua}"]],"uaPool":["u/1"]},"at":1700000000999}`)
	a.adoptShapeHeader(h)
	if a.Shape == nil || a.Shape.Name != "cdn-asset" || a.ShapeAt != 1700000000999 {
		t.Fatalf("adoption: %+v at=%d", a.Shape, a.ShapeAt)
	}
	// malformed delivery keeps the current shape.
	h.Set("x-varvel-shape", `{broken`)
	a.adoptShapeHeader(h)
	if a.Shape == nil || a.Shape.Name != "cdn-asset" {
		t.Fatal("malformed delivery must keep the current shape")
	}
	// plain clears.
	h.Set("x-varvel-shape", `{"name":"plain"}`)
	a.adoptShapeHeader(h)
	if a.Shape != nil || a.ShapeAt != 0 {
		t.Fatalf("plain must clear: %+v", a.Shape)
	}
	// a launch-anchored shape keeps its anchor when the delivery carries none.
	a2 := &Agent{Token: vecToken, ShapeAt: 42}
	a2.Logf = func(string, ...any) {}
	h2 := http.Header{}
	h2.Set("x-varvel-shape", `{"name":"x","cadence":{"intervalMs":300}}`)
	a2.adoptShapeHeader(h2)
	if a2.ShapeAt != 42 {
		t.Fatalf("existing anchor must survive an at-less delivery: %d", a2.ShapeAt)
	}
}

// shape.go — the SHAPING PACK (malleable profile library v2) ported to the native
// tier, byte-exact against engine/malleable.mjs (READ THAT FIRST — it is the spec;
// the sim agent's adoption semantics live in agents/sim-agent.mjs).
//
// A shape profile is the whole WIRE SHAPE: request path templates, an ORDERED header
// set (JA4H is header-name-order sensitive — engine/fingerprint.mjs hashes the names
// in wire order), a UA family, a cadence model (interval + PROPORTIONAL jitterPct +
// bursts), optional batch/dwell windows, optional constant-rate padding. The native
// agent adopts a shape two ways, exactly like the sim agent plus one launch-time
// fallback:
//
//   · channel-delivered: the x-varvel-shape header on every check-in reply (the
//     x-varvel-profile pattern). 'plain' (or a shape with no active blocks) CLEARS —
//     back to today's byte-identical minimal wire.
//   · launch-time: -shape <name> from the embedded library below (the same four
//     profiles the Node engine ships: plain | cdn-asset | software-update |
//     telemetry-beacon). A channel delivery re-anchors/overrides it live.
//
// PARITY ANCHORS (the platform's discipline — measured, never claimed):
//   · windowIndexAt/windowOffsetMs/windowFlushAt are HMAC-seeded deterministic
//     functions of the shared token; shape_test.go pins Node-computed vectors.
//   · wireHeaders is a straight port of malleable.expectedWireHeaders — the exact
//     ordered header list shapegrade's expectedJa4h is computed over. The emitter
//     (shapehttp.go) writes headers in EXACTLY this order and lowercase, so the
//     platform oracle's measured JA4H equals the claim byte-for-byte (proven against
//     the live Node oracle by harness/shape-observe.mjs, driven from shape_test.go).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand"
	"strings"
)

// ——— UA families (engine/malleable.mjs, verbatim) ———
const (
	uaChrome    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	uaChromeEdg = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
	uaUpdate    = "Microsoft-Update-Agent/10.0.10011.16384 Client-Protocol/2.0"
	uaTelemetry = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

// ShapeProfile mirrors engine/malleable.mjs shapeProfile()'s RESOLVED output (the
// channel delivers that resolved form as compact JSON; the library below is the same
// data for the launch-time -shape flag). nil blocks mean "no shaping on that axis".
type ShapeProfile struct {
	Name    string
	Label   string
	Cadence *ShapeCadence
	Batch   *ShapeBatch
	Padding *ShapePadding
	HTTP    *ShapeHTTP
}

type ShapeCadence struct {
	IntervalMs int64
	JitterPct  float64 // PROPORTIONAL jitter: gap = interval * (1 ± pct*r)
	JitterMs   int64
	Burst      ShapeBurst
}

type ShapeBurst struct {
	Chance float64
	MinN   int
	MaxN   int
	GapMs  int64
}

type ShapeBatch struct {
	WindowMs int64
}

type ShapePadding struct {
	PerCycle int
}

// ShapeHTTP is the wire template. Headers keep TEMPLATE ORDER — that order is the
// JA4H-significant one (the oracle hashes header names in wire order).
type ShapeHTTP struct {
	PullPaths []string
	PushPaths []string
	QueryKey  string
	Headers   [][2]string
	UAPool    []string
}

// shapeLibrary is engine/malleable.mjs SHAPE_PROFILES, verbatim (minus 'plain',
// which is "no shape" — represented as nil everywhere on this side).
var shapeLibrary = map[string]ShapeProfile{
	"cdn-asset": {
		Name: "cdn-asset", Label: "CDN static assets",
		Cadence: &ShapeCadence{IntervalMs: 4000, JitterPct: 0.4, Burst: ShapeBurst{Chance: 0.10, MinN: 2, MaxN: 4, GapMs: 400}},
		HTTP: &ShapeHTTP{
			PullPaths: []string{"/assets/js/app.min.js", "/assets/css/site.css", "/static/img/logo.svg", "/assets/js/vendor.min.js"},
			PushPaths: []string{"/api/telemetry"},
			QueryKey:  "v",
			Headers: [][2]string{
				{"user-agent", "{ua}"},
				{"accept", "*/*"},
				{"accept-language", "en-US,en;q=0.9"},
				{"accept-encoding", "gzip, deflate, br"},
				{"cache-control", "no-cache"},
				{"pragma", "no-cache"},
			},
			UAPool: []string{uaChrome, uaChromeEdg},
		},
	},
	"software-update": {
		Name: "software-update", Label: "Software update check",
		Cadence: &ShapeCadence{IntervalMs: 30000, JitterPct: 0.15, Burst: ShapeBurst{Chance: 0, MinN: 0, MaxN: 0, GapMs: 0}},
		HTTP: &ShapeHTTP{
			PullPaths: []string{"/update/check", "/v2/manifest.json"},
			PushPaths: []string{"/update/telemetry"},
			QueryKey:  "cb",
			Headers: [][2]string{
				{"user-agent", "{ua}"},
				{"accept", "application/json"},
				{"accept-encoding", "gzip, deflate"},
			},
			UAPool: []string{uaUpdate},
		},
	},
	"telemetry-beacon": {
		Name: "telemetry-beacon", Label: "Analytics telemetry ping",
		Cadence: &ShapeCadence{IntervalMs: 15000, JitterPct: 0.5, Burst: ShapeBurst{Chance: 0.06, MinN: 2, MaxN: 3, GapMs: 600}},
		HTTP: &ShapeHTTP{
			PullPaths: []string{"/collect", "/telemetry/v2/events", "/analytics/ping"},
			PushPaths: []string{"/collect", "/telemetry/v2/events"},
			QueryKey:  "z",
			Headers: [][2]string{
				{"user-agent", "{ua}"},
				{"accept", "*/*"},
				{"accept-language", "en-US,en;q=0.9"},
				{"accept-encoding", "gzip, deflate, br"},
			},
			UAPool: []string{uaTelemetry, uaChrome},
		},
	},
}

// shapeByName resolves a launch-time -shape flag against the embedded library.
// 'plain'/'' = no shape (nil, nil); an unknown name is an honest error, never a
// silent reshape (shapeProfile() returns null Node-side — same contract).
func shapeByName(name string) (*ShapeProfile, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "plain" {
		return nil, nil
	}
	if s, ok := shapeLibrary[name]; ok {
		cp := s
		return &cp, nil
	}
	return nil, &ShapeError{Msg: "unknown shape profile '" + name + "' — known: plain, cdn-asset, software-update, telemetry-beacon"}
}

// ShapeError is the honest refusal carrier for unknown names / malformed payloads.
type ShapeError struct{ Msg string }

func (e *ShapeError) Error() string { return e.Msg }

// shapePayload is the wire form of x-varvel-shape (callback.mjs shapeHeaders():
// { name, cadence, batch, padding, http, at } — already shapeProfile()-resolved
// channel-side; the clamps below mirror shapeProfile() for defense in depth).
type shapePayload struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Cadence *struct {
		IntervalMs int64   `json:"intervalMs"`
		JitterPct  float64 `json:"jitterPct"`
		JitterMs   int64   `json:"jitterMs"`
		Burst      *struct {
			Chance float64 `json:"chance"`
			MinN   int     `json:"minN"`
			MaxN   int     `json:"maxN"`
			GapMs  int64   `json:"gapMs"`
		} `json:"burst"`
	} `json:"cadence"`
	Batch *struct {
		WindowMs int64 `json:"windowMs"`
	} `json:"batch"`
	Padding *struct {
		PerCycle int `json:"perCycle"`
	} `json:"padding"`
	HTTP *struct {
		PullPaths []string   `json:"pullPaths"`
		PushPaths []string   `json:"pushPaths"`
		QueryKey  string     `json:"queryKey"`
		Headers   [][]string `json:"headers"`
		UAPool    []string   `json:"uaPool"`
	} `json:"http"`
	At int64 `json:"at"`
}

// resolveShapePayload parses one x-varvel-shape header value the way sim-agent's
// _adoptConfigHeaders does: 'plain' (or a payload with NO active shaping blocks)
// clears — (nil, 0, true, nil); a malformed payload is ignored ((…, false, nil) with
// ok=false so the caller keeps the current shape, exactly like the sim agent's
// catch{}); a real payload resolves with shapeProfile()'s clamps.
func resolveShapePayload(raw string) (shape *ShapeProfile, at int64, ok bool) {
	var p shapePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, 0, false
	}
	// The clear contract (sim-agent _adoptConfigHeaders, verbatim semantics).
	if (p.Name == "plain" || p.Name == "") && p.HTTP == nil && p.Cadence == nil && p.Batch == nil && p.Padding == nil {
		return nil, 0, true
	}
	s := &ShapeProfile{Name: p.Name, Label: p.Label}
	if s.Name == "" {
		s.Name = "custom"
	}
	if p.Cadence != nil {
		c := &ShapeCadence{
			IntervalMs: p.Cadence.IntervalMs,
			JitterPct:  clampF(p.Cadence.JitterPct, 0, 0.9),
			JitterMs:   maxI64(p.Cadence.JitterMs, 0),
		}
		if c.IntervalMs < 200 { // malleableProfile's floor: Math.max(200, …||2500)
			if c.IntervalMs <= 0 {
				c.IntervalMs = 2500
			} else {
				c.IntervalMs = 200
			}
		}
		if b := p.Cadence.Burst; b != nil {
			c.Burst = ShapeBurst{Chance: clampF(b.Chance, 0, 1), MinN: maxInt(b.MinN, 0), MaxN: maxInt(b.MaxN, 0), GapMs: maxI64(b.GapMs, 0)}
		}
		s.Cadence = c
	}
	if p.Batch != nil && p.Batch.WindowMs > 0 {
		s.Batch = &ShapeBatch{WindowMs: maxI64(p.Batch.WindowMs, 1000)}
	}
	if p.Padding != nil && p.Padding.PerCycle > 1 {
		s.Padding = &ShapePadding{PerCycle: minInt(8, p.Padding.PerCycle)}
	}
	if p.HTTP != nil && len(p.HTTP.PullPaths) > 0 {
		h := &ShapeHTTP{QueryKey: p.HTTP.QueryKey}
		h.PullPaths = capStrs(p.HTTP.PullPaths, 8)
		h.PushPaths = capStrs(p.HTTP.PushPaths, 8)
		if len(h.PushPaths) == 0 {
			h.PushPaths = h.PullPaths
		}
		if h.QueryKey == "" {
			h.QueryKey = "v"
		}
		if len(h.QueryKey) > 12 {
			h.QueryKey = h.QueryKey[:12]
		}
		for _, pair := range p.HTTP.Headers {
			if len(pair) >= 2 && len(h.Headers) < 16 {
				h.Headers = append(h.Headers, [2]string{pair[0], pair[1]})
			}
		}
		h.UAPool = capStrs(p.HTTP.UAPool, 6)
		if len(h.UAPool) == 0 {
			h.UAPool = []string{"{ua}"}
		}
		s.HTTP = h
	}
	return s, p.At, true
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func capStrs(in []string, cap int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(out) >= cap {
			break
		}
		out = append(out, s)
	}
	return out
}

// ——— Cadence model (malleable.nextGap, byte-port) ———

// nextGap samples one cycle's gap: with burst.chance probability a BURST of
// minN..maxN quick cycles at burst.gapMs spacing, else interval ± proportional
// jitter (jitterPct) or absolute jitter (jitterMs), floored at 200ms. randFn is the
// injectable sampler (nil -> math/rand), mirroring nextGap(profile, { rand }).
func nextGap(c *ShapeCadence, randFn func() float64) (gapMs int64, burst int) {
	if randFn == nil {
		randFn = rand.Float64
	}
	b := c.Burst
	if b.Chance > 0 && b.MaxN > 0 && randFn() < b.Chance {
		n := b.MinN + int(math.Floor(randFn()*float64(b.MaxN-b.MinN+1)))
		return b.GapMs, maxInt(1, n)
	}
	pct := clampF(c.JitterPct, 0, 0.9)
	var gap float64
	if pct > 0 {
		gap = math.Round(float64(c.IntervalMs) * (1 + (randFn()*2-1)*pct))
	} else {
		gap = float64(c.IntervalMs) + math.Round((randFn()*2-1)*float64(c.JitterMs))
	}
	return maxI64(200, int64(gap)), 1
}

// ——— Batch/dwell windows (malleable.windowIndexAt/windowOffsetMs/windowFlushAt,
// byte-exact — the parity vectors in shape_test.go are Node-computed) ———

// windowIndexAt: Math.max(0, Math.floor((now - anchor) / Math.max(1, windowMs))).
func windowIndexAt(anchorMs, windowMs, nowMs int64) int64 {
	w := windowMs
	if w < 1 {
		w = 1
	}
	i := (nowMs - anchorMs) / w // positive-only division == floor here (index clamped ≥ 0)
	if i < 0 {
		return 0
	}
	return i
}

// windowOffsetMs: the HMAC-seeded flush offset inside a window —
// frac = uint32BE(HMAC-SHA256(token, 'varvel-batch:'+index)[0:4]) / 2^32;
// offset = floor(frac * max(1, windowMs)). float64 division is IEEE-exact in both
// runtimes, so the floor lands on the same integer byte-for-byte.
func windowOffsetMs(token string, windowMs, windowIndex int64) int64 {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("varvel-batch:" + itoa(windowIndex)))
	digest := m.Sum(nil)
	frac := float64(binary.BigEndian.Uint32(digest[:4])) / 4294967296.0
	w := windowMs
	if w < 1 {
		w = 1
	}
	return int64(math.Floor(frac * float64(w)))
}

// windowFlushAt: anchor + index*window + the seeded offset inside it.
func windowFlushAt(token string, anchorMs, windowMs, windowIndex int64) int64 {
	return anchorMs + windowIndex*windowMs + windowOffsetMs(token, windowMs, windowIndex)
}

// ——— Request template (malleable.expectedWireHeaders + the sim agent's
// _pickPath/_shapeHeaders, byte-port) ———

// pickPath renders one shaped request path: a random template entry plus the
// cache-busting query key (4 random bytes hex — sim-agent _pickPath verbatim).
func (s *ShapeProfile) pickPath(paths []string, randFn func() float64) string {
	if s == nil || s.HTTP == nil || len(paths) == 0 {
		return ""
	}
	if randFn == nil {
		randFn = rand.Float64
	}
	p := paths[int(math.Floor(randFn()*float64(len(paths))))%len(paths)]
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return p
	}
	return p + "?" + s.HTTP.QueryKey + "=" + hex.EncodeToString(b[:])
}

// wireHeaders builds the EXACT ordered header list for one shaped request — a port
// of malleable.expectedWireHeaders with real values filled in (the oracle hashes
// header NAMES in wire order plus the accept-language VALUE; everything else's value
// is free, so host/connection/content-length carry their real ones):
//
//	host, connection, <template headers in profile order, {ua} filled from the UA
//	pool>, x-agent, x-seq, [x-task], x-auth, [x-varvel-enc when enc — the sim agent's
//	insertion position], then the runtime-default append sequence for any template
//	missing: accept → accept-language → sec-fetch-mode → user-agent →
//	accept-encoding; sec-fetch-mode present in the template is FORCED to 'cors' in
//	place; POST adds content-length LAST.
//
// All names are emitted lowercase (undici lowercases on send — the oracle's measured
// ring is lowercase, and expectedJa4h is computed over lowercase names).
func (s *ShapeProfile) wireHeaders(method, host, agentID string, seq int64, auth, taskID string, enc bool, randFn func() float64) [][2]string {
	sh := s.HTTP
	if randFn == nil {
		randFn = rand.Float64
	}
	ua := sh.UAPool[0]
	if len(sh.UAPool) > 1 {
		ua = sh.UAPool[int(math.Floor(randFn()*float64(len(sh.UAPool))))%len(sh.UAPool)]
	}
	out := [][2]string{{"host", host}, {"connection", "keep-alive"}}
	set := map[string]bool{}
	secFetchIdx := -1
	for _, pair := range sh.Headers {
		n := strings.ToLower(pair[0])
		v := pair[1]
		if v == "{ua}" {
			v = ua
		}
		out = append(out, [2]string{n, v})
		set[n] = true
		if n == "sec-fetch-mode" {
			secFetchIdx = len(out) - 1
		}
	}
	out = append(out, [2]string{"x-agent", agentID}, [2]string{"x-seq", itoa(seq)})
	if method == "POST" {
		out = append(out, [2]string{"x-task", taskID})
	}
	out = append(out, [2]string{"x-auth", auth})
	if enc {
		// sim-agent _pullEnvelope: the capability flag is set AFTER the auth headers
		// (JS object insertion order) — keep that exact position. Honest note: the
		// claim (expectedJa4h) is computed for the non-enc wire, so an enc+shape
		// combination measures ONE header over the claim — shapegrade reports that
		// divergence; it is the platform working, never hidden.
		out = append(out, [2]string{"x-varvel-enc", "1"})
	}
	if secFetchIdx >= 0 { // forced to cors IN PLACE (template position kept)
		out[secFetchIdx][1] = "cors"
	}
	if !set["accept"] {
		out = append(out, [2]string{"accept", "*/*"})
	}
	if !set["accept-language"] {
		out = append(out, [2]string{"accept-language", "*"})
	}
	if !set["sec-fetch-mode"] {
		out = append(out, [2]string{"sec-fetch-mode", "cors"})
	}
	if !set["user-agent"] {
		out = append(out, [2]string{"user-agent", "node"})
	}
	if !set["accept-encoding"] {
		out = append(out, [2]string{"accept-encoding", "gzip, deflate"})
	}
	// content-length is appended by the emitter (it owns the body length) — LAST,
	// exactly where expectedWireHeaders puts it for POST.
	return out
}

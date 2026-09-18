// evasion_windows_test.go — the native evasion tier, proven hermetically: the
// snapshot/patch/verify/restore byte math over FAKE memory regions, the typed-error
// rails, idempotency, the spec-gate port, and the evidence JSON shape (the field set
// engine/evasion.mjs parseEvasionEvidence reads). No test here patches real memory —
// the live in-process chain is the integration leg's job (test/native-agent.test.mjs,
// VARVEL_NATIVE_IT=1), exactly as the PS tier's live flip is the guarded leg of
// test/evasion.test.mjs.
package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The same fake 8-byte function prologue the Node suite uses (test/evasion.test.mjs);
// the patch span is its first 6 bytes (the recipe length — exact-span writes only).
var fakePrologue = []byte{0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x08, 0x57}

// Cross-implementation pins: sha256 of the two public recipe byte strings, computed
// once by Node crypto (2026-08-24) — the SAME digests engine/evasion.mjs derives for
// EVASION_RECIPES[*].recipeSha256. A drift between the Go recipes and the Node
// recipes turns this red.
const (
	amsiRecipeShaPin = "d84f4c120005f1837dc65c04181f3da9466b123fc369c359a301babc12061570"
	etwRecipeShaPin  = "fc9727eae305b45d1df8a58191610014e9104fa57b472dca0dbbded60cb84d82"
)

func TestEvasionRecipePins(t *testing.T) {
	if len(evasionTechniques) != 2 || evasionTechniques[0] != "amsi" || evasionTechniques[1] != "etw" {
		t.Fatalf("technique set/order drifted: %v", evasionTechniques)
	}
	amsi := evasionRecipes["amsi"]
	if amsi.dll != "amsi.dll" || amsi.export != "AmsiScanBuffer" {
		t.Fatalf("amsi recipe target drifted: %s!%s", amsi.dll, amsi.export)
	}
	if got := amsi.patch; !equalBytes(got, []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}) {
		t.Fatalf("amsi patch bytes drifted: % x", got)
	}
	if amsi.sha256 != amsiRecipeShaPin {
		t.Fatalf("amsi recipeSha256 %s != the Node-computed pin %s", amsi.sha256, amsiRecipeShaPin)
	}
	etw := evasionRecipes["etw"]
	if etw.dll != "ntdll.dll" || etw.export != "EtwEventWrite" {
		t.Fatalf("etw recipe target drifted: %s!%s", etw.dll, etw.export)
	}
	if got := etw.patch; !equalBytes(got, []byte{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}) {
		t.Fatalf("etw patch bytes drifted: % x", got)
	}
	if etw.sha256 != etwRecipeShaPin {
		t.Fatalf("etw recipeSha256 %s != the Node-computed pin %s", etw.sha256, etwRecipeShaPin)
	}
}

func TestPatchRegionContract(t *testing.T) {
	mem := append([]byte(nil), fakePrologue...)
	region, err := newPatchRegion(mem[:6], nil) // plain-copy write: the fake span
	if err != nil {
		t.Fatal(err)
	}
	patch := evasionRecipes["amsi"].patch
	// snapshot BEFORE: the original bytes and their hash are the restore source
	snapSha := region.snapshot()
	if snapSha != sha256Hex(mem[:6]) {
		t.Fatalf("snapshot hash != original region hash")
	}
	if !region.verify(fakePrologue[:6]) {
		t.Fatal("pre-patch: region holds the original bytes")
	}
	// patch: exact-span write, re-read PROVEN
	patchedSha, err := region.patch(patch)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if patchedSha != amsiRecipeShaPin {
		t.Fatalf("patched region hash != the recipe pin")
	}
	if !region.verify(patch) || region.verify(fakePrologue[:6]) {
		t.Fatal("post-patch: re-read must equal the patch bytes and not the originals")
	}
	// restore: the SNAPSHOT bytes go back, re-read PROVEN against the original
	restoredSha, err := region.restore()
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restoredSha != snapSha {
		t.Fatalf("restored region must hash EXACTLY to the pre-patch snapshot")
	}
	if !region.verify(fakePrologue[:6]) || region.verify(patch) {
		t.Fatal("restore-verifies-original: the region is byte-identical to before")
	}
}

func TestPatchRegionRails(t *testing.T) {
	patch := evasionRecipes["etw"].patch
	// never write what you cannot restore
	r1, _ := newPatchRegion(append([]byte(nil), fakePrologue...), nil)
	if _, err := r1.patch(patch); !errors.Is(err, errPatchNoSnapshot) {
		t.Fatalf("patch without snapshot: want errPatchNoSnapshot, got %v", err)
	}
	// exact-span writes only — a short/long write would build a franken-function
	r2, _ := newPatchRegion(append([]byte(nil), fakePrologue[:6]...), nil)
	r2.snapshot()
	var se *spanError
	if _, err := r2.patch([]byte{0xC3}); !errors.As(err, &se) {
		t.Fatalf("short patch: want *spanError, got %T %v", err, err)
	}
	if _, err := r2.patch(make([]byte, 8)); !errors.As(err, &se) {
		t.Fatalf("long patch: want *spanError, got %T %v", err, err)
	}
	if !r2.verify(fakePrologue[:6]) {
		t.Fatal("a REFUSED patch never touched the region")
	}
	// restore without a snapshot is refused; the constructor validates input
	r3, _ := newPatchRegion(make([]byte, 4), nil)
	if _, err := r3.restore(); !errors.Is(err, errRestoreNoSnapshot) {
		t.Fatalf("restore without snapshot: want errRestoreNoSnapshot, got %v", err)
	}
	if _, err := newPatchRegion(nil, nil); err == nil {
		t.Fatal("empty view must refuse")
	}
	// the write-failure path propagates the typed/nested error honestly
	werr := errors.New("VirtualProtect refused")
	r4, _ := newPatchRegion(append([]byte(nil), fakePrologue[:6]...), func([]byte) error { return werr })
	r4.snapshot()
	if _, err := r4.patch(patch); !errors.Is(err, werr) {
		t.Fatalf("write failure must propagate: got %v", err)
	}
}

func TestParseEvasionSpec(t *testing.T) {
	// valid specs parse (dedup + case-fold); restore empty means all-patched
	s, err := parseEvasionSpec("evasion-enable", `{"techniques":["AMSI","amsi","etw"]}`)
	if err != nil || len(s.techniques) != 2 || s.techniques[0] != "amsi" || s.techniques[1] != "etw" {
		t.Fatalf("enable parse: %+v %v", s, err)
	}
	s, err = parseEvasionSpec("evasion-restore", `{"techniques":["etw"]}`)
	if err != nil || len(s.techniques) != 1 || s.techniques[0] != "etw" {
		t.Fatalf("restore parse: %+v %v", s, err)
	}
	for _, empty := range []string{"", "{}", "  "} {
		s, err = parseEvasionSpec("evasion-restore", empty)
		if err != nil || s.techniques != nil {
			t.Fatalf("empty restore must mean all-patched: %+v %v", s, err)
		}
	}
	s, err = parseEvasionSpec("evasion-status", "")
	if err != nil || s.techniques != nil {
		t.Fatalf("status parse: %+v %v", s, err)
	}
	// every malformed spec refuses loudly (nothing patches)
	for name, tc := range map[string]struct{ kind, data, want string }{
		"not json":          {"evasion-enable", "not json", "not valid JSON"},
		"no techniques":     {"evasion-enable", "{}", "must be an array"},
		"empty techniques":  {"evasion-enable", `{"techniques":[]}`, "empty"},
		"string techniques": {"evasion-enable", `{"techniques":"amsi"}`, "must be an array"},
		"sleepmask":         {"evasion-enable", `{"techniques":["amsi","sleepmask"]}`, `unknown technique "sleepmask"`},
		"kernel":            {"evasion-enable", `{"techniques":["kernel"]}`, "unknown technique"},
		"status with data":  {"evasion-status", `{"techniques":["amsi"]}`, "takes no task data"},
		"unknown kind":      {"evasion-x", "{}", "unknown kind"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseEvasionSpec(tc.kind, tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want refusal containing %q, got %v", tc.want, err)
			}
		})
	}
}

// fakeEvasionEnv backs the op machinery with fake memory: one 8-byte prologue span
// per technique, a scripted AMSI scanner, a scripted ETW call. The machinery above
// the seam is the LIVE code — that's the point of the seam.
type fakeEvasionEnv struct {
	env     *evasionEnv
	mems    map[string][]byte // technique -> the fake region (first 6 bytes are the span)
	scans   []string          // scripted amsiScan results, popped in order
	etwRC   uint32
	etwAddr uintptr // last address etwCall was invoked with
}

func newFakeEvasionEnv(scans ...string) *fakeEvasionEnv {
	f := &fakeEvasionEnv{mems: map[string][]byte{}, scans: scans, etwRC: 0}
	f.env = &evasionEnv{
		resolve: func(tech string) (*patchRegion, uintptr, error) {
			if _, ok := evasionRecipes[tech]; !ok {
				return nil, 0, &unknownTechniqueError{tech: tech}
			}
			mem := append([]byte(nil), fakePrologue...)
			f.mems[tech] = mem
			region, err := newPatchRegion(mem[:6], nil)
			return region, 0x41410000, err
		},
		amsiScan: func() string {
			if len(f.scans) == 0 {
				return "blocked" // a scanner that flags the test string is the sane default
			}
			s := f.scans[0]
			f.scans = f.scans[1:]
			return s
		},
		etwCall: func(addr uintptr) uint32 { f.etwAddr = addr; return f.etwRC },
	}
	return f
}

func newFakeEngine(f *fakeEvasionEnv) *evasionEngine {
	return &evasionEngine{env: f.env, live: map[string]*livePatch{}}
}

func decodeResult(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("result body is not JSON: %v\n%s", err, s)
	}
	return m
}

func TestEvasionOpsFakeEnv(t *testing.T) {
	// scripted scanner: before=blocked, after-enable=clear, after-restore=blocked
	f := newFakeEvasionEnv("blocked", "clear", "blocked")
	e := newFakeEngine(f)

	// ENABLE both techniques
	out := e.runOp("enable", []string{"amsi", "etw"})
	if !strings.HasPrefix(out, `{"op":"enable","pid":`) {
		t.Fatalf("op must lead the result body (the ledger preview carries it): %.80s", out)
	}
	res := decodeResult(t, out)
	if res["state"] != "patched" {
		t.Fatalf("enable aggregate state: %v", res["state"])
	}
	techs := res["techniques"].(map[string]any)
	amsi := techs["amsi"].(map[string]any)
	if amsi["state"] != "patched" || amsi["byteVerified"] != true {
		t.Fatalf("amsi enable evidence: %v", amsi)
	}
	if amsi["originalSha256"] != sha256Hex(fakePrologue[:6]) {
		t.Fatalf("amsi originalSha256 must pin the SNAPSHOT bytes: %v", amsi["originalSha256"])
	}
	if amsi["patchedSha256"] != amsiRecipeShaPin {
		t.Fatalf("amsi patchedSha256 must equal the recipe pin: %v", amsi["patchedSha256"])
	}
	v := amsi["verify"].(map[string]any)
	if v["before"] != "blocked" || v["after"] != "clear" || v["flipProven"] != true {
		t.Fatalf("the blocked->clear flip must be MEASURED: %v", v)
	}
	etw := techs["etw"].(map[string]any)
	if etw["state"] != "patched" || etw["byteVerified"] != true || etw["patchedSha256"] != etwRecipeShaPin {
		t.Fatalf("etw enable evidence: %v", etw)
	}
	if f.etwAddr != 0x41410000 {
		t.Fatalf("the etw functional probe must call the resolved export address: %#x", f.etwAddr)
	}
	ev := etw["verify"].(map[string]any)
	if ev["flipProven"] != false || !strings.Contains(ev["functional"].(string), "returned 0x0") {
		t.Fatalf("etw verify: the in-process noop call must report ERROR_SUCCESS: %v", ev)
	}
	// the FAKE MEMORY itself must hold the patch bytes now (the write really landed)
	if !equalBytes(f.mems["amsi"][:6], evasionRecipes["amsi"].patch) || !equalBytes(f.mems["etw"][:6], evasionRecipes["etw"].patch) {
		t.Fatalf("post-enable: the fake regions must hold the patch bytes: % x / % x", f.mems["amsi"][:6], f.mems["etw"][:6])
	}

	// STATUS: live re-read proves the patch is still in place (measured, not remembered)
	res = decodeResult(t, e.runOp("status", nil))
	if res["state"] != "patched" {
		t.Fatalf("status aggregate: %v", res["state"])
	}
	for _, name := range []string{"amsi", "etw"} {
		st := res["techniques"].(map[string]any)[name].(map[string]any)
		if st["state"] != "patched" || st["byteVerified"] != true {
			t.Fatalf("status %s: %v", name, st)
		}
	}

	// RESTORE with no techniques = whatever THIS process has patched
	res = decodeResult(t, e.runOp("restore", nil))
	if res["state"] != "restored" {
		t.Fatalf("restore aggregate: %v", res["state"])
	}
	amsi = res["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["restoreVerified"] != true || amsi["restoredSha256"] != sha256Hex(fakePrologue[:6]) {
		t.Fatalf("amsi restore evidence: %v", amsi)
	}
	v = amsi["verify"].(map[string]any)
	if v["before"] != "clear" || v["after"] != "blocked" || v["flipBackProven"] != true {
		t.Fatalf("the clear->blocked flip-back must be MEASURED: %v", v)
	}
	// the fake memory is byte-identical to before the whole dance
	for _, name := range []string{"amsi", "etw"} {
		if !equalBytes(f.mems[name], fakePrologue) {
			t.Fatalf("post-restore: %s region must be byte-identical to the original prologue: % x", name, f.mems[name])
		}
	}

	// STATUS after restore: aggregate 'restored'
	res = decodeResult(t, e.runOp("status", nil))
	if res["state"] != "restored" {
		t.Fatalf("post-restore status aggregate: %v", res["state"])
	}
}

func TestEvasionIdempotency(t *testing.T) {
	f := newFakeEvasionEnv("blocked", "clear", "blocked")
	e := newFakeEngine(f)

	first := decodeResult(t, e.runOp("enable", []string{"amsi"}))
	origSha := first["techniques"].(map[string]any)["amsi"].(map[string]any)["originalSha256"]

	// re-enable: idempotent — the ORIGINAL snapshot stays the only restore source
	second := decodeResult(t, e.runOp("enable", []string{"amsi"}))
	amsi := second["techniques"].(map[string]any)["amsi"].(map[string]any)
	if second["state"] != "patched" || amsi["state"] != "patched" || amsi["byteVerified"] != true {
		t.Fatalf("idempotent re-enable: %v", amsi)
	}
	if amsi["originalSha256"] != origSha {
		t.Fatalf("re-enable must NOT re-snapshot (the patch bytes are not the original): %v vs %v", amsi["originalSha256"], origSha)
	}
	if !strings.Contains(amsi["note"].(string), "idempotent") {
		t.Fatalf("the idempotent no-op is noted honestly: %v", amsi["note"])
	}

	// TAMPER: someone else rewrites the region under the live patch
	f.mems["amsi"][0] = 0x90
	st := decodeResult(t, e.runOp("status", nil))
	amsi = st["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["state"] != "tampered" || amsi["byteVerified"] != false {
		t.Fatalf("a live re-read mismatch must flip the honest state to tampered: %v", amsi)
	}
	// re-enable on a tampered region refuses loudly (snapshot preserved); restore
	// still puts the TRUE original bytes back
	en := decodeResult(t, e.runOp("enable", []string{"amsi"}))
	amsi = en["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["state"] != "failed" || !strings.Contains(amsi["error"].(string), "tampered") {
		t.Fatalf("tampered re-enable must fail loudly: %v", amsi)
	}
	re := decodeResult(t, e.runOp("restore", []string{"amsi"}))
	amsi = re["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["restoreVerified"] != true || amsi["restoredSha256"] != origSha {
		t.Fatalf("restore after tamper must put the TRUE original back: %v", amsi)
	}
	if !equalBytes(f.mems["amsi"], fakePrologue) {
		t.Fatalf("the region is byte-identical to the original prologue after restore: % x", f.mems["amsi"])
	}

	// double-restore: the honest no-op (idempotent), never a fabricated restore
	re2 := decodeResult(t, e.runOp("restore", []string{"amsi"}))
	amsi = re2["techniques"].(map[string]any)["amsi"].(map[string]any)
	if re2["state"] != "restored" || !strings.Contains(amsi["note"].(string), "no live patch") {
		t.Fatalf("double-restore must be the honest no-op: %v", amsi)
	}
}

func TestEvasionFailurePaths(t *testing.T) {
	// a scanner that is OFF/ABSENT: the flip is unprovable — byte-proof only, noted honestly
	f := newFakeEvasionEnv("unavailable:0x80070005", "unavailable:0x80070005")
	e := newFakeEngine(f)
	res := decodeResult(t, e.runOp("enable", []string{"amsi"}))
	amsi := res["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["state"] != "patched" || amsi["byteVerified"] != true {
		t.Fatalf("bytes patched + verified even when the scanner is unavailable: %v", amsi)
	}
	v := amsi["verify"].(map[string]any)
	if v["flipProven"] != false || !strings.Contains(amsi["note"].(string), "NOT measured") {
		t.Fatalf("an unprovable flip is noted, never claimed: %v / %v", v, amsi["note"])
	}
	// op-level failure: enable with no techniques → failed envelope, EMPTY techniques
	// (engine/evasion.mjs fabricates NO audit event from an empty technique map)
	res = decodeResult(t, e.runOp("enable", nil))
	if res["state"] != "failed" || len(res["techniques"].(map[string]any)) != 0 {
		t.Fatalf("op-level failure envelope: %v", res)
	}
	// unknown op is a loud failure envelope
	res = decodeResult(t, e.runOp("sidestep", nil))
	if res["state"] != "failed" || !strings.Contains(res["error"].(string), "unknown evasion op") {
		t.Fatalf("unknown op: %v", res)
	}
	// unknown technique below the parse layer: failed evidence, loud text (defense in depth)
	res = decodeResult(t, e.runOp("enable", []string{"sleepmask"}))
	te := res["techniques"].(map[string]any)["sleepmask"].(map[string]any)
	if te["state"] != "failed" || !strings.Contains(te["error"].(string), "unknown evasion technique") {
		t.Fatalf("unknown technique: %v", te)
	}
}

func TestEvasionEvidenceShape(t *testing.T) {
	// The field contract engine/evasion.mjs parseEvasionEvidence reads — pinned so a
	// Go-side drift breaks HERE, not silently channel-side.
	f := newFakeEvasionEnv("blocked", "clear")
	e := newFakeEngine(f)
	res := decodeResult(t, e.runOp("enable", []string{"amsi"}))
	for _, k := range []string{"op", "pid", "state", "techniques", "at"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("top-level key %q missing: %v", k, res)
		}
	}
	amsi := res["techniques"].(map[string]any)["amsi"].(map[string]any)
	wantKeys := []string{"state", "recipe", "recipeNote", "recipeSha256", "originalSha256", "patchedSha256", "restoredSha256", "byteVerified", "restoreVerified", "verify", "note", "error"}
	for _, k := range wantKeys {
		if _, ok := amsi[k]; !ok {
			t.Fatalf("per-technique key %q missing (the intake parser reads exactly this set): %v", k, amsi)
		}
	}
	// null fields are REAL nulls (PS host parity — not omitted, not empty strings)
	if amsi["restoredSha256"] != nil || amsi["note"] != nil || amsi["error"] != nil {
		t.Fatalf("unset evidence fields must be JSON null: %v", amsi)
	}
	if amsi["recipe"] != "amsi.dll!AmsiScanBuffer" || amsi["recipeSha256"] != amsiRecipeShaPin {
		t.Fatalf("recipe fields: %v", amsi)
	}
	// the restore body carries the full hash chain: restored == original
	re := decodeResult(t, e.runOp("restore", nil))
	amsi = re["techniques"].(map[string]any)["amsi"].(map[string]any)
	if amsi["restoredSha256"] != amsi["originalSha256"] || amsi["restoredSha256"] == nil {
		t.Fatalf("restoredSha256 must equal the original snapshot hash: %v", amsi)
	}
}

func TestExecEvasionGate(t *testing.T) {
	ctxAgent := &Agent{Dir: t.TempDir()}
	ctxAgent.Logf = func(string, ...any) {}
	// gate OFF (the default): every kind refuses LOUDLY and NOTHING runs
	for _, kind := range []string{"evasion-enable", "evasion-restore", "evasion-status"} {
		got := string(ctxAgent.execEvasion(kind, `{"techniques":["amsi"]}`))
		if !strings.HasPrefix(got, kind+" REFUSED: agent-side evasion is OFF") {
			t.Fatalf("%s gate-off refusal: %q", kind, got)
		}
		if !strings.Contains(got, "-allow-evasion") || !strings.Contains(got, "exec.evasion") {
			t.Fatalf("the refusal names BOTH gate halves: %q", got)
		}
	}
	// gate ON: a malformed spec is REJECTED before anything resolves memory
	armed := &Agent{Dir: t.TempDir(), AllowEvasion: true}
	armed.Logf = func(string, ...any) {}
	got := string(armed.execEvasion("evasion-enable", "garbage"))
	if !strings.HasPrefix(got, "evasion-enable REJECTED: ") {
		t.Fatalf("bad spec: %q", got)
	}
	// gate ON: evasion-status on a fresh engine touches NO memory and reports honestly
	// (status of never-patched techniques resolves nothing — safe in a unit test)
	res := decodeResult(t, string(armed.execEvasion("evasion-status", "")))
	if res["op"] != "status" || res["state"] != "untouched" {
		t.Fatalf("fresh status: %v", res)
	}
	for _, name := range []string{"amsi", "etw"} {
		if res["techniques"].(map[string]any)[name].(map[string]any)["state"] != "not-applied" {
			t.Fatalf("fresh status %s: %v", name, res["techniques"])
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

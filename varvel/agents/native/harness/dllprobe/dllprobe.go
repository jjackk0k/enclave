// dllprobe.go — a minimal LoadLibrary/GetProcAddress probe for the DLL form of
// the agent (varvel-agent.dll, -tags varveldll -buildmode=c-shared). It calls
// the VarvelStatus export DIRECTLY (no rundll32 in the loop), so a failing
// signed-proxy leg can be isolated: if THIS probe writes the marker file, the
// DLL + export are sound and any failure is in the host-side invocation.
//
// Usage: dllprobe.exe <path\to\varvel-agent.dll> <path\to\status-out.json>
// Exit 0 + the marker file = the export ran. Stdlib only (syscall) — no new
// module dependencies.
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dllprobe <varvel-agent.dll> <status-out.json>")
		os.Exit(2)
	}
	d, err := syscall.LoadDLL(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "LoadDLL:", err)
		os.Exit(3)
	}
	p, err := d.FindProc("VarvelStatus")
	if err != nil {
		fmt.Fprintln(os.Stderr, "FindProc(VarvelStatus):", err)
		os.Exit(4)
	}
	bp, err := syscall.BytePtrFromString(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "out path:", err)
		os.Exit(2)
	}
	r, _, callErr := p.Call(0, 0, uintptr(unsafe.Pointer(bp)), 0)
	fmt.Printf("VarvelStatus ret=%d callErr=%v\n", r, callErr)
	if r != 0 {
		os.Exit(5)
	}
}

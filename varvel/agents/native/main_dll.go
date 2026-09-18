//go:build varveldll

// main_dll.go — with -tags varveldll (buildmode=c-shared) the real CLI main
// (main.go, tagged !varveldll) is excluded and THIS no-op is the entry: a DLL
// must never parse os.Args or os.Exit on load (the Go runtime calls main in a
// goroutine when the host loads the DLL — exiting would kill the SIGNED HOST
// process, e.g. rundll32.exe, mid-load). All behavior lives behind the exported
// C ABI in proxydll.go.
package main

func main() {}

// agent_test.go — the agent loop rehearsed against a stub listener enforcing the real
// intake rules (strict seq, per-route HMAC, 204-uniform rejects, server-side kill), so
// the Go side proves enroll-free check-in → task down → exec → result up → kill
// silence before the Node-side integration test ever drives the real CallbackChannel.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubChannel is the minimal honest listener: the intake rules from
// engine/callback.mjs, no more. killed=true makes everything 204 (kill-list parity).
type stubChannel struct {
	t       *testing.T
	lastSeq atomic.Int64
	killed  atomic.Bool
	task    *Task // one queued task, delivered once
	results []string
}

func (s *stubChannel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseInt(r.Header.Get("x-seq"), 10, 64)
	id := r.Header.Get("x-agent")
	auth := r.Header.Get("x-auth")
	if s.killed.Load() || err != nil || seq <= s.lastSeq.Load() || id != vecID {
		w.WriteHeader(http.StatusNoContent) // killed / stale / unknown: 204-uniform
		return
	}
	switch r.URL.Path {
	case "/c":
		if auth != pullAuth(vecToken, id, seq) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.lastSeq.Store(seq)
		if s.task == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t := s.task
		s.task = nil
		w.Header().Set("content-type", "application/octet-stream")
		json.NewEncoder(w).Encode(map[string]string{"taskId": t.TaskID, "kind": t.Kind, "data": t.Data})
	case "/r":
		body, _ := io.ReadAll(r.Body)
		if auth != pushAuth(vecToken, id, seq, r.Header.Get("x-task"), body) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.lastSeq.Store(seq)
		s.results = append(s.results, string(body))
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestAgentLoopEndToEnd(t *testing.T) {
	stub := &stubChannel{t: t, task: &Task{TaskID: vecTaskID, Kind: "echo", Data: "wire round-trip probe"}}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	dir := t.TempDir()
	a := &Agent{URL: srv.URL, ID: vecID, Token: vecToken, Dir: dir, Client: srv.Client()}
	a.Logf = func(string, ...any) {} // quiet in tests

	// Cycle 1: the queued echo task comes down, its result goes up.
	worked, err := a.tick(context.Background())
	if err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	if !worked {
		t.Fatal("tick 1: task was queued but nothing was delivered")
	}
	if len(stub.results) != 1 || stub.results[0] != "wire round-trip probe" {
		t.Fatalf("result up: got %v", stub.results)
	}

	// Cycle 2: idle — 204, nothing to do.
	worked, err = a.tick(context.Background())
	if err != nil || worked {
		t.Fatalf("tick 2 (idle): worked=%v err=%v", worked, err)
	}

	// Kill: the agent cannot tell killed from idle — that IS the contract.
	stub.killed.Store(true)
	stub.task = &Task{TaskID: "post-kill", Kind: "echo", Data: "must never be delivered"}
	worked, err = a.tick(context.Background())
	if err != nil || worked {
		t.Fatalf("tick 3 (killed): worked=%v err=%v — a queued task reached a killed agent", worked, err)
	}
	if len(stub.results) != 1 {
		t.Fatal("killed agent pushed a result")
	}
}

func TestExecKinds(t *testing.T) {
	a := &Agent{Dir: t.TempDir()}
	a.Logf = func(string, ...any) {}
	ctx := context.Background()

	if got := string(a.exec(ctx, Task{Kind: "note", Data: "hello"})); got != "noted: hello" {
		t.Fatalf("note: got %q", got)
	}
	if got := string(a.exec(ctx, Task{Kind: "echo", Data: "verbatim ✓"})); got != "verbatim ✓" {
		t.Fatalf("echo: got %q", got)
	}
	if got := string(a.exec(ctx, Task{Kind: "never-heard-of-it", Data: "x"})); got != "unknown task kind: never-heard-of-it" {
		t.Fatalf("unknown kind: got %q", got)
	}

	// shell: a REAL PowerShell child, cwd-locked to the sandbox.
	out := string(a.exec(ctx, Task{Kind: "shell", Data: "(Get-Location).Path"}))
	want, _ := filepath.EvalSymlinks(a.Dir)
	if !strings.EqualFold(strings.TrimSpace(out), strings.TrimSpace(want)) {
		t.Fatalf("shell cwd confinement: got %q want %q", out, want)
	}
	// Output cap honesty: 70KB of output truncates to the 60KB cap.
	big := string(a.exec(ctx, Task{Kind: "shell", Data: "'x' * 70000"}))
	if len(big) > resultCapBytes {
		t.Fatalf("output cap: got %d bytes, cap is %d", len(big), resultCapBytes)
	}
	// Timeout honesty: a 60s sleep dies at the 20s exec timeout.
	start := time.Now()
	if got := string(a.exec(ctx, Task{Kind: "shell", Data: "Start-Sleep -Seconds 60"})); got != "(task timeout)" {
		t.Fatalf("timeout: got %q", got)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("timeout did not kill the child promptly")
	}
}

// The -once dry-run path against an idle channel: one cycle, clean exit.
func TestOnceAgainstIdleChannel(t *testing.T) {
	stub := &stubChannel{t: t}
	srv := httptest.NewServer(stub)
	defer srv.Close()
	a := &Agent{URL: srv.URL, ID: vecID, Token: vecToken, Dir: t.TempDir(), Client: srv.Client()}
	a.Logf = func(string, ...any) {}
	done := make(chan struct{})
	go func() { a.run(context.Background(), true); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("-once did not return after one cycle")
	}
	if _, err := os.Stat(a.Dir); err != nil {
		t.Fatalf("sandbox dir missing: %v", err)
	}
}

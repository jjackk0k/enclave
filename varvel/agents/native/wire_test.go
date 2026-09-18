// wire_test.go — cross-implementation wire vectors: the auth signatures and hashes
// below were computed ONCE by the platform's own Node runtime (the exact crypto the
// listener uses) and pinned here. If Go and Node ever disagree, this test — not a
// reviewer — says so. Provenance:
//
//	node -e "crypto.createHmac('sha256', token).update(id + ':1:pull').digest('hex')" …
//
// (full generator inline below; token/id/taskId/body are fixed test constants).
package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Node-generated vectors (engine/callback.mjs's hmac/sha256 helpers, verbatim):
//
//	token  = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
//	id     = 'f00ba7cafe01'
//	taskId = '9f1c2ab3-44aa-4e7c-9d01-112233445566'
//	body   = 'hello varvel wire'
const (
	vecToken  = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	vecID     = "f00ba7cafe01"
	vecTaskID = "9f1c2ab3-44aa-4e7c-9d01-112233445566"
	vecBody   = "hello varvel wire"

	vecPullSeq1  = "8db4b814b9d0b918e40acf73d0d27e42a3361f94c83969de648e033179191b87"
	vecPullSeq42 = "9583e220a3e97f5bec2401cf4f0496975dc8d9aa94ee58d89534c36da177b2d7"
	vecBodySHA   = "871aa43e271f0dd36989d6a81bba3268a59835aa8260a828410df231ad3da0d1"
	vecPushSeq3  = "7b39853d94ae9c7d7a06459b87637658e435b44a25aa5c1d3994fd9a1974d6a7"
	vecEmptySHA  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func TestCrossImplementationVectors(t *testing.T) {
	if got := pullAuth(vecToken, vecID, 1); got != vecPullSeq1 {
		t.Fatalf("pull auth seq1: got %s want %s (Node-computed)", got, vecPullSeq1)
	}
	if got := pullAuth(vecToken, vecID, 42); got != vecPullSeq42 {
		t.Fatalf("pull auth seq42: got %s want %s (Node-computed)", got, vecPullSeq42)
	}
	if got := sha256Hex([]byte(vecBody)); got != vecBodySHA {
		t.Fatalf("body sha256: got %s want %s (Node-computed)", got, vecBodySHA)
	}
	if got := pushAuth(vecToken, vecID, 3, vecTaskID, []byte(vecBody)); got != vecPushSeq3 {
		t.Fatalf("push auth seq3: got %s want %s (Node-computed)", got, vecPushSeq3)
	}
	if got := sha256Hex(nil); got != vecEmptySHA {
		t.Fatalf("empty sha256: got %s want %s (Node-computed)", got, vecEmptySHA)
	}
}

func TestSeqIsAgentGlobalStrictlyIncreasing(t *testing.T) {
	a := &Agent{}
	s1 := a.nextSeq()
	s2 := a.nextSeq()
	if s1 != 1 || s2 != 2 {
		t.Fatalf("seq must start at 1 and increase by 1 across ANY request; got %d then %d", s1, s2)
	}
}

// The task-reply decoder against the channel's two real reply shapes (single + batch),
// byte-verbatim from engine/callback.mjs's res.end(JSON.stringify(...)) lines.
func TestTaskReplyDecoding(t *testing.T) {
	single := `{"taskId":"t-1","kind":"shell","data":"whoami"}`
	batch := `{"batch":true,"tasks":[{"taskId":"t-1","kind":"note","data":"hi"},{"taskId":"t-2","kind":"echo","data":"yo"}]}`
	var tr taskReply
	if err := json.Unmarshal([]byte(single), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.Batch || tr.TaskID != "t-1" || tr.Kind != "shell" || tr.Data != "whoami" {
		t.Fatalf("single shape misdecoded: %+v", tr)
	}
	if err := json.Unmarshal([]byte(batch), &tr); err != nil {
		t.Fatal(err)
	}
	if !tr.Batch || len(tr.Tasks) != 2 || tr.Tasks[1].Kind != "echo" {
		t.Fatalf("batch shape misdecoded: %+v", tr)
	}
}

// pull/push against a stub listener that enforces the REAL intake rules (204 idle,
// strict seq, per-route HMAC) — the Go-side wire rehearsal before the Node-side
// integration test drives the actual CallbackChannel.
func TestPullPushAgainstStubListener(t *testing.T) {
	lastSeq := int64(0)
	var pushedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("x-agent")
		seqStr := r.Header.Get("x-seq")
		auth := r.Header.Get("x-auth")
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil || seq <= lastSeq {
			w.WriteHeader(http.StatusNoContent) // stale-seq: 204-uniform
			return
		}
		switch r.URL.Path {
		case "/c":
			if auth != pullAuth(vecToken, id, seq) {
				w.WriteHeader(http.StatusNoContent) // bad-auth: 204-uniform
				return
			}
			lastSeq = seq
			w.WriteHeader(http.StatusNoContent) // idle
		case "/r":
			taskID := r.Header.Get("x-task")
			body, _ := io.ReadAll(r.Body)
			if auth != pushAuth(vecToken, id, seq, taskID, body) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			lastSeq = seq
			pushedBody = body
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	a := &Agent{URL: srv.URL, ID: vecID, Token: vecToken, Client: srv.Client()}
	tasks, _, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), false, nil, nil)
	if err != nil || tasks != nil {
		t.Fatalf("idle pull: tasks=%v err=%v (want nil, nil)", tasks, err)
	}
	if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), vecTaskID, []byte(vecBody), false, nil, nil); err != nil {
		t.Fatalf("push: %v", err)
	}
	if string(pushedBody) != vecBody {
		t.Fatalf("listener got body %q, want %q", pushedBody, vecBody)
	}
	// Replay discipline: re-sending seq 2 must be rejected (stub enforces it).
	if err := push(a.Client, a.URL, a.ID, a.Token, 2, vecTaskID, []byte(vecBody), false, nil, nil); err == nil {
		t.Fatal("replayed seq was accepted — strict-seq discipline failed")
	}
}

// The enc wire against a stub listener that mirrors the REAL intake's required-mode
// rules (engine/callback.mjs): capability-less pull => 204 'enc-required'; sealed task
// reply down; sealed result body up — HMAC over the CIPHERTEXT. Plus the agent-side
// downgrade refusal: a plaintext task reply is never tasked from.
func TestEncWireAgainstStubListener(t *testing.T) {
	key, err := deriveEncKey(vecToken, vecID)
	if err != nil {
		t.Fatal(err)
	}
	lastSeq := int64(0)
	var pushedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("x-agent")
		seq, err := strconv.ParseInt(r.Header.Get("x-seq"), 10, 64)
		if err != nil || seq <= lastSeq {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.URL.Path {
		case "/c":
			if r.Header.Get("x-auth") != pullAuth(vecToken, id, seq) ||
				r.Header.Get("x-varvel-enc") != "1" { // required mode: capability-less pull refused
				w.WriteHeader(http.StatusNoContent)
				return
			}
			lastSeq = seq
			reply, err := sealString(key, `{"taskId":"`+vecTaskID+`","kind":"echo","data":"sealed-down"}`)
			if err != nil {
				t.Errorf("stub seal: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, reply)
		case "/r":
			taskID := r.Header.Get("x-task")
			body, _ := io.ReadAll(r.Body)
			// Encrypt-then-MAC: the HMAC signs the sealed bytes as posted.
			if r.Header.Get("x-auth") != pushAuth(vecToken, id, seq, taskID, body) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if !isSealedBytes(body) { // required mode: plaintext content refused
				w.WriteHeader(http.StatusNoContent)
				return
			}
			lastSeq = seq
			pushedBody = body
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	a := &Agent{URL: srv.URL, ID: vecID, Token: vecToken, Client: srv.Client(), Enc: true}
	tasks, _, err := pull(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), a.Enc, key, nil)
	if err != nil || len(tasks) != 1 || tasks[0].Kind != "echo" || tasks[0].Data != "sealed-down" {
		t.Fatalf("sealed pull: tasks=%+v err=%v", tasks, err)
	}
	if err := push(a.Client, a.URL, a.ID, a.Token, a.nextSeq(), vecTaskID, []byte("sealed-up"), a.Enc, key, nil); err != nil {
		t.Fatalf("sealed push: %v", err)
	}
	opened, err := openBytes(key, pushedBody)
	if err != nil || string(opened) != "sealed-up" {
		t.Fatalf("listener-side open of the pushed ciphertext: %q err=%v", opened, err)
	}

	// Downgrade refusal: the same agent against a PLAINTEXT-replying listener must
	// refuse loudly (errPlaintextReply) and consume the task never.
	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"taskId":"t-9","kind":"shell","data":"plaintext downgrade"}`)
	}))
	defer plainSrv.Close()
	_, _, err = pull(plainSrv.Client(), plainSrv.URL, vecID, vecToken, 1, true, key, nil)
	if !errors.Is(err, errPlaintextReply) {
		t.Fatalf("plaintext reply to an enc agent: got %v, want errPlaintextReply", err)
	}

	// Tamper-evidence: a sealed-looking reply that does not open is a typed
	// *EnvelopeError, never a task.
	tamperSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bad, _ := sealString(key, "x")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, bad[:len(bad)-2]+"zz") // tag broken, prefix intact
	}))
	defer tamperSrv.Close()
	_, _, err = pull(tamperSrv.Client(), tamperSrv.URL, vecID, vecToken, 1, true, key, nil)
	var ee *EnvelopeError
	if !errors.As(err, &ee) || ee.Code != "open" {
		t.Fatalf("tampered sealed reply: got %v, want EnvelopeError 'open'", err)
	}
}

// wire.go — the VARVEL callback-channel HTTP wire, ported byte-for-byte from the
// reference sim agent (varvel/agents/sim-agent.mjs) against the listener's intake
// (varvel/engine/callback.mjs). Speaks the envelope layer (engine/envelope.mjs,
// ported in envelope.go): with enc on, the capability header rides every pull
// (x-varvel-enc: 1), task replies MUST arrive sealed ('enc1:…' — a plaintext reply
// is a refused downgrade, loud and never tasked from), and result bodies are sealed
// BEFORE the HMAC signs them (encrypt-then-MAC: the signature authenticates the
// ciphertext — the formula is unchanged).
//
// THE CONTRACT (listener-side truth, engine/callback.mjs _handle):
//   pull: GET  {url}/c  headers x-agent, x-seq, x-auth = HMAC-SHA256hex(token, id:seq:pull)
//         [+ x-varvel-enc: 1 when enc]
//         204 = idle OR any rejection (unknown/killed/bad-auth/stale-seq: 204-uniform)
//         200 = JSON { taskId, kind, data } / { batch:true, tasks:[...] } — the sealed
//               string form ('enc1:'+base64url(blob)) when the agent is enc-proven
//   push: POST {url}/r  headers x-agent, x-seq, x-task, body = raw result bytes
//         (the AEAD blob 'VE'‖0x01‖nonce‖ct‖tag when enc),
//         x-auth = HMAC-SHA256hex(token, id:seq:taskId:sha256hex(body))
//         200 empty = accepted; 204-uniform = rejected
//   seq is AGENT-GLOBAL and strictly increasing across pulls AND pushes — the listener
//   rejects seq <= lastSeen. Killed agents are indistinguishable from idle ones (the
//   kill-list is enforced server-side by silence; there is nothing to detect).
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"time"
)

// hmacHex mirrors Node: createHmac('sha256', key).update(msg).digest('hex').
func hmacHex(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// sha256Hex mirrors Node: createHash('sha256').update(buf).digest('hex').
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Task is one delivered unit of work from the channel.
type Task struct {
	TaskID string `json:"taskId"`
	Kind   string `json:"kind"`
	Data   string `json:"data"`
}

// taskReply is the union of the single-task and batch reply shapes.
type taskReply struct {
	TaskID string `json:"taskId"`
	Kind   string `json:"kind"`
	Data   string `json:"data"`
	Batch  bool   `json:"batch"`
	Tasks  []Task `json:"tasks"`
}

// pullAuth is the check-in signature for seq: HMAC(token, id:seq:pull).
func pullAuth(token, agentID string, seq int64) string {
	return hmacHex(token, agentID+":"+itoa(seq)+":pull")
}

// padAuth is the PADDING-DUMMY signature: HMAC(token, id:seq:pad) — a real
// authenticated envelope carrying NO task semantics (the channel audits it as
// 'agent.pad' and answers 204, never delivers tasks on it). Constant-rate shaping,
// profile-gated (shape.padding.perCycle), sim-agent _pad parity.
func padAuth(token, agentID string, seq int64) string {
	return hmacHex(token, agentID+":"+itoa(seq)+":pad")
}

// shapeWireCtx bundles what a SHAPED request needs beyond the plain wire: the
// adopted profile, the injectable sampler (path/UA pick + cadence), and the TLS
// dial config for the ordered emitter's https leg (shapehttp.go — the emitter owns
// the connection because net/http cannot emit headers in template order).
type shapeWireCtx struct {
	shape    *ShapeProfile
	randFn   func() float64
	tlsProf  string
	tlsInsec bool
}

// issue sends one request: the shaped leg (ordered emitter, exact template header
// order) when a shape with an http template is adopted, else the plain minimal
// request through the ordinary client (today's byte-identical wire).
func issue(client *http.Client, sc *shapeWireCtx, method, url string, headers [][2]string, body []byte) (*http.Response, error) {
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return doShapedRequest(ctx, sc.tlsProf, sc.tlsInsec, method, url, headers, body)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	return client.Do(req)
}

// pushAuth binds a result to its task AND content: HMAC(token, id:seq:taskId:sha256(body)).
func pushAuth(token, agentID string, seq int64, taskID string, body []byte) string {
	return hmacHex(token, agentID+":"+itoa(seq)+":"+taskID+":"+sha256Hex(body))
}

func itoa(v int64) string {
	// strconv.Itoa for the int64 the seq counter holds; kept as a helper so the wire
	// formatting lives in exactly one place (Node String(seq) == base-10, no padding).
	return fmt.Sprintf("%d", v)
}

// errPlaintextReply is the loud DOWNGRADE refusal: an enc agent was handed a plaintext
// task reply. tick treats it as "idle this cycle" (never tasked from) — sim-agent
// parity ('enc: PLAINTEXT task reply refused … — possible downgrade').
var errPlaintextReply = errors.New("enc: PLAINTEXT task reply refused (this agent seals) — possible downgrade")

// pull performs one authenticated check-in. Returns the delivered tasks (nil when
// idle), the reply HEADERS (the x-varvel-* config delivery channel — shape adoption
// rides them on 204 idle replies exactly as on 200 task replies), or an error only on
// TRANSPORT/parse failure — every governance rejection is the same 204 as idle, so
// "no tasks" is the only honest reading of 204. With enc the capability header rides
// the request and the reply MUST be a sealed string: errPlaintextReply on a plaintext
// body, a typed *EnvelopeError on one that fails to open (tamper-evidence — the AEAD
// tag authenticates the reply).
//
// sc != nil with an adopted http template switches the request to the profile's
// shaped path + ordered header set (the shaping pack, shape.go/shapehttp.go); the
// envelope semantics below are unchanged either way.
func pull(client *http.Client, url, agentID, token string, seq int64, enc bool, encKey []byte, sc *shapeWireCtx) ([]Task, http.Header, error) {
	path := "/c"
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		path = sc.shape.pickPath(sc.shape.HTTP.PullPaths, sc.randFn)
	}
	var headers [][2]string
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		headers = sc.shape.wireHeaders(http.MethodGet, hostOf(url), agentID, seq, pullAuth(token, agentID, seq), "", enc, sc.randFn)
	} else {
		headers = [][2]string{{"x-agent", agentID}, {"x-seq", itoa(seq)}, {"x-auth", pullAuth(token, agentID, seq)}}
		if enc {
			headers = append(headers, [2]string{"x-varvel-enc", "1"}) // the ec:1 capability flag, http-wire form
		}
	}
	resp, err := issue(client, sc, http.MethodGet, url+path, headers, nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		io.Copy(io.Discard, resp.Body)
		return nil, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, fmt.Errorf("pull HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.Header, err
	}
	if enc {
		opened, err := openString(encKey, string(body))
		if err != nil {
			if !isSealedString(string(body)) {
				return nil, resp.Header, errPlaintextReply
			}
			return nil, resp.Header, err // typed *EnvelopeError — tamper or wrong key, dropped loudly
		}
		body = []byte(opened)
	}
	var tr taskReply
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, resp.Header, fmt.Errorf("pull: undecodable task reply: %w", err)
	}
	if tr.Batch {
		return tr.Tasks, resp.Header, nil
	}
	if tr.TaskID == "" {
		return nil, resp.Header, nil // a 200 with no task id is treated as idle (defensive; unseen on the real wire)
	}
	return []Task{{TaskID: tr.TaskID, Kind: tr.Kind, Data: tr.Data}}, resp.Header, nil
}

// pad emits ONE constant-rate padding dummy (sim-agent _pad parity): the same wire
// shape as a pull (shaped path + headers when a shape is adopted) but the ':pad'
// HMAC context — the channel audits it as padding ('agent.pad'), answers 204, and
// never delivers tasks on it. Config headers on the pad reply are NOT adopted
// (sim-agent _pad drains without adopting — mirrored deliberately).
func pad(client *http.Client, url, agentID, token string, seq int64, enc bool, sc *shapeWireCtx) error {
	path := "/c"
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		path = sc.shape.pickPath(sc.shape.HTTP.PullPaths, sc.randFn)
	}
	var headers [][2]string
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		headers = sc.shape.wireHeaders(http.MethodGet, hostOf(url), agentID, seq, padAuth(token, agentID, seq), "", enc, sc.randFn)
	} else {
		headers = [][2]string{{"x-agent", agentID}, {"x-seq", itoa(seq)}, {"x-auth", padAuth(token, agentID, seq)}}
		if enc {
			headers = append(headers, [2]string{"x-varvel-enc", "1"})
		}
	}
	resp, err := issue(client, sc, http.MethodGet, url+path, headers, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // drain; the 204 body is empty by contract
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("pad HTTP %d (204-uniform expected — rejection or miswire)", resp.StatusCode)
	}
	return nil
}

// push posts one result bound to its task. Accepted = 200; anything else is reported
// (the wire's rejections are 204-uniform, so a non-200 here is a rejection, never an
// acknowledgment). With enc the body is AEAD-sealed FIRST — the HMAC below then signs
// the CIPHERTEXT (encrypt-then-MAC; the sha256(body) formula is unchanged). With an
// adopted http template the push rides the profile's push path + ordered header set.
func push(client *http.Client, url, agentID, token string, seq int64, taskID string, body []byte, enc bool, encKey []byte, sc *shapeWireCtx) error {
	if enc {
		sealed, err := sealBytes(encKey, body)
		if err != nil {
			return err
		}
		body = sealed
	}
	path := "/r"
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		path = sc.shape.pickPath(sc.shape.HTTP.PushPaths, sc.randFn)
	}
	auth := pushAuth(token, agentID, seq, taskID, body)
	var headers [][2]string
	if sc != nil && sc.shape != nil && sc.shape.HTTP != nil {
		headers = sc.shape.wireHeaders(http.MethodPost, hostOf(url), agentID, seq, auth, taskID, enc, sc.randFn)
	} else {
		headers = [][2]string{{"x-agent", agentID}, {"x-seq", itoa(seq)}, {"x-task", taskID}, {"x-auth", auth}}
	}
	resp, err := issue(client, sc, http.MethodPost, url+path, headers, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push HTTP %d (204-uniform = rejected by the channel)", resp.StatusCode)
	}
	return nil
}

// hostOf extracts the Host header value (host[:port]) for the shaped emitter —
// the 'host' pair leads every ordered header block.
func hostOf(rawURL string) string {
	u, err := urlpkg.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

const maxBody = 4 * 1024 * 1024 // the listener's MAX_BODY cap (engine/callback.mjs)

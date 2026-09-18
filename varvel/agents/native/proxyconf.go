// proxyconf.go — the JSON launch config for the DLL form of the agent
// (buildmode=c-shared, the SIGNED-PROXY EXECUTION tier; see docs/NATIVE.md).
//
// The exe takes flags; a DLL export cannot, so VarvelRun takes ONE JSON document
// (inline, or "@<path>" to read it from a file inside the host's reachable fs).
// This file is the PURE parse/validate half — no cgo, no build tag — so the Go
// test suite covers it without needing a C compiler (proxyconf_test.go); the
// cgo export shim that consumes it lives in proxydll.go (tag `varveldll`).
//
// Governance note (honest, deliberate): the DLL carries NO allow-flag of its own FOR
// THE PROXY TIER. It is the payload half of that tier — the double gate lives
// platform-side (engagement setting exec.proxy + the delivering agent's
// -AllowProxyExec / --proxy flag). A DLL that refuses to run without its own flag
// would be security theater: the bytes are already on the box by operator decision.
// The EVASION tier is different: its flag gates WHAT THE AGENT DOES at task time
// (patching its own host process), not whether it runs — so the DLL config carries
// "allowEvasion" as the launch-flag equivalent of the exe's -allow-evasion, default
// OFF, the agent-side half of the evasion double gate (the engagement exec.evasion
// setting is the channel-side half; BOTH must say yes or nothing is ever patched).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ProxyConfig mirrors the exe flags (main.go) one-for-one.
type ProxyConfig struct {
	URL         string `json:"url"`
	ID          string `json:"id"`
	Token       string `json:"token"`
	Interval    int    `json:"interval"`    // base poll gap ms (floor 200, sim-agent parity)
	Jitter      int    `json:"jitter"`      // ± uniform jitter ms
	Dir         string `json:"dir"`         // sandbox dir (default ./.native-<id>)
	TLSProfile  string `json:"tlsProfile"`  // chrome (default) | go-native
	Once        bool   `json:"once"`        // single pull/exec/push cycle, then return
	TLSInsecure  bool   `json:"tlsInsecure"`  // LAB ONLY — skip server-cert verification
	Enc          bool   `json:"enc"`          // envelope encryption (engine/envelope; -enc parity)
	Shape        string `json:"shape"`        // launch-time wire shape (-shape parity): plain | cdn-asset | software-update | telemetry-beacon
	AllowEvasion bool   `json:"allowEvasion"` // the DLL form's -allow-evasion: agent-side half of the evasion-* double gate (default OFF)
}

// parseProxyConfig validates a JSON config document. The same defaults the exe
// flags carry apply here; url/id/token are required exactly as on the CLI.
func parseProxyConfig(raw []byte) (ProxyConfig, error) {
	var cfg ProxyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("proxy config is not valid JSON: %w", err)
	}
	if strings.TrimSpace(cfg.URL) == "" || strings.TrimSpace(cfg.ID) == "" || strings.TrimSpace(cfg.Token) == "" {
		return cfg, errors.New("proxy config needs url, id and token (id+token are issued channel-side at registration)")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 2000
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.TLSProfile == "" {
		cfg.TLSProfile = ProfileChrome
	}
	if cfg.TLSProfile != ProfileChrome && cfg.TLSProfile != ProfileGoNative {
		return cfg, fmt.Errorf("unknown tlsProfile %q (want %s | %s)", cfg.TLSProfile, ProfileChrome, ProfileGoNative)
	}
	if _, err := shapeByName(cfg.Shape); err != nil {
		return cfg, err // honest refusal, same as the exe's -shape flag
	}
	return cfg, nil
}

// loadProxyConfig accepts inline JSON or "@<path>" (read the document from a
// file — the shape a rundll32 command tail can actually carry).
func loadProxyConfig(arg string) (ProxyConfig, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ProxyConfig{}, errors.New("empty proxy config (want inline JSON or @<path>)")
	}
	raw := []byte(arg)
	if strings.HasPrefix(arg, "@") {
		b, err := os.ReadFile(strings.TrimSpace(arg[1:]))
		if err != nil {
			return ProxyConfig{}, fmt.Errorf("proxy config file: %w", err)
		}
		raw = b
	}
	return parseProxyConfig(raw)
}

// agentFromConfig builds the SAME Agent the exe main() builds — identical wire,
// HMAC, seq, sandbox and exec containment (agent.go is shared verbatim).
func agentFromConfig(cfg ProxyConfig) (*Agent, error) {
	client, err := httpClient(cfg.URL, cfg.TLSProfile, cfg.TLSInsecure)
	if err != nil {
		return nil, err
	}
	shape, err := shapeByName(cfg.Shape)
	if err != nil {
		return nil, err
	}
	dir := cfg.Dir
	if dir == "" {
		dir = defaultSandbox(cfg.ID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("sandbox dir: %w", err)
	}
	a := &Agent{
		URL:      trimTrailingSlash(cfg.URL),
		ID:       cfg.ID,
		Token:    cfg.Token,
		Dir:      dir,
		Interval: time.Duration(maxInt(cfg.Interval, minGapMs)) * time.Millisecond,
		Jitter:   time.Duration(cfg.Jitter) * time.Millisecond,
		Client:   client,
		Enc:          cfg.Enc,
		Shape:        shape,
		TLSProfile:   cfg.TLSProfile,
		TLSInsecure:  cfg.TLSInsecure,
		AllowEvasion: cfg.AllowEvasion,
	}
	if shape != nil {
		a.ShapeAt = time.Now().UnixMilli() // launch anchor; a channel delivery re-anchors live
	}
	return a, nil
}

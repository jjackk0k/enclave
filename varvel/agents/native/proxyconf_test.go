// proxyconf_test.go — hermetic coverage for the DLL form's JSON launch config
// (proxyconf.go). No cgo, no network: the parse/validate/default contract the
// VarvelRun export depends on, plus the "@file" form rundll32 command tails use.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProxyConfigValid(t *testing.T) {
	cfg, err := parseProxyConfig([]byte(`{"url":"http://127.0.0.1:8971","id":"a1","token":"deadbeef","interval":500,"jitter":100,"tlsProfile":"go-native","once":true}`))
	if err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if cfg.URL != "http://127.0.0.1:8971" || cfg.ID != "a1" || cfg.Token != "deadbeef" {
		t.Fatalf("fields dropped: %+v", cfg)
	}
	if cfg.Interval != 500 || cfg.Jitter != 100 || !cfg.Once || cfg.TLSProfile != ProfileGoNative {
		t.Fatalf("values not carried: %+v", cfg)
	}
}

func TestParseProxyConfigDefaults(t *testing.T) {
	cfg, err := parseProxyConfig([]byte(`{"url":"http://127.0.0.1:8971","id":"a1","token":"t"}`))
	if err != nil {
		t.Fatalf("minimal config refused: %v", err)
	}
	if cfg.Interval != 2000 || cfg.Jitter != 0 || cfg.TLSProfile != ProfileChrome || cfg.Once {
		t.Fatalf("defaults differ from the exe flags: %+v", cfg)
	}
}

func TestParseProxyConfigRefusals(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":     `{`,
		"missing url":  `{"id":"a1","token":"t"}`,
		"missing id":   `{"url":"http://x","token":"t"}`,
		"missing token": `{"url":"http://x","id":"a1"}`,
		"bad profile":  `{"url":"http://x","id":"a1","token":"t","tlsProfile":"opera"}`,
	} {
		if _, err := parseProxyConfig([]byte(raw)); err == nil {
			t.Fatalf("%s: expected a loud refusal, got ok", name)
		}
	}
}

func TestLoadProxyConfigAtFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(p, []byte(`{"url":"http://127.0.0.1:8971","id":"a1","token":"t","once":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadProxyConfig("@" + p)
	if err != nil {
		t.Fatalf("@file form refused: %v", err)
	}
	if cfg.ID != "a1" || !cfg.Once {
		t.Fatalf("@file values not carried: %+v", cfg)
	}
	if _, err := loadProxyConfig(""); err == nil {
		t.Fatal("empty config arg must refuse loudly")
	}
	if _, err := loadProxyConfig("@" + filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing @file must refuse loudly")
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withCoordinator completes cfg with what an official relay needs to run
// with the default register_auth (required): the Coordinator and the node.
func withCoordinator(cfg *Config) *Config {
	cfg.Control.ServerURL = "https://c.example"
	cfg.Node = NodeConfig{ID: "r", Region: "x", Addr: "r:1"}
	return cfg
}

func TestConfigCreateDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := loadOrCreateConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// register_auth is required by default, which needs the Coordinator
	// (device keys): that is all a fresh config lacks.
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "control.server_url") {
		t.Fatalf("default config: err = %v, want control.server_url needed", err)
	}
	if err := withCoordinator(cfg).validate(); err != nil {
		t.Fatalf("default config with a coordinator invalid: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits (files report 0666).
	if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("config created with mode %o, want 600", perm)
	}
	// Round trip: the written defaults load back identically.
	again, err := loadOrCreateConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Relay.SessionTTL != 120*time.Second || again.Discovery.DedupTTL != 3*time.Second || !again.Discovery.Enabled {
		t.Fatalf("round trip lost values: %+v", again)
	}
}

func TestConfigLoads30xFile(t *testing.T) {
	// Shape written by relay 3.0.x config.go.
	const v30 = `node:
    id: relay-hk-1
    region: hk
    addr: relay-hk.example.net:21031
relay:
    bind: '[::]:21031'
control:
    server_url: https://coord.example.net
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(v30), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOrCreateConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("3.0.x config rejected: %v", err)
	}
	if cfg.Node.ID != "relay-hk-1" || cfg.Relay.MaxSessions != 65536 || cfg.Control.RelaySecret != "" {
		t.Fatalf("unexpected: %+v", cfg)
	}
	// Existing configs get the log file without editing them.
	if cfg.Log.File != "relay.log" || cfg.Log.MaxSizeMB != 50 || cfg.Log.MaxBackups != 5 {
		t.Fatalf("log defaults: %+v", cfg.Log)
	}
}

func TestConfigLogFile(t *testing.T) {
	cfg := withCoordinator(defaultConfig())
	cfg.Log.MaxSizeMB = 0
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "log.max_size_mb") {
		t.Fatalf("max_size_mb 0: err = %v", err)
	}
	cfg.Log.File = "" // off: the size does not matter
	if err := cfg.validate(); err != nil {
		t.Fatalf("file logging off: %v", err)
	}
	cfg.Log.MaxBackups = -1
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "log.max_backups") {
		t.Fatalf("max_backups -1: err = %v", err)
	}
}

func TestConfigRejectsUnknownAndInvalid(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadOrCreateConfig(write("relay:\n    max_sesions: 5\n")); err == nil {
		t.Fatal("misspelled key accepted")
	}

	cases := map[string]string{
		"server_url without node":  "control:\n    server_url: https://c.example\n",
		"bad scheme":               "node: {id: a, region: b, addr: c}\ncontrol:\n    server_url: ftp://c.example\n",
		"zero sessions":            "relay:\n    max_sessions: 0\n",
		"ttl below keepalive":      "relay:\n    session_ttl: 20s\n",
		"heartbeat beyond expiry":  "node: {id: a, region: b, addr: c}\ncontrol:\n    server_url: https://c\n    heartbeat_interval: 30s\n",
		"egress burst < fanout":    "discovery:\n    max_fanout: 100\n    egress_burst: 10\n",
		"negative rate":            "discovery:\n    sender_rate: -1\n",
		"stale ttl below room ttl": "discovery:\n    room_cache_ttl: 10s\n    room_cache_stale_ttl: 5s\n",
	}
	for name, body := range cases {
		cfg, err := loadOrCreateConfig(write(body))
		if err != nil {
			t.Fatalf("%s: load: %v", name, err)
		}
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfigEmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOrCreateConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.Bind != "[::]:21031" {
		t.Fatalf("defaults not applied: %q", cfg.Relay.Bind)
	}
}

func TestConfigSecretNotInValidationErrors(t *testing.T) {
	cfg := defaultConfig()
	cfg.Control.ServerURL = "https://c.example"
	cfg.Control.RelaySecret = "topsecret-value"
	err := cfg.validate()
	if err == nil || strings.Contains(err.Error(), "topsecret-value") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigDeprecatedProbeKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("relay:\n    probe_rate: 5000\n    probe_burst: 10000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadOrCreateConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := withCoordinator(cfg).validate(); err != nil {
		t.Fatalf("config with deprecated probe keys rejected: %v", err)
	}

	fresh := filepath.Join(dir, "new.yaml")
	if _, err := loadOrCreateConfig(fresh); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(fresh)
	if strings.Contains(string(data), "probe_") {
		t.Fatal("new config still writes deprecated probe keys")
	}
}

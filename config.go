package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultConfigFile = "config.yaml"

// Config is a superset of the 3.0.x config: an existing 3.0.x config.yaml
// loads unchanged, and new sections take the defaults below.
type Config struct {
	Node      NodeConfig      `yaml:"node"`
	Relay     RelayConfig     `yaml:"relay"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Control   ControlConfig   `yaml:"control"`
	Log       LogConfig       `yaml:"log"`
}

// NodeConfig is what the relay advertises to the Coordinator.
type NodeConfig struct {
	ID     string `yaml:"id"`
	Region string `yaml:"region"`
	// Addr is the public host:port clients use to reach this relay.
	Addr string `yaml:"addr"`
}

type RelayConfig struct {
	Bind              string `yaml:"bind"`
	SocketReadBuffer  int    `yaml:"socket_read_buffer"`
	SocketWriteBuffer int    `yaml:"socket_write_buffer"`

	// MaxSessions caps registered devices; registrations beyond it are
	// rejected until bindings expire.
	MaxSessions int `yaml:"max_sessions"`
	// SessionTTL expires a binding with no register/keepalive. Clients send
	// keepalives every 5–30 s (client default 25 s).
	SessionTTL time.Duration `yaml:"session_ttl"`

	// Relay ping (0x05) echoes per second, across all senders.
	PingRate  float64 `yaml:"ping_rate"`
	PingBurst int     `yaml:"ping_burst"`
	// P2P ping/pong (0x06/0x07) forwards per second, across all senders.
	// Clients send about one relay-path probe per peer per probe interval.
	ProbeRate  float64 `yaml:"probe_rate"`
	ProbeBurst int     `yaml:"probe_burst"`

	// RegisterAuth controls unauthenticated register/keepalive
	// (0x01/0x02/0x03; REGISTRATION_AUTH.md): "optional" accepts them unless
	// the device ID has a live binding made by authenticated 0x0E; "required"
	// drops them (only after all clients send 0x0E).
	RegisterAuth string `yaml:"register_auth"`
	// Device public keys for 0x0E come from the Coordinator. A key is
	// refreshed after DeviceKeyTTL and served for DeviceKeyStaleTTL after the
	// last successful fetch (Coordinator outages); at most
	// DeviceKeyMaxEntries are cached.
	DeviceKeyTTL        time.Duration `yaml:"device_key_ttl"`
	DeviceKeyStaleTTL   time.Duration `yaml:"device_key_stale_ttl"`
	DeviceKeyMaxEntries int           `yaml:"device_key_max_entries"`
}

type DiscoveryConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxSessions int           `yaml:"max_sessions"`
	SessionTTL  time.Duration `yaml:"session_ttl"` // client re-registers every 25 s

	// Per-sender limit (3.0.x: 10 packets per second per device).
	SenderRate  float64 `yaml:"sender_rate"`
	SenderBurst int     `yaml:"sender_burst"`
	MaxSenders  int     `yaml:"max_senders"`
	// Global limits on discovery packets received and datagrams sent.
	IngressRate  float64 `yaml:"ingress_rate"`
	IngressBurst int     `yaml:"ingress_burst"`
	EgressRate   float64 `yaml:"egress_rate"`
	EgressBurst  int     `yaml:"egress_burst"`

	DedupTTL        time.Duration `yaml:"dedup_ttl"`
	DedupMaxEntries int           `yaml:"dedup_max_entries"`

	RoomCacheTTL        time.Duration `yaml:"room_cache_ttl"`
	RoomCacheStaleTTL   time.Duration `yaml:"room_cache_stale_ttl"`
	RoomCacheMaxEntries int           `yaml:"room_cache_max_entries"`

	// MaxFanout caps recipients per discovery packet.
	MaxFanout int `yaml:"max_fanout"`
	// RequireSenderInRoom is deprecated and ignored: authenticated discovery
	// always requires the sender to be a discovery peer of the room. Kept so
	// that existing config files still load.
	RequireSenderInRoom bool `yaml:"require_sender_in_room"`

	// Auth is the secure discovery mode (SECURE_DISCOVERY.md). Only
	// "required" exists: 3.1.x clients use authenticated discovery only, and
	// unauthenticated 0x08/0x09 are retired. Empty means "required".
	Auth string `yaml:"auth"`
	// AuthKeyFile holds the relay's X25519 private key (base64); created
	// with mode 0600 if missing. It is used for secure discovery and for
	// registration authentication (relay.register_auth), whether or not
	// discovery is enabled. Its public key is reported to the Coordinator as
	// pub_key; clients get it via GET /relays.
	AuthKeyFile string `yaml:"auth_key_file"`
	// AuthMaxClockSkew bounds |client clock - relay clock| for sdisc and
	// sreg packet counters, and thereby how long a packet can be replayed
	// after a relay restart.
	AuthMaxClockSkew time.Duration `yaml:"auth_max_clock_skew"`
}

type ControlConfig struct {
	// ServerURL is the Coordinator base URL. Empty disables registration and
	// discovery peer lookups; data forwarding works regardless.
	ServerURL string `yaml:"server_url"`
	// RelaySecret is sent as X-Relay-Secret on /relay/register and
	// /relay/heartbeat; it must match the Coordinator's relay_secret.
	RelaySecret       string        `yaml:"relay_secret"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	RequestTimeout    time.Duration `yaml:"request_timeout"`
}

type LogConfig struct {
	// StatsInterval is how often a counters line is logged; 0 disables.
	StatsInterval time.Duration `yaml:"stats_interval"`
}

func defaultConfig() *Config {
	return &Config{
		Relay: RelayConfig{
			Bind:                "[::]:21031",
			SocketReadBuffer:    4 << 20,
			SocketWriteBuffer:   4 << 20,
			MaxSessions:         65536,
			SessionTTL:          120 * time.Second,
			PingRate:            2000,
			PingBurst:           4000,
			ProbeRate:           5000,
			ProbeBurst:          10000,
			RegisterAuth:        "optional",
			DeviceKeyTTL:        10 * time.Minute,
			DeviceKeyStaleTTL:   time.Hour,
			DeviceKeyMaxEntries: 65536,
		},
		Discovery: DiscoveryConfig{
			Enabled:             true,
			MaxSessions:         65536,
			SessionTTL:          120 * time.Second,
			SenderRate:          10,
			SenderBurst:         10,
			MaxSenders:          65536,
			IngressRate:         2000,
			IngressBurst:        4000,
			EgressRate:          20000,
			EgressBurst:         40000,
			DedupTTL:            3 * time.Second,
			DedupMaxEntries:     65536,
			RoomCacheTTL:        5 * time.Second,
			RoomCacheStaleTTL:   30 * time.Second,
			RoomCacheMaxEntries: 4096,
			MaxFanout:           256,
			RequireSenderInRoom: true,
			Auth:                "required",
			AuthKeyFile:         "relay_discovery.key",
			AuthMaxClockSkew:    30 * time.Second,
		},
		Control: ControlConfig{
			HeartbeatInterval: 10 * time.Second, // Coordinator expires relays after 30 s
			RequestTimeout:    10 * time.Second,
		},
		Log: LogConfig{
			StatsInterval: 60 * time.Second,
		},
	}
}

// loadOrCreateConfig reads path, or writes a default config there if it does
// not exist (3.0.x behaviour). The file may hold relay_secret, so it is
// created with mode 0600.
func loadOrCreateConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeConfig(path, cfg); err != nil {
			return nil, fmt.Errorf("create config: %w", err)
		}
		log.Printf("created default config at %s; fill in node/control and restart to register with a Coordinator", path)
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func writeConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (c *Config) validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if _, err := net.ResolveUDPAddr("udp", c.Relay.Bind); err != nil {
		bad("relay.bind %q: %v", c.Relay.Bind, err)
	}
	positive := map[string]float64{
		"relay.max_sessions":               float64(c.Relay.MaxSessions),
		"relay.ping_rate":                  c.Relay.PingRate,
		"relay.ping_burst":                 float64(c.Relay.PingBurst),
		"relay.probe_rate":                 c.Relay.ProbeRate,
		"relay.probe_burst":                float64(c.Relay.ProbeBurst),
		"discovery.max_sessions":           float64(c.Discovery.MaxSessions),
		"discovery.sender_rate":            c.Discovery.SenderRate,
		"discovery.sender_burst":           float64(c.Discovery.SenderBurst),
		"discovery.max_senders":            float64(c.Discovery.MaxSenders),
		"discovery.ingress_rate":           c.Discovery.IngressRate,
		"discovery.ingress_burst":          float64(c.Discovery.IngressBurst),
		"discovery.egress_rate":            c.Discovery.EgressRate,
		"discovery.egress_burst":           float64(c.Discovery.EgressBurst),
		"discovery.dedup_max_entries":      float64(c.Discovery.DedupMaxEntries),
		"discovery.room_cache_max_entries": float64(c.Discovery.RoomCacheMaxEntries),
		"discovery.max_fanout":             float64(c.Discovery.MaxFanout),
		"relay.device_key_ttl":             c.Relay.DeviceKeyTTL.Seconds(),
		"relay.device_key_stale_ttl":       c.Relay.DeviceKeyStaleTTL.Seconds(),
		"relay.device_key_max_entries":     float64(c.Relay.DeviceKeyMaxEntries),
		"relay.session_ttl":                c.Relay.SessionTTL.Seconds(),
		"discovery.session_ttl":            c.Discovery.SessionTTL.Seconds(),
		"discovery.dedup_ttl":              c.Discovery.DedupTTL.Seconds(),
		"discovery.room_cache_ttl":         c.Discovery.RoomCacheTTL.Seconds(),
		"discovery.room_cache_stale_ttl":   c.Discovery.RoomCacheStaleTTL.Seconds(),
		"control.heartbeat_interval":       c.Control.HeartbeatInterval.Seconds(),
		"control.request_timeout":          c.Control.RequestTimeout.Seconds(),
	}
	for _, k := range slices.Sorted(maps.Keys(positive)) {
		if !(positive[k] > 0) {
			bad("%s must be > 0", k)
		}
	}
	if c.Discovery.EgressBurst < c.Discovery.MaxFanout {
		bad("discovery.egress_burst (%d) must be >= discovery.max_fanout (%d)", c.Discovery.EgressBurst, c.Discovery.MaxFanout)
	}
	if c.Discovery.RoomCacheStaleTTL < c.Discovery.RoomCacheTTL {
		bad("discovery.room_cache_stale_ttl must be >= discovery.room_cache_ttl")
	}
	if c.Relay.SessionTTL < 31*time.Second {
		bad("relay.session_ttl must exceed the client's maximum keepalive interval (30s)")
	}
	if c.Discovery.SessionTTL < 26*time.Second {
		bad("discovery.session_ttl must exceed the client's discovery registration interval (25s)")
	}
	if a := c.Discovery.Auth; a != "" && a != "required" {
		bad("discovery.auth %q: only \"required\" is supported (unauthenticated discovery is retired in 3.1.x)", a)
	}
	if c.Discovery.AuthKeyFile == "" {
		bad("discovery.auth_key_file is required (relay key for discovery and registration auth)")
	}
	if c.Discovery.AuthMaxClockSkew <= 0 {
		bad("discovery.auth_max_clock_skew must be > 0")
	}
	// Replay windows must outlive any packet that is still fresh.
	if c.Discovery.Enabled && c.Discovery.SessionTTL < 2*c.Discovery.AuthMaxClockSkew {
		bad("discovery.session_ttl must be >= 2 * discovery.auth_max_clock_skew")
	}
	if c.Relay.SessionTTL < 2*c.Discovery.AuthMaxClockSkew {
		bad("relay.session_ttl must be >= 2 * discovery.auth_max_clock_skew")
	}
	if mode, err := parseRegAuthMode(c.Relay.RegisterAuth); err != nil {
		bad("relay.register_auth: %v", err)
	} else if mode == regAuthRequired && c.Control.ServerURL == "" {
		bad("relay.register_auth: required needs control.server_url (device keys come from the Coordinator)")
	}
	if c.Relay.DeviceKeyStaleTTL < c.Relay.DeviceKeyTTL {
		bad("relay.device_key_stale_ttl must be >= relay.device_key_ttl")
	}
	if c.Log.StatsInterval < 0 {
		bad("log.stats_interval must be >= 0")
	}
	if c.Control.ServerURL != "" {
		u, err := url.Parse(c.Control.ServerURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			bad("control.server_url %q must be an http(s) URL", c.Control.ServerURL)
		}
		if c.Node.ID == "" || c.Node.Region == "" || c.Node.Addr == "" {
			bad("node.id, node.region and node.addr are required when control.server_url is set")
		}
		if c.Control.HeartbeatInterval >= 30*time.Second {
			bad("control.heartbeat_interval must be < 30s (Coordinator relay expiry)")
		}
	}
	return errors.Join(errs...)
}

// regAuthMode returns the parsed relay.register_auth. Call after validate.
func (c *Config) regAuthMode() regAuthMode {
	m, _ := parseRegAuthMode(c.Relay.RegisterAuth)
	return m
}

func (c *Config) limits() relayLimits {
	return relayLimits{
		maxSessions:         c.Relay.MaxSessions,
		sessionTTL:          c.Relay.SessionTTL,
		pingRate:            c.Relay.PingRate,
		pingBurst:           c.Relay.PingBurst,
		probeRate:           c.Relay.ProbeRate,
		probeBurst:          c.Relay.ProbeBurst,
		regAuth:             c.regAuthMode(),
		discoveryEnabled:    c.Discovery.Enabled,
		discMaxSessions:     c.Discovery.MaxSessions,
		discSessionTTL:      c.Discovery.SessionTTL,
		discSenderRate:      c.Discovery.SenderRate,
		discSenderBurst:     c.Discovery.SenderBurst,
		discMaxSenders:      c.Discovery.MaxSenders,
		discIngressRate:     c.Discovery.IngressRate,
		discIngressBurst:    c.Discovery.IngressBurst,
		discEgressRate:      c.Discovery.EgressRate,
		discEgressBurst:     c.Discovery.EgressBurst,
		discDedupTTL:        c.Discovery.DedupTTL,
		discDedupMax:        c.Discovery.DedupMaxEntries,
		discMaxFanout:       c.Discovery.MaxFanout,
		authSkew:            c.Discovery.AuthMaxClockSkew,
		maintenanceInterval: 5 * time.Second,
	}
}

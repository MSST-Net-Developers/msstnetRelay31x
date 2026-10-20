package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Vectors (client repo docs/ROOM_RELAY_SERVER_3.1.md) ─────────────────

func TestRelayKeyproofVector(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x02))
	server := testKey(t, 0x03)
	serverPub := [32]byte(server.PublicKey().Bytes())
	if got := hex.EncodeToString(serverPub[:]); got != "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" {
		t.Fatalf("server_pub = %s", got)
	}
	var cid [16]byte
	for i := range cid {
		cid[i] = 0x11
	}
	mac, err := auth.relayKeyproofMAC(serverPub, cid)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mac[:]); got != "6fb95d31d70d3d66953314fb80497d8d21261b770235dd5dfa38e6f83cc373d3" {
		t.Fatalf("mac = %s", got)
	}
	// Low-order server key (all-zero shared secret) is refused.
	if _, err := auth.relayKeyproofMAC([32]byte{}, cid); err == nil {
		t.Fatal("all-zero server_pub accepted")
	}
}

func TestRelayPasswordVerifierVector(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x02))
	got := hex.EncodeToString(relayPasswordVerifier("relay secret", auth.pub))
	if got != "7a8ef8ff39824ac7476ecbe76264a5b16cc0376d6e5f805bea3436060f3af9a3" {
		t.Fatalf("verifier = %s", got)
	}
}

func TestRelayLink(t *testing.T) {
	pub := newSdiscAuth(testKey(t, 0x02)).pub
	const want = "msst-relay://relay.example.com:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk"
	if got := relayLink("relay.example.com:7000", pub, false); got != want {
		t.Fatalf("link = %s", got)
	}
	if got := relayLink("relay.example.com:7000", pub, true); got != want+"?pw=1" {
		t.Fatalf("link with password = %s", got)
	}
	frag := strings.TrimSuffix(want[strings.IndexByte(want, '#')+1:], "?pw=1")
	if dec, err := base64.RawURLEncoding.DecodeString(frag); err != nil || !bytes.Equal(dec, pub[:]) {
		t.Fatal("link key does not decode to the relay public key")
	}
}

// ── Config (RR1, RR2) ────────────────────────────────────────────────────

func selfHostedConfig() *Config {
	cfg := defaultConfig()
	cfg.Relay.Mode = relayModeSelfHosted
	cfg.Relay.RegisterAuth = "required"
	cfg.Control.ServerURL = "https://coord.example.com"
	cfg.Node.Addr = "relay.example.com:7000"
	return cfg
}

func TestConfigSelfHosted(t *testing.T) {
	if !defaultConfig().Relay.RequireRoomPassword || defaultConfig().Relay.Mode != relayModeOfficial {
		t.Fatal("defaults: want mode official, require_room_password true")
	}
	for _, c := range []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"valid", func(c *Config) {}, true},
		{"no node id/region needed", func(c *Config) { c.Node.ID, c.Node.Region = "", "" }, true},
		{"password", func(c *Config) { c.Relay.Password = "pw" }, true},
		{"register_auth optional", func(c *Config) { c.Relay.RegisterAuth = "optional" }, false},
		{"register_auth default", func(c *Config) { c.Relay.RegisterAuth = "" }, false},
		{"relay_secret set", func(c *Config) { c.Control.RelaySecret = "official" }, false},
		{"http coordinator", func(c *Config) { c.Control.ServerURL = "http://coord.example.com" }, false},
		{"no coordinator", func(c *Config) { c.Control.ServerURL = "" }, false},
		{"no addr", func(c *Config) { c.Node.Addr = "" }, false},
		{"addr without port", func(c *Config) { c.Node.Addr = "relay.example.com" }, false},
		{"addr port 0", func(c *Config) { c.Node.Addr = "relay.example.com:0" }, false},
		{"addr with fragment", func(c *Config) { c.Node.Addr = "a#b:7000" }, false},
		{"ipv6 addr", func(c *Config) { c.Node.Addr = "[2001:db8::1]:7000" }, true},
		{"public ipv4 addr", func(c *Config) { c.Node.Addr = "198.51.100.10:7000" }, true},
		{"private addr", func(c *Config) { c.Node.Addr = "192.168.1.2:7000" }, false},
		{"loopback addr", func(c *Config) { c.Node.Addr = "127.0.0.1:7000" }, false},
		{"ipv6 loopback addr", func(c *Config) { c.Node.Addr = "[::1]:7000" }, false},
		{"link-local addr", func(c *Config) { c.Node.Addr = "[fe80::1%eth0]:7000" }, false},
		{"ula addr", func(c *Config) { c.Node.Addr = "[fd00::1]:7000" }, false},
		{"cgnat addr", func(c *Config) { c.Node.Addr = "100.64.1.1:7000" }, false},
		{"unspecified addr", func(c *Config) { c.Node.Addr = "0.0.0.0:7000" }, false},
		{"addr host with underscore", func(c *Config) { c.Node.Addr = "my_relay.example.com:7000" }, false},
		{"addr host with space", func(c *Config) { c.Node.Addr = "bad host:7000" }, false},
		{"addr host trailing dot", func(c *Config) { c.Node.Addr = "relay.example.com.:7000" }, false},
		{"unknown mode", func(c *Config) { c.Relay.Mode = "public" }, false},
		{"password in official mode", func(c *Config) { c.Relay.Mode = relayModeOfficial; c.Relay.Password = "pw" }, false},
	} {
		cfg := selfHostedConfig()
		c.mut(cfg)
		if err := cfg.validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
	if !selfHostedConfig().limits().requireRegisteredSrc || defaultConfig().limits().requireRegisteredSrc {
		t.Fatal("requireRegisteredSrc must follow relay.mode")
	}
}

// ── Forwarding (RR3) ─────────────────────────────────────────────────────

func TestSelfHostedWireGuardRequiresRegisteredSender(t *testing.T) {
	f := newSregFixture(t, regAuthRequired)
	f.r.lim.requireRegisteredSrc = true
	f.r.handle(f.reg(idB, tNow), addrB, tNow)

	// A is not registered: dropped.
	frame := wgFrame(idA, idB, 64, 1)
	f.r.handle(frame, addrA, tNow)
	if out := f.w.take(); len(out) != 0 || f.r.stats.dropUnregisteredSrc.Load() != 1 {
		t.Fatalf("unregistered sender forwarded (%d datagrams)", len(out))
	}
	// Unauthenticated 0x01 does not help (register_auth required).
	f.r.handle(encodePacket(typRegister, idA, 0, nil), addrA, tNow)
	f.r.handle(frame, addrA, tNow)
	if len(f.w.take()) != 0 {
		t.Fatal("0x01-registered sender forwarded")
	}

	// A registers with 0x0E: forwarded byte for byte.
	f.r.handle(f.reg(idA, tNow), addrA, tNow)
	f.r.handle(frame, addrA, tNow)
	if out := f.w.take(); len(out) != 1 || out[0].dst != addrB || !bytes.Equal(out[0].b, frame) {
		t.Fatalf("registered sender not forwarded: %+v", out)
	}
	// Claiming A's ID from another address: dropped.
	f.r.handle(frame, addrC, tNow)
	if len(f.w.take()) != 0 || f.r.stats.dropUnregisteredSrc.Load() != 3 {
		t.Fatal("spoofed src_id forwarded")
	}
	// After A's binding expires: dropped again.
	later := tNow.Add(f.r.lim.sessionTTL + time.Second)
	f.r.handle(f.reg(idB, later), addrB, later)
	f.r.handle(frame, addrA, later)
	if len(f.w.take()) != 0 {
		t.Fatal("expired sender forwarded")
	}

	// Relay ping is echoed for anyone (room-relay health checks run before
	// registration).
	ping := encodePacket(typPing, idC, 0, []byte{1, 2, 3, 4})
	f.r.handle(ping, addrC, later)
	if out := f.w.take(); len(out) != 1 || out[0].dst != addrC {
		t.Fatal("ping not echoed to unregistered sender")
	}
}

// ── Coordinator protocol (RR1, RR4, RR6) ─────────────────────────────────

// fakeSelfHostedCoordinator implements the self-hosted relay endpoints of
// ROOM_RELAY_SERVER_3.1.md CR2/CR3, verifying proofs independently of
// relayKeyproofMAC.
type fakeSelfHostedCoordinator struct {
	t *testing.T

	mu         sync.Mutex
	challenges map[string]*ecdh.PrivateKey // challenge_id → server key
	token      string
	regBody    map[string]any
	registers  int
	heartbeats int
	badProofs  int
	peerAuths  []string
	features   []string // reject registration unless these are reported
}

func newFakeSelfHosted(t *testing.T) *fakeSelfHostedCoordinator {
	return &fakeSelfHostedCoordinator{t: t, challenges: map[string]*ecdh.PrivateKey{}}
}

func jsonError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "rejected", "code": code})
}

func (f *fakeSelfHostedCoordinator) bearerOK(r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token != "" && r.Header.Get("Authorization") == "Bearer "+f.token && r.Header.Get("X-Relay-Secret") == ""
}

func (f *fakeSelfHostedCoordinator) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay/self-hosted/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PubKey string `json:"pub_key"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			jsonError(w, 400, "bad_request")
			return
		}
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		var id [16]byte
		_, _ = rand.Read(id[:])
		cid := hex.EncodeToString(id[:])
		f.mu.Lock()
		f.challenges[cid] = k
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge_id": cid,
			"server_pub":   base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
		})
	})
	mux.HandleFunc("POST /relay/self-hosted/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PubKey   string   `json:"pub_key"`
			Features []string `json:"features"`
			Proof    struct {
				ChallengeID string `json:"challenge_id"`
				MAC         string `json:"mac"`
			} `json:"proof"`
		}
		raw, _ := readAllLimited(r, 1<<16)
		var body map[string]any
		if json.Unmarshal(raw, &req) != nil || json.Unmarshal(raw, &body) != nil {
			jsonError(w, 400, "bad_request")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		k := f.challenges[req.Proof.ChallengeID]
		delete(f.challenges, req.Proof.ChallengeID) // single use
		relayPub, _ := base64.StdEncoding.DecodeString(req.PubKey)
		mac, _ := base64.StdEncoding.DecodeString(req.Proof.MAC)
		if k == nil || len(relayPub) != 32 || !hmac.Equal(mac, refKeyproof(f.t, k, relayPub, req.Proof.ChallengeID)) {
			f.badProofs++
			jsonError(w, 401, "key_proof_invalid")
			return
		}
		for _, want := range f.features {
			if !strings.Contains(strings.Join(req.Features, ","), want) {
				jsonError(w, 400, "relay_unsupported")
				return
			}
		}
		var tok [32]byte
		_, _ = rand.Read(tok[:])
		f.token = base64.RawURLEncoding.EncodeToString(tok[:])
		f.regBody = body
		f.registers++
		_ = json.NewEncoder(w).Encode(map[string]any{"relay_id": "self-0123456789abcdef", "token": f.token, "expires_at": time.Now().Add(30 * time.Second).Unix()})
	})
	mux.HandleFunc("POST /relay/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !f.bearerOK(r) {
			jsonError(w, 401, "unauthorized")
			return
		}
		f.mu.Lock()
		f.heartbeats++
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int64{"expires_at": time.Now().Add(30 * time.Second).Unix()})
	})
	mux.HandleFunc("GET /room/{id}/discovery-peers", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.peerAuths = append(f.peerAuths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if !f.bearerOK(r) {
			jsonError(w, 401, "unauthorized")
			return
		}
		if r.PathValue("id") != "space-mine" {
			jsonError(w, 403, "forbidden")
			return
		}
		_, _ = w.Write([]byte(`[{"device_id":"device-a1a1a1a1"}]`))
	})
	mux.HandleFunc("POST /relay/device-keys", func(w http.ResponseWriter, r *http.Request) {
		if !f.bearerOK(r) {
			jsonError(w, 401, "unauthorized")
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	return mux
}

func readAllLimited(r *http.Request, n int64) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(http.MaxBytesReader(nil, r.Body, n))
	return b.Bytes(), err
}

// refKeyproof is the Coordinator-side computation:
// X25519(server_sk, relay_pub), same HKDF/HMAC as the relay.
func refKeyproof(t *testing.T, server *ecdh.PrivateKey, relayPub []byte, cidHex string) []byte {
	cid, err := hex.DecodeString(cidHex)
	if err != nil {
		return nil
	}
	shared, err := server.ECDH(mustX25519Pub(t, [32]byte(relayPub)))
	if err != nil {
		return nil
	}
	info := append(bytes.Clone(relayPub), server.PublicKey().Bytes()...)
	k, err := hkdf.Key(sha256.New, shared, []byte("msst-relay-keyproof-v1"), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte("msst-relay-keyproof-v1"))
	m.Write(cid)
	return m.Sum(nil)
}

func (f *fakeSelfHostedCoordinator) snapshot() (registers, heartbeats, badProofs int, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registers, f.heartbeats, f.badProofs, f.token
}

// restart forgets the registration, like a Coordinator restart.
func (f *fakeSelfHostedCoordinator) restart() {
	f.mu.Lock()
	f.token = ""
	f.mu.Unlock()
}

func testSelfHostedClient(t *testing.T, url, password string) (*controlClient, *relayCreds) {
	cfg := selfHostedConfig()
	cfg.Control.ServerURL = url
	cfg.Control.HeartbeatInterval = 20 * time.Millisecond
	cfg.Relay.Password = password
	creds := newRelayCreds(true, "")
	c := newControlClient(cfg, creds, newSdiscAuth(testKey(t, 0x02)))
	c.retryInitial = 10 * time.Millisecond
	c.retryMax = 40 * time.Millisecond
	return c, creds
}

func runClient(t *testing.T, c *controlClient) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("control client did not stop on cancel")
		}
	}
}

func TestSelfHostedRegisterHeartbeatReregister(t *testing.T) {
	fc := newFakeSelfHosted(t)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	c, creds := testSelfHostedClient(t, srv.URL, "relay secret")
	stop := runClient(t, c)
	defer stop()

	waitFor(t, "heartbeats", func() bool { _, hb, _, _ := fc.snapshot(); return hb >= 2 })
	fc.mu.Lock()
	body := fc.regBody
	fc.mu.Unlock()
	if body["addr"] != "relay.example.com:7000" || body["pub_key"] != c.auth.publicKeyBase64() ||
		body["require_room_password"] != true || len(body["features"].([]any)) != 2 {
		t.Fatalf("registration body = %v", body)
	}
	if _, ok := body["id"]; ok {
		t.Fatal("self-hosted registration must not carry an official relay id")
	}
	// Password verifier vector (relay key 2×32, password "relay secret").
	if v, _ := base64.StdEncoding.DecodeString(body["password_verifier"].(string)); hex.EncodeToString(v) != "7a8ef8ff39824ac7476ecbe76264a5b16cc0376d6e5f805bea3436060f3af9a3" {
		t.Fatalf("password_verifier = %x", v)
	}
	_, _, _, tok := fc.snapshot()
	creds.mu.Lock()
	held := creds.token
	creds.mu.Unlock()
	if held != tok {
		t.Fatal("relay does not hold the issued token")
	}

	// Coordinator restart: heartbeat gets 401 → new challenge and register.
	fc.restart()
	waitFor(t, "re-registration", func() bool { r, _, _, tk := fc.snapshot(); return r >= 2 && tk != "" })
	waitFor(t, "heartbeats after re-registration", func() bool { _, hb, _, _ := fc.snapshot(); return hb >= 4 })
	if _, _, bad, _ := fc.snapshot(); bad != 0 {
		t.Fatalf("%d proofs rejected", bad)
	}
}

func TestSelfHostedNoPasswordOmitsVerifier(t *testing.T) {
	fc := newFakeSelfHosted(t)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	c, _ := testSelfHostedClient(t, srv.URL, "")
	if _, err := c.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if _, ok := fc.regBody["password_verifier"]; ok {
		t.Fatal("password_verifier sent without relay.password")
	}
}

func TestSelfHostedRegisterErrorCode(t *testing.T) {
	fc := newFakeSelfHosted(t)
	fc.features = []string{"sreg2"} // pretend the Coordinator wants more
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	c, creds := testSelfHostedClient(t, srv.URL, "")
	_, err := c.register(context.Background())
	if err == nil || !strings.Contains(err.Error(), "code=relay_unsupported") {
		t.Fatalf("err = %v", err)
	}
	if _, aerr := creds.apply(httptest.NewRequest("GET", "/", nil)); !errors.Is(aerr, errNoToken) {
		t.Fatal("token set after failed registration")
	}
}

func TestSelfHostedFetchersUseToken(t *testing.T) {
	fc := newFakeSelfHosted(t)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	c, creds := testSelfHostedClient(t, srv.URL, "")
	peers := coordinatorPeerFetcher(srv.URL, creds, srv.Client())
	keys := coordinatorKeyFetcher(srv.URL, creds, srv.Client())
	ctx := context.Background()

	// Before registration nothing is sent.
	if _, err := peers(ctx, "space-mine"); !errors.Is(err, errNoToken) {
		t.Fatalf("before registration: %v", err)
	}
	if _, err := keys(ctx, []uint64{idA}); !errors.Is(err, errNoToken) {
		t.Fatalf("before registration: %v", err)
	}
	fc.mu.Lock()
	sent := len(fc.peerAuths)
	fc.mu.Unlock()
	if sent != 0 {
		t.Fatal("request sent without a token")
	}

	if _, err := c.register(ctx); err != nil {
		t.Fatal(err)
	}
	if recs, err := peers(ctx, "space-mine"); err != nil || len(recs) != 1 {
		t.Fatalf("designated room: %v %v", recs, err)
	}
	if _, err := peers(ctx, "space-other"); !errors.Is(err, errRoomForbidden) {
		t.Fatalf("other room: %v", err)
	}
	if _, err := keys(ctx, []uint64{idA}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-creds.reauth:
		t.Fatal("re-registration requested without a 401")
	default:
	}

	// Token revoked (Coordinator restart): 401 → re-registration requested.
	_, _, _, tok := fc.snapshot()
	fc.restart()
	if _, err := keys(ctx, []uint64{idA}); err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("401: %v", err)
	}
	select {
	case <-creds.reauth:
	default:
		t.Fatal("401 did not request re-registration")
	}

	// A 401 for a token that has since been replaced is ignored.
	creds.unauthorized("old-token")
	select {
	case <-creds.reauth:
		t.Fatal("stale 401 requested re-registration")
	default:
	}
}

func TestSelfHostedFetcherReauthTriggersRegister(t *testing.T) {
	fc := newFakeSelfHosted(t)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	c, creds := testSelfHostedClient(t, srv.URL, "")
	c.interval = time.Hour // only the reauth signal can cause re-registration
	stop := runClient(t, c)
	defer stop()
	waitFor(t, "registration", func() bool { r, _, _, _ := fc.snapshot(); return r == 1 })
	waitFor(t, "token", func() bool { _, err := creds.apply(httptest.NewRequest("GET", "/", nil)); return err == nil })

	fc.restart()
	if _, err := coordinatorPeerFetcher(srv.URL, creds, srv.Client())(context.Background(), "space-mine"); err == nil {
		t.Fatal("want 401")
	}
	waitFor(t, "re-registration", func() bool { r, _, _, _ := fc.snapshot(); return r == 2 })
}

func TestRoomCacheForbiddenClearsList(t *testing.T) {
	var forbid bool
	var mu sync.Mutex
	fetch := func(_ context.Context, _ string) ([]peerRecord, error) {
		mu.Lock()
		defer mu.Unlock()
		if forbid {
			return nil, errRoomForbidden
		}
		return []peerRecord{{id: idA}}, nil
	}
	c := newRoomCache(fetch, nil, 16, time.Second, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.run(ctx, time.Second)

	now := time.Now()
	c.peers([]byte("space-x"), now)
	waitFor(t, "list", func() bool { _, ok := c.peers([]byte("space-x"), now); return ok })

	mu.Lock()
	forbid = true
	mu.Unlock()
	later := now.Add(2 * time.Second) // past ttl: refresh
	c.peers([]byte("space-x"), later)
	waitFor(t, "list cleared", func() bool { _, ok := c.peers([]byte("space-x"), later); return !ok })
}

func TestOfficialCredsUnchanged(t *testing.T) {
	creds := newRelayCreds(false, "s3cret")
	req := httptest.NewRequest("GET", "/", nil)
	if _, err := creds.apply(req); err != nil || req.Header.Get("X-Relay-Secret") != "s3cret" || req.Header.Get("Authorization") != "" {
		t.Fatal("official mode must send X-Relay-Secret only")
	}
	creds.unauthorized("")
	select {
	case <-creds.reauth:
		t.Fatal("official mode does not re-register on fetcher 401")
	default:
	}
}

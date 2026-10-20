package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Client-side reference (independent of sdiscAuth.deriveReg) ──────────

func (d *testDevice) regKey(t testing.TB, relayPub [32]byte) [32]byte {
	t.Helper()
	shared, err := d.priv.ECDH(mustX25519Pub(t, relayPub))
	if err != nil {
		t.Fatal(err)
	}
	info := binary.BigEndian.AppendUint64(nil, d.id)
	info = append(info, d.priv.PublicKey().Bytes()...)
	info = append(info, relayPub[:]...)
	okm, err := hkdf.Key(sha256.New, shared, []byte("msst-sreg-v1"), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(okm)
}

// sreg builds a 0x0E packet with the given counter.
func sregPacket(id uint64, key [32]byte, counter uint64) []byte {
	b := encodePacket(typSecureRegister, id, 0, binary.BigEndian.AppendUint64(nil, counter))
	m := hmac.New(sha256.New, key[:])
	m.Write(b)
	return append(b, m.Sum(nil)[:16]...)
}

type fakeRegKeys map[uint64]*regKey

func (f fakeRegKeys) key(id uint64, _ time.Time) (*regKey, bool) {
	k, ok := f[id]
	return k, ok
}

type sregFixture struct {
	r      *relay
	w      *fakeWriter
	auth   *sdiscAuth
	a, b   *testDevice
	ka, kb [32]byte // client-side keys
	ctr    map[uint64]uint64
}

func newSregFixture(t *testing.T, mode regAuthMode) *sregFixture {
	t.Helper()
	f := &sregFixture{auth: newSdiscAuth(testKey(t, 0x77)), ctr: map[uint64]uint64{}}
	f.a = newTestDevice(t, idA, 0x0a, f.auth)
	f.b = newTestDevice(t, idB, 0x0b, f.auth)
	f.ka, f.kb = f.a.regKey(t, f.auth.pub), f.b.regKey(t, f.auth.pub)
	keys := fakeRegKeys{}
	for _, d := range []*testDevice{f.a, f.b} {
		k, err := f.auth.deriveReg(d.id, d.pub())
		if err != nil {
			t.Fatal(err)
		}
		keys[d.id] = k
	}
	lim := authLimits()
	lim.regAuth = mode
	f.r, f.w = newTestRelay(t, lim, nil)
	f.r.regKeys = keys
	return f
}

// reg returns a fresh 0x0E for d.
func (f *sregFixture) reg(id uint64, now time.Time) []byte {
	f.ctr[id] = nextCounter(f.ctr[id], now)
	k := f.ka
	if id == idB {
		k = f.kb
	}
	return sregPacket(id, k, f.ctr[id])
}

// ── Crypto ───────────────────────────────────────────────────────────────

func TestSregDeriveMatchesClientAndIsSeparate(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	d := newTestDevice(t, idA, 0x0a, auth)
	k, err := auth.deriveReg(idA, d.pub())
	if err != nil {
		t.Fatal(err)
	}
	if k.mac != d.regKey(t, auth.pub) {
		t.Fatal("relay and client derived different sreg keys")
	}
	if k.mac == d.c2r || k.mac == d.r2c {
		t.Fatal("sreg key equals an sdisc key (no domain separation)")
	}
	if _, err := auth.deriveReg(idA, [32]byte{}); err == nil {
		t.Fatal("low-order public key accepted")
	}
}

// TestSregVectors pins the wire format; listed in REGISTRATION_AUTH.md.
func TestSregVectors(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x02))
	d := newTestDevice(t, 0xa1b2c3d4, 0x01, auth)
	k := d.regKey(t, auth.pub)
	pkt := sregPacket(d.id, k, 0x0000_0199_0000_0001)
	if got := hex.EncodeToString(k[:]); got != "600586d9b33a5bcb970b6998524c7974ef368a4d2c48d4cdb649fe194840c2cc" {
		t.Errorf("k_reg = %s", got)
	}
	if got := hex.EncodeToString(pkt); got != "4d535354010e0000000000a1b2c3d4000000000000000000000199000000019c3ba1a9cf8c539f28c897fba08e581d" {
		t.Errorf("0x0E = %s", got)
	}
}

// ── Relay behaviour ──────────────────────────────────────────────────────

func TestSecureRegisterBindsAndForwards(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	f.r.handle(f.reg(idB, tNow), addrB, tNow)
	if !f.r.sessions.secureBound(idB, tNow) {
		t.Fatal("0x0E did not create an authenticated binding")
	}
	frame := wgFrame(idA, idB, 64, 1)
	f.r.handle(frame, addrA, tNow)
	if out := f.w.take(); len(out) != 1 || out[0].dst != addrB {
		t.Fatalf("0x0D not delivered to 0x0E-registered device: %+v", out)
	}
	// Keepalive (another 0x0E) from a new address: roaming.
	moved := ap("203.0.113.99:50000")
	f.r.handle(f.reg(idB, tNow.Add(time.Second)), moved, tNow.Add(time.Second))
	if a, _ := f.r.sessions.lookup(idB, tNow.Add(time.Second)); a != moved {
		t.Fatalf("authenticated rebind failed: %s", a)
	}
}

func TestSecureRegisterRejectsForgery(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	f.r.handle(f.reg(idB, tNow), addrB, tNow)
	evil := ap("192.0.2.66:4444")

	tampered := f.reg(idB, tNow)
	tampered[len(tampered)-1] ^= 1
	wrongKey := sregPacket(idB, f.ka, nextCounter(f.ctr[idB], tNow)) // A's key, B's ID
	unknown := sregPacket(0xdddddddd, f.ka, nextCounter(0, tNow))
	short := encodePacket(typSecureRegister, idB, 0, make([]byte, sregPayloadLen-1))
	withDst := f.reg(idB, tNow)
	binary.BigEndian.PutUint64(withDst[15:23], idA)

	for _, p := range [][]byte{tampered, wrongKey, unknown, short, withDst} {
		f.r.handle(p, evil, tNow)
	}
	if a, _ := f.r.sessions.lookup(idB, tNow); a != addrB {
		t.Fatalf("forgery moved B to %s", a)
	}
	s := f.r.stats
	if s.dropRegAuth.Load() != 2 || s.dropRegKeyUnknown.Load() != 1 || s.dropMalformed.Load() != 2 {
		t.Fatalf("counters: auth=%d key_unknown=%d malformed=%d", s.dropRegAuth.Load(), s.dropRegKeyUnknown.Load(), s.dropMalformed.Load())
	}
	// Forgeries consumed no replay state: B's next keepalive is accepted.
	f.r.handle(f.reg(idB, tNow.Add(time.Second)), addrB, tNow.Add(time.Second))
	if s.dropRegReplay.Load() != 0 || s.dropRegAuth.Load() != 2 {
		t.Fatal("genuine keepalive after forgeries rejected")
	}
}

func TestSecureRegisterReplay(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	p1 := f.reg(idB, tNow)
	p2 := f.reg(idB, tNow)
	f.r.handle(p2, addrB, tNow)
	evil := ap("192.0.2.66:4444")
	f.r.handle(p2, evil, tNow.Add(time.Second)) // captured and replayed elsewhere
	f.r.handle(p1, evil, tNow.Add(time.Second)) // older counter
	f.r.handle(sregPacket(idB, f.kb, nextCounter(0, tNow.Add(-time.Minute))), evil, tNow)
	if a, _ := f.r.sessions.lookup(idB, tNow); a != addrB || f.r.stats.dropRegReplay.Load() != 3 {
		t.Fatalf("replay: B at %s, replay drops %d", a, f.r.stats.dropRegReplay.Load())
	}
}

func TestUnauthenticatedRegisterOptional(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	evil := ap("192.0.2.66:4444")

	// Devices that have not upgraded still register with 0x01/0x02.
	f.r.handle(encodePacket(typRegister, idA, 0, nil), addrA, tNow)
	if a, _ := f.r.sessions.lookup(idA, tNow); a != addrA {
		t.Fatal("0x01 refused in optional mode")
	}
	// An authenticated binding cannot be taken over by them.
	f.r.handle(f.reg(idB, tNow), addrB, tNow)
	for _, typ := range []byte{typRegister, typKeepalive} {
		f.r.handle(encodePacket(typ, idB, 0, nil), evil, tNow)
	}
	if a, _ := f.r.sessions.lookup(idB, tNow); a != addrB || f.r.stats.dropUnauthRegister.Load() != 2 {
		t.Fatalf("legacy register hijacked authenticated binding: %s", a)
	}
	// An unauthenticated binding is upgraded by 0x0E.
	f.r.handle(f.reg(idA, tNow), addrA, tNow)
	if !f.r.sessions.secureBound(idA, tNow) {
		t.Fatal("0x0E did not upgrade an unauthenticated binding")
	}
	// After expiry the ID is free again.
	later := tNow.Add(f.r.lim.sessionTTL)
	f.r.handle(encodePacket(typRegister, idB, 0, nil), evil, later)
	if a, _ := f.r.sessions.lookup(idB, later); a != evil {
		t.Fatal("expired authenticated binding still blocks 0x01")
	}
}

func TestUnauthenticatedRegisterRequired(t *testing.T) {
	f := newSregFixture(t, regAuthRequired)
	for _, typ := range []byte{typRegister, typKeepalive} {
		f.r.handle(encodePacket(typ, idA, 0, nil), addrA, tNow)
	}
	if f.r.sessions.len() != 0 || f.r.stats.dropUnauthRegister.Load() != 2 {
		t.Fatal("unauthenticated registration accepted in required mode")
	}
	f.r.handle(f.reg(idA, tNow), addrA, tNow)
	if a, _ := f.r.sessions.lookup(idA, tNow); a != addrA {
		t.Fatal("0x0E refused in required mode")
	}
}

func TestSecureRegisterWithoutCoordinator(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	f.r.regKeys = nil
	f.r.handle(f.reg(idA, tNow), addrA, tNow)
	if f.r.sessions.len() != 0 || f.r.stats.dropRegKeyUnknown.Load() != 1 {
		t.Fatal("0x0E accepted without a key source")
	}
}

func TestSregStateReclaimed(t *testing.T) {
	f := newSregFixture(t, regAuthOptional)
	f.r.handle(f.reg(idA, tNow), addrA, tNow)
	f.r.handle(f.reg(idB, tNow), addrB, tNow)
	if f.r.regReplay.len() != 2 {
		t.Fatalf("replay entries = %d", f.r.regReplay.len())
	}
	f.r.handle([]byte("junk"), addrA, tNow.Add(f.r.lim.sessionTTL))
	if f.r.regReplay.len() != 0 || f.r.sessions.len() != 0 {
		t.Fatal("sreg state not reclaimed")
	}
}

// ── Device key cache ─────────────────────────────────────────────────────

type keyServer struct {
	mu    sync.Mutex
	pubs  map[uint64][32]byte
	fail  bool
	calls [][]uint64
}

func (s *keyServer) fetch(_ context.Context, ids []uint64) (map[uint64][32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, append([]uint64(nil), ids...))
	if s.fail {
		return nil, errors.New("coordinator down")
	}
	out := map[uint64][32]byte{}
	for _, id := range ids {
		if p, ok := s.pubs[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

// drain runs the worker's steps synchronously.
func drainKeys(c *regKeyCache, now time.Time) {
	var batch []uint64
	for {
		select {
		case id := <-c.queue:
			batch = append(batch, id)
			continue
		default:
		}
		break
	}
	if len(batch) == 0 {
		return
	}
	pubs, err := c.fetch(context.Background(), batch)
	var derived map[uint64]*regKey
	if err == nil {
		derived = c.prepare(batch, pubs)
	}
	c.complete(batch, derived, err, now)
}

func TestRegKeyCacheLifecycle(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	a, b := newTestDevice(t, idA, 0x0a, auth), newTestDevice(t, idB, 0x0b, auth)
	srv := &keyServer{pubs: map[uint64][32]byte{idA: a.pub()}}
	c := newRegKeyCache(srv.fetch, auth, 10, 10*time.Minute, time.Hour)

	// Miss schedules exactly one fetch; lookups never block.
	for range 3 {
		if _, ok := c.key(idA, t0); ok {
			t.Fatal("miss returned a key")
		}
	}
	if len(c.queue) != 1 {
		t.Fatalf("queued %d fetches, want 1", len(c.queue))
	}
	drainKeys(c, t0)
	k1, ok := c.key(idA, t0.Add(time.Second))
	if !ok || k1.mac != a.regKey(t, auth.pub) {
		t.Fatal("key not cached after fetch")
	}

	// Unknown ID: negative entry, no refetch before regKeyNegTTL.
	c.key(idB, t0)
	drainKeys(c, t0)
	if _, ok := c.key(idB, t0.Add(time.Second)); ok || len(c.queue) != 0 {
		t.Fatal("unknown device refetched too early")
	}
	srv.pubs[idB] = b.pub() // device registers at the Coordinator
	c.key(idB, t0.Add(regKeyNegTTL))
	drainKeys(c, t0.Add(regKeyNegTTL))
	if _, ok := c.key(idB, t0.Add(regKeyNegTTL)); !ok {
		t.Fatal("device not picked up after negative TTL")
	}

	// Refresh after ttl reuses the derived key while the public key is
	// unchanged.
	at := t0.Add(10 * time.Minute)
	c.key(idA, at)
	drainKeys(c, at)
	if k2, _ := c.key(idA, at); k2 != k1 {
		t.Fatal("unchanged key re-derived")
	}

	// Coordinator outage: keys keep being served until stale.
	srv.fail = true
	at = t0.Add(25 * time.Minute)
	c.key(idA, at)
	drainKeys(c, at)
	if _, ok := c.key(idA, t0.Add(59*time.Minute)); !ok {
		t.Fatal("key dropped during Coordinator outage")
	}
	if _, ok := c.key(idA, at.Add(time.Hour)); ok {
		t.Fatal("stale key served")
	}

	// Device removed at the Coordinator: key revoked on next refresh.
	srv.fail = false
	delete(srv.pubs, idB)
	at = t0.Add(2 * time.Hour)
	c.key(idB, at)
	drainKeys(c, at)
	if _, ok := c.key(idB, at); ok {
		t.Fatal("revoked key still served")
	}

	// Sweep removes idle entries.
	c.sweep(at.Add(2 * time.Hour))
	if len(c.keys) != 0 || len(c.neg) != 0 {
		t.Fatalf("not swept: keys=%d neg=%d", len(c.keys), len(c.neg))
	}
}

func TestRegKeyCacheBounds(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	srv := &keyServer{pubs: map[uint64][32]byte{}}
	c := newRegKeyCache(srv.fetch, auth, 2, time.Minute, time.Hour)

	// Random spoofed IDs: bounded by the queue, never block.
	for i := range 3 * regKeyQueueLen {
		c.key(uint64(i+1), t0)
	}
	if len(c.queue) != regKeyQueueLen || len(c.neg) != regKeyQueueLen {
		t.Fatalf("queue=%d neg=%d, want %d", len(c.queue), len(c.neg), regKeyQueueLen)
	}

	// Known-key cap.
	c = newRegKeyCache(srv.fetch, auth, 2, time.Minute, time.Hour)
	for i := range 4 {
		d := newTestDevice(t, uint64(i+1), byte(i+1), auth)
		srv.pubs[d.id] = d.pub()
		c.key(d.id, t0)
	}
	drainKeys(c, t0)
	if len(c.keys) != 2 {
		t.Fatalf("keys = %d, want cap 2", len(c.keys))
	}
}

func TestRegKeyCacheWorkerBatches(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	srv := &keyServer{pubs: map[uint64][32]byte{}}
	for i := range 300 {
		d := newTestDevice(t, uint64(i+1), byte(i), auth)
		srv.pubs[d.id] = d.pub()
	}
	c := newRegKeyCache(srv.fetch, auth, 1000, time.Minute, time.Hour)
	now := time.Now()
	for id := range srv.pubs {
		c.key(id, now)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { c.run(ctx, time.Second) })
	waitFor(t, "keys fetched", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.keys) == 300
	})
	// Concurrent lookups while the worker runs (race detector).
	for id := range srv.pubs {
		if _, ok := c.key(id, time.Now()); !ok {
			t.Fatalf("key %d missing", id)
		}
	}
	cancel()
	wg.Wait()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.calls) != 2 || len(srv.calls[0]) != regKeyBatch {
		t.Fatalf("batches: %d calls, first %d IDs", len(srv.calls), len(srv.calls[0]))
	}
}

// ── Coordinator fetcher ──────────────────────────────────────────────────

func TestCoordinatorKeyFetcher(t *testing.T) {
	pub := bytes.Repeat([]byte{7}, 32)
	var gotIDs atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/relay/device-keys" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Relay-Secret") != "s3cret" {
			http.Error(w, "invalid relay secret", http.StatusUnauthorized)
			return
		}
		var req struct {
			DeviceIDs []string `json:"device_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotIDs.Store(strings.Join(req.DeviceIDs, ","))
		b64 := base64.StdEncoding.EncodeToString(pub)
		fmt.Fprintf(w, `[{"device_id":"device-a1a1a1a1","pub_key":%q},{"device_id":"device-b2b2b2b2","pub_key":"c2hvcnQ="},{"device_id":"device-eeeeeeee","pub_key":%q}]`, b64, b64)
	}))
	defer srv.Close()

	got, err := coordinatorKeyFetcher(srv.URL+"/", "s3cret", srv.Client())(context.Background(), []uint64{idA, idB})
	if err != nil {
		t.Fatal(err)
	}
	if gotIDs.Load() != "device-a1a1a1a1,device-b2b2b2b2" {
		t.Fatalf("request ids = %v", gotIDs.Load())
	}
	// Bad key for B and an unrequested device are ignored.
	if a, ok := got[idA]; len(got) != 1 || !ok || !bytes.Equal(a[:], pub) {
		t.Fatalf("got %v", got)
	}
	_, err = coordinatorKeyFetcher(srv.URL, "wrong", srv.Client())(context.Background(), []uint64{idA})
	if err == nil || !strings.Contains(err.Error(), "relay_secret") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err = %v", err)
	}
}

// ── Config ───────────────────────────────────────────────────────────────

func TestConfigRegisterAuth(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"default optional", func(c *Config) {}, true},
		{"required without coordinator", func(c *Config) { c.Relay.RegisterAuth = "required" }, false},
		{"required with coordinator", func(c *Config) {
			c.Relay.RegisterAuth = "required"
			c.Control.ServerURL = "https://c.example"
			c.Node = NodeConfig{ID: "r", Region: "x", Addr: "r:1"}
		}, true},
		{"unknown mode", func(c *Config) { c.Relay.RegisterAuth = "off" }, false},
		{"stale below ttl", func(c *Config) { c.Relay.DeviceKeyStaleTTL = time.Minute }, false},
		{"zero cache", func(c *Config) { c.Relay.DeviceKeyMaxEntries = 0 }, false},
	} {
		cfg := defaultConfig()
		c.mut(cfg)
		if err := cfg.validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

// ── End to end ───────────────────────────────────────────────────────────

func TestUDPSecureRegisterEndToEnd(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := newSregFixture(t, regAuthRequired)
	r := newRelay(conn, f.r.lim, nil, &stats{})
	r.regKeys = f.r.regKeys
	done := make(chan struct{})
	go func() { serve(conn, r); close(done) }()
	defer func() { _ = conn.Close(); <-done }()

	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	ca, cb := dial(), dial()
	_, _ = cb.Write(f.reg(idB, time.Now()))
	_, _ = cb.Write(encodePacket(typPing, idB, 0, nil)) // sync: echo after register
	buf := make([]byte, maxDatagram)
	_ = cb.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cb.Read(buf); err != nil {
		t.Fatalf("ping echo: %v", err)
	}
	frame := wgFrame(idA, idB, 1532, 5)
	_, _ = ca.Write(frame)
	n, err := cb.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], frame) {
		t.Fatalf("0x0D after 0x0E registration: n=%d err=%v", n, err)
	}
}

func mustX25519Pub(t testing.TB, b [32]byte) *ecdh.PublicKey {
	t.Helper()
	k, err := ecdh.X25519().NewPublicKey(b[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

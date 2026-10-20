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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── Client-side reference ────────────────────────────────────────────────
//
// testDevice implements the client half of SECURE_DISCOVERY.md
// independently of sdiscAuth.derive, so the tests catch asymmetric
// derivation mistakes.

type testDevice struct {
	id      uint64
	priv    *ecdh.PrivateKey
	c2r     [32]byte
	r2c     [32]byte
	counter uint64
}

func testKey(t testing.TB, seed byte) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestDevice(t testing.TB, id uint64, seed byte, relay *sdiscAuth) *testDevice {
	t.Helper()
	d := &testDevice{id: id, priv: testKey(t, seed)}
	relayPub, err := ecdh.X25519().NewPublicKey(relay.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := d.priv.ECDH(relayPub)
	if err != nil {
		t.Fatal(err)
	}
	info := binary.BigEndian.AppendUint64(nil, id)
	info = append(info, d.priv.PublicKey().Bytes()...)
	info = append(info, relay.pub[:]...)
	okm, err := hkdf.Key(sha256.New, shared, []byte("msst-sdisc-v1"), string(info), 64)
	if err != nil {
		t.Fatal(err)
	}
	copy(d.c2r[:], okm[:32])
	copy(d.r2c[:], okm[32:])
	return d
}

func (d *testDevice) pub() [32]byte { return [32]byte(d.priv.PublicKey().Bytes()) }

// peer returns the relay-side room entry for d.
func (d *testDevice) peer(t testing.TB, relay *sdiscAuth) discPeer {
	t.Helper()
	k, err := relay.derive(d.id, d.pub())
	if err != nil {
		t.Fatal(err)
	}
	return discPeer{id: d.id, keys: k}
}

// packet builds a 0x0A (ip == nil) or 0x0B packet with a fresh counter.
func (d *testDevice) packet(room string, ip []byte, now time.Time) []byte {
	d.counter = nextCounter(d.counter, now)
	return d.packetWithCounter(room, ip, d.counter)
}

func (d *testDevice) packetWithCounter(room string, ip []byte, counter uint64) []byte {
	typ := byte(typSecureDiscoveryRegister)
	if ip != nil {
		typ = typSecureDiscoveryData
	}
	payload := binary.BigEndian.AppendUint64(nil, counter)
	payload = append(payload, byte(len(room)))
	payload = append(payload, room...)
	payload = append(payload, ip...)
	b := encodePacket(typ, d.id, 0, payload)
	m := hmac.New(sha256.New, d.c2r[:])
	m.Write(b)
	return append(b, m.Sum(nil)[:16]...)
}

// openDeliver verifies a 0x0C packet and returns its flags, src_id and IPv4.
func (d *testDevice) openDeliver(t testing.TB, b []byte) (flags byte, src uint64, ip []byte) {
	t.Helper()
	p, err := parsePacket(b)
	if err != nil || p.typ != typSecureDiscoveryDeliver || p.dstID != d.id || len(p.payload) < 8+20+16 {
		t.Fatalf("not a 0x0C for %08x: %x", d.id, b)
	}
	n := len(b) - 16
	m := hmac.New(sha256.New, d.r2c[:])
	m.Write(b[:n])
	if !hmac.Equal(m.Sum(nil)[:16], b[n:]) {
		t.Fatalf("0x0C tag invalid for %08x", d.id)
	}
	return p.flags, p.srcID, b[headerLen+8 : n]
}

type fakeSecureRooms map[string][]discPeer

func (f fakeSecureRooms) peers(roomID []byte, _ time.Time) ([]discPeer, bool) {
	p, ok := f[string(roomID)]
	return p, ok
}

// tNow is a wall-clock-like time; counters encode unix ms.
var tNow = time.UnixMilli(1_760_000_000_000)

func authLimits() relayLimits {
	lim := testLimits()
	lim.authSkew = 30 * time.Second
	return lim
}

type secureFixture struct {
	r       *relay
	w       *fakeWriter
	auth    *sdiscAuth
	a, b, c *testDevice
	rooms   fakeSecureRooms
}

// newSecureFixture: A, B, C are in room with keys; B and C are registered.
func newSecureFixture(t *testing.T) *secureFixture {
	t.Helper()
	return newSecureFixtureLimits(t, authLimits())
}

func newSecureFixtureLimits(t *testing.T, lim relayLimits) *secureFixture {
	t.Helper()
	f := &secureFixture{auth: newSdiscAuth(testKey(t, 0x77))}
	f.a = newTestDevice(t, idA, 0x0a, f.auth)
	f.b = newTestDevice(t, idB, 0x0b, f.auth)
	f.c = newTestDevice(t, idC, 0x0c, f.auth)
	f.rooms = fakeSecureRooms{room: {f.a.peer(t, f.auth), f.b.peer(t, f.auth), f.c.peer(t, f.auth)}}
	f.r, f.w = newTestRelay(t, lim, f.rooms)
	f.r.handle(f.b.packet(room, nil, tNow), addrB, tNow)
	f.r.handle(f.c.packet(room, nil, tNow), addrC, tNow)
	if b, _ := f.r.discSessions.lookup(idB, tNow); b != addrB {
		t.Fatal("setup: secure registration failed")
	}
	if c, _ := f.r.discSessions.lookup(idC, tNow); c != addrC {
		t.Fatal("setup: secure registration failed")
	}
	return f
}

// ── Crypto and parsing ───────────────────────────────────────────────────

func TestSdiscDeriveMatchesClient(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	d := newTestDevice(t, idA, 0x0a, auth)
	k, err := auth.derive(idA, d.pub())
	if err != nil {
		t.Fatal(err)
	}
	if k.c2r != d.c2r || k.r2c != d.r2c || k.c2r == k.r2c {
		t.Fatal("relay and client derived different (or non-directional) keys")
	}
	// Keys are bound to the device ID as well as the key pair.
	k2, _ := auth.derive(idB, d.pub())
	if k2.c2r == k.c2r {
		t.Fatal("device ID not bound into key derivation")
	}
	// Low-order public key (all-zero shared secret) is rejected.
	if _, err := auth.derive(idA, [32]byte{}); err == nil {
		t.Fatal("low-order public key accepted")
	}
}

// TestSdiscVectors pins the wire format for client implementers. The same
// values are listed in SECURE_DISCOVERY.md.
func TestSdiscVectors(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x02))
	d := newTestDevice(t, 0xa1b2c3d4, 0x01, auth)
	pkt := d.packetWithCounter("space-0a1b2c3d", fakeIPv4(20, 0), 0x0000_0199_0000_0001)
	keys, err := auth.derive(d.id, d.pub())
	if err != nil {
		t.Fatal(err)
	}
	// Relay → device: sender 0x00000001 (verified), counter 0x0000019900000002.
	msg := encodePacket(typSecureDiscoveryDeliver, 1, 0, binary.BigEndian.AppendUint64(nil, 0x0000_0199_0000_0002))
	msg[6] = sdiscFlagSenderVerified
	msg = append(msg, fakeIPv4(20, 0)...)
	r := &relay{}
	deliver := r.sealDeliver(msg, d.id, keys)
	got := map[string]string{
		"relay_pub":  hex.EncodeToString(auth.pub[:]),
		"device_pub": hex.EncodeToString(d.priv.PublicKey().Bytes()),
		"c2r":        hex.EncodeToString(d.c2r[:]),
		"r2c":        hex.EncodeToString(d.r2c[:]),
		"0x0B":       hex.EncodeToString(pkt),
		"0x0C":       hex.EncodeToString(deliver),
	}
	want := map[string]string{
		"relay_pub":  "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59",
		"device_pub": "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
		"c2r":        "0eb7f36437a118f7db30875fafb8b74e78d0b7ddf7e2707c3d3360bfc81d8d25",
		"r2c":        "b91f9f3c48fabc3672c47973da68bf80af849fe27d473428ca573b84aea6059f",
		"0x0B":       "4d535354010b0000000000a1b2c3d4000000000000000000000199000000010e73706163652d3061316232633364450000000000000000000000000000000000000001345fd3335882d082471c107a809cf6",
		"0x0C":       "4d535354010c01000000000000000100000000a1b2c3d40000019900000002450000000000000000000000000000000000000014ea364ad6741e5caf670ca30cebf809",
	}
	for k := range want {
		if got[k] != want[k] {
			t.Errorf("%s = %s", k, got[k])
		}
	}
}

func TestParseSecureDiscoveryPayload(t *testing.T) {
	tag := make([]byte, 16)
	mk := func(parts ...[]byte) []byte {
		return bytes.Join(append([][]byte{{0, 0, 0, 0, 0, 0, 0, 9}}, append(parts, tag)...), nil)
	}
	ip := fakeIPv4(20, 0)

	if c, r, p, ok := parseSecureDiscoveryPayload(mk([]byte{3}, []byte("abc"), ip), true); !ok || c != 9 || string(r) != "abc" || !bytes.Equal(p, ip) {
		t.Fatal("valid data payload rejected")
	}
	if _, r, p, ok := parseSecureDiscoveryPayload(mk([]byte{3}, []byte("abc")), false); !ok || string(r) != "abc" || p != nil {
		t.Fatal("valid register payload rejected")
	}
	bad := []struct {
		name   string
		p      []byte
		withIP bool
	}{
		{"short", make([]byte, 23), false},
		{"register trailing bytes", mk([]byte{3}, []byte("abcd")), false},
		{"register empty room", mk([]byte{0}), false},
		{"register bad room char", mk([]byte{3}, []byte("a/c")), false},
		{"data without ip", mk([]byte{3}, []byte("abc")), true},
		{"data ipv6", mk([]byte{3}, []byte("abc"), append([]byte{0x60}, make([]byte, 39)...)), true},
	}
	for _, c := range bad {
		if _, _, _, ok := parseSecureDiscoveryPayload(c.p, c.withIP); ok {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestReplayGuard(t *testing.T) {
	g := newReplayGuard(2, 120*time.Second, 30*time.Second)
	at := func(d time.Duration, seq uint64) uint64 { return uint64(tNow.Add(d).UnixMilli())<<16 | seq }

	cases := []struct {
		id      uint64
		counter uint64
		want    replayResult
	}{
		{1, at(0, 0), replayOK},
		{1, at(0, 0), replayRepeat},            // exact replay
		{1, at(0, 1), replayOK},                // same ms, next sequence
		{1, at(-time.Second, 0), replayRepeat}, // older than last accepted
		{1, at(-31*time.Second, 0), replayStale},
		{1, at(31*time.Second, 0), replayStale}, // clock too far ahead
		{1, at(29*time.Second, 0), replayOK},
		{2, at(0, 0), replayOK},
		{3, at(0, 0), replayFull}, // cap reached: fail closed
	}
	for i, c := range cases {
		if got := g.accept(c.id, c.counter, tNow); got != c.want {
			t.Errorf("case %d: got %v, want %v", i, got, c.want)
		}
	}
	g.sweep(tNow.Add(2 * time.Minute))
	if g.len() != 0 {
		t.Fatalf("not swept: %d", g.len())
	}
}

func TestNextCounterMonotonic(t *testing.T) {
	c := nextCounter(0, tNow)
	if c>>16 != uint64(tNow.UnixMilli()) {
		t.Fatal("counter does not encode time")
	}
	if c2 := nextCounter(c, tNow); c2 != c+1 {
		t.Fatal("same millisecond must increment")
	}
	if c3 := nextCounter(c, tNow.Add(-time.Hour)); c3 <= c {
		t.Fatal("clock step back must not decrease the counter")
	}
}

// ── Forwarding ───────────────────────────────────────────────────────────

func TestSecureDiscoveryFanout(t *testing.T) {
	f := newSecureFixture(t)
	ip := fakeIPv4(48, 1)
	f.r.handle(f.a.packet(room, ip, tNow), addrA, tNow)

	out := f.w.take()
	if len(out) != 2 {
		t.Fatalf("fan-out = %d, want 2", len(out))
	}
	for _, s := range out {
		d := map[netip.AddrPort]*testDevice{addrB: f.b, addrC: f.c}[s.dst]
		if d == nil {
			t.Fatalf("sent to %s", s.dst)
		}
		flags, src, got := d.openDeliver(t, s.b)
		if flags != sdiscFlagSenderVerified || src != idA || !bytes.Equal(got, ip) {
			t.Fatalf("deliver: flags=%x src=%08x ip=%x", flags, src, got)
		}
	}
	if a, _ := f.r.discSessions.lookup(idA, tNow); a != addrA {
		t.Fatal("authenticated data did not bind the sender")
	}
}

func TestSecureDiscoveryRejectsForgery(t *testing.T) {
	f := newSecureFixture(t)
	ip := fakeIPv4(20, 1)
	evil := ap("192.0.2.66:4444")

	good := f.b.packet(room, ip, tNow)
	tampered := bytes.Clone(good)
	tampered[len(tampered)-17] ^= 1 // last IPv4 byte
	wrongKey := f.c.packetWithCounter(room, ip, nextCounter(0, tNow))
	binary.BigEndian.PutUint64(wrongKey[7:15], idB) // C's tag, B's ID
	notMember := newTestDevice(t, 0xdddddddd, 0x0d, f.auth).packet(room, ip, tNow)

	for name, pkt := range map[string][]byte{"tampered": tampered, "wrong key": wrongKey, "not member": notMember} {
		f.r.handle(pkt, evil, tNow)
		if out := f.w.take(); len(out) != 0 {
			t.Fatalf("%s: forwarded", name)
		}
	}
	// Forged secure register from another address does not move B.
	forgedReg := f.c.packetWithCounter(room, nil, nextCounter(0, tNow.Add(time.Second)))
	binary.BigEndian.PutUint64(forgedReg[7:15], idB)
	f.r.handle(forgedReg, evil, tNow)

	if a, _ := f.r.discSessions.lookup(idB, tNow); a != addrB {
		t.Fatalf("forgery rebound B to %s", a)
	}
	if n := f.r.stats.dropAuthFailed.Load(); n != 3 {
		t.Fatalf("auth failures = %d, want 3", n)
	}
	if f.r.stats.dropNotInRoom.Load() != 1 {
		t.Fatal("non-member not counted")
	}
	// Forgeries consumed none of B's state: the genuine packet still passes.
	f.r.handle(good, addrB, tNow)
	if n := len(f.w.take()); n != 1 {
		t.Fatalf("genuine packet after forgeries: forwarded %d, want 1", n)
	}
}

func TestSecureDiscoveryReplay(t *testing.T) {
	f := newSecureFixture(t)
	p1 := f.a.packet(room, fakeIPv4(20, 1), tNow)
	p2 := f.a.packet(room, fakeIPv4(20, 2), tNow)
	f.r.handle(p2, addrA, tNow)
	f.r.handle(p2, addrA, tNow.Add(5*time.Second)) // replay after dedup TTL
	f.r.handle(p1, addrA, tNow)                    // older counter
	stale := f.a.packetWithCounter(room, fakeIPv4(20, 3), nextCounter(0, tNow.Add(-time.Minute)))
	f.r.handle(stale, addrA, tNow)
	if n := len(f.w.take()); n != 2 {
		t.Fatalf("forwarded %d datagrams, want 2 (first packet only)", n)
	}
	if n := f.r.stats.dropReplay.Load(); n != 3 {
		t.Fatalf("replay drops = %d, want 3", n)
	}
}

func TestSecureDiscoveryRoaming(t *testing.T) {
	f := newSecureFixture(t)
	moved := ap("203.0.113.99:50000")
	f.r.handle(f.b.packet(room, nil, tNow.Add(time.Second)), moved, tNow.Add(time.Second))
	if a, _ := f.r.discSessions.lookup(idB, tNow.Add(time.Second)); a != moved {
		t.Fatalf("authenticated rebind failed: %s", a)
	}
}

func TestSecureBindingResistsRetiredSpoof(t *testing.T) {
	f := newSecureFixture(t)
	evil := ap("192.0.2.66:4444")
	f.r.handle(encodePacket(typRetiredDiscoveryRegister, idB, 0, nil), evil, tNow)
	f.r.handle(encodePacket(typRetiredDiscoveryData, idB, 0, discoveryPayload(room, fakeIPv4(20, 0))), evil, tNow)
	if a, _ := f.r.discSessions.lookup(idB, tNow); a != addrB {
		t.Fatalf("unauthenticated register moved B to %s", a)
	}
	if len(f.w.take()) != 0 || f.r.stats.dropRetired.Load() != 2 {
		t.Fatal("unauthenticated discovery not dropped")
	}
}

func TestSecureDiscoveryRecipientsNeedKeys(t *testing.T) {
	f := newSecureFixture(t)
	// D is listed without a key (it never authenticated); it cannot have a
	// discovery binding and receives nothing.
	f.rooms[room] = append(f.rooms[room], discPeer{id: 0xdddddddd})
	ip := fakeIPv4(20, 1)
	f.r.handle(f.a.packet(room, ip, tNow), addrA, tNow)
	out := f.w.take()
	if len(out) != 2 {
		t.Fatalf("fan-out = %d, want 2", len(out))
	}
	for _, s := range out {
		if s.b[6]&sdiscFlagSenderVerified == 0 || bytes.Equal(s.b, ip) {
			t.Fatal("delivery without verified flag, or bare IPv4")
		}
	}

	// A recipient whose key disappeared from the list gets nothing.
	f.rooms[room][2] = discPeer{id: idC}
	f.r.handle(f.a.packet(room, fakeIPv4(20, 3), tNow), addrA, tNow)
	for _, s := range f.w.take() {
		if s.dst == addrC {
			t.Fatal("recipient without key received a packet")
		}
	}
}

func TestSecureDiscoveryMisc(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	a := newTestDevice(t, idA, 0x0a, auth)
	r, _ := newTestRelay(t, authLimits(), fakeSecureRooms{room: {{id: idA}}})
	// Member without a key cannot authenticate.
	r.handle(a.packet(room, nil, tNow), addrA, tNow)
	// Non-zero dst_id is malformed.
	pkt := a.packet(room, nil, tNow)
	binary.BigEndian.PutUint64(pkt[15:23], idB)
	r.handle(pkt, addrA, tNow)
	// Unknown room.
	r.handle(a.packet("space-other", nil, tNow), addrA, tNow)
	// Invalid sender ID.
	bad := a.packet(room, nil, tNow)
	binary.BigEndian.PutUint64(bad[7:15], 0)
	r.handle(bad, addrA, tNow)
	if r.stats.dropAuthFailed.Load() != 1 || r.stats.dropMalformed.Load() != 2 || r.stats.dropRoomUnknown.Load() != 1 {
		t.Fatalf("counters: auth=%d malformed=%d room=%d",
			r.stats.dropAuthFailed.Load(), r.stats.dropMalformed.Load(), r.stats.dropRoomUnknown.Load())
	}
	if r.discSessions.len() != 0 {
		t.Fatal("rejected packets created bindings")
	}
}

func TestSecureStateReclaimed(t *testing.T) {
	f := newSecureFixture(t)
	if f.r.discReplay.len() != 2 {
		t.Fatalf("replay entries = %d", f.r.discReplay.len())
	}
	f.r.handle([]byte("junk"), addrA, tNow.Add(f.r.lim.discSessionTTL))
	if f.r.discReplay.len() != 0 || f.r.discSessions.len() != 0 {
		t.Fatal("secure discovery state not reclaimed")
	}
}

// ── Room cache, Coordinator, key file, config ────────────────────────────

func TestRoomCachePrepareKeys(t *testing.T) {
	auth := newSdiscAuth(testKey(t, 0x77))
	a, b := newTestDevice(t, idA, 0x0a, auth), newTestDevice(t, idB, 0x0b, auth)
	c := newRoomCache(nil, auth, 10, time.Second, 10*time.Second)
	c.peers([]byte(room), t0) // create entry

	l1 := c.prepare(room, []peerRecord{{id: idA, pub: a.pub(), hasPub: true}, {id: idB}, {id: idC, hasPub: true}})
	if l1[0].keys == nil || l1[0].keys.c2r != a.c2r || l1[1].keys != nil || l1[2].keys != nil {
		t.Fatalf("prepare: %+v", l1)
	}
	c.complete(room, l1, nil, t0)

	// Unchanged key: reused without X25519; changed key: re-derived.
	l2 := c.prepare(room, []peerRecord{{id: idA, pub: a.pub(), hasPub: true}, {id: idB, pub: b.pub(), hasPub: true}})
	if l2[0].keys != l1[0].keys || l2[1].keys == nil || l2[1].keys.c2r != b.c2r {
		t.Fatal("key reuse / derivation wrong")
	}
	l3 := c.prepare(room, []peerRecord{{id: idA, pub: b.pub(), hasPub: true}})
	if l3[0].keys == l1[0].keys {
		t.Fatal("stale key reused after public key change")
	}

	// Auth off: no keys at all.
	off := newRoomCache(nil, nil, 10, time.Second, 10*time.Second)
	if l := off.prepare(room, []peerRecord{{id: idA, pub: a.pub(), hasPub: true}}); l[0].keys != nil {
		t.Fatal("keys derived with auth off")
	}
}

func TestCoordinatorPeerFetcherPubKey(t *testing.T) {
	pub := bytes.Repeat([]byte{7}, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"device_id":"device-a1b2c3d4","pub_key":%q},{"device_id":"device-00000002","pub_key":"c2hvcnQ="},{"device_id":"device-00000003","pub_key":"!!"}]`,
			base64.StdEncoding.EncodeToString(pub))
	}))
	defer srv.Close()
	recs, err := coordinatorPeerFetcher(srv.URL, "", srv.Client())(context.Background(), room)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || !recs[0].hasPub || !bytes.Equal(recs[0].pub[:], pub) || recs[1].hasPub || recs[2].hasPub {
		t.Fatalf("recs = %+v", recs)
	}
}

func TestRelayKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.key")
	k1, err := loadOrCreateRelayKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o", fi.Mode().Perm())
	}
	k2, err := loadOrCreateRelayKey(path)
	if err != nil || !k1.Equal(k2) {
		t.Fatal("key not stable across reloads")
	}
	const garbage = "not-a-key-but-secret-looking"
	_ = os.WriteFile(path, []byte(garbage), 0o600)
	if _, err := loadOrCreateRelayKey(path); err == nil || strings.Contains(err.Error(), garbage) {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigAuth(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"default", func(c *Config) {}, true},
		{"empty auth", func(c *Config) { c.Discovery.Auth = "" }, true},
		{"off retired", func(c *Config) { c.Discovery.Auth = "off" }, false},
		{"optional retired", func(c *Config) { c.Discovery.Auth = "optional" }, false},
		{"no key file", func(c *Config) { c.Discovery.AuthKeyFile = "" }, false},
		{"no key file, discovery off", func(c *Config) { c.Discovery.AuthKeyFile, c.Discovery.Enabled = "", false }, false}, // sreg needs it too
		{"zero skew", func(c *Config) { c.Discovery.AuthMaxClockSkew = 0 }, false},
		{"skew vs ttl", func(c *Config) { c.Discovery.AuthMaxClockSkew = 61 * time.Second }, false},
		{"deprecated require_sender_in_room", func(c *Config) { c.Discovery.RequireSenderInRoom = false }, true},
	} {
		cfg := defaultConfig()
		c.mut(cfg)
		if err := cfg.validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
	if defaultConfig().Discovery.Auth != "required" {
		t.Fatal("default auth must be required")
	}
}

func TestControlReportsPubKey(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	c := testControlClient(srv.URL, "")
	if err := c.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["pub_key"]; ok {
		t.Fatal("pub_key sent with auth off")
	}
	c.pubKey = "cHVi"
	_ = c.register(context.Background())
	if body["pub_key"] != "cHVi" || fmt.Sprint(body["features"]) != "[sdisc1 sreg1]" {
		t.Fatalf("body = %v", body)
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────────

func BenchmarkSecureDiscoveryFanout(b *testing.B) {
	auth := newSdiscAuth(testKey(b, 0x77))
	sender := newTestDevice(b, 1, 1, auth)
	peers := []discPeer{sender.peer(b, auth)}
	r := newRelay(discardWriter{}, authLimits(), nil, &stats{})
	const recipients = 32
	for i := range recipients {
		d := newTestDevice(b, uint64(i+2), byte(i+2), auth)
		peers = append(peers, d.peer(b, auth))
		r.rooms = fakeSecureRooms{room: peers}
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 2)}), 21032)
		r.handle(d.packet(room, nil, tNow), addr, tNow)
	}
	r.lim.discSenderRate, r.lim.discSenderBurst = 1e12, 1<<30
	r.discSender = newKeyedLimiter(10, 1e12, 1<<30)
	r.discIngress = newTokenBucket(1e12, 1<<30)
	r.discEgress = newTokenBucket(1e12, 1<<30)
	ip := fakeIPv4(300, 0)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		binary.BigEndian.PutUint32(ip[12:], uint32(i)) // defeat dedup
		r.handle(sender.packet(room, ip, tNow), ap("192.0.2.1:21032"), tNow)
	}
}

package main

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type sent struct {
	b   []byte
	dst netip.AddrPort
}

type fakeWriter struct {
	out []sent
	err error
}

func (w *fakeWriter) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.out = append(w.out, sent{bytes.Clone(b), addr})
	return len(b), nil
}

func (w *fakeWriter) take() []sent { o := w.out; w.out = nil; return o }

// fakeRooms lists room members without keys (legacy Coordinator).
type fakeRooms map[string][]uint64

func (f fakeRooms) peers(roomID []byte, _ time.Time) ([]discPeer, bool) {
	ids, ok := f[string(roomID)]
	if !ok {
		return nil, false
	}
	list := make([]discPeer, len(ids))
	for i, id := range ids {
		list[i] = discPeer{id: id}
	}
	return list, true
}

// testLimits are the default limits, but with register_auth optional: most
// tests register with plain 0x01 (forwarding doesn't depend on how a
// binding was made); sreg_test.go covers required mode.
func testLimits() relayLimits {
	lim := defaultConfig().limits()
	lim.regAuth = regAuthOptional
	return lim
}

func newTestRelay(t *testing.T, lim relayLimits, rooms roomPeerLookup) (*relay, *fakeWriter) {
	t.Helper()
	w := &fakeWriter{}
	return newRelay(w, lim, rooms, &stats{}), w
}

const (
	idA = 0xa1a1a1a1
	idB = 0xb2b2b2b2
	idC = 0xc3c3c3c3
)

var (
	addrA = ap("198.51.100.1:21031")
	addrB = ap("203.0.113.2:40000")
	addrC = ap("192.0.2.3:21031")
)

// wgFrame is a 0x0D frame carrying an n-byte WireGuard-sized payload.
func wgFrame(src, dst uint64, n int, fill byte) []byte {
	return encodePacket(typWireGuard, src, dst, bytes.Repeat([]byte{fill}, n))
}

func TestWireGuardForwardedVerbatim(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	// Handshake initiation size and a full 1500-MTU transport message.
	for _, n := range []int{148, 1500 + 32} {
		f := wgFrame(idA, idB, n, 7)
		r.handle(f, addrA, t0)
		out := w.take()
		if len(out) != 1 || out[0].dst != addrB || !bytes.Equal(out[0].b, f) {
			t.Fatalf("%d-byte payload: want whole frame to B, got %d datagrams", n, len(out))
		}
	}
	if r.stats.dataForwarded.Load() != 2 {
		t.Fatal("counter not incremented")
	}
}

func TestWireGuardSenderNeedNotBeRegistered(t *testing.T) {
	// Clients send through the destination's relay, so an unregistered
	// sender is legitimate.
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typKeepalive, idB, 0, nil), addrB, t0)
	r.handle(wgFrame(idA, idB, 32, 0), addrC, t0)
	if len(w.take()) != 1 {
		t.Fatal("frame from unregistered sender dropped")
	}
}

func TestWireGuardDrops(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	cases := []struct {
		name string
		pkt  []byte
		src  netip.AddrPort
	}{
		{"unknown dst", wgFrame(idA, idC, 32, 0), addrA},
		{"shorter than any WireGuard message", wgFrame(idA, idB, minWireGuardLen-1, 0), addrA},
		{"loop to self", wgFrame(idB, idB, 32, 0), addrB},
		{"bad version", append([]byte("MSST\x02"), make([]byte, 60)...), addrA},
		{"bad magic", append([]byte("XSST\x01\x0d"), make([]byte, 60)...), addrA},
		{"truncated", wgFrame(idA, idB, 32, 0)[:10], addrA},
		{"unknown type", encodePacket(0x7f, idA, idB, fakeIPv4(20, 0)), addrA},
	}
	for _, c := range cases {
		r.handle(c.pkt, c.src, t0)
		if out := w.take(); len(out) != 0 {
			t.Errorf("%s: forwarded %+v", c.name, out)
		}
	}
	s := r.stats
	if s.dropUnknownDst.Load() != 1 || s.dropLoop.Load() != 1 || s.dropVersion.Load() != 1 ||
		s.dropUnknownType.Load() != 1 || s.dropMalformed.Load() != 3 {
		t.Fatalf("unexpected drop counters: unknown_dst=%d loop=%d version=%d type=%d malformed=%d",
			s.dropUnknownDst.Load(), s.dropLoop.Load(), s.dropVersion.Load(), s.dropUnknownType.Load(), s.dropMalformed.Load())
	}
}

func TestRetiredTypesDropped(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), fakeRooms{room: {idA, idB}})
	r.handle(encodePacket(typRegister, idA, 0, nil), addrA, t0)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	probe := make([]byte, 12) // seq(4) + timestamp_ms(8)

	// 0x03 (3.0.x punch) no longer registers: it cannot move B.
	r.handle(encodePacket(typRetiredPunch, idB, 0, nil), addrC, t0)
	// Plaintext data (0x04) is no longer forwarded in any form.
	r.handle(encodePacket(typRetiredData, idA, idB, fakeIPv4(20, 0)), addrA, t0)
	// P2P ping/pong (0x06/0x07) between registered devices is not relayed:
	// clients measure the relay path inside the tunnel (0x0D).
	r.handle(encodePacket(typRetiredP2PPing, idA, idB, probe), addrA, t0)
	r.handle(encodePacket(typRetiredP2PPong, idB, idA, probe), addrB, t0)
	// Unauthenticated discovery (0x08/0x09) creates no binding and is not
	// fanned out, so it can neither hijack nor inject.
	r.handle(encodePacket(typRetiredDiscoveryRegister, idB, 0, nil), addrC, t0)
	r.handle(encodePacket(typRetiredDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 0))), addrA, t0)
	if len(w.take()) != 0 || r.discSessions.len() != 0 || r.stats.dropRetired.Load() != 6 {
		t.Fatalf("retired types handled: disc_sessions=%d retired=%d", r.discSessions.len(), r.stats.dropRetired.Load())
	}
	if b, _ := r.sessions.lookup(idB, t0); b != addrB || r.stats.rebinds.Load() != 0 {
		t.Fatalf("0x03 moved a binding to %s", b)
	}
}

func TestExpiredSessionNotUsed(t *testing.T) {
	lim := testLimits()
	r, w := newTestRelay(t, lim, nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	late := t0.Add(lim.sessionTTL)
	r.handle(wgFrame(idA, idB, 32, 0), addrA, late)
	if len(w.take()) != 0 {
		t.Fatal("forwarded through expired binding")
	}
	// Maintenance removes it and updates the gauge.
	r.maintain(late)
	if r.sessions.len() != 0 || r.stats.sessions.Load() != 0 {
		t.Fatal("expired session not swept")
	}
}

func TestRebindDeliversOnlyToNewAddress(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	moved := ap("203.0.113.2:40001") // NAT rebinding
	r.handle(encodePacket(typKeepalive, idB, 0, nil), moved, t0.Add(time.Second))
	r.handle(wgFrame(idA, idB, 32, 0), addrA, t0.Add(time.Second))
	out := w.take()
	if len(out) != 1 || out[0].dst != moved {
		t.Fatalf("want delivery to rebound address only, got %+v", out)
	}
	if r.stats.rebinds.Load() != 1 {
		t.Fatal("rebind not counted")
	}
}

func TestRegistrationValidation(t *testing.T) {
	lim := testLimits()
	lim.maxSessions = 2
	r, _ := newTestRelay(t, lim, nil)

	r.handle(encodePacket(typRegister, 0, 0, nil), addrA, t0)             // zero ID
	r.handle(encodePacket(typRegister, 1<<40, 0, nil), addrA, t0)         // > 32 bits
	r.handle(encodePacket(typRegister, idA, 0, nil), ap("0.0.0.0:1"), t0) // bad address
	if r.sessions.len() != 0 || r.stats.invalidRegistrant.Load() != 3 {
		t.Fatalf("invalid registrations stored: len=%d invalid=%d", r.sessions.len(), r.stats.invalidRegistrant.Load())
	}

	r.handle(encodePacket(typRegister, idA, 0, nil), addrA, t0)
	r.handle(encodePacket(typKeepalive, idB, 0, nil), addrB, t0) // keepalive also registers
	r.handle(encodePacket(typRegister, idC, 0, nil), addrC, t0)
	if r.sessions.len() != 2 || r.stats.sessionsFull.Load() != 1 {
		t.Fatalf("capacity not enforced: len=%d full=%d", r.sessions.len(), r.stats.sessionsFull.Load())
	}
}

func TestPingEcho(t *testing.T) {
	lim := testLimits()
	lim.pingRate, lim.pingBurst = 1, 2
	r, w := newTestRelay(t, lim, nil)

	ping := encodePacket(typPing, idA, 0, nil)
	r.handle(ping, addrA, t0)
	out := w.take()
	if len(out) != 1 || out[0].dst != addrA || !bytes.Equal(out[0].b, ping) {
		t.Fatalf("ping not echoed verbatim: %+v", out)
	}

	// Oversized pings are not reflected.
	r.handle(encodePacket(typPing, idA, 0, make([]byte, maxPingEchoLen)), addrA, t0)
	if len(w.take()) != 0 {
		t.Fatal("oversized ping echoed")
	}
	// Rate limit.
	r.handle(ping, addrA, t0)
	r.handle(ping, addrA, t0)
	if n := len(w.take()); n != 1 {
		t.Fatalf("rate limit: echoed %d, want 1", n)
	}
}

func TestSendErrorKeepsSession(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	w.err = errors.New("network is unreachable")
	r.handle(wgFrame(idA, idB, 32, 0), addrA, t0)
	if r.stats.sendErrors.Load() != 1 || r.stats.dataForwarded.Load() != 0 {
		t.Fatal("send error not accounted")
	}
	if _, ok := r.sessions.lookup(idB, t0); !ok {
		t.Fatal("transient send error removed session")
	}
}

// ── Discovery (limits and lifecycle; authentication is in sdisc_test.go) ──

const room = "space-0a1b2c3d"

func TestDiscoveryDedupAndRateLimits(t *testing.T) {
	f := newSecureFixture(t)
	ip := fakeIPv4(20, 3)
	// Same IP packet from the same sender within the dedup TTL (each with a
	// fresh counter, so not a replay).
	f.r.handle(f.a.packet(room, ip, tNow), addrA, tNow)
	f.r.handle(f.a.packet(room, ip, tNow), addrA, tNow.Add(time.Second))
	if n := len(f.w.take()); n != 2 { // one packet × B, C
		t.Fatalf("dedup: sent %d, want 2", n)
	}

	lim := authLimits()
	lim.discSenderRate, lim.discSenderBurst = 1, 2
	f = newSecureFixtureLimits(t, lim)
	for i := range 5 {
		f.r.handle(f.a.packet(room, fakeIPv4(20, byte(i)), tNow), addrA, tNow)
	}
	if n := len(f.w.take()); n != 4 { // 2 packets × B, C
		t.Fatalf("per-sender limit: sent %d, want 4", n)
	}

	// Egress budget counts recipients, so a large room cannot amplify past it.
	lim = authLimits()
	lim.discEgressRate, lim.discEgressBurst = 1, 3
	f = newSecureFixtureLimits(t, lim)
	f.r.handle(f.a.packet(room, fakeIPv4(20, 1), tNow), addrA, tNow)
	f.r.handle(f.a.packet(room, fakeIPv4(20, 2), tNow), addrA, tNow)
	if n := len(f.w.take()); n != 2 {
		t.Fatalf("egress limit: sent %d, want 2 (first packet only)", n)
	}
}

func TestDiscoveryFanoutCap(t *testing.T) {
	lim := authLimits()
	lim.discMaxFanout = 1
	f := newSecureFixtureLimits(t, lim)
	f.r.handle(f.a.packet(room, fakeIPv4(20, 0), tNow), addrA, tNow)
	if n := len(f.w.take()); n != 1 {
		t.Fatalf("fan-out cap: sent %d, want 1", n)
	}
}

func TestDiscoveryDisabled(t *testing.T) {
	lim := authLimits()
	lim.discoveryEnabled = false
	f := newSecureFixture(t) // keys and rooms only
	r, w := newTestRelay(t, lim, f.rooms)
	r.handle(f.a.packet(room, nil, tNow), addrA, tNow)
	r.handle(f.a.packet(room, fakeIPv4(20, 0), tNow), addrA, tNow)
	if len(w.take()) != 0 || r.stats.dropUnknownType.Load() != 2 {
		t.Fatal("discovery handled while disabled")
	}
}

func TestDiscoveryWithoutCoordinator(t *testing.T) {
	f := newSecureFixture(t)
	r, w := newTestRelay(t, authLimits(), nil)
	r.handle(f.a.packet(room, fakeIPv4(20, 0), tNow), addrA, tNow)
	if len(w.take()) != 0 || r.stats.dropRoomUnknown.Load() != 1 {
		t.Fatal("expected room-unknown drop without a Coordinator")
	}
}

func TestMaintenanceBoundsState(t *testing.T) {
	lim := authLimits()
	auth := newSdiscAuth(testKey(t, 0x77))
	devs := make([]*testDevice, 0, 300)
	peers := make([]discPeer, 0, 300)
	for i := range 300 {
		d := newTestDevice(t, uint64(i+1), byte(i), auth)
		devs = append(devs, d)
		peers = append(peers, d.peer(t, auth))
	}
	r, _ := newTestRelay(t, lim, fakeSecureRooms{room: peers})
	for i, d := range devs {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), uint16(1000+i))
		r.handle(encodePacket(typRegister, d.id, 0, nil), src, tNow)
		r.handle(d.packet(room, fakeIPv4(20, byte(i)), tNow), src, tNow)
	}
	if r.sessions.len() != 300 || r.discSessions.len() != 300 || r.discReplay.len() != 300 {
		t.Fatalf("setup: %d %d %d", r.sessions.len(), r.discSessions.len(), r.discReplay.len())
	}
	// Maintenance runs inline from handle once the interval has passed.
	r.handle([]byte("junk"), addrA, tNow.Add(lim.sessionTTL+lim.discSessionTTL))
	if r.sessions.len() != 0 || r.discSessions.len() != 0 || r.discSender.len() != 0 || r.discDedup.len() != 0 || r.discReplay.len() != 0 {
		t.Fatalf("state not reclaimed: sessions=%d disc=%d senders=%d dedup=%d replay=%d",
			r.sessions.len(), r.discSessions.len(), r.discSender.len(), r.discDedup.len(), r.discReplay.len())
	}
}

func BenchmarkForwardData(b *testing.B) {
	w := &discardWriter{}
	r := newRelay(w, testLimits(), nil, &stats{})
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	pkt := wgFrame(idA, idB, 1312, 0) // 1280-MTU transport message
	b.ReportAllocs()
	for b.Loop() {
		r.handle(pkt, addrA, t0)
	}
}

type discardWriter struct{}

func (discardWriter) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) { return len(b), nil }

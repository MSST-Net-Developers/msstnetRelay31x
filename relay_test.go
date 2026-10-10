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

type fakeRooms map[string][]uint64

func (f fakeRooms) peers(roomID []byte, _ time.Time) ([]uint64, bool) {
	p, ok := f[string(roomID)]
	return p, ok
}

func testLimits() relayLimits {
	return defaultConfig().limits()
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

func TestDataForwardStripsHeader(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	ip := fakeIPv4(60, 7)
	r.handle(encodePacket(typData, idA, idB, ip), addrA, t0)

	out := w.take()
	if len(out) != 1 || out[0].dst != addrB || !bytes.Equal(out[0].b, ip) {
		t.Fatalf("want raw payload to B, got %+v", out)
	}
	if r.stats.dataForwarded.Load() != 1 {
		t.Fatal("counter not incremented")
	}
}

func TestDataSenderNeedNotBeRegistered(t *testing.T) {
	// Clients send through the destination's relay, so an unregistered
	// sender is legitimate.
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typKeepalive, idB, 0, nil), addrB, t0)
	r.handle(encodePacket(typData, idA, idB, fakeIPv4(20, 0)), addrC, t0)
	if len(w.take()) != 1 {
		t.Fatal("data from unregistered sender dropped")
	}
}

func TestDataDrops(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	cases := []struct {
		name string
		pkt  []byte
		src  netip.AddrPort
	}{
		{"unknown dst", encodePacket(typData, idA, idC, fakeIPv4(20, 0)), addrA},
		{"empty payload", encodePacket(typData, idA, idB, nil), addrA},
		{"nested MSST header", encodePacket(typData, idA, idB, encodePacket(typData, idA, idC, fakeIPv4(20, 0))), addrA},
		{"loop to self", encodePacket(typData, idB, idB, fakeIPv4(20, 0)), addrB},
		{"bad version", append([]byte("MSST\x02"), make([]byte, 30)...), addrA},
		{"bad magic", append([]byte("XSST\x01\x04"), make([]byte, 30)...), addrA},
		{"truncated", encodePacket(typData, idA, idB, nil)[:10], addrA},
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
		s.dropUnknownType.Load() != 1 || s.dropMalformed.Load() != 4 {
		t.Fatalf("unexpected drop counters: unknown_dst=%d loop=%d version=%d type=%d malformed=%d",
			s.dropUnknownDst.Load(), s.dropLoop.Load(), s.dropVersion.Load(), s.dropUnknownType.Load(), s.dropMalformed.Load())
	}
}

func TestExpiredSessionNotUsed(t *testing.T) {
	lim := testLimits()
	r, w := newTestRelay(t, lim, nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	late := t0.Add(lim.sessionTTL)
	r.handle(encodePacket(typData, idA, idB, fakeIPv4(20, 0)), addrA, late)
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
	r.handle(encodePacket(typData, idA, idB, fakeIPv4(20, 0)), addrA, t0.Add(time.Second))
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
	r.handle(encodePacket(typPunch, idB, 0, nil), addrB, t0) // legacy punch registers
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

func TestP2PProbeForwarding(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idA, 0, nil), addrA, t0)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)

	payload := make([]byte, pingPayloadLen)
	ping := encodePacket(typP2PPing, idA, idB, payload)
	r.handle(ping, addrA, t0)
	out := w.take()
	if len(out) != 1 || out[0].dst != addrB || !bytes.Equal(out[0].b, ping) {
		t.Fatalf("p2p ping not forwarded verbatim: %+v", out)
	}

	// The pong comes from the peer's main socket; that need not be
	// registered here.
	pong := encodePacket(typP2PPong, idB, idA, payload)
	r.handle(pong, addrC, t0)
	out = w.take()
	if len(out) != 1 || out[0].dst != addrA || !bytes.Equal(out[0].b, pong) {
		t.Fatalf("p2p pong not forwarded verbatim: %+v", out)
	}
}

func TestP2PProbeDrops(t *testing.T) {
	lim := testLimits()
	r, w := newTestRelay(t, lim, nil)
	r.handle(encodePacket(typRegister, idA, 0, nil), addrA, t0)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	payload := make([]byte, pingPayloadLen)

	// Spoofed src_id: idA is not bound to addrC.
	r.handle(encodePacket(typP2PPing, idA, idB, payload), addrC, t0)
	// Short payload.
	r.handle(encodePacket(typP2PPing, idA, idB, payload[:4]), addrA, t0)
	// Destination bound to the source address (relay loop).
	r.handle(encodePacket(typP2PPong, idC, idB, payload), addrB, t0)
	if out := w.take(); len(out) != 0 {
		t.Fatalf("forwarded: %+v", out)
	}
	if r.stats.dropUnverifiedSrc.Load() != 1 || r.stats.dropLoop.Load() != 1 {
		t.Fatal("drop counters wrong")
	}

	lim.probeRate, lim.probeBurst = 1, 1
	r, w = newTestRelay(t, lim, nil)
	r.handle(encodePacket(typRegister, idA, 0, nil), addrA, t0)
	for range 3 {
		r.handle(encodePacket(typP2PPong, idB, idA, payload), addrB, t0)
	}
	if n := len(w.take()); n != 1 {
		t.Fatalf("probe rate limit: forwarded %d, want 1", n)
	}
}

func TestSendErrorKeepsSession(t *testing.T) {
	r, w := newTestRelay(t, testLimits(), nil)
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	w.err = errors.New("network is unreachable")
	r.handle(encodePacket(typData, idA, idB, fakeIPv4(20, 0)), addrA, t0)
	if r.stats.sendErrors.Load() != 1 || r.stats.dataForwarded.Load() != 0 {
		t.Fatal("send error not accounted")
	}
	if _, ok := r.sessions.lookup(idB, t0); !ok {
		t.Fatal("transient send error removed session")
	}
}

// ── Discovery ────────────────────────────────────────────────────────────

const room = "space-0a1b2c3d"

func discRelay(t *testing.T, lim relayLimits, rooms roomPeerLookup) (*relay, *fakeWriter) {
	r, w := newTestRelay(t, lim, rooms)
	for id, a := range map[uint64]netip.AddrPort{idA: addrA, idB: addrB, idC: addrC} {
		r.handle(encodePacket(typDiscoveryRegister, id, 0, nil), a, t0)
	}
	return r, w
}

func TestDiscoveryFanout(t *testing.T) {
	r, w := discRelay(t, testLimits(), fakeRooms{room: {idA, idB, idC, 0xdddddddd}})
	ip := fakeIPv4(48, 1)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, ip)), addrA, t0)

	out := w.take()
	got := map[netip.AddrPort]bool{}
	for _, s := range out {
		if !bytes.Equal(s.b, ip) {
			t.Fatalf("discovery egress is not the bare IPv4 packet: %x", s.b)
		}
		got[s.dst] = true
	}
	// Excludes the sender and the unregistered peer.
	if len(out) != 2 || !got[addrB] || !got[addrC] {
		t.Fatalf("fan-out = %+v", out)
	}
	// Discovery registrations are independent of data sessions.
	if r.sessions.len() != 0 {
		t.Fatal("discovery registration created a data session")
	}
}

func TestDiscoveryDrops(t *testing.T) {
	r, w := discRelay(t, testLimits(), fakeRooms{room: {idA, idB}, "space-other": {idB, idC}})
	ip := fakeIPv4(20, 2)

	// Sender not a discovery participant of the claimed room.
	r.handle(encodePacket(typDiscoveryData, idC, 0, discoveryPayload(room, ip)), addrC, t0)
	// Unknown room (no peer list available).
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload("space-unknown", ip)), addrA, t0)
	// Malformed payload.
	r.handle(encodePacket(typDiscoveryData, idA, 0, []byte{3, 'a'}), addrA, t0)
	// Invalid sender ID.
	r.handle(encodePacket(typDiscoveryData, 0, 0, discoveryPayload(room, ip)), addrA, t0)
	if out := w.take(); len(out) != 0 {
		t.Fatalf("forwarded: %+v", out)
	}
	if r.stats.dropNotInRoom.Load() != 1 || r.stats.dropRoomUnknown.Load() != 1 || r.stats.dropMalformed.Load() != 2 {
		t.Fatalf("counters: not_in_room=%d room_unknown=%d malformed=%d",
			r.stats.dropNotInRoom.Load(), r.stats.dropRoomUnknown.Load(), r.stats.dropMalformed.Load())
	}

	// Duplicate suppression (keyed on sender + IP packet, not room).
	ip2 := fakeIPv4(20, 3)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, ip2)), addrA, t0)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, ip2)), addrA, t0.Add(time.Second))
	if n := len(w.take()); n != 1 {
		t.Fatalf("dedup: forwarded %d, want 1", n)
	}
}

func TestDiscoverySenderInRoomOptional(t *testing.T) {
	lim := testLimits()
	lim.discRequireSenderIn = false
	r, w := discRelay(t, lim, fakeRooms{room: {idB}})
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 0))), addrA, t0)
	if n := len(w.take()); n != 1 {
		t.Fatalf("forwarded %d, want 1 (3.0.x behaviour)", n)
	}
}

func TestDiscoveryRateLimits(t *testing.T) {
	lim := testLimits()
	lim.discSenderRate, lim.discSenderBurst = 1, 2
	r, w := discRelay(t, lim, fakeRooms{room: {idA, idB}})
	for i := range 5 {
		r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, byte(i)))), addrA, t0)
	}
	if n := len(w.take()); n != 2 {
		t.Fatalf("per-sender limit: forwarded %d, want 2", n)
	}

	// Egress budget counts recipients, so a large room cannot amplify past it.
	lim = testLimits()
	lim.discEgressRate, lim.discEgressBurst = 1, 3
	r, w = discRelay(t, lim, fakeRooms{room: {idA, idB, idC}})
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 1))), addrA, t0)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 2))), addrA, t0)
	if n := len(w.take()); n != 2 {
		t.Fatalf("egress limit: sent %d, want 2 (first packet only)", n)
	}
}

func TestDiscoveryFanoutCap(t *testing.T) {
	lim := testLimits()
	lim.discMaxFanout = 2
	peers := []uint64{idB, idC, 0xdddddddd, idA} // sender listed last
	r, w := discRelay(t, lim, fakeRooms{room: peers})
	r.handle(encodePacket(typDiscoveryRegister, 0xdddddddd, 0, nil), ap("192.0.2.4:21032"), t0)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 0))), addrA, t0)
	if n := len(w.take()); n != 2 {
		t.Fatalf("fan-out cap: sent %d, want 2", n)
	}
}

func TestDiscoveryDisabled(t *testing.T) {
	lim := testLimits()
	lim.discoveryEnabled = false
	r, w := newTestRelay(t, lim, fakeRooms{room: {idA, idB}})
	r.handle(encodePacket(typDiscoveryRegister, idB, 0, nil), addrB, t0)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 0))), addrA, t0)
	if len(w.take()) != 0 || r.stats.dropUnknownType.Load() != 2 {
		t.Fatal("discovery handled while disabled")
	}
}

func TestDiscoveryWithoutCoordinator(t *testing.T) {
	r, w := discRelay(t, testLimits(), nil)
	r.handle(encodePacket(typDiscoveryData, idA, 0, discoveryPayload(room, fakeIPv4(20, 0))), addrA, t0)
	if len(w.take()) != 0 || r.stats.dropRoomUnknown.Load() != 1 {
		t.Fatal("expected room-unknown drop without a Coordinator")
	}
}

func TestMaintenanceBoundsState(t *testing.T) {
	lim := testLimits()
	r, _ := newTestRelay(t, lim, fakeRooms{})
	for i := range 1000 {
		id := uint64(i + 1)
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), uint16(1000+i))
		r.handle(encodePacket(typRegister, id, 0, nil), src, t0)
		r.handle(encodePacket(typDiscoveryData, id, 0, discoveryPayload(room, fakeIPv4(20, byte(i)))), src, t0)
	}
	if r.sessions.len() != 1000 || r.discSessions.len() != 1000 {
		t.Fatalf("setup: %d %d", r.sessions.len(), r.discSessions.len())
	}
	// Maintenance runs inline from handle once the interval has passed.
	r.handle([]byte("junk"), addrA, t0.Add(lim.sessionTTL+lim.discSessionTTL))
	if r.sessions.len() != 0 || r.discSessions.len() != 0 || r.discSender.len() != 0 || r.discDedup.len() != 0 {
		t.Fatalf("state not reclaimed: sessions=%d disc=%d senders=%d dedup=%d",
			r.sessions.len(), r.discSessions.len(), r.discSender.len(), r.discDedup.len())
	}
}

func BenchmarkForwardData(b *testing.B) {
	w := &discardWriter{}
	r := newRelay(w, testLimits(), nil, &stats{})
	r.handle(encodePacket(typRegister, idB, 0, nil), addrB, t0)
	pkt := encodePacket(typData, idA, idB, fakeIPv4(1400, 0))
	b.ReportAllocs()
	for b.Loop() {
		r.handle(pkt, addrA, t0)
	}
}

type discardWriter struct{}

func (discardWriter) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) { return len(b), nil }

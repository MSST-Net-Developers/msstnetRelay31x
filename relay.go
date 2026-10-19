package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// datagramWriter is the egress side of the UDP socket (*net.UDPConn).
type datagramWriter interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// relayLimits are the resource limits applied by the forwarding core.
type relayLimits struct {
	maxSessions int
	sessionTTL  time.Duration
	pingRate    float64
	pingBurst   int
	probeRate   float64
	probeBurst  int

	discoveryEnabled    bool
	discMaxSessions     int
	discSessionTTL      time.Duration
	discSenderRate      float64
	discSenderBurst     int
	discMaxSenders      int
	discIngressRate     float64
	discIngressBurst    int
	discEgressRate      float64
	discEgressBurst     int
	discDedupTTL        time.Duration
	discDedupMax        int
	discMaxFanout       int
	discRequireSenderIn bool
	discAuth            authMode
	discAuthSkew        time.Duration // accepted |client clock - relay clock|
	maintenanceInterval time.Duration
}

// relay is the packet-forwarding core.
//
// Ownership: every field except stats and rooms is owned by the single UDP
// read-loop goroutine (handle and maintain are only called from it), so the
// hot path takes no locks. Processing stays synchronous to preserve per-flow
// ordering, as in 3.0.x. rooms is internally synchronized; stats is atomic.
type relay struct {
	out   datagramWriter
	lim   relayLimits
	stats *stats
	logs  *logLimiter

	sessions *registry // data path: device ID → main socket address

	pingLimit  *tokenBucket // relay ping echoes (reflection bound)
	probeLimit *tokenBucket // P2P ping/pong forwarding (loop bound)

	discSessions *registry // device ID → discovery socket address
	discSender   *keyedLimiter
	discIngress  *tokenBucket
	discEgress   *tokenBucket
	discDedup    *dedupCache
	rooms        roomPeerLookup // nil: discovery peers unavailable (no Coordinator)
	fanout       []fanoutTarget

	// Secure discovery; nil/zero unless lim.discAuth != authOff.
	discReplay *replayGuard
	txCounter  uint64 // last counter used on a 0x0C packet
	deliverBuf []byte // 0x0C egress scratch

	nextMaintenance time.Time
}

func newRelay(out datagramWriter, lim relayLimits, rooms roomPeerLookup, st *stats) *relay {
	r := &relay{
		out:        out,
		lim:        lim,
		stats:      st,
		logs:       newLogLimiter(10, 50),
		sessions:   newRegistry(lim.maxSessions, lim.sessionTTL),
		pingLimit:  newTokenBucket(lim.pingRate, lim.pingBurst),
		probeLimit: newTokenBucket(lim.probeRate, lim.probeBurst),
		rooms:      rooms,
	}
	if lim.discoveryEnabled {
		r.discSessions = newRegistry(lim.discMaxSessions, lim.discSessionTTL)
		r.discSender = newKeyedLimiter(lim.discMaxSenders, lim.discSenderRate, lim.discSenderBurst)
		r.discIngress = newTokenBucket(lim.discIngressRate, lim.discIngressBurst)
		r.discEgress = newTokenBucket(lim.discEgressRate, lim.discEgressBurst)
		r.discDedup = newDedupCache(lim.discDedupMax, lim.discDedupTTL)
		r.fanout = make([]fanoutTarget, 0, lim.discMaxFanout)
		if lim.discAuth != authOff {
			r.discReplay = newReplayGuard(lim.discMaxSessions, lim.discSessionTTL, lim.discAuthSkew)
			r.deliverBuf = make([]byte, 0, headerLen+sdiscCounterLen+maxDatagram+sdiscTagLen)
		}
	}
	return r
}

// fanoutTarget is one discovery recipient. keys != nil means the recipient
// registered with authentication and receives 0x0C; otherwise it receives the
// bare IPv4 packet (3.0.x).
type fanoutTarget struct {
	id   uint64
	addr netip.AddrPort
	keys *sdiscKeys
}

// handle processes one datagram received from src. buf aliases the receive
// buffer and is not retained.
func (r *relay) handle(buf []byte, src netip.AddrPort, now time.Time) {
	r.stats.rxPackets.Add(1)
	if !now.Before(r.nextMaintenance) {
		r.maintain(now)
	}

	p, err := parsePacket(buf)
	if err != nil {
		if errors.Is(err, errVersion) {
			r.stats.dropVersion.Add(1)
		} else {
			r.stats.dropMalformed.Add(1)
		}
		return
	}

	switch p.typ {
	case typRegister, typKeepalive, typPunch:
		r.register(r.sessions, p.srcID, src, now, "session", false)

	case typData:
		r.forwardData(p, src, now)

	case typPing:
		r.echoPing(p, src, now)

	case typP2PPing:
		// Relay-path RTT probe: the client sends it to its own relay, so the
		// sender must be registered here from this exact address. This keeps
		// the relay from bouncing probes for third parties.
		if !r.sessions.boundTo(p.srcID, src, now) {
			r.stats.dropUnverifiedSrc.Add(1)
			return
		}
		r.forwardProbe(p, src, now)

	case typP2PPong:
		// The pong comes from the peer's main socket, which need not be
		// registered at this relay; it is delivered only to a registered
		// destination.
		r.forwardProbe(p, src, now)

	case typDiscoveryRegister:
		if r.discSessions == nil {
			r.stats.dropUnknownType.Add(1)
			return
		}
		if r.lim.discAuth == authRequired {
			r.stats.dropUnauthenticated.Add(1)
			return
		}
		r.register(r.discSessions, p.srcID, src, now, "discovery", false)

	case typDiscoveryData:
		if r.discSessions == nil {
			r.stats.dropUnknownType.Add(1)
			return
		}
		if r.lim.discAuth == authRequired {
			r.stats.dropUnauthenticated.Add(1)
			return
		}
		r.forwardDiscovery(p, src, now)

	case typSecureDiscoveryRegister, typSecureDiscoveryData:
		if r.discReplay == nil {
			r.stats.dropUnknownType.Add(1)
			return
		}
		r.secureDiscovery(p, src, now)

	default:
		r.stats.dropUnknownType.Add(1)
	}
}

func (r *relay) register(reg *registry, id uint64, src netip.AddrPort, now time.Time, kind string, secure bool) {
	if !validDeviceID(id) {
		r.stats.invalidRegistrant.Add(1)
		return
	}
	switch reg.register(id, src, now, secure) {
	case regNew:
		r.stats.registrations.Add(1)
		r.logs.printf(now, "%s registered: id=%08x addr=%s", kind, id, src)
	case regRebound:
		r.stats.rebinds.Add(1)
		r.logs.printf(now, "%s rebound: id=%08x addr=%s", kind, id, src)
	case regFull:
		r.stats.sessionsFull.Add(1)
		r.logs.printf(now, "%s table full (%d): rejecting id=%08x", kind, reg.max, id)
	case regInvalidAddr:
		r.stats.invalidRegistrant.Add(1)
	case regDenied:
		r.stats.dropUnauthenticated.Add(1)
	case regRefreshed:
	}
}

// forwardData strips the MSST header and sends the bare payload to the
// destination's registered address (3.0.x wire behaviour; the receiving client
// treats a raw IP datagram from the relay as inbound traffic).
//
// The sender is not required to be registered here: clients send data via the
// destination peer's relay, which may differ from their own.
func (r *relay) forwardData(p packet, src netip.AddrPort, now time.Time) {
	if len(p.payload) == 0 {
		r.stats.dropMalformed.Add(1)
		return
	}
	// A payload that is itself an MSST packet would be re-interpreted as a
	// control/data packet by the receiver (or by another relay), letting a
	// sender smuggle headers through the relay. The client never delivers
	// such payloads as IP traffic, so dropping them loses nothing.
	if hasMagic(p.payload) {
		r.stats.dropMalformed.Add(1)
		return
	}
	dst, ok := r.sessions.lookup(p.dstID, now)
	if !ok {
		r.stats.dropUnknownDst.Add(1)
		return
	}
	if dst == src {
		r.stats.dropLoop.Add(1)
		return
	}
	if r.send(p.payload, dst, now) {
		r.stats.dataForwarded.Add(1)
	}
}

// echoPing returns the datagram to its sender for RTT measurement.
func (r *relay) echoPing(p packet, src netip.AddrPort, now time.Time) {
	if len(p.raw) > maxPingEchoLen {
		r.stats.dropMalformed.Add(1)
		return
	}
	if !r.pingLimit.allow(now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	if r.send(p.raw, src, now) {
		r.stats.pingsEchoed.Add(1)
	}
}

// forwardProbe forwards a P2P ping/pong unchanged to the registered
// destination.
func (r *relay) forwardProbe(p packet, src netip.AddrPort, now time.Time) {
	if len(p.payload) < pingPayloadLen {
		r.stats.dropMalformed.Add(1)
		return
	}
	dst, ok := r.sessions.lookup(p.dstID, now)
	if !ok {
		r.stats.dropUnknownDst.Add(1)
		return
	}
	if dst == src {
		r.stats.dropLoop.Add(1)
		return
	}
	// The global budget also terminates forwarding loops between relays
	// that hold spoofed registrations pointing at each other.
	if !r.probeLimit.allow(now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	if r.send(p.raw, dst, now) {
		r.stats.probesForwarded.Add(1)
	}
}

// forwardDiscovery fans a legacy (unauthenticated) discovery IPv4 packet out
// to the other discovery participants of the claimed room that are registered
// at this relay.
func (r *relay) forwardDiscovery(p packet, src netip.AddrPort, now time.Time) {
	roomID, ipPkt, ok := parseDiscoveryPayload(p.payload)
	if !ok || !validDeviceID(p.srcID) {
		r.stats.dropMalformed.Add(1)
		return
	}
	// An ID that authenticated recently cannot be impersonated by
	// unauthenticated packets (optional mode).
	if r.discReplay != nil && r.discSessions.secureBound(p.srcID, now) {
		r.stats.dropUnauthenticated.Add(1)
		return
	}
	// Data packets refresh the discovery binding, as in 3.0.x (this grants
	// nothing beyond what a register packet already does).
	r.register(r.discSessions, p.srcID, src, now, "discovery", false)

	if !r.discIngress.allow(now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	if !r.discDedup.firstSeen(p.srcID, ipPkt, now) {
		r.stats.dropDuplicate.Add(1)
		return
	}
	if !r.discSender.allow(p.srcID, now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	// Only forward from a sender actually bound at this address, so stale or
	// table-full registrations cannot be used to inject into a room.
	if !r.discSessions.boundTo(p.srcID, src, now) {
		r.stats.dropUnverifiedSrc.Add(1)
		return
	}
	if r.rooms == nil {
		r.stats.dropRoomUnknown.Add(1)
		return
	}
	peers, ok := r.rooms.peers(roomID, now)
	if !ok {
		r.stats.dropRoomUnknown.Add(1)
		return
	}
	r.fanOutDiscovery(p.srcID, src, peers, ipPkt, false, r.lim.discRequireSenderIn, now)
}

// secureDiscovery handles authenticated discovery register (0x0A) and data
// (0x0B). Nothing has side effects on relay state until the tag and counter
// have been verified, so forged packets cannot rebind an address, consume a
// device's rate budget or replay-window state.
//
// The global ingress budget is applied after verification: verification is
// one HMAC (the X25519 work happens in the room-cache workers), and charging
// forged packets to the shared budget would let them starve real ones.
func (r *relay) secureDiscovery(p packet, src netip.AddrPort, now time.Time) {
	isData := p.typ == typSecureDiscoveryData
	counter, roomID, ipPkt, ok := parseSecureDiscoveryPayload(p.payload, isData)
	if !ok || !validDeviceID(p.srcID) || p.dstID != 0 {
		r.stats.dropMalformed.Add(1)
		return
	}
	if r.rooms == nil {
		r.stats.dropRoomUnknown.Add(1)
		return
	}
	peers, ok := r.rooms.peers(roomID, now)
	if !ok {
		r.stats.dropRoomUnknown.Add(1)
		return
	}
	// The key comes from the claimed room's list, so authentication also
	// proves the sender is a discovery participant of that room.
	var keys *sdiscKeys
	found := false
	for i := range peers {
		if peers[i].id == p.srcID {
			keys, found = peers[i].keys, true
			break
		}
	}
	if !found {
		r.stats.dropNotInRoom.Add(1)
		return
	}
	if keys == nil || !sdiscVerify(&keys.c2r, p.raw) {
		r.stats.dropAuthFailed.Add(1)
		return
	}
	switch r.discReplay.accept(p.srcID, counter, now) {
	case replayOK:
	case replayFull:
		r.stats.sessionsFull.Add(1)
		return
	default:
		r.stats.dropReplay.Add(1)
		return
	}
	// Authenticated: the sender may (re)bind its discovery address, which
	// also covers NAT rebinding and roaming.
	r.register(r.discSessions, p.srcID, src, now, "discovery", true)
	if !isData {
		return
	}

	if !r.discIngress.allow(now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	if !r.discDedup.firstSeen(p.srcID, ipPkt, now) {
		r.stats.dropDuplicate.Add(1)
		return
	}
	if !r.discSender.allow(p.srcID, now) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	if !r.discSessions.boundTo(p.srcID, src, now) { // table full
		r.stats.dropUnverifiedSrc.Add(1)
		return
	}
	r.fanOutDiscovery(p.srcID, src, peers, ipPkt, true, true, now)
}

// fanOutDiscovery sends ipPkt to the room's other participants registered
// here. verified reports whether senderID was authenticated.
func (r *relay) fanOutDiscovery(senderID uint64, src netip.AddrPort, peers []discPeer, ipPkt []byte, verified, requireSender bool, now time.Time) {
	r.fanout = r.fanout[:0]
	senderInRoom := false
	for _, peer := range peers {
		if peer.id == senderID {
			senderInRoom = true
			continue
		}
		if len(r.fanout) >= r.lim.discMaxFanout {
			continue // keep scanning for the sender
		}
		b, ok := r.discSessions.get(peer.id, now)
		if !ok || b.addr == src {
			continue
		}
		t := fanoutTarget{id: peer.id, addr: b.addr}
		if b.secure {
			// Never downgrade an authenticated recipient to bare IPv4; if
			// its key is no longer listed it gets nothing.
			if peer.keys == nil {
				continue
			}
			t.keys = peer.keys
		}
		r.fanout = append(r.fanout, t)
	}
	if requireSender && !senderInRoom {
		r.stats.dropNotInRoom.Add(1)
		return
	}
	if len(r.fanout) == 0 {
		return
	}
	if !r.discEgress.allowN(now, len(r.fanout)) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	var deliver []byte // built on first secure recipient
	for _, t := range r.fanout {
		out := ipPkt
		if t.keys != nil {
			if deliver == nil {
				deliver = r.buildDeliver(senderID, ipPkt, verified, now)
			}
			out = r.sealDeliver(deliver, t.id, t.keys)
		}
		if r.send(out, t.addr, now) {
			r.stats.discoveryForwarded.Add(1)
		}
	}
}

// buildDeliver writes a 0x0C packet without dst_id and tag into deliverBuf:
//
//	hdr(type 0x0C, flags, src_id=sender, dst_id=recipient) | counter u64 | ipv4 | tag
//
// One counter is used for all recipients of a packet (each has its own key
// and dst_id); the read loop is sequential, so counters increase per
// recipient.
func (r *relay) buildDeliver(senderID uint64, ipPkt []byte, verified bool, now time.Time) []byte {
	var flags byte
	if verified {
		flags = sdiscFlagSenderVerified
	}
	r.txCounter = nextCounter(r.txCounter, now)
	b := append(r.deliverBuf[:0], 'M', 'S', 'S', 'T', protocolVersion, typSecureDiscoveryDeliver, flags)
	b = binary.BigEndian.AppendUint64(b, senderID)
	b = binary.BigEndian.AppendUint64(b, 0) // dst_id, set per recipient
	b = binary.BigEndian.AppendUint64(b, r.txCounter)
	return append(b, ipPkt...)
}

// sealDeliver sets the recipient and appends its tag. msg must come from
// buildDeliver; the returned slice is valid until the next call.
func (r *relay) sealDeliver(msg []byte, dstID uint64, keys *sdiscKeys) []byte {
	binary.BigEndian.PutUint64(msg[15:23], dstID)
	var tag [sdiscTagLen]byte
	sdiscTag(&keys.r2c, msg, &tag)
	return append(msg, tag[:]...)
}

// send hands b to the kernel. A send error does not invalidate the binding:
// unconnected UDP cannot reliably tell a transient error from a dead peer, and
// stale bindings are removed by TTL.
func (r *relay) send(b []byte, dst netip.AddrPort, now time.Time) bool {
	if _, err := r.out.WriteToUDPAddrPort(b, dst); err != nil {
		r.stats.sendErrors.Add(1)
		if !errors.Is(err, net.ErrClosed) {
			r.logs.printf(now, "send to %s: %v", dst, err)
		}
		return false
	}
	return true
}

// maintain expires state owned by the read loop. It runs inline at most once
// per maintenanceInterval.
func (r *relay) maintain(now time.Time) {
	r.nextMaintenance = now.Add(r.lim.maintenanceInterval)
	r.sessions.sweep(now)
	r.stats.sessions.Store(int64(r.sessions.len()))
	if r.discSessions != nil {
		r.discSessions.sweep(now)
		r.discSender.sweep(now)
		r.discDedup.sweep(now)
		if r.discReplay != nil {
			r.discReplay.sweep(now)
		}
		r.stats.discoverySessions.Store(int64(r.discSessions.len()))
	}
	if rc, ok := r.rooms.(*roomCache); ok && rc != nil {
		rc.sweep(now)
	}
}

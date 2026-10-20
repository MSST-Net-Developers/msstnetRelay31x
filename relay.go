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
	regAuth     regAuthMode

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
	authSkew            time.Duration // sdisc/sreg: accepted |client clock - relay clock|
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

	sessions  *registry    // data path: device ID → main socket address
	regKeys   regKeyLookup // sreg device keys; nil: 0x0E unavailable (no Coordinator)
	regReplay *replayGuard // sreg counters

	pingLimit *tokenBucket // relay ping echoes (reflection bound)

	discSessions *registry // device ID → discovery socket address (sdisc-authenticated)
	discSender   *keyedLimiter
	discIngress  *tokenBucket
	discEgress   *tokenBucket
	discDedup    *dedupCache
	rooms        roomPeerLookup // nil: discovery peers unavailable (no Coordinator)
	fanout       []fanoutTarget
	discReplay   *replayGuard
	txCounter    uint64 // last counter used on a 0x0C packet
	deliverBuf   []byte // 0x0C egress scratch

	nextMaintenance time.Time
}

func newRelay(out datagramWriter, lim relayLimits, rooms roomPeerLookup, st *stats) *relay {
	r := &relay{
		out:       out,
		lim:       lim,
		stats:     st,
		logs:      newLogLimiter(10, 50),
		sessions:  newRegistry(lim.maxSessions, lim.sessionTTL),
		pingLimit: newTokenBucket(lim.pingRate, lim.pingBurst),
		regReplay: newReplayGuard(lim.maxSessions, lim.sessionTTL, lim.authSkew),
		rooms:     rooms,
	}
	if lim.discoveryEnabled {
		r.discSessions = newRegistry(lim.discMaxSessions, lim.discSessionTTL)
		r.discSender = newKeyedLimiter(lim.discMaxSenders, lim.discSenderRate, lim.discSenderBurst)
		r.discIngress = newTokenBucket(lim.discIngressRate, lim.discIngressBurst)
		r.discEgress = newTokenBucket(lim.discEgressRate, lim.discEgressBurst)
		r.discDedup = newDedupCache(lim.discDedupMax, lim.discDedupTTL)
		r.fanout = make([]fanoutTarget, 0, lim.discMaxFanout)
		r.discReplay = newReplayGuard(lim.discMaxSessions, lim.discSessionTTL, lim.authSkew)
		r.deliverBuf = make([]byte, 0, headerLen+sdiscCounterLen+maxDatagram+sdiscTagLen)
	}
	return r
}

// fanoutTarget is one discovery recipient.
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
	case typRegister, typKeepalive:
		if r.lim.regAuth == regAuthRequired {
			r.stats.dropUnauthRegister.Add(1)
			return
		}
		r.register(r.sessions, p.srcID, src, now, "session", false)

	case typSecureRegister:
		r.secureRegister(p, src, now)

	case typWireGuard:
		r.forwardWireGuard(p, src, now)

	case typPing:
		r.echoPing(p, src, now)

	case typSecureDiscoveryRegister, typSecureDiscoveryData:
		if r.discSessions == nil {
			r.stats.dropUnknownType.Add(1)
			return
		}
		r.secureDiscovery(p, src, now)

	case typRetiredPunch, typRetiredData, typRetiredP2PPing, typRetiredP2PPong,
		typRetiredDiscoveryRegister, typRetiredDiscoveryData:
		r.stats.dropRetired.Add(1)

	default:
		r.stats.dropUnknownType.Add(1)
	}
}

// register binds id to src. secure reports that the packet was authenticated.
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
		r.stats.dropUnauthRegister.Add(1)
	case regRefreshed:
	}
}

// secureRegister handles an authenticated register/keepalive (0x0E). The
// binding is only touched after the tag and counter are verified, and once
// made it cannot be taken over by unauthenticated 0x01/0x02 while it is live.
func (r *relay) secureRegister(p packet, src netip.AddrPort, now time.Time) {
	if len(p.payload) != sregPayloadLen || p.dstID != 0 || !validDeviceID(p.srcID) {
		r.stats.dropMalformed.Add(1)
		return
	}
	if r.regKeys == nil {
		r.stats.dropRegKeyUnknown.Add(1)
		return
	}
	k, ok := r.regKeys.key(p.srcID, now) // a miss schedules a fetch
	if !ok {
		r.stats.dropRegKeyUnknown.Add(1)
		return
	}
	if !sdiscVerify(&k.mac, p.raw) {
		r.stats.dropRegAuth.Add(1)
		return
	}
	switch r.regReplay.accept(p.srcID, binary.BigEndian.Uint64(p.payload), now) {
	case replayOK:
	case replayFull:
		r.stats.sessionsFull.Add(1)
		return
	default:
		r.stats.dropRegReplay.Add(1)
		return
	}
	r.register(r.sessions, p.srcID, src, now, "session", true)
}

// forwardWireGuard sends the whole datagram, header included and byte for
// byte, to dst_id's registered address. The payload is one WireGuard message,
// opaque to the relay (RELAY_REQUIREMENTS_3.1.md).
//
// The sender is not required to be registered here: clients send via the
// destination's relay, which may differ from their own.
//
// Because the frame is forwarded unchanged, a frame that reaches another
// relay is processed there again. A two-relay loop (spoofed registrations
// pointing R1 and R2 at each other) is cut by the dst == src check; longer
// cycles need spoofed registrations at three or more relays and are not
// detected (see README.md "Trust model").
func (r *relay) forwardWireGuard(p packet, src netip.AddrPort, now time.Time) {
	if len(p.payload) < minWireGuardLen {
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
	if r.send(p.raw, dst, now) {
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
	r.fanOutDiscovery(p.srcID, src, peers, ipPkt, now)
}

// fanOutDiscovery sends ipPkt as 0x0C to the room's other participants
// registered here. The sender has been authenticated and found in peers.
func (r *relay) fanOutDiscovery(senderID uint64, src netip.AddrPort, peers []discPeer, ipPkt []byte, now time.Time) {
	r.fanout = r.fanout[:0]
	for _, peer := range peers {
		if len(r.fanout) >= r.lim.discMaxFanout {
			break
		}
		// A peer without a key cannot have registered here; this also skips
		// one whose key was removed since.
		if peer.id == senderID || peer.keys == nil {
			continue
		}
		if addr, ok := r.discSessions.lookup(peer.id, now); ok && addr != src {
			r.fanout = append(r.fanout, fanoutTarget{id: peer.id, addr: addr, keys: peer.keys})
		}
	}
	if len(r.fanout) == 0 {
		return
	}
	if !r.discEgress.allowN(now, len(r.fanout)) {
		r.stats.dropRateLimited.Add(1)
		return
	}
	msg := r.buildDeliver(senderID, ipPkt, now)
	for _, t := range r.fanout {
		if r.send(r.sealDeliver(msg, t.id, t.keys), t.addr, now) {
			r.stats.discoveryForwarded.Add(1)
		}
	}
}

// buildDeliver writes a 0x0C packet without dst_id and tag into deliverBuf:
//
//	hdr(type 0x0C, flags=sender verified, src_id=sender, dst_id=recipient) | counter u64 | ipv4 | tag
//
// One counter is used for all recipients of a packet (each has its own key
// and dst_id); the read loop is sequential, so counters increase per
// recipient.
func (r *relay) buildDeliver(senderID uint64, ipPkt []byte, now time.Time) []byte {
	r.txCounter = nextCounter(r.txCounter, now)
	b := append(r.deliverBuf[:0], 'M', 'S', 'S', 'T', protocolVersion, typSecureDiscoveryDeliver, sdiscFlagSenderVerified)
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
	r.regReplay.sweep(now)
	if kc, ok := r.regKeys.(*regKeyCache); ok && kc != nil {
		kc.sweep(now)
	}
	r.stats.sessions.Store(int64(r.sessions.len()))
	if r.discSessions != nil {
		r.discSessions.sweep(now)
		r.discSender.sweep(now)
		r.discDedup.sweep(now)
		r.discReplay.sweep(now)
		r.stats.discoverySessions.Store(int64(r.discSessions.len()))
	}
	if rc, ok := r.rooms.(*roomCache); ok && rc != nil {
		rc.sweep(now)
	}
}

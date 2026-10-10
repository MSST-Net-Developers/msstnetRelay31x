package main

import (
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
	fanout       []netip.AddrPort

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
		r.fanout = make([]netip.AddrPort, 0, lim.discMaxFanout)
	}
	return r
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
		r.register(r.sessions, p.srcID, src, now, "session")

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
		r.register(r.discSessions, p.srcID, src, now, "discovery")

	case typDiscoveryData:
		if r.discSessions == nil {
			r.stats.dropUnknownType.Add(1)
			return
		}
		r.forwardDiscovery(p, src, now)

	default:
		r.stats.dropUnknownType.Add(1)
	}
}

func (r *relay) register(reg *registry, id uint64, src netip.AddrPort, now time.Time, kind string) {
	if !validDeviceID(id) {
		r.stats.invalidRegistrant.Add(1)
		return
	}
	switch reg.register(id, src, now) {
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

// forwardDiscovery fans a discovery IPv4 packet out to the other discovery
// participants of the claimed room that are registered at this relay.
func (r *relay) forwardDiscovery(p packet, src netip.AddrPort, now time.Time) {
	roomID, ipPkt, ok := parseDiscoveryPayload(p.payload)
	if !ok || !validDeviceID(p.srcID) {
		r.stats.dropMalformed.Add(1)
		return
	}
	// Data packets refresh the discovery binding, as in 3.0.x (this grants
	// nothing beyond what a register packet already does).
	r.register(r.discSessions, p.srcID, src, now, "discovery")

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

	r.fanout = r.fanout[:0]
	senderInRoom := false
	for _, id := range peers {
		if id == p.srcID {
			senderInRoom = true
			continue
		}
		if len(r.fanout) >= r.lim.discMaxFanout {
			continue // keep scanning for the sender
		}
		if addr, ok := r.discSessions.lookup(id, now); ok && addr != src {
			r.fanout = append(r.fanout, addr)
		}
	}
	if r.lim.discRequireSenderIn && !senderInRoom {
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
	for _, addr := range r.fanout {
		if r.send(ipPkt, addr, now) {
			r.stats.discoveryForwarded.Add(1)
		}
	}
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
		r.stats.discoverySessions.Store(int64(r.discSessions.len()))
	}
	if rc, ok := r.rooms.(*roomCache); ok && rc != nil {
		rc.sweep(now)
	}
}

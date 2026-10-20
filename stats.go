package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// stats holds low-cardinality operational counters. Counters are written by
// the read loop and read by the periodic reporter, hence atomics.
type stats struct {
	rxPackets atomic.Uint64

	// Accepted control traffic.
	registrations     atomic.Uint64 // new bindings (data + discovery)
	rebinds           atomic.Uint64 // binding moved to a different address
	sessionsFull      atomic.Uint64 // registration rejected: table full
	invalidRegistrant atomic.Uint64 // registration rejected: bad ID or address

	// Registration authentication (sreg).
	dropUnauthRegister atomic.Uint64 // 0x01/0x02 refused (required mode, or ID bound by 0x0E)
	dropRegKeyUnknown  atomic.Uint64 // 0x0E: device key not cached (yet)
	dropRegAuth        atomic.Uint64 // 0x0E: bad tag
	dropRegReplay      atomic.Uint64 // 0x0E: counter stale or not increasing

	// Forwarding. "forwarded" means handed to the kernel socket; UDP gives no
	// delivery guarantee beyond that.
	dataForwarded      atomic.Uint64 // WireGuard (0x0D) frames
	pingsEchoed        atomic.Uint64
	discoveryForwarded atomic.Uint64 // per-recipient datagrams
	sendErrors         atomic.Uint64

	// Drops.
	dropMalformed     atomic.Uint64 // framing / field validation
	dropVersion       atomic.Uint64
	dropUnknownType   atomic.Uint64
	dropRetired       atomic.Uint64 // retired types 0x03/0x04/0x06/0x07/0x08/0x09
	dropUnknownDst    atomic.Uint64 // destination not registered or expired
	dropUnverifiedSrc atomic.Uint64 // P2P ping whose src_id is not bound to its source address
	dropLoop          atomic.Uint64 // destination equals source
	dropRateLimited   atomic.Uint64
	dropDuplicate     atomic.Uint64 // discovery dedup
	dropRoomUnknown   atomic.Uint64 // discovery: room peers not (yet) known
	dropNotInRoom     atomic.Uint64 // discovery: sender not registered in room

	// Secure discovery.
	dropAuthFailed atomic.Uint64 // no key for the claimed sender, or bad tag
	dropReplay     atomic.Uint64 // counter stale or not increasing

	sessions          atomic.Int64 // gauge
	discoverySessions atomic.Int64 // gauge
}

func (s *stats) report() {
	log.Printf("stats: sessions=%d discovery_sessions=%d rx=%d data_fwd=%d ping_echo=%d disc_fwd=%d "+
		"send_err=%d reg_new=%d rebind=%d reg_full=%d reg_invalid=%d "+
		"reg_drop{unauth=%d key_unknown=%d auth=%d replay=%d} "+
		"drop{malformed=%d version=%d type=%d retired=%d unknown_dst=%d unverified_src=%d loop=%d rate=%d dup=%d room_unknown=%d not_in_room=%d auth=%d replay=%d}",
		s.sessions.Load(), s.discoverySessions.Load(), s.rxPackets.Load(),
		s.dataForwarded.Load(), s.pingsEchoed.Load(), s.discoveryForwarded.Load(),
		s.sendErrors.Load(), s.registrations.Load(), s.rebinds.Load(), s.sessionsFull.Load(), s.invalidRegistrant.Load(),
		s.dropUnauthRegister.Load(), s.dropRegKeyUnknown.Load(), s.dropRegAuth.Load(), s.dropRegReplay.Load(),
		s.dropMalformed.Load(), s.dropVersion.Load(), s.dropUnknownType.Load(), s.dropRetired.Load(), s.dropUnknownDst.Load(),
		s.dropUnverifiedSrc.Load(), s.dropLoop.Load(), s.dropRateLimited.Load(), s.dropDuplicate.Load(),
		s.dropRoomUnknown.Load(), s.dropNotInRoom.Load(),
		s.dropAuthFailed.Load(), s.dropReplay.Load())
}

// runReporter logs a stats line every interval until ctx is cancelled.
func (s *stats) runReporter(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.report()
		}
	}
}

// logLimiter bounds diagnostic logging that remote parties can trigger, so
// a flood cannot overwhelm the log sink. Owned by the read loop.
type logLimiter struct {
	bucket     *tokenBucket
	suppressed uint64
}

func newLogLimiter(perSec float64, burst int) *logLimiter {
	return &logLimiter{bucket: newTokenBucket(perSec, burst)}
}

func (l *logLimiter) printf(now time.Time, format string, args ...any) {
	if !l.bucket.allow(now) {
		l.suppressed++
		return
	}
	if l.suppressed > 0 {
		log.Printf("(%d log lines suppressed by rate limit)", l.suppressed)
		l.suppressed = 0
	}
	log.Printf(format, args...)
}

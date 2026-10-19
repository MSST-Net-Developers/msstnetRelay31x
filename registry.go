package main

import (
	"net/netip"
	"time"
)

// registry maps device ID → most recently observed UDP source address.
//
// Ownership: a registry is owned by the UDP read-loop goroutine and is not
// safe for concurrent use. Entries expire ttl after the last refresh; expired
// entries are never returned by lookup, even before sweep removes them.
//
// Binding is last-writer-wins, as in 3.0.x: a register/keepalive from a new
// address replaces the old one (needed for NAT rebinding and roaming). The
// protocol has no sender authentication, so this cannot distinguish a roaming
// client from a spoofed registration.
//
// Exception (secure discovery): a binding made by an authenticated packet is
// marked secure, and while it is live, unauthenticated registrations for the
// same ID are refused (regDenied). Authenticated packets may still rebind it.
type registry struct {
	entries map[uint64]binding
	max     int
	ttl     time.Duration
}

type binding struct {
	addr     netip.AddrPort
	lastSeen time.Time
	secure   bool
}

type registerResult uint8

const (
	regNew registerResult = iota
	regRefreshed
	regRebound
	regFull
	regInvalidAddr
	regDenied // unauthenticated registration for a live secure binding
)

func newRegistry(max int, ttl time.Duration) *registry {
	return &registry{entries: make(map[uint64]binding), max: max, ttl: ttl}
}

// validClientAddr rejects source addresses that can never be a legitimate
// client endpoint.
func validClientAddr(a netip.AddrPort) bool {
	if !a.IsValid() || a.Port() == 0 {
		return false
	}
	ip := a.Addr().Unmap()
	return !ip.IsUnspecified() && !ip.IsMulticast() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// register binds id to addr. secure reports that the caller authenticated
// the packet.
func (r *registry) register(id uint64, addr netip.AddrPort, now time.Time, secure bool) registerResult {
	if !validClientAddr(addr) {
		return regInvalidAddr
	}
	old, exists := r.entries[id]
	if exists && now.Sub(old.lastSeen) >= r.ttl {
		exists = false // expired: treat as a fresh registration
	}
	if exists && old.secure && !secure {
		return regDenied
	}
	if !exists && len(r.entries) >= r.max {
		if _, present := r.entries[id]; !present {
			return regFull
		}
	}
	r.entries[id] = binding{addr: addr, lastSeen: now, secure: secure}
	switch {
	case !exists:
		return regNew
	case old.addr != addr:
		return regRebound
	default:
		return regRefreshed
	}
}

// lookup returns the live binding for id.
func (r *registry) lookup(id uint64, now time.Time) (netip.AddrPort, bool) {
	b, ok := r.get(id, now)
	return b.addr, ok
}

func (r *registry) get(id uint64, now time.Time) (binding, bool) {
	b, ok := r.entries[id]
	if !ok || now.Sub(b.lastSeen) >= r.ttl {
		return binding{}, false
	}
	return b, true
}

// secureBound reports whether id has a live authenticated binding.
func (r *registry) secureBound(id uint64, now time.Time) bool {
	b, ok := r.get(id, now)
	return ok && b.secure
}

// boundTo reports whether id is currently registered at exactly addr.
func (r *registry) boundTo(id uint64, addr netip.AddrPort, now time.Time) bool {
	a, ok := r.lookup(id, now)
	return ok && a == addr
}

// sweep deletes expired entries and returns how many were removed.
func (r *registry) sweep(now time.Time) int {
	n := 0
	for id, b := range r.entries {
		if now.Sub(b.lastSeen) >= r.ttl {
			delete(r.entries, id)
			n++
		}
	}
	return n
}

func (r *registry) len() int { return len(r.entries) }

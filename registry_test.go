package main

import (
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestRegistryLifecycle(t *testing.T) {
	r := newRegistry(10, time.Minute)
	a, b := ap("198.51.100.1:5000"), ap("198.51.100.2:6000")

	if got := r.register(1, a, t0, false); got != regNew {
		t.Fatalf("first register = %v", got)
	}
	if got := r.register(1, a, t0.Add(time.Second), false); got != regRefreshed {
		t.Fatalf("refresh = %v", got)
	}
	if got := r.register(1, b, t0.Add(2*time.Second), false); got != regRebound {
		t.Fatalf("rebind = %v", got)
	}
	if addr, ok := r.lookup(1, t0.Add(3*time.Second)); !ok || addr != b {
		t.Fatalf("lookup after rebind = %v %v, want new address only", addr, ok)
	}
	if r.boundTo(1, a, t0.Add(3*time.Second)) {
		t.Fatal("old address still considered bound")
	}

	// Expiry: TTL counts from the last refresh.
	exp := t0.Add(2*time.Second + time.Minute)
	if _, ok := r.lookup(1, exp); ok {
		t.Fatal("expired binding returned")
	}
	if got := r.register(1, b, exp, false); got != regNew {
		t.Fatalf("register after expiry = %v, want regNew", got)
	}
	if n := r.sweep(exp.Add(time.Minute)); n != 1 || r.len() != 0 {
		t.Fatalf("sweep removed %d, len %d", n, r.len())
	}
	// Repeated sweep is a no-op.
	if n := r.sweep(exp.Add(time.Minute)); n != 0 {
		t.Fatalf("second sweep removed %d", n)
	}
}

func TestRegistryCapacity(t *testing.T) {
	r := newRegistry(2, time.Minute)
	a := ap("198.51.100.1:5000")
	r.register(1, a, t0, false)
	r.register(2, a, t0, false)
	if got := r.register(3, a, t0, false); got != regFull {
		t.Fatalf("over capacity = %v", got)
	}
	// Existing entries can still refresh when full.
	if got := r.register(1, a, t0.Add(time.Second), false); got != regRefreshed {
		t.Fatalf("refresh when full = %v", got)
	}
	// An expired-but-unswept entry can be reclaimed by its own ID.
	if got := r.register(2, a, t0.Add(2*time.Minute), false); got != regNew {
		t.Fatalf("reclaim expired = %v", got)
	}
	// After sweeping, new IDs fit again.
	r.sweep(t0.Add(3 * time.Minute))
	if got := r.register(3, a, t0.Add(3*time.Minute), false); got != regNew {
		t.Fatalf("after sweep = %v", got)
	}
}

func TestRegistryRejectsInvalidAddr(t *testing.T) {
	r := newRegistry(10, time.Minute)
	for _, s := range []string{"0.0.0.0:1", "[::]:1", "198.51.100.1:0", "224.0.0.251:5353", "255.255.255.255:9", "[::ffff:0.0.0.0]:1", "[ff02::1]:1"} {
		if got := r.register(1, ap(s), t0, false); got != regInvalidAddr {
			t.Errorf("%s: %v", s, got)
		}
	}
	if r.len() != 0 {
		t.Fatal("invalid address stored")
	}
	if got := r.register(1, ap("[2001:db8::1]:21031"), t0, false); got != regNew {
		t.Fatalf("ipv6 rejected: %v", got)
	}
	if got := r.register(2, ap("[::ffff:198.51.100.1]:21031"), t0, false); got != regNew {
		t.Fatalf("v4-mapped rejected: %v", got)
	}
}

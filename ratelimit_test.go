package main

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(10, 5)
	for i := range 5 {
		if !b.allow(t0) {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if b.allow(t0) {
		t.Fatal("allowed beyond burst")
	}
	if !b.allow(t0.Add(100 * time.Millisecond)) {
		t.Fatal("no refill after 100ms at 10/s")
	}
	// Refill is capped at burst.
	later := t0.Add(time.Hour)
	if !b.allowN(later, 5) || b.allow(later) {
		t.Fatal("refill not capped at burst")
	}
	// allowN never partially consumes.
	b2 := newTokenBucket(1, 3)
	if b2.allowN(t0, 4) || !b2.allowN(t0, 3) {
		t.Fatal("allowN partial consumption")
	}
}

func TestKeyedLimiter(t *testing.T) {
	k := newKeyedLimiter(2, 10, 1)
	if !k.allow(1, t0) || k.allow(1, t0) {
		t.Fatal("per-key burst not enforced")
	}
	if !k.allow(2, t0) {
		t.Fatal("independent key limited")
	}
	if k.allow(3, t0) {
		t.Fatal("new key admitted beyond max tracked keys")
	}
	k.sweep(t0.Add(time.Second))
	if k.len() != 0 {
		t.Fatalf("idle buckets not swept: %d", k.len())
	}
	if !k.allow(3, t0.Add(time.Second)) {
		t.Fatal("key denied after sweep")
	}
}

func TestDedupCache(t *testing.T) {
	d := newDedupCache(2, 3*time.Second)
	pkt := []byte("hello")
	if !d.firstSeen(1, pkt, t0) {
		t.Fatal("first packet treated as dup")
	}
	if d.firstSeen(1, pkt, t0.Add(time.Second)) {
		t.Fatal("dup within ttl forwarded")
	}
	if !d.firstSeen(2, pkt, t0.Add(time.Second)) {
		t.Fatal("same bytes from another sender treated as dup")
	}
	if !d.firstSeen(1, pkt, t0.Add(3*time.Second)) {
		t.Fatal("packet after ttl treated as dup")
	}
	// Full cache: new packets pass but are not recorded.
	if !d.firstSeen(3, pkt, t0.Add(3*time.Second)) || !d.firstSeen(3, pkt, t0.Add(3*time.Second)) {
		t.Fatal("full cache must not drop unseen packets")
	}
	if d.len() > 2 {
		t.Fatalf("dedup grew beyond max: %d", d.len())
	}
	d.sweep(t0.Add(time.Minute))
	if d.len() != 0 {
		t.Fatalf("not swept: %d", d.len())
	}
}

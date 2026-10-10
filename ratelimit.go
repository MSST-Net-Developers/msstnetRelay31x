package main

import (
	"hash/maphash"
	"time"
)

// tokenBucket is a classic token bucket. Not safe for concurrent use; the
// relay's limiters are owned by the read-loop goroutine.
type tokenBucket struct {
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst)}
}

func (b *tokenBucket) refill(now time.Time) {
	if !b.last.IsZero() {
		if dt := now.Sub(b.last).Seconds(); dt > 0 {
			b.tokens += dt * b.rate
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
		}
	}
	b.last = now
}

func (b *tokenBucket) allow(now time.Time) bool { return b.allowN(now, 1) }

// allowN consumes n tokens if available. It never partially consumes.
func (b *tokenBucket) allowN(now time.Time, n int) bool {
	b.refill(now)
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// full reports whether the bucket would be at full burst at now, i.e. it
// carries no state worth keeping.
func (b *tokenBucket) full(now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*b.rate >= b.burst
}

// keyedLimiter keeps one token bucket per key with a hard cap on tracked
// keys. When the cap is reached, unknown keys are denied (fail closed) until
// sweep frees idle buckets. Not safe for concurrent use.
type keyedLimiter struct {
	buckets map[uint64]*tokenBucket
	max     int
	rate    float64
	burst   int
}

func newKeyedLimiter(max int, rate float64, burst int) *keyedLimiter {
	return &keyedLimiter{buckets: make(map[uint64]*tokenBucket), max: max, rate: rate, burst: burst}
}

func (k *keyedLimiter) allow(key uint64, now time.Time) bool {
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.max {
			return false
		}
		b = newTokenBucket(k.rate, k.burst)
		k.buckets[key] = b
	}
	return b.allow(now)
}

// sweep drops buckets that have refilled completely.
func (k *keyedLimiter) sweep(now time.Time) {
	for key, b := range k.buckets {
		if b.full(now) {
			delete(k.buckets, key)
		}
	}
}

func (k *keyedLimiter) len() int { return len(k.buckets) }

// dedupCache remembers packet fingerprints for ttl. Fingerprints use a
// per-process random seed so remote parties cannot craft collisions to
// suppress someone else's packets. Not safe for concurrent use.
type dedupCache struct {
	seed    maphash.Seed
	seen    map[uint64]time.Time
	max     int
	ttl     time.Duration
	scratch [8]byte
}

func newDedupCache(max int, ttl time.Duration) *dedupCache {
	return &dedupCache{seed: maphash.MakeSeed(), seen: make(map[uint64]time.Time), max: max, ttl: ttl}
}

func (d *dedupCache) key(senderID uint64, data []byte) uint64 {
	var h maphash.Hash
	h.SetSeed(d.seed)
	for i := range d.scratch {
		d.scratch[i] = byte(senderID >> (56 - 8*i))
	}
	_, _ = h.Write(d.scratch[:])
	_, _ = h.Write(data)
	return h.Sum64()
}

// firstSeen returns true if (senderID, data) has not been seen within ttl and
// records it. When the cache is full the packet is treated as new but not
// recorded; other limits still bound throughput.
func (d *dedupCache) firstSeen(senderID uint64, data []byte, now time.Time) bool {
	k := d.key(senderID, data)
	if t, ok := d.seen[k]; ok && now.Sub(t) < d.ttl {
		return false
	}
	if len(d.seen) < d.max {
		d.seen[k] = now
	} else if _, ok := d.seen[k]; ok {
		d.seen[k] = now // replacing an expired entry does not grow the map
	}
	return true
}

func (d *dedupCache) sweep(now time.Time) {
	for k, t := range d.seen {
		if now.Sub(t) >= d.ttl {
			delete(d.seen, k)
		}
	}
}

func (d *dedupCache) len() int { return len(d.seen) }

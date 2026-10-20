package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Registration authentication (sreg v1). See REGISTRATION_AUTH.md.
//
// 0x0E replaces register/keepalive (0x01/0x02) for clients that support it:
//
//	hdr(type 0x0E, flags 0, src_id = own ID, dst_id 0) | counter u64 | tag[16]
//
// tag = HMAC-SHA256(k_reg, header ‖ counter)[:16], with
// k_reg = kdf("msst-sreg-v1", device_id, device_pk, 32) (see sdiscAuth.kdf).
// Counters follow the sdisc rules (unix_ms<<16 | seq, strictly increasing,
// fresh within the configured skew).
//
// The relay needs each device's public key. It gets them in batches from the
// Coordinator (POST /relay/device-keys) through regKeyCache, so the read loop
// does only an HMAC and never waits for I/O. The tag cannot cover the source
// address (NAT changes it), so an on-path attacker who sees a 0x0E and
// delivers it first can move the binding until the device's next keepalive;
// off-path attackers cannot.
const (
	typSecureRegister = 0x0E

	sregLabel      = "msst-sreg-v1"
	sregPayloadLen = sdiscCounterLen + sdiscTagLen
)

// regAuthMode controls unauthenticated registration (0x01/0x02).
type regAuthMode uint8

const (
	regAuthOptional regAuthMode = iota // accepted unless the ID has a live authenticated binding
	regAuthRequired                    // dropped
)

func parseRegAuthMode(s string) (regAuthMode, error) {
	switch s {
	case "optional", "":
		return regAuthOptional, nil
	case "required":
		return regAuthRequired, nil
	}
	return 0, fmt.Errorf("unknown mode %q (want optional or required)", s)
}

// deriveReg returns the sreg MAC key shared with a device.
func (a *sdiscAuth) deriveReg(id uint64, devPub [32]byte) (*regKey, error) {
	okm, err := a.kdf(sregLabel, id, devPub, 32)
	if err != nil {
		return nil, err
	}
	k := &regKey{pub: devPub}
	copy(k.mac[:], okm)
	return k, nil
}

// regKey is the sreg key for one device. Immutable once built.
type regKey struct {
	pub [32]byte // device public key it was derived from
	mac [32]byte
}

// regKeyLookup is what the read loop needs from the device key cache.
type regKeyLookup interface {
	// key returns the cached key for id. On a miss it schedules a fetch
	// (if budget allows) and returns false.
	key(id uint64, now time.Time) (*regKey, bool)
}

// deviceKeyFetcher returns the public keys of the given devices. Devices the
// Coordinator does not know are omitted.
type deviceKeyFetcher func(ctx context.Context, ids []uint64) (map[uint64][32]byte, error)

const (
	regKeyBatch     = 256                    // IDs per Coordinator request
	regKeyQueueLen  = 4096                   // pending IDs
	regKeyMinGap    = 100 * time.Millisecond // between requests: ≤ 10 req/s
	regKeyNegTTL    = 10 * time.Second       // retry interval for unknown IDs
	regKeyNegMax    = 4 * regKeyQueueLen     // unknown / in-flight IDs tracked
	maxKeysRespSize = 1 << 20
)

// regKeyCache maps device ID → sreg key, filled by one background worker.
//
// Shared between the read loop (key) and the worker (complete), so guarded by
// mu; no I/O or X25519 work happens while mu is held. Known keys (keys) are
// bounded by max and refreshed after ttl; a key is served for staleTTL after
// its last successful fetch, so a Coordinator outage does not interrupt
// devices that already registered. IDs without a key (pending or unknown to
// the Coordinator) live in neg, bounded by regKeyNegMax; an ID is only added
// there when a fetch can be queued for it, so spoofed random IDs are limited
// by the fetch throughput.
type regKeyCache struct {
	mu       sync.Mutex
	keys     map[uint64]*regKeyEntry
	neg      map[uint64]*negEntry
	max      int
	ttl      time.Duration
	staleTTL time.Duration
	queue    chan uint64
	fetch    deviceKeyFetcher
	auth     *sdiscAuth
	full     bool // last insert refused; logged once per transition
}

type regKeyEntry struct {
	key       *regKey
	fetchedAt time.Time
	attemptAt time.Time
	lastUsed  time.Time
	queued    bool
}

type negEntry struct {
	attemptAt time.Time
	queued    bool
}

func newRegKeyCache(fetch deviceKeyFetcher, auth *sdiscAuth, max int, ttl, staleTTL time.Duration) *regKeyCache {
	return &regKeyCache{
		keys:     make(map[uint64]*regKeyEntry),
		neg:      make(map[uint64]*negEntry),
		max:      max,
		ttl:      ttl,
		staleTTL: staleTTL,
		queue:    make(chan uint64, regKeyQueueLen),
		fetch:    fetch,
		auth:     auth,
	}
}

// enqueue must be called with mu held; it never blocks because all sends
// happen under mu after the length check.
func (c *regKeyCache) enqueue(id uint64) bool {
	if len(c.queue) >= cap(c.queue) {
		return false
	}
	c.queue <- id
	return true
}

func (c *regKeyCache) key(id uint64, now time.Time) (*regKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.keys[id]; ok {
		e.lastUsed = now
		if !e.queued && now.Sub(e.attemptAt) >= c.ttl && c.enqueue(id) {
			e.queued, e.attemptAt = true, now
		}
		if now.Sub(e.fetchedAt) >= c.staleTTL {
			return nil, false
		}
		return e.key, true
	}
	n, ok := c.neg[id]
	if !ok {
		if len(c.neg) >= regKeyNegMax {
			return nil, false
		}
		if !c.enqueue(id) {
			return nil, false
		}
		c.neg[id] = &negEntry{attemptAt: now, queued: true}
		return nil, false
	}
	if !n.queued && now.Sub(n.attemptAt) >= regKeyNegTTL && c.enqueue(id) {
		n.queued, n.attemptAt = true, now
	}
	return nil, false
}

// run fetches queued IDs in batches until ctx is cancelled.
func (c *regKeyCache) run(ctx context.Context, timeout time.Duration) {
	batch := make([]uint64, 0, regKeyBatch)
	for {
		batch = batch[:0]
		select {
		case <-ctx.Done():
			return
		case id := <-c.queue:
			batch = append(batch, id)
		}
	drain:
		for len(batch) < regKeyBatch {
			select {
			case id := <-c.queue:
				batch = append(batch, id)
			default:
				break drain
			}
		}
		fctx, cancel := context.WithTimeout(ctx, timeout)
		pubs, err := c.fetch(fctx, batch)
		cancel()
		var derived map[uint64]*regKey
		if err == nil {
			derived = c.prepare(batch, pubs)
		} else if !errors.Is(err, context.Canceled) && !errors.Is(err, errNoToken) {
			log.Printf("registration: fetch %d device keys: %v", len(batch), err)
		}
		c.complete(batch, derived, err, time.Now())
		if !sleepCtx(ctx, regKeyMinGap) {
			return
		}
	}
}

// prepare derives keys for fetched public keys, reusing cached keys whose
// public key is unchanged. Runs in the worker.
func (c *regKeyCache) prepare(ids []uint64, pubs map[uint64][32]byte) map[uint64]*regKey {
	c.mu.Lock()
	old := make(map[uint64]*regKey, len(ids))
	for _, id := range ids {
		if e, ok := c.keys[id]; ok {
			old[id] = e.key
		}
	}
	c.mu.Unlock()

	out := make(map[uint64]*regKey, len(pubs))
	bad := 0
	for _, id := range ids {
		pub, ok := pubs[id]
		if !ok {
			continue
		}
		if k := old[id]; k != nil && k.pub == pub {
			out[id] = k
		} else if k, err := c.auth.deriveReg(id, pub); err == nil {
			out[id] = k
		} else {
			bad++
		}
	}
	if bad > 0 {
		log.Printf("registration: %d device public keys rejected", bad)
	}
	return out
}

// complete records a fetch result. keys is nil when the fetch failed: known
// keys are then kept (until stale) and retried after ttl, unknown IDs after
// regKeyNegTTL.
func (c *regKeyCache) complete(ids []uint64, keys map[uint64]*regKey, err error, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		e, known := c.keys[id]
		if err != nil {
			if known {
				e.queued = false
			} else if n, ok := c.neg[id]; ok {
				n.queued = false
			}
			continue
		}
		k, ok := keys[id]
		if !ok {
			// The Coordinator no longer knows this device (or its key was
			// rejected): stop accepting it.
			delete(c.keys, id)
			if n, ok := c.neg[id]; ok {
				n.queued, n.attemptAt = false, now
			} else if len(c.neg) < regKeyNegMax {
				c.neg[id] = &negEntry{attemptAt: now}
			}
			continue
		}
		delete(c.neg, id)
		if !known {
			if len(c.keys) >= c.max {
				if !c.full {
					log.Printf("registration: device key cache full (%d), not caching new devices", c.max)
					c.full = true
				}
				continue
			}
			c.full = false
			e = &regKeyEntry{lastUsed: now}
			c.keys[id] = e
		}
		e.key, e.fetchedAt, e.attemptAt, e.queued = k, now, now, false
	}
}

// sweep drops keys unused for staleTTL and expired unknown IDs.
func (c *regKeyCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.keys {
		if !e.queued && now.Sub(e.lastUsed) >= c.staleTTL {
			delete(c.keys, id)
		}
	}
	for id, n := range c.neg {
		if !n.queued && now.Sub(n.attemptAt) >= regKeyNegTTL {
			delete(c.neg, id)
		}
	}
}

// coordinatorKeyFetcher returns a deviceKeyFetcher that queries
//
//	POST {base}/relay/device-keys  {"device_ids":["device-xxxxxxxx", ...]}
//	→ [{"device_id":"device-xxxxxxxx","pub_key":"<base64 X25519>"}, ...]
//
// with relay credentials (creds). Unknown devices are omitted from the
// response; for a self-hosted relay, so are devices that are not current
// members of a room that designated it.
func coordinatorKeyFetcher(base string, creds *relayCreds, client *http.Client) deviceKeyFetcher {
	base = strings.TrimRight(base, "/")
	return func(ctx context.Context, ids []uint64) (map[uint64][32]byte, error) {
		req := struct {
			DeviceIDs []string `json:"device_ids"`
		}{make([]string, len(ids))}
		for i, id := range ids {
			req.DeviceIDs[i] = fmt.Sprintf("device-%08x", id)
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/relay/device-keys", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/json")
		tok, err := creds.apply(hreq)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			if resp.StatusCode == http.StatusUnauthorized {
				creds.unauthorized(tok)
				return nil, fmt.Errorf("coordinator returned %s (%s)", resp.Status, creds.unauthorizedHint())
			}
			return nil, fmt.Errorf("coordinator returned %s", resp.Status)
		}
		var items []struct {
			DeviceID string `json:"device_id"`
			PubKey   string `json:"pub_key"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxKeysRespSize)).Decode(&items); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		asked := make(map[uint64]bool, len(ids))
		for _, id := range ids {
			asked[id] = true
		}
		out := make(map[uint64][32]byte, len(items))
		for _, it := range items {
			id, ok := parseDeviceID(it.DeviceID)
			if !ok || !asked[id] {
				continue // never cache keys we did not ask for
			}
			if pub, err := base64.StdEncoding.DecodeString(it.PubKey); err == nil && len(pub) == 32 {
				out[id] = [32]byte(pub)
			}
		}
		return out, nil
	}
}

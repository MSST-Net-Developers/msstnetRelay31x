package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Game-discovery proxy support.
//
// Clients register a separate UDP socket (client port 21032) with
// TYPE_DISCOVERY_REGISTER and send captured IPv4 broadcast/multicast packets as
// TYPE_DISCOVERY_DATA. The relay forwards the bare IPv4 packet to the
// discovery address of every other device that has done `discovery_join` for
// the same room on the Coordinator (GET /room/{id}/discovery-peers).
//
// In 3.0.x the peer list was fetched synchronously inside the UDP read loop,
// stalling all forwarding for up to the HTTP timeout on every cache miss. Here
// the read loop only consults roomCache; misses are fetched by a bounded set of
// background workers and the triggering packet is dropped. Games re-broadcast
// discovery packets periodically, so the next one is forwarded.

const (
	maxPeersResponseBytes = 1 << 20
	maxPeersPerRoom       = 4096
	roomFetchQueueLen     = 64
	roomFetchWorkers      = 2

	// Coordinator fetch budget. The Coordinator rate-limits per source IP
	// (3.1.x default 30 req/s, burst 60) and the relay shares that budget with
	// its heartbeats, so lookups for many distinct rooms must not exhaust it.
	roomFetchRate  = 10
	roomFetchBurst = 20
)

// roomPeerLookup is what the read loop needs from the room cache.
type roomPeerLookup interface {
	// peers returns the cached discovery peer list for roomID. ok is false
	// when no usable list is available yet.
	peers(roomID []byte, now time.Time) (ids []uint64, ok bool)
}

type peerFetcher func(ctx context.Context, roomID string) ([]uint64, error)

// roomCache is shared between the read loop (lookups) and fetch workers
// (updates), so it is guarded by mu. No I/O happens while mu is held.
type roomCache struct {
	mu         sync.Mutex
	entries    map[string]*roomEntry
	maxEntries int
	ttl        time.Duration // refresh after
	staleTTL   time.Duration // stop serving a list this long after its last successful fetch
	queue      chan string
	fetch      peerFetcher
	fetchLimit *tokenBucket
	full       bool // last insert was refused; logged once per transition
}

type roomEntry struct {
	peers      []uint64 // immutable once stored; replaced wholesale
	fetchedAt  time.Time
	attemptAt  time.Time
	refreshing bool
}

func newRoomCache(fetch peerFetcher, maxEntries int, ttl, staleTTL time.Duration) *roomCache {
	return &roomCache{
		entries:    make(map[string]*roomEntry),
		maxEntries: maxEntries,
		ttl:        ttl,
		staleTTL:   staleTTL,
		queue:      make(chan string, roomFetchQueueLen),
		fetch:      fetch,
		fetchLimit: newTokenBucket(roomFetchRate, roomFetchBurst),
	}
}

func (c *roomCache) peers(roomID []byte, now time.Time) ([]uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[string(roomID)] // no allocation for map lookups
	if !ok {
		if len(c.entries) >= c.maxEntries {
			if !c.full {
				log.Printf("discovery: room cache full (%d rooms), not tracking new rooms", c.maxEntries)
				c.full = true
			}
			return nil, false
		}
		c.full = false
		e = &roomEntry{}
		c.entries[string(roomID)] = e
	}
	if !e.refreshing && now.Sub(e.attemptAt) >= c.ttl && len(c.queue) < cap(c.queue) && c.fetchLimit.allow(now) {
		// All sends on queue happen under mu, so the length check above
		// guarantees this send does not block.
		c.queue <- string(roomID)
		e.refreshing = true
		e.attemptAt = now
	}
	if e.peers == nil || now.Sub(e.fetchedAt) >= c.staleTTL {
		return nil, false
	}
	return e.peers, true
}

// run processes refresh requests until ctx is cancelled.
func (c *roomCache) run(ctx context.Context, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case roomID := <-c.queue:
			fctx, cancel := context.WithTimeout(ctx, timeout)
			ids, err := c.fetch(fctx, roomID)
			cancel()
			c.complete(roomID, ids, err, time.Now())
		}
	}
}

func (c *roomCache) complete(roomID string, ids []uint64, err error, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[roomID]
	if !ok {
		return // swept meanwhile
	}
	e.refreshing = false
	if err != nil {
		// Keep serving the previous list until it goes stale; attemptAt
		// (set at enqueue) spaces out retries by ttl.
		if !errors.Is(err, context.Canceled) {
			log.Printf("discovery: fetch peers for room %s: %v", roomID, err)
		}
		return
	}
	if ids == nil {
		ids = []uint64{}
	}
	e.peers = ids
	e.fetchedAt = now
}

// sweep removes rooms that have not been looked up or refreshed for staleTTL.
func (c *roomCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		if !e.refreshing && now.Sub(e.attemptAt) >= c.staleTTL && now.Sub(e.fetchedAt) >= c.staleTTL {
			delete(c.entries, id)
		}
	}
}

// coordinatorPeerFetcher returns a peerFetcher that queries
// GET {base}/room/{roomID}/discovery-peers. Response shape (Coordinator
// room.go handleDiscoveryPeers): [{"device_id":"device-xxxxxxxx", ...}, ...].
func coordinatorPeerFetcher(base string, client *http.Client) peerFetcher {
	base = strings.TrimRight(base, "/")
	return func(ctx context.Context, roomID string) ([]uint64, error) {
		if !validRoomID(roomID) {
			return nil, fmt.Errorf("invalid room id")
		}
		u := base + "/room/" + url.PathEscape(roomID) + "/discovery-peers"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("coordinator returned %s", resp.Status)
		}
		var items []struct {
			DeviceID string `json:"device_id"`
		}
		dec := json.NewDecoder(io.LimitReader(resp.Body, maxPeersResponseBytes))
		if err := dec.Decode(&items); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		if len(items) > maxPeersPerRoom {
			items = items[:maxPeersPerRoom]
		}
		ids := make([]uint64, 0, len(items))
		for _, it := range items {
			if id, ok := parseDeviceID(it.DeviceID); ok {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}
}

// parseDeviceID converts "device-XXXXXXXX" (8 hex digits) to its wire ID.
func parseDeviceID(s string) (uint64, bool) {
	hex, ok := strings.CutPrefix(s, "device-")
	if !ok || len(hex) != 8 {
		return 0, false
	}
	n, err := strconv.ParseUint(hex, 16, 64)
	if err != nil || !validDeviceID(n) {
		return 0, false
	}
	return n, true
}

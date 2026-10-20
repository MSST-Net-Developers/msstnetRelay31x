package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoordinatorPeerFetcher(t *testing.T) {
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.EscapedPath())
		if strings.Contains(r.URL.Path, "space-bad") {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		if strings.Contains(r.URL.Path, "space-garbage") {
			fmt.Fprint(w, `{not json`)
			return
		}
		fmt.Fprint(w, `[{"device_id":"device-a1b2c3d4","extra":1},{"device_id":"bogus"},{"device_id":"device-00000001"}]`)
	}))
	defer srv.Close()
	fetch := coordinatorPeerFetcher(srv.URL+"/", newRelayCreds(false, ""), srv.Client())

	ids, err := fetch(context.Background(), "space-0a1b2c3d")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0].id != 0xa1b2c3d4 || ids[1].id != 1 || ids[0].hasPub {
		t.Fatalf("ids = %+v", ids)
	}
	if p := gotPath.Load(); p != "/room/space-0a1b2c3d/discovery-peers" {
		t.Fatalf("path = %v", p)
	}

	if _, err := fetch(context.Background(), "space-bad"); err == nil {
		t.Fatal("non-200 accepted")
	}
	if _, err := fetch(context.Background(), "space-garbage"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := fetch(context.Background(), "../relays"); err == nil {
		t.Fatal("unsafe room ID requested")
	}
}

func TestCoordinatorPeerFetcherSendsSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Relay-Secret") != "s3cret" {
			http.Error(w, "invalid relay secret", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	if _, err := coordinatorPeerFetcher(srv.URL, newRelayCreds(false, "s3cret"), srv.Client())(context.Background(), "space-x"); err != nil {
		t.Fatal(err)
	}
	_, err := coordinatorPeerFetcher(srv.URL, newRelayCreds(false, "wrong"), srv.Client())(context.Background(), "space-x")
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err = %v (must fail without echoing the secret)", err)
	}
}

func TestCoordinatorPeerFetcherBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[")
		item := `{"device_id":"device-a1b2c3d4"},`
		for range maxPeersResponseBytes/len(item) + 10 {
			fmt.Fprint(w, item)
		}
		fmt.Fprint(w, `{"device_id":"device-a1b2c3d4"}]`)
	}))
	defer srv.Close()
	if _, err := coordinatorPeerFetcher(srv.URL, newRelayCreds(false, ""), srv.Client())(context.Background(), "space-x"); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestRoomCacheAsyncRefresh(t *testing.T) {
	var calls atomic.Int32
	result := []peerRecord{{id: 1}, {id: 2}}
	var fail atomic.Bool
	fetch := func(ctx context.Context, roomID string) ([]peerRecord, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("down")
		}
		return result, nil
	}
	c := newRoomCache(fetch, nil, 10, 5*time.Second, 30*time.Second)
	drain := func(now time.Time) {
		for {
			select {
			case id := <-c.queue:
				recs, err := c.fetch(context.Background(), id)
				c.complete(id, c.prepare(id, recs), err, now)
			default:
				return
			}
		}
	}

	// Miss: nothing returned, one fetch queued; lookups never block on I/O.
	if _, ok := c.peers([]byte("r"), t0); ok {
		t.Fatal("miss returned peers")
	}
	if _, ok := c.peers([]byte("r"), t0); ok || len(c.queue) != 1 {
		t.Fatalf("duplicate refresh queued: %d", len(c.queue))
	}
	drain(t0)
	if p, ok := c.peers([]byte("r"), t0.Add(time.Second)); !ok || len(p) != 2 {
		t.Fatalf("after fetch: %v %v", p, ok)
	}
	if len(c.queue) != 0 {
		t.Fatal("fresh entry re-queued")
	}

	// Stale-while-revalidate, and failures keep the previous list until stale.
	fail.Store(true)
	if _, ok := c.peers([]byte("r"), t0.Add(6*time.Second)); !ok || len(c.queue) != 1 {
		t.Fatal("stale entry not served while refreshing")
	}
	drain(t0.Add(6 * time.Second))
	if _, ok := c.peers([]byte("r"), t0.Add(29*time.Second)); !ok {
		t.Fatal("previous list dropped on fetch error")
	}
	if _, ok := c.peers([]byte("r"), t0.Add(31*time.Second)); ok {
		t.Fatal("list served past stale TTL")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (retries spaced by ttl)", n)
	}

	// Sweep removes idle rooms.
	drain(t0.Add(31 * time.Second))
	c.sweep(t0.Add(2 * time.Minute))
	if len(c.entries) != 0 {
		t.Fatalf("not swept: %d", len(c.entries))
	}
}

func TestRoomCacheBounds(t *testing.T) {
	c := newRoomCache(func(context.Context, string) ([]peerRecord, error) { return nil, nil }, nil, 3, time.Second, 10*time.Second)
	for i := range 10 {
		c.peers(fmt.Appendf(nil, "room-%d", i), t0)
	}
	if len(c.entries) != 3 {
		t.Fatalf("entries = %d, want cap 3", len(c.entries))
	}

	// Fetch budget: many distinct rooms cannot flood the Coordinator.
	c = newRoomCache(func(context.Context, string) ([]peerRecord, error) { return nil, nil }, nil, 1000, time.Second, 10*time.Second)
	for i := range 500 {
		c.peers(fmt.Appendf(nil, "room-%d", i), t0)
	}
	if n := len(c.queue); n > roomFetchBurst {
		t.Fatalf("queued %d fetches, budget is %d", n, roomFetchBurst)
	}
}

func TestRoomCacheConcurrent(t *testing.T) {
	fetch := func(ctx context.Context, roomID string) ([]peerRecord, error) {
		return []peerRecord{{id: 1}, {id: 2}, {id: 3}}, nil
	}
	c := newRoomCache(fetch, nil, 100, time.Millisecond, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range roomFetchWorkers {
		wg.Go(func() { c.run(ctx, time.Second) })
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		now := time.Now()
		c.peers([]byte("space-a"), now)
		c.peers([]byte("space-b"), now)
		c.sweep(now)
	}
	cancel()
	wg.Wait() // workers exit on cancellation
	if p, ok := c.peers([]byte("space-a"), time.Now()); !ok || len(p) != 3 {
		t.Fatalf("peers = %v %v", p, ok)
	}
}

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeCoordinator implements the relay endpoints of Coordinator 3.1.x
// (relay.go): X-Relay-Secret check, 404 on heartbeat for unknown relays.
type fakeCoordinator struct {
	secret string

	mu         sync.Mutex
	registered map[string]map[string]string
	registers  int
	heartbeats int
	authFails  int
}

func (f *fakeCoordinator) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if f.secret != "" && r.Header.Get("X-Relay-Secret") != f.secret {
			f.mu.Lock()
			f.authFails++
			f.mu.Unlock()
			http.Error(w, "invalid relay secret", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /relay/register", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req map[string]string
		if json.NewDecoder(r.Body).Decode(&req) != nil || req["id"] == "" || req["region"] == "" || req["addr"] == "" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.registered[req["id"]] = req
		f.registers++
		f.mu.Unlock()
	})
	mux.HandleFunc("POST /relay/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.registered[req["id"]]; !ok {
			http.Error(w, "relay not found", http.StatusNotFound)
			return
		}
		f.heartbeats++
	})
	return mux
}

func (f *fakeCoordinator) snapshot() (registers, heartbeats, authFails int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registers, f.heartbeats, f.authFails
}

func (f *fakeCoordinator) forget() {
	f.mu.Lock()
	f.registered = map[string]map[string]string{}
	f.mu.Unlock()
}

func testControlClient(url, secret string) *controlClient {
	cfg := defaultConfig()
	cfg.Node = NodeConfig{ID: "relay-test", Region: "test", Addr: "relay.example:21031"}
	cfg.Control.ServerURL = url
	cfg.Control.RelaySecret = secret
	cfg.Control.HeartbeatInterval = 20 * time.Millisecond
	c := newControlClient(cfg)
	c.retryInitial = 10 * time.Millisecond
	c.retryMax = 40 * time.Millisecond
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestControlRegisterHeartbeatReregister(t *testing.T) {
	fc := &fakeCoordinator{secret: "s3cret", registered: map[string]map[string]string{}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	c := testControlClient(srv.URL+"/", "s3cret")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()

	waitFor(t, "heartbeats", func() bool { _, hb, _ := fc.snapshot(); return hb >= 2 })
	fc.mu.Lock()
	reg := fc.registered["relay-test"]
	fc.mu.Unlock()
	if reg["region"] != "test" || reg["addr"] != "relay.example:21031" {
		t.Fatalf("registration body = %v", reg)
	}

	// Coordinator restart: heartbeat gets 404 → relay re-registers.
	fc.forget()
	waitFor(t, "re-registration", func() bool { r, _, _ := fc.snapshot(); return r >= 2 })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("control client did not stop on cancel")
	}
	if _, _, af := fc.snapshot(); af != 0 {
		t.Fatalf("auth failures with correct secret: %d", af)
	}
}

func TestControlWrongSecretRetries(t *testing.T) {
	fc := &fakeCoordinator{secret: "right", registered: map[string]map[string]string{}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	c := testControlClient(srv.URL, "wrong")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()

	waitFor(t, "retries", func() bool { _, _, af := fc.snapshot(); return af >= 3 })
	cancel()
	<-done
	if r, _, _ := fc.snapshot(); r != 0 {
		t.Fatal("registered with wrong secret")
	}
}

func TestControlUnreachableStopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listening

	c := testControlClient(url, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop did not stop on cancel")
	}
}

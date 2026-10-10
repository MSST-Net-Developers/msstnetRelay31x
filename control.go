package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// controlClient registers this relay with the Coordinator and keeps it alive
// with heartbeats (Coordinator relay.go: POST /relay/register,
// POST /relay/heartbeat; relays expire after 30 s without a heartbeat).
//
// Forwarding never depends on the Coordinator being reachable; this only
// affects whether clients are offered this relay via GET /relays.
type controlClient struct {
	serverURL string
	id        string
	region    string
	addr      string
	secret    string
	interval  time.Duration
	http      *http.Client

	retryInitial time.Duration
	retryMax     time.Duration
}

// errNotRegistered is returned when the Coordinator no longer knows this
// relay (typically because it restarted).
var errNotRegistered = errors.New("relay not registered with coordinator")

func newControlClient(cfg *Config) *controlClient {
	return &controlClient{
		serverURL:    strings.TrimRight(cfg.Control.ServerURL, "/"),
		id:           cfg.Node.ID,
		region:       cfg.Node.Region,
		addr:         cfg.Node.Addr,
		secret:       cfg.Control.RelaySecret,
		interval:     cfg.Control.HeartbeatInterval,
		http:         &http.Client{Timeout: cfg.Control.RequestTimeout},
		retryInitial: 5 * time.Second,
		retryMax:     5 * time.Minute,
	}
}

func (c *controlClient) post(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("X-Relay-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("coordinator returned %s (check control.relay_secret)", resp.Status)
	case resp.StatusCode == http.StatusNotFound && path == "/relay/heartbeat":
		return errNotRegistered
	default:
		return fmt.Errorf("coordinator returned %s", resp.Status)
	}
}

func (c *controlClient) register(ctx context.Context) error {
	return c.post(ctx, "/relay/register", map[string]string{
		"id":     c.id,
		"region": c.region,
		"addr":   c.addr,
	})
}

func (c *controlClient) heartbeat(ctx context.Context) error {
	return c.post(ctx, "/relay/heartbeat", map[string]string{"id": c.id})
}

// registerWithRetry retries with capped exponential backoff and jitter until
// registration succeeds or ctx is cancelled. Returns false on cancellation.
func (c *controlClient) registerWithRetry(ctx context.Context) bool {
	delay := c.retryInitial
	for {
		err := c.register(ctx)
		if err == nil {
			log.Printf("control: registered id=%s region=%s addr=%s", c.id, c.region, c.addr)
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		wait := delay/2 + rand.N(delay/2+1)
		log.Printf("control: register failed: %v; retrying in %s", err, wait.Round(time.Millisecond))
		if !sleepCtx(ctx, wait) {
			return false
		}
		delay = min(delay*2, c.retryMax)
	}
}

// run registers, then heartbeats every interval. A failed heartbeat is
// followed by re-registration (register is idempotent on the Coordinator),
// which also covers a Coordinator restart. Returns when ctx is cancelled.
func (c *controlClient) run(ctx context.Context) {
	if strings.HasPrefix(c.serverURL, "http://") && c.secret != "" {
		log.Printf("control: warning: relay_secret is sent over plain HTTP to %s", c.serverURL)
	}
	for {
		if !c.registerWithRetry(ctx) {
			return
		}
		ticker := time.NewTicker(c.interval)
		for err := error(nil); err == nil; {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
			}
			if err = c.heartbeat(ctx); err != nil && ctx.Err() == nil {
				log.Printf("control: heartbeat failed: %v; re-registering", err)
			}
		}
		ticker.Stop()
		if ctx.Err() != nil {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

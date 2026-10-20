package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
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
// Official relays authenticate with their pre-shared secret
// (control.relay_secret). Self-hosted relays prove possession of the relay
// key (POST /relay/self-hosted/challenge, /relay/self-hosted/register) and
// heartbeat with the bearer token they get back (selfhosted.go).
//
// Forwarding never depends on the Coordinator being reachable; this only
// affects whether clients are offered this relay (official: GET /relays;
// self-hosted: whether rooms can designate it).
type controlClient struct {
	serverURL string
	id        string
	region    string
	addr      string
	creds     *relayCreds
	auth      *sdiscAuth // relay key; nil only in tests of official mode
	interval  time.Duration
	http      *http.Client

	// Self-hosted only. pwVerifier is nil without relay.password.
	pwVerifier          []byte
	requireRoomPassword bool

	retryInitial time.Duration
	retryMax     time.Duration
}

// errNotRegistered is returned when the Coordinator no longer knows this
// relay (typically because it restarted).
var errNotRegistered = errors.New("relay not registered with coordinator")

const (
	maxControlRespBytes = 64 << 10
	maxTokenLen         = 512
)

func newControlClient(cfg *Config, creds *relayCreds, auth *sdiscAuth) *controlClient {
	c := &controlClient{
		serverURL:           strings.TrimRight(cfg.Control.ServerURL, "/"),
		id:                  cfg.Node.ID,
		region:              cfg.Node.Region,
		addr:                cfg.Node.Addr,
		creds:               creds,
		auth:                auth,
		interval:            cfg.Control.HeartbeatInterval,
		http:                &http.Client{Timeout: cfg.Control.RequestTimeout},
		requireRoomPassword: cfg.Relay.RequireRoomPassword,
		retryInitial:        5 * time.Second,
		retryMax:            5 * time.Minute,
	}
	if creds.selfHosted && cfg.Relay.Password != "" {
		c.pwVerifier = relayPasswordVerifier(cfg.Relay.Password, auth.pub)
	}
	return c
}

// post sends body as JSON and decodes a 2xx JSON response into out (if not
// nil). bearer, when set, overrides the configured credentials.
func (c *controlClient) post(ctx context.Context, path string, body, out any, bearer string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case bearer != "":
		req.Header.Set("Authorization", "Bearer "+bearer)
	case !c.creds.selfHosted:
		_, _ = c.creds.apply(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	lr := io.LimitReader(resp.Body, maxControlRespBytes)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			_, _ = io.Copy(io.Discard, lr)
			return nil
		}
		if err := json.NewDecoder(lr).Decode(out); err != nil {
			return fmt.Errorf("parse %s response: %w", path, err)
		}
		return nil
	}
	// Coordinator errors are {"error": "...", "code": "..."}; code is
	// optional. Only these two fields are logged.
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.NewDecoder(lr).Decode(&e)
	detail := ""
	if e.Code != "" {
		detail = " code=" + e.Code
	}
	if e.Error != "" {
		detail += fmt.Sprintf(" (%.200s)", e.Error)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized && !c.creds.selfHosted:
		return fmt.Errorf("coordinator returned %s%s (check control.relay_secret)", resp.Status, detail)
	case resp.StatusCode == http.StatusUnauthorized && path == "/relay/heartbeat":
		return errNotRegistered // token expired or Coordinator restarted
	case resp.StatusCode == http.StatusNotFound && path == "/relay/heartbeat":
		return errNotRegistered
	default:
		return fmt.Errorf("coordinator returned %s%s", resp.Status, detail)
	}
}

// relayFeatures are the optional protocols this relay supports, reported on
// registration so that clients can pick them per relay (via GET /relays):
// "sdisc1" = SECURE_DISCOVERY.md, "sreg1" = REGISTRATION_AUTH.md. 0x0E has no
// reply, so clients cannot detect support any other way.
var relayFeatures = []string{"sdisc1", "sreg1"}

// register registers once and returns a description for the log.
func (c *controlClient) register(ctx context.Context) (string, error) {
	if c.creds.selfHosted {
		return c.registerSelfHosted(ctx)
	}
	body := map[string]any{
		"id":     c.id,
		"region": c.region,
		"addr":   c.addr,
	}
	// Clients need this key (via GET /relays) for secure discovery and
	// authenticated registration with this relay.
	if c.auth != nil {
		body["pub_key"] = c.auth.publicKeyBase64()
		body["features"] = relayFeatures
	}
	if err := c.post(ctx, "/relay/register", body, nil, ""); err != nil {
		return "", err
	}
	return fmt.Sprintf("id=%s region=%s addr=%s", c.id, c.region, c.addr), nil
}

// registerSelfHosted performs challenge-response registration and stores the
// returned token in creds. The token is never logged.
func (c *controlClient) registerSelfHosted(ctx context.Context) (string, error) {
	pub := c.auth.publicKeyBase64()
	var ch struct {
		ChallengeID string `json:"challenge_id"`
		ServerPub   string `json:"server_pub"`
	}
	if err := c.post(ctx, "/relay/self-hosted/challenge", map[string]string{"pub_key": pub}, &ch, ""); err != nil {
		return "", fmt.Errorf("challenge: %w", err)
	}
	cid, err := hex.DecodeString(ch.ChallengeID)
	if err != nil || len(cid) != 16 || ch.ChallengeID != strings.ToLower(ch.ChallengeID) {
		return "", errors.New("challenge: invalid challenge_id")
	}
	spub, err := base64.StdEncoding.DecodeString(ch.ServerPub)
	if err != nil || len(spub) != 32 {
		return "", errors.New("challenge: invalid server_pub")
	}
	mac, err := c.auth.relayKeyproofMAC([32]byte(spub), [16]byte(cid))
	if err != nil {
		return "", fmt.Errorf("challenge: %w", err)
	}
	body := map[string]any{
		"pub_key":               pub,
		"addr":                  c.addr,
		"features":              relayFeatures,
		"require_room_password": c.requireRoomPassword,
		"proof": map[string]string{
			"challenge_id": ch.ChallengeID,
			"mac":          base64.StdEncoding.EncodeToString(mac[:]),
		},
	}
	if c.pwVerifier != nil {
		body["password_verifier"] = base64.StdEncoding.EncodeToString(c.pwVerifier)
	}
	var reg struct {
		RelayID string `json:"relay_id"`
		Token   string `json:"token"`
	}
	if err := c.post(ctx, "/relay/self-hosted/register", body, &reg, ""); err != nil {
		return "", fmt.Errorf("register: %w", err)
	}
	if reg.Token == "" || len(reg.Token) > maxTokenLen {
		return "", errors.New("register: invalid token in response")
	}
	c.creds.setToken(reg.Token)
	return fmt.Sprintf("self-hosted relay_id=%.40q addr=%s password=%v require_room_password=%v",
		reg.RelayID, c.addr, c.pwVerifier != nil, c.requireRoomPassword), nil
}

func (c *controlClient) heartbeat(ctx context.Context) error {
	if !c.creds.selfHosted {
		return c.post(ctx, "/relay/heartbeat", map[string]string{"id": c.id}, nil, "")
	}
	c.creds.mu.Lock()
	tok := c.creds.token
	c.creds.mu.Unlock()
	if tok == "" {
		return errNotRegistered
	}
	return c.post(ctx, "/relay/heartbeat", map[string]string{}, nil, tok)
}

// registerWithRetry retries with capped exponential backoff and jitter until
// registration succeeds or ctx is cancelled. Returns false on cancellation.
func (c *controlClient) registerWithRetry(ctx context.Context) bool {
	delay := c.retryInitial
	for {
		desc, err := c.register(ctx)
		if err == nil {
			log.Printf("control: registered %s", desc)
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
// which also covers a Coordinator restart. A self-hosted relay also
// re-registers when another request was rejected with its token. Returns
// when ctx is cancelled.
func (c *controlClient) run(ctx context.Context) {
	if strings.HasPrefix(c.serverURL, "http://") && c.creds.secret != "" {
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
			case <-c.creds.reauth:
				err = errNotRegistered
				log.Printf("control: coordinator rejected the relay token; re-registering")
				continue
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

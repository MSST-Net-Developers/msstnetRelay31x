package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Self-hosted relays (relay.mode: self_hosted; client repo
// docs/ROOM_RELAY_SERVER_3.1.md RR1–RR6).
//
// A self-hosted relay is not listed in GET /relays. Room owners designate it
// by its connection link (public key + address), and the Coordinator scopes
// its credentials to rooms that designated it. It authenticates to the
// Coordinator by proving possession of its X25519 key (challenge-response,
// like device keyproof v1) and then uses a bearer token held in memory only.

const (
	relayModeOfficial   = "official"
	relayModeSelfHosted = "self_hosted"

	relayKeyproofLabel = "msst-relay-keyproof-v1"
	relayPasswordSalt  = "msst-relay-pw-v1"
)

// relayKeyproofMAC proves possession of the relay key for one challenge:
//
//	shared = X25519(relay_sk, server_pub)        (all-zero rejected)
//	k      = HKDF-SHA256(shared, salt=label, info=relay_pub‖server_pub, 32)
//	mac    = HMAC-SHA256(k, label ‖ challenge_id (16 raw bytes))
func (a *sdiscAuth) relayKeyproofMAC(serverPub [32]byte, challengeID [16]byte) ([32]byte, error) {
	var mac [32]byte
	pk, err := ecdh.X25519().NewPublicKey(serverPub[:])
	if err != nil {
		return mac, err
	}
	shared, err := a.priv.ECDH(pk) // fails on an all-zero result
	if err != nil {
		return mac, err
	}
	info := make([]byte, 0, 64)
	info = append(info, a.pub[:]...)
	info = append(info, serverPub[:]...)
	k, err := hkdf.Key(sha256.New, shared, []byte(relayKeyproofLabel), string(info), 32)
	if err != nil {
		return mac, err
	}
	m := hmac.New(sha256.New, k)
	_, _ = m.Write([]byte(relayKeyproofLabel))
	_, _ = m.Write(challengeID[:])
	copy(mac[:], m.Sum(nil))
	return mac, nil
}

// relayPasswordVerifier derives the value reported to the Coordinator for
// relay.password: Argon2id(password, "msst-relay-pw-v1"‖relay_pub, t=2,
// m=19 MiB, p=1, 32 bytes). Binding the relay key into the salt makes the
// same password differ per relay. Never log the password or the verifier.
func relayPasswordVerifier(password string, relayPub [32]byte) []byte {
	salt := append([]byte(relayPasswordSalt), relayPub[:]...)
	return argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
}

// relayLink is the connection link a room owner pastes when creating a room:
//
//	msst-relay://<node.addr>#<base64url(relay_pub), unpadded>[?pw=1]
//
// pw=1 only tells the client to ask for the relay password.
func relayLink(addr string, relayPub [32]byte, hasPassword bool) string {
	s := "msst-relay://" + addr + "#" + base64.RawURLEncoding.EncodeToString(relayPub[:])
	if hasPassword {
		s += "?pw=1"
	}
	return s
}

// errNoToken is returned by Coordinator requests made by a self-hosted
// relay before it has registered.
var errNoToken = errors.New("not registered with coordinator yet")

// relayCreds authenticates requests to the Coordinator: X-Relay-Secret for
// official relays, the bearer token from self-hosted registration otherwise.
//
// Shared by the control client (sets the token) and the room/device-key
// fetchers (use it), so the token is guarded by mu. A fetcher that gets 401
// calls unauthorized, which asks the control client to register again.
type relayCreds struct {
	selfHosted bool
	secret     string // official mode only

	mu     sync.Mutex
	token  string        // self-hosted: current bearer token, "" before registration
	reauth chan struct{} // cap 1: a request was rejected with this token
}

func newRelayCreds(selfHosted bool, secret string) *relayCreds {
	return &relayCreds{selfHosted: selfHosted, secret: secret, reauth: make(chan struct{}, 1)}
}

// apply sets the credentials on req and returns the token used ("" in
// official mode), to be passed back to unauthorized.
func (c *relayCreds) apply(req *http.Request) (string, error) {
	if !c.selfHosted {
		if c.secret != "" {
			req.Header.Set("X-Relay-Secret", c.secret)
		}
		return "", nil
	}
	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()
	if tok == "" {
		return "", errNoToken
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return tok, nil
}

func (c *relayCreds) setToken(tok string) {
	c.mu.Lock()
	c.token = tok
	c.mu.Unlock()
	// A rejection reported before this registration is now resolved.
	select {
	case <-c.reauth:
	default:
	}
}

// unauthorized reports a 401 for a request made with tok. It is ignored in
// official mode (re-registering cannot fix a wrong secret) and when the token
// has been replaced since (the request raced a re-registration).
func (c *relayCreds) unauthorized(tok string) {
	if !c.selfHosted {
		return
	}
	c.mu.Lock()
	current := tok != "" && tok == c.token
	c.mu.Unlock()
	if current {
		select {
		case c.reauth <- struct{}{}:
		default:
		}
	}
}

// unauthorizedHint explains a 401 in log messages. Never includes the
// credential itself.
func (c *relayCreds) unauthorizedHint() string {
	if c.selfHosted {
		return "token expired or coordinator restarted; re-registering"
	}
	return "check control.relay_secret"
}

func (c *relayCreds) String() string { return fmt.Sprintf("relayCreds{selfHosted:%v}", c.selfHosted) }

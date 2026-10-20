package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// Secure discovery (sdisc v1): sender authentication for the game-discovery
// proxy using the device's existing X25519 identity key. See
// SECURE_DISCOVERY.md for the full specification and test vectors.
//
// Device and relay derive per-device MAC keys from a static-static X25519
// exchange:
//
//	ikm  = X25519(device_sk, relay_pk) = X25519(relay_sk, device_pk)
//	okm  = HKDF-SHA256(ikm, salt="msst-sdisc-v1", info=device_id(8, BE)‖device_pk‖relay_pk, 64)
//	c2r  = okm[0:32]   client → relay
//	r2c  = okm[32:64]  relay → client
//
// Packets carry tag = HMAC-SHA256(key, everything before the tag)[:16].
// HMAC is used rather than an AEAD in authentication-only mode because its
// security does not depend on the counter never repeating (a client restart
// or clock step could repeat one; with Poly1305 that leaks the one-time key).
//
// This authenticates the sender to the relay and the relay to the
// recipient. It does not encrypt, and it has no forward secrecy: whoever
// holds the relay's private key can forge any device's packets to this relay.
const (
	typSecureDiscoveryRegister = 0x0A // [counter:8][room_len:1][room_id][tag:16]
	typSecureDiscoveryData     = 0x0B // [counter:8][room_len:1][room_id][ipv4][tag:16]
	typSecureDiscoveryDeliver  = 0x0C // relay → client: [counter:8][ipv4][tag:16]

	sdiscCounterLen = 8
	sdiscTagLen     = 16
	sdiscLabel      = "msst-sdisc-v1"

	// sdiscFlagSenderVerified is set in the header flags of every 0x0C
	// packet: the relay authenticated the original sender (src_id). 3.1.x
	// clients drop 0x0C without it.
	sdiscFlagSenderVerified = 0x01

	// sdiscCounterShift: counters are unix_ms<<16 | sequence, so both sides
	// can check freshness without persisting state across restarts.
	sdiscCounterShift = 16
)

// sdiscAuth is the relay's static X25519 key.
type sdiscAuth struct {
	priv *ecdh.PrivateKey
	pub  [32]byte
}

func newSdiscAuth(priv *ecdh.PrivateKey) *sdiscAuth {
	a := &sdiscAuth{priv: priv}
	copy(a.pub[:], priv.PublicKey().Bytes())
	return a
}

func (a *sdiscAuth) publicKeyBase64() string { return base64.StdEncoding.EncodeToString(a.pub[:]) }

// sdiscKeys are the MAC keys shared with one device. Immutable once built.
type sdiscKeys struct {
	pub [32]byte // device public key the keys were derived from
	c2r [32]byte
	r2c [32]byte
}

// derive performs the X25519 exchange with a device key. It fails for
// low-order device keys (all-zero shared secret).
func (a *sdiscAuth) derive(id uint64, devPub [32]byte) (*sdiscKeys, error) {
	pk, err := ecdh.X25519().NewPublicKey(devPub[:])
	if err != nil {
		return nil, err
	}
	shared, err := a.priv.ECDH(pk)
	if err != nil {
		return nil, err
	}
	info := make([]byte, 0, 8+32+32)
	info = binary.BigEndian.AppendUint64(info, id)
	info = append(info, devPub[:]...)
	info = append(info, a.pub[:]...)
	okm, err := hkdf.Key(sha256.New, shared, []byte(sdiscLabel), string(info), 64)
	if err != nil {
		return nil, err
	}
	k := &sdiscKeys{pub: devPub}
	copy(k.c2r[:], okm[:32])
	copy(k.r2c[:], okm[32:])
	return k, nil
}

// sdiscTag computes the truncated HMAC of msg into out.
func sdiscTag(key *[32]byte, msg []byte, out *[sdiscTagLen]byte) {
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write(msg)
	var sum [sha256.Size]byte
	copy(out[:], m.Sum(sum[:0]))
}

// sdiscVerify checks the trailing tag of pkt (header included) in constant
// time.
func sdiscVerify(key *[32]byte, pkt []byte) bool {
	if len(pkt) < sdiscTagLen {
		return false
	}
	n := len(pkt) - sdiscTagLen
	var want [sdiscTagLen]byte
	sdiscTag(key, pkt[:n], &want)
	return hmac.Equal(want[:], pkt[n:])
}

// parseSecureDiscoveryPayload splits a 0x0A (withIP=false) or 0x0B
// (withIP=true) payload. The tag is not checked here.
func parseSecureDiscoveryPayload(p []byte, withIP bool) (counter uint64, roomID, ipPkt []byte, ok bool) {
	if len(p) < sdiscCounterLen+sdiscTagLen {
		return 0, nil, nil, false
	}
	counter = binary.BigEndian.Uint64(p)
	body := p[sdiscCounterLen : len(p)-sdiscTagLen]
	if withIP {
		roomID, ipPkt, ok = parseDiscoveryPayload(body)
		return counter, roomID, ipPkt, ok
	}
	if len(body) < 1 || int(body[0]) != len(body)-1 || !validRoomID(string(body[1:])) {
		return 0, nil, nil, false
	}
	return counter, body[1:], nil, true
}

// replayGuard enforces strictly increasing, fresh counters per device.
//
// Ownership: read loop. Entries expire ttl after the last accepted packet;
// with ttl >= 2*skew (checked by config validation) an expired entry can no
// longer be exploited, because any packet it would have rejected is also
// outside the freshness window. State is lost on restart, so a packet may be
// replayed once within the skew window after a relay restart.
type replayGuard struct {
	entries map[uint64]replayEntry
	max     int
	ttl     time.Duration
	skewMs  int64
}

type replayEntry struct {
	counter uint64
	seen    time.Time
}

type replayResult uint8

const (
	replayOK replayResult = iota
	replayStale
	replayRepeat
	replayFull
)

func newReplayGuard(max int, ttl, skew time.Duration) *replayGuard {
	return &replayGuard{entries: make(map[uint64]replayEntry), max: max, ttl: ttl, skewMs: skew.Milliseconds()}
}

// accept records counter for id if it is fresh and newer than the last
// accepted one. Call only after the packet's tag has been verified.
func (g *replayGuard) accept(id, counter uint64, now time.Time) replayResult {
	ts := int64(counter >> sdiscCounterShift)
	if d := now.UnixMilli() - ts; d > g.skewMs || d < -g.skewMs {
		return replayStale
	}
	e, ok := g.entries[id]
	if ok && now.Sub(e.seen) < g.ttl && counter <= e.counter {
		return replayRepeat
	}
	if !ok && len(g.entries) >= g.max {
		return replayFull
	}
	g.entries[id] = replayEntry{counter: counter, seen: now}
	return replayOK
}

func (g *replayGuard) sweep(now time.Time) {
	for id, e := range g.entries {
		if now.Sub(e.seen) >= g.ttl {
			delete(g.entries, id)
		}
	}
}

func (g *replayGuard) len() int { return len(g.entries) }

// nextCounter returns a counter greater than last that encodes now.
func nextCounter(last uint64, now time.Time) uint64 {
	return max(last+1, uint64(now.UnixMilli())<<sdiscCounterShift)
}

// loadOrCreateRelayKey reads the relay's X25519 private key (base64, as
// WireGuard stores keys) from path, creating it with mode 0600 if missing.
func loadOrCreateRelayKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Bytes()) + "\n"); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		log.Printf("discovery: created relay key %s", path)
		return priv, nil
	}
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Printf("discovery: warning: %s is accessible by group/others (mode %v)", path, fi.Mode().Perm())
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		// Never echo key material.
		return nil, fmt.Errorf("%s: expected a base64-encoded 32-byte X25519 private key", path)
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

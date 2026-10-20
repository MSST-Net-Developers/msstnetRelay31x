# Secure discovery (sdisc v1)

Sender authentication for the game-discovery proxy, using each device's
existing X25519 identity key (the WireGuard key in `private.key`). Relay side
implemented in `sdisc.go`. It is the only discovery protocol in 3.1.x:
unauthenticated 0x08/0x09 and bare-IPv4 delivery are retired (client
contract: `msst-net-core-31x/docs/RELAY_REQUIREMENTS_3.1.md`).

## Goals and non-goals

Prevents:

- injecting discovery packets into a room under another device's ID;
- hijacking another device's discovery address (and so receiving its
  discovery traffic) with a spoofed register;
- replaying captured packets (outside the window described under Replay);
- injecting packets straight into a client's UDP 21032 socket, bypassing the
  relay (3.1.x clients accept only verified 0x0C there).

Does **not** provide: confidentiality (payloads are not encrypted), forward
secrecy, or protection against a malicious room member or a compromised
relay. Whoever holds the relay's private key can forge any device's packets
to that relay and any relay→client packet from it.

The scheme is only as strong as the binding between device ID and public
key held by the Coordinator (see Coordinator requirements).

## Keys

- Relay: static X25519 key in `discovery.auth_key_file` (base64, 0600,
  created on first start). The public key is logged at startup and sent as
  `pub_key` in `POST /relay/register`.
- Device: the existing identity key pair. `device_id` below is the 64-bit
  wire ID (big-endian u64 of the 8 hex digits).

```
shared = X25519(device_sk, relay_pk)                 # == X25519(relay_sk, device_pk)
okm    = HKDF-SHA256(ikm  = shared,
                     salt = "msst-sdisc-v1",
                     info = device_id (8 bytes BE) ‖ device_pk (32) ‖ relay_pk (32),
                     L    = 64)
k_c2r  = okm[0:32]     # client → relay
k_r2c  = okm[32:64]    # relay → client
tag    = HMAC-SHA256(key, all packet bytes before the tag)[0:16]
```

Reject an all-zero shared secret (low-order key). Compare tags in constant
time. HMAC is used instead of an AEAD in authentication-only mode so that an
accidentally repeated counter does not enable forgery.

## Packets

All use the MSST header (`"MSST" | ver=1 | type | flags | src_id u64 | dst_id u64`).
The tag covers the header too.

| Type | Direction | Payload | Header |
|------|-----------|---------|--------|
| `0x0A` SDISC_REGISTER | client → relay (from UDP 21032) | `counter u64 ‖ room_len u8 ‖ room_id ‖ tag[16]` | src = own ID, dst = 0, flags = 0 |
| `0x0B` SDISC_DATA | client → relay (from UDP 21032) | `counter u64 ‖ room_len u8 ‖ room_id ‖ ipv4 ‖ tag[16]` | src = own ID, dst = 0, flags = 0 |
| `0x0C` SDISC_DELIVER | relay → client (to UDP 21032) | `counter u64 ‖ ipv4 ‖ tag[16]` | src = original sender, dst = recipient, flags bit 0 = sender verified |

`room_id`: `[A-Za-z0-9_-]{1,64}`. `ipv4`: the captured IPv4 broadcast/multicast packet.
Send 0x0A only while the device is in a room, because the relay finds the
device key through that room's peer list. Send it on joining, again about
1 s later, then every 25 s. When the relay has not yet cached the room's peer
list, it drops the first packet and fetches the list in the background, so
without the early retry the device might not be reachable for up to 25 s.

The relay sets 0x0C flag bit 0 on every packet (the original sender was
authenticated); 3.1.x clients drop 0x0C without it.

## Counters and replay

`counter = unix_time_ms << 16 | seq`, strictly increasing per sender:
`counter = max(last + 1, now_ms << 16)`. On the client, 0x0A and 0x0B share
one counter (they leave the same socket). The relay uses one counter across
all 0x0C packets it sends.

The receiver accepts a packet only if `|now_ms - (counter >> 16)| <=
max_skew` (relay: `discovery.auth_max_clock_skew`, default 30 s) and
`counter` is greater than the last counter accepted from that peer.
Packets that arrive out of order are dropped; games re-broadcast discovery
packets. Replay state is lost when the relay restarts, so after a restart a
captured packet can be replayed once while it is still within the skew
window. Clients whose clocks are off by more than the skew cannot use
secure discovery.

## Relay behaviour

Order for 0x0A/0x0B: parse → room peer list (cached; a miss starts an async
fetch and drops the packet) → sender must be listed with a key → verify the
tag → counter check → only then (re)bind the discovery address. For 0x0B,
then global ingress limit → dedup → per-sender limit → fan-out. Forged
packets change no state.

The relay always runs in `required` mode (`discovery.auth` accepts only
`required`). Retired 0x08/0x09 are dropped and counted as `drop{retired}`;
they create no binding. A recipient whose key is missing from the current
peer list receives nothing. Earlier drafts of this document described `off`
and `optional` modes; they were removed for 3.1.x.

## Coordinator (implemented in Coordinator 3.1.x, commit 66eb3f8)

1. `GET /room/{id}/discovery-peers` returns `pub_key` per item, lists only
   current room members, and requires `X-Relay-Secret` (the relay sends
   `control.relay_secret`; serve it over HTTPS).
2. `POST /relay/register` accepts the relay `pub_key`; `GET /relays` returns
   it. Clients get no discovery through a relay without one.
3. `discovery_join` requires room membership.
4. Device keys: the device ID must be derived from the key, and the first key
   seen for an ID is pinned. Proof of possession (`device_key_proof`,
   DEVICE_KEY_PROOF.md) defaults to `off`. Until it is `required`, whoever
   registers a device ID first decides its key. Because the ID is only 32 bits
   of SHA-256, a matching key for a not-yet-registered ID can be found in
   about 2^32 tries. Enable `device_key_proof: required` once clients send
   proofs.

## Client (msst-net-core-31x)

- Derives `k_c2r`/`k_r2c` per relay from the relay `pub_key` in `/relays`;
  no discovery through relays without one.
- On UDP 21032 accepts only 0x0C that passes tag, `dst_id`, counter and
  sender-verified checks; never bare IPv4.
- Keeps the counter monotonic as specified and never logs keys.

## Deployment order

1. Relay (sends `X-Relay-Secret` on `discovery-peers` and `pub_key` on
   register). Deploy before the Coordinator if it has `relay_secret` set,
   because otherwise discovery-peers returns 401.
2. Coordinator 3.1.x.
3. 3.1.x clients. 3.0.x clients lose relay data (0x04) and discovery.

## Test vectors

Device private key = 32 × `0x01`, relay private key = 32 × `0x02`, device
ID `0xa1b2c3d4` (`device-a1b2c3d4`). IPv4 = `45` followed by 19 zero bytes.
Checked against an independent Python (`cryptography`) implementation.

```
relay_pub  ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59
device_pub a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209
k_c2r      0eb7f36437a118f7db30875fafb8b74e78d0b7ddf7e2707c3d3360bfc81d8d25
k_r2c      b91f9f3c48fabc3672c47973da68bf80af849fe27d473428ca573b84aea6059f

0x0B, room "space-0a1b2c3d", counter 0x0000019900000001:
4d535354010b0000000000a1b2c3d4000000000000000000000199000000010e73706163652d
3061316232633364450000000000000000000000000000000000000001345fd3335882d08247
1c107a809cf6

0x0C to 0xa1b2c3d4, src 0x00000001, flags 0x01, counter 0x0000019900000002:
4d535354010c01000000000000000100000000a1b2c3d4000001990000000245000000000000
0000000000000000000000000014ea364ad6741e5caf670ca30cebf809
```

These are pinned by `TestSdiscVectors`.

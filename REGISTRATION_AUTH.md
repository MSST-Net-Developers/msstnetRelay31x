# Registration authentication (sreg v1)

Authenticates relay register/keepalive with the device's X25519 identity key,
so a device ID can no longer be registered by someone who does not hold its
private key. Relay side implemented in `sreg.go`. The Coordinator endpoint
and the client changes below are **not implemented yet**.

Same building blocks as secure discovery (SECURE_DISCOVERY.md): the relay's
static X25519 key, HKDF-SHA256, a truncated HMAC-SHA256 tag and time-based
counters. The HKDF salt differs, so sreg and sdisc keys are independent.

## Threat addressed

With unauthenticated `0x01`/`0x02` (last writer wins), anyone who can send UDP
to a relay can bind any device ID to their own address. They receive that
device's `0x0D`/`0x06`/`0x07` traffic (WireGuard ciphertext, so this is
denial of service rather than disclosure) until the device's next keepalive.
They can also point bindings at other relays to build forwarding loops.

With sreg, a binding made by `0x0E` cannot be moved except by another valid
`0x0E` for that device, and `register_auth: required` removes unauthenticated
registration entirely.

## Keys

```
shared = X25519(device_sk, relay_pk)
k_reg  = HKDF-SHA256(ikm  = shared,
                     salt = "msst-sreg-v1",
                     info = device_id (8 bytes BE) ‖ device_pk (32) ‖ relay_pk (32),
                     L    = 32)
```

`relay_pk` is the relay's `pub_key` from `GET /relays` (the same key as
sdisc). Reject an all-zero shared secret.

## Packet `0x0E` (SREG: register + keepalive)

Sent from the client's main socket (UDP 21031) to the relay, in place of
`0x01` (register) and `0x02` (keepalive):

```
"MSST" | ver=1 | type=0x0E | flags=0 | src_id=own ID | dst_id=0 | counter u64 | tag[16]
tag = HMAC-SHA256(k_reg, the 31 bytes before the tag)[0:16]
```

The datagram is exactly 47 bytes. The relay sends no reply.

`counter` follows the sdisc rules: `max(last + 1, now_ms << 16)`, strictly
increasing per relay. The relay accepts it only if it is within
`discovery.auth_max_clock_skew` (default 30 s) of its own clock and greater
than the last accepted counter from that device. It uses a separate replay
window from sdisc, so the two counters need not be shared.

## Relay behaviour

1. Malformed (wrong length, `dst_id` ≠ 0, invalid ID) → drop.
2. Look up the device key in the cache. On a miss, a background fetch is
   scheduled and the packet is dropped (`reg_drop{key_unknown}`).
3. Verify the tag (`reg_drop{auth}`), then the counter (`reg_drop{replay}`).
   Forged packets change no state.
4. Bind `src_id` → source address and mark the binding authenticated.
   A later `0x0E` from another address moves it (NAT rebinding, roaming).

`relay.register_auth` decides what happens to unauthenticated
`0x01`/`0x02`/`0x03`:

| Mode | Unauthenticated register/keepalive |
|------|------------------------------------|
| `optional` (default) | accepted, **except** for an ID whose live binding was made by `0x0E` (`reg_drop{unauth}`) |
| `required` | dropped (`reg_drop{unauth}`) |

Bindings expire after `relay.session_ttl` (120 s) without a valid
register/keepalive, as before. Once an authenticated binding expires, the ID
is open to `0x01` again in `optional` mode.

### Device key cache

Keys come from the Coordinator through `POST /relay/device-keys` (below).
- One worker sends batches of ≤ 256 IDs, at least 100 ms apart (≤ 10
  requests/s, within the Coordinator's per-IP limit together with heartbeats
  and room lookups).
- The X25519 work is done in the worker; the read loop only computes an HMAC.
- A key is refreshed after `relay.device_key_ttl` (10 min) and served for
  `relay.device_key_stale_ttl` (1 h) after the last successful fetch, so a
  Coordinator outage does not affect devices that already registered. **New**
  devices cannot register with `0x0E` while the Coordinator is unreachable.
- If the Coordinator stops returning a device, its key is removed on the
  next refresh.
- Bounds: `relay.device_key_max_entries` known keys (default 65536), 16384
  unknown/pending IDs, 4096 queued IDs. Unknown IDs are retried after 10 s.
  An ID is tracked only when a fetch can be queued for it, so spoofed random
  IDs cannot grow state beyond these bounds or exceed the fetch rate.

## Coordinator requirement (not implemented)

```
POST /relay/device-keys
X-Relay-Secret: <relay_secret>
{"device_ids": ["device-a1b2c3d4", ...]}        # ≤ 256

200 [{"device_id": "device-a1b2c3d4", "pub_key": "<base64 X25519>"}, ...]
```

- Omit unknown devices. Return the key pinned at device registration.
- 401 on a wrong secret. Serve over HTTPS.
- Pass the relay's `features` (sent on `POST /relay/register`, currently
  `["sdisc1","sreg1"]`) through in `GET /relays`.
- Enable `device_key_proof: required` (DEVICE_KEY_PROOF.md). Until then,
  whoever registers a device ID first at the Coordinator decides its key.
  sreg authenticates against that key.

## Client requirements (not implemented)

- Use `0x0E` instead of `0x01`/`0x02` with relays whose `/relays` entry lists
  `"sreg1"` in `features`. Keep `0x01`/`0x02` for other relays.
- After selecting a relay (and after every coordinator reconnect), send
  `0x0E` immediately, again about 1 s and 3 s later, then at the keepalive
  interval. The first packet may be dropped while the relay fetches the
  device key, and the relay sends no reply.
- Never log `k_reg`.

## Limitations

- **On-path attacker:** the tag cannot cover the source address (NAT
  rewrites it). An attacker who sees a device's `0x0E` and gets a copy to the
  relay first moves the binding to their own address until the next
  keepalive. The genuine packet is then rejected as a replay. Off-path
  attackers cannot do this. WireGuard keeps the traffic confidential, so the
  impact is denial of service.
- After a relay restart, replay state is lost. A captured `0x0E` can then be
  replayed while it is still within the clock-skew window, with the same
  on-path effect.
- `optional` mode protects only devices that use `0x0E`. Switch to
  `required` once every client does.
- Clients whose clocks are off by more than the skew cannot register with
  `0x0E`.

## Deployment order

1. Relay (this change): `register_auth: optional`. It reports
   `features: ["sdisc1","sreg1"]`.
2. Coordinator: `POST /relay/device-keys`, `features` in `/relays`,
   `device_key_proof: required` once clients send proofs.
3. Clients send `0x0E` to relays advertising `sreg1`.
4. Relays switch to `register_auth: required`.

## Test vectors

Device private key = 32 × `0x01`, relay private key = 32 × `0x02`, device
ID `0xa1b2c3d4` (public keys as in SECURE_DISCOVERY.md). Checked against an
independent Python (`cryptography`) implementation; pinned by
`TestSregVectors`.

```
k_reg  600586d9b33a5bcb970b6998524c7974ef368a4d2c48d4cdb649fe194840c2cc

0x0E, counter 0x0000019900000001:
4d535354010e0000000000a1b2c3d4000000000000000000000199000000019c3ba1a9cf8c539f28c897fba08e581d
```

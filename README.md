# MSST-Net Relay 3.1.x

UDP data-plane relay for MSST-Net Core 3.1.x and Coordinator 3.1.x. The
client contract is `msst-net-core-31x/docs/RELAY_REQUIREMENTS_3.1.md`.
3.0.x clients are not supported: plaintext data and unauthenticated
discovery are retired.

```bash
go build -o msstnetRelay31x .
./msstnetRelay31x -config config.yaml   # creates a default config (mode 0600) if missing
go vet ./... && go test -race ./...
```

## Packet handling

Single UDP socket (default `[::]:21031`), single read loop, synchronous
processing (preserves per-flow ordering). Header: `"MSST"|ver=1|type|flags|src_id u64|dst_id u64`.

| Type | Relay action | Checks |
|------|--------------|--------|
| 0x01 register, 0x02 keepalive, 0x03 punch | bind `src_id` → source address | ID in `1..0xFFFFFFFF`; address not unspecified/multicast/broadcast; table cap |
| 0x05 ping | echo datagram to sender | ≤ 64 bytes; global rate limit |
| 0x06 p2p ping | forward datagram unchanged to `dst_id` | `src_id` must be bound to the source address; dst registered; dst ≠ src; payload ≥ 12; global rate limit |
| 0x07 p2p pong | forward datagram unchanged to `dst_id` | dst registered; dst ≠ src; payload ≥ 12; global rate limit |
| 0x0D WireGuard | forward **whole datagram unchanged** to `dst_id` | dst registered and not expired; payload ≥ 32 (smallest WireGuard message); dst ≠ src. Sender need not be registered here |
| 0x0A / 0x0B sdisc register / data | authenticate, bind discovery address / fan out as 0x0C | see below and [SECURE_DISCOVERY.md](SECURE_DISCOVERY.md) |
| 0x04, 0x08, 0x09 (retired) | drop | counted as `drop{retired}` |

Version ≠ 1, bad magic, truncated and unknown types are dropped and counted.
Datagrams up to 65 507 bytes are accepted.

**Discovery** (always authenticated): parse → room peer list from
`GET /room/{id}/discovery-peers` (cached, fetched asynchronously; a miss
drops the packet while the list is fetched) → sender must be listed with a
public key → verify tag → counter fresh and increasing → (re)bind discovery
address. For data, then: global ingress limit → dedup (sender+packet, 3 s) →
per-sender limit (10/s) → fan-out to keyed peers registered at *this* relay
as 0x0C with the sender-verified flag set, capped by `max_fanout` and the
global egress budget. No bare IPv4 is ever sent.

## Trust model (what is and is not verified)

- **Discovery** is authenticated end to end through the relay (sdisc v1):
  only devices holding the private key that the Coordinator bound to their
  device ID can register a discovery address or inject into a room, and
  clients accept only relay-authenticated 0x0C.
- **Peer data** is WireGuard (0x0D): confidentiality and integrity are end to
  end between clients, and the relay forwards it without inspecting it.
- **Registration (0x01/0x02) is still unauthenticated.** `src_id` is a
  claim; anyone who can send UDP to the relay can register any device ID and
  divert that device's 0x0D/0x06/0x07 traffic until its next keepalive (last
  writer wins, needed for NAT rebinding). With WireGuard this is a denial of
  service, not a data leak. Closing it needs an sdisc-style tag on
  register/keepalive and a matching client change.
- **Relay forwarding loops.** 0x0D/0x06/0x07 are forwarded unchanged, so a
  frame sent to a client address that is in fact another relay is processed
  again there. Two relays pointed at each other are cut by the dst ≠ src
  check, and the relay's own address by the same check. Cycles through three
  or more relays need spoofed registrations from the relays' own addresses
  (IP spoofing). They are bounded for probes by the global probe budget and
  for 0x0D only by binding expiry (`session_ttl`). Authenticated
  registration would remove this too.
- Data senders are not required to be registered: clients deliberately send
  via the *destination's* relay.

## Coordinator interface

- `POST /relay/register {id,region,addr,pub_key}` (`pub_key`: the sdisc key;
  omitted only when discovery is disabled), `POST /relay/heartbeat {id}` every
  `heartbeat_interval` (10 s; Coordinator expires relays after 30 s), with
  `X-Relay-Secret: <control.relay_secret>` when set. 401 → secret mismatch;
  404 on heartbeat → re-register. Backoff 5 s → 5 min with jitter.
- `GET /room/{id}/discovery-peers` with `X-Relay-Secret`: `[{device_id, pub_key}]`.
- Forwarding never depends on the Coordinator being reachable; discovery
  needs the peer list.

## Configuration and limits

All limits are in `config.yaml` (see `config.go` for comments); unknown keys
are rejected. A 3.0.x `config.yaml` still loads; add
`control.relay_secret` if the Coordinator has `relay_secret` set. An
earlier 3.1.x config with `discovery.auth: off` or `optional` is rejected:
those modes no longer exist. `discovery.require_sender_in_room` is accepted
but ignored, because senders must always be room members.

| Key | Default | Rationale |
|-----|---------|-----------|
| `relay.max_sessions` | 65536 | bounded state |
| `relay.session_ttl` | 120s | client keepalive is 5–30 s (default 25 s) |
| `relay.ping_rate/burst` | 2000/4000 | bounds reflection to spoofed sources |
| `relay.probe_rate/burst` | 5000/10000 | bounds P2P probe forwarding and relay↔relay loops |
| `discovery.session_ttl` | 120s | client re-registers every 25 s |
| `discovery.sender_rate/burst` | 10/10 | 3.0.x per-device limit |
| `discovery.ingress_rate/burst` | 2000/4000 | global, applied to authenticated data packets |
| `discovery.egress_rate/burst` | 20000/40000 | global, counts each recipient |
| `discovery.max_fanout` | 256 | recipients per packet |
| `discovery.room_cache_*` | 5s / 30s / 4096 | refresh / serve-stale / rooms |
| `discovery.auth` | required | only `required` (or empty) |
| `discovery.auth_key_file` | relay_discovery.key | relay X25519 key, created 0600 |
| `discovery.auth_max_clock_skew` | 30s | counter freshness; `session_ttl` must be ≥ 2× |
| `log.stats_interval` | 60s | counters line; 0 disables |

Coordinator lookups are additionally limited to 10/s (burst 20) and 2
workers so the relay stays within the Coordinator's per-IP rate limit.

Observability is a periodic stats log line; there is no admin/HTTP
interface. Diagnostic logs that remote parties can trigger are rate-limited.

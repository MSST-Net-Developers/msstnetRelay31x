# MSST-Net Relay 3.1.x

UDP data-plane relay for MSST-Net. Wire-compatible with relay 3.0.x and
msst-net-client-core; registers with Coordinator 3.1.x.

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
| 0x04 data | send **payload only** to `dst_id`'s address | dst registered and not expired; non-empty; payload not itself an MSST packet; dst ≠ src |
| 0x05 ping | echo datagram to sender | ≤ 64 bytes; global rate limit |
| 0x06 p2p ping | forward datagram unchanged to `dst_id` | `src_id` must be bound to the source address; dst registered; dst ≠ src; payload ≥ 12; global rate limit |
| 0x07 p2p pong | forward datagram unchanged to `dst_id` | dst registered; dst ≠ src; payload ≥ 12; global rate limit |
| 0x08 discovery register | bind `src_id` → discovery address | as register, separate table |
| 0x09 discovery data | send bare IPv4 packet to other discovery peers of the room | see below |

Version ≠ 1, bad magic, truncated and unknown types are dropped and counted.

**Discovery** (`[room_len][room_id][ipv4]`): room ID `[A-Za-z0-9_-]{1,64}`,
IPv4 only → global ingress limit → dedup (sender+packet, 3 s) → per-sender
limit (10/s) → sender bound at source → peer list from
`GET /room/{id}/discovery-peers` (cached, fetched asynchronously) → sender must
be in that list (`require_sender_in_room`) → fan-out capped by `max_fanout` and
the global egress budget. Only peers registered at *this* relay receive
packets (as in 3.0.x). On a room-cache miss the packet is dropped while the
list is fetched; games re-broadcast periodically.

## Trust model (what is and is not verified)

The MSST relay protocol has **no sender authentication or integrity
protection**. `src_id` is a claim. Consequently:

- Anyone who can send UDP to the relay can register any device ID and
  redirect that device's relay traffic to themselves until the real client's
  next keepalive (last writer wins, as in 3.0.x; required for NAT rebinding).
- Data senders are not required to be registered: clients deliberately send
  via the *destination's* relay. The relay cannot verify who sent a packet.
- Payloads are forwarded opaquely; the relay does not inspect or decrypt them.
  Whether payloads are end-to-end encrypted is decided by the client, not the
  relay (client 3.0.x sends raw IP packets in DATA).

Fixing this requires a protocol change (e.g. Coordinator-issued relay tokens
or client-key-signed registrations) coordinated across client, Coordinator
and relay.

## Coordinator interface

- `POST /relay/register {id,region,addr}`, `POST /relay/heartbeat {id}` every
  `heartbeat_interval` (10 s; Coordinator expires relays after 30 s), with
  `X-Relay-Secret: <control.relay_secret>` when set. 401 → secret mismatch;
  404 on heartbeat → re-register. Backoff 5 s → 5 min with jitter.
- `GET /room/{id}/discovery-peers` (unauthenticated on Coordinator 3.1.x).
- Forwarding never depends on the Coordinator being reachable.

## Configuration and limits

All limits are in `config.yaml` (see `config.go` for comments); unknown keys
are rejected. A 3.0.x `config.yaml` loads unchanged; add
`control.relay_secret` if the Coordinator has `relay_secret` set.

| Key | Default | Rationale |
|-----|---------|-----------|
| `relay.max_sessions` | 65536 | bounded state |
| `relay.session_ttl` | 120s | client keepalive is 5–30 s (default 25 s) |
| `relay.ping_rate/burst` | 2000/4000 | bounds reflection to spoofed sources |
| `relay.probe_rate/burst` | 5000/10000 | bounds P2P probe forwarding and relay↔relay loops |
| `discovery.session_ttl` | 120s | client re-registers every 25 s |
| `discovery.sender_rate/burst` | 10/10 | 3.0.x per-device limit |
| `discovery.ingress_rate/burst` | 2000/4000 | global, covers spoofed sender IDs |
| `discovery.egress_rate/burst` | 20000/40000 | global, counts each recipient |
| `discovery.max_fanout` | 256 | recipients per packet |
| `discovery.room_cache_*` | 5s / 30s / 4096 | refresh / serve-stale / rooms |
| `log.stats_interval` | 60s | counters line; 0 disables |

Coordinator lookups are additionally limited to 10/s (burst 20) and 2
workers so the relay stays within the Coordinator's per-IP rate limit.

Observability is a periodic stats log line; there is no admin/HTTP
interface. Diagnostic logs that remote parties can trigger are rate-limited.

# MSST-Net Relay 3.1.x — technical reference

UDP data-plane relay for MSST-Net Core 3.1.x and Coordinator 3.1.x. The
client contract is `msst-net-core-31x/docs/RELAY_REQUIREMENTS_3.1.md`.
3.0.x clients are not supported: plaintext data and unauthenticated
discovery are retired.

The same program runs as an **official** relay (default; listed in
`GET /relays`) or as a **self-hosted** relay that rooms designate by its
connection link ([SELF_HOSTED.md](SELF_HOSTED.md)).

```bash
go build -o msstnetRelay31x .
./msstnetRelay31x -config config.yaml   # creates a default config (mode 0600) if missing
./msstnetRelay31x -config config.yaml -print-link   # print the connection link and exit (creates the relay key if missing)
go vet ./... && go test -race ./...
```

## Packet handling

Single UDP socket (default `[::]:21031`), single read loop, synchronous
processing (preserves per-flow ordering). Header: `"MSST"|ver=1|type|flags|src_id u64|dst_id u64`.

| Type | Relay action | Checks |
|------|--------------|--------|
| 0x01 register, 0x02 keepalive | bind `src_id` → source address | ID in `1..0xFFFFFFFF`; address not unspecified/multicast/broadcast; table cap. `register_auth: optional`: refused for an ID with a live 0x0E binding; `required`: dropped |
| 0x0E sreg (authenticated register/keepalive) | bind `src_id` → source address, marked authenticated | device key from the Coordinator (cached; miss → drop + fetch); tag; counter. See [REGISTRATION_AUTH.md](REGISTRATION_AUTH.md) |
| 0x05 ping | echo datagram to sender | ≤ 64 bytes; global rate limit |
| 0x0D WireGuard | forward **whole datagram unchanged** to `dst_id` | dst registered and not expired; payload ≥ 32 (smallest WireGuard message); dst ≠ src. Official: sender need not be registered here. Self-hosted: `src_id` must be registered at the source address (`drop{unregistered_src}`) |
| 0x0A / 0x0B sdisc register / data | authenticate, bind discovery address / fan out as 0x0C | see below and [SECURE_DISCOVERY.md](SECURE_DISCOVERY.md) |
| 0x03, 0x04, 0x06, 0x07, 0x08, 0x09 (retired) | drop | counted as `drop{retired}`. 0x06/0x07 are client-to-client only; the relay-path RTT is measured inside the tunnel (0x0D) |

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
- **Registration:** devices using sreg (`0x0E`, REGISTRATION_AUTH.md) hold
  bindings that only the key holder can move. Unauthenticated `0x01`/`0x02`
  remain accepted only in `register_auth: optional` (the default is
  `required`: every 3.1 client sends 0x0E). For devices still using them, `src_id` is a claim: anyone who
  can send UDP to the relay can divert their 0x0D traffic until
  their next keepalive (denial of service; WireGuard keeps the content
  confidential). `register_auth: required` closes this. Even with sreg, an
  on-path attacker who relays a captured `0x0E` first can move a binding
  until the next keepalive.
- **Relay forwarding loops.** 0x0D is forwarded unchanged, so a
  frame sent to a client address that is in fact another relay is processed
  again there. Two relays pointed at each other are cut by the dst ≠ src
  check, and the relay's own address by the same check. Cycles through three
  or more relays need spoofed registrations from the relays' own addresses
  (IP spoofing) and last until the bindings expire (`session_ttl`). With
  `register_auth: required` such registrations need the device's private
  key.
- Data senders are not required to be registered at an official relay:
  clients deliberately send via the *destination's* relay. A self-hosted
  relay forwards only from senders registered with it by 0x0E.

## Coordinator interface

- `POST /relay/register {id,region,addr,pub_key,features}` (`pub_key`: the
  relay key for sdisc and sreg; `features`: `["sdisc1","sreg1"]`), `POST /relay/heartbeat {id}` every
  `heartbeat_interval` (10 s; Coordinator expires relays after 30 s), with
  `X-Relay-Secret: <control.relay_secret>` (this relay's own secret) when set. 401 → secret mismatch;
  404 on heartbeat → re-register. Backoff 5 s → 5 min with jitter.
- `GET /room/{id}/discovery-peers` with `X-Relay-Secret`: `[{device_id, pub_key}]`.
- `POST /relay/device-keys {device_ids:[…≤256]}` with `X-Relay-Secret`:
  `[{device_id, pub_key}]`, for 0x0E.
- Self-hosted mode replaces the secret with challenge-response registration
  and a bearer token; see [SELF_HOSTED.md](SELF_HOSTED.md).
- Forwarding never depends on the Coordinator being reachable. Discovery
  needs the peer list, and a device's *first* 0x0E needs its key (cached keys
  are served for `device_key_stale_ttl` during outages).

## Configuration and limits

All limits are in `config.yaml` (see `config.go` for comments); unknown keys
are rejected. A 3.0.x `config.yaml` still loads; add
`control.relay_secret` if the Coordinator has `relay_secret` set. An
earlier 3.1.x config with `discovery.auth: off` or `optional` is rejected:
those modes no longer exist. `discovery.require_sender_in_room` is accepted
but ignored, because senders must always be room members; so are
`relay.probe_rate`/`probe_burst` (0x06/0x07 are no longer forwarded).

| Key | Default | Rationale |
|-----|---------|-----------|
| `relay.max_sessions` | 65536 | bounded state |
| `relay.session_ttl` | 120s | client keepalive is 5–30 s (default 25 s) |
| `relay.ping_rate/burst` | 2000/4000 | bounds reflection to spoofed sources |
| `relay.register_auth` | required | `required` / `optional` (unauthenticated 0x01/0x02); `required` needs `control.server_url`; must be `required` when self-hosted |
| `relay.mode` | official | `official` / `self_hosted` ([SELF_HOSTED.md](SELF_HOSTED.md)) |
| `relay.password` | (none) | self-hosted only; room owners must give it to designate the relay |
| `relay.require_room_password` | true | self-hosted only; Coordinator refuses rooms without a room password |
| `relay.device_key_ttl` / `_stale_ttl` | 10m / 1h | sreg key refresh / serve during Coordinator outage |
| `relay.device_key_max_entries` | 65536 | cached device keys |
| `discovery.session_ttl` | 120s | client re-registers every 25 s |
| `discovery.sender_rate/burst` | 10/10 | 3.0.x per-device limit |
| `discovery.ingress_rate/burst` | 2000/4000 | global, applied to authenticated data packets |
| `discovery.egress_rate/burst` | 20000/40000 | global, counts each recipient |
| `discovery.max_fanout` | 256 | recipients per packet |
| `discovery.room_cache_*` | 5s / 30s / 4096 | refresh / serve-stale / rooms |
| `discovery.auth` | required | only `required` (or empty) |
| `discovery.auth_key_file` | relay_discovery.key | relay X25519 key (sdisc and sreg), created 0600 |
| `discovery.auth_max_clock_skew` | 30s | sdisc/sreg counter freshness; both session TTLs must be ≥ 2× |
| `log.stats_interval` | 60s | counters line; 0 disables |

Coordinator lookups are additionally limited (room lists 10/s, burst 20, 2
workers; device keys ≤ 10 batched requests/s, 1 worker) so the relay stays
within the Coordinator's per-IP rate limit.

Observability is a periodic stats log line; there is no admin/HTTP
interface. Diagnostic logs that remote parties can trigger are rate-limited.

## License

MIT. See [LICENSE](LICENSE). Release binaries also include the third-party
software listed in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) (BSD-3-Clause,
MIT, Apache-2.0); ship that file with any binary you distribute and update
it when dependencies change (CI checks the module versions).

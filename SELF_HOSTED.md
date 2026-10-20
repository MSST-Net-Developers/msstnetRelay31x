# Self-hosted relays

A self-hosted relay is the same program as an official relay, run by anyone
for their own rooms. The Coordinator does not list it in `GET /relays`; a
room owner designates it when creating a room by pasting its connection
link, and the room's traffic then goes through it. Design and decisions:
`msst-net-core-31x/docs/ROOM_RELAY_3.1.md`; server-side items RR1–RR6 of
`ROOM_RELAY_SERVER_3.1.md` are implemented here (`selfhosted.go`,
`control.go`). The Coordinator side (CR2–CR5) is **not implemented yet**;
until it is, registration fails and is retried (forwarding is unaffected).

## Configuration

```yaml
node:
  addr: relay.example.com:7000      # public host:port; goes into the link
relay:
  bind: "[::]:7000"
  mode: self_hosted
  register_auth: required           # mandatory in this mode
  password: ""                      # optional relay password
  require_room_password: true       # default
discovery:
  auth_key_file: relay_discovery.key
control:
  server_url: https://coord.example.com   # must be https
  # relay_secret must not be set
```

The relay refuses to start in self-hosted mode if `register_auth` is not
`required` (otherwise anyone could register with `0x01` and use the relay
without the relay password), if `control.relay_secret` is set (official
secrets must not be copied to third-party machines), if `server_url` is not
https, or if `node.addr` is not a `host:port`. `node.id` and `node.region`
are not used.

Keep the config file mode 0600 when it holds a password; the relay warns
otherwise. The password is never logged; only its Argon2id verifier is
sent to the Coordinator.

## Connection link

Printed at startup and by `-print-link`:

```
msst-relay://<node.addr>#<base64url(relay public key), unpadded>[?pw=1]
```

`?pw=1` appears when `relay.password` is set, so the client asks for it. The
link carries the relay's public key; whoever runs another relay at the same
address cannot use it without the private key in `auth_key_file`.

## Registration with the Coordinator

1. `POST /relay/self-hosted/challenge {"pub_key"}` →
   `{"challenge_id", "server_pub"}`.
2. `POST /relay/self-hosted/register {"pub_key", "addr", "features",
   "require_room_password", "password_verifier"?, "proof": {"challenge_id",
   "mac"}}` → `{"relay_id", "token", "expires_at"}`.
3. `POST /relay/heartbeat` with `Authorization: Bearer <token>` every
   `control.heartbeat_interval` (10 s).

```
shared = X25519(relay_sk, server_pub)                  # all-zero rejected
k      = HKDF-SHA256(shared, salt = "msst-relay-keyproof-v1",
                     info = relay_pub ‖ server_pub, L = 32)
mac    = HMAC-SHA256(k, "msst-relay-keyproof-v1" ‖ challenge_id (16 raw bytes))

password_verifier = Argon2id(password, salt = "msst-relay-pw-v1" ‖ relay_pub,
                             t = 2, m = 19 MiB, p = 1, 32 bytes)
```

The token is held in memory only and never logged. A failed heartbeat (401
after a Coordinator restart or token expiry, or a network error) or a 401 on
any other Coordinator request made with the current token starts a new
challenge and registration, with backoff 5 s → 5 min. Registration errors
are logged with the Coordinator's `code` (e.g. `relay_unsupported`,
`key_proof_invalid`). Until registration succeeds the relay forwards as
usual, but no room can designate it.

Changing the password takes effect on restart (new verifier); rooms already
created keep working.

## Coordinator requests with the token

`GET /room/{id}/discovery-peers` and `POST /relay/device-keys` send
`Authorization: Bearer <token>` instead of `X-Relay-Secret`. The
Coordinator answers only for rooms that designated this relay:

- `discovery-peers` 403: the room's peer list is cleared and refetched
  after `room_cache_ttl`; its packets count as `drop{room_unknown}`.
- 401: re-registration is triggered; the request counts as failed.
- `device-keys` omits devices outside those rooms: `reg_drop{key_unknown}`.
- Before the first registration no requests are sent.

## Forwarding

- `0x0D` is forwarded only when the source address is the one `src_id` is
  currently registered at (by `0x0E`); otherwise it is dropped as
  `drop{unregistered_src}`. Members send through the room relay only while
  registered with it, so this does not affect them, and outsiders cannot use
  the relay as an open forwarder.
- `0x05` is echoed for anyone (rate-limited as before): clients check room
  relay health before registering.
- Everything else is as for official relays.

## What a self-hosted relay can and cannot do

It sees member device IDs, public addresses, traffic timing and discovery
payloads (not encrypted). It cannot read or forge WireGuard data. It can
drop or delay packets; clients then fall back to their preferred relay. Its
operator can forge discovery packets towards members of rooms that use it,
as any relay can for its users (SECURE_DISCOVERY.md, non-goals).

## Test vectors

Relay private key = 32 × `0x02`, Coordinator ephemeral key = 32 × `0x03`,
`challenge_id` = 16 × `0x11`. Pinned by `TestRelayKeyproofVector`,
`TestRelayPasswordVerifierVector` and `TestRelayLink`; they match
`ROOM_RELAY_SERVER_3.1.md`.

```
relay_pub   ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59
server_pub  5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22
mac         6fb95d31d70d3d66953314fb80497d8d21261b770235dd5dfa38e6f83cc373d3

password "relay secret":
verifier    7a8ef8ff39824ac7476ecbe76264a5b16cc0376d6e5f805bea3436060f3af9a3

link        msst-relay://relay.example.com:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk
```

## Deployment order

Coordinator CR2–CR5 first, then relays in self-hosted mode. Official relays
are unaffected; for CR1 they only need their own `control.relay_secret`.

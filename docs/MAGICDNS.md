# MagicDNS — .buddy Names

BuddyNet's MagicDNS lets you reach peers by name instead of virtual IP.
Add `--name alice` to your buddy and `ping alice.buddy` works from any peer
that runs `--dns`.

## Quick start

```bash
# Machine A — announces itself as "alice", runs the resolver
buddynet --role=buddy \
  --server VPS:51820 --server-key SERVER_KEY \
  --quic-handshake \
  --invite --forward 127.0.0.1:873 \
  --name alice --dns

# Machine B — announces itself as "bob", runs the resolver
buddynet --role=buddy \
  --server VPS:51820 --server-key SERVER_KEY \
  --quic-handshake \
  --join=TOKEN -L 127.0.0.1:9000 \
  --name bob --dns

# From B, once paired:
ping alice.buddy                 # resolves to alice's virtual IP (10.66.X.Y)
dig @127.0.0.153 alice.buddy    # direct query to the stub resolver
```

## Flags

| Flag | Env | Description |
|------|-----|-------------|
| `--name NAME` | `BUDDYNET_NAME` | Self-asserted hostname. Must be lowercase letters, digits, and hyphens; max 63 chars; no leading or trailing hyphen. Example: `alice`, `home-server`, `node1`. |
| `--dns` | `BUDDYNET_DNS=1` | Start the `.buddy` stub resolver on `127.0.0.153:53`. Requires `CAP_NET_BIND_SERVICE` or root. Fails gracefully with a `WARNING` if the bind is not permitted — the tunnel keeps running. |

## How it works

1. On `REGISTER`, the buddy sends its `--name` to the handshake server.
2. The server validates the name (DNS-label rules) and relays it verbatim in `PEER_LIST`.
3. The receiving buddy pins the name in `peers.json` (TOFU — first claim wins).
4. When `--dns` is set, a stub resolver listens on `127.0.0.153:53` and answers A queries for `<name>.buddy` with the peer's virtual IP.

## Name rules

- Lowercase letters (`a–z`), digits (`0–9`), hyphens (`-`) only.
- Must start and end with a letter or digit.
- Maximum 63 characters (one DNS label).
- The TLD is always `.buddy` — you only choose the label before it.

## Fingerprint fallback

Every peer is also reachable as `<fp8>.buddy`, where `<fp8>` is the first
8 hex characters of `SHA-256(pubkey)`. This works even for peers without
a `--name`, and is stable as long as the key does not change.

```bash
# Find a peer's fingerprint
buddynet --role=buddy --key /path/to/id.key identity \
  | sha256sum | cut -c1-8
# or just try to resolve it — the stub will log what names are in the table
dig @127.0.0.153 a3f2b1c0.buddy
```

## TOFU pinning and name collisions

The first name a key announces is pinned permanently:

- **Same key, different name later** → WARNING in the log, original name kept.
- **Two keys claim the same name** → first claimant keeps it; second gets an empty name (fingerprint-only) and a WARNING.

Pinned names survive restarts via `peers.json`.

## System resolver integration (Linux / systemd-resolved)

With `--dns`, BuddyNet tries to register the `.buddy` domain with
`systemd-resolved` so the system resolver routes `*.buddy` queries to
`127.0.0.153` automatically:

```bash
# What BuddyNet runs internally (you do not need to run this manually):
resolvectl dns lo 127.0.0.153
resolvectl domain lo ~buddy

# Verify:
resolvectl status lo
ping alice.buddy
```

If `resolvectl` is not available (non-systemd systems), a `NOTE` is logged.
You can then add `nameserver 127.0.0.153` to `/etc/resolv.conf` manually,
or query the stub directly with `dig @127.0.0.153 alice.buddy`.

On shutdown, BuddyNet reverts the resolvectl configuration.

## Permissions

Port 53 requires elevated privileges. Options:

```bash
# Option 1 — run as root (simplest for a systemd service)
ExecStart=/usr/local/bin/buddynet --role=buddy ... --dns

# Option 2 — grant the binary the capability
sudo setcap cap_net_bind_service=+ep /usr/local/bin/buddynet

# Option 3 — skip --dns, query the stub manually on a high port
# (not yet supported; planned for a future release)
```

Without sufficient permissions, `--dns` logs a `WARNING` and continues
without DNS — the tunnel itself is unaffected.

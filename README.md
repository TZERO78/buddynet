# BuddyNet

**One binary, three roles. A zero-config, end-to-end-encrypted overlay between
machines behind NAT — no port forwarding, no router config.**

BuddyNet gives every node a stable identity and a deterministic virtual IP, finds
peers through a tiny bootstrap server, and brings up a direct (hole-punched)
encrypted tunnel — falling back to a blind relay only when a direct path is
impossible. **[BuddyPeer](docs/BUDDYPEER.md)** — two buddies, one server — is the
v1 milestone: point `rsync`, `borg`, or `ssh` at a local socket and it travels
straight to your buddy.

```
buddynet --role=buddy       # ordinary peer; NAT is fine
buddynet --role=relay       # public IP; blindly forwards encrypted sessions
buddynet --role=handshake   # bootstrap/matchmaking server on a VPS
```

There is **no auto-detection** — you always set `--role`. Every binary carries
all three roles; in a buddy the relay and handshake code sit dormant as fallback.

## Quickstart (BuddyPeer: two sites, one VPS)

**1 — On the VPS,** run the bootstrap server and grab the key to pin:

```bash
buddynet --role=handshake --key /var/lib/buddynet/id.key
buddynet --role=handshake --key /var/lib/buddynet/id.key identity   # → SERVER_KEY
```

**2 — Inviter** (e.g. the machine being backed up *to*, running an rsync daemon):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --invite -forward 127.0.0.1:873
# prints a one-time TOKEN, then waits for your buddy to join
```

**3 — Joiner** (the machine doing the backup):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --join=TOKEN -L 127.0.0.1:9000 &
rsync -a /data/ rsync://localhost:9000/backup/
```

That's it — an end-to-end-encrypted, NAT-traversed tunnel carrying plain rsync.
Check the link any time with `--status`.

## How it works

- **Identity = address.** Each node has one Ed25519 key; its virtual IP is
  `10.66.0.X` where `X = SHA-256(pubkey)[0]`. No DHCP, nobody assigns IPs.
- **Signed matchmaking.** The handshake server learns peers' public endpoints,
  pairs two that share a token, and hands back a **signed** `PEER_LIST`. No
  tunnel data ever flows through it.
- **Fallback chain.** Direct P2P → known relay → handshake-as-relay → cached
  peer (works even if the server is offline).
- **Blind relay.** Buddies run their own QUIC/TLS end to end; a relay only
  forwards the encrypted packets, keyed by an opaque session token. It sees
  virtual IPs and ciphertext, never content.
- **QUIC now, WireGuard later.** The data plane sits behind a `Transport`
  interface; v1 ships QUIC (TLS 1.3), v2 can drop in WireGuard unchanged.

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** and
**[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Security

- Pin the server with `--server-key` and your buddy with `--peer-key` (each
  buddy prints its identity at startup). Without a pin, trust-on-first-use
  records the buddy key and refuses later changes (SSH-style).
- The token is a **bearer secret** — keep it off the command line (use a `0600`
  file or `BUDDYNET_TOKEN`).
- Optional allowlist (approval mode) on the handshake server, with sealed
  enrollment codes so a code can't be read off the wire.

## Build & run

```bash
go build -ldflags="-s -w" -o buddynet ./cmd/buddynet
go test ./...
```

Runs on Linux, macOS, Windows, and ARM64 (Raspberry Pi, Unraid). Zero external
runtime dependencies. Server side via Docker:

```bash
docker compose -f deployments/docker-compose.yml up -d --build
```

On a VPS you can run both server roles in one process:
`buddynet --role=handshake,relay`. On **Unraid**, the buddy role ships as a
plugin — see [unraid/BuddyNet](unraid/BuddyNet/README.md).

## Status

v1 / BuddyPeer (two peers) is implemented and tested end to end. Multi-peer mesh,
peer-to-peer gossip, and the WireGuard transport are the v2 roadmap — additive on
the v1 wire format, virtual IPs, and fallback chain.

## License

MIT — see [LICENSE](LICENSE). With thanks to the open-source projects BuddyNet
builds on; see [CREDITS.md](CREDITS.md).

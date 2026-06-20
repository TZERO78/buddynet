# BuddyNet

**One binary, three roles. A zero-config, end-to-end-encrypted overlay between
machines behind NAT — no port forwarding, no router config.**

BuddyNet gives every node a stable identity and a deterministic virtual IP, finds
peers through a tiny bootstrap server, and brings up a direct (hole-punched)
encrypted tunnel — falling back to a blind relay only when a direct path is
impossible. Point `rsync`, `borg`, or `ssh` at a local socket and it travels
straight to your buddy — and a single node can hold **many tunnels at once**
([MultiPeer](docs/PEERS.md)), routing to each buddy by name. The coordination
server is a VPS *you* own, and it never sees your traffic. Your MultiPeer is
ready for the party.

```
buddynet --role=buddy       # ordinary peer; NAT is fine
buddynet --role=relay       # public IP; blindly forwards encrypted sessions
buddynet --role=handshake   # bootstrap/matchmaking server on a VPS
```

There is **no auto-detection** — you always set `--role`. Every binary carries
all three roles; in a buddy the relay and handshake code sit dormant as fallback.

## Quickstart (two sites, one VPS)

**1 — On the VPS,** run the bootstrap server with `--quic-handshake` and grab
the key to pin:

```bash
buddynet --role=handshake,relay \
    --key /var/lib/buddynet/id.key \
    --relay-endpoint vps.example:51821 \
    --quic-handshake
buddynet --role=handshake --key /var/lib/buddynet/id.key identity   # → SERVER_KEY
```

> **Always use `--quic-handshake`.** Without it the pairing token travels in
> cleartext over the public internet. Set it identically on the server and on
> every buddy. See [docs/OPERATIONS.md](docs/OPERATIONS.md#quic-control-plane---quic-handshake).

**2 — Inviter** (e.g. the machine being backed up *to*, running an rsync daemon):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake \
    --invite --forward 127.0.0.1:873
# prints a one-time TOKEN, then waits for your buddy to join
```

**3 — Joiner** (the machine doing the backup):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake \
    --join=TOKEN -L 127.0.0.1:9000 &
rsync -a /data/ rsync://localhost:9000/backup/
```

That's it — an end-to-end-encrypted, NAT-traversed tunnel carrying plain rsync.
Check the link any time with `--status` — it exits `0` reachable, `3`
unreachable, `4` offline, `5` untrusted, `1` local error (see
[docs/TWO-BUDDIES.md](docs/TWO-BUDDIES.md#checking-the-link)).

## How it works

- **Identity = address.** Each node has one Ed25519 key; its virtual IP is
  `10.66.X.Y` where `X,Y = SHA-256(pubkey)[0:2]`. No DHCP, nobody assigns IPs.
- **Signed matchmaking.** The handshake server learns peers' public endpoints,
  pairs two that share a token, and hands back a **signed** `PEER_LIST`. No
  tunnel data ever flows through it.
- **Encrypted control plane.** Use `--quic-handshake` (server + every buddy) to
  run matchmaking over QUIC/TLS 1.3 — the pairing token stays encrypted in
  transit. Plain UDP is available for constrained environments but sends the token
  in cleartext. QUIC also validates source addresses structurally (no extra
  round-trip), so the server is never a reflector.
- **Fallback chain.** Direct P2P → known relay → handshake-as-relay → cached
  peer (works even if the server is offline).
- **Blind relay.** Buddies run their own QUIC/TLS end to end; a relay only
  forwards the encrypted packets, keyed by an opaque session token. It sees
  virtual IPs and ciphertext, never content.
- **QUIC now, WireGuard later.** The data plane sits behind a `Transport`
  interface; v1 ships QUIC (TLS 1.3), v2 can drop in WireGuard unchanged.
- **Lazy tunnel (`--lazy`).** The `-L` TCP listener binds immediately; the
  QUIC tunnel is established on demand when the first connection arrives.
  Useful for backup tools (rsync, kopia) that are invoked infrequently.

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** and
**[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Documentation

| Doc | What it covers |
|-----|---------------|
| [docs/TWO-BUDDIES.md](docs/TWO-BUDDIES.md) | The two-buddy setup, end to end |
| [docs/PEERS.md](docs/PEERS.md) | **MultiPeer** (many buddies): `--peers-file` manifest, `--vip-listen` routing, `peers` subcommands, live reload |
| [docs/INVITE.md](docs/INVITE.md) | Invite/join flow, SAS, session secrets, TOFU, re-auth |
| [docs/APPROVAL.md](docs/APPROVAL.md) | Server-side client allowlist and enrollment codes |
| [docs/BUDDYDNS.md](docs/BUDDYDNS.md) | `.buddy` names and the stub resolver |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | QUIC, IP allowlists, relay setup, lazy tunnel, log schema |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and package map |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Wire format and message types |
| [SECURITY.md](SECURITY.md) | Threat model and trust hierarchy |

## Security

- Pin the server with `--server-key` and your buddy with `--peer-key` (each
  buddy prints its identity at startup). Without `--peer-key`, trust-on-first-use
  is used — but on that first connect both sides show a **Short Authentication
  String**: a 6-character code (e.g. `K7QX2M`) derived from both keys and the
  live TLS session. Read it to your buddy over a trusted channel (phone, Signal);
  confirm only if they match. A man in the middle makes the two sides show a
  *different* code, so you catch it before any key is trusted. After that the key
  is pinned and checked silently. For daemons set `--no-interactive` and pin with
  `--peer-key` (an unknown key is then refused, never learned blind).
- The token is a **bearer secret** — keep it off the command line (use a `0600`
  file or `BUDDYNET_TOKEN`).
- Optional allowlist (approval mode) on the handshake server, with sealed
  enrollment codes so a code can't be read off the wire.
- The bootstrap server is hardened against abuse: source-address validation,
  global + per-source rate limits, bounded in-memory state, and replay rejection
  in approval mode. `--quic-handshake` (recommended default) encrypts the control
  plane and validates source addresses without a cookie round-trip.
- Restrict **who** can reach a server role with `--allow-cidr` (comma-separated
  CIDRs; relay **and** handshake). Disallowed sources are dropped before any
  crypto, so a private relay/handshake needs no separate firewall.
- A direct tunnel isn't revocable centrally — the server isn't in the data path.
  `--reauth-interval` periodically rebuilds the tunnel so a revocation or token
  rotation takes effect within the interval (off by default; see
  [SECURITY.md](SECURITY.md#revoking-access)).

The full threat model — what BuddyNet protects against, the trust hierarchy, and
its honest limits — is in **[SECURITY.md](SECURITY.md)**.

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

## Verifying a download

Release binaries are signed with [Sigstore](https://www.sigstore.dev/) (keyless
`cosign`). Each `buddynet-<os>-<arch>` ships a `.bundle` (signature + certificate
+ transparency-log proof) alongside a `.sha256`. Verify provenance before running:

```bash
cosign verify-blob --bundle buddynet-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github.com/TZERO78/buddynet' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  buddynet-linux-amd64
# -> Verified OK
```

Each release also carries an SPDX SBOM (`buddynet-<tag>-sbom.spdx.json`).
(Releases up to v1.1.0 used separate `.sig`/`.pem` files; v1.1.2 onward uses the
single `.bundle`.)

## Status

The two-buddy setup is implemented and tested end to end. **MultiPeer** (many
buddies at once — `--peers-file`, per-buddy VIP routing, live reload) is built
and lab-validated for the v2.1 line. Peer-to-peer gossip and the WireGuard
transport remain on the v2 roadmap — all additive on the v1 wire format, virtual
IPs, and fallback chain.

## License

MIT — see [LICENSE](LICENSE). With thanks to the open-source projects BuddyNet
builds on; see [CREDITS.md](CREDITS.md).

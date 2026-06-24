# BuddyNet

[![CI](https://github.com/TZERO78/buddynet/actions/workflows/ci.yml/badge.svg)](https://github.com/TZERO78/buddynet/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Latest release](https://img.shields.io/github/v/release/TZERO78/buddynet?sort=semver)](https://github.com/TZERO78/buddynet/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pentest: 14/14 defenses hold](https://img.shields.io/badge/pentest-14%2F14%20defenses%20hold-brightgreen)](lab/pentest/README.md)

> **Self-hosted P2P overlay. One binary. Your VPS coordinates — but never sees —
> your traffic. No Tailscale account needed.**

![BuddyNet deployment walkthrough — the VPS runs the coordinator, machine A mints a one-time invite, machine B joins behind its own NAT, and a direct hole-punched tunnel comes up](media/deploy-demo.gif)

<sup>Stand it up in three steps, live: the VPS runs the coordinator (`--role=handshake,relay`), machine A mints a one-time invite, machine B joins behind its own NAT, and the tunnel is `via="direct P2P"` — hole-punched, no port-forwarding, no traffic through the server. Reproduce: `lab/demo-deploy.sh`.</sup>

BuddyNet gives every node a stable identity and a deterministic virtual IP, finds
peers through a tiny bootstrap server, and brings up a direct (hole-punched)
encrypted tunnel — falling back to a blind relay only when a direct path is
impossible. Point `rsync`, `borg`, or `ssh` at a local socket and it travels
straight to your buddy — and a single node can hold **many tunnels at once**
([MultiPeer](docs/PEERS.md)), routing to each buddy by name. The coordination
server is a VPS *you* own, and it never sees your traffic.

```
buddynet --role=buddy       # ordinary peer; NAT is fine
buddynet --role=relay       # public IP; blindly forwards encrypted sessions
buddynet --role=handshake   # bootstrap/matchmaking server on a VPS
```

There is **no auto-detection** — you always set `--role`. Every binary carries
all three roles; in a buddy the relay and handshake code sit dormant as fallback.

## Why BuddyNet?

| | BuddyNet | Tailscale | Netbird | WireGuard |
|---|---|---|---|---|
| Coordination server | **Your VPS** | Tailscale Inc. | Self-hostable | None |
| Traffic through server | ❌ Never | ❌ Never | ❌ Never | N/A (no server) |
| Zero-config NAT traversal | ✅ | ✅ | ✅ | ❌ Manual |
| One binary, all roles | ✅ | ❌ | ❌ | ✅ |
| Sealed token on wire | ✅ v2.2 | N/A | N/A | N/A |
| Supply chain (cosign+SBOM) | ✅ | ✅ | ❌ | N/A |
| Unraid plugin | ✅ | ✅ | ❌ | ❌ |
| Live pentest results | ✅ [in repo](lab/pentest/README.md) | ❌ | ❌ | N/A |

> **BuddyNet is not a mesh VPN.**
> It is built for small, trusted groups of up to **48 peers**. If you need more
> than 48 simultaneous connections, use a solution designed for large-scale
> meshes — that is deliberately not what BuddyNet aims to be.

## What you need

BuddyNet needs **one publicly reachable node** to do the matchmaking (the
`handshake` role) and to act as a blind `relay` when a direct P2P path can't be
punched. That node needs a **stable, public IP address** — IPv4, IPv6, or both —
so the buddies can always find it.

You have two ways to provide it:

- **A small VPS** with a fixed public IP. The usual setup: run
  `--role=handshake,relay` on a cheap VPS *you* own. It coordinates and relays
  ciphertext only — it never sees your traffic. This is the
  [Quickstart](#quickstart-two-sites-one-vps) below.
- **Your own connection, if it has a fixed public IP** (no CGNAT). Then you don't
  need a VPS at all — the machine on that line takes the `handshake` and `relay`
  roles itself, and your other buddies connect to it.

The **buddies** themselves can sit behind ordinary NAT — that's the whole point.
Only the coordinating node needs to be reachable. If your line is behind
**CGNAT** or only has a dynamic address, a VPS is the simpler option. (Dynamic
public IPs can work with a DNS name that tracks the address, but that's on you to
keep current.)

## Quickstart (two sites, one VPS)

**1 — On the VPS,** run the bootstrap server with `--quic-handshake` and grab the
key to pin:

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
    --quic-handshake --invite --forward 127.0.0.1:873
# prints a one-time TOKEN, then waits for your buddy to join
```

**3 — Joiner** (the machine doing the backup):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake --join=TOKEN -L 127.0.0.1:9000 &
rsync -a /data/ rsync://localhost:9000/backup/
```

That's it — an end-to-end-encrypted, NAT-traversed tunnel carrying plain rsync.
Check the link any time with `--status` — it exits `0` reachable, `3`
unreachable, `4` offline, `5` untrusted, `1` local error (see
[docs/TWO-BUDDIES.md](docs/TWO-BUDDIES.md#checking-the-link)).

## MultiPeer — one hub, many buddies

One node can hold **many tunnels at once** ([`--peers-file`](docs/PEERS.md)):
each buddy is pinned by key, reachable by name via BuddyDNS (`<name>.buddy →
10.66.X.Y`), and self-managed with the `peers` CLI — `list`, `add` (invite), and
`remove` (revoke, drops the manifest entry **and** the session). No central
authority: throw one buddy out and the rest keep tunneling, untouched.

A node maintains **up to 48 buddies** — a deliberate design limit for a personal
overlay, enforced fail-closed (see [docs/PEERS.md](docs/PEERS.md)). For a larger
mesh, use a solution built for that.

![BuddyNet MultiPeer demo — one hub holding five buddy tunnels: list them, reach them by name via BuddyDNS, revoke one, the rest keep tunneling](media/multipeer-demo.gif)

<sup>One hub, five buddies (`bob alice steven markus sandra`) — `peers list`, reach a buddy by name (BuddyDNS), revoke one, and the other four keep tunneling. Reproduce: `lab/demo.sh`.</sup>

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
- **QUIC by default, kernel WireGuard opt-in.** The default data plane is QUIC
  (TLS 1.3). With `--wireguard` (Phase 3, Linux + `NET_ADMIN`) the tunnel runs over
  kernel WireGuard instead and the partner is reachable natively at its VIP — same
  control plane, same fallback chain. See **[docs/WIREGUARD.md](docs/WIREGUARD.md)**.
- **Lazy tunnel (`--lazy`).** The `-L` TCP listener binds immediately; the
  QUIC tunnel is established on demand when the first connection arrives.
  Useful for backup tools (rsync, kopia) that are invoked infrequently.

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** and
**[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

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

> **Live-pentested (by us).** The repository includes a
> [structural attack tool and full results](lab/pentest/README.md) — 16 tests, 14
> defenses verified against a live lab instance, 1 N/A, 1 low finding (stale VIP
> after `kill -9`, fixed in v2.2.0). No critical or high findings. This is our own
> structural testing, **not** an independent third-party audit — bugs can always
> remain. Found one? Please open an issue; we're grateful for every report.

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
| [lab/pentest/README.md](lab/pentest/README.md) | Red-team playbook + dated pentest report |

## Build & run

```bash
go build -ldflags="-s -w" -o buddynet ./cmd/buddynet
go test ./...
```

Runs on Linux, macOS, Windows, and ARM64 (Raspberry Pi, Unraid). A deliberately
small, pinned dependency set (`quic-go`, `miekg/dns`, `golang.org/x/crypto`),
gated by `govulncheck` in CI. Server side via Docker:

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

## Status & Roadmap

The two-buddy setup is implemented and tested end to end. **MultiPeer** (many
buddies at once — `--peers-file`, per-buddy VIP routing, live reload) is built
and lab-validated for the v2.1 line. A **kernel-WireGuard data plane**
(`--wireguard`, direct + relay + MultiPeer) is built and lab-validated on the
`phase3/wireguard` integration branch — opt-in, not yet in a tagged release
(see [docs/WIREGUARD.md](docs/WIREGUARD.md)). Peer-to-peer gossip remains
deferred. Everything is additive on the v1 wire format, virtual IPs, and fallback
chain.

**Security posture**

- **v2.2.0: live pentested by us — 14/14 applicable defenses verified, no
  critical/high findings** (our own structural testing, not an independent audit).
  Full report: [lab/pentest/README.md](lab/pentest/README.md).
- `govulncheck` in CI, Dependabot for dependency updates.
- cosign keyless signing + SPDX SBOM on every release.

## License

MIT — see [LICENSE](LICENSE). With thanks to the open-source projects BuddyNet
builds on; see [CREDITS.md](CREDITS.md).

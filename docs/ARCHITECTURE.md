# BuddyNet Architecture

BuddyNet is one binary that runs in one of three explicit roles. There is **no
auto-detection** — the operator always sets `--role`. Every binary contains all
three roles; in a buddy the relay and handshake code sit dormant as fallback.

```
                 ┌─────────────────────────┐
                 │  handshake  (VPS)        │   matchmaking only:
                 │  REGISTER → PEER_LIST     │   learns endpoints, pairs
                 │  signs every roster       │   peers, signs, steps out
                 └────────────┬──────────────┘
            REGISTER /        │        \ REGISTER
            PEER_LIST        │         \  PEER_LIST
                 ┌────────────┘          └────────────┐
                 ▼                                    ▼
        ┌────────────────┐   direct (hole-punch)  ┌────────────────┐
        │   buddy A      │◀══════════════════════▶│   buddy B      │
        │ vip 10.66.x.x  │   QUIC / TLS 1.3       │ vip 10.66.y.y  │
        └───────┬────────┘                        └────────┬───────┘
                │          if direct fails:                │
                │      ┌────────────────────────┐          │
                └─────▶│  relay  (public IP)     │◀─────────┘
                       │  blind: forwards QUIC   │
                       │  packets, never content │
                       └────────────────────────┘
```

## Roles

| Role | Needs | Job |
|---|---|---|
| `buddy` | nothing (NAT is fine) | Find the partner, bring up the tunnel along the fallback chain, forward TCP. |
| `relay` | public IP | Blindly forward encrypted datagrams between two session legs. |
| `handshake` | public IP | Learn peer endpoints, pair peers by token, hand back a **signed** `PEER_LIST`. No data flows through it. |

A node may run **several roles at once**, comma-separated:
`--role=handshake,relay` runs both in one process, each on its own port (the
relay defaults to `:51821`, or set `--relay-listen`). This is the usual VPS
setup — one box, bootstrap + relay. Roles are still always explicit; combining
them is opt-in, never auto-detected.

## Identity & the virtual IP

Each node holds one long-term **Ed25519** key. That single key is:

- its **identity** (pinned by buddies),
- the key of its **self-signed TLS cert** (so the QUIC peer is authenticated by
  key, not by any CA), and
- the seed of its **virtual IP**.

The virtual IP is a pure function of the public key — no DHCP, no server assigns
it:

```
10.66.X.Y   where  X = SHA-256(pubkey)[0], Y = SHA-256(pubkey)[1]
            (10.66.0.0 and 10.66.255.255 are folded off the reserved
             network/broadcast addresses)
```

Two nodes that know each other's public key already agree on each other's
virtual IP, and a roster that claims an inconsistent IP is rejected. See
[`internal/crypto/keys.go`](../internal/crypto/keys.go).

## The fallback chain (inside every buddy)

A buddy tries paths in order, cheapest and most private first
([`internal/relay/fallback.go`](../internal/relay/fallback.go)):

1. **Direct P2P** — hole-punch to the partner's live candidates, run QUIC
   straight over the punched UDP path. No third party in the data path.
2. **Known relay** — a relay the handshake server offered for this pair.
3. **Handshake-as-relay** — the bootstrap server acting as a relay of last
   resort (only if the VPS also runs `--role=relay` and advertises it with
   `--relay-endpoint`).
4. **Cached peer** — the partner's last-known endpoints from `peers.json`,
   tried when the handshake server was unreachable, so a pair that has met
   before can reconnect with **no server in the loop**.

## Transport seam (QUIC now, WireGuard later)

The data plane is hidden behind a small interface
([`internal/tunnel/transport.go`](../internal/tunnel/transport.go)):

```go
type Transport interface {
    Listen(ctx) (Session, error)
    Dial(ctx, endpoint string) (Session, error)
    Close() error
}
```

- **v1 ships `QUICTransport`** — TLS 1.3, reliable, ordered, multiplexed. Already
  end-to-end encrypted, and relay-blind (a relay sees only QUIC packets).
- **v2 can drop in `WireGuardTransport`** — same interface, ChaCha20-Poly1305
  data plane — without the roles above it changing a line. The seam is compiled
  today as an inert placeholder ([`wireguard.go`](../internal/tunnel/wireguard.go)).

A QUIC `Session` multiplexes streams (control / data / keepalive), so one
encrypted connection carries everything.

## Why the relay stays blind

The buddies run **their own** end-to-end QUIC/TLS between each other. A relay
only forwards the resulting UDP datagrams between two NAT-bound addresses keyed
by a session token; it never terminates the TLS and so never sees plaintext —
only virtual IPs and ciphertext. See [PROTOCOL.md](PROTOCOL.md) for the bind
handshake.

## Handshake transport (UDP or QUIC)

The matchmaking control plane (`REGISTER` → `PEER_LIST`) runs over one of two
transports, chosen with `--quic-handshake` and set the **same** on the server and
every buddy. Both validate the source address before the server does any work, so
neither can be turned into a reflector; they differ only in how:

- **Plain UDP + cookie (default).** A `REGISTER` without a valid cookie is
  answered only with a small `COOKIE` challenge (`HMAC(subkey, epoch‖src-IP)`,
  smaller than the request); the buddy echoes it on its next `REGISTER`. A
  spoofed source never receives the challenge, so it can never be answered. No
  TLS certificate, and the buddy's single UDP socket is untouched — so hole
  punching and the peer tunnel are unaffected.
- **QUIC (`--quic-handshake`).** The exchange rides QUIC, whose handshake
  validates the address itself (no cookie needed). The server presents its
  identity cert; the buddy pins it by `--server-key`. The buddy runs the QUIC
  control connection on its **shared** socket and closes it before punching, so
  the same NAT mapping still carries the tunnel.

See the `REGISTER` section of [PROTOCOL.md](PROTOCOL.md) for the wire details.

## Security posture

- **Signed rosters.** The handshake server signs every `PEER_LIST` over
  `(token, ts, peers)`; buddies pin the server key and verify, so a man in the
  middle on the control path cannot inject or alter peers.
- **Pinned peers.** A buddy pins its partner with `--peer-key`, or learns it
  trust-on-first-use (SSH-style) and refuses later changes. On first contact (no
  pin) both ends show a **Short Authentication String** bound to the live TLS
  session; the humans compare it out of band, so a man in the middle is caught
  before the key is trusted.
- **Ephemeral pairing secret.** `--invite`/`--join` use a one-time invite token;
  after first pairing both ends derive a long-lived rendezvous **session secret**
  from the channel binding (never transmitted) and reconnect with that. See
  [SECURITY.md](../SECURITY.md) for the full threat model.
- **Bounded server memory.** Hard caps (`maxTokens`, two ids per token,
  capped candidates) bound memory even under spoofed source addresses; the
  attacker-growable approval-mode maps are capped and pruned.
- **Rate-limited listeners.** A global + per-source token bucket gates each
  datagram before any parsing or crypto, so a flood is dropped cheaply and the
  per-packet work stays bounded. The relay rate-limits binds per source and caps
  legs per source IP.
- **No reflection.** The handshake server validates the source address (UDP
  cookie or QUIC) before emitting a `PEER_LIST`; the relay only ever replies to an
  address it has just heard a valid bind from. Neither is a usable amplifier.
- **Replay-resistant registrations.** In approval mode a bounded cache drops
  repeated registration signatures seen within the freshness window.

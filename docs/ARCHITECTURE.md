# BuddyNet Architecture

**In one paragraph.** Two machines want to talk. Each one registers with a small
**handshake server** that you run; the server learns where they currently are on
the internet, notices that they share a pairing token, and hands each one a
signed list containing the other. From then on the two machines talk **directly**
to each other, encrypted end to end — the handshake server carries none of that
traffic. If a direct path cannot be established (some NATs simply will not
cooperate), they fall back to a **relay**, also yours, which forwards the
encrypted packets without being able to read them.

That fallback is not free of information: a relay necessarily sees that *some*
session exists, when it runs and how many bytes cross it. It does not see the
content, the identities behind it, or which of your buddies is which — a bind
carries an opaque, server-chosen session id and a one-attempt ephemeral key,
nothing durable. A direct tunnel gives the relay nothing at all, because it is
not in the path.

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
| `buddy` | nothing (NAT is fine) | Find each partner, bring up a tunnel along the fallback chain (one per buddy), forward TCP. |
| `relay` | public IP | Blindly forward encrypted datagrams between two session legs, for sessions a named handshake server authorised. |
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
3. **Handshake-as-relay** — the handshake server acting as a relay of last
   resort (only if the VPS also runs `--role=relay` and advertises it with
   `--relay-endpoint`).
4. **Cached peer** — the partner's last-known endpoints from `peers.json`,
   tried when the handshake server was unreachable, so a pair that has met
   before can reconnect with **no server in the loop**.

## Many buddies at once (MultiPeer)

The fallback chain above brings up **one** tunnel to **one** partner. A buddy can
hold **many at the same time**: list each buddy's pinned key in a manifest
(`--peers-file`) and a supervisor
([`internal/role/supervisor.go`](../internal/role/supervisor.go)) runs one
independent worker per buddy — each with its own fallback chain, its own
reconnect/backoff, and its own per-peer rendezvous session secret. One buddy
failing, being revoked (`peers remove`), or reconnecting never touches the
others. `--vip-listen` then binds each connected buddy's virtual IP on the
loopback interface ([`internal/vip`](../internal/vip), via netlink) so
`name.buddy:port` routes to the right buddy's tunnel. The manifest is reconciled
live on `SIGHUP`. See [OPERATIONS.md](OPERATIONS.md).

## Data plane: QUIC streams, or kernel WireGuard

The **default** data plane is hidden behind a small interface
([`internal/tunnel/transport.go`](../internal/tunnel/transport.go)):

```go
type Transport interface {
    Listen(ctx) (Session, error)
    Dial(ctx, endpoint string) (Session, error)
    Close() error
}
```

- **`QUICTransport`** — TLS 1.3, reliable, ordered, multiplexed. Already
  end-to-end encrypted, and relay-blind (a relay sees only QUIC packets). A QUIC
  `Session` multiplexes streams (control / data / keepalive), so one encrypted
  connection carries `-L`/`-forward`/`--vip-listen`.

- **Kernel WireGuard (`--wireguard`, Phase 3)** — an **opt-in second data plane**,
  *not* a `Transport` implementation. It does not expose streams: it brings up a
  kernel WireGuard interface (`bnet0`, …, one per buddy) so the partner is reachable
  **natively at its VIP**. It reuses the entire control plane and the same
  direct→relay fallback (the blind relay forwards the encrypted WireGuard packets as
  it forwards QUIC). Built over raw netlink in [`internal/wg`](../internal/wg) +
  [`internal/role/wgpath.go`](../internal/role/wgpath.go). See
  **[WIREGUARD.md](WIREGUARD.md)**.

## Why a relay is authorized but still blind

Two requirements that sound opposed: a relay must not serve strangers (it carries
the operator's bandwidth, and a stranger can hoard the capacity the pair needs),
and it must not learn who talks to whom.

A **ticket** satisfies both. The handshake server signs a short-lived permit for
each paired buddy; the relay verifies it with the server's public key. It learns
*that* the session was authorised — not who is in it. The alternative designs were
rejected for exactly this reason: a buddy list on the relay would need durable
identities in the bind (and would put runtime state on a server), and an
`--relay-open` switch would end up in production.

The permit is bound to an ephemeral key the buddy mints per attempt and must sign
with, so it is not a bearer token: capturing it, or the whole bind, gains nothing.
The relay holds only a **public** key — it can withhold service, never authorise a
session. Full format in [PROTOCOL.md](PROTOCOL.md), operator setup in
[OPERATIONS.md](OPERATIONS.md).

## Why the relay stays blind

The buddies run **their own** end-to-end QUIC/TLS between each other. A relay
only forwards the resulting UDP datagrams between two NAT-bound addresses keyed
by a session token; it never terminates the TLS and so never sees plaintext —
only virtual IPs and ciphertext. See [PROTOCOL.md](PROTOCOL.md) for the bind
handshake.

## Handshake transport (QUIC)

The matchmaking control plane (`REGISTER` → `PEER_LIST`) runs over **QUIC/TLS
1.3**, and only that. There is no transport to choose and nothing to keep in sync
between server and buddies.

QUIC's own handshake validates the source address before the server does any
work, so the server cannot be turned into a reflector — no application-layer
cookie is needed. The server presents its identity certificate and the buddy pins
it with `--server-key`. The buddy runs the control connection on its **shared**
UDP socket and closes it before punching, so the same NAT mapping still carries
the peer tunnel.

> **Removed in v5 (protocol v8):** the plain-UDP control plane and its
> application-layer `COOKIE` challenge. It provided the same anti-reflection
> property but left the rest of a `REGISTER` in cleartext on the wire, and a
> choice of transports is a choice a deployment can get wrong. `TypeCookie` and
> `Message.cookie` are gone with it. The **relay** keeps its own cookie: a relay
> bind is plain UDP by design (see "Relay bind handshake" in PROTOCOL.md).

See the `REGISTER` section of [PROTOCOL.md](PROTOCOL.md) for the wire details.

## Security posture

- **Signed rosters.** The handshake server signs every `PEER_LIST` over
  `(token, ts, peers)`; buddies pin the server key and verify, so a man in the
  middle on the control path cannot inject or alter peers.
- **Pinned peers.** By default the pin comes from the invite itself: `--invite`
  mints `bnet1.<token>.<key>` and `--join` pins the key inside it, so the joining
  side is protected with no human step. `--peer-key` does the same by hand.
  Failing both, a buddy learns its partner trust-on-first-use (SSH-style) and
  refuses later changes, verified by a **Short Authentication String** bound to
  the live TLS session — typed in, not clicked away. See SECURITY.md §4.3.
- **Ephemeral pairing secret.** `--invite`/`--join` use a one-time invite token;
  after first pairing both ends derive a long-lived rendezvous **session secret**
  from the channel binding — computed locally, never derived from anything on the
  wire — and reconnect with that. It travels sealed to the server's pinned key,
  which the server unseals to match the pair: never in the clear, but not a secret
  from the server. See [SECURITY.md](../SECURITY.md) for the full threat model.
- **Bounded server memory.** Hard caps (`maxTokens`, two ids per token,
  capped candidates) bound memory even under spoofed source addresses; the
  attacker-growable approval-mode maps are capped and pruned.
- **Rate-limited listeners.** A global + per-source token bucket gates each
  datagram before any parsing or crypto, so a flood is dropped cheaply and the
  per-packet work stays bounded. The relay rate-limits binds per source and caps
  legs per source IP.
- **No reflection.** The handshake server validates the source address in the
  QUIC handshake before emitting a `PEER_LIST`; the relay only ever replies to an
  address it has just heard a valid bind from — and its cookie is bound to the
  full source **address**, port included, so a captured bind is worthless from any
  other port. Neither is a usable amplifier.
- **Replay-resistant registrations.** In approval mode a bounded cache drops
  repeated registration signatures seen within the freshness window.

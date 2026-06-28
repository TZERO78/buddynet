# WireGuard data plane (`--wireguard`)

> **Status:** Phase 3, on the `phase3/wireguard` integration branch — opt-in and
> lab-validated by the project's own netns tests (`lab/test-wg-*.sh`), **not yet in
> a tagged release**. The default data plane is still QUIC.

BuddyNet can carry the tunnel over **kernel WireGuard** instead of QUIC. It is
opt-in (`--wireguard`, set on **both** buddies) and changes only the *data plane* —
the whole control plane (matchmaking, signed `PEER_LIST`, pinning/TOFU, the
fallback chain, the blind relay, the 48-buddy cap) is unchanged. No protocol
version bump: the wire format between buddy and server is identical.

> **The control plane is always QUIC/plain — never WireGuard.** Matchmaking runs
> over `--quic-handshake` (encrypted, source-validated, and — with `--authorized` —
> pinning clients to the allowlist at the TLS handshake; see
> [OPERATIONS.md](OPERATIONS.md) and [APPROVAL.md](APPROVAL.md)). Keeping control
> off WireGuard is deliberate: the server would otherwise key peers by identity and
> a buddy's N concurrent registrations would collide, breaking per-buddy endpoint
> discovery and MultiPeer — the same reason Tailscale/Netbird keep their control
> plane off WireGuard. `--wireguard` is purely the data plane.

## Why WireGuard

The QUIC path forwards TCP over streams (`-L`/`-forward`). WireGuard instead gives
each node a real L3 overlay address: once the tunnel is up, the partner is
reachable **natively at its virtual IP** (`10.66.X.Y`) for *any* protocol, with no
per-connection plumbing. It is steadier for long-running mesh use (survives roaming
and re-keys) — the motivation for Phase 3.

## Identity is still address

Nothing new is trusted. The WireGuard (X25519) key pair is **derived
deterministically** from the node's long-term Ed25519 identity
(`crypto.X25519FromEd25519Public/Private`), and the interface VIP is the same
`10.66.X.Y = SHA-256(pubkey)` as everywhere else. So `identity = key = VIP` carries
onto the data plane with **nothing exchanged over the wire** — two nodes that know
each other's pinned Ed25519 key already agree on each other's WireGuard key and VIP.
A roster claiming an inconsistent VIP is rejected exactly as on the QUIC path.

The kernel interface is configured directly over **raw netlink** (no `wg`/`ip`
subprocess, no `wireguard-tools` dependency), mirroring `internal/vip`'s approach
and keeping the zero-runtime-dependency posture. See `internal/wg/`.

## How a tunnel comes up

The WG path walks the **same fallback chain** as QUIC — direct first, then a relay:

1. **Register & verify** (unchanged): learn the partner's endpoint from the signed
   `PEER_LIST`; run the identity/VIP/pinning checks.
2. **Prime the path on one UDP socket:**
   - **Direct** — hole-punch to the partner's candidates.
   - **Relay** — bind a leg on the relay; the relay address becomes the endpoint.
3. **First contact only (TOFU):** verify the partner with a **Short Authentication
   String** bound to a fresh ephemeral-DH exchange run *over the punched UDP socket*
   (RFC 6189), since there is no TLS exporter on this path. A rejected SAS stops —
   it never falls back to another plane. Pinned peers (`--peer-key`, and all of
   MultiPeer) skip the SAS.
4. **Hand the socket to the kernel.** The punched socket is closed and kernel
   WireGuard is brought up **reusing that same local port**, so the NAT mapping
   survives the handoff (`lab/test-wg-handoff.sh`). Over a relay, the relay
   blindly forwards the encrypted WireGuard packets between the two legs — it is
   **not** a WireGuard peer and holds no key, exactly as it forwards QUIC.
5. **Reconnects** use a deterministic static-DH secret (`crypto.PairSecret`) of the
   two identities — no stored TLS material.

`CONNECTED` logs the path, e.g. `via="direct P2P (WireGuard)"` or
`via="handshake server as relay (WireGuard)"`.

## Reaching the partner

The interface (`bnet0`, …) is assigned this node's VIP as a `/32`, with an explicit
`/32` route to the partner's VIP out that interface. So you simply talk to the
partner's VIP directly:

```
http://10.66.40.12          # the partner's Unraid web UI, a Docker app, ssh, …
```

`-L` / `-forward` / `--vip-listen` are the QUIC stream-forwarding flags; on the WG
path they are **not needed and ignored** (a `NOTE` is printed if set). Reach the
partner at `<partner-vip>:<port>`.

**Scope:** what is reachable is whatever the partner publishes **on its own host**
(services bound to `0.0.0.0`, Docker ports on the host, …). BuddyNet routes only the
partner's VIP `/32` — it does **not** route the LANs/VLANs *behind* the partner.
That is deliberate: BuddyNet connects two hosts, it is not a site-to-site / subnet
router or a mesh VPN.

## MultiPeer: one interface per buddy

`--wireguard` combines with `--peers-file`. Each buddy gets its **own** WireGuard
interface — `bnet0`, `bnet1`, … — not one shared device.

This is forced by kernel WireGuard: a device has a single UDP listen port, and the
direct hole-punch hands its punched socket's port to that device — so two buddies
cannot share one device/port. One interface per buddy keeps every buddy on the
proven single-peer path, which means:

- **Peer-to-peer is preserved** — each tunnel still goes direct where it can; there
  is no central hub/"switch" on the VPS that all traffic must cross.
- **The relay still works per buddy** — each buddy has its own socket and thus its
  own relay leg, with none of the demux collisions a single shared port would hit.

The supervisor assigns each buddy a stable interface index, reconciled live on
`SIGHUP` like the rest of the manifest.

> A WireGuard **hub** on the VPS (the obvious "switch") was rejected on purpose: a
> hub terminates WireGuard and therefore sees plaintext, which would break the
> end-to-end and peer-to-peer properties that the blind relay exists to preserve.

## Requirements

- **Linux** with the `wireguard` kernel module and **`NET_ADMIN`** (root, or the
  capability) to create the interface. BuddyNet probes this with `wg.Available()`
  and **fails closed** if `--wireguard` is set but kernel WireGuard is unavailable —
  it does not silently fall back to QUIC.
- Set `--wireguard` on **both** buddies.
- Not combinable with `--lazy` (a QUIC-stream-specific feature).

## Security notes

- All control-plane guarantees are unchanged: signed `PEER_LIST`, VIP↔key reject,
  pinning/TOFU with a SAS on first contact, replay/cap protections, blind relay.
- **Fails closed:** WG unavailable, no usable path, or a rejected SAS → an error,
  never a silent switch to another data plane.
- **Full-host exposure (known, accepted for now).** Because the VIP is a real
  address on the host, *every* service listening on `0.0.0.0` is reachable by the
  partner over the overlay — the overlay is not yet scoped to a single service. For
  the two-person trust model this is accepted; once **BuddyShare** is defined, the
  plan is to firewall `bnet*` down to just that path. Until then: only pair with a
  buddy you trust, and keep host services authenticated.
- The relay never sees plaintext on this path either — it forwards sealed WireGuard
  packets, just as it forwards QUIC.

## Lab validation

Run as root with the `wireguard` module loaded (netns labs):

- `lab/test-wg-buddy.sh` — direct P2P over WireGuard + native VIP ping; confirms the
  QUIC default still works (no regression).
- `lab/test-wg-relay.sh` — the direct path firewalled off, so the tunnel runs over
  the blind relay.
- `lab/test-wg-multipeer.sh` — a full mesh of three buddies, each on its own
  `bnet0`/`bnet1`, each pinging both partners' VIPs.

See also `docs/ARCHITECTURE.md` (data-plane seam) and `SECURITY.md` (threat model).

# BuddyNet Protocol v1

The control plane is **UDP + JSON**, one datagram per message. The single source
of truth is [`pkg/protocol`](../pkg/protocol); a one-byte drift between
implementations would break signature verification, so anything that crosses the
wire or is signed lives there and nowhere else.

- **Version:** `1` (`protocol.Version`). Every message stamps `ver`; a mismatch
  is reported clearly instead of failing as an opaque signature error.
- **Field cap:** untrusted strings are bounded by `MaxFieldLen` (128) before
  being used as map keys.

## Message envelope

```jsonc
{
  "type": "REGISTER|PEER_LIST|COOKIE|RELAY_OFFER|CONNECT|PING|PONG",
  "ver":  2,
  // ...type-specific fields, all omitempty...
}
```

## REGISTER  (peer → handshake)

A buddy (or relay) announces itself. Sent ~once per second to every server
address (IPv4 **and** IPv6) from one socket, so the server learns every
candidate and the same NAT mapping is reused for the tunnel.

| Field | Meaning |
|---|---|
| `token` | the **rendezvous secret** the server pairs on: a one-time invite token on first pairing, or the derived session secret on later reconnects (see *Pairing secret* below). The server treats it as opaque. |
| `role` | `buddy` / `relay` |
| `id` | ephemeral per-run id (dedupes a peer's v4+v6 registrations) |
| `pubkey` | base64 Ed25519 identity |
| `virtual_ip` | the sender's `10.66.0.X` |
| `ts`, `reg_sig` | key-ownership proof for an allowlist server (sign `RegistrationPayload(token,id,pubkey,ts)`) |
| `code_enc` | optional enrollment code, sealed to the server identity |
| `cookie` | address-validation token echoed from a prior `COOKIE` reply (UDP transport) |

The server observes the **source address** of the datagram as a candidate
endpoint (over IPv6 this is directly reachable; over IPv4 it is the punched NAT
mapping).

**Address validation.** On the plain-UDP transport a `REGISTER` without a valid
`cookie` is answered only with a `COOKIE` message — `HMAC(subkey, epoch‖src-IP)`,
smaller than the request, never a useful amplifier — and the server does no
further work. The buddy echoes it in `cookie` on its next `REGISTER`; a spoofed
source can never receive the challenge, so it can never be answered. With
`--quic-handshake` the exchange instead rides QUIC, whose handshake validates the
source address before any work and makes the cookie unnecessary. Either way the
server never emits a `PEER_LIST` to an unvalidated address.

```
REGISTER (no cookie) ─▶ server
       ◀── COOKIE = HMAC(subkey, epoch‖src-IP)   (smaller than the request)
REGISTER + cookie ─▶ server ──validate──▶ pair, then PEER_LIST
```

## PEER_LIST  (handshake → peer)

Sent only after a token pairs two distinct peers, and only to the sender. In
2-peer (BuddyPeer) mode it carries exactly the one partner.

| Field | Meaning |
|---|---|
| `peers[]` | roster: `{id, pubkey, virtual_ip, candidates[], relay, last_seen}` |
| `ts` | server timestamp (freshness window, anti-replay) |
| `sig` | Ed25519 signature over `PeerListPayload(token, ts, peers)` |

**Verification (buddy side):** reconstruct the canonical payload (peers
ID-sorted, candidates Addr-sorted), verify `sig` against the **pinned** server
key, check `ts` is within ±60 s, then apply the trust policy to the partner's
identity and confirm its `virtual_ip` matches `SHA-256(pubkey)[0]`. The trust
policy is, strongest first: `--peer-key` (strict pin) → trust-on-first-use, where
on the **first** contact both ends compare a Short Authentication String (below)
before the key is trusted → `--insecure` (none). A reconnect via a stored session
pins the key recorded at pairing and skips the SAS.

## SAS — first-contact verification

This is a human step, not a wire message. On a trust-on-first-use first contact,
once the QUIC tunnel is up but **before** the key is trusted, both ends compute a
6-character Short Authentication String

```
SAS = base32( SHA-256( sort(pubA,pubB) || EKM ) )[0:6]
```

where `EKM` is the TLS exported keying material (RFC 5705 channel binding) of the
live session. Both ends derive the same string; a man in the middle — a different
TLS session per side — derives a different one. The humans compare it out of
band; a mismatch (or `--no-interactive`) refuses the key. See
[`internal/role/sas.go`](../internal/role/sas.go).

## Pairing secret (invite token vs. session secret)

`--invite`/`--join` use a **one-time invite token**, valid only until the first
pairing. On that first SAS-confirmed (or `--peer-key`-pinned) pairing both ends
derive a long-lived **session secret** from the same channel binding

```
session_secret = base64url( EKM("buddynet-session-rendezvous-v1", sort(pubA,pubB), 32) )
```

It is **never transmitted** and becomes the `token` in REGISTER on every later
reconnect, so the invite is retired after first use. `--token` is the legacy mode:
a fixed token reused as the rendezvous secret on every connect (no session
secret). See [SECURITY.md](../SECURITY.md).

## RELAY_OFFER  (advertise a relay)

Advertises a relay for a pair. In v1 a single relay is most simply carried in a
peer's `relay` field on the `PEER_LIST`; the standalone message exists for
multi-relay futures.

| Field | Meaning |
|---|---|
| `from`, `to` | virtual IPs of the pair |
| `relay_endpoint` | relay `host:port` |
| `relay_pubkey` | pin the relay |

## CONNECT  (buddy → peer/relay)

Opens a session. Names both identities and carries a short-lived
`session_token`. In v1 the session token is **derived deterministically** by
both buddies from the rendezvous secret they used this connection (the invite
token, or the session secret on reconnect):

```
session = base64url( SHA-256(rendezvous || "\0" || lo(pubA,pubB) || "\0" || hi(pubA,pubB)) )[0:16]
```

so the two sides agree with **no extra round trip**, and the relay treats it as
an opaque pairing key.

## PING / PONG

Keepalive, exchanged every **25 s** (`peer.KeepalivePeriod`) to keep NAT
mappings and registrations fresh. In v1 the QUIC transport's own keepalive
(derived as `idle-timeout / 4`) carries this on the data plane.

## Relay bind handshake (data plane)

To use a relay, each buddy claims a leg over the **same socket** it will run QUIC
on ([`internal/relay/offer.go`](../internal/relay/offer.go)):

```
client → relay :  "BNRELAY1" || {"s": session_token}    (~5×/s until acked)
relay  → client:  "BNRELAY1" || {"s": session_token}    (ack; opens return path)
```

Once both legs are bound, the relay forwards every **non-bind** datagram from one
leg to the other. QUIC's first byte is never the bind prefix, so data and
control are unambiguous. The relay:

- caps sessions and **exactly two legs** per token (a third is rejected),
- rate-limits bind control packets per source and caps **legs per source IP**
  (data forwarding is never throttled),
- never originates traffic to an address it has not heard a bind from
  (anti-reflector), and
- reaps a leg after its TTL with no traffic.

The buddies then run end-to-end QUIC with the relay address as the peer
endpoint — the relay forwards ciphertext and never sees content.

## Threat model summary

| Attacker | Defense |
|---|---|
| MITM on the control path | server-signed `PEER_LIST`, pinned server key |
| Impersonating the partner | partner cert must carry the pinned/learned pubkey |
| MITM at first contact (TOFU) | SAS compared out of band over the TLS channel binding before the key is trusted |
| Leaked pairing token | invite token is one-time/short-lived; the long-lived session secret is derived from the channel binding and never sent |
| Replaying an old roster | `ts` freshness window binds each roster in time |
| Replaying a signed registration (approval mode) | bounded cache rejects a repeated `reg_sig` within the freshness window |
| Spoofed-source memory blowup | hard caps on tokens / ids / candidates; capped+pruned approval-mode maps |
| Flooding the listener (CPU) | global + per-source rate limit before any crypto |
| Turning a server into a reflector | source address validated first — a UDP cookie (`HMAC(subkey, epoch‖src-IP)`, reply smaller than request) or QUIC's handshake — before any `PEER_LIST`; relay replies only to a just-heard source |
| Reading an enrollment code on the wire | sealed box to the server identity |

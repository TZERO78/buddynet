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
  "type": "REGISTER|PEER_LIST|RELAY_OFFER|CONNECT|PING|PONG",
  "ver":  1,
  // ...type-specific fields, all omitempty...
}
```

## REGISTER  (peer → handshake)

A buddy (or relay) announces itself. Sent ~once per second to every server
address (IPv4 **and** IPv6) from one socket, so the server learns every
candidate and the same NAT mapping is reused for the tunnel.

| Field | Meaning |
|---|---|
| `token` | shared secret pairing two buddies |
| `role` | `buddy` / `relay` |
| `id` | ephemeral per-run id (dedupes a peer's v4+v6 registrations) |
| `pubkey` | base64 Ed25519 identity |
| `virtual_ip` | the sender's `10.66.0.X` |
| `ts`, `reg_sig` | key-ownership proof for an allowlist server (sign `RegistrationPayload(token,id,pubkey,ts)`) |
| `code_enc` | optional enrollment code, sealed to the server identity |

The server observes the **source address** of the datagram as a candidate
endpoint (over IPv6 this is directly reachable; over IPv4 it is the punched NAT
mapping).

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
identity and confirm its `virtual_ip` matches `SHA-256(pubkey)[0]`.

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
both buddies as

```
session = base64url( SHA-256(token || "\0" || lo(pubA,pubB) || "\0" || hi(pubA,pubB)) )[0:16]
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
| Replaying an old roster | `ts` freshness window binds each roster in time |
| Spoofed-source memory blowup | hard caps on tokens / ids / candidates |
| Turning a server into a reflector | reply only to a just-heard source |
| Reading an enrollment code on the wire | sealed box to the server identity |

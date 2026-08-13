# BuddyNet Protocol

The control plane is **UDP + JSON**, one datagram per message. The single source
of truth is [`pkg/protocol`](../pkg/protocol); a one-byte drift between
implementations would break signature verification, so anything that crosses the
wire or is signed lives there and nowhere else.

- **Version:** `7` (`protocol.Version`). Every message stamps `ver`; a mismatch
  is reported clearly instead of failing as an opaque signature error. Server and
  buddies must run the same version. Notable bumps: **v3** added the relay bind
  address-validation cookie (see "Relay bind handshake"), **v4** widened the
  virtual IP to a `/16` (`10.66.X.Y`), **v6** lets the pairing token travel sealed
  to the server's pinned key (`token_enc`) instead of in cleartext, **v7** added
  the per-attempt `nonce` and widens the registration signature to cover every
  field the server acts on.

> **v8 is a breaking change with no compatibility shim.** A v6 registration
> signature does not cover `ver`, `role`, `virtual_ip`, `name`, `nonce` or
> `code_enc`, so it cannot be verified under v7 — and it is *not* accepted under
> the old rules. Once the source address is validated, a mismatched client is
> answered with a version-stamped empty `PEER_LIST`, which surfaces on the buddy
> as *"server speaks vN, we speak vM — update buddynet"*.

### Migrating a running server to v7

A v7 server does not serve v6 buddies, so a single in-place upgrade cuts every
buddy off until each one is updated. **Do not add a compatibility shim** — a v6
signature does not cover the fields v7 relies on, so accepting one would mean
accepting a weaker proof. Run the two versions side by side instead:

1. **Keep the v6 server running** on its current address and port. Do not touch it.
2. **Start the v7 server alongside it**, on a second port (or a second address) —
   same host is fine, it is a separate process with its own `--listen`. Reuse the
   **same identity key** so buddies keep the `--server-key` they have already
   pinned; only the port changes for them.
3. **Migrate buddies one at a time**: update the binary and point `--server` at
   the v7 port. Each buddy that moves pairs over v7; the ones still on v6 keep
   working against the old server. Note that a *pair* must move together — both
   buddies rendezvous on the same server, so migrate them as a couple.
4. **Watch the v6 server's log** until no registrations arrive any more.
5. **Shut the v6 server down.** If you want the original port back, stop v6 and
   restart v7 on it; buddies then need one more `--server` change, so it is
   usually simpler to keep the new port.

**Writable state must not be shared.** Since v5.0.0 the control server writes
nothing at runtime (pending enrolments live in memory), so the only file to think
about is the allowlist. In approval mode, **copy** it to the v7 server rather than
pointing both at the same file: two processes appending and atomically renaming the same path
will drop each other's approvals. Copy it before migrating, or the first buddy to
move finds itself unapproved — `--authorized` is fail-closed, so an empty file
means nobody pairs. Approvals made during the migration have to be applied to
whichever server that buddy talks to (or to both).
- **Field cap:** untrusted strings are bounded by `MaxFieldLen` (128) before
  being used as map keys.

## Message envelope

```jsonc
{
  "type": "REGISTER|PEER_LIST|COOKIE|RELAY_OFFER|CONNECT|PING|PONG",
  "ver":  7,
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
| `token_enc` | the rendezvous secret, **sealed to the server's pinned key** (NaCl sealed box; v6). Since v8 this is the ONLY form on the wire — the cleartext `token` field is no longer serialised; the server unseals this to the value the signature covers. |
| `role` | `buddy` / `relay` |
| `id` | ephemeral per-run id (dedupes a peer's v4+v6 registrations) |
| `pubkey` | base64 Ed25519 identity |
| `virtual_ip` | the sender's `10.66.X.Y`. **The server does not trust this**: it derives the virtual IP from `pubkey` and rejects a registration claiming a different one. |
| `ts`, `nonce`, `reg_sig` | key-ownership proof: `nonce` is 128 bits of CSPRNG, base64url (22 chars, strictly validated), **fresh for every attempt**; `reg_sig` signs `RegistrationPayload(m)` — see below |
| `code_enc` | optional enrollment code, sealed to the server identity |
| `cookie` | address-validation token echoed from a prior `COOKIE` reply (UDP transport) |

The server observes the **source address** of the datagram as a candidate
endpoint (over IPv6 this is directly reachable; over IPv4 it is the punched NAT
mapping).

**What `reg_sig` covers (v7).** `RegistrationPayload` signs every field the
server acts on: `ver`, `role`, `token` (the **plaintext**, i.e. what `token_enc`
unseals to), `id`, `pubkey`, `virtual_ip`, `name`, `ts`, `nonce` and `code_enc`.
Two fields are deliberately outside it:

- `cookie` — minted by the server and checked against the server's own HMAC key
  and the packet's source IP, so signing it would add nothing; leaving it out is
  what lets a buddy attach a freshly challenged cookie without re-deriving
  anything else.
- `token_enc` — it must first decrypt under the server's identity key; the signed
  value is the recovered plaintext `token`, which is what every downstream check
  uses.

Because `code_enc` is signed, a captured enrollment code cannot be grafted onto a
different public key's registration.

**Freshness and replay.** `ts` must be within ±60 s of the server's clock. Within
that window the server keeps a bounded cache of `(pubkey, nonce)` pairs and
rejects a repeat as a replay. A **fresh nonce per attempt** is therefore
mandatory, not optional: a buddy waiting for its partner re-registers about once
a second, and sends one datagram per server address, so every one of those
datagrams must be signed anew. Re-sending a cached registration is
indistinguishable from an attacker replaying a captured one, and is refused.

**Address validation.** The control plane is QUIC/TLS 1.3: the handshake proves
return-routability before the server does any work, so an IP-spoofed sender can
never make it reflect a `PEER_LIST`. Until v8 a plain-UDP transport with an
application-layer cookie provided the same property; it is removed, and with it
`TypeCookie` and `Message.cookie`. (The RELAY keeps its own cookie — a relay bind
is always plain UDP.)

```
REGISTER (no cookie) ─▶ server
       ◀── COOKIE = HMAC(subkey, epoch‖src-IP)   (smaller than the request)
REGISTER + cookie ─▶ server ──validate──▶ pair, then PEER_LIST
```

## PEER_LIST  (handshake → peer)

Sent only after a token pairs two distinct peers, and only to the sender — so the
roster carries exactly the one partner. (MultiPeer changes nothing here: it uses a
separate token per buddy, each still pairing exactly two, so every roster names a
single partner.)

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
before the key is trusted → `--lab` (none). A reconnect via a stored session
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

It is **never derived from anything on the wire** — both ends compute it from
their own TLS channel binding, so nothing an observer sees yields it. It then
becomes the rendezvous `token` in REGISTER on every later reconnect, so the invite
is retired after first use.

Be precise about what that does and does not mean: on reconnect the secret **is**
sent to the handshake server, sealed to the server's pinned key (`token_enc`), and
the server **unseals it** — it is the value it matches the two buddies on. So it is
never in the clear on the wire and never in a log, but it is not a secret from the
server. A hostile server therefore knows the rendezvous value and can squat a
pairing with it; what it still cannot do is read any traffic (the tunnel is
end-to-end between the two pinned identities) or impersonate a buddy to one that
pins its partner with `--peer-key` or has TOFU-pinned it. `--join` is the legacy mode:
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
client → relay :  "BNRELAY1" || {"s": session_token}              (~5×/s)
relay  → client:  "BNRLYC1"  || cookie(16B)                       (address-validation challenge)
client → relay :  "BNRELAY1" || {"s": session_token, "c": cookie} (echoes the cookie)
relay  → client:  "BNRELAY1" || {"s": session_token}              (ack; opens return path)
```

The relay binds **no leg** until the client echoes a valid cookie —
`HMAC(per-process key, epoch‖src-IP)`, truncated, accepted for the current and
previous 30 s epoch. The challenge is a fixed, compact binary message **smaller
than the bind that triggers it**, so it is never an amplifier. This is the same
return-routability proof the handshake server uses: it closes the relay's only
reflection / traffic-laundering vector — without it, a spoofed bind could
register a victim's address as a leg and have attacker data forwarded to it.

Once both legs are bound, the relay forwards every **non-bind** datagram from one
leg to the other. QUIC's first byte is never the bind prefix, so data and
control are unambiguous. The relay:

- requires an **address-validation cookie** before binding a leg (above),
- caps sessions and **exactly two legs** per token (a third is rejected),
- rate-limits bind control packets per source and caps **legs per source IP**
  (data forwarding is never throttled),
- never originates traffic to an address it has not heard a validated bind from
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
| Leaked pairing token | invite token is one-time/short-lived; the long-lived session secret is derived locally from the channel binding, never in the clear on the wire, and sealed to the server's pinned key in transit (the server does see it — see above) |
| Replaying an old roster | `ts` freshness window binds each roster in time |
| Replaying a signed registration (approval mode) | bounded cache rejects a repeated `(pubkey, nonce)` within the freshness window |
| Forging a peer's virtual IP in the roster | the server derives `virtual_ip` from `pubkey` and rejects any other claim |
| Grafting a captured enrollment code onto another key | `code_enc` is inside the registration signature |
| Spoofed-source memory blowup | hard caps on tokens / ids / candidates; capped+pruned approval-mode maps |
| Flooding the listener (CPU) | global + per-source rate limit before any crypto |
| Turning a server into a reflector | source address validated first — a UDP cookie (`HMAC(subkey, epoch‖src-IP)`, reply smaller than request) or QUIC's handshake — before any `PEER_LIST` |
| Turning a **relay** into a reflector / traffic launderer | a bind binds no leg until the source echoes an address-validation cookie (`HMAC(per-process key, epoch‖src-IP)`, reply smaller than the bind); a spoofed source can never validate |
| Reading an enrollment code on the wire | sealed box to the server identity |

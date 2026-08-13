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
| `epk` | (v8) the **ephemeral relay-session key**: base64url Ed25519, fresh per attempt, unrelated to the identity. The server signs it into the relay ticket, so the ticket is worthless to anyone who captures it. Optional — a buddy that will never use a relay may omit it. |
| `cookie` | address-validation token echoed from a prior `COOKIE` reply (UDP transport) |

The server observes the **source address** of the datagram as a candidate
endpoint (over IPv6 this is directly reachable; over IPv4 it is the punched NAT
mapping).

**What `reg_sig` covers (v7).** `RegistrationPayload` signs every field the
server acts on: `ver`, `role`, `token` (the **plaintext**, i.e. what `token_enc`
unseals to), `id`, `pubkey`, `virtual_ip`, `name`, `ts`, `nonce`, `code_enc` and
`epk`.

`epk` is the one whose omission would be exploitable rather than merely sloppy:
the server signs that key into a relay ticket, so an on-path party able to swap it
would be handed a usable permit for someone else's session. Signed, the swap
invalidates the registration instead.

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
| `ticket` | (v8) `{p, s}` — the relay permit for THIS recipient and the server's signature over it, both base64url. Present only when the server has a relay configured (`--relay-id`) and the pair is matched. See *Relay tickets* below. |

The ticket is deliberately **not** covered by `sig`: it carries its own signature
by the same key and is bound to the recipient's `epk`. Stripping it can only cost
the relay fallback, and swapping one in gains nothing — the swapped-in ticket
names an `epk` the recipient cannot prove. One signed-payload definition stays one.

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

## Relay tickets (v8)

**A relay does not take anyone's word for a session.** It is configured with the
PUBLIC key of a handshake server (`--server-key`) and that server's id for it
(`--relay-id`), and it then admits only sessions that server authorised. It never
learns *who* is in them: a bind carries no identity, there is no buddy list on
the relay, and nothing in it says who talks to whom.

A relay refuses to start without an authorization policy — `--server-key` or
`--allow-cidr`, and both together are an AND. See [OPERATIONS.md](OPERATIONS.md).

**Issuance.** A buddy mints a fresh Ed25519 key pair for each connection attempt
and sends the public half as `epk` on its `REGISTER` (covered by the registration
signature, so it cannot be swapped in flight). When the server pairs the two
buddies, each paired `PEER_LIST` carries a `ticket` for THAT recipient:

```
ticket_payload = {v, rid, sid, leg, epk, iat, exp, nonce}     (base64url, opaque on the wire)
ticket_sig     = Ed25519(server_priv, "buddynet-relay-ticket-v1\0" || ticket_payload)
```

| Field | Meaning |
|---|---|
| `v` | TICKET FORMAT version (1), independent of `protocol.Version` |
| `rid` | which relay this is valid at — an id, not an address (addresses move) |
| `sid` | the relay session id, **server-chosen**: two legs meet only if the server put them together |
| `leg` | `a` or `b`; assigned by identity-key order, so both buddies derive opposite legs with no extra signaling |
| `epk` | the ephemeral public key this ticket is bound to |
| `iat`, `exp` | issued-at and absolute expiry (span ≤ 120 s) |
| `nonce` | server-chosen, 128 bit |

The ticket is issued **unrequested, before the punch is even tried**. Asking for
one later would need a second control round trip at exactly the moment the direct
path just failed, would make the server remember the pairing (the runtime state
v5 deliberately removed), and would gate issuance on "my punch failed" — a claim
no server can verify. A pairing that succeeds directly just discards its ticket.

The payload is **opaque**: the relay verifies `ticket_sig` over the exact bytes it
received and parses only afterwards, so there is no canonicalisation step to get
wrong. Parsing is strict — unknown fields, duplicate keys, wrong types and
oversized payloads are all refused.

**Proof of possession.** A bare ticket would be a bearer token, so the bind must
also carry a signature by the ephemeral private key, over this relay's current
cookie:

```
bind_sig = Ed25519(eph_priv, "buddynet-relay-bind-v1\0" || SHA-256(ticket_payload || ticket_sig) || cookie)
```

Hashing `payload‖sig` ties the bind to the COMPLETE ticket, so no field can be
swapped without invalidating it. The cookie is what stops replay: it is the only
value that is fresh, relay-chosen and bound to the source address, and it rotates
every 30–60 s. A captured ticket, or a whole captured bind, is worthless from
another address or after the epoch turns — and cannot be re-signed, because the
ephemeral private key never leaves the buddy.

**Lifetime.** `exp - iat` ≤ 120 s, with a 10 s clock-skew allowance in each
direction. The worst-case real lifetime against a shifted clock is therefore
**140 s** (`120 + 2×10`), not 120 and not 130 — that is the number to reason about
when judging exposure. Relay and handshake server must agree on the time within
the allowance; if they drift apart, every ticket is refused and the relay logs a
reason that names BOTH possible causes, because it genuinely cannot tell a skewed
clock from a wrongly-issued ticket.

A ticket authorises **joining, not staying**: an established session is not torn
down at `exp`, but nothing new can be bound with an expired one — including a
re-bind from an address that already holds a leg.

**Address migration.** A buddy that changes address (NAT rebind, a mobile switch)
is not a third party: a bind for a leg that is already filled replaces the
recorded address atomically when the source presents a fresh cookie for the NEW
address, a proof of possession against the SAME `epk` the leg holds, and a ticket
that is still valid. A bind for a filled leg with a different `epk` is refused
whatever it carries.

## Relay bind handshake (data plane)

To use a relay, each buddy claims a leg over the **same socket** it will run QUIC
on ([`internal/relay/offer.go`](../internal/relay/offer.go)):

```
client → relay :  "BNRELAY1" || {"s": sid}                            (~5×/s, no ticket yet)
relay  → client:  "BNRLYC1"  || cookie(16B)                           (address-validation challenge)
client → relay :  "BNRELAY1" || {"s": sid, "c": cookie,
                                 "t": ticket, "ts": ticket_sig,
                                 "b": bind_sig}                       (echoes the cookie, proves possession)
relay  → client:  "BNRELAY1" || {"s": sid}                            (ack; opens return path)
```

The first bind carries no ticket on purpose: the relay checks the cookie before
it looks at a ticket, so that bind can only ever draw a challenge — sending the
permit before the relay has proven reachable would put it on the wire for
nothing. In network mode (`--allow-cidr` alone) the three ticket fields are absent
and `s` is the buddy-derived `session_token` below.

The relay binds **no leg** until the client echoes a valid cookie —
`HMAC(per-process key, epoch‖src-IP)`, truncated, accepted for the current and
previous 30 s epoch. The challenge is a fixed, compact binary message **smaller
than the bind that triggers it**, so it is never an amplifier. This is the same
return-routability proof the handshake server uses: it closes the relay's only
reflection / traffic-laundering vector — without it, a spoofed bind could
register a victim's address as a leg and have attacker data forwarded to it.

Once both legs are bound, the relay forwards every **non-bind** datagram from one
leg to the other. QUIC's first byte is never the bind prefix, so data and
control are unambiguous.

The relay runs a **fixed check order**, cheapest and most spoof-resistant first,
and nothing below the cookie runs for a packet that fails it:

1. **size cap** — before any field is looked at,
2. **CIDR** (if configured) — before any crypto,
3. **per-source rate limit** — one map lookup,
4. **cookie** — no valid cookie: answer a challenge, create NO state,
5. **bounded parse** of the ticket envelope,
6. **server signature** over the exact received bytes,
7. **field checks** — version, window, span, `rid`, `sid`, `leg`,
8. **proof of possession**, and only then
9. **state**: allocate or update the leg.

The order is the control: an unvalidated source can never make the relay perform
an Ed25519 verification or allocate a session. Behind the cookie, the two
verifications per bind are bounded by a **global** per-second budget (an attacker
with many real addresses stays under every per-source budget), a hard cap on
verifications **in flight**, and a small **reserve** for sessions that already
hold one leg — separately metered and keyed by `sid`, so it cannot be added to the
global budget and one `sid` cannot consume it. Verification runs off the read
loop, because two signature checks inline would let a flood stall the data path.

Beyond that the relay:

- caps sessions and **exactly two legs** per session (one `a`, one `b`),
- caps **legs per source** (one IPv4 address or one IPv6 /64),
- expires a session that holds only ONE leg after an absolute 60 s, whatever its
  traffic (an idle timer alone is refreshed by a trickle),
- never originates traffic to an address it has not heard a validated bind from
  (anti-reflector), and
- reaps a leg after its TTL with no traffic.

**What the relay logs.** A shortened session id, the leg, and a rejection reason —
enough to correlate the two legs of one session in one log, deliberately not
enough to link a session to a buddy. Never a ticket, a cookie, a signature or an
ephemeral key; source addresses only under `--debug`. Rejection lines are
rate-limited per reason.

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
| **Using someone else's relay** (bandwidth, capacity hoarding) | a relay admits only sessions a named handshake server authorised (signed ticket) and/or named networks; it refuses to start with neither, and `0.0.0.0/0` is not an accepted answer |
| **Replaying a captured relay ticket** | the ticket is bound to an ephemeral key the binder must sign with; the signature covers the relay's own address-bound, rotating cookie |
| Spending a ticket at a **different relay** | the ticket names the relay by id and the signature covers it |
| **Re-entering a relay session forever** on one old ticket | every bind, including an address migration, takes the same expiry check — the ephemeral key proves *who*, never *how long* |
| **Forcing a relay to burn CPU** on signature checks | the cookie gates all of it; behind it a global per-second budget, an in-flight cap and a separately metered per-`sid` reserve bound the total regardless of how many real addresses the load comes from |
| Reading an enrollment code on the wire | sealed box to the server identity |

# Security model

BuddyNet brings up an end-to-end-encrypted overlay between two (or a few)
machines behind NAT. This document states, honestly and without overclaiming,
**what it protects, who the adversaries are, and which mechanism stops which
attack.** It is organised threat-model-first:

1. [What BuddyNet is](#1-what-buddynet-is--trust-boundaries) — the components and
   what each one can see.
2. [Assets](#2-assets--what-we-protect) — what is worth protecting.
3. [Adversaries at a glance](#3-adversaries-at-a-glance) — the summary table.
4. [How the data is protected](#4-how-the-data-is-protected) — encryption, the
   trust hierarchy, key hygiene.
5. [The control plane](#5-the-control-plane-handshake-server) — matchmaking,
   spoof-proofing, server hardening.
6. [The data planes](#6-the-data-planes) — QUIC, WireGuard, scoped exposure, the
   blind relay.
7. [Detecting an attack](#7-detecting-an-attack) — the log schema.
8. [Operational security](#8-operational-security) — lost keys, revocation,
   release integrity.
9. [Limits](#9-limits--what-buddynet-cannot-do) — what it cannot protect
   against, and what is left out by design.
10. [Non-goals / positioning](#10-non-goals--positioning).
10. [Reporting a vulnerability](#11-reporting-a-vulnerability).

The threat model in `docs/ARCHITECTURE.md` and the protocol in `docs/PROTOCOL.md`
give the design rationale behind the properties claimed here.

---

## 1. What BuddyNet is — trust boundaries

One binary runs in one of three explicit roles. Two of them are **servers you or
your buddy operate**; the third is the endpoint that actually holds your data.

```
   buddy A  ├─────────── end-to-end encrypted tunnel ───────────┤  buddy B
  (your host)                                                    (partner host)
      │                                                               │
      │  REGISTER / signed PEER_LIST (matchmaking only)               │
      └──────────────►  handshake server  ◄───────────────────────────┘
                              │
                        relay (optional, only if no direct path)
                        forwards SEALED packets blindly
```

- **buddy** — the endpoint. Holds the identity key, sees plaintext. This is the
  only place your data is in the clear.
- **handshake server** — matchmaking control plane. Learns public endpoints from
  signed `REGISTER`s, pairs two peers sharing a token, returns a **signed**
  `PEER_LIST`. **No tunnel data ever flows through it.**
- **relay** — a fallback when no direct path exists. Forwards **encrypted**
  packets between two legs keyed by an opaque token. Sees ciphertext and virtual
  IPs, **never plaintext or any key.**

There are two **data planes** (the control plane is the same for both):

- **QUIC transport (default)** — TLS 1.3, TCP forwarded over multiplexed streams
  (`-L`/`-forward`).
- **WireGuard overlay (`--wireguard`, opt-in)** — a kernel WireGuard interface
  (`bnet0`, …) so the partner is reachable natively at its virtual IP. See §6.2.

### The core invariant: identity = key = address

Every node has **one** long-term Ed25519 key. That key is simultaneously its
identity (pinned by peers), its self-signed TLS certificate key, and the seed of
its virtual IP: `10.66.X.Y` where `X,Y = SHA-256(pubkey)[0:2]`
([`internal/crypto/keys.go`](internal/crypto/keys.go)). No server assigns
addresses — two nodes that know each other's pubkey already agree on each other's
virtual IP, and **a roster claiming an inconsistent IP is rejected.** Losing the
key changes the address and forces re-pinning (see §8.1).

---

## 2. Assets — what we protect

| Asset | Protected by | Section |
|---|---|---|
| **Tunnel content** (confidentiality + integrity) | End-to-end encryption; forward secrecy | §4.1 |
| **Peer authenticity** (you are talking to the right buddy) | Key-bound invite; key pinning; TOFU + SAS | §4.2–§4.3 |
| **Identity keys** (at rest and in memory) | `0600` files, no core dump, symlink-safe load, best-effort wipe | §4.7 |
| **Host reachability** (what a buddy can touch on your machine) | Scoped exposure (`--expose`), fail-closed | §6.3 |
| **Availability of the control plane** | Rate limits, bounded state, spoof-proofing | §5.3 |

Everything below is stated as "which mechanism defends which asset against which
adversary."

---

## 3. Adversaries at a glance

| Adversary | Outcome | Verdict |
|---|---|---|
| Passive eavesdropper on the path | Sees only encrypted QUIC / WireGuard. | **Safe** |
| Active network MITM (not the server) | Cannot impersonate a peer — pinned mutual auth, and the SAS catches a first-contact substitution (§4.2–§4.3). | **Safe** |
| Malicious / compromised **handshake server** | Cannot impersonate a buddy: on the default invite path the joiner **pinned** the inviter's key from the invite itself, so a substituted identity is refused with no human involved, and the inviter catches the reverse direction by typing a code it cannot see. Without an invite, a pin (`--peer-key`) or the SAS catches it. Can deny service. | **Mitigated** |
| A **relay** in the data path | Sees only ciphertext; cannot read or inject (QUIC/WireGuard auth). | **Safe** |
| Someone who learns the **token** | Cannot impersonate a buddy (SAS / pin). Can at most occupy a pairing slot and *deny* the legitimate pair — a DoS, not a breach. The token (and the reconnect rendezvous secret) is **sealed to the server's pinned key** (`TokenEnc`), and the control plane is TLS 1.3 on top of that. | **Mitigated** |
| Spoofed-source flood / reflection on the **handshake server** | Source address validated by the QUIC handshake before any `PEER_LIST`; global + per-source rate limits and bounded state cap the rest. Never a useful amplifier (§5.2–§5.3). | **Mitigated** |
| Spoofed-source reflection / traffic-laundering through a **relay** | A bind binds no leg until the source echoes an address-validation cookie (reply smaller than the bind); a spoofed source can never validate, so attacker data can never be forwarded to a victim address. | **Mitigated** |
| A stranger **using your relay** (bandwidth, or hoarding capacity so your own fallback fails) | The relay admits only sessions your handshake server authorised (signed ticket bound to an ephemeral key the binder must prove) and/or named networks; it refuses to start with neither. | **Mitigated** (v5.0.0) |
| A **compromised relay** | It holds only a public verify key: it can withhold service — which it can do by being offline anyway — but can never authorise a session, nor forge one for another relay. It still sees only ciphertext. In a COMBINED `--role=handshake,relay` process the server's signing key is in the same memory; run them separated when the relay is exposed (§6.4). | **Mitigated (separated) / reduced (combined)** |
| **Malicious / compromised paired buddy** (WireGuard plane) | Reaches only the port(s) you `--expose`; without a scope, nothing (fail-closed). It is a *trusted* peer by construction — treat what you expose as reachable by a hostile peer and keep it patched and least-privileged (§6.3). | **Scoped** |
| A **revoked** buddy trying to come back | `peers remove` (and *Forget buddy* in the plugin) puts the key on a permanent local revocation list, deletes the stored session and drops the manifest entry. The key is refused at every reconnect attempt, no session can be written for it, it cannot be learned trust-on-first-use, and a restart does not bring it back. Lifting it is a separate, explicit act (§8.2). | **Mitigated** (v5.2.0) |
| **Malformed or hostile packets** | Every parser that faces the network is bounded before it decodes (length caps, fixed-size id fields) and runs under panic isolation, so one crafted datagram cannot take the process down. The parsers are fuzzed nightly in CI. | **Mitigated** |
| An **accidentally open relay** | A relay refuses to start without an authorization policy, and `--allow-cidr 0.0.0.0/0` (or `::/0`) is refused rather than accepted — "open to everyone" is not a configuration you can reach by mistake. | **Mitigated** (v5.0.0) |
| Local process on the same host | Reads the `0600` key / `known_peers`, or a TCP-loopback `-L`. Use a `unix:/path` socket and the systemd sandbox. | **Mitigated** |

Each row is expanded in the sections referenced.

---

## 4. How the data is protected

### 4.1 End-to-end encryption & forward secrecy

The tunnel is confidential and integrity-protected end to end; only the two
buddies ever see plaintext.

- **QUIC / TLS 1.3** (default plane): forward secrecy from ephemeral ECDHE.
  Compromising a node's **long-term identity key does not decrypt past captured
  traffic.**
- **WireGuard** (`--wireguard`): the Noise IK handshake with per-session
  ephemeral keys, same forward-secrecy property.
- Neither the handshake server nor a relay is ever in a position to read it: the
  server carries no tunnel data at all, and a relay forwards only **sealed**
  packets (§6.4).

### 4.2 Mutual authentication, pinned by key

Each node presents its **Ed25519 identity as its TLS certificate key**, and each
side requires the other's certificate to carry **exactly** the expected public
key ([`internal/tunnel/quic.go`](internal/tunnel/quic.go), verified in
`VerifyPeerCertificate`). There is **no CA and no hostname** — identity *is* the
key — so a network man-in-the-middle cannot impersonate a peer without that
peer's private key. On the WireGuard plane the same pinning carries: the
partner's WG key is *derived* from its pinned Ed25519 key (§4.6), so nothing is
exchanged over the wire to be substituted.

### 4.3 The trust hierarchy — how a key becomes trusted

The token alone is a **bearer secret**: the handshake pairs the first two
registrations and signs whatever key registered. So on its own, a token-knower —
or a malicious/compromised handshake server — could be vouched for as "the
partner." BuddyNet closes this with a trust hierarchy (strongest first):

**1. Key-bound invite (`--invite` / `--join`, the default pairing path).** The
invite a buddy hands over is not a bare secret: it is
`bnet1.<token>.<inviter-public-key>` ([`internal/invite`](internal/invite/invite.go)).
`--join` splits it and **pins the inviter's key** before contacting the server, so
that direction is verified with **no human step at all** and is exactly as strong
as `--peer-key` — a handshake server that substitutes an identity is refused, not
merely noticed.

The trust anchor here is the channel the invite already travels over (phone,
Signal). That channel was always required; binding the key to it is what turns it
from a way to move a secret into a way to move an *identity*.

The reverse direction — the inviter verifying the joiner — is the one remaining
human step, and it is deliberately asymmetric: the **joiner displays** its code
and the **inviter types it in without seeing its own** (`PromptSASBlind`). A
person who cannot see a code cannot copy it off their own screen, so the six
characters can only have come from the buddy over the trusted channel.

A **malformed** invite is an error, never a silent fall back to the weaker
unpinned path. A **bare** token from an older inviter still pairs, by §2 below.

**2. `--peer-key` (strict pin).** The buddy's Ed25519 key, exchanged once
out-of-band. Any other partner is refused, no prompt. **Equivalent in strength to
the pin an invite carries, and the right choice for unattended daemons** — it
needs no invite exchange and no human at all, in either direction.

**3. Trust-on-first-use + SAS (fallback).** Used when neither side pinned the
other — a bare token, or a manual pairing. On the first connect for a token,
after the tunnel is up but **before the key is trusted**, both buddies display a
**Short Authentication String** — a 6-character code:

- QUIC plane: `SHA-256(sort(bothKeys) + TLS-exported-keying-material)`
  ([`internal/role/sas.go`](internal/role/sas.go)).
- WireGuard plane: bound to a fresh ephemeral-DH exchange run over the punched
  UDP socket (RFC 6189), since there is no TLS exporter there
  ([`docs/WIREGUARD.md`](docs/WIREGUARD.md)).

```
🔑 Safety check — first contact with this buddy.
        your code:  K7QX2M
Type your buddy's code: _
```

Call your buddy over a **trusted out-of-band channel** (phone, Signal), read them
**your** code, and **type in the code they read to you**. Both buddies do this,
so the check is mutual. Because the code is bound to the live session (channel
binding), a man in the middle — who terminates a *different* session to each side
— makes the two codes differ, so the entry is rejected. This catches the MITM
**at first contact**, not after the fact, and it holds **even against a malicious
handshake server**: a substituted key yields a mismatching code. On a match the
key is pinned (indexed by a *hash* of the token, never the token in clear) and
later connects are checked silently. A rejected SAS aborts and never falls back
to another plane.

> **Why type it, not press `y`:** requiring the code to be *entered* means it
> cannot be confirmed without actually receiving it out of band — a reflexive
> keypress no longer trusts an unverified key.
>
> This symmetric form has one residual: both ends derive the *same* code and both
> display it, so a user could type their **own** code instead of the one they
> heard. That is far more deliberate than a single `y`, but it is why the invite
> path above is asymmetric — there the verifying side never sees a code to copy,
> and the residual is gone rather than merely made inconvenient. For unattended
> links `--peer-key` removes the human step entirely.

**4. `--lab` — no verification at all.** Must be set explicitly, is logged
loudly, **testing only.** Never use it on a daemon or a server-side host.

For daemons/Unraid there is no human to compare a SAS: run with `--no-interactive`
and **pin with `--peer-key`**. An unknown key is then refused rather than learned
blind.

#### The trust store (`known_peers`)

The SAS protects the **first** connect. After that, the partner key is read from
`known_peers` and trusted on every subsequent connect without a prompt. That file
is therefore a **trust anchor** and must live in the **same trust domain as the
identity key**:

- Keep it `0600` next to `id.key` (the systemd sandbox already enforces a `0700`
  directory). **Do not** put `--known-peers` on a synced/shared location
  (Dropbox, Syncthing, NFS/SMB) or in a world-writable path: anyone who can
  rewrite the file there can swap in a different key, and a later connect would
  trust it silently (the SAS already happened).
- A local attacker running **as the same user** can rewrite `known_peers` — but
  that attacker also owns `id.key`, so they are already inside the node's trust
  domain; this is out of scope at the application layer (rely on file
  permissions, a dedicated user, and the systemd sandbox). Application-level
  signing of the store would not help, since the same key signs it.
- For the strongest setup, skip the store entirely and **pin with `--peer-key`**;
  then `known_peers` is not consulted at all.

#### Invite token vs. session secret

The pairing secret is split so the value that actually travels is short-lived:

- **`--invite` / `--join`** mint/use a **one-time, key-bearing invite**, valid
  only until the first pairing (`--invite-timeout`, default 15 min). It carries
  the inviter's public key, so the joiner pins it (see §4.3). On the first
  SAS-confirmed (or `--peer-key`-pinned) pairing, both ends **derive a long-lived
  session secret from the channel binding** (`HKDF`-style over the exported
  keying material + both keys) and store it next to the partner key. It is
  **never transmitted** — both sides compute the same value, and a man in the
  middle (a different session per side) derives a different one.
- All later **reconnects use the stored session secret** as the rendezvous token;
  the invite token is retired after first use. So a leaked invite is worthless
  after 15 min or after the first connect, and the long-lived secret never
  appears in a chat log or on the wire.
- **`--join`** is the legacy mode: a single fixed token used for rendezvous on
  every reconnect (no session secret). Fine for scripted/daemon setups,
  especially together with `--peer-key`.

This is hygiene, not a new confidentiality guarantee — impersonation is already
caught by `--peer-key`/SAS. It shrinks the exposure of the one secret you hand to
your buddy out of band.

### 4.6 One identity key, many roles — a reviewed reuse

From the one Ed25519 identity, BuddyNet derives — deterministically — an X25519
keypair ([`internal/crypto/x25519.go`](internal/crypto/x25519.go)) that serves as
the long-term key of **more than one protocol at once**: the NaCl **sealed box**
for enrollment codes, the static-static DH behind the **rendezvous secret**, and
the shipped **WireGuard** static key. The same seed also signs (Ed25519) and
seeds the virtual IP.

The textbook reflex is "one key, one purpose." We deliberately keep the single
shared key, because separating it would break the load-bearing invariant that a
peer can recompute another peer's keys from the **pinned public key alone**, with
no key exchange (§1). A per-protocol key derived with `HKDF(seed, label)` needs
the private seed, so the public half could no longer be derived non-interactively;
giving each protocol its own exchanged/pinned public key would add a fresh key to
distribute and pin — a **real** MITM surface — to defend against a **theoretical**
cross-protocol concern the design already neutralises.

Why it is safe:

- **Ed25519 sign + X25519 DH from one seed** is the construction libsodium
  (`crypto_sign_ed25519_sk_to_curve25519`) and Signal use by design.
- **Separation lives at each consumer's KDF, not at the key.** The rendezvous
  secret runs the DH output through a **labelled** HKDF
  (`buddynet-pair-secret-v1` ‖ both public keys); the sealed box is domain-fixed
  by its own HSalsa20 construction and is the only NaCl-box user; WireGuard/Noise
  IK binds the static key into its handshake transcript.
- No shared signing oracle exists between the protocols.

**Invariant for contributors:** any *new* consumer of the identity-derived X25519
key MUST post-process the raw DH through a labelled KDF, and MUST NOT add a second
public-key derivation for the same identity. With the WireGuard data plane now
shipped, this three-protocol reuse of the one identity key is the designated item
for an external crypto review.

### 4.7 Key hygiene — at rest and in memory

- **File permissions.** Identity keys are `0600` files; the systemd sandbox
  enforces a `0700` directory. On load the key file is opened **`O_NOFOLLOW`**
  and every check (permissions) and fix (tightening `chmod`) is done on that one
  descriptor, so a symlinked or swapped path can never redirect the read/chmod to
  another file; the create path uses `O_CREATE|O_EXCL|O_NOFOLLOW`. A key file
  wider than `0600` is tightened in place with a loud `WARNING`, or the node
  refuses to run (fail-closed, like SSH).
- **No core-dump leak.** The systemd units set `LimitCORE=0` so the in-memory key
  cannot leak into a core dump.
- **Best-effort in-memory wipe.** Derived scalars and the raw DH output are zeroed
  after use (`internal/crypto`). This is defence in depth, **not a guarantee**:
  Go gives no hard promise (the GC may copy, and without `mlock` bytes can be
  paged to swap). On sensitive hosts, disable swap or encrypt it.
- **No passphrase / at-rest encryption / rotation.** See §9. Protect and back up
  the key (§8.1).

---

## 5. The control plane (handshake server)

### 5.1 Signed introductions

The handshake server signs every `PEER_LIST` over `(token, ts, peers)` with its
Ed25519 key. Buddies pin the server key (`--server-key`) and verify, with a
**±60 s freshness window**, so the control path cannot be tampered with or
replayed. A `ver` field in every message means an incompatible build is reported
clearly rather than as an opaque crypto error.

### 5.2 A spoof-proof control plane

The control plane is **QUIC/TLS 1.3**, and there is nothing to choose. It
structurally closes the spoofed-source reflection vector: QUIC validates the
source address in its own handshake, so the server never produces a `PEER_LIST`
for an address that has not proven it can receive packets, and it does so before
any server-side work. The cost is a certificate, which costs nothing here — the
server presents its self-signed identity cert and the buddy pins it by
`--server-key`, the same key-pinning model used for peer identity, with no CA and
no domain. The buddy runs the control connection on its **shared** UDP socket and
tears it down before punching, so the same NAT mapping still carries the peer
tunnel.

> **Removed in v5 (protocol v8): the plain-UDP transport.** It obtained the same
> return-routability proof with an application-layer `COOKIE` challenge
> (`HMAC(subkey, epoch ‖ source-IP)`, the reply smaller than the request, so never
> an amplifier). It is gone because it only reproduced what QUIC does anyway,
> while leaving the rest of a `REGISTER` in cleartext — and because a transport
> you can select is a transport a deployment can select wrongly. The **relay**
> still uses a cookie of its own: a relay bind is plain UDP by design, and that
> cookie covers the full source address, port included (§6.4).

The global + per-source rate limits and the bounded registry caps apply to the
control plane as before.

**Confidentiality of a `REGISTER`.** The whole exchange rides QUIC/TLS 1.3, so an
on-path observer sees ciphertext and nothing else. Underneath that, the one secret
in a `REGISTER` — the pairing token (and, on reconnect, the rendezvous secret) —
is *additionally* **sealed to the server's pinned identity key** (`TokenEnc`, a
NaCl sealed box), so it is never in the clear even inside the TLS session, and
since v8 the cleartext `token` field is not serialised at all. The rest of a
`REGISTER` (id, pubkey, virtual IP, name) is non-secret identity data. The
partner is pinned by key — from the invite, from `--peer-key`, or by SAS on first
contact (§4.3).

### 5.3 Server hardening

- **Bounded memory under spoofing.** An in-memory registry with hard caps stops
  spoofed-source memory exhaustion.
- **No reflection/amplification.** Covered structurally by §5.2; the server is
  never a useful UDP reflector.
- **Rate limiting before crypto.** A global ceiling bounds total per-packet crypto
  so a flood cannot saturate the read loop, and a bounded per-source bucket keeps
  one address from consuming the budget.
- **Replay rejection (approval mode).** Every `REGISTER` carries a fresh 128-bit
  nonce inside its signature; a bounded cache rejects a repeated
  `(pubkey, nonce)` within the freshness window. Only **approved** keys occupy a
  cache slot, so an outsider cannot flood it and evict a real buddy's entry.
- **Expensive crypto behind source validation.** QUIC validates the source
  address in its own handshake before the server spends anything on a
  registration, so a spoofed sender never reaches the signature verification or
  the sealed-token open.
- **Control-connection caps.** The QUIC control listener bounds connections
  globally **and per source address** (IPv4/IPv6/IPv4-mapped normalised), demands
  a first stream within seconds, and puts a read deadline on every request, so
  neither a broad flood nor one host parking connections can exhaust the table.
- **Relay caps.** The relay carries the same per-source bind rate-limit plus a
  legs-per-source ceiling, and a refused bind leaves no session behind, so the
  ceiling bounds table occupancy and not just legs. Since v5.0.0 these sit on top
  of an authorization policy (tickets and/or a network allowlist, §6.4) rather
  than standing in for one.
- **Bounded signature work on the relay.** A ticketed bind costs two Ed25519
  verifications, where a bind used to be nearly free. The address-validation
  cookie gates all of it — an unvalidated source can never make the relay verify a
  signature or allocate a session — and behind the cookie a **global** per-second
  budget, a hard cap on verifications **in flight** and a separately metered,
  per-session **reserve** bound the total. The per-source limiter alone would not:
  an attacker with many real addresses stays under every per-source budget while
  driving the total up. Verification also runs off the read loop, so a flood
  cannot stall the data path the relay exists to carry.
- **A half-open relay session expires absolutely** (60 s from creation, not
  extendable), because a leg's idle timer is refreshed by any packet from a bound
  source — one leg plus a trickle would otherwise hold a slot indefinitely.
- **What counts as one source.** Every per-source budget in BuddyNet — the
  control-connection cap, the handshake rate limits, the relay's bind limiter and
  leg cap — charges the same key (`internal/netkey`): **one IPv4 address**, or
  **one IPv6 `/64`**, with IPv4-mapped IPv6 folded onto the IPv4 key. IPv6 is
  aggregated because every address inside a `/64` is free to mint, so counting per
  address counts nothing; IPv4 is not, because addresses are scarce enough there
  that rotation is no lever and aggregating would fold unrelated customers of one
  provider together. This removes **free** rotation inside one `/64` — it is not a
  claim that an attacker is limited to one budget: a site delegated a `/56` or
  `/60`, or a botnet, still commands several. Use `--allow-cidr` or a firewall for
  a relay that should not be open to strangers.
- **Network allowlist.** `--allow-cidr` restricts which source networks may reach
  the relay **and** the handshake server, dropping others before any crypto.
- **Anonymised logs.** Tokens are logged only as a hash (the log-tag HMAC key is
  HKDF-derived from the identity, never the raw seed).
- **Locked-down deployment.** Ships as a distroless/non-root image and a
  systemd sandbox with a size-capped log namespace, plus default-drop firewall
  rules. See [`deployments/`](deployments/).

### 5.4 Approval mode

With `--authorized`, only operator-approved client keys may pair: registrations
must carry a valid key-ownership signature, and outsiders are rejected outright.
`--authorized` alone decides the mode — a missing or empty allowlist file means
**zero** authorized clients, never open mode, and deleting the file at runtime
empties the loaded allowlist rather than leaving its last contents in force.

**Authentication and authorization sit at different layers.** On QUIC the TLS
handshake requires an Ed25519 client certificate and proof of possession, and
`REGISTER.pubkey` must equal that authenticated key or the connection is closed
with nothing stored. It does **not** decide who may pair: an unknown key has to be
able to complete the handshake, otherwise it could never deliver the enrollment
code that gets it approved. The allowlist decision is made per `REGISTER` —
approved keys pair, unknown keys with a valid sealed code become pending
enrollments, everything else is refused — and unknown keys run under a much
tighter rate limit than approved ones. Since the registration is bound to the
authenticated key and the sealed code is inside the registration signature, a
stranger can only ever enroll its own key.

Clients enroll with a short code sealed to the server's identity (`--code`); the
server prints the enrolling key and the operator approves THAT key while the
client is running. Nothing about a pending enrolment is written to disk, so there
is no `code → key` record to read or alter in between; see
[docs/APPROVAL.md](docs/APPROVAL.md).

---

## 6. The data planes

### 6.1 QUIC transport (default)

TCP forwarded over TLS 1.3 streams (`-L`/`-forward`). What a buddy can reach is
**exactly the connections you forward** — nothing else on your host is exposed.
`-L`/`-forward` accept a Unix domain socket (`unix:/path`, mode `0600`) as a safer
alternative to TCP loopback on shared/container hosts. The E2E and pinning
properties are §4.1–§4.2; the relay's blindness is §6.4.

### 6.2 WireGuard overlay (`--wireguard`)

Opt-in (set on **both** buddies), kernel WireGuard, brought up over raw netlink
(no `wg`/`ip` subprocess, no `wireguard-tools` dependency). It changes **only the
data plane** — the whole control plane (matchmaking, signed `PEER_LIST`,
pinning/TOFU with the SAS, the fallback chain, the blind relay, the 48-buddy cap)
is unchanged, and there is no protocol version bump. All the control-plane
guarantees above carry unchanged, and the WG key is *derived* from the pinned
Ed25519 identity (§4.6), so **nothing new is trusted** and `identity = key = VIP`
extends onto the data plane with nothing exchanged over the wire.

What is *different* about this plane, and therefore new in the threat model:

- **The exposure model flips from "scoped forwarder" to "L3 reachability."** On
  the QUIC plane a buddy reaches only what you forward. On WireGuard the partner
  is reachable natively at your VIP for *any* protocol. That makes a **trusted but
  hostile paired buddy** a first-class adversary (row 8 of §3), which §6.3
  contains by default.
- **The trust boundary extends into the kernel.** A crafted tunnel packet on the
  QUIC plane hits a userspace goroutine wrapped by `internal/safe`'s
  panic-recovery. On the WireGuard plane it hits the **kernel** WireGuard
  implementation and netfilter instead — code BuddyNet does not own and cannot
  wrap. The robustness of that path rests on the host kernel's own WireGuard and
  nftables subsystems; keep the kernel patched. This is the reason the WG plane is
  **opt-in** and QUIC remains the default.
- **Fails closed.** WG unavailable, no usable path, or a rejected SAS → an error,
  never a silent switch to another data plane.
- **The relay stays blind here too** — it forwards sealed WireGuard packets and is
  not a WireGuard peer (§6.4). A WireGuard **hub** on the VPS was rejected on
  purpose: a hub terminates WireGuard and would see plaintext.

BuddyNet routes only the partner's VIP `/32`, **never the LANs/VLANs behind it** —
it is not a subnet router (see §10).

### 6.3 Scoped exposure (`--expose`)

This is what contains a hostile paired buddy on the WireGuard plane. **Formerly
the documented residual risk** — the VIP is a real host address, so every service
on `0.0.0.0` used to be reachable by the paired buddy — **now closed as a
property:**

- Inbound on each `bnetN` is **fail-closed by default.** A buddy reaches **only**
  the port(s) the operator names with `--expose` (or per buddy via `expose:` in
  the manifest); without a scope, **nothing** (ping stays allowed for diagnosis).
  Whole-host access requires the explicit **`--expose all`**.
- Enforcement is in the kernel's nftables subsystem, a **private `buddynet`
  table** programmed over raw nfnetlink (no dependence on any userspace firewall
  tool, and it never touches the host's own `filter`/ufw/firewalld tables). It is
  installed **before** the interface exists, and the tunnel **refuses to come up**
  if the scope cannot be programmed — never fail-open.
- The host firewall can never *widen* the scope (a drop in any table wins); on a
  default-deny host firewall, tunnel traffic needs an allow there too (both layers
  must agree — defence in depth). Each buddy has its own interface and thus its
  own scope (MultiPeer).

**Exposing a service is the operator's decision, and it is a real one.** What a
buddy can reach over the tunnel is whatever the scope names, and that service's
own security then matters:

- The exposed service is reachable **only** by the pinned, mutually
  authenticated tunnel peer — never by the network at large. An exposed port is
  not an open port on the internet.
- It is still reachable by a buddy who is compromised or malicious. Expose the
  minimum: one port, and a service you keep patched. `--expose all` means what it
  says.
- A service's own authentication (an SMB password, an rsync secret) selects
  *which* account the buddy uses. It is not the boundary that keeps everyone else
  out — the key-pinned tunnel and the fail-closed scope are.
- An **already-established** connection survives the removal of a scope until it
  disconnects (the established-traffic rule). To cut it immediately, restart the
  tunnel or disable the account in the service itself.

### 6.4 The blind relay

Used only when no direct path exists. It forwards **encrypted** datagrams between
two legs keyed by an opaque session id — it sees ciphertext and virtual IPs, never
plaintext, and holds **no private key** on either plane. It cannot read or inject
(QUIC/WireGuard authentication). Its abuse ceilings and its spoof-proof leg
binding are in §5.3 and §3 (relay rows).

**Since v5.0.0 it is no longer open.** A relay admits a session only if a
handshake server the operator named authorised it (a signed **relay ticket**),
and/or if the source is inside a named network. It refuses to start with neither,
and `--allow-cidr 0.0.0.0/0` is refused rather than accepted as a policy.

What the relay learns is deliberately kept minimal, and the ticket design is what
keeps it that way:

- it verifies **that** the server authorised this session, never **who** is in it.
  A bind carries no durable identity, only an opaque server-chosen session id and
  an ephemeral key that exists for one attempt;
- there is **no buddy list on the relay**. Checking one would require the buddy's
  durable key in the bind, and the relay would then know who talks to whom —
  metadata it deliberately does not have, plus runtime state on a server, which is
  the shape behind every persistence bug this project has had;
- its logs carry a shortened session id, the leg and a reason. **Source addresses
  only under `--debug`.**

A ticket is bound to a **fresh ephemeral key per attempt**, and the bind must
carry a signature by that key over the relay's own rotating cookie, which is bound
to the full source address — **IP and port**. So a captured ticket, or an entire
captured bind, is inert: it cannot be replayed from another address, **not even
from a different port behind the same public IP** (the case an IP-only cookie left
open until v5.1.1: on-path neighbours on the same NAT could replay a capture and
have the leg follow them, redirecting the buddy's encrypted traffic), cannot be
replayed after the cookie epoch turns, and cannot be re-signed — the private half
never leaves the buddy. A ticket authorises
**joining, not staying**: an established session is not torn down when it expires,
but nothing new can be bound with an expired one, including a re-bind after an
address change.

**Combined roles cost blast radius.** `--role=handshake,relay` runs both in ONE
process, so the server's signing key sits in the memory that also parses relay
packets: code execution reached through the relay could then **sign tickets**,
which is strictly worse than abusing a relay — it forges authorisation for every
relay that trusts that key. "The relay holds no private key" is a property of the
**separated** deployment (two processes, ideally two users, ideally two hosts).
Both are supported; they are not equivalent, and the choice belongs to whoever
writes the command.

**Residual risks, stated:**

- **Clocks.** Relay and server must agree within 10 s or every ticket is refused.
  A relay cannot tell a skewed clock from a tampered ticket, so its rejection line
  names both causes and asserts neither.
- **Tickets authorise, they do not meter.** A paired buddy may use the relay as
  much as it likes. This is access control, not cost control.
- **A packet flood still degrades a relay.** The ticket budgets (a global
  verification ceiling, an in-flight cap, a small per-session reserve) bound the
  *cryptographic* work an attacker with many real addresses can force. The coarse
  per-second bind limiter that predates them sits in front and drops cheap packets
  indiscriminately, so a flood above that rate delays legitimate binds too. It is
  bounded, not eliminated.
- **A live session id is not a secret.** Anyone who learns one can contend for
  that session's own share of the small reserve. It buys no admission — both
  signature checks still run first and no state is allocated — and it cannot reach
  other sessions' capacity, which is what the per-session limit is for.

---

## 7. Detecting an attack

When a SAS is **rejected** (explicit mismatch), the buddy logs a full record —
remote endpoint (annotated as the peer's real address on a direct path, or the
relay's on a relayed one), the claimed virtual IP, the partner public key, the
token hash, and a UTC timestamp — and aborts without trusting the key:

```bash
journalctl --namespace=buddynet | grep "SAS REJECTED"
```

A timeout (no answer) is logged separately as caution, not as an attack.

### Log schema

Logs use three deliberately distinct, grep-friendly levels:

```bash
# 1) Security events — always logged, never suppressed, key=value:
journalctl --namespace=buddynet | grep '^.*SECURITY:'
#   event=replay-detected | squat-rejected | new-pubkey | key-changed
#         | pin-mismatch | vip-mismatch | leg-cap-hit | panic-recovered
#         token=<tag> src=<ip> key=<b64[8]> component=<site> ...

# 2) State transitions — CONNECTED / DISCONNECTED / PAIRED / TRUST / AUTHZ:
journalctl --namespace=buddynet | grep -E '(CONNECTED|DISCONNECTED|PAIRED|TRUST|AUTHZ):'
#   DISCONNECTED carries reason=<idle|reauth|shutdown|...> and duration=
#   CONNECTED/PAIRED/TRUST carry the STABLE key=<b64[8]> (not the ephemeral id)

# 3) Per-minute aggregates — only when active; ALERT segment on security counters:
journalctl --namespace=buddynet | grep 'stats (last'
#   stats (last 1m0s): role=handshake paired=.. challenged=.. rate-limited=.. dropped=..
#                      [ALERT: new-pubkey=.. squat-rejected=.. replay=.. panics=..]
#   stats (last 1m0s): role=relay paired=.. challenged=.. rejected=.. [ALERT: leg-cap=.. panics=..]
```

Each role tags its lines with a `SyslogIdentifier`, so you can narrow to one role
within the namespace: `journalctl --namespace=buddynet -t buddynet-handshake` (or
`-t buddynet-relay`, `-t buddynet-buddy@<name>`).

Peer identity in the audit trail is the **stable key tag** (`key=<first 8 chars of
the base64 pubkey>`), so it survives reconnects — unlike the ephemeral per-run id.
Tokens are anonymised: a server-keyed HMAC on the handshake/authz side (so the
same token maps to the same `token=` tag without becoming a public guessing
oracle) and a plain truncated hash on the buddy side.

An `ALERT:` segment, any `SECURITY:` line, or a sustained spike in
`rate-limited`/`dropped`/`rejected` is the signature of an attack being absorbed
(a spoofed-source flood, a token-squat, or a replay attempt). A non-zero `panics=`
in the ALERT is the per-interval count of handler panics recovered by the safety
net (see `panic-recovered` above): a rising value means a crafted input is
reliably tripping a parser (ours or a dependency's) and is worth investigating
even though the process kept running.

---

## 8. Operational security

### 8.1 Lost identity keys

Identity *is* the key, so losing the file changes who the node **is**.

Since v5.0.0 the two roles behave differently on purpose:

- **A server role refuses to start** without its key (`--role=handshake`, both
  binaries). It does not generate one, because from inside the process a first run
  and a lost key are indistinguishable — and inventing a replacement would bring
  the node up as a *different* server that every buddy rejects as a possible MITM.
  The refusal names the path and prints the `init` command. Creating an identity is
  only ever `buddynet --key PATH init`, which also refuses to replace an existing
  one.
- **A buddy still creates its key on first start.** Setting one up is a person on
  their own machine, and a buddy that loses its key is re-pinned by its one
  partner rather than locking a network out.

Either way the new identity is **not** trusted automatically (the safe behaviour):

- **Server key lost:** restore it from backup. If you genuinely start over
  (`init`), every buddy must update its pinned `--server-key`.
- **Buddy key lost, `--peer-key` in use:** the partner rejects the new key as a
  mismatch until it updates the pin **and** drops the session stored from the old
  pairing (`peers remove <old key>`, then a fresh invite) — like SSH's "host key
  changed", where the old entry has to go too.
- **Buddy key lost, allowlist server:** re-enroll the new key (`--code`, then
  `approve` the key the server logs), revoke the dead one.

**Prevention:** keys are tiny `0600` files — persist them on durable storage
(server: `StateDirectory`/volume; buddy: `--key`) and back them up.

### 8.2 Revoking access

> **Since v5.2.0.** The revocation list described below, and `peers allow` to
> lift it, are new in that release. In v5.1.x and earlier, `peers remove` dropped
> the manifest entry and the session but kept no record, so a still-running buddy
> could re-pair itself back in.

BuddyNet's data plane is a **direct** peer-to-peer tunnel — once two buddies have
punched a path, the handshake server is no longer in it and **cannot tear that
tunnel down**. Revocation is therefore not instantaneous the way it is in a
hub-and-spoke VPN. What actually revokes access:

- **Approval mode (`--authorized`).** `revoke <key>` removes a client from the
  allowlist so it can no longer *re-pair*; an already-established tunnel keeps
  running until it next re-registers.
- **`--peer-key` pin — changing it, not removing it.** *Changing* the pin on the
  surviving side revokes: the buddy compares the configured pin against the pin
  stored from the previous pairing, and if they disagree it refuses to connect at
  all — before it even registers with the handshake server — and prints how to
  re-pair. *Removing* the pin is **not** a revocation and is not meant to be: with
  no `--peer-key` there is nothing to compare, the stored session pin governs, and
  the connection continues. Dropping a flag must not silently delete state.
  A changed pin therefore also needs the stored session cleared —
  `peers remove <old key>` (or "Forget buddy" in the Unraid plugin) — followed by
  a **new invite**. That, and not the flag alone, is the complete revocation.
- **Token rotation.** Re-invite (`--invite`) to mint a fresh token and retire the
  old session secret; the old credential stops working for new connects.
- **`peers remove <key>` — the complete one.** It records the key on a permanent
  local revocation list (`<known_peers>.revoked`) **and** drops the stored session
  secret **and** the manifest line, in that order under one lock. The list is what
  makes it stick: a still-running buddy used to re-pair on the bootstrap token it
  held in memory and write its session straight back, so the `SIGHUP` meant to
  apply the revocation restarted it instead. Now the key is refused at every
  door — the next reconnect attempt stops that worker, no session can be stored
  for it, it cannot be learned trust-on-first-use, and a `SIGHUP` will not
  re-assemble it. This is a purely local, self-sovereign decision: it revokes that
  buddy from *your* node only and never affects your other buddies. It works with
  or without a manifest.

  Lift it deliberately with `peers allow <key>` (or by adding the buddy back with
  `peers add`), and only together with a **new invite** — the old session secret
  is gone. Nothing expires the list on its own: a tombstone that ages out is
  exactly when the zombie comes back.

To **bound** how long an established tunnel can outlive a revocation, run the buddy
with **`--reauth-interval`** (off by default). It rebuilds the tunnel on that
interval, re-running the allowlist/trust checks each time — so a revocation takes
effect within one interval, at the cost of a brief reconnect (leave it off for
uninterrupted long transfers like a multi-hour backup). To cut a live tunnel
**immediately**, stop the revoked node's process (`systemctl stop …`) or block it
at the firewall.

### 8.3 Release integrity

Release binaries are built by GitHub Actions (pinned by commit SHA; Docker base
images pinned by digest) and **keyless-signed with cosign/Sigstore**. Each
artifact ships a `.bundle` (signature + certificate + Rekor transparency-log
proof) and a `.sha256`, and every release carries an SPDX SBOM. Verify provenance
before trusting a download:

```bash
cosign verify-blob --bundle buddynet-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github\.com/TZERO78/buddynet/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  buddynet-linux-amd64
```

The identity regexp ties the signature to **this repository's release workflow at
a SemVer tag**, and the OIDC issuer to GitHub's Actions token — a binary signed by
anything else fails. The anchors and escapes matter: an unanchored
`^https://github.com/TZERO78/buddynet` would also accept any other workflow in
this repo, any branch instead of a tag, and any same-owner repository whose name
merely *starts* with `buddynet` (there is no `/` after it), and the unescaped dots
would match any character.
(Releases through v1.1.0 used separate `.sig`/`.pem`; v1.1.2 onward uses the
`.bundle`.) The Unraid plugin pins the published binary's SHA-256 and refuses to
install on a mismatch.

Releases **after v5.2.0** additionally carry a SLSA build provenance attestation,
generated by `actions/attest` in the same release workflow and under the same
short-lived OIDC identity:

```bash
gh attestation verify buddynet-linux-amd64 --repo TZERO78/buddynet   # gh >= 2.49
```

This is not a second copy of the cosign check. The cosign bundle is a **file next
to the binary** and verifies offline; the attestation is **stored at GitHub** and
additionally binds the artifact to the source commit and workflow run it was
built from. So it strengthens the answer to "was this built from the source I can
read?" and weakens nothing — but it is retrieved from GitHub, and therefore worth
nothing against a threat model in which GitHub itself is the adversary. The
cosign bundle plus a rebuild remains the check that does not depend on that.
Attestations exist only for releases built after the workflow change; for older
tags the command correctly reports that it found none.

---

## 9. Limits — what BuddyNet cannot do

### 9.1 What it cannot protect against

BuddyNet secures a connection between two machines. It cannot secure the
machines. Concretely, none of the following are things it can help with:

- **A compromised endpoint.** Once an endpoint is compromised with root or
  equivalent access, the attacker can generally access everything that this
  endpoint can access. BuddyNet cannot repair a compromised operating system.
  This is a normal system boundary, not a weakness specific to this project.
- **Malware on a buddy's machine**, or a buddy who is themselves hostile: they
  are a legitimate, authenticated peer of yours.
- **A stolen identity key.** Whoever holds `id.key` *is* that node until you
  revoke it on the other side (§8.1, §8.2).
- **An insecure host or server configuration** — a weak SSH setup, an open
  firewall, wrong file permissions, an unpatched kernel.
- **A service you deliberately exposed.** `--expose 445` means your buddy can
  talk to that service; its own bugs and its own authentication are its own.
- **Denial of service in general.** Rate limits and bounded state stop one source
  from consuming unbounded work; they cannot stop someone from saturating a small
  VPS's uplink. Availability is a property of your network and your provider.
- **Vulnerabilities in what BuddyNet is built from** — the operating system, the
  kernel, Go, QUIC (`quic-go`), kernel WireGuard, or any dependency. They are
  pinned and scanned (`govulncheck` in CI), which is not the same as being free
  of them.
- **Operator error**, and **lost or corrupted backups**. BuddyNet is a transport;
  it neither makes backups nor verifies them.

**The source code is public, and an attacker may be assumed to know all of it.**
That is deliberate: security here comes from keys and secrets, never from
anything being hidden. The only things that must stay secret are identity keys,
invite tokens, session secrets and enrollment codes. Open source cuts both ways —
it lets an attacker study the design, and it lets anyone verify it. There is no
"security through obscurity" claim anywhere in this project, and none should be
read into it.

### 9.2 Deliberately out of scope

- **Server-forced disconnect of a live tunnel.** The handshake server is not in
  the data path, so it **cannot kill an established direct tunnel** — see §8.2 for
  what to do instead. A server-side token blacklist is still not built: it would
  close only a narrow window at the cost of new attack surface.
- **At-rest key encryption / rotation.** No passphrase; see §4.7 for what *is*
  done (permissions, no core dump, best-effort wipe) and the swap caveat.
- **Per-stream idle timeout.** Forwarded streams are bounded only by the session
  idle timeout (`--idle-timeout`) and the 256-stream cap, not by an independent
  per-stream deadline — an aggressive one would kill legitimately idle streams
  (e.g. an interactive SSH session), so it is deliberately omitted.
- **Local tampering of `peers.json` / `known_peers`.** These caches have no
  integrity protection, but they live in a `0700` dir alongside the identity key:
  a local attacker with write access there already controls the node. Pinning and
  the SAS still hold regardless of cache contents.
- **The host kernel's WireGuard / netfilter implementation.** On the `--wireguard`
  plane, crafted-packet robustness below BuddyNet's own scope enforcement is the
  kernel's responsibility (§6.2); keep it patched.

---

## 10. Non-goals / positioning

BuddyNet is a small, self-hosted peer-to-peer network for families, friends and
small teams. It reduces dependence on a managed VPN provider; it does not attempt
to replace the administration, support, platform coverage or enterprise features
of Tailscale or NetBird, and it is not measured against them. Concretely:

- **Recommended size: roughly 2 to 16 buddies per node.** That is the range this
  is built and tested for.
- **Hard cap of 48 peers**, enforced fail-closed in the code. That is a
  guardrail against a runaway manifest, **not** a capacity target and not a
  recommendation. For more than a handful of machines, use a tool designed for
  fleets.
- **Connects hosts, not networks.** It routes only a partner's VIP `/32`, never
  the LANs/VLANs behind it — it is not a site-to-site/subnet router.
- **No central hub that sees plaintext.** Peer-to-peer first, blind relay as
  fallback; a plaintext-terminating hub was rejected on purpose (§6.2, §6.4).

---

## 11. Reporting a vulnerability

Please open a **private security advisory** on the repository rather than a public
issue.

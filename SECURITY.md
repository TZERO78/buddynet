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
9. [Deliberately out of scope](#9-deliberately-out-of-scope) and
   [non-goals](#10-non-goals--positioning).
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
| **Peer authenticity** (you are talking to the right buddy) | Key pinning; TOFU + SAS | §4.2–§4.3 |
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
| Malicious / compromised **handshake server** | Cannot impersonate a buddy: a substituted key fails the SAS (or is refused by `--peer-key`). Can deny service. | **Mitigated** |
| A **relay** in the data path | Sees only ciphertext; cannot read or inject (QUIC/WireGuard auth). | **Safe** |
| Someone who learns the **token** | Cannot impersonate a buddy (SAS / pin). Can at most occupy a pairing slot and *deny* the legitimate pair — a DoS, not a breach. The token (and the reconnect rendezvous secret) is **sealed to the server's pinned key** (`TokenEnc`) even on plain UDP. | **Mitigated** |
| Spoofed-source flood / reflection on the **handshake server** | Source address validated first (UDP cookie or QUIC) before any `PEER_LIST`; global + per-source rate limits and bounded state cap the rest. Never a useful amplifier (§5.2–§5.3). | **Mitigated** |
| Spoofed-source reflection / traffic-laundering through a **relay** | A bind binds no leg until the source echoes an address-validation cookie (reply smaller than the bind); a spoofed source can never validate, so attacker data can never be forwarded to a victim address. | **Mitigated** |
| **Malicious / compromised paired buddy** (WireGuard plane) | Reaches only the port(s) you `--expose`; without a scope, nothing (fail-closed). It is a *trusted* peer by construction — treat what you expose as reachable by a hostile peer and keep it patched and least-privileged (§6.3). | **Scoped** |
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

**1. `--peer-key` (strict pin).** The buddy's Ed25519 key, exchanged once
out-of-band. Any other partner is refused, no prompt. **Strongest; recommended
for anything important, and required for unattended daemons.**

**2. Trust-on-first-use + SAS (default).** On the first connect for a token,
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
> keypress no longer trusts an unverified key. The residual is a user who types
> their **own** displayed code instead of the one they heard; that is far more
> deliberate than a single `y`, but for unattended links use `--peer-key`, which
> removes the human step entirely.

**3. `--lab` — no verification at all.** Must be set explicitly, is logged
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

- **`--invite` / `--join`** mint/use a **one-time invite token**, valid only
  until the first pairing (`--invite-timeout`, default 15 min). On the first
  SAS-confirmed (or `--peer-key`-pinned) pairing, both ends **derive a long-lived
  session secret from the channel binding** (`HKDF`-style over the exported
  keying material + both keys) and store it next to the partner key. It is
  **never transmitted** — both sides compute the same value, and a man in the
  middle (a different session per side) derives a different one.
- All later **reconnects use the stored session secret** as the rendezvous token;
  the invite token is retired after first use. So a leaked invite is worthless
  after 15 min or after the first connect, and the long-lived secret never
  appears in a chat log or on the wire.
- **`--token`** is the legacy mode: a single fixed token used for rendezvous on
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

### 5.2 Two spoof-proof transports

The control plane can run over either transport. **Both structurally close the
spoofed-source reflection vector** — the server never produces a `PEER_LIST` for
an address that has not proven it can receive packets. They differ only in how
that proof is obtained.

- **Plain UDP + address-validation cookie (default).** A `REGISTER` without a
  valid cookie is answered only with a small `COOKIE` challenge — *smaller* than
  the request, so never a useful amplifier — and no further work. The cookie is
  `HMAC(subkey, epoch ‖ source-IP)` (the subkey HKDF-derived from the server
  identity), so a spoofed source can never receive and echo it. The buddy echoes
  it on its next `REGISTER`. This is QUIC's Retry-token idea at the application
  layer: zero extra dependencies, no TLS certificate, and the buddy's single
  socket is untouched (so hole punching and the peer tunnel are unaffected).

- **QUIC (`--quic-handshake`).** The control plane runs over QUIC, which validates
  the source address in its own handshake before the server does any work. The
  cost is a TLS certificate: the server presents its self-signed identity cert and
  the buddy pins it by `--server-key` — the same TOFU model already used for peer
  identity, no CA or domain. The buddy runs the QUIC control connection on its
  **shared** UDP socket and tears it down before punching, so the same NAT mapping
  still carries the peer tunnel.

Set the **same** transport on the server and every buddy (`--quic-handshake`, or
`BUDDYNET_QUIC=1`); a mismatch simply fails to connect. On both transports the
global + per-source rate limits and the bounded registry caps still apply.

**Confidentiality of a `REGISTER`.** Plain UDP `REGISTER`s are otherwise cleartext
JSON, but the one secret in them — the pairing token (and, on reconnect, the
rendezvous secret) — is **sealed to the server's pinned identity key** (`TokenEnc`,
a NaCl sealed box), so an on-path observer sees only ciphertext where the secret
would be. The rest of a `REGISTER` (id, pubkey, virtual IP, name) is non-secret
identity data. `--quic-handshake` additionally encrypts the *whole* exchange.
Either way, the partner is still pinned by key and verified by SAS; treat the
token as a bearer secret and pin buddies with `--peer-key`.

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
- **Expensive crypto behind source validation.** On the plain-UDP transport the
  address-validation cookie is checked *before* anything asymmetric runs — the
  sealed token, the registration signature and the sealed enrollment code are all
  unreachable from an unvalidated (and therefore spoofable) source. The only
  crypto ahead of it is the cookie's own HMAC.
- **Control-connection caps.** The QUIC control listener bounds connections
  globally **and per source address** (IPv4/IPv6/IPv4-mapped normalised), demands
  a first stream within seconds, and puts a read deadline on every request, so
  neither a broad flood nor one host parking connections can exhaust the table.
- **Relay caps.** The relay carries the same per-source bind rate-limit plus a
  legs-per-source ceiling. It stays unauthenticated **by design** — the caps are
  abuse ceilings, not access control.
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

Clients enroll with a short code sealed to the server's identity (`--code`,
approved via `allowclient <code>`); see [docs/APPROVAL.md](docs/APPROVAL.md).

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

### 6.3 Scoped exposure (`--expose`) and BuddyShare

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

**BuddyShare (SMB over the scoped door).** The flagship use exposes the host's
**Samba** to the paired buddy (`--expose 445`), nothing else. In threat-model
terms:

- The buddy-reachable surface is **smbd** — a large, widely audited C codebase
  with its own CVE history. It is reachable **only** by the pinned,
  mutually-authenticated tunnel peer, never by the network at large; this is not
  an open port 445. Still, a buddy who is compromised (or malicious) gets to talk
  to your Samba — patch Unraid as usual, and grant the share user the minimum
  rights (read-only where possible).
- **The SMB password is not a security boundary.** It selects which Unraid user
  the buddy is (and thus their per-share rights); the boundary that keeps everyone
  else out is the key-pinned, end-to-end-encrypted tunnel plus the fail-closed
  scope. With several buddies, each can reach `:445`, but each can only
  authenticate as the user whose password they hold.
- **Public shares bypass the user layer by definition** — any SMB client may open
  them, so the paired buddy can too the moment the tunnel is up. The plugin warns
  prominently; the fix is Unraid's own share security (Secure/Private). The
  tunnel-scope layer is unaffected either way.
- Two identities, one coupling: the buddy's BuddyNet key (tunnel) and their Unraid
  share user (folders) are independent credentials; the coupling is "only this key
  reaches `:445`." Revocation works per layer and each layer alone suffices (see
  [`docs/BUDDYSHARE.md`](docs/BUDDYSHARE.md)); note that an already-established SMB
  session survives a scope removal until it disconnects (the established-traffic
  rule) — disable the user or restart the tunnel to cut it immediately.

### 6.4 The blind relay

Used only when no direct path exists. It forwards **encrypted** datagrams between
two legs keyed by an opaque token — it sees ciphertext and virtual IPs, never
plaintext, and holds **no key** on either plane. It cannot read or inject
(QUIC/WireGuard authentication). It is unauthenticated by design; its abuse
ceilings and its spoof-proof leg binding are in §5.3 and §3 (relay rows).

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

Identity *is* the key. If a node loses its key file, it generates a **new** one
and logs a loud `WARNING: generated a NEW identity`. The new identity is **not**
trusted automatically (the safe behaviour):

- **Server key lost:** every buddy must update its pinned `--server-key`.
- **Buddy key lost, `--peer-key` in use:** the partner rejects the new key as a
  mismatch until it updates the pin (like SSH's "host key changed").
- **Buddy key lost, allowlist server:** re-enroll the new key (`--code` then
  `allowclient`), revoke the dead one.

**Prevention:** keys are tiny `0600` files — persist them on durable storage
(server: `StateDirectory`/volume; buddy: `--key`) and back them up.

### 8.2 Revoking access

BuddyNet's data plane is a **direct** peer-to-peer tunnel — once two buddies have
punched a path, the handshake server is no longer in it and **cannot tear that
tunnel down**. Revocation is therefore not instantaneous the way it is in a
hub-and-spoke VPN. What actually revokes access:

- **Approval mode (`--authorized`).** `revoke <key>` removes a client from the
  allowlist so it can no longer *re-pair*; an already-established tunnel keeps
  running until it next re-registers.
- **`--peer-key` pin.** Change or remove the pin on the surviving side; the
  revoked key is then refused on the next connect.
- **Token rotation.** Re-invite (`--invite`) to mint a fresh token and retire the
  old session secret; the old credential stops working for new connects.
- **`peers remove <key>` (MultiPeer).** Removing one drops **both** its manifest
  line and its stored session secret, so it can no longer re-pair. This is a
  purely local, self-sovereign decision: it revokes that buddy from *your* node
  only and never affects your other buddies. A running daemon applies it on
  `SIGHUP` (or restart).

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
  --certificate-identity-regexp '^https://github.com/TZERO78/buddynet' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  buddynet-linux-amd64
```

The identity regexp ties the signature to this repository's workflow, and the OIDC
issuer to GitHub's Actions token — a binary signed by anything else fails.
(Releases through v1.1.0 used separate `.sig`/`.pem`; v1.1.2 onward uses the
`.bundle`.) The Unraid plugin pins the published binary's SHA-256 and refuses to
install on a mismatch.

---

## 9. Deliberately out of scope

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

BuddyNet is a **two-person (small-circle) tool** to connect a handful of hosts
securely — deliberately **not** a mesh VPN and not measured against Tailscale or
Netbird. Concretely:

- **Hard cap of 48 buddies** (fail-closed). For more, use a mesh VPN — that is a
  different tool.
- **Connects hosts, not networks.** It routes only a partner's VIP `/32`, never
  the LANs/VLANs behind it — it is not a site-to-site/subnet router.
- **No central hub that sees plaintext.** Peer-to-peer first, blind relay as
  fallback; a plaintext-terminating hub was rejected on purpose (§6.2, §6.4).

---

## 11. Reporting a vulnerability

Please open a **private security advisory** on the repository rather than a public
issue.

# Security model

BuddyNet brings up an end-to-end-encrypted overlay between machines behind NAT.
This document states honestly what it protects against and what it assumes — no
overclaiming.

## What protects the data

- **End-to-end encryption.** The tunnel is QUIC with TLS 1.3: confidential,
  integrity-protected, with forward secrecy (ephemeral ECDHE). Compromising a
  node's long-term identity key does **not** decrypt past captured traffic.
- **Mutual authentication, pinned by key.** Each node presents an Ed25519
  identity (its TLS certificate key). Each side requires the other's certificate
  to carry exactly the expected public key
  ([`internal/tunnel/quic.go`](internal/tunnel/quic.go)). There is no CA and no
  hostname — identity is the key — so a network man-in-the-middle cannot
  impersonate a peer without that peer's private key.
- **Signed introductions.** The handshake server signs every `PEER_LIST` over
  `(token, ts, peers)` with its Ed25519 key. Buddies pin the server key and
  verify, with a ±60 s freshness window, so the control path cannot be tampered
  with or replayed.
- **No data through the servers.** The handshake server only does matchmaking;
  a relay (if used) forwards **encrypted** QUIC datagrams blindly. Neither ever
  sees plaintext — only virtual IPs and ciphertext.
- **Hardened server.** In-memory registry with hard caps against spoofed-source
  memory exhaustion, never a useful UDP reflector, tokens logged only as a hash
  (the log-tag HMAC key is HKDF-derived from the identity, never the raw seed).
  On top of the caps, the public UDP listener is **rate-limited** — a global
  ceiling bounds total per-packet crypto so a flood cannot saturate the read
  loop, and a bounded per-source bucket keeps one address from consuming the
  budget. In **approval mode**, a bounded cache rejects **replayed**
  registration signatures within the freshness window. The relay carries the same
  per-source bind rate-limit plus a legs-per-source ceiling (it stays
  unauthenticated by design — the caps are abuse ceilings, not access control).
  For a private deployment, `--allow-cidr` restricts which source networks may
  reach the relay **and** the handshake server, dropping others before any crypto.
  Ships as a distroless/non-root image and a locked-down systemd sandbox with a
  size-capped log namespace, plus default-drop firewall rules. See
  [`deployments/`](deployments/).
- **Optional approval mode.** With `--authorized`, only operator-approved client
  keys may pair; registrations must carry a valid key-ownership signature, and
  outsiders are rejected outright. Clients can enroll with a short code sealed to
  the server's identity (`--code`, approved via `allowclient <code>`).

## Buddy identity trust — the trust hierarchy

The token alone is a bearer secret: the handshake pairs the first two
registrations and signs whatever key registered. So on its own a token-knower —
or a malicious/compromised handshake server — could be vouched for as "the
partner." BuddyNet closes this with a trust hierarchy (strongest first):

1. **`--peer-key` (strict pin)** — the buddy's Ed25519 key, exchanged once
   out-of-band. Any other partner is refused, no prompt. **Strongest;
   recommended for anything important.**

2. **Trust-on-first-use + SAS (default).** On the first connect for a token,
   after the QUIC tunnel is up but **before the key is trusted**, both buddies
   display a **Short Authentication String** — a 6-character code derived from
   `SHA-256(sort(bothKeys) + TLS-exported-keying-material)`
   ([`internal/role/sas.go`](internal/role/sas.go)):

   ```
   🔑 Safety check — first contact with this buddy.
           K7QX2M
   Do they match? [y/N]
   ```

   Read it to your buddy over a **trusted out-of-band channel** (phone, Signal)
   and confirm only if **both sides show the same code**. Because the code is
   bound to the live TLS session (channel binding), a man in the middle — who
   terminates a *different* TLS session to each side — makes the two codes
   differ. This catches the MITM **at first contact**, not after the fact, and
   it holds **even against a malicious handshake server**: a substituted key
   yields a mismatching SAS. On confirm the key is pinned (indexed by a *hash* of
   the token, never the token in clear) and later connects are checked silently.

   > **The one assumption you cannot remove:** the SAS only protects you if a
   > human actually compares it. Reflexively pressing `y` defeats it. For
   > unattended links, use `--peer-key` instead.

3. **`--insecure`** — no verification at all. Must be set explicitly, logged
   loudly, **testing only.** Never use it on a daemon or a server-side host.

For daemons/Unraid there is no human to compare a SAS: run with
`--no-interactive` and **pin with `--peer-key`**. An unknown key is then refused
rather than learned blind.

### The trust store (`known_peers`)

The SAS protects the **first** connect (on the wire). After that the partner key
is read from `known_peers` and trusted on every subsequent connect without a
prompt. That file is therefore a trust anchor and must live in the **same trust
domain as the identity key**:

- Keep it `0600` next to `id.key` (the systemd sandbox already enforces a `0700`
  directory). **Do not** put `--known-peers` on a synced/shared location
  (Dropbox, Syncthing, NFS/SMB) or in a world-writable path: anyone who can
  rewrite the file there can swap in a different key, and a later connect would
  trust it silently (the SAS already happened).
- A local attacker running **as the same user** can rewrite `known_peers` — but
  that attacker also owns `id.key`, so they are already inside the node's trust
  domain; this is out of scope at the application layer (rely on file
  permissions, a dedicated user, and the systemd sandbox). Application-level
  signing of the store would not help here, since the same key signs it.
- For the strongest setup, skip the store entirely and **pin with `--peer-key`**;
  then `known_peers` is not consulted at all.

### Invite token vs. session secret

The pairing secret is split so the value that actually travels is short-lived:

- **`--invite` / `--join`** mint/use a **one-time invite token**, valid only until
  the first pairing (`--invite-timeout`, default 15 min). On the first
  SAS-confirmed (or `--peer-key`-pinned) pairing, both ends **derive a long-lived
  session secret from the TLS channel binding** (`HKDF`-style over the exported
  keying material + both keys) and store it next to the partner key. It is
  **never transmitted** — both sides compute the same value, and a man in the
  middle (different TLS session per side) derives a different one.
- All later **reconnects use the stored session secret** as the rendezvous
  token; the invite token is retired after first use. So a leaked invite is
  worthless after 15 min or after the first connect, and the long-lived secret
  never appears in a chat log or on the wire.
- **`--token`** is the legacy mode: a single fixed token used for rendezvous on
  every reconnect (no session secret). Fine for scripted/daemon setups,
  especially together with `--peer-key`.

This is hygiene, not a new confidentiality guarantee — impersonation is already
caught by `--peer-key`/SAS. It shrinks the exposure of the one secret you hand to
your buddy out of band.

## Detecting an attack

When a SAS is **rejected** (explicit mismatch), the buddy logs a full record —
remote endpoint (annotated as the peer's real address on a direct path, or the
relay's on a relayed one), the claimed virtual IP, the partner public key, the
token hash, and a UTC timestamp — and aborts without trusting the key. With the
systemd journal namespace you can review attempts at any time:

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
#         | pin-mismatch | vip-mismatch | leg-cap-hit   token=<tag> src=<ip> key=<b64[8]> ...

# 2) State transitions — CONNECTED / DISCONNECTED / PAIRED / TRUST / AUTHZ:
journalctl --namespace=buddynet | grep -E '(CONNECTED|DISCONNECTED|PAIRED|TRUST|AUTHZ):'
#   DISCONNECTED carries reason=<idle|reauth|shutdown|...> and duration=
#   CONNECTED/PAIRED/TRUST carry the STABLE key=<b64[8]> (not the ephemeral id)

# 3) Per-minute aggregates — only when active; ALERT segment on security counters:
journalctl --namespace=buddynet | grep 'stats (last'
#   stats (last 1m0s): role=handshake paired=.. challenged=.. rate-limited=.. dropped=..
#                      [ALERT: new-pubkey=.. squat-rejected=.. replay=..]
#   stats (last 1m0s): role=relay paired=.. challenged=.. rejected=.. [ALERT: leg-cap=..]
```

Each role tags its lines with a `SyslogIdentifier`, so you can narrow to one role
within the namespace: `journalctl --namespace=buddynet -t buddynet-handshake`
(or `-t buddynet-relay`, `-t buddynet-buddy@<name>`).

Peer identity in the audit trail is the **stable key tag** (`key=<first 8 chars
of the base64 pubkey>`), so it survives reconnects — unlike the ephemeral per-run
id. Tokens are anonymized: a server-keyed HMAC on the handshake/authz side (so the
same token maps to the same `token=` tag across those logs without becoming a
public guessing oracle) and a plain truncated hash on the buddy side.

An `ALERT:` segment, any `SECURITY:` line, or a sustained spike in
`rate-limited`/`dropped`/`rejected` is the signature of an attack being absorbed
(a spoofed-source flood, a token-squat, or a replay attempt).

## Attacker capabilities

| Attacker | Outcome |
|---|---|
| Passive eavesdropper on the path | Sees only encrypted QUIC. **Safe.** |
| Active network MITM (not the server) | Cannot impersonate a peer — pinned mutual cert auth, and the SAS catches a first-contact substitution. **Safe.** |
| Malicious/compromised **handshake server** | Cannot impersonate a buddy: a substituted key fails the SAS (or is refused by `--peer-key`). Can deny service. **Mitigated.** |
| A **relay** in the data path | Sees only ciphertext; cannot read or inject (QUIC auth). **Safe.** |
| Someone who learns the **token** | Cannot impersonate a buddy (SAS / pin). Can at most occupy a pairing slot and *deny* the legitimate pair — a DoS, not a breach. On the default UDP transport the token travels in cleartext, so an on-path observer can learn it; run `--quic-handshake` to encrypt the control plane and always pin with `--peer-key`. **Mitigated.** |
| Spoofed-source flood / reflection on the handshake server | Source address validated first (UDP cookie or QUIC) before any `PEER_LIST`; global + per-source rate limits and bounded state cap the rest. Never a useful amplifier. **Mitigated.** |
| Spoofed-source reflection / traffic-laundering through a **relay** | A bind binds no leg until the source echoes an address-validation cookie (reply smaller than the bind); a spoofed source can never validate, so attacker data can never be forwarded to a victim address. **Mitigated.** |
| Local process on the same host | Reads the `0600` key / `known_peers`, or a TCP-loopback `-L`. Use a `unix:/path` socket and the systemd sandbox. **Mitigated.** |

## Other properties

- **Deterministic identity = address.** A node's virtual IP is a pure function of
  its public key; a roster claiming an inconsistent IP is rejected.
- **Protocol version.** Each message carries a `ver`; an incompatible build is
  reported clearly instead of as an opaque crypto error.
- **Local socket.** `-L`/`-forward` accept a Unix domain socket (`unix:/path`,
  mode `0600`) as a safer alternative to TCP loopback in shared/container hosts.
- **Forward secrecy.** Provided by TLS 1.3 by default.

## Handshake server transport — two ways, both spoof-proof

The handshake control plane (the `REGISTER` → `PEER_LIST` exchange) can run over
either transport. **Both structurally close the spoofed-source reflection
vector** — the server never produces a `PEER_LIST` for an address that has not
proven it can receive packets. They differ only in how that proof is obtained.

- **Plain UDP + address-validation cookie (default).** A `REGISTER` without a
  valid cookie is answered only with a small `COOKIE` challenge — *smaller* than
  the request, so never a useful amplifier — and no further work. The cookie is
  `HMAC(subkey, epoch ‖ source-IP)` (the subkey HKDF-derived from the server
  identity), so a spoofed source can never receive and echo it. The buddy echoes
  it on its next `REGISTER`. This is QUIC's Retry-token idea at the application
  layer: zero extra dependencies, no TLS certificate, and the buddy's single
  socket is untouched (so hole punching and the peer tunnel are unaffected).

- **QUIC (`--quic-handshake`).** The control plane runs over QUIC, which
  validates the source address in its own handshake before the server does any
  work. The cost is a TLS certificate: the server presents its self-signed
  identity cert and the buddy pins it by `--server-key` — the same TOFU model
  already used for peer identity, no CA or domain. The buddy runs the QUIC
  control connection on its **shared** UDP socket and tears it down before
  punching, so the same NAT mapping still carries the peer tunnel.

Set the **same** transport on the server and every buddy (`--quic-handshake`, or
`BUDDYNET_QUIC=1`); a mismatch simply fails to connect. On both transports the
global + per-source rate limits and the bounded registry caps still apply.

**Confidentiality differs, though.** Plain UDP `REGISTER`s are cleartext JSON, so
the pairing token (and, on reconnect, the rendezvous secret) is visible to an
on-path observer near either endpoint. That cannot break a tunnel — the partner
is still pinned by key and verified by SAS — but it lets an observer squat/deny a
pairing, and it enables a full MITM **only** against a buddy run with `--insecure`.
`--quic-handshake` encrypts the whole exchange (the token never appears in
cleartext on the wire). The server logs a `WARNING` at startup on the UDP path.
Either way, treat the token as a bearer secret and pin buddies with `--peer-key`.

## Deliberately out of scope

- **Server-forced disconnect of a live tunnel.** The handshake server is not in
  the data path, so it **cannot kill an established direct tunnel** — see
  [Revoking access](#revoking-access) for what to do instead. A server-side token
  blacklist is still not built: it would close only a narrow window at the cost of
  new attack surface.
- **At-rest key encryption / rotation.** Identity keys are `0600` files; protect
  and back them up (see below). No passphrase. The systemd units set `LimitCORE=0`
  so the in-memory key cannot leak into a core dump, but the key is not `mlock`ed
  against swap — disable swap or encrypt it on sensitive hosts.
- **Enrollment code in the server log (approval mode).** When a client enrolls
  with `--code`, the handshake server logs the cleartext code so the operator can
  `allowclient <code>`. The code is a one-time, low-entropy reference and only
  grants *pending* status; approval still requires write access to the allowlist
  file (which already implies operator trust), so log-read alone cannot escalate.
- **Per-stream idle timeout.** Forwarded streams are bounded only by the session
  idle timeout (`--idle-timeout`) and the 256-stream cap, not by an independent
  per-stream deadline — an aggressive one would kill legitimately idle streams
  (e.g. an interactive SSH session), so it is deliberately omitted.
- **Local tampering of `peers.json` / `known_peers`.** These caches have no
  integrity protection, but they live in a `0700` dir alongside the identity key:
  a local attacker with write access there already controls the node. Pinning and
  the SAS still hold regardless of cache contents.

## Lost identity keys

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

## Revoking access

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

To **bound** how long an established tunnel can outlive a revocation, run the
buddy with **`--reauth-interval`** (off by default). It rebuilds the tunnel on
that interval, re-running the allowlist/trust checks each time — so a revocation
takes effect within one interval, at the cost of a brief reconnect (leave it off
for uninterrupted long transfers like a multi-hour backup). To cut a live tunnel
**immediately**, stop the revoked node's process (`systemctl stop …`) or block it
at the firewall.

## Release integrity

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

The identity regexp ties the signature to this repository's workflow, and the
OIDC issuer to GitHub's Actions token — a binary signed by anything else fails.
(Releases through v1.1.0 used separate `.sig`/`.pem`; v1.1.2 onward uses the
`.bundle`.) The Unraid plugin pins the published binary's SHA-256 and refuses to
install on a mismatch.

## Reporting a vulnerability

Please open a **private security advisory** on the repository rather than a
public issue.

# Approval Mode — client allowlist

By default — **open mode** — the handshake server pairs any two buddies that
present the same valid token. **Approval mode** adds a server-side allowlist:
only clients whose Ed25519 public key appears in the authorized-clients file may
pair. Everyone else is logged as pending and silently dropped.

**What holding a token does and does not grant.** A token is a rendezvous
credential, not an identity and not an authorization. Someone who obtains one can
ask the server to pair them, and in open mode the server will — but they still
cannot become your buddy: the buddy keys are pinned end to end, so a substituted
partner is refused on the buddy side, with no human involved on the invite path.
What a token-holder can do is occupy a pairing slot and keep the legitimate pair
from meeting — and, if the slot is free, pair with a *second* stranger holding the
same token, which gets both of them signed `PEER_LIST`s and (where relay tickets
are enabled) tickets for your relay. So it is denial of service **plus
unauthorised use of your infrastructure**, but never a break into a tunnel.

The server keeps no record of spent tokens, so this does not expire on its own:
`--invite-timeout` bounds how long the inviter waits, not how long a token is
accepted (see [INVITE.md](INVITE.md#what-a-leaked-invite-is-worth)). Approval mode
is what removes it — an unapproved key is refused when its signed `REGISTER` is
handled, before it can occupy a slot or be paired with anyone. **On a server that
only ever serves people you know, run it.**

### Where the two checks happen

BuddyNet separates **authentication** ("which key is this?") from
**authorization** ("may that key pair?"), and they run at different layers:

| Layer | How |
|---|---|
| **Authentication** | Two independent proofs. TLS 1.3 client certificate: every client must present an Ed25519 identity **and prove possession** of its private key in the handshake; `REGISTER.pubkey` must then equal that authenticated key, or the connection is closed and nothing is stored. On top of that, every `REGISTER` carries the `reg_sig` key-ownership proof, which the server verifies unconditionally. |
| **Authorization** | Application layer, per `REGISTER`: allowlisted → pair; unknown **with** a valid enrollment code → recorded as pending; unknown without one → refused. |

**Only allowlisted keys can pair.**

> **Why authorization is not done at the TLS handshake.** It used to be: the QUIC
> server refused any client key that was not already on the allowlist. That made
> code-based enrollment (Flow B below) impossible — a client that has never been
> approved could not complete the handshake, so its encrypted enrollment code
> could never reach the server's application layer, so the operator could never
> approve it. An unknown key is now allowed to *authenticate* so it can deliver
> its code; it is still never allowed to *pair*.
>
> This does not weaken key pinning. An unknown client can do exactly two things:
> be noted in the log, or (with a valid code) become a pending entry. Because the
> registration is bound to the TLS-authenticated key **and** the sealed code is
> covered by the registration signature, a stranger can only ever enroll **its
> own** key — it cannot bind a code, captured or invented, to somebody else's.
> Unknown keys are also rate-limited far more tightly than allowlisted ones, so
> the enrollment path cannot be used to flood the pending database or the log.

This is the right mode for:
- A shared VPS where you control who can rendezvous.
- Multi-tenant setups where different user groups must be isolated.
- Any situation where the token alone is not a sufficient access control.

## Enabling approval mode

Start the handshake server with `--authorized`:

```bash
buddynet --role=handshake \
  --key /var/lib/buddynet/id.key \
  --authorized /etc/buddynet/authorized_clients
```

The file is created automatically on first `approve`.

> **`--authorized` is fail-closed.** Passing the flag puts the server in approval
> mode, unconditionally. A missing allowlist file means **zero authorized
> clients**, not open mode — nobody can pair until you `approve` someone. If the
> file is deleted while the server is running, the in-memory allowlist is cleared
> within the reload interval and the server logs a WARNING; recreating the file
> loads its entries again.

The file is **hot-reloaded every 2 seconds** — adding or revoking a key takes
effect within 2 s without restarting the server.

## Authorizing a new client

There are two flows: manual (approve by public key) and code-based (the client
sends an enrollment code; the operator approves it server-side).

### Flow A — approve by public key

1. Have the client print its identity:

   ```bash
   buddynet --role=buddy --key /var/lib/buddynet/id.key identity
   # → CLIENT_KEY (base64)
   ```

2. On the server, approve it:

   ```bash
   buddynet --role=handshake \
     --authorized /etc/buddynet/authorized_clients \
     approve CLIENT_KEY [optional-label]
   ```

   The optional label (e.g. a username or hostname) is stored next to the key
   for operator reference. It has no effect on authorization logic.

### Flow B — code-based enrollment

Useful when the operator cannot easily copy-paste public keys (e.g. Unraid UI,
automated provisioning). The client presents an **enrollment code**; the operator
approves the code without ever seeing the raw key.

1. Generate a code and give it to the client operator (any secure channel):

   ```bash
   buddynet gen-token   # prints a strong random string
   ```

2. The client starts with `--code`:

   ```bash
   buddynet --role=buddy \
     --server vps.example:51820 --server-key SERVER_KEY \
     --key /var/lib/buddynet/id.key \
     --code MY_ENROLLMENT_CODE \
     --join=TOKEN -L 127.0.0.1:9000
   ```

   The client sends the code (encrypted to the server's public key) along with
   its registration. The server decrypts it, holds the `(code → key)` mapping **in
   memory only**, and logs:

   ```
   AUTHZ: action=pending key=abc12345 code=78c86dc0 — approve with:
     buddynet --role=handshake --authorized /etc/buddynet/authorized_clients approve <CLIENT_KEY>
   ```

   The log line carries a **non-reversible hash** of the code, never the code
   itself — it is a bearer secret and logs get shipped off-box. The public key is
   printed in full on purpose: it is not a secret, and it is the command you need.

3. The operator approves the **key** the log line printed:

   ```bash
   buddynet --role=handshake \
     --authorized /etc/buddynet/authorized_clients \
     approve <CLIENT_KEY>
   ```

   The running server hot-reloads within 2 s and the client's **next registration
   attempt succeeds — no restart on either side.** (Each attempt carries a fresh
   nonce and signature, so a client polling while it waits for approval is never
   mistaken for a replay.)

   > **Changed in v5.0.0.** There used to be an `allowclient CODE` subcommand: it
   > looked the code up in an `authorized_clients.pending` file the server
   > maintained, and approved whatever key was recorded there. That file is gone,
   > and with it the subcommand.
   >
   > **This is a security improvement, not only a simplification.** The pending
   > file was a `code → key` mapping sitting on disk for up to 30 minutes and
   > written by two processes, and `allowclient` *trusted* it: anyone able to write
   > that file could swap the recorded key, and typing the correct code would then
   > approve the **wrong** key without anything looking wrong. Approving the key
   > from the log removes that indirection — you authorise exactly what the server
   > saw. It also means an enrolment only exists while the client is actually
   > running and talking to the server, so there is no waiting entry to tamper with.
   >
   > The cost is real and worth stating: if the client is no longer running, the
   > entry is gone and there is nothing to approve — start it again. Previously the
   > entry survived 30 minutes regardless.
   >
   > In practice this lands **once per buddy, ever**. It is the first-contact step:
   > after the approval the key is on the allowlist (operator configuration, which
   > does persist) and the pair stores a session secret in `known_peers`.
   >
   > Everything after that is unattended. When your buddy's provider hands them a
   > new IP, the handshake server does exactly what it is for — both ends
   > re-register, it matches them and returns the new endpoints — and the tunnel
   > comes back on the stored session secret. No code, no operator, no enrolment:
   > the server is still in the loop for **matchmaking**, just not for
   > **authorisation**, because the key is already approved.
   >
   > So the live requirement costs you one moment per buddy — the moment you are
   > already on the phone with them — and it is precisely the moment worth pinning
   > down, because it is the one where an attacker would want to slip a key in.

## Subcommands

All subcommands require `--authorized` and exit immediately.

```bash
# Approve a key directly
buddynet --role=handshake --authorized FILE approve KEY [LABEL]

# List all approved keys
buddynet --role=handshake --authorized FILE list

# Revoke a key
buddynet --role=handshake --authorized FILE revoke KEY
```

### `approve KEY [LABEL]`

Adds KEY to the authorized file. KEY must be a base64-encoded Ed25519 public key
(44 characters). Duplicate approvals are silently ignored. The optional label is
free-form text stored next to the key. A good label for Flow B is
`code:<code-hash>`, matching the `code=` field of the server's log line.

`allowclient CODE` was removed in v5.0.0 (see the note in Flow B). Running it
prints what to do instead and exits non-zero, so old scripts fail loudly rather
than silently doing nothing.

### `list`

Prints all currently authorized keys with their labels, one per line, sorted.

### `revoke KEY`

Removes KEY from the authorized file. The running server hot-reloads within 2 s;
the revoked client is dropped on its next registration attempt. To force
immediate disconnection, combine with `--reauth-interval` on the client side
(see [INVITE.md — Re-authentication](INVITE.md#re-authentication)).

## Authorized file format

Plain text, one entry per line:

```
# comments are ignored
BASE64_KEY optional label or description
BASE64_KEY another-client
```

The file is written as `0600` by `approve`; keep it that way. The server reads
it with the same permissions check it applies to identity key files.

This is the **only** file the control server needs across restarts, alongside its
identity key — and both are operator configuration, not runtime state. Since
v5.0.0 the server writes nothing else: pending enrolments are held in memory,
bounded and pruned after 30 minutes, and are gone when the process stops. A
leftover `<authorized>.pending` from an older version is simply ignored and can be
deleted.

## Two things to know about the enrollment code

**The code is a bearer secret, and the first claim wins.** Whoever presents a
valid code first is the key that gets recorded as pending under it — the server
cannot tell your buddy's key from anyone else's, only that both sealed the same
code. So send the code over a channel you trust (the same one you would use for
the SAS), and check the key tag in the log line against what your buddy sees
before you approve it:

```
AUTHZ: action=pending key=Ab3dEf9k code=1a2b3c4d — approve with: …
                      ^^^^^^^^^^ this must match your buddy's `identity` output
```

Approving by key (Flow A) has no such window; the code exists to spare you
copying a 44-character key by hand.

**A restart relaxes the approval-transition check.** The server records WHEN it
approved a key, and refuses registrations minted before that moment — this closes
the window where a registration captured while the key was still unapproved
becomes replayable the instant you approve it. Two caveats, both deliberate:

- Keys already in the file at startup carry no approval moment (no transition
  happened in this process), so they are unconstrained. Constraining them would
  punish clock-skewed clients after every restart for no gain.
- The nonce cache that does the actual work is in memory only.

So a registration captured shortly before an approval is replayable for the rest
of its freshness window (at most 2x the clock-skew tolerance, ~120 s) **if the
server restarts inside that window**. Approving a key and restarting the server
in the same two minutes is worth avoiding; there is no reason to do both at once.

## Security properties

- **Replay protection.** Every `REGISTER` carries a timestamp and a fresh
  128-bit nonce, and is signed with the client's private key over all of it. The
  server accepts registrations only within ±60 s of its clock and caches recent
  `(pubkey, nonce)` pairs to detect replays across that window. Because the nonce
  is per attempt, ordinary polling is not a replay; re-sending a captured
  registration verbatim is.

- **Registration binding.** The signature covers the protocol version, role,
  token, id, public key, virtual IP, name, timestamp, nonce and sealed enrollment
  code — so none of them can be altered in flight, and a captured code cannot be
  grafted onto another key. On QUIC the registration must additionally name the
  key the TLS handshake authenticated.

- **Enrollment rate limit.** Unknown keys get their own, much tighter limiter
  (per source and global) than allowlisted clients, so a stranger flood can
  neither consume an approved buddy's budget nor grow the pending database.

- **Flood caps.** The pending map and the log-dedup map are bounded at 1024
  entries each. A flood of registrations from fresh keys fills the cap, then
  drops silently — bounded memory regardless of source. The global rate limiter
  (pre-parse) applies first.

- **No oracle.** Enrollment codes are encrypted to the server's public key before
  being sent on the wire, so a passive observer cannot read them. The server never
  sends the code back, and only the server learns which key presented it.

- **Key-change detection.** If a different key re-registers with a code that
  already has an approved entry, the second key is silently dropped (the approved
  key wins). This prevents a race where an attacker re-uses a captured code before
  the operator approves it.

- **Nothing waits on disk.** The enrolment exists only while the client is running
  and talking to the server, so there is no `code → key` record for anyone to read
  or alter between registration and approval — and you approve the key the server
  reports, not one looked up in a file (see the v5.0.0 note in Flow B).

## Combining with `--allow-cidr`

For a private fleet you can add a network-level pre-filter on top of the allowlist:

```bash
buddynet --role=handshake \
  --authorized /etc/buddynet/authorized_clients \
  --allow-cidr 10.0.0.0/8,192.168.0.0/16 \
  --key /var/lib/buddynet/id.key
```

Sources outside the listed CIDRs are refused before the connection takes one of
the server's slots — cheaper than an allowlist check for high-volume abuse. On the
handshake server that is *after* the TLS handshake quic-go already performed, not
before it; only the relay filters before any crypto. See
[SECURITY.md §5.5](../SECURITY.md#55-what-an-unauthenticated-source-can-cost-you-the-pre-tls-boundary)
for what an unauthenticated source can actually cost, and
[OPERATIONS.md](OPERATIONS.md) for the flag itself.

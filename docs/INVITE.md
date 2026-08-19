# Pairing — invite, join, trust, and sessions

BuddyNet's pairing model is **one-time, key-bearing invites**: the inviter mints
a short-lived invite, hands it to the joiner out of band, and the two nodes pair
once. The invite carries the inviter's **public key**, so the joiner pins that
identity straight from the trusted channel the invite travelled over. On success
a long-lived **session secret** is derived from the encrypted channel and stored;
all later reconnects use that secret — the invite is never seen again.

## Quick start

**On the inviter** (the machine hosting the service):

```bash
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  --key /var/lib/buddynet/id.key \
  --invite --forward 127.0.0.1:873
```

BuddyNet prints a one-time invite and waits:

```
Invite for your buddy — hand it over on a channel you trust (phone, Signal)
and have them pass it to --join. It is one-time and carries your identity,
so they pin YOUR key from it; treat it as a secret:

  bnet1.QmF6ZTY0dG9rZW4…. ZDk3YmY1Y2E4…

Invite hidden — now waiting for your buddy to join...
```

**On the joiner** (the machine that will consume the service):

```bash
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  --key /var/lib/buddynet/id.key \
  --join=bnet1.… -L 127.0.0.1:9000
```

### What each side has to do

The two directions are **not** symmetric, and that is the point:

| | Joiner | Inviter |
|---|---|---|
| Verifying the other side | Nothing to do — the invite pinned the inviter's key | Types a six-character code |
| What it sees | Its own code, displayed to read out | No code at all |

The joiner displays its code:

```
🔑 Your buddy's identity is already verified — you pinned their key from the
   invite, so there is nothing for you to check here.
   They still have to verify YOU. Read them this code over the phone:

        your code:  K7QX2M
```

and the inviter asks for it, **without showing its own**:

```
🔑 Safety check — your buddy is joining with your invite.
   Call them over a trusted channel (phone, Signal) and ask for the code shown
   on THEIR screen, then type it here. Your own code is deliberately not shown:
   the code has to come from your buddy, not from this screen.

Type the code your buddy reads to you: _
```

One phone call, one code, both directions covered. The inviter cannot satisfy the
prompt from its own screen because there is nothing on it to copy — the six
characters can only come from the buddy. A wrong code, a blank line or a timeout
aborts and stores nothing.

From the second connect onwards neither side needs user input — the stored
session secret is used automatically.

> **Bare tokens still work.** An invite from an older BuddyNet has no key in it.
> `--join` accepts it and pairs by trust-on-first-use, where **both** sides show a
> code and type one (weaker: see [Trust hierarchy](#trust-hierarchy)). What is
> *not* accepted is a **mangled** invite — a truncated or edited `bnet1.…` string
> is an error, never a quiet downgrade to the unpinned path.

## Flags

| Flag | Env | Description |
|------|-----|-------------|
| `--invite` | — | Mint a ONE-TIME invite, print it, and wait for the joiner. It carries this node's public key, so the joiner pins this identity. Expires after `--invite-timeout` (default 15 min) without a first pairing. |
| `--join=INVITE` | `BUDDYNET_JOIN` | Join with the invite your buddy gave you. A key-bearing invite (`bnet1.…`) pins them automatically; a bare token falls back to trust-on-first-use. A malformed invite is refused. |
| `--invite-timeout` | — | How long to wait for the first pairing before giving up on the invite. Default `15m`. Re-run `--invite` for a fresh token after expiry. |
| `--peer-key KEY` | `BUDDYNET_PEER_KEY` | Pin the buddy's Ed25519 public key (base64). Strongest: any key mismatch is refused outright, no SAS needed. |
| `--known-peers PATH` | `BUDDYNET_KNOWN_PEERS` | Trust-on-first-use store. Defaults to `~/.config/buddynet/known_peers`. Holds one `token-hash → pubkey` entry per paired buddy. |
| `--no-interactive` | — | Never prompt for SAS. A NEW unknown buddy key is refused rather than learned. Use for daemons and Unraid. Combine with `--peer-key`. |
| `--sas-timeout` | — | How long to wait for the code to be typed in. Default `30s`. A timeout aborts the connection and stores nothing. |
| `--reauth-interval` | — | Tear down and re-pair after this interval even while the tunnel is healthy. See [Re-authentication](#re-authentication). Default `0` (off). |
| `--status` | — | One-shot probe: check whether the buddy is reachable, then exit. See [Checking the link](#checking-the-link). |

## Trust hierarchy

From strongest to weakest:

### 1. Key-bound invite (default) / pinned key (`--peer-key`)

These are the same strength — a key you got over a channel you trust, checked
before anything else. They differ only in how the key gets there.

The invite carries it for you:

```
bnet1.<one-time-token>.<inviter-public-key>
```

`--join` splits it, uses the token as the rendezvous and pins the key. From then
on only that identity can be your buddy: a handshake server that vouches for
someone else is refused outright, with no human involved and nothing to compare.
The inviter verifies the joiner by typing the code the joiner displays (see
[Quick start](#quick-start)).

`--peer-key` does the same pinning by hand, in both directions, and needs no
invite exchange at all:

```bash
# Print the buddy's identity — run this on the buddy's machine
buddynet --role=buddy --key /var/lib/buddynet/id.key identity
# → BASE64_KEY

# Inviter: pin the joiner's key
buddynet --role=buddy ... --invite --peer-key BASE64_KEY

# Joiner: pin the inviter's key
buddynet --role=buddy ... --join=INVITE --peer-key BASE64_KEY
```

With both ends pinned there is no prompt on either side — the right choice for
daemons and automated setups. A `--peer-key` that contradicts the key inside the
invite is an error: one of the two is not your buddy, and BuddyNet will not pick.

### 2. Trust-on-first-use + SAS (fallback)

Used when neither side pinned the other — a bare token from an older inviter, or
a manual pairing. Both sides display the same 6-character code and both type in
the one they hear:

```
🔑 Safety check — first contact with this buddy.
   Call your buddy over a trusted channel (phone, Signal). Read them YOUR code,
   then type the code THEY read back to you.

        your code:  K7QX2M

Type your buddy's code: _
```

The code is bound to the live session, so a man in the middle — who terminates a
different session to each side — makes the two codes differ and the entry fails.
On a match the key is recorded in `--known-peers` and later connects match it
silently.

This is weaker than §1 for one human reason: both ends see a code *and* type one,
so someone in a hurry can type what is on their own screen without ever calling.
The invite path removes that possibility by construction — the verifying side is
shown no code at all.

A key change on a known token is refused outright (`SECURITY: event=key-changed`).
To legitimately rekey, remove the old entry from `--known-peers` and pair again.

### 3. Lab mode (`--lab`)

Disables identity verification entirely. **Use only in isolated test environments.**
The tunnel is still encrypted but you cannot know who is at the other end.

## Session secrets

When `--invite`/`--join` pairing succeeds (code confirmed, or key pinned),
BuddyNet derives a **session secret** from the QUIC channel binding and stores it
alongside the partner's key in `--known-peers`. On all later reconnects:

- The session secret is used as the rendezvous token instead of the invite.
- The stored partner key is re-checked on every connect (a change is refused).
- The invite token is discarded — it cannot be used again.

The session secret is never transmitted in the clear and is never logged.

## Re-authentication

A direct P2P tunnel bypasses the handshake server entirely — once two buddies
have punched a hole, the server cannot revoke or terminate that session. If you
need revocations or token rotations to take effect on long-lived sessions, set
`--reauth-interval`:

```bash
buddynet --role=buddy ... --reauth-interval=1h
```

Every hour the tunnel is torn down, the handshake server is re-contacted, and
a new session is established. If the token was revoked or the client is no longer
in the allowlist (`--authorized`), the new session is refused and the buddy
disconnects cleanly.

**Trade-off:** `--reauth-interval` may interrupt a long-running transfer (rsync,
kopia). Set it longer than your longest expected transfer, or only use it where
revocation latency matters more than transfer continuity. Default is `0` (off).

## Checking the link

`--status` is a one-shot probe that exits immediately with a status code:

```bash
buddynet --role=buddy --server vps:51820 --server-key KEY \
  --join=TOKEN --status
echo "exit code: $?"
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Buddy is reachable (tunnel up, data flowing) |
| `3` | Buddy is registered but unreachable (punch and relay both failed) |
| `4` | Buddy is offline (not registered at the handshake server) |
| `5` | Buddy is online but the identity check failed (wrong key or untrusted) |
| `1` | Local error (bad flags, network, key file) |

Use it in scripts, health checks, or monitoring:

```bash
if ! buddynet --role=buddy ... --status; then
    echo "buddy unreachable, sending alert"
fi
```

## Daemon setup (no interactive prompts)

For a systemd service, Unraid, or any unattended process:

1. **Pin the key** with `--peer-key` so no prompt can appear.
2. Add `--no-interactive` as a belt-and-suspenders safeguard.
3. Store the invite in `BUDDYNET_JOIN` or a `0600` file to keep it out of
   `argv`/`ps`.

**Which side can run headless.** A key-bearing invite makes the **joiner**
unattended-safe on its own: it pinned the inviter from the invite, so there is
nothing to confirm — it prints its code to the log and carries on. The
**inviter** is the side that verifies, and verifying needs a human at a terminal:
running `--invite` with `--no-interactive` (or no TTY) refuses the unknown joiner
key rather than learning it blind. For an unattended inviter, pin the joiner with
`--peer-key` instead — then neither side has anything to type.

```ini
[Service]
ExecStart=/usr/local/bin/buddynet \
  --role=buddy \
  --key /var/lib/buddynet/id.key \
  --server vps.example:51820 \
  --server-key SERVER_KEY \ \
  --peer-key PARTNER_KEY \
  --no-interactive \
  -L 0.0.0.0:9000
EnvironmentFile=/etc/buddynet/env  # contains BUDDYNET_JOIN_UNUSED=…
```

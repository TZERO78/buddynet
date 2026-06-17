# Pairing — invite, join, trust, and sessions

BuddyNet's default pairing model is **one-time invite tokens**: the inviter mints
a short-lived token, hands it to the joiner out of band, and the two nodes pair
once. On success a long-lived **session secret** is derived from the encrypted
channel and stored; all later reconnects use that secret — the invite token is
never seen again. This is stronger than a fixed shared token because the
long-lived secret is never transmitted in the clear and is unique to each pair.

The older `--token` flag (a fixed string, reused on every reconnect) is still
supported for backwards compatibility but is the weaker option.

## Quick start

**On the inviter** (the machine hosting the service):

```bash
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  --quic-handshake \
  --key /var/lib/buddynet/id.key \
  --invite --forward 127.0.0.1:873
```

BuddyNet prints a one-time TOKEN and waits. Send it to your buddy out of band.

**On the joiner** (the machine that will consume the service):

```bash
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  --quic-handshake \
  --key /var/lib/buddynet/id.key \
  --join=TOKEN -L 127.0.0.1:9000
```

On first contact both sides print a **Short Authentication String (SAS)** — four
words, matching on both ends. Confirm with `y` on each machine. The session
secret is then stored in `--known-peers` and the tunnel stays up.

From the second reconnect onwards neither side needs user input — the stored
session secret is used automatically.

## Flags

| Flag | Env | Description |
|------|-----|-------------|
| `--invite` | — | Mint a ONE-TIME invite token, print it, and wait for the joiner. Tokens expire after `--invite-timeout` (default 15 min) without a first pairing. |
| `--join=TOKEN` | — | Join with the invite token your buddy gave you. Sets the rendezvous token and marks the session as ephemeral (one-time). |
| `--token TOKEN` | `BUDDYNET_TOKEN` | **Legacy.** Fixed token reused on every reconnect. Weaker: anyone who ever observed the token can reconnect. Prefer `--invite`/`--join`. |
| `--invite-timeout` | — | How long to wait for the first pairing before giving up on the invite. Default `15m`. Re-run `--invite` for a fresh token after expiry. |
| `--peer-key KEY` | `BUDDYNET_PEER_KEY` | Pin the buddy's Ed25519 public key (base64). Strongest: any key mismatch is refused outright, no SAS needed. |
| `--known-peers PATH` | `BUDDYNET_KNOWN_PEERS` | Trust-on-first-use store. Defaults to `~/.config/buddynet/known_peers`. Holds one `token-hash → pubkey` entry per paired buddy. |
| `--no-interactive` | — | Never prompt for SAS. A NEW unknown buddy key is refused rather than learned. Use for daemons and Unraid. Combine with `--peer-key`. |
| `--sas-timeout` | — | How long to wait for a human to type `y/N` on the SAS prompt. Default `30s`. If the timeout fires, the connection is aborted. |
| `--reauth-interval` | — | Tear down and re-pair after this interval even while the tunnel is healthy. See [Re-authentication](#re-authentication). Default `0` (off). |
| `--status` | — | One-shot probe: check whether the buddy is reachable, then exit. See [Checking the link](#checking-the-link). |

## Trust hierarchy

From strongest to weakest:

### 1. Pinned key (`--peer-key`)

```bash
# Print the buddy's identity — run this on the buddy's machine
buddynet --role=buddy --key /var/lib/buddynet/id.key identity
# → BASE64_KEY

# Inviter: pin the joiner's key
buddynet --role=buddy ... --invite --peer-key BASE64_KEY

# Joiner: pin the inviter's key
buddynet --role=buddy ... --join=TOKEN --peer-key BASE64_KEY
```

The connection is refused immediately if the key does not match — no SAS, no
human needed. This is the right choice for daemons and automated setups.

### 2. Trust-on-first-use + SAS (default)

On the first connection both sides print a **Short Authentication String** (four
words). Compare them out of band (phone call, Signal, anything not the tunnel
itself). If they match, confirm with `y` — the key is recorded in `--known-peers`
and all later connects match it silently. If they differ, type `n` — the connection
is aborted; a mismatch means someone is in the path between you and your buddy.

```
First contact with partner abc12345… — SAS: "maple river stone clock"
Confirm? (y/N) y
TRUST: action=tofu-new — recorded; pin with --peer-key to skip the SAS next time
```

A key change on a known token is refused outright (`SECURITY: event=key-changed`).
To legitimately rekey, remove the old entry from `--known-peers` and re-run SAS.

### 3. Insecure (`--insecure`)

Disables identity verification entirely. **Use only in isolated test environments.**
The tunnel is still encrypted but you cannot know who is at the other end.

## Session secrets

When `--invite`/`--join` pairing succeeds (SAS confirmed, or `--peer-key` match),
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

1. **Pin the key** with `--peer-key` so the SAS prompt never appears.
2. Add `--no-interactive` as a belt-and-suspenders safeguard.
3. Store the token (or `--join` value) in an environment variable (`BUDDYNET_TOKEN`)
   or a `0600` file to keep it out of `argv`/`ps`.

```ini
[Service]
ExecStart=/usr/local/bin/buddynet \
  --role=buddy \
  --key /var/lib/buddynet/id.key \
  --server vps.example:51820 \
  --server-key SERVER_KEY \
  --quic-handshake \
  --peer-key PARTNER_KEY \
  --no-interactive \
  -L 0.0.0.0:9000
EnvironmentFile=/etc/buddynet/env  # contains BUDDYNET_TOKEN=…
```

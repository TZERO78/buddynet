# Approval Mode — client allowlist

By default the handshake server pairs any two buddies that share a valid token.
**Approval mode** adds a server-side allowlist: only clients whose Ed25519 public
key appears in the authorized-clients file may pair. Everyone else is logged as
pending and silently dropped.

This is the right mode for:
- A shared VPS where you control who can rendezvous.
- Multi-tenant setups where different user groups must be isolated.
- Any situation where the token alone is not a sufficient access control.

## Enabling approval mode

Start the handshake server with `--authorized`:

```bash
buddynet --role=handshake \
  --key /var/lib/buddynet/id.key \
  --quic-handshake \
  --authorized /etc/buddynet/authorized_clients
```

The file is created automatically on first `approve`. If the file does not exist
on startup the server runs in open mode and logs a reminder.

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
     --quic-handshake \
     --key /var/lib/buddynet/id.key \
     --code MY_ENROLLMENT_CODE \
     --join=TOKEN -L 127.0.0.1:9000
   ```

   The client sends the code (encrypted to the server's public key) along with
   its registration. The server decrypts it, records the `(code → key)` mapping
   in `authorized_clients.pending`, and logs:

   ```
   AUTHZ: action=pending key=abc12345 code="MY_ENROLLMENT_CODE" — approve with:
     buddynet --role=handshake --authorized /etc/buddynet/authorized_clients allowclient MY_ENROLLMENT_CODE
   ```

3. The operator approves the code:

   ```bash
   buddynet --role=handshake \
     --authorized /etc/buddynet/authorized_clients \
     allowclient MY_ENROLLMENT_CODE
   ```

   The key that presented the code is moved from `.pending` to the authorized
   file. The client's next registration attempt succeeds.

## Subcommands

All subcommands require `--authorized` and exit immediately.

```bash
# Approve a key directly
buddynet --role=handshake --authorized FILE approve KEY [LABEL]

# Approve via enrollment code (Flow B)
buddynet --role=handshake --authorized FILE allowclient CODE

# List all approved keys
buddynet --role=handshake --authorized FILE list

# Revoke a key
buddynet --role=handshake --authorized FILE revoke KEY
```

### `approve KEY [LABEL]`

Adds KEY to the authorized file. KEY must be a base64-encoded Ed25519 public key
(44 characters). Duplicate approvals are silently ignored. The optional label is
free-form text stored next to the key; `allowclient` sets it to `code:<CODE>`.

### `allowclient CODE`

Looks up CODE in the `.pending` file (written by the running server), moves the
corresponding key into the authorized file, and removes the pending entry. Fails
if the code is not in `.pending` (client has not registered yet, or the 30-minute
pending TTL has elapsed).

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

A companion file `<authorized>.pending` is maintained automatically — do not
edit it by hand. It holds `(code-hash → key)` entries for clients that have
registered with a `--code` but have not been approved yet. Entries older than
30 minutes are pruned automatically.

## Security properties

- **Replay protection.** In approval mode every `REGISTER` message carries a
  timestamp and is signed with the client's private key. The server accepts
  registrations only within ±60 s of its clock and caches recent signatures to
  detect replays across that window.

- **Flood caps.** The pending map and the log-dedup map are bounded at 1024
  entries each. A flood of registrations from fresh keys fills the cap, then
  drops silently — bounded memory regardless of source. The global rate limiter
  (pre-parse) applies first.

- **No oracle.** Enrollment codes are encrypted to the server's public key before
  being sent on the wire, so a passive observer cannot read them. The server
  never sends the code back; the operator approves by code, and only the
  server learns which key presented it.

- **Key-change detection.** If a different key re-registers with a code that
  already has an approved entry in `.pending`, the second key is silently dropped
  (the approved key wins). This prevents a race where an attacker re-uses a
  captured code before the operator approves it.

## Combining with `--allow-cidr`

For a private fleet you can add a network-level pre-filter on top of the allowlist:

```bash
buddynet --role=handshake \
  --authorized /etc/buddynet/authorized_clients \
  --allow-cidr 10.0.0.0/8,192.168.0.0/16 \
  --quic-handshake \
  --key /var/lib/buddynet/id.key
```

Datagrams from outside the listed CIDRs are dropped before any crypto — cheaper
than an allowlist check for high-volume abuse. See [OPERATIONS.md](OPERATIONS.md).

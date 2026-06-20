# Two Buddies — the point-to-point setup

**The simplest BuddyNet setup: exactly two buddies and one handshake server.** A
zero-config, end-to-end-encrypted, NAT-traversing tunnel between two sites — point
`rsync`, `borg`, `ssh`, or any TCP service at a local socket and it travels
straight to your buddy.

Everything in [ARCHITECTURE.md](ARCHITECTURE.md) applies; with two buddies a
`PEER_LIST` simply names a single partner. To hold tunnels to **more than one**
buddy at once, see [MultiPeer](PEERS.md).

## One-time setup (the VPS)

Run the bootstrap server and print the key your buddies will pin:

```bash
buddynet --role=handshake,relay \
    --key /var/lib/buddynet/id.key \
    --relay-endpoint vps.example:51821 \
    --quic-handshake
buddynet --role=handshake --key /var/lib/buddynet/id.key identity   # → SERVER_KEY
```

`--quic-handshake` must be set identically on the server **and** on every buddy
(or `BUDDYNET_QUIC=1`). Without it the pairing token travels in cleartext over
the public internet. See [OPERATIONS.md](OPERATIONS.md#quic-control-plane---quic-handshake).

## Pairing two buddies

**Inviter** (e.g. the machine being backed up *to*, running an rsync daemon):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake \
    --invite --forward 127.0.0.1:873
# prints a one-time TOKEN and waits for the buddy to join
```

**Joiner** (the machine doing the backup):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake \
    --join=TOKEN -L 127.0.0.1:9000 &
rsync -a /data/ rsync://localhost:9000/backup/
```

`--invite` mints a **one-time** token; `--join` consumes it. It is valid only
until the first pairing (`--invite-timeout`, default 15 min) — a stolen invite is
worthless afterwards.

### Reconnecting

On the first successful pairing both buddies derive a long-lived **session
secret** from the TLS channel binding (never sent over the wire) and store it
next to the partner key. From then on just rerun **without a token** — each side
reconnects via the stored session secret:

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --quic-handshake \
    -L 127.0.0.1:9000        # no --join/--token: reconnects via the stored session
```

For scripted/daemon setups that prefer one fixed reusable token, use the legacy
`--token` instead (ideally with `--peer-key`).

## First contact: the safety check (SAS)

Without `--peer-key`, the very first connect uses trust-on-first-use — but it is
not blind. Once the tunnel is up, both buddies print a **Short Authentication
String** before the key is trusted:

```
🔑 Safety check — first contact with this buddy.
        K7QX2M
Do they match? [y/N]
```

The code is derived from both identities and the live TLS session. Read it to
your buddy over a trusted channel (phone, Signal) and confirm only if **both
sides show the same** code. A man in the middle terminates a different TLS
session to each side, so the two codes differ — that is how you catch it. On a
mismatch (or no answer within `--sas-timeout`, default 30s) the connection is
dropped and nothing is trusted. Later connects check the pinned key silently.

For unattended buddies (daemons, Unraid), there is no human to confirm: set
`--no-interactive` and pin the key with `--peer-key` up front. An unknown key is
then refused rather than learned blind.

## Hardening (recommended)

Each buddy prints its own identity at startup. Pin your buddy explicitly to skip
the safety check entirely:

```bash
buddynet --role=buddy ... --peer-key <buddy-identity>
```

The token is a **bearer secret** — keep it out of argv (use a `0600` file or
`BUDDYNET_TOKEN`). On an allowlist server, enroll with `--code <code>` and have
the operator approve it:

```bash
buddynet --role=handshake --authorized clients.txt allowclient <code>
```

## Checking the link

```bash
buddynet --role=buddy --server ... --server-key ... --token ... --status
```

It prints one human-readable line and exits with a distinct code, so a script
can branch on the outcome without parsing the text:

| Exit | Meaning | stdout |
|---|---|---|
| `0` | online and directly reachable | `buddy is ONLINE and REACHABLE …` |
| `3` | online but not directly reachable (a relay would be used) | `buddy is ONLINE but NOT directly reachable …` |
| `4` | offline — no buddy registered with this token | `buddy is OFFLINE …` |
| `5` | registered but identity not trusted (possible hijack) | `… identity is NOT trusted …` |
| `1` | local error (cannot open socket / resolve the server) | logged to stderr |

## Beyond two buddies

The same binary scales up — see **[MultiPeer](PEERS.md)**: list many buddies in a
manifest (`--peers-file`), hold a tunnel to each at once, and route to them by
name (`--vip-listen`), all under one supervisor where one buddy failing never
affects the others.

| | Two buddies | MultiPeer (shipping) | Still on the roadmap |
|---|---|---|---|
| Buddies | the one partner | many, each pinned in a manifest | — |
| Discovery | handshake server | handshake server (per buddy) | peer-to-peer gossip overlay |
| Transport | QUIC | QUIC | QUIC **or** WireGuard (same seam) |

The wire format, virtual IPs, and fallback chain are unchanged, so each step is
additive — never a rewrite.

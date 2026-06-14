# BuddyPeer — the two-peer use case of BuddyNet

**BuddyPeer is BuddyNet with exactly two buddies and one handshake server.** It
is the v1 milestone: a zero-config, end-to-end-encrypted, NAT-traversing tunnel
between two sites — point `rsync`, `borg`, `ssh`, or any TCP service at a local
socket and it travels straight to your buddy.

Everything in [ARCHITECTURE.md](ARCHITECTURE.md) applies; BuddyPeer just never
has a third buddy on the token, so a `PEER_LIST` always names a single partner.

## One-time setup (the VPS)

Run the bootstrap server and print the key your buddies will pin:

```bash
buddynet --role=handshake --key /var/lib/buddynet/id.key
buddynet --role=handshake --key /var/lib/buddynet/id.key identity   # → SERVER_KEY
```

Optionally also run a relay on the same box for buddies behind symmetric NAT,
and advertise it:

```bash
buddynet --role=relay --listen '[::]:51821'
# then start handshake with:  --relay-endpoint vps.example:51821
```

## Pairing two buddies

**Inviter** (e.g. the machine being backed up *to*, running an rsync daemon):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --invite -forward 127.0.0.1:873
# prints a one-time TOKEN and waits for the buddy to join
```

**Joiner** (the machine doing the backup):

```bash
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
    --join=TOKEN -L 127.0.0.1:9000 &
rsync -a /data/ rsync://localhost:9000/backup/
```

`--invite` mints the token; `--join` consumes it. Both are thin sugar over
`--token` (both buddies use the same value).

## Hardening (recommended)

Each buddy prints its own identity at startup. Pin your buddy explicitly instead
of trusting on first use:

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

## How it differs from "real" BuddyNet (v2+)

| | BuddyPeer (v1) | BuddyNet (v2+) |
|---|---|---|
| Peers per token | 2 | many (mesh) |
| Roster | the one partner | full gossiped roster |
| Discovery | handshake server | peer-to-peer gossip overlay |
| Transport | QUIC | QUIC **or** WireGuard (same seam) |

The wire format, virtual IPs, and fallback chain are already the BuddyNet ones,
so growing past two peers is additive, not a rewrite.

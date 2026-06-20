# MultiPeer — Many Tunnels at Once

A single BuddyNet node can hold **N tunnels to N buddies at the same time**, each
pinned and verified independently — that's **MultiPeer**. You list your buddies in
a manifest, route to each by name or virtual IP, and add or remove them while the
daemon runs. (Two buddies is just the one-line case; the manifest scales it up.)

This is decentralised and **self-sovereign**: your manifest is *your* list of who
*you* talk to. There is no group, no admin, no shared roster — removing a buddy
is a purely local decision that never touches the other peers.

## Quick start

Two machines, each maintaining the other (and any further buddies you add):

```bash
# Find each buddy's identity (its pinned key) once:
buddynet --role=buddy --key /var/lib/buddynet/id.key identity
# → alice prints ALICE_KEY, bob prints BOB_KEY (base64)

# Machine "home" — lists the buddies it serves, routes them on their VIPs:
cat > /var/lib/buddynet/peers <<EOF
ALICE_KEY  shared-token-with-alice
BOB_KEY    shared-token-with-bob
EOF

buddynet --role=buddy \
  --server VPS:51820 --server-key SERVER_KEY --quic-handshake \
  --key /var/lib/buddynet/id.key \
  --peers-file /var/lib/buddynet/peers \
  --name home --dns \
  --vip-listen 8080            # alice.buddy:8080 / bob.buddy:8080 each tunnel to that buddy
```

Each listed buddy runs the same way, listing `home` (and anyone else) in **its**
manifest with the matching bootstrap token. Once paired, the token is retired and
reconnects use a per-buddy stored session secret.

## The manifest (`--peers-file`)

One buddy per line; blank lines and `#` comments are ignored:

```
# <peer-pubkey-b64>                              [bootstrap-token]
ALICE_KEY-base64...                              shared-token-with-alice
BOB_KEY-base64...                                shared-token-with-bob
CAROL_KEY-base64...                                                        # already paired, no token
```

- **`<peer-pubkey-b64>`** (required) — the buddy's Ed25519 identity. Every tunnel
  is pinned by key (no trust-on-first-use, no SAS prompt — daemon-friendly).
- **`[bootstrap-token]`** (optional) — a shared one-time token used only for the
  *first* pairing. Both buddies put the same token on their respective lines.
  Once paired, a session secret is stored in `--known-peers` and the token is no
  longer needed (you can delete it from the line).

The file is the same trust domain as `known_peers` — keep it `0600`.

`--peers-file` is mutually exclusive with the single-buddy pairing modes
(`--invite` / `--join` / `--token`) and with `--lazy`. To route to more than one
buddy use `--vip-listen` (a single `-L` port can only reach one buddy).

## Managing your buddies — `peers` subcommands

Curate your own list without editing the file by hand. These run and exit:

```bash
# Show your buddies and whether each is paired yet:
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers peers list
# ALICE_KEY...  paired    token-set  (manifest)
# BOB_KEY...    unpaired  token-set  (manifest)
# CAROL_KEY...  paired    no-token   (session only)

# Add a buddy (pinned key + optional bootstrap token):
buddynet --peers-file /var/lib/buddynet/peers peers add DAVE_KEY shared-token-with-dave

# Remove (revoke) a buddy:
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers peers remove DAVE_KEY
```

`peers remove` is a **full local revocation**: it drops the manifest line **and**
the stored session secret. Both are required — removing only the manifest line
would leave the supervisor reconnecting via the leftover session.

## Routing — `--vip-listen`

With many buddies, one local `-L` port cannot tell them apart, so multi-buddy
routes on each buddy's **virtual IP**. `--vip-listen PORT` binds every connected
buddy's VIP (`10.66.X.Y`) on the loopback interface and forwards `VIP:PORT` (and,
with `--dns`, `name.buddy:PORT`) through *that* buddy's tunnel.

```bash
--vip-listen 8080            # listen on alice.buddy:8080, bob.buddy:8080, … each → its tunnel
--forward 127.0.0.1:8080     # the receiving side dials its local service for incoming streams
```

Binding a VIP needs `NET_ADMIN` (it adds an address to `lo` over netlink — no
`ip` subprocess). Without it, `--vip-listen` logs a `WARNING` and routes nothing,
but the tunnels themselves keep working — graceful degradation, like the DNS bind.
See [BUDDYDNS.md](BUDDYDNS.md) for resolving `*.buddy` names. The far side answers
incoming streams from its `--forward` target (one service per buddy).

## Live reload — `SIGHUP`

A running buddy re-reads its manifest on `SIGHUP` and reconciles: newly added
buddies get a tunnel, removed ones are dropped — no restart:

```bash
buddynet --peers-file ... peers add DAVE_KEY tok
kill -HUP "$(pidof buddynet)"        # picks up DAVE without downtime
```

Caveat: an **already-established direct tunnel** to a removed buddy persists until
it drops, because the handshake server is not in the data path. Set
`--reauth-interval` (e.g. `1h`) to bound how long a revocation can take to bite on
a live tunnel. (Windows has no `SIGHUP`; there a restart re-reads the manifest.)

## Flags

| Flag | Env | Description |
|------|-----|-------------|
| `--peers-file PATH` | — | Multi-buddy manifest (`<peer-key> [token]` per line). Maintains a tunnel to every listed buddy plus any previously paired peer. Mutually exclusive with `--invite`/`--join`/`--token`/`--lazy`. |
| `--vip-listen PORT` | — | Bind each connected buddy's VIP on `lo` and route `VIP:PORT` (and `name.buddy:PORT`) through that buddy's tunnel. Needs `NET_ADMIN`; degrades gracefully. |
| `--known-peers PATH` | — | Per-buddy session store (also where `peers remove` revokes the session secret). |
| `--reauth-interval D` | — | Periodically rebuild tunnels so a revocation takes effect within `D` on a live direct tunnel (off by default). |

Subcommands: `peers list`, `peers add <key> [token]`, `peers remove <key>`.

## How it works

1. **Assemble.** At start (and on every `SIGHUP`) the *worker set* is the union of
   the manifest and the stored sessions — so buddies paired before they were
   listed are not dropped.
2. **One worker per buddy.** Each runs its own connect/reconnect loop with its own
   backoff: it reconnects via its stored session if it has one, otherwise
   bootstraps via its token, otherwise stops. Workers are fully independent — one
   buddy going offline, failing, or being removed never affects the others.
3. **Per-buddy rendezvous secret.** After first pairing, each buddy gets a session
   secret derived from the live TLS channel binding (RFC 5705) — never a publicly
   computable value. Two nodes that know each other's public key therefore cannot
   be located by a third party who also knows those keys; only the holder of the
   secret can rendezvous. See [INVITE.md](INVITE.md) for the session-secret model.

## Security notes

- **Pinned, always.** Every manifest buddy is pinned by key (Model A). There is no
  trust-on-first-use in multi-buddy mode, so no SAS prompt and no blind learning —
  a key you did not list is a stranger with no access.
- **No authority.** Nothing here administers other nodes. Your `peers remove`
  protects *you*: afterwards your node won't register that buddy's rendezvous,
  won't pin it, and won't route to it. Whether that buddy still reaches *other*
  nodes is their own sovereign decision, not your exposure.
- **Revocation is two files.** `peers remove` drops both the manifest line and the
  session secret; the supervisor applies it on `SIGHUP`/restart, bounded on a live
  tunnel by `--reauth-interval`.
- **VIP scope.** Only *connected* buddies' VIPs are bound on `lo`; an unrelated
  `10.66.x.y` is never reachable. The bind uses a host-scoped `/32` so the address
  is local-only and not used for outbound source selection.

The full threat model is in [SECURITY.md](../SECURITY.md); the two-buddy basics in
[Two Buddies](TWO-BUDDIES.md).

# MultiPeer — Many Tunnels at Once

A single BuddyNet node can hold **N tunnels to N buddies at the same time**, each
pinned and verified independently — that's **MultiPeer**. You list your buddies in
a manifest, route to each by name or virtual IP, and add or remove them while the
daemon runs. (Two buddies is just the one-line case; the manifest scales it up.)

This is decentralised and **self-sovereign**: your manifest is *your* list of who
*you* talk to. There is no group, no admin, no shared roster — removing a buddy
is a purely local decision that never touches the other peers.

> **We recommend no more than 16 buddies per node — the enforced ceiling of 48 is
> a guardrail, not a capacity target.** 16 is the range BuddyNet is tested and
> tuned for; 48 is where the code stops you fail-closed so a bad manifest cannot
> bring up an unbounded number of tunnels.
>
> The 48 is a deliberate design limit, not a performance one — BuddyNet is a
> personal overlay for small, trusted groups, and there is no flag to raise it. It
> is enforced fail-closed: a manifest (or a `peers add`) over the limit is refused
> with a clear error, not silently truncated; an over-large *session* store is
> capped with a warning instead. The assembler also rejects a virtual-IP collision
> between two keys outright rather than routing ambiguously. If you need more
> simultaneous peers, use a solution designed for large-scale meshes — that is not
> what BuddyNet aims to be.

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
  --server VPS:51820 --server-key SERVER_KEY \
  --key /var/lib/buddynet/id.key \
  --peers-file /var/lib/buddynet/peers \
  --name home --dns \
  --vip-listen 8080            # alice.buddy:8080 / bob.buddy:8080 each tunnel to that buddy
```

Each listed buddy runs the same way, listing `home` (and anyone else) in **its**
manifest with the matching bootstrap token. Once paired, the token is retired and
reconnects use a per-buddy stored session secret.

## The manifest (`--peers-file`)

The manifest is **YAML** — one entry per buddy, hand-editable and managed by the
`peers` subcommands:

```yaml
buddies:
  - name: alice                 # optional — display name / .buddy hint
    key: ALICE_KEY-base64...    # required — the buddy's pinned Ed25519 identity
    token: shared-with-alice    # optional — one-time bootstrap token
    expose: [873]               # optional — WireGuard: alice reaches ONLY tcp :873 here
  - name: bob
    key: BOB_KEY-base64...
    expose: [8080, "udp/51820"] # bare numbers are tcp; "udp/…" for UDP
  - key: CAROL_KEY-base64...
    expose: all                 # explicit whole-host access for carol
  - key: DAVE_KEY-base64...     # no expose → inherits --expose, else fail-closed
```

- **`key`** (required) — the buddy's Ed25519 identity. Every tunnel is pinned by
  key (no trust-on-first-use, no SAS prompt — daemon-friendly).
- **`token`** (optional) — a shared one-time token used only for the *first*
  pairing. Both buddies configure the same token. Once paired, a session secret
  is stored in `--known-peers` and the token is no longer needed.
- **`name`** (optional) — a display name (letters/digits/hyphens, max 63).
- **`expose`** (optional, WireGuard data plane) — the port(s) THIS buddy may
  reach on your host over its tunnel. Overrides the global `--expose` flag;
  omitted, the buddy inherits the flag — and with neither, **nothing is exposed**
  (fail-closed). `all` is the explicit whole-host opt-out. See
  [WIREGUARD.md](WIREGUARD.md).

Unknown fields are rejected (a typo never silently changes your security posture).
The file is the same trust domain as `known_peers` — keep it `0600`.

> **Upgrading from the old line format** (`<key> [token]` per line): it is still
> read for one release (with a deprecation warning). Convert it in place with
> `peers migrate` — the original is kept as `<file>.bak`:
>
> ```bash
> buddynet --peers-file /var/lib/buddynet/peers peers migrate
> ```

`--peers-file` is mutually exclusive with the single-buddy pairing modes
(`--invite` / `--join` / `--join`) and with `--lazy`. To route to more than one
buddy use `--vip-listen` (a single `-L` port can only reach one buddy).

## Managing your buddies — `peers` subcommands

Curate your own list without editing the file by hand. These run and exit:

```bash
# Show your buddies and whether each is paired yet:
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers peers list
# VIP            NAME   STATUS    KEY     TOKEN      EXPOSE     SOURCE
# 10.66.18.240   alice  paired    m2x9Kp  token-set  tcp/873    manifest
# 10.66.7.13     —      unpaired  q8Lm2A  token-set  (inherit)  manifest
# 10.66.44.2     bob    paired    Zk1pQ9  —          (inherit)  session-only

# Add a buddy (pinned key + optional bootstrap token, name, WireGuard scope):
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers \
    peers add DAVE_KEY shared-token-with-dave --name dave --expose 873

# Remove (revoke) a buddy — the short 6-char KEY from `peers list` is enough:
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers \
    peers remove Zk1pQ9

# Allow a revoked buddy again (then pair with a NEW invite):
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers \
    peers allow Zk1pQ9
```

> **Pass the same `--known-peers` to every `peers` command.** The stored sessions
> and the revocation list live next to that path, so a command run without it
> works on a different set of files than the one run with it. If you use the
> default location, simply omit the flag everywhere.

The `KEY` column is the first 6 characters of the buddy's identity key — a
human-friendly handle, not the full key. `peers remove` accepts it (or any unique
prefix, or the full key) and refuses an ambiguous one. `NAME` is the buddy's
self-asserted `.buddy` name; it is best-effort from the offline cache
(`--peers` / peers.json) and shows `—` until the buddy has been seen via the
server. `VIP` is derived deterministically from the key, so it is always shown.

> **Since v5.2.0.** The revocation list, `peers allow`, and the "a still-running
> buddy cannot undo it" property are new in that release. In v5.1.x, `peers
> remove` dropped the manifest entry and the session but kept no permanent
> record.

`peers remove` is a **full local revocation**: it records the key on the
revocation list (`<known_peers>.revoked`), drops the stored session secret, and
drops the manifest line — in that order, under one lock. All three are required.
Removing only the two files was not enough: a still-running worker held the
bootstrap token in memory, re-paired with it, and wrote the session back, so the
`SIGHUP` that was meant to apply the revocation restarted the buddy instead.

The revocation list is permanent and there is deliberately no expiry — an entry
disappears only when you lift it:

```bash
# lift a revocation (then pair again with a NEW invite):
buddynet --known-peers /var/lib/buddynet/known_peers peers allow Zk1pQ9

# with a manifest, adding the buddy back lifts it in the same step:
buddynet --peers-file /var/lib/buddynet/peers --known-peers /var/lib/buddynet/known_peers \
  peers add DAVE_KEY fresh-token
```

A revoked buddy is refused at every door: the reconnect attempt stops the worker
(`peer-stopped … buddy revoked`), a session cannot be stored for it, it cannot be
learned trust-on-first-use, and `SIGHUP` will not re-assemble it. `peers list`
shows it with status `REVOKED` so it never disappears silently.

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
| `--peers-file PATH` | — | Multi-buddy manifest (`<peer-key> [token]` per line). Maintains a tunnel to every listed buddy plus any previously paired peer. Mutually exclusive with `--invite`/`--join`/`--join`/`--lazy`. |
| `--vip-listen PORT` | — | Bind each connected buddy's VIP on `lo` and route `VIP:PORT` (and `name.buddy:PORT`) through that buddy's tunnel. Needs `NET_ADMIN`; degrades gracefully. |
| `--known-peers PATH` | `~/.config/buddynet/known_peers` | Per-buddy session store. `peers remove` deletes the session secret here, and the revocation list lives next to it as `<path>.revoked`. |
| `--reauth-interval D` | — | Periodically rebuild tunnels so a revocation takes effect within `D` on a live direct tunnel (off by default). |

Subcommands: `peers list`, `peers add <key> [token]`, `peers remove <key>`
(revoke), `peers allow <key>` (lift a revocation), `peers migrate`.

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
- **Revocation is one transaction.** `peers remove` writes the tombstone, then
  drops the session secret, then the manifest line — under one lock, so a crash
  in between leaves the *safe* state (revoked, possibly still configured), never
  a buddy that is unconfigured but still allowed back. A running worker stops on
  its next round; a live direct tunnel is bounded by `--reauth-interval`.
- **VIP scope.** Only *connected* buddies' VIPs are bound on `lo`; an unrelated
  `10.66.x.y` is never reachable. The bind uses a host-scoped `/32` so the address
  is local-only and not used for outbound source selection.

The full threat model is in [SECURITY.md](../SECURITY.md); the two-buddy basics in
[Two Buddies](TWO-BUDDIES.md).

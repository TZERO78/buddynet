# Operations reference

Deployment options, network-level controls, and the log schema for BuddyNet
operators. Covers: QUIC control plane, IP allowlists, relay setup, log format,
and the `--status` probe.

> **New to this?** For a friendly, start-to-finish walkthrough of standing up your
> own VPS coordinator — install & verify, a hardened nftables firewall, systemd,
> connecting buddies, and maintenance — see **[SETUP.md](SETUP.md)**. This
> page is the flag-by-flag reference behind it.

---

## QUIC control plane

**The control plane is encrypted with QUIC/TLS 1.3 by default** — security by
default. You do not need to pass anything; it is on unless you explicitly opt out
with (or on the handshake server **and**
every buddy. Keep it on. The examples below explicitly,
which is fine (it just confirms the default).

```bash
# Server
buddynet --role=handshake \
  --key /var/lib/buddynet/id.key \

# Every buddy
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  ...
```

### Why the control plane is QUIC

The control plane is QUIC/TLS 1.3, and there is no alternative to choose: the
whole `REGISTER` exchange — pairing token included — is inside TLS, and only the
server can read it. Source addresses are validated by the QUIC handshake itself,
so the server can never be turned into a reflector and no extra round-trip is
needed for it.

Until v5 a plain-UDP transport existed alongside it, with an application-layer
cookie for source validation and the `REGISTER` in cleartext. It is removed: the
cookie only reproduced what QUIC does anyway, while the cleartext token was what
made an on-path pairing squat possible in the first place.

### Approval mode (`--authorized`) at runtime

Setting it up is in [SETUP.md — Harden](SETUP.md#approval-mode--recommended-for-a-private-server).
What matters while it runs:

- **TLS authenticates, the allowlist authorizes.** Every client is authenticated
  by its Ed25519 key at the TLS handshake; whether that key may pair is decided
  per signed `REGISTER`. An unknown key therefore reaches the application layer —
  that is what makes code-based enrollment possible — and is refused there before
  any pairing state exists for it.
- **Unknown keys get their own, much tighter limiter** (2/s per source, 20/s
  global, against 50/s and 1000/s for allowlisted traffic), so strangers cannot
  spend an approved buddy's budget or grow the pending set.
- **The list is re-read on change**, so approving a buddy needs no restart. Watch
  it with the `AUTHZ:` lines below.
- **Empty or missing list = nobody pairs.** It never falls back to open mode; the
  server logs a `WARNING` naming the exact `approve` command.

> The data plane can run over QUIC (default) or kernel WireGuard (`--wireguard`);
> the control plane is always QUIC — never WireGuard — so per-buddy endpoint
> discovery and MultiPeer keep working (see [WIREGUARD.md](WIREGUARD.md)).

## IP allowlists (`--allow-cidr`)

A network-level pre-filter for the handshake server and/or relay: sources outside
the listed CIDRs are refused before they can occupy a connection slot.

**Where it runs differs by role, and the difference matters when you size a public
VPS.** On the **relay** the check really is pre-crypto — the relay owns its UDP
read loop, so a disallowed source never causes a signature verification. On the
**handshake server** quic-go owns the packet path, so the QUIC/TLS handshake has
already happened by the time the CIDR is seen. It is a cheap way to keep strangers
out of your slots, not a way to avoid the cost of TLS: only a firewall rule does
that (see [SECURITY.md §5.5](../SECURITY.md#55-what-an-unauthenticated-source-can-cost-you-the-pre-tls-boundary)).

```bash
buddynet --role=handshake,relay \
  --allow-cidr 203.0.113.0/24,198.51.100.0/24 \
  --key /var/lib/buddynet/id.key
```

**Format:** comma-separated CIDRs (`10.0.0.0/8`) or bare IPs (treated as `/32`
or `/128`). Both IPv4 and IPv6 are supported.

`--allow-cidr` applies to both the handshake role and the relay role when they
run on the same node (combined with `--role=handshake,relay`). Buddies' virtual
IPs (`10.66.0.0/16`) are loopback-only — they are never the source address on
the server-facing socket, so there is no interaction with the virtual network.

**Combined with approval mode:** `--allow-cidr` runs before `--authorized`.
It is a cheap pre-filter, not a replacement for key-based authorization.

---

## Relay setup

The relay blindly forwards encrypted QUIC datagrams between two buddies when a
direct hole-punch has failed. It sees only ciphertext — never plaintext or
virtual IPs.

> **A relay refuses to start without an authorization policy (v5.0.0).** It
> carries your bandwidth, and a stranger who hoards its capacity takes away the
> fallback the two people it was built for need. Give it one of:
>
> - **`--server-key` + `--relay-id`** — verify **relay tickets** from your own
>   handshake server. Recommended: a ticket follows a buddy whose address
>   changes, which is exactly the buddy that needs a relay.
> - **`--allow-cidr`** — serve named networks only. Supported, but a CIDR list
>   cannot follow a residential address that moves.
>
> Both together are an **AND**, never an either/or. `--allow-cidr 0.0.0.0/0` and
> `::/0` are refused with their own message: an open relay is not a supported
> configuration, and there is no `--relay-open` switch.

### Relay tickets in one minute

Mint the id **once** and use the SAME value on both sides:

```bash
buddynet gen-relay-id            # e.g. aN_ckZY_txk-nL6BNLTKTg
```

The handshake server then issues every paired buddy a short-lived signed permit
for that relay, and the relay verifies it with the server's **public** key. The
relay learns *that* a session was authorised — never who is in it. It holds no
buddy list and no signing key.

Both sides print the id they are using at startup, because a mismatch otherwise
shows up only as "every ticket rejected" with nothing naming the cause.

### Combined handshake + relay (typical VPS setup)

One process, one command. The relay derives the key it trusts from the handshake
server in its own process, so the only new flag is the id:

```bash
buddynet --role=handshake,relay \
  --listen [::]:51820 \
  --relay-listen [::]:51821 \
  --relay-endpoint vps.example:51821 \
  --relay-id aN_ckZY_txk-nL6BNLTKTg \
  --key /var/lib/buddynet/id.key
```

When `--relay-endpoint` is set, every `PEER_LIST` sent to buddies includes the
relay address. Buddies try direct hole-punch first; if that fails within
`--punch` (default 2 s, max 60 s), they fall back to the relay automatically.

### Standalone relay (separated — recommended when the relay is exposed)

```bash
buddynet --role=relay \
  --listen [::]:51821 \
  --server-key <SERVER_KEY> \
  --relay-id aN_ckZY_txk-nL6BNLTKTg
```

`<SERVER_KEY>` is what `buddynet --key ... identity` prints on the handshake
server. The relay needs **no identity key of its own** and writes nothing.

> **Combined and separated are not equivalent, and the difference is a security
> one.** `--role=handshake,relay` is one process, so the server's **signing key
> sits in the same memory that parses relay packets**: code execution reached
> through the relay could then mint tickets — worse than abusing a relay, because
> it forges authorisation for every relay that trusts that key. In the separated
> setup (two processes, ideally two users, ideally two hosts) the relay holds no
> signing key at all, and compromising it yields no ability to authorise
> anything. Combined stays first-class and is what most small VPS setups will
> run; choose it knowing what it costs.

### Rotating the handshake server key

Pass **two** keys to the relay (`--server-key OLD,NEW`) while buddies move over,
then drop the retired one. The relay accepts tickets signed by either during the
window.

### Clocks

Relay and handshake server must agree on the time within **10 s**. NTP handles
it; when it breaks, *every* ticket is refused and the relay logs a line naming
both possible causes — the clock, or a wrongly-issued ticket. It genuinely cannot
tell them apart, so it does not claim to.

### What the relay logs

A shortened session id, the leg, and a reason. That is enough to correlate the
two legs of one session in one log and deliberately not enough to link a session
to a buddy. Tickets, signatures, cookies and ephemeral keys are never logged, and
**source addresses only under `--debug`** — a relay that prints who talks to whom
has given up the property this design exists to protect. Debugging is harder for
it; that is the trade.

### Relay flags

| Flag | Description |
|------|-------------|
| `--server-key KEY[,KEY2]` | Handshake server(s) whose relay tickets this relay accepts. Two during a key rotation. One of the two authorization policies. |
| `--relay-id ID` | This relay's id, the SAME value on the handshake server (`buddynet gen-relay-id`). Required with `--server-key`. |
| `--allow-cidr CIDRS` | Only these source networks may bind a leg. The other authorization policy; ANDed with tickets when both are set. `0.0.0.0/0`, `::/0` refused. |
| `--relay-listen ADDR` | Relay listen address when combined with another role. Default `[::]:51821`. |
| `--relay-endpoint HOST:PORT` | (handshake) Advertised to buddies as the relay-of-last-resort. |
| `--ttl DURATION` | Idle timeout for relay sessions. Default 60 s. A session holding only one leg expires after an absolute 60 s regardless. |
| `--relay-max-sessions N` | Concurrent session ceiling (default 4096). |
| `--relay-max-legs-per-ip N` | Legs one source may hold (default 64; a source is one IPv4 address or one IPv6 /64). |
| `--debug` | Also log source addresses on rejections. Not for production. |

### No relay at all is a supported setup

BuddyNet works P2P-only: a handshake server with no relay configuration is fully
functional, and no relay port needs to be open anywhere. When the direct path
fails and no relay is configured, the buddy says exactly that instead of timing
out silently.

---

## Many buddies (MultiPeer)

A node can hold **N tunnels to N buddies at once**, each pinned and verified
independently. You list your buddies in a manifest, route to each by name or
virtual IP, and add or remove them while the daemon runs.

This is self-sovereign: the manifest is *your* list of who *you* talk to. There is
no group, no admin, no shared roster — removing a buddy is a local decision that
never touches the other peers.

> **We recommend no more than 16 buddies per node — the enforced ceiling of 48 is
> a guardrail, not a capacity target.** The 48 is a design limit, not a performance
> one, and there is no flag to raise it: a manifest over the limit is refused with
> a clear error, never silently truncated. If you need more simultaneous peers, use
> something built for large meshes — that is not what BuddyNet aims to be.

The manifest is YAML, hand-editable and managed by the `peers` subcommands:

```yaml
buddies:
  - name: alice                 # optional — display name / .buddy hint
    key: ALICE_KEY-base64...    # required — the buddy's pinned Ed25519 identity
    token: shared-with-alice    # optional — one-time bootstrap token
    expose: [873]               # optional — WireGuard: alice reaches ONLY tcp :873
  - name: bob
    key: BOB_KEY-base64...
    expose: [8080, "udp/51820"] # bare numbers are tcp; "udp/…" for UDP
  - key: CAROL_KEY-base64...
    expose: all                 # explicit whole-host access for carol
  - key: DAVE_KEY-base64...     # no expose → inherits --expose, else fail-closed
```

Every manifest buddy is pinned by key — there is no trust-on-first-use in
multi-buddy mode, so no SAS prompt and no blind learning. `token` is used only for
the first pairing; afterwards each buddy has its own stored session secret.
Unknown fields are rejected, so a typo never silently changes your posture. Keep
the file `0600` — it is the same trust domain as `known_peers`.

`--peers-file` is mutually exclusive with the single-buddy pairing modes
(`--invite` / `--join`) and with `--lazy`. Routing to more than one buddy needs
`--vip-listen`; a single `-L` port can only reach one buddy.

### Curating the list

```bash
# Show your buddies and whether each is paired yet:
buddynet --peers-file /var/lib/buddynet/peers \
    --known-peers /var/lib/buddynet/known_peers peers list
# VIP            NAME   STATUS    KEY     TOKEN      EXPOSE     SOURCE
# 10.66.18.240   alice  paired    m2x9Kp  token-set  tcp/873    manifest
# 10.66.7.13     —      unpaired  q8Lm2A  token-set  (inherit)  manifest

# Add / remove (revoke) / un-revoke:
buddynet --peers-file … --known-peers … peers add DAVE_KEY tok --name dave --expose 873
buddynet --peers-file … --known-peers … peers remove Zk1pQ9
buddynet --peers-file … --known-peers … peers allow Zk1pQ9
```

> **Pass the same `--known-peers` to every `peers` command.** The stored sessions
> and the revocation list live next to that path, so a command run without it
> works on a different set of files. If you use the default location, omit the
> flag everywhere.

The `KEY` column is the first 6 characters of the identity key — `peers remove`
accepts it, any unique prefix, or the full key, and refuses an ambiguous one.
`VIP` is derived from the key, so it is always known; `NAME` is best-effort from
the offline cache and shows `—` until the buddy has been seen via the server.

**`peers remove` is a full local revocation** (since v5.2.0): it records the key on
a permanent revocation list (`<known_peers>.revoked`), drops the stored session,
and drops the manifest line — in that order, under one lock. All three are
required. Removing only the files was not enough: a still-running worker held the
bootstrap token in memory, re-paired with it and wrote the session back, so the
`SIGHUP` meant to apply the revocation restarted the buddy instead. A revoked
buddy is refused at every door and shows as `REVOKED` in `peers list`, so it never
disappears silently. The list never expires; `peers allow` (or adding the buddy
back) is the only way off it.

### Routing and reload

`--vip-listen PORT` binds every connected buddy's VIP (`10.66.X.Y`) on loopback and
forwards `VIP:PORT` — and, with `--dns`, `name.buddy:PORT` — through *that* buddy's
tunnel. The far side answers from its `--forward` target. Binding a VIP needs
`NET_ADMIN`; without it `--vip-listen` logs a `WARNING` and routes nothing while
the tunnels keep working.

A running buddy re-reads its manifest on **`SIGHUP`** and reconciles — new buddies
get a tunnel, removed ones are dropped, no restart:

```bash
buddynet --peers-file … peers add DAVE_KEY tok
kill -HUP "$(pidof buddynet)"
```

Caveat: an already-established **direct** tunnel to a removed buddy persists until
it drops, because the server is not in the data path. `--reauth-interval` (e.g.
`1h`) bounds how long a revocation can take to bite on a live tunnel.

Workers are fully independent: one buddy going offline, failing, or being removed
never affects the others. At start and on every `SIGHUP` the worker set is the
union of the manifest and the stored sessions, so buddies paired before they were
listed are not dropped.

---

## Names (`.buddy`)

Add `--name alice` to a buddy and `--dns` to whoever wants to resolve, and
`alice.buddy` reaches that buddy over its own tunnel:

```bash
buddynet --role=buddy --server VPS:51820 --server-key SERVER_KEY \
  --invite --forward 127.0.0.1:873 --name alice --dns

ping alice.buddy                # → alice's virtual IP (10.66.X.Y)
dig @127.0.0.153 alice.buddy    # ask the stub resolver directly
```

The buddy sends its name on `REGISTER`; the server validates it against DNS-label
rules and relays it verbatim in `PEER_LIST`; the receiving buddy pins it in
`peers.json` (first claim wins) and answers `<name>.buddy` from a stub resolver on
`127.0.0.153:53`.

**Name rules:** lowercase letters, digits and hyphens, starting and ending with a
letter or digit, at most 63 characters. A label of **exactly 8 hex characters** is
rejected — that shape is reserved for the fingerprint alias below, so a
self-asserted name can never shadow another peer's fingerprint entry (`deadbeef` is
refused for this reason; `deadbeefx` or `web01` are fine).

**Fingerprint fallback.** Every peer is also reachable as `<fp8>.buddy`, the first
8 hex characters of `SHA-256(pubkey)`. It works for peers without a `--name` and is
stable as long as the key is.

**Collisions are resolved on first claim.** The same key announcing a different
name later keeps its original and logs a `WARNING`; a second key claiming a name
already taken gets fingerprint-only addressing and a `WARNING`. Pinned names
survive restarts via `peers.json`.

With `--dns`, BuddyNet registers the `.buddy` domain with `systemd-resolved`
(`resolvectl dns lo 127.0.0.153`, `resolvectl domain lo ~buddy`) and reverts it on
shutdown. Without `resolvectl` it logs a `NOTE`; add `nameserver 127.0.0.153` to
`/etc/resolv.conf` yourself, or query the stub directly.

Port 53 needs privilege: run the service as root, or grant the binary
`sudo setcap cap_net_bind_service=+ep /usr/local/bin/buddynet`. Without either,
`--dns` logs a `WARNING` and the tunnel runs on without name resolution.

---

## When no path comes up

You are most likely here because BuddyNet said:

```
no path to the partner: the direct connection failed and no relay is configured
```

A buddy walks a fallback chain, cheapest and most private first:

| # | Path | Log label | When it exists |
|---|------|-----------|----------------|
| 1 | Direct P2P | `direct P2P` | the server gave you live candidates for your partner |
| 2 | Known relay | `known relay <host:port>` | the server advertised a relay for this pair |
| 3 | Handshake as relay | `handshake server as relay` | the server itself also runs `--role=relay` |
| 4 | Cached peer | `cached peer (server offline)` | you paired before and `peers.json` still knows the partner |

Every attempt is logged (`CONNECT: action=path-try` / `path-failed`), and a
successful run ends with the path that won. **If the chain only ever contained
`direct P2P`, there was no relay to fall back to** — that is the message above,
not a mystery failure.

### Why a direct connection sometimes cannot work

BuddyNet hole-punches: both sides send outward simultaneously so each NAT opens a
return path. Whether that works depends on the two NATs, and you control neither:

- **Endpoint-independent NAT ("full cone") on at least one side** — punching
  usually works. The common home-router case, and why no port forwarding is needed.
- **Symmetric NAT on both sides** — the router picks a *different* external port
  per destination, so the port your partner was told about is not the one that
  reaches you. Punching cannot succeed by design.
- **CGNAT** — you are behind the provider's NAT as well as your own. Frequently
  symmetric, and never something you can reconfigure.

BuddyNet **cannot tell you which case you are in.** It sees that the path failed,
not how the NAT behaved — which is why the error does not promise that a relay
would help. It usually does.

### What fixes it, and what doesn't

A relay forwards the already-encrypted session. It sees ciphertext and virtual
IPs, never plaintext. Setup is under [Relay setup](#relay-setup) above; two things
produce exactly the error at the top of this section:

- **Without `--relay-endpoint`, buddies are never told the relay exists.** A
  running relay that is not advertised is invisible — `PEER_LIST` carries its
  address only when that flag is set, so the chain stays one entry long.
- **A relay refuses to start without an authorization policy** (since v5.0.0). If
  it isn't running at all, its log says why.

Also check that the relay port is open in the VPS firewall. And mint the relay id
**once** — substituting `gen-relay-id` into the start line hands out a fresh id on
every restart and invalidates every ticket already issued.

**Opening a port on the buddy does not fix it.** The buddy binds an *ephemeral*
UDP port, so the kernel picks a different one on every start and there is no flag
to pin it. You cannot forward a port whose number you won't know until the process
is running. Port forwarding applies to the VPS side, not to a buddy.

**Checklist**

1. Is the handshake server reachable at all? `CONNECT: action=server-unreachable`
   means the problem is before any of this — wrong `--server`, firewall, or down.
2. Does the log show more than one path being tried? If not, no relay is
   configured or advertised.
3. Is `--relay-endpoint` set to the address *buddies* can reach (its public
   host:port, not `[::]`)?
4. Is the relay port open in the firewall, and is the relay actually running?
5. `--punch` (default 2 s, max 60 s) can be raised on a slow link — but a longer
   punch does not help against symmetric NAT. That is structural, not timing.

---

## Unattended nodes

For a daemon with no human at the keyboard:

- **Pin explicitly with `--peer-key`** instead of relying on the first-contact
  code. It is checked on every connect, including reconnects from a stored
  session.
- **Set `--no-interactive`.** It never learns an unknown key blindly — it fails
  instead, which is what you want unattended.
- **Keep secrets out of argv**: `--join`, `--code` and friends read from the
  environment (`BUDDYNET_JOIN`, …) or a file.
- **`--reauth-interval`** periodically rebuilds tunnels so a revocation takes
  effect within that interval on a live direct tunnel. Off by default, because it
  trades a brief reconnect for that bound.

---

## WireGuard data plane (`--wireguard`)

Opt-in (Phase 3): carry the tunnel over kernel WireGuard instead of QUIC, so the
partner is reachable natively at its VIP. Full design and security notes in
**[WIREGUARD.md](WIREGUARD.md)**; the operational essentials:

- **Requirements.** Linux with the `wireguard` kernel module (`modprobe wireguard`)
  and **`NET_ADMIN`** (root, or `AmbientCapabilities=CAP_NET_ADMIN` in the unit) to
  create the interface. Set `--wireguard` on **both** buddies.
- **Fails closed.** If `--wireguard` is set but kernel WireGuard is unavailable, the
  buddy errors out — it does **not** silently fall back to QUIC.
- **Interfaces.** One WireGuard interface per buddy: `bnet0` for a single partner,
  `bnet0`, `bnet1`, … in MultiPeer (`--peers-file`). Each carries this node's VIP and
  a `/32` route to that partner's VIP. They are torn down when the tunnel drops.
- **Forwarding flags are ignored** on this path: the VIP is reachable directly, so
  `-L`/`-forward`/`--vip-listen` print a `NOTE` and do nothing. Reach the partner at
  `<partner-vip>:<port>`.
- **Exposure is scoped by default (`--expose`).** A buddy can reach **only** the
  port(s) you `--expose` (e.g. `--expose 873`, or per buddy via `expose:` in the
  manifest); without it, nothing is reachable (fail-closed). `--expose all` restores
  whole-host access explicitly. Only the partner's VIP `/32` is routed; LANs/VLANs
  behind the buddy are not. See [WIREGUARD.md](WIREGUARD.md).
- **`--expose` covers this host only — a buddy is never routed THROUGH it.**
  BuddyNet drops everything that arrives on `bnetN` and is destined elsewhere
  (a `fwd` chain next to the `in` chain in `table inet buddynet`). This matters on
  any host that forwards, which includes anything running Docker: without it, a
  buddy could address a machine on your LAN directly and bypass `--expose`
  entirely, since WireGuard's AllowedIPs constrains only the packet's *source*.
  **Behaviour change in v5.0.0:** if you were routing a LAN host to a buddy through
  this node — or a buddy into your LAN — that stops. Subnet routing returns as its
  own explicit option with the destinations named by you; it will never be implied
  by `--expose all`.
- **Changing a scope at runtime.** A per-buddy `expose:` edit in the `--peers-file`
  manifest takes effect on `SIGHUP`: the supervisor reprograms that buddy's `bnetN`
  firewall scope **in place** — the tunnel stays up, no reconnect, the partner is
  not involved (`SUPERVISOR: action=reload-rescope`). A tightened scope therefore
  takes effect immediately, unlike a removed *buddy*, whose live tunnel lingers.
  The global `--expose` flag is fixed for the process; change it with a restart.
- `CONNECTED` logs `via="… (WireGuard)"`.

---

## Log schema

BuddyNet uses structured `key=value` log lines so audit trails can be parsed,
grepped, and forwarded to log management tools. All lines go to stderr/journal.

### Security events — `SECURITY:`

Always logged. Never rate-limited or silenced.

| Line | When |
|------|------|
| `SECURITY: event=pin-mismatch token=… key=… detail=…` | The partner key does not match `--peer-key`. Possible MITM or misconfiguration. |
| `SECURITY: event=key-changed token=… key=… detail=…` | The buddy's key changed for a known token. Possible MITM or key rotation. Check with the partner. |
| `SECURITY: event=vip-mismatch key=… detail=…` | The handshake server's `PEER_LIST` claims a VIP inconsistent with the key. Hostile or buggy server. |
| `SECURITY: event=replay-detected token=… src=… key=… id=…` | A `REGISTER` signature was seen twice within the replay window. |
| `SECURITY: event=leg-cap-hit src=… detail=…` | One source holds the maximum number of relay legs — possible session hoarding. `src` is the accounting key, so it is an IPv4 address (`203.0.113.7`) or an IPv6 **`/64`** (`2001:db8:1:2::/64`), not a single IPv6 address: every address inside a `/64` is free to mint, so they share one budget. |
| `SECURITY: event=panic-recovered component=… detail=…` | A request/connection handler panicked and was contained (the request was dropped, the process kept running). A repeat is a bug or a panic-triggering input worth investigating; the line is throttled per component. |

### Trust events — `TRUST:`

```
TRUST: action=tofu-new    key=… token=… store=… detail=…   # first contact, SAS confirmed, key recorded
TRUST: action=tofu-match  key=… token=…                    # reconnect, key matches stored
TRUST: action=pinned-ok   key=… token=…                    # --peer-key check passed
TRUST: action=insecure    key=… token=… detail=…           # --lab, no verification
```

### Authorization events — `AUTHZ:` (approval mode only)

```
AUTHZ: action=pending key=… token=…   — approve with: buddynet … approve KEY
AUTHZ: action=pending key=… code=…    — approve with: buddynet … approve KEY
AUTHZ: action=reload  count=N         # authorized file was hot-reloaded
```

### Tunnel lifecycle

```
PAIRED:       token=… a=KEY/IP b=KEY/IP cands=N/N      # two buddies paired at the server
CONNECTED:    role=buddy partner=… key=… vip=… via=… remote=…   # tunnel up
CONNECTED:    … via="… (WireGuard)" remote=… handshake=…       # --wireguard: proven handshake time
DISCONNECTED: role=buddy partner=… key=… reason=… duration=… streams=N
```

On the `--wireguard` path `CONNECTED` carries `handshake=` — the time of the
WireGuard handshake the partner completed. The line is only logged once that
handshake exists, so it never reports a tunnel to a partner that never answered.

### Connection lifecycle — `CONNECT:` (bring-up) / `RECONNECT:` (retry loop)

```
CONNECT: action=partner-verified id=… key=… vip=… cands=N   # roster checked, not online yet
CONNECT: action=path-try         path=… role=server|client [endpoint=…]   # trying a fallback path
CONNECT: action=path-failed      path=… detail=…            # that path did not come up; try the next
CONNECT: action=session-stored   store=… detail=…           # first pairing done; session secret saved
CONNECT: action=cached           id=… vip=… detail="server offline"   # using the offline peer cache
CONNECT: action=server-unreachable server=… detail=…        # handshake server down; falling back to cache
CONNECT: action=reauth           interval=… detail=…         # --reauth-interval fired, re-checking trust

RECONNECT: action=waiting          detail="no peer with this token yet"   # registered, awaiting partner
RECONNECT: action=error            detail=…                  # the attempt failed; will retry
RECONNECT: action=retry            delay=…                   # backing off before the next attempt
RECONNECT: action=session-fallback key=… failures=N detail=…  # stale session presumed; probing the
                                                              # bootstrap token to recover (key stays pinned)
```

### Server lifecycle — `HANDSHAKE:` / `RELAY:`

```
HANDSHAKE: action=listening      addr=… transport=udp           # handshake server is up
RELAY:     action=listening      addr=… transport=udp detail=…  # relay is up (blind forwarder)
RELAY:     action=session-paired a=… b=…                        # two legs matched, relaying
RELAY:     action=session-closed detail="idle > …"              # relayed session expired
```

### Multi-buddy supervisor — `SUPERVISOR:` (`--peers-file`)

```
SUPERVISOR: action=start        buddies=N          # supervising N buddies (SIGHUP reloads the manifest)
SUPERVISOR: action=peer-stopped key=… detail=…     # one buddy's worker stopped (others unaffected)
SUPERVISOR: action=reload-start key=…              # SIGHUP: a newly listed buddy started
SUPERVISOR: action=reload-stop  key=…              # SIGHUP: a removed buddy stopped (revoked)
SUPERVISOR: action=reload       buddies=N          # reconcile complete, N buddies now running
SUPERVISOR: action=reload-failed detail=…          # the manifest could not be re-read
```

### Lazy tunnel — `LAZY:` (`--lazy`)

```
LAZY: action=listening addr=… detail="tunnel deferred until first connection"
LAZY: action=waking    detail="local connection arrived, dialing tunnel"   # a CONNECTED: line follows
```

### Scoped exposure — `EXPOSE:` (`--wireguard --expose`)

Logged once per buddy interface at WireGuard bring-up, so the effective
least-privilege posture is visible without guessing (see docs/WIREGUARD.md).

```
EXPOSE: action=scoped        iface=bnet0 ports=tcp/873,udp/51820   # buddy reaches ONLY these ports here
EXPOSE: action=fail-closed   iface=bnet0 detail="…"                # no --expose: nothing reachable (default)
EXPOSE: action=whole-host    iface=bnet0 detail="explicit --expose all"   # opted out of scoping
EXPOSE: action=remove-failed iface=bnet0 detail=…                 # teardown could not drop the rules
```

A scope that cannot be enforced (no kernel nftables support / missing
`CAP_NET_ADMIN`) is fail-closed: the tunnel is refused, surfaced as
`RECONNECT: action=error` with an actionable message (add `--expose <port>`, or
`--expose all`), never a silent whole-host exposure.

### BuddyDNS — `BUDDYDNS:` (`--dns`)

```
BUDDYDNS: action=listening           addr=127.0.0.153:53        # stub resolver bound
BUDDYDNS: action=resolver-registered addr=127.0.0.153 detail="*.buddy routed via resolvectl"
```

(The bind-failure and resolvectl-skip cases are logged as `WARNING:`/`NOTE:` — see below.)

The `via=` field in `CONNECTED` tells you which path the tunnel actually took —
this is how you check whether your traffic is going direct or through a relay:

| Value (quoted in the log) | Meaning |
|-------|---------|
| `via="direct P2P"` | Hole-punch succeeded — no relay in the path |
| `via="known relay HOST:PORT"` | The relay your server advertised is forwarding; the direct punch failed |
| `via="handshake server as relay"` | The handshake server is also relaying (combined role) |
| `via="cached peer (server offline)"` | The handshake server was unreachable; the offline peer cache was used |

```bash
# Is the current tunnel direct, or over a relay?
journalctl --namespace=buddynet | grep 'CONNECTED:' | tail -1
```

With `--wireguard` the same field reads `via="… (WireGuard)"`.

### Operational warnings — `WARNING:` and `NOTE:`

```
WARNING: key file PATH has permissions MODE, expected 0600
WARNING: ephemeral identity KEY — pass --key to persist it (buddies pin this)
NOTE: --reauth-interval is 0 (off): a server-side revocation will NOT tear down a direct tunnel
NOTE: BuddyDNS: could not register .buddy with systemd-resolved (…)
NOTE: server roster is signed but N out of date — check NTP/time-sync
```

### Filtering examples

The shipped units log into their **own journal namespace** (`LogNamespace=buddynet`)
so a flood of BuddyNet lines can never fill the main system journal. Every
command therefore needs `--namespace=buddynet`; without it you are reading a
different journal and will see nothing:

```bash
# All security events from the last hour
journalctl --namespace=buddynet --since "1 hour ago" | grep "SECURITY:"

# All tunnel connections today
journalctl --namespace=buddynet --since today | grep "CONNECTED:"

# All pending approval requests
journalctl --namespace=buddynet | grep "AUTHZ: action=pending"

# Did any buddies connect over a relay (not direct)?
journalctl --namespace=buddynet | grep 'CONNECTED:' | grep -F 'via="known relay'
```

The unit names are `buddynet-handshake`, `buddynet-relay` and
`buddynet-buddy@<instance>` (plus `buddynet-public-handshake` for the
single-purpose public server) — there is no unit called plain `buddynet`. Each
sets a `SyslogIdentifier`, so you can also filter by role:

```bash
journalctl --namespace=buddynet -u buddynet-handshake -f   # one unit, follow
journalctl --namespace=buddynet -t buddynet-relay          # by identifier
```

### Running a port that is open to the internet

The handshake port is meant to be reachable from anywhere — that is how buddies
behind NAT find each other. Some things about that are worth knowing before they
worry you:

- **Automated scanning is constant and normal.** Any address with an open UDP
  port is probed continuously by researchers, botnets and search engines. It is
  background noise on the internet, not a sign that someone is after you.
- **Most of it never reaches the application.** Packets from a source that
  `--allow-cidr` excludes, packets that fail address validation, and malformed
  datagrams are dropped early and deliberately **without a log line**. Logging
  every dropped packet would be the easiest way to turn a scan into a disk-space
  attack.
- **An empty BuddyNet log therefore does not prove nobody knocked.** It proves
  that nothing got far enough to be worth writing down. If you want to see the
  volume, count it where packets actually arrive — nftables counters, or your
  provider's traffic graphs:

  ```bash
  sudo nft list ruleset | grep -A2 'udp dport 51820'   # counters on the rule
  ```

- **Rate limits protect resources, not availability.** BuddyNet bounds how much
  work one source can cause (connection budget, per-source and global limits,
  bounded in-memory state). Someone with enough bandwidth can still saturate the
  uplink of a small VPS. That is a property of the network, not something an
  application can fix; if it matters to you, that is a question for your provider.
- **The clock matters.** Relay tickets and registration proofs carry timestamps
  with a tolerance measured in seconds. Keep NTP running: a drifting clock looks
  exactly like an attack in the logs, and eventually breaks pairing.
- **`--debug` is not for a public server.** It logs source addresses next to
  session ids — pairing metadata the server deliberately does not keep otherwise.

### How long logs are kept

The shipped `journald@buddynet.conf` caps the namespace at **50 MB** and drops
entries **older than one week** (`MaxRetentionSec=1week`). That is a storage
guarantee, and it is also a limit on what you can investigate later: anything you
want to look at beyond a week has to be **exported before it expires**, for
example a nightly

```bash
journalctl --namespace=buddynet --since yesterday --until today \
    -o export > /var/backups/buddynet-$(date +%F).journal
```

or forwarding to a log host you run. Raise `MaxRetentionSec` and `SystemMaxUse`
together if you would rather keep more on the machine — but check the disk first,
because the cap is what keeps a log flood from filling it.

Logs deliberately contain **no private keys, no invite tokens and no session
secrets**. Public keys appear shortened, and source addresses appear on the relay
only with `--debug`, which is why `--debug` is not for a public server.

---

## Lazy tunnel mode (`--lazy`)

By default BuddyNet establishes the QUIC tunnel before binding the local
listener (`-L`). If the server or peer is unreachable at startup the port
is never opened — the caller sees `connection refused`.

`--lazy` inverts this:

- The `-L` TCP listener binds **immediately**, before any tunnel attempt.
- The QUIC tunnel is established **on demand** when the first connection
  arrives.
- Subsequent connections within the same session are instant (CONNECTED
  fast-path).
- If the tunnel drops (idle-timeout or peer close) the listener stays open
  and the next connection wakes a fresh dial.

```bash
buddynet --role=buddy \
  --server vps.example:51820 --server-key KEY \
  --join=TOKEN \
  -L 127.0.0.1:5432 --forward 10.66.0.2:5432 \
  --lazy
```

**When to use it:** backup tools (rsync, kopia), cron jobs, or any client
that is invoked infrequently and should not have to wait for a persistent
daemon to reconnect before binding its port.

**Constraints:**

- Requires `-L`. `--lazy` without `-L` is a startup error.
- The first connection experiences the full tunnel setup latency (~1–2 RTT
  for hole-punch or relay fallback). The OS TCP receive buffer (≥ 64 KB)
  holds client data during this WAKING window.
- `BUDDYNET_LAZY=1` is the equivalent environment variable.

---

## `--status` probe

A one-shot connectivity check for scripts and monitoring: it brings the tunnel up,
reports, and exits. This section is the reference for it.

```bash
buddynet --role=buddy --server … --server-key … --join=TOKEN --status
# exit 0: reachable | 3: unreachable | 4: offline | 5: untrusted | 1: error
```

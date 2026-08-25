# Operations reference

Deployment options, network-level controls, and the log schema for BuddyNet
operators. Covers: QUIC control plane, IP allowlists, relay setup, log format,
and the `--status` probe.

> **New to this?** For a friendly, start-to-finish walkthrough of standing up your
> own VPS coordinator — install & verify, a hardened nftables firewall, systemd,
> connecting buddies, and maintenance — see **[VPS-HOWTO.md](VPS-HOWTO.md)**. This
> page is the flag-by-flag reference behind it.

---

## QUIC control plane, the secure default)

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

### Locking the control plane to known buddies (`--authorized`)

In **approval mode** (`--authorized <allowlist>`) the control plane separates
**authentication** from **authorization**, and the split is deliberate:

- **TLS authenticates every client.** Each buddy presents an Ed25519 identity
  certificate and TLS 1.3 makes it sign the transcript, so the key handed up is one
  it demonstrably holds. `REGISTER.pubkey` must equal that key or the connection is
  closed with nothing stored.
- **The allowlist decides per `REGISTER`**, not at the TLS handshake. An
  allowlisted key registers; an unknown key carrying a valid sealed enrollment code
  becomes a pending enrollment; an unknown key without one is refused.

A TLS-layer allowlist gate would make code-based enrollment impossible — a key that
was never approved could not complete the handshake, so its sealed code could never
reach the operator (that was the bug fixed in v4.1.0). Unknown keys are therefore
rate-limited far more tightly than allowlisted ones (2/s per source, 20/s global).
The server logs:

```
approval mode: QUIC control authenticates every client by key at the TLS handshake; the allowlist decision (allow / enroll with a code / refuse) is made per REGISTER
```

```bash
# Server: only allowlisted buddy keys may even open a control connection
buddynet --role=handshake \
  --authorized /var/lib/buddynet/clients.txt --key /var/lib/buddynet/id.key

# Approve a buddy (get its key with `buddynet identity` on that node):
buddynet --authorized /var/lib/buddynet/clients.txt approve <buddy-key>
```

Without `--authorized` (open mode) the QUIC handshake still encrypts the exchange
and validates the source, but any client may connect and pairing is gated only by
the secret token at the application layer. See [APPROVAL.md](APPROVAL.md).

> This is BuddyNet's "known buddies only" control plane. The data plane can run
> over QUIC (default) or kernel WireGuard (`--wireguard`); the control plane is
> always QUIC/plain — never WireGuard — so per-buddy endpoint discovery and
> MultiPeer keep working (see [WIREGUARD.md](WIREGUARD.md)).

### Environment variable

```bash
export   # equivalent to
```

---

## IP allowlists (`--allow-cidr`)

A network-level pre-filter for the handshake server and/or relay. Datagrams or
connections from sources outside the listed CIDRs are dropped **before any
crypto**, making it a cheap first line of defence for private or fleet
deployments.

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

A one-shot connectivity check for scripts and monitoring. See the full
reference in [INVITE.md — Checking the link](INVITE.md#checking-the-link).

```bash
buddynet --role=buddy --server … --server-key … --join=TOKEN --status
# exit 0: reachable | 3: unreachable | 4: offline | 5: untrusted | 1: error
```

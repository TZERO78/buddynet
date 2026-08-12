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
  --server vps.example:51820 --server-key SERVER_KEY \ \
  ...
```

### Why QUIC is the right default

| Property | Plain UDP | QUIC |
|---|---|---|
| REGISTER confidentiality | **Cleartext** — token travels in the clear | Encrypted (TLS 1.3) |
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

In **approval mode** (`--authorized <allowlist>`) the QUIC control plane pins
clients by key at the **TLS handshake**: every buddy presents its Ed25519 identity
certificate, and the server rejects any key not on the allowlist **before** it can
send a `REGISTER`. A non-allowlisted node never reaches the matchmaking logic — the
same early rejection a firewall gives, enforced cryptographically (no PKI; the key
is pinned directly, mirroring how the buddy pins the server key). The server logs:

```
approval mode: QUIC control pins clients to the allowlist at the TLS handshake
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
  --allow-cidr 203.0.113.0/24,198.51.100.0/24 \ \
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

### Standalone relay

```bash
buddynet --role=relay \
  --listen [::]:51821 \
  --key /var/lib/buddynet/id.key
```

### Combined handshake + relay (typical VPS setup)

Run both roles on one node. Use `--relay-listen` to bind the relay on a
different port from the handshake, and `--relay-endpoint` to advertise it to
buddies:

```bash
buddynet --role=handshake,relay \
  --listen [::]:51820 \
  --relay-listen [::]:51821 \
  --relay-endpoint vps.example:51821 \
  --key /var/lib/buddynet/id.key \
```

When `--relay-endpoint` is set, every `PEER_LIST` sent to buddies includes the
relay address. Buddies try direct hole-punch first; if that fails within
`--punch` (default 2 s), they fall back to the relay automatically.

### Relay flags

| Flag | Description |
|------|-------------|
| `--relay-listen ADDR` | Relay listen address when combined with another role. Default `[::]:51821`. |
| `--relay-endpoint HOST:PORT` | Advertised to buddies as the relay-of-last-resort. Set when the handshake server also runs relay. |
| `--allow-cidr CIDRS` | Drop relay datagrams from sources outside these networks (same syntax as above). |
| `--ttl DURATION` | Idle timeout for relay sessions. Default 60 s. |

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
HANDSHAKE: action=listening      addr=… transport=udp           # bootstrap server is up
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

The `via=` field in `CONNECTED` tells you which path the tunnel used:

| Value | Meaning |
|-------|---------|
| `direct` | Hole-punch succeeded — no relay in the path |
| `relay:HOST:PORT` | Relay is forwarding; direct punch failed |
| `cached` | Server was unreachable; used the offline peer cache |

### Operational warnings — `WARNING:` and `NOTE:`

```
WARNING: key file PATH has permissions MODE, expected 0600
WARNING: ephemeral identity KEY — pass --key to persist it (buddies pin this)
NOTE: --reauth-interval is 0 (off): a server-side revocation will NOT tear down a direct tunnel
NOTE: BuddyDNS: could not register .buddy with systemd-resolved (…)
NOTE: server roster is signed but N out of date — check NTP/time-sync
```

### Filtering examples

```bash
# All security events from the last hour
journalctl -u buddynet --since "1 hour ago" | grep "^[0-9: UTC]* SECURITY:"

# All tunnel connections today
journalctl -u buddynet --since today | grep "CONNECTED:"

# All pending approval requests
journalctl -u buddynet | grep "AUTHZ: action=pending"

# Did any buddies connect via relay (not direct)?
journalctl -u buddynet | grep 'CONNECTED:' | grep 'via=relay'
```

The `SyslogIdentifier` is set per-role when running under systemd
(`buddynet-handshake`, `buddynet-relay`, `buddynet-buddy`), so you can filter
by role with `-t`:

```bash
journalctl -t buddynet-handshake -f
```

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

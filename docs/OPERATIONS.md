# Operations reference

Deployment options, network-level controls, and the log schema for BuddyNet
operators. Covers: QUIC control plane, IP allowlists, relay setup, log format,
and the `--status` probe.

---

## QUIC control plane (`--quic-handshake`)

**Use `--quic-handshake` on every deployment.** It must be set identically on
the handshake server and on every buddy that connects to it.

```bash
# Server
buddynet --role=handshake \
  --key /var/lib/buddynet/id.key \
  --quic-handshake

# Every buddy
buddynet --role=buddy \
  --server vps.example:51820 --server-key SERVER_KEY \
  --quic-handshake \
  ...
```

### Why QUIC is the right default

| Property | Plain UDP | QUIC |
|---|---|---|
| REGISTER confidentiality | **Cleartext** — token travels in the clear | Encrypted (TLS 1.3) |
| Source-address validation | Cookie round-trip (UDP overhead) | Built into QUIC handshake |
| Reflection/amplification | Cookie mitigates, still needs a round-trip | Prevented structurally |
| Connection overhead | One RTT for cookie + one for REGISTER | ~1 RTT amortised |

On plain UDP the `REGISTER` message — including the pairing token — travels
**in cleartext** over the public internet. A passive observer on your path to
the VPS can read the token. With `--quic-handshake` the entire control
exchange is inside TLS 1.3; only the server can read the token.

The server logs a `WARNING` when plain UDP is used:

```
WARNING: on plain UDP the REGISTER (incl. the pairing token) travels in
CLEARTEXT — use --quic-handshake on the server and every buddy to encrypt
the control plane.
```

### Environment variable

```bash
export BUDDYNET_QUIC=1   # equivalent to --quic-handshake
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
  --quic-handshake \
  --key /var/lib/buddynet/id.key
```

**Format:** comma-separated CIDRs (`10.0.0.0/8`) or bare IPs (treated as `/32`
or `/128`). Both IPv4 and IPv6 are supported.

`--allow-cidr` applies to both the handshake role and the relay role when they
run on the same node (combined with `--role=handshake,relay`). Buddies' virtual
IPs (`10.66.0.0/24`) are loopback-only — they are never the source address on
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
  --quic-handshake
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
| `SECURITY: event=leg-cap-hit src=… detail=…` | One source IP holds the maximum number of relay legs — possible session hoarding. |

### Trust events — `TRUST:`

```
TRUST: action=tofu-new    key=… token=… store=… detail=…   # first contact, SAS confirmed, key recorded
TRUST: action=tofu-match  key=… token=…                    # reconnect, key matches stored
TRUST: action=pinned-ok   key=… token=…                    # --peer-key check passed
TRUST: action=insecure    key=… token=… detail=…           # --insecure, no verification
```

### Authorization events — `AUTHZ:` (approval mode only)

```
AUTHZ: action=pending key=… token=…   — approve with: buddynet … approve KEY
AUTHZ: action=pending key=… code=…    — approve with: buddynet … allowclient CODE
AUTHZ: action=reload  count=N         # authorized file was hot-reloaded
```

### Tunnel lifecycle

```
PAIRED:       token=… a=KEY/IP b=KEY/IP cands=N/N      # two buddies paired at the server
CONNECTED:    role=buddy partner=… key=… vip=… via=… remote=…   # tunnel up
DISCONNECTED: role=buddy partner=… key=… reason=… duration=… streams=N
```

The `via=` field in `CONNECTED` tells you which path the tunnel used:

| Value | Meaning |
|-------|---------|
| `direct` | Hole-punch succeeded — no relay in the path |
| `relay:HOST:PORT` | Relay is forwarding; direct punch failed |
| `cached` | Server was unreachable; used the offline peer cache |

### Operational warnings — `WARNING:` and `NOTE:`

```
WARNING: on plain UDP the REGISTER … travels in CLEARTEXT — use --quic-handshake
WARNING: key file PATH has permissions MODE, expected 0600
WARNING: generated a NEW identity at PATH — buddies must pin the new key
NOTE: --reauth-interval is 0 (off): a server-side revocation will NOT tear down a direct tunnel
NOTE: MagicDNS: could not register .buddy with systemd-resolved (…)
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

## `--status` probe

A one-shot connectivity check for scripts and monitoring. See the full
reference in [INVITE.md — Checking the link](INVITE.md#checking-the-link).

```bash
buddynet --role=buddy --server … --server-key … --join=TOKEN --status
# exit 0: reachable | 3: unreachable | 4: offline | 5: untrusted | 1: error
```

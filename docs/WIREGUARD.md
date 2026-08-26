# WireGuard data plane (`--wireguard`)

> **Status:** shipped in **v3.0.0** — opt-in and lab-validated by the project's
> own netns tests (`lab/test-wg-*.sh`). The default data plane is still QUIC.
> A common use of the scoped door is a single service, for example SMB with
> `--expose 445`. BuddyNet provides the scoped transport; the service itself is
> yours to run, secure and patch.

> ## ⚠️ Sharing is SCOPED by default (`--expose`)
>
> **A buddy can reach ONLY the port(s) you `--expose` — never your whole host,
> and never anything BEHIND it.** Without `--expose`, **nothing** on your host is
> reachable over the tunnel (fail-closed; ping stays allowed for diagnosis). To
> share everything on *this host* — the pre-scoping behaviour — you must say so
> explicitly: `--expose all`.
>
> **`--expose all` means this HOST, not your LAN.** Traffic arriving on `bnetN` is
> never routed onward, whatever your scope — see
> [the `fwd` chain](#the-fwd-chain---expose-means-this-host-not-your-lan). If you
> were relying on a buddy reaching your LAN through this node (or the other way
> round), that stops in v5.0.0; subnet routing returns as its own explicit option.
>
> ```bash
> buddynet --role=buddy ... --wireguard --expose 873          # buddy reaches ONLY tcp :873
> buddynet --role=buddy ... --wireguard --expose tcp/873,udp/51820
> buddynet --role=buddy ... --wireguard --expose all          # explicit whole-host access
> ```
>
> - **Requirement:** kernel **nftables support** + `CAP_NET_ADMIN` — both already
>   required for `--wireguard` on any current kernel. **No** userspace firewall
>   tool is needed: BuddyNet does **not** depend on `nft`, `iptables`, `ufw` or
>   `firewalld` being installed (it talks to the kernel directly over netlink).
> - **Coexistence:** rules live in BuddyNet's own private `table inet buddynet`,
>   never in the host's `filter`/ufw/firewalld tables. An existing firewall setup
>   is not touched, and its reloads do not touch BuddyNet's scope. The host
>   firewall can never *widen* the scope (a drop in any table wins) — and the
>   reverse also holds: on a default-deny host firewall, tunnel traffic needs an
>   allow there too (both layers must agree; defense in depth).
> - **Fail-closed:** if the scope cannot be enforced (ancient pre-nftables
>   kernel), the tunnel **refuses to come up** instead of silently exposing the
>   host. This now includes `--expose all`, which used to be the escape hatch:
>   since it also has to install the rule that stops a buddy being *routed onward*,
>   there is nothing left it could enforce without nftables — and coming up anyway
>   would mean routing into your LAN with no way to say so.
> - **Per buddy:** in MultiPeer, each manifest entry can carry its own `expose:`
>   list — see [OPERATIONS.md](OPERATIONS.md). Precedence: per-buddy `expose` →
>   `--expose` flag → fail-closed.

BuddyNet can carry the tunnel over **kernel WireGuard** instead of QUIC. It is
opt-in (`--wireguard`, set on **both** buddies) and changes only the *data plane* —
the whole control plane (matchmaking, signed `PEER_LIST`, pinning/TOFU, the
fallback chain, the blind relay, the 48-buddy cap) is unchanged. No protocol
version bump: the wire format between buddy and server is identical.

> **The control plane is always QUIC — never WireGuard.** Matchmaking runs over
> QUIC/TLS 1.3 (encrypted, source-validated, every client authenticated by its
> Ed25519 key; with `--authorized` the allowlist decision is made per `REGISTER`,
> not at the TLS handshake — see
> [OPERATIONS.md](OPERATIONS.md) and [SETUP.md](SETUP.md)). Keeping control
> off WireGuard is deliberate: the server would otherwise key peers by identity and
> a buddy's N concurrent registrations would collide, breaking per-buddy endpoint
> discovery and MultiPeer — the same reason Tailscale/Netbird keep their control
> plane off WireGuard. `--wireguard` is purely the data plane.

## Why WireGuard

The QUIC path forwards TCP over streams (`-L`/`-forward`). WireGuard instead gives
each node a real L3 overlay address: once the tunnel is up, the partner is
reachable **natively at its virtual IP** (`10.66.X.Y`) for *any* protocol, with no
per-connection plumbing. It is steadier for long-running mesh use (survives roaming
and re-keys) — the motivation for Phase 3.

## Identity is still address

Nothing new is trusted. The WireGuard (X25519) key pair is **derived
deterministically** from the node's long-term Ed25519 identity
(`crypto.X25519FromEd25519Public/Private`), and the interface VIP is the same
`10.66.X.Y = SHA-256(pubkey)` as everywhere else. So `identity = key = VIP` carries
onto the data plane with **nothing exchanged over the wire** — two nodes that know
each other's pinned Ed25519 key already agree on each other's WireGuard key and VIP.
A roster claiming an inconsistent VIP is rejected exactly as on the QUIC path.

The kernel interface is configured directly over **raw netlink** (no `wg`/`ip`
subprocess, no `wireguard-tools` dependency), mirroring `internal/vip`'s approach
and keeping the zero-runtime-dependency posture. See `internal/wg/`.

## How a tunnel comes up

The WG path walks the **same fallback chain** as QUIC — direct first, then a relay:

1. **Register & verify** (unchanged): learn the partner's endpoint from the signed
   `PEER_LIST`; run the identity/VIP/pinning checks.
2. **Prime the path on one UDP socket:**
   - **Direct** — hole-punch to the partner's candidates.
   - **Relay** — bind a leg on the relay; the relay address becomes the endpoint.
3. **First contact only (TOFU):** verify the partner with a **Short Authentication
   String** bound to a fresh ephemeral-DH exchange run *over the punched UDP socket*
   (RFC 6189), since there is no TLS exporter on this path. A rejected SAS stops —
   it never falls back to another plane. Pinned peers (`--peer-key`, and all of
   MultiPeer) skip the SAS.
4. **Hand the socket to the kernel.** The punched socket is closed and kernel
   WireGuard is brought up **reusing that same local port**, so the NAT mapping
   survives the handoff (`lab/test-wg-handoff.sh`). Over a relay, the relay
   blindly forwards the encrypted WireGuard packets between the two legs — it is
   **not** a WireGuard peer and holds no key, exactly as it forwards QUIC.
5. **Wait for the WireGuard handshake.** Bringing the interface up is pure
   configuration — it succeeds even if that partner does not exist anywhere. So
   BuddyNet sends a probe datagram to the partner's VIP (this is what makes the
   kernel start the handshake; the 25 s keepalive alone could be that late) and
   polls the device until the peer reports a completed handshake. Only the holder
   of the pinned key can produce one. Timeout: 10 s — same budget as the QUIC
   dial; then the interface is torn down, **nothing is persisted**, and the
   supervisor retries.
6. **Reconnects** use a deterministic static-DH secret (`crypto.PairSecret`) of the
   two identities — no stored TLS material.

`CONNECTED` logs the path and the proven handshake time, e.g.
`via="direct P2P (WireGuard)" … handshake=2026-08-12T09:14:07Z`, or
`via="handshake server as relay (WireGuard)"`. It is logged **after** step 5, so a
`CONNECTED` line on this path always means a real partner answered.

### With `--direct` (no handshake server)

Step 1 falls away entirely: the partner is not learned, it is configured
(`--peer-endpoint` for where, `--peer-key` for who — see
[SETUP.md](SETUP.md#direct-mode-no-server-at-all)). Step 2 changes shape, because
WireGuard has no "listen" call — a peer either has an endpoint and initiates, or
has none and can only answer:

- The side that **dials** is configured with the resolved endpoint and initiates,
  exactly as above.
- The side that **is dialled** has no endpoint to configure, since nothing ever
  observed an address for it. It is therefore brought up as a peer with **no
  endpoint at all** and adopts the address of whatever handshake completes
  (WireGuard roaming). Its `CONNECTED` line reads `remote=adopted-from-handshake`.
  It also arms every path in the chain at once (`armWGPaths`) rather than trying
  them in turn — with no server, nothing synchronises the two ends, and one
  endpoint-less interface covers the direct path and the relay path together.

This is not a weakening of step 5: only the holder of the pinned key can complete
a handshake, so an unauthenticated packet cannot cause the adoption, and the
completed-handshake requirement is unchanged. `lab/test-wg-direct.sh` asserts that
the no-endpoint path was the one actually exercised, not merely that a tunnel
appeared.

There is no SAS on this path (step 3): direct mode always has a pinned key, and
without a rendezvous channel there would be nothing to run a first-contact
exchange over.

## Reaching the partner

The interface (`bnet0`, …) is assigned this node's VIP as a `/32`, with an explicit
`/32` route to the partner's VIP out that interface. So you simply talk to the
partner's VIP directly:

```
http://10.66.40.12          # the partner's Unraid web UI, a Docker app, ssh, …
```

`-L` / `-forward` / `--vip-listen` are the QUIC stream-forwarding flags; on the WG
path they are **not needed and ignored** (a `NOTE` is printed if set). Reach the
partner at `<partner-vip>:<port>`.

**Scope:** what is reachable is what the partner **`--expose`s** (see the box at
the top): only the named port(s), nothing without the flag, the whole host only
with an explicit `--expose all`. Independently of that, BuddyNet routes only the
partner's VIP `/32` — it does **not** route the LANs/VLANs *behind* the partner.
That is deliberate: BuddyNet connects two hosts, it is not a site-to-site / subnet
router or a mesh VPN.

## Scoped exposure — how it works

WireGuard's own AllowedIPs is *address*-based cryptokey routing; it cannot scope
*ports*. So BuddyNet gates inbound traffic on each `bnetN` in the kernel's
nftables subsystem, programmed directly over raw nfnetlink (`internal/nft`, the
same no-subprocess posture as the interface setup itself):

```
table inet buddynet {            # private table — never touches your firewall
  chain in {                     # input hook, policy accept (host unaffected)
    iifname "bnet0" ct state established,related accept
    iifname "bnet0" tcp dport 873 accept        # one rule per exposed port
    iifname "bnet0" meta l4proto icmp accept    # ping for diagnosis
    iifname "bnet0" meta l4proto ipv6-icmp accept
    iifname "bnet0" drop                        # the fail-closed floor
  }
  chain fwd {                    # forward hook, policy accept (host unaffected)
    iifname "bnet0" drop         # a buddy is never routed THROUGH this host
  }
}
```

### The `fwd` chain: `--expose` means *this host*, not your LAN

The `in` chain answers "what may the buddy reach **on this host**". It does not,
by itself, answer "may the buddy be routed **through** this host" — a packet that
is forwarded onward never traverses the input hook at all. And WireGuard's
AllowedIPs pins only the **source** of a decrypted packet, never its destination:
a buddy may put its own permitted VIP in the source field and any address it likes
in the destination field.

So on a host that forwards — and Docker turns forwarding on — a buddy could send a
packet addressed to a machine on your LAN and reach it: with ports exposed, with
**nothing** exposed, and under `--expose all`. That is what the `fwd` chain closes.
It is an unconditional drop, so:

- `--expose` (any value) opens ports **on this host only**.
- `--expose all` means the whole **host**, never the networks behind it.
- With no `--expose` at all, nothing is reachable either way.

> **Behaviour change (v5.0.0).** Traffic arriving on `bnetN` is no longer forwarded
> anywhere. If you were routing a LAN machine to a buddy through this node — or a
> buddy to your LAN — **that stops working.** It was never a documented feature and
> it bypassed `--expose`, which is why it is closed rather than grandfathered.
> Routing whole subnets over a buddy tunnel is a real thing to want; it will come
> back as its **own explicit option**, with the destination networks named by you,
> and never implicitly via `--expose all`.

- The scope is installed **before** the interface comes up — there is never a
  window of whole-host access — and removed with it on teardown.
- Established/related is allowed **on the input chain**, so *your own* outbound
  connections to the buddy always get their answers regardless of your scope.
  (There is deliberately no such rule on `fwd`: it would accept replies to
  *forwarded* connections, which is subnet routing by another name.)
- Each buddy has its own interface, so each has its own scope (MultiPeer) — and
  each gets its own forward drop.
- The whole table is rebuilt atomically on every change; a stale table from a
  killed process is cleared on the next start. Only a global `nft flush ruleset`
  removes it early — it is re-asserted on the next reconnect.
- Your own reach *into* the buddy is decided by the **buddy's** scope, not yours
  (egress is not filtered — this is inbound least-privilege, per host).

## MultiPeer: one interface per buddy

`--wireguard` combines with `--peers-file`. Each buddy gets its **own** WireGuard
interface — `bnet0`, `bnet1`, … — not one shared device.

This is forced by kernel WireGuard: a device has a single UDP listen port, and the
direct hole-punch hands its punched socket's port to that device — so two buddies
cannot share one device/port. One interface per buddy keeps every buddy on the
proven single-peer path, which means:

- **Peer-to-peer is preserved** — each tunnel still goes direct where it can; there
  is no central hub/"switch" on the VPS that all traffic must cross.
- **The relay still works per buddy** — each buddy has its own socket and thus its
  own relay leg, with none of the demux collisions a single shared port would hit.

The supervisor assigns each buddy a stable interface index, reconciled live on
`SIGHUP` like the rest of the manifest.

> A WireGuard **hub** on the VPS (the obvious "switch") was rejected on purpose: a
> hub terminates WireGuard and therefore sees plaintext, which would break the
> end-to-end and peer-to-peer properties that the blind relay exists to preserve.

## Requirements

- **Linux** with the `wireguard` kernel module and **`NET_ADMIN`** (root, or the
  capability) to create the interface. BuddyNet probes this with `wg.Available()`
  and **fails closed** if `--wireguard` is set but kernel WireGuard is unavailable —
  it does not silently fall back to QUIC.
- Set `--wireguard` on **both** buddies.
- Not combinable with `--lazy` (a QUIC-stream-specific feature).

## Security notes

- All control-plane guarantees are unchanged: signed `PEER_LIST`, VIP↔key reject,
  pinning/TOFU with a SAS on first contact, replay/cap protections, blind relay.
- **Fails closed:** WG unavailable, no usable path, a rejected SAS, or no
  WireGuard handshake within 10 s → an error, never a silent switch to another
  data plane.
- **Nothing is persisted before the partner is proven.** The `.buddy` name table,
  the cached endpoint and retiring the invite token all wait for the completed
  handshake (step 5 above). Without that, a compromised handshake server could get
  a name TOFU-pinned and an invite token retired for a connection that never
  existed — configuring an interface proves nothing about who is on the far end.
- **Whole-host exposure: RESOLVED by scoped exposure.** The formerly documented
  residual risk — every `0.0.0.0` service reachable by the buddy — is closed:
  inbound on `bnetN` is **fail-closed by default** and opened per port with
  `--expose` (per buddy in the manifest). `--expose all` restores the old
  behaviour, as an explicit operator decision. Defense in depth still applies:
  keep the services you do expose authenticated.
- The relay never sees plaintext on this path either — it forwards sealed WireGuard
  packets, just as it forwards QUIC.

## Lab validation

Run as root with the `wireguard` module loaded (netns labs):

- `lab/test-wg-buddy.sh` — direct P2P over WireGuard + native VIP ping; confirms the
  QUIC default still works (no regression).
- `lab/test-wg-direct.sh` — `--direct --wireguard` with no server anywhere:
  asserts the dialled side really ran the **no-endpoint** path
  (`remote=adopted-from-handshake`), pings the partner's VIP across the interface,
  then re-runs the same pair on QUIC so a regression in either plane shows up in
  one run.
- `lab/test-wg-relay.sh` — the direct path firewalled off, so the tunnel runs over
  the blind relay.
- `lab/test-wg-multipeer.sh` — a full mesh of three buddies, each on its own
  `bnet0`/`bnet1`, each pinging both partners' VIPs.
- `lab/test-wg-expose.sh` — scoped exposure: the exposed port answers, everything
  else is blocked, no `--expose` exposes nothing (fail-closed), `--expose all`
  keeps whole-host reach, and the nft table is gone after teardown.
- `lab/test-wg-forward.sh` — the `fwd` chain: a buddy cannot reach a LAN host
  behind the victim with ports exposed, with nothing exposed, or under
  `--expose all`; forwarding that never touches `bnetN` keeps working; the host's
  own outbound connections to the buddy keep working; and LAN→buddy forwarding is
  blocked (deliberate, until subnet routing exists). Every LAN check runs over
  IPv4 **and** IPv6, since the rules are an `inet` table matching on `iifname`.
  Set `APPLYSCOPE=` to a pre-fix build to watch it fail — 22/0 with the fix,
  15/7 without.
- `lab/test-wg-firewalls.sh` — coexistence with the host's own firewall:
  iptables-nft/iptables-legacy ACCEPTs cannot override the buddynet DROP, an
  `iptables-restore` reload leaves the buddynet table alone, a ufw-style
  default-deny additionally gates the tunnel (both layers must allow), and after
  a global `nft flush ruleset` the scope is re-asserted on reconnect.
- `lab/test-docker-firewalls.sh` — the same coexistence against REAL running
  firewall daemons in Docker (`firewalld`, `ufw`, a host `nft` table, and none):
  the tunnel forms, the exposed port is reachable, the unexposed port stays
  blocked by BuddyNet's scope, and the `inet buddynet` table lives alongside the
  host firewall's own tables (`inet firewalld` / `ip filter` / `inet hostfw`).

See also `docs/ARCHITECTURE.md` (data-plane seam) and `SECURITY.md` (threat model).

# Connectivity — when no path to your buddy comes up

You are most likely reading this because BuddyNet told you to:

```
no path to the partner: the direct connection failed and no relay is configured
(the handshake server advertises one with --relay-endpoint; see docs/CONNECTIVITY.md)
```

This page explains what was tried, why a direct connection sometimes cannot
work at all, and what actually fixes it. It does not promise that every network
can be made to work without a relay — because that is not true.

## What BuddyNet tried

A buddy walks a fallback chain, cheapest and most private first
(`internal/relay/fallback.go`):

| # | Path | Log label | When it exists |
|---|------|-----------|----------------|
| 1 | Direct P2P | `direct P2P` | the server gave you live candidates for your partner |
| 2 | Known relay | `known relay <host:port>` | the server advertised a relay for this pair |
| 3 | Handshake server as relay | `handshake server as relay` | the server itself also runs `--role=relay` |
| 4 | Cached peer | `cached peer (server offline)` | you have paired before and `peers.json` still knows the partner |

Every attempt is logged. A failing run looks like this:

```
CONNECT:  action=path-try path="direct P2P" role=client endpoint=203.0.113.7:41234
CONNECT:  action=path-failed path="direct P2P" detail="QUIC failed: ..."
```

and a successful one ends with the path that won:

```
CONNECTED: role=buddy partner=... vip=10.66.x.y via="direct P2P" remote=...
```

If the chain only ever contained `direct P2P`, **there was no relay to fall back
to** — that is the message quoted at the top, and it is not a mystery failure.

## Why a direct connection sometimes cannot work

BuddyNet hole-punches: both sides send outward at the same time so each one's NAT
opens a return path. Whether that works depends on how the two NATs behave, and
you have no control over some of them:

- **Endpoint-independent NAT ("full cone") on at least one side** — punching
  usually works. This is the common home-router case, and why the normal setup
  needs no port forwarding at all.
- **Symmetric NAT on both sides** — the router picks a *different* external port
  per destination, so the port the partner was told about is not the port the
  partner can reach. Punching cannot succeed by design.
- **CGNAT** (carrier-grade NAT, common on mobile and some fibre/cable ISPs) —
  you are behind the provider's NAT as well as your own. Frequently symmetric,
  and never something you can reconfigure.

BuddyNet **cannot tell you which case you are in.** It sees that the path failed,
not why the NAT behaved that way — which is why the error message does not claim
a relay would definitely help. It usually does.

## What fixes it: a relay

The relay forwards the already-encrypted QUIC session between the two buddies.
It sees ciphertext and virtual IPs, never plaintext — the partner's key is pinned
by the buddies themselves, so a relay cannot read or impersonate anything.

If you already run a VPS for the handshake role, the usual answer is to let that
same process relay as well:

```bash
# Mint the relay id ONCE and keep it — it must stay the same across restarts
# and on both sides. Substituting the command into the start line would hand
# out a fresh id on every restart and invalidate every ticket already issued.
buddynet gen-relay-id            # e.g. aN_ckZY_txk-nL6BNLTKTg

buddynet --role=handshake,relay \
  --listen [::]:51820 \
  --relay-listen [::]:51821 \
  --relay-endpoint vps.example:51821 \
  --relay-id aN_ckZY_txk-nL6BNLTKTg \
  --key /var/lib/buddynet/id.key
```

Full setup, including the separated relay variant and what a relay refuses to
start without, is in [OPERATIONS.md](OPERATIONS.md#relay-setup). Two things are worth
repeating here, because both produce exactly the error at the top of this page:

- **Without `--relay-endpoint`, buddies are never told the relay exists.** A
  running relay that is not advertised is invisible: `PEER_LIST` carries the
  relay address only when that flag is set, so the chain stays one entry long.
- **A relay refuses to start without an authorization policy** (since v5.0.0). If
  the relay is not running at all, check its log first — it will say so.

Also make sure the relay port (`--relay-listen`, `51821` above) is actually open
in the VPS firewall. That is a *server* port, fixed and known in advance.

## What does not fix it: opening a port on the buddy

A natural instinct is to forward a port to the machine running `--role=buddy`.
**That does not work today, and the reason is worth knowing:** the buddy binds an
**ephemeral** UDP port — `net.ListenUDP("udp", &net.UDPAddr{Port: 0})` in
`internal/role/connect.go` — so the kernel picks a different port on every start.
There is no flag to pin it. You cannot forward a port whose number you will not
know until the process is already running, and it changes on the next restart.

Port forwarding applies to the **VPS side** (handshake and relay listeners), not
to a buddy.

## Checklist

1. Is the handshake server reachable at all? A `CONNECT: action=server-unreachable`
   line means the problem is before any of this — wrong `--server`, firewall, or
   the server is down.
2. Does the log show more than one path being tried? If not, no relay is
   configured or advertised.
3. Is `--relay-endpoint` set on the server, with the address **buddies** can
   reach (its public host:port, not `[::]`)?
4. Is the relay port open in the VPS firewall?
5. Is the relay running? It exits at startup without an authorization policy.
6. `--punch` (default 2 s, max 60 s) can be raised on a slow link, but a longer
   punch does not help against symmetric NAT — that is a structural failure, not
   a timing one.

## Related

- [OPERATIONS.md](OPERATIONS.md) — relay setup, allowlists, log format.
- [VPS-HOWTO.md](VPS-HOWTO.md) — standing up the coordinator from scratch.
- [ARCHITECTURE.md](ARCHITECTURE.md) — why the relay is blind, and what it can and cannot see.

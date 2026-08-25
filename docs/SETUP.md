# Setup — from a blank VPS to a working tunnel

BuddyNet needs one small, always-on machine with a public IP to introduce your
buddies to each other: the **coordinator** (`--role=handshake`, optionally also
`--role=relay`). It only does matchmaking — **it never sees your traffic**
(see [SECURITY.md](../SECURITY.md)). This page takes you from a blank VPS to two
paired machines, in order, with commands you can paste.

**You don't always need a VPS.** If one of your two machines has a public IP or an
open port, that machine can be the coordinator. This guide covers the common case:
both machines behind NAT/CGNAT.

**What you need:** a VPS (the smallest tier is plenty — this is a control plane,
not a data path), its IP or a DNS name, and SSH access.

| # | Step | Why |
|---|------|-----|
| 1 | [Prepare the VPS](#1-prepare-the-vps) | a tiny always-on public IP |
| 2 | [Install the binary](#2-install-the-binary-verified) | signed release, provenance checked |
| 3 | [Firewall](#3-firewall) | default-drop; only SSH + BuddyNet ports |
| 4 | [systemd units](#4-systemd-units) | hardened, sandboxed, auto-restart |
| 5 | [Identity and server key](#5-identity-and-server-key) | the key your buddies pin |
| 6 | [Pair your buddies](#6-pair-your-buddies) | mint an invite, join from the other host |
| 7 | [Verify and maintain](#7-verify-and-maintain) | confirm it works; keep it updated |
| 8 | [Harden](#8-harden) | approval mode, source allowlist |

Two ports do all the work:

| Port | Role | Flag |
|------|------|------|
| **51820/udp** | handshake (matchmaking) | `--listen [::]:51820` |
| **51821/udp** | relay (fallback forwarder) | `--relay-listen [::]:51821` |
| 22/tcp | your SSH — keep it! | — |

---

## 1. Prepare the VPS

Any provider works. The coordinator is light on CPU, RAM and bandwidth.

```bash
ssh root@vps.example
apt update && apt -y upgrade        # or your distro's equivalent
```

Point a DNS name at it if you have one, or use the raw IP in the buddy commands
later. A **fixed** public IP is what matters.

---

## 2. Install the binary (verified)

Download the latest `buddynet-linux-amd64` and its `.bundle` from the
[releases page](https://github.com/TZERO78/buddynet/releases), then **verify the
signature before trusting it** — every release is keyless-signed with
cosign/Sigstore:

```bash
# needs cosign installed (https://docs.sigstore.dev/system_config/installation/)
cosign verify-blob --bundle buddynet-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github\.com/TZERO78/buddynet/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  buddynet-linux-amd64

sudo install -m0755 buddynet-linux-amd64 /usr/local/bin/buddynet
buddynet --version
```

A binary signed by anything other than this repository's workflow fails the check
— don't run it (see [SECURITY.md §8.3](../SECURITY.md#83-release-integrity)).

Since v5.2.0 there is also a build provenance attestation, if the box has **GitHub
CLI 2.49 or newer** (Ubuntu 24.04 ships 2.45, which lacks the command). `cosign`
above stays the offline check and is enough on its own:

```bash
gh attestation verify buddynet-linux-amd64 --repo TZERO78/buddynet
```

---

## 3. Firewall

This is the one layer that protects the **kernel's UDP stack and your bandwidth**.
BuddyNet's own caps bound the *process*; only the firewall stops a flood from
reaching the socket at all. Do this **before** you expose the service.

> ⚠️ **Read this first:** the ruleset sets the input policy to **drop** and
> explicitly re-allows **SSH on port 22**. If your SSH runs elsewhere, change
> `port_ssh` in that file *before* applying, or you will lock yourself out. Keep
> your current session open until a second one works.

BuddyNet ships a ready ruleset —
[`deployments/nftables.conf`](../deployments/nftables.conf), or
[`deployments/iptables.rules`](../deployments/iptables.rules) for hosts still on
iptables. **Apply that file; do not retype it from here.** This page deliberately
carries no second copy: it used to, the two drifted apart, and the copy here was
the one with the hole in it.

What the shipped policy does, and why the order matters:

- **default-drop** input, with loopback, ICMP/ICMPv6 (PMTU discovery) and **SSH**
  explicitly allowed.
- The **handshake port** is rate-limited, and that rule sits **before** the generic
  `established,related` accept, followed by an **explicit drop** of the excess.
  Both details are load-bearing. Netfilter marks a UDP flow established as soon as
  it has seen traffic both ways, so an earlier generic accept would wave through
  every later packet of that 5-tuple and the limit would never be reached — and
  without the explicit drop, over-limit packets fall through to that accept. QUIC
  also multiplexes many connections over one UDP flow, so conntrack is not a
  per-connection quota either.
- The **relay port** deliberately has **no packet-rate limit**. It carries tunnel
  *data*: a rate safe for a control plane would throttle the tunnel itself. Its
  abuse ceilings live in the relay (per-source bind limit, legs per source, session
  cap); bandwidth is a shaping problem (`tc`, an nftables meter sized for your
  link, a provider egress budget). Restrict **who** may reach it instead.

Be honest about what the limit buys: it is a **single global token bucket**. It
caps what a flood costs your VPS, but it does not guarantee availability under
attack — one noisy source can consume the shared budget and crowd out legitimate
pairings. For a link under real pressure you need your provider's DDoS handling,
not a packets-per-second rule.

Read the shipped file itself for the full commentary — every rule says why it is
where it is. Then apply and persist it (nftables shown; the iptables file has the
equivalent commands in its header):

```bash
sudo install -m0644 deployments/nftables.conf /etc/nftables.d/buddynet.conf
sudo nft -f /etc/nftables.d/buddynet.conf
echo 'include "/etc/nftables.d/*.conf"' | sudo tee -a /etc/nftables.conf
sudo systemctl enable --now nftables
sudo nft list table inet buddynet          # confirm
```

Pick **one** firewall system, not both — never two default-drop rulesets fighting
over the input hook.

**Notes**

- **`table inet`** covers IPv4 and IPv6 in one table. Running handshake only?
  Delete the `port_relay` line and don't open that port.
- **Keep the ports in sync** with your `--listen` / `--relay-listen`.
- **Rate-limit, don't source-restrict, by default.** Buddies usually sit behind
  dynamic/CGNAT addresses, so you can't pin their source IP.
- **If your buddies do have static IPs**, tighten as defence-in-depth — either
  `ip saddr { A, B }` in the nft rule, or BuddyNet's own `--allow-cidr` (step 8).
- **Already running ufw / firewalld?** Add the ports to *that* tool instead of
  stacking a second default-drop table.
- **Don't forget your provider's cloud firewall.** Open the ports there too, or
  traffic never reaches the box.

> **Verify it locally first.** [`lab/test-vps-howto.sh`](../lab/test-vps-howto.sh)
> loads this exact ruleset in a throwaway network namespace, proves the two
> BuddyNet ports and SSH pass while everything else is dropped, then runs a real
> pairing. Run it before you trust the rules on a box you SSH into.

---

## 4. systemd units

BuddyNet ships hardened, sandboxed units (`DynamicUser`, `ProtectSystem=strict`,
dropped capabilities, a size-capped private journal). Install them from
[`deployments/systemd/`](../deployments/systemd/):

```bash
# size-capped log namespace FIRST, so the units have somewhere to log
sudo install -m0644 deployments/systemd/journald@buddynet.conf /etc/systemd/journald@buddynet.conf
sudo systemctl restart systemd-journald@buddynet

sudo install -m0644 deployments/systemd/*.service /etc/systemd/system/
sudo install -m0644 deployments/systemd/buddynet-tmpfiles.conf /etc/tmpfiles.d/buddynet.conf
sudo systemd-tmpfiles --create
sudo systemctl daemon-reload
```

The handshake unit stores its identity key under `/var/lib/buddynet-handshake/`
(created `0700`). There is nothing to switch on: the control plane is QUIC/TLS 1.3
unconditionally since protocol v8.

To change the listen address, override the variable the unit defines:

```bash
sudo systemctl edit buddynet-handshake
# add:
#   [Service]
#   Environment=BUDDYNET_LISTEN=[::]:7000
```

> ⚠️ Never write a bare `Environment=` in an override. An empty assignment
> **resets every** `Environment=` the unit set — including `BUDDYNET_LISTEN`,
> which `ExecStart` expands — so the service starts with an empty `--listen`.

---

## 5. Identity and server key

The server does **not** create its own key. That is deliberate: if the state
directory is ever empty — an unmounted volume, a typo in `--key` — it refuses to
start rather than come up as a *different* server that every buddy rejects as a
possible MITM.

```bash
# ONCE: create the identity. Back this file up.
sudo -u buddynet-handshake buddynet --role=handshake \
    --key /var/lib/buddynet-handshake/id.key init

sudo systemctl enable --now buddynet-handshake

# ONCE: mint the relay id (not a secret) and set the SAME value on both units.
buddynet gen-relay-id                             # → RELAY_ID
#   sudo systemctl edit buddynet-handshake
#     [Service]
#     Environment=BUDDYNET_RELAY_ARGS=--relay-endpoint vps.example:51821 --relay-id RELAY_ID
#   sudo systemctl edit buddynet-relay
#     [Service]
#     Environment=BUDDYNET_RELAY_POLICY=--server-key SERVER_KEY --relay-id RELAY_ID
sudo systemctl enable --now buddynet-relay        # optional but recommended

# Print the key again later — `identity` only READS it:
sudo buddynet --key /var/lib/buddynet-handshake/id.key identity
```

That last command prints the **server public key**. Save it — every buddy pins it
with `--server-key`, so a hostile or swapped server can't impersonate yours.

```bash
journalctl --namespace=buddynet -u buddynet-handshake -f
# look for: HANDSHAKE: action=listening addr=[::]:51820 ...
```

> **The relay refuses to start without an authorization policy.** Give it
> `--server-key <SERVER_KEY> --relay-id <RELAY_ID>` (verify tickets from your
> handshake server — recommended, it follows a buddy whose address changes) or
> `--allow-cidr` (named networks only). `0.0.0.0/0` is refused. Without a policy,
> anyone on the internet can spend your bandwidth.

> **Running both roles in one process?** `--role=handshake,relay --relay-endpoint
> vps.example:51821 --relay-id RELAY_ID` works — the relay then trusts the
> handshake server in its own process, so no `--server-key` is needed. **The trade
> is blast radius:** one process means the signing key sits in the memory that
> parses relay packets, so code execution through the relay could mint tickets.
> Two units keep the relay holding no signing key at all — prefer them when the
> relay faces the public internet.

---

## 6. Pair your buddies

The coordinator doesn't create tunnels — your two machines do, using the server
address and the key from step 5.

### The words, first

These five get confused constantly, and the differences are what the security
rests on:

| Term | What it is | Lifetime | If it leaks |
|---|---|---|---|
| **Invite** (`bnet1.<token>.<key>`) | A rendezvous token plus the inviter's public key, handed over out of band. "One-time" describes what the *legitimate* sides do with it — they stop using it once paired. | The pair stops using it after the first pairing; the **server** never marks it spent | Someone else can take the joiner's place while the slot is free — and can keep trying later, because the server keeps no list of spent tokens. Treat it as a password. |
| **Identity key** (`id.key`) | The node's long-term Ed25519 key. It *is* the node's identity, and its virtual IP is derived from it. | Forever, until you replace it | Whoever holds it is that node. Revoke it on the other side and re-key. |
| **Buddy key** / `--peer-key` | The *partner's* public key, pinned on this side. Public information — pinning it is what makes a substituted partner fail. | As long as you keep it | Nothing. It is public. |
| **SAS** (six characters, e.g. `K7QX2M`) | A short code derived from both keys **and the live session**, compared once by a human on first contact when nothing was pinned. | One pairing attempt | Nothing by itself — it is only meaningful during that attempt. |
| **Session secret** | Derived from the encrypted channel after a successful pairing, stored locally. Later reconnects use it instead of the invite. | Until revoked or re-paired | It is a rendezvous credential; the partner key stays pinned, so it does not by itself let anyone impersonate your buddy. |

And the pair to all of them: **revocation** is a local decision on *your* node. It
removes a buddy's session, its manifest entry, and records the key so it cannot
come back. The handshake server does not do it for you, and it cannot tear down a
direct tunnel that is already up — see
[SECURITY.md §8.2](../SECURITY.md#82-revoking-access).

### The flow

```bash
# On machine A — mint an invite (prints an INVITE blob):
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
     --invite --forward 127.0.0.1:873

# On machine B — join with it, and reach A's service locally on :9000:
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
     --join INVITE -L 127.0.0.1:9000
```

Hand the invite over on a channel you trust (phone, Signal). It carries A's public
key, so **B pins A's identity straight from the blob** — nobody has to compare
anything in that direction, and a hostile handshake server cannot put a different
identity on that end.

The other direction still needs one human step: **A asks once for the
six-character code shown on B's screen** and types it in. That verifies B. It
cannot be click-confirmed away, and it takes a phone call.

`--invite-timeout` (default 15 minutes) bounds how long **A waits** — it does not
make the token unusable on the server. Treat a leaked invite as live until you
rotate it; [step 8](#8-harden) closes that properly.

### What is trusted, and how

In descending order of strength:

1. **Key-bound invite (default), or `--peer-key`.** The invite pins the inviter;
   `--peer-key` pins a partner explicitly and is the strongest option for
   unattended nodes — no human, no prompt. `--peer-key` is checked on **every**
   connect, including reconnects that use a stored session. If it names a
   different key than the stored one, the buddy stops before registering: that is
   a re-pin or a revocation, and it needs `peers remove <old key>` plus a new
   invite. Removing `--peer-key` is **not** a revocation — the stored pin governs.
2. **Trust-on-first-use + SAS.** With nothing pinned, both sides show the
   six-character code and a human compares it out of band. Then the key is
   remembered in `--known-peers`, and a later silent key change is refused.
   `--no-interactive` never learns an unknown key blindly — it fails instead.
3. **`--lab`** disables the check entirely. It exists for automated tests. Never
   use it on a real network.

After the first pairing both ends derive a **session secret** from the encrypted
channel and store it beside the partner key. It is never transmitted — both sides
compute the same value, and a man in the middle derives a different one. Every
later reconnect uses it, so the invite never has to be kept around.

---

## 7. Verify and maintain

```bash
# on a buddy — exit 0 = reachable:
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \
     --peer-key BUDDY_KEY --status

# or watch the coordinator:
journalctl --namespace=buddynet -u buddynet-handshake | grep PAIRED
```

A healthy direct tunnel shows `via="direct P2P"` on the buddy — no traffic crosses
your VPS at all. The relay only carries data when a direct punch fails. If no path
comes up, see [OPERATIONS.md — when no path comes up](OPERATIONS.md#when-no-path-comes-up).

**Keep it updated.** BuddyNet is security software; track releases. Fetch and
verify the new binary (step 2), then:

```bash
sudo install -m0755 buddynet-linux-amd64 /usr/local/bin/buddynet
sudo systemctl restart buddynet-handshake buddynet-relay
```

The identity key is stable across upgrades, so buddies keep their pins. **Back up
`/var/lib/buddynet-handshake/id.key`** — losing it changes the server's identity
and forces every buddy to re-pin.

**Watch for trouble.** Any `SECURITY:` line, an `ALERT:` segment, or a sustained
spike in `rate-limited`/`dropped` is an attack being absorbed:

```bash
journalctl --namespace=buddynet | grep -E 'SECURITY:|ALERT:'
```

See [OPERATIONS.md — Log schema](OPERATIONS.md#log-schema) for the reference, and
[OPERATIONS.md — Running a port that is open to the internet](OPERATIONS.md#running-a-port-that-is-open-to-the-internet)
for what constant scanning looks like — and why an empty log is not proof that
nobody knocked. Logs are kept for one week by the shipped journald drop-in (50 MB
cap); export sooner if you need a longer window.

---

## 8. Harden

The defaults — QUIC control plane, key pinning, default-drop firewall — are secure
on their own. The first item below is nevertheless **the recommended setting for a
server you run privately**. The second is situational.

### Approval mode — recommended for a private server

**Turn this on unless you deliberately want a server strangers may use.** Without
it the server is in *open mode*: it pairs any two buddies presenting the same
valid token, and keeps **no list of spent tokens**. A leaked invite therefore still
works — not to get into your tunnel (your buddy is pinned by key, so a substituted
partner fails on your side), but to let **two strangers pair with each other** on
your matchmaker and draw tickets for your relay. That is your bandwidth and your
box, used by people you never approved.

Approval mode ends that: only operator-approved keys may pair.

**Where the check happens matters.** TLS authenticates every client by its Ed25519
key — it proves the key is one the client holds — but it authorizes none. The
allowlist decision is made when the server handles the client's signed `REGISTER`.
That split is deliberate: a TLS-layer allowlist gate would make code-based
enrollment impossible, because a key that was never approved could not complete
the handshake and so could never deliver its enrollment code. An unapproved client
therefore completes TLS and is refused before any pairing state is created for it,
and unknown keys are rate-limited far more tightly than allowlisted ones. See
[SECURITY.md §5.5](../SECURITY.md#55-what-an-unauthenticated-source-can-cost-you-the-pre-tls-boundary).

```bash
sudo systemctl edit buddynet-handshake
#   [Service]
#   ExecStart=                       # reset, then re-specify with --authorized
#   ExecStart=/usr/local/bin/buddynet --role=handshake --listen ${BUDDYNET_LISTEN} \
#     --key ${STATE_DIRECTORY}/id.key \
#     --authorized ${STATE_DIRECTORY}/clients.txt
```

With `--authorized` set and the list empty, **nobody pairs** — that is the
fail-closed default, and the server says so at startup. Approve keys one of two
ways:

**A — approve by public key.** Simplest when you can read the key off the other
machine: run `buddynet identity` there, then on the server

```bash
sudo -u buddynet-handshake buddynet \
  --authorized /var/lib/buddynet-handshake/clients.txt approve <buddy-key> alice
```

**B — enrollment code.** When you can't get the key first, hand out a code
instead. The buddy starts with `--code <CODE>`; its key arrives sealed to the
server, is logged as pending, and you approve it with the same command. The code
is a bearer secret and never appears in the log in the clear — only its hash and
the key it enrolled. Two things worth knowing: a code enrolls **one** key (it is
inside the registration signature, so it cannot be grafted onto another), and an
unapproved key that presents a valid code costs the server almost nothing, because
that path has its own tight limiter.

Manage the list with `approve`, `list` and `revoke` — see `buddynet --help`. The
file is plain text, one key per line, comments with `#`, and it is re-read on
change, so approving a buddy needs no restart.

### Source allowlist (`--allow-cidr`)

If every buddy sits in a known network, refuse everything else before it occupies
a connection slot. On the **relay** this runs before any crypto. On the
**handshake server** the TLS handshake has already happened by then — quic-go owns
the packet path — so this complements the firewall rule rather than replacing it.
Run a host or cloud firewall as well; it is the only layer that caps the pre-TLS
cost of a public UDP port.

On the relay, `--allow-cidr` is also one of the two authorization policies (the
other is `--server-key`), and `0.0.0.0/0` or `::/0` are refused as a sham policy.

---

## Where to go next

- [OPERATIONS.md](OPERATIONS.md) — day-to-day: many buddies, `.buddy` names,
  diagnosing a link that won't come up, the log schema
- [SECURITY.md](../SECURITY.md) — the threat model and what the boundary does and
  does not cover
- [WIREGUARD.md](WIREGUARD.md) — the opt-in kernel-WireGuard data plane
- [PROTOCOL.md](PROTOCOL.md) — the wire format, if you're working on BuddyNet
- `buddynet --help` — every flag, always current

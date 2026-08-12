# Run your own VPS coordinator — a step-by-step HowTo

BuddyNet needs one small, always-on machine with a public IP to introduce your
buddies to each other: the **coordinator** (`--role=handshake`, optionally also
`--role=relay`). It only does matchmaking — **it never sees your traffic** (that
is the whole point; see [SECURITY.md](../SECURITY.md)). This guide takes you from
a blank VPS to a working coordinator with a locked-down firewall, in order, with
copy-pasteable commands.

If you'd rather not run a server at all: when one of your two machines has a
**public IP or an open port**, that machine can be the coordinator and you need no
VPS. This guide is for the common case — both machines behind NAT/CGNAT — where a
cheap VPS is the simplest fix.

**What you need:** a VPS (any provider; the smallest tier is plenty — this is a
control plane, not a data path), a domain or just the VPS's IP, and SSH access.

---

## At a glance

| # | Step | Why |
|---|------|-----|
| 1 | [Pick & prepare the VPS](#1-pick-and-prepare-the-vps) | A tiny always-on public IP |
| 2 | [Install the binary (verified)](#2-install-the-binary-verified) | Signed release, provenance checked |
| 3 | [Set up the firewall (nftables)](#3-set-up-the-firewall-nftables) | Default-drop; only SSH + BuddyNet ports |
| 4 | [Install the systemd units](#4-install-the-systemd-units) | Hardened, sandboxed, auto-restart |
| 5 | [Start it & get the server key](#5-start-it-and-get-the-server-key) | The key your buddies pin |
| 6 | [Connect your buddies](#6-connect-your-buddies) | Mint an invite, join from each host |
| 7 | [Verify & maintain](#7-verify-and-maintain) | Confirm it works; keep it updated |
| 8 | [Optional hardening](#8-optional-hardening) | Approval mode, source allowlist |

Two ports do all the work:

| Port | Role | Flag |
|------|------|------|
| **51820/udp** | handshake (matchmaking) | `--listen [::]:51820` |
| **51821/udp** | relay (fallback forwarder) | `--relay-listen [::]:51821` |
| 22/tcp | your SSH — keep it! | — |

---

## 1. Pick and prepare the VPS

Any provider works (Hetzner, netcube, a Pi with a public IP, …). The coordinator
is light on CPU/RAM/bandwidth; the cheapest tier is fine.

```bash
ssh root@vps.example
apt update && apt -y upgrade        # or your distro's equivalent
```

Point a DNS name at it if you have one (`vps.example`), or just use the raw IP in
the buddy commands later. A **fixed** public IP is what matters.

---

## 2. Install the binary (verified)

Download the latest `buddynet-linux-amd64` (and its `.bundle`) from the
[releases page](https://github.com/TZERO78/buddynet/releases), then **verify the
signature before trusting it** — every release is keyless-signed with
cosign/Sigstore:

```bash
# needs cosign installed (https://docs.sigstore.dev/system_config/installation/)
cosign verify-blob --bundle buddynet-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github.com/TZERO78/buddynet' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  buddynet-linux-amd64

sudo install -m0755 buddynet-linux-amd64 /usr/local/bin/buddynet
buddynet --version
```

A binary signed by anything other than this repository's workflow fails the check
— don't run it (see [SECURITY.md §8.3](../SECURITY.md#83-release-integrity)).

---

## 3. Set up the firewall (nftables)

This is the one layer that protects the **kernel's UDP stack and your bandwidth**
— BuddyNet's own in-process caps bound the *process*, but only the firewall stops
a flood from reaching the socket at all. Do this **before** you expose the
service.

> ⚠️ **Read this first:** the ruleset sets the input policy to **drop** and
> explicitly re-allows **SSH on port 22**. If your SSH runs on a different port,
> change `port_ssh` below *before* applying, or you will lock yourself out. Keep
> your current SSH session open until you've confirmed a second one works.

BuddyNet ships a ready ruleset — [`deployments/nftables.conf`](../deployments/nftables.conf).
It is default-drop and opens only SSH and the two BuddyNet UDP ports,
rate-limited against floods:

```nft
#!/usr/sbin/nft -f
define port_handshake = 51820      # keep in sync with --listen
define port_relay     = 51821      # keep in sync with --relay-listen
define port_ssh       = 22         # change if your SSH is elsewhere

table inet buddynet {
    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept                      # loopback
        ct state established,related accept # answers to your own connections
        ct state invalid drop

        ip protocol icmp accept            # PMTU discovery + ping
        ip6 nexthdr icmpv6 accept

        tcp dport $port_ssh accept         # management — don't lock yourself out

        # control + relay, rate-limited so a flood can't saturate the read loop
        udp dport $port_handshake limit rate 100/second burst 50 packets accept
        udp dport $port_relay     limit rate 100/second burst 50 packets accept
    }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output  { type filter hook output  priority filter; policy accept; }
}
```

Apply and persist it:

```bash
# copy the shipped file (edit the port_* defines first if needed)
sudo install -m0644 deployments/nftables.conf /etc/nftables.d/buddynet.conf
sudo nft -f /etc/nftables.d/buddynet.conf

# make it survive reboot: include it from /etc/nftables.conf, then enable nftables
echo 'include "/etc/nftables.d/*.conf"' | sudo tee -a /etc/nftables.conf
sudo systemctl enable --now nftables

# confirm
sudo nft list table inet buddynet
```

### Still on iptables? (the equivalent)

nftables is the modern default, but plenty of hosts still run iptables — so
BuddyNet ships the **exact same policy** as an iptables ruleset,
[`deployments/iptables.rules`](../deployments/iptables.rules) (default-drop
input; only SSH + the two rate-limited UDP ports):

```bash
# same SSH-lockout warning applies — check the --dport 22 line first
sudo iptables-restore < deployments/iptables.rules

# persist across reboot (Debian/Ubuntu):
sudo apt install iptables-persistent    # or: netfilter-persistent save
sudo netfilter-persistent save

# IPv6: the same file works with ip6tables-restore — change the
#   -A INPUT -p icmp -j ACCEPT
# line to `-p icmpv6` first, then:
sudo ip6tables-restore < deployments/iptables.rules   # (with the icmpv6 edit)
```

Pick **one** firewall system, not both — nftables *or* iptables, never two
default-drop rulesets fighting over the input hook. Everything in
*Recommendations & notes* below applies to either.

**Recommendations & notes**

- **`table inet`** covers IPv4 and IPv6 in one table — no separate ipv6 ruleset
  needed. If you run **handshake only** (no relay), delete the `port_relay` line
  and don't open 51821.
- **Keep the ports in sync** with your `--listen` / `--relay-listen`. If you move
  the handshake to `:7000`, change `port_handshake` too.
- **Rate-limit, don't source-restrict, by default.** Your buddies usually sit
  behind dynamic/CGNAT addresses, so you can't pin their source IP. The
  `limit rate` clause blunts floods without needing to know who connects.
- **If your buddies *do* have static IPs**, you can tighten further as
  defence-in-depth — either add `ip saddr { A, B }` before the `accept` in the nft
  rule, **or** (cleaner) use BuddyNet's own `--allow-cidr` (step 8), which drops
  out-of-range sources before any crypto.
- **Already running ufw / firewalld?** They own the `filter`/`inet` space with
  their own default policy. Rather than stack a second default-drop table (order
  and policy can fight), add the two UDP ports and SSH to *that* tool instead —
  the goal is the same: default-deny with only these ports open. (This is the host
  firewall; it is unrelated to the private `inet buddynet` table BuddyNet programs
  for `--wireguard --expose` on a *buddy* — that never runs on the coordinator.)
- **Don't forget your provider's cloud firewall.** Many VPS providers have a
  separate security-group/cloud firewall in their panel — open 51820/udp (and
  51821/udp if relaying) there too, or traffic never reaches the box.

> **Verify it locally first.** [`lab/test-vps-howto.sh`](../lab/test-vps-howto.sh)
> loads this exact ruleset in a throwaway network namespace and proves it
> functionally — the two BuddyNet ports and SSH pass, everything else is dropped —
> then runs a real coordinator + invite/join pairing. Run it before you trust the
> rules on a box you SSH into.

---

## 4. Install the systemd units

BuddyNet ships hardened, sandboxed units (DynamicUser, `ProtectSystem=strict`,
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
(created `0700`). **Turn on the encrypted control plane** — set QUIC on the server
(and later on every buddy; the transport must match on both ends):

```bash
sudo systemctl edit buddynet-handshake
# add:
#   [Service]
#   Environment=
```

Without this, a `REGISTER` (including the pairing token) travels in **cleartext**
and the server logs a `WARNING`. Keep QUIC on — it's the secure default.

---

## 5. Start it and get the server key

```bash
sudo systemctl enable --now buddynet-handshake
sudo systemctl enable --now buddynet-relay        # optional but recommended fallback

# the server key your buddies must pin (--server-key).
# `identity` just reads the key and prints the pubkey, then exits:
sudo buddynet --role=handshake --key /var/lib/buddynet-handshake/id.key identity
```

That last command prints the **server public key**. Save it — every buddy pins it
with `--server-key` so a hostile or swapped server can't impersonate yours.

Check it's listening:

```bash
journalctl --namespace=buddynet -u buddynet-handshake -f
# look for: HANDSHAKE: action=listening addr=[::]:51820 ...
```

> **Running both roles in one process instead?** You can skip the separate relay
> unit and run `--role=handshake,relay` with `--relay-endpoint vps.example:51821`
> so buddies learn the relay address automatically. See
> [OPERATIONS.md — Combined handshake + relay](OPERATIONS.md#combined-handshake--relay-typical-vps-setup).

---

## 6. Connect your buddies

On the coordinator you don't create tunnels — your two machines do, using the
server address + the key from step 5. The friendly flow uses a **one-time
invite** (valid 15 min or until first pairing):

```bash
# On machine A — mint an invite (prints a TOKEN):
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \ --invite

# On machine B — join with that token:
buddynet --role=buddy --server vps.example:51820 --server-key SERVER_KEY \ --join=TOKEN
```

On first contact each side shows a 6-character **safety code** — read yours to
your buddy over the phone/Signal and type theirs in; this catches a
man-in-the-middle (even a hostile server) at first contact. For unattended
daemons, pin directly with `--peer-key` instead. Full walkthrough:
[TWO-BUDDIES.md](TWO-BUDDIES.md) and [INVITE.md](INVITE.md).

---

## 7. Verify and maintain

**Confirm a tunnel formed** (and whether it went direct or via your relay):

```bash
# on a buddy:
buddynet --role=buddy --server … --server-key … --join=TOKEN --status
# exit 0 = reachable. Or watch the coordinator:
journalctl --namespace=buddynet -u buddynet-handshake | grep PAIRED
```

A healthy direct tunnel shows `via="direct P2P"` on the buddy — no traffic
crosses your VPS at all. The relay only carries data when a direct punch fails.

**Keep it updated.** BuddyNet is security software; track releases:

```bash
# fetch + verify the new binary (step 2), then:
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

See [OPERATIONS.md — Log schema](OPERATIONS.md#log-schema) for the full reference.

---

## 8. Optional hardening

Neither is required — the defaults (QUIC control plane, key pinning, default-drop
firewall) are already secure. Add these if you want a smaller surface.

**Approval mode — "known buddies only."** Only operator-approved keys may pair;
outsiders are rejected at the TLS handshake, before they reach any logic:

```bash
sudo systemctl edit buddynet-handshake
#   [Service]
#   Environment=
#   ExecStart=                       # reset, then re-specify with --authorized
#   ExecStart=/usr/local/bin/buddynet --role=handshake --listen ${BUDDYNET_LISTEN} \
#     --key ${STATE_DIRECTORY}/id.key \
#     --authorized ${STATE_DIRECTORY}/clients.txt

# approve a buddy (get its key with `buddynet identity` on that host):
sudo -u buddynet-handshake buddynet \
  --authorized /var/lib/buddynet-handshake/clients.txt approve <buddy-key>
```

See [APPROVAL.md](APPROVAL.md).

**Source allowlist (`--allow-cidr`).** If every buddy has a known/static network,
drop everything else before any crypto — a cheap pre-filter that complements the
firewall:

```bash
#   ExecStart=/usr/local/bin/buddynet --role=handshake,relay \
#     --allow-cidr 203.0.113.0/24,198.51.100.0/24 \
#     --key /var/lib/buddynet-handshake/id.key
```

It applies to both the handshake and relay roles on the same node. See
[OPERATIONS.md — IP allowlists](OPERATIONS.md#ip-allowlists---allow-cidr).

**Harden the whole host, not just BuddyNet.** Everything above secures *this
service* — but a VPS with a public IP wants the usual baseline too: SSH keys only
(no password login), automatic security updates, `fail2ban`, a locked-down user,
and sane sysctl. For a self-sovereign, reproducible take on all of that, see
Markus's **[server-baukasten](https://github.com/TZERO78/server-baukasten)** — the
host-hardening toolkit this project is designed to sit on top of.

---

## Where to go next

- [TWO-BUDDIES.md](TWO-BUDDIES.md) — the end-to-end two-machine walkthrough.
- [OPERATIONS.md](OPERATIONS.md) — the full operator reference (all flags, log
  schema, `--status`).
- [SECURITY.md](../SECURITY.md) — the threat model: what the coordinator can and
  cannot see.
- [WIREGUARD.md](WIREGUARD.md) / [BUDDYSHARE.md](BUDDYSHARE.md) — the opt-in
  kernel-WireGuard data plane and scoped SMB sharing (these run on the *buddies*,
  not the coordinator).
- [server-baukasten](https://github.com/TZERO78/server-baukasten) — full host
  hardening for the VPS this coordinator runs on (SSH, updates, fail2ban, users).

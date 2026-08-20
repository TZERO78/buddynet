# BuddyNet — Unraid plugin

Runs the **buddy** role of BuddyNet as an Unraid-managed service: a zero-config,
end-to-end-encrypted tunnel to your buddy. It finds your partner via a small
handshake server, hole-punches through NAT (no port forwarding), and falls back
to a blind relay only when a direct path is impossible. Point `rsync`, `borg`, or
`kopia` at the local socket and back up directly between two sites.

## Install

Plugins → *Install Plugin* → paste the raw `.plg` URL:

```
https://raw.githubusercontent.com/TZERO78/buddynet/main/unraid/BuddyNet/buddynet.plg
```

Then configure under **Tools → BuddyNet**.

The install pins **buddynet v2.0.0** and verifies the downloaded
`buddynet-linux-amd64` against its published SHA256 — a corrupted or tampered
download is refused.

> **Upgrading from a v1.x plugin:** v2.0.0 widens the virtual IP to a `/16`
> (`10.66.X.Y`), so every node's virtual IP changes. After updating, your buddy
> must **re-pin** your Buddy key (the identity itself is unchanged; only the
> derived virtual IP moves).

## What it does

- **Settings page** (Tools → BuddyNet) + a service that runs on array start and
  stops on array stop.
- **Bidirectional over one tunnel:** `-L` pushes backups *to* your buddy,
  `-forward` lets your buddy reach a local service (e.g. an rsync daemon on
  `:873`). Set at least one.
- **BuddyDNS:** give this node a `--name` (so your buddy reaches it as
  `<name>.buddy`) and/or enable the `--dns` resolver, which answers `*.buddy`
  queries on `127.0.0.153:53`. To use the names on the Unraid host, route the
  `.buddy` TLD to that resolver (see
  [BUDDYDNS.md](../../docs/BUDDYDNS.md)).
- **Lazy tunnel:** with `--lazy` the `-L` listener binds immediately but the
  encrypted tunnel is only dialled on the first incoming connection (needs `-L`).
- **Live status** and a **Dashboard tile** with a buddy online/offline
  traffic-light, plus per-direction transfer/throughput.
- **Secrets off the FAT flash:** the token file, identity key, trust store and
  peer cache live on `/mnt/user/appdata/buddynet/` (real `0600`). A token typed
  into the page is only a testing fallback — prefer the token file.
- **Danger zone:** *Forget buddy* (clear `known_peers`) and *Reset identity*
  (delete `id.key` — note this changes your virtual IP, so your buddy must
  re-pin your new key).

## First contact — four steps, no terminal on either side

Either side can start. Whoever does is "you" below:

1. **You:** on the settings page, click **create invite** and apply. Send the
   whole `bnet1.…` string to your buddy over a channel you both trust (a call,
   Signal). Your own *Invite* field keeps the bare token — that is correct.
2. **Your buddy:** pastes that string into their *Invite* field and applies. The
   invite carries your identity, so their side pins **you** automatically. They
   type nothing into their *Buddy key* field.
3. **Your buddy:** copies their own identity (shown at the top of their BuddyNet
   page) and sends it back to you.
4. **You:** paste it into *Buddy key* and apply. Both sides are pinned, the
   tunnel comes up.

Between steps 1 and 4 your log says the Buddy key is missing and the connection
is refused — that is the expected in-between state, not a fault.

Never paste your own invite into your own *Invite* field: it carries *your*
identity, so the node would pin itself as the partner and refuse everything with
`partner identity MISMATCH`.

Nobody has to be online at the same time, and nobody types a code. The trust
comes from the channel you sent the invite and the identity over — the same
place a spoken safety code would have come from.

## Security

Unraid runs the buddy **headless**, so there is no terminal to compare the
first-contact safety check (SAS). Your buddy's identity therefore has to be
pinned before the connection comes up — from one of two sources:

- a **`bnet1.…` invite** carries your buddy's identity, and BuddyNet pins it from
  there. Nothing to fill into the **Buddy key** field.
- a **bare token** (the older format) carries no identity, so there you **must**
  set the **Buddy key** field yourself (each node logs its own identity at
  startup).

The service runs `--no-interactive` either way, so an unknown key is refused
rather than trusted blind — a bare token with no Buddy key set will not connect.
The invite is a bearer secret — keep it in the `0600` invite file, not the flash
config. See the project [README](../../README.md) and
[SECURITY.md](../../SECURITY.md).

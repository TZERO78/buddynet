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

## Security

Unraid runs the buddy **headless**, so there is no terminal to compare the
first-contact safety check (SAS). You must therefore **pin your buddy** with the
**Buddy key** field (each node logs its own identity at startup); the service
runs `--no-interactive`, so an unknown key is refused rather than trusted blind.
The token is a bearer secret — keep it in the `0600` token file, not the flash
config. See the project [README](../../README.md) and
[SECURITY.md](../../SECURITY.md).

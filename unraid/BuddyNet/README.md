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

The install verifies the downloaded `buddynet` binary against a pinned SHA256.

> **Not yet installable from a release.** The `.plg` install block still has
> placeholder `BINVER` / `BINURL` / `BINSHA` values. After the first
> `buddynet` GitHub release (tag `vX.Y.Z`, which builds `buddynet-linux-amd64`),
> set those three to the real version, asset URL, and `sha256sum` of the asset.
> Until then the checksum gate will correctly refuse to install.

## What it does

- **Settings page** (Tools → BuddyNet) + a service that runs on array start and
  stops on array stop.
- **Bidirectional over one tunnel:** `-L` pushes backups *to* your buddy,
  `-forward` lets your buddy reach a local service (e.g. an rsync daemon on
  `:873`). Set at least one.
- **Live status** and a **Dashboard tile** with a buddy online/offline
  traffic-light, plus per-direction transfer/throughput.
- **Secrets off the FAT flash:** the token file, identity key, trust store and
  peer cache live on `/mnt/user/appdata/buddynet/` (real `0600`). A token typed
  into the page is only a testing fallback — prefer the token file.
- **Danger zone:** *Forget buddy* (clear `known_peers`) and *Reset identity*
  (delete `id.key` — note this changes your virtual IP, so your buddy must
  re-pin your new key).

## Security

Pin your buddy with the **Buddy key** field (each node logs its own identity at
startup). Without a pin, trust-on-first-use records the buddy key on first
connect and refuses later changes. The token is a bearer secret — keep it in the
`0600` token file, not the flash config. See the project
[README](../../README.md) and [docs/PROTOCOL.md](../../docs/PROTOCOL.md).

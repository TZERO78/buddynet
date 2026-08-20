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

The install pins one buddynet release — currently **v5.2.0** — and verifies the
downloaded `buddynet-linux-amd64` against its published SHA256, so a corrupted or
tampered download is refused. The pinned version and its checksum are in
`buddynet.plg` (`BINVER` / `BINSHA`) and move together on each release.

## What it does

- **Settings page** (Tools → BuddyNet) + a service that runs on array start and
  stops on array stop.
- **Both directions over one tunnel:** `-L` exposes a local port that reaches a
  service on your buddy's side, `-forward` lets your buddy reach a service here
  (an rsync daemon on `:873`, for example). Set at least one — a tunnel with
  neither carries nothing.
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
- **Optional WireGuard data plane** with **scoped exposure**: with WireGuard
  enabled your buddy reaches only the port(s) you list under *Exposed ports* —
  with the field empty, nothing at all (fail-closed). This is a transport scope,
  not a file-sharing feature: whatever service you expose is ordinary software
  you install and secure yourself.
- **Danger zone:**
  - *Forget buddy* **revokes** the buddy: its key goes on this node's revocation
    list and the stored session is deleted, so it cannot reconnect — not with the
    invite still saved in the plugin config, and not after a restart. The service
    is left stopped, because this node then has no buddy.
  - *Allow buddy again* lifts that revocation and starts the service. It refuses
    unless a buddy key **and** an invite are configured, so the revocation is
    never lifted before there is something new to pin.
  - *Reset identity* deletes `id.key`. That changes this node's identity **and**
    its virtual IP, so your buddy has to re-pin the new key.

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

Unraid runs the buddy **headless**: there is no terminal on which a human could
compare the first-contact safety check (the six-character SAS code). The service
therefore always runs with `--no-interactive`, and that has one consequence worth
stating plainly:

> **An unknown buddy key is refused, never learned.** There is no
> trust-on-first-use here. If the key is not pinned, the connection does not come
> up.

So your buddy's identity has to be pinned before the tunnel can come up, and it
comes from one of two sources:

- a **`bnet1.…` invite** carries your buddy's identity and BuddyNet pins it from
  there. Nothing has to go into the **Buddy key** field.
- a **bare token** (the older format) carries no identity. There you **must**
  fill in the **Buddy key** field yourself — every node prints its own identity
  at startup — or the connection is refused.

Since v5.2.0 a pinned key that contradicts the key stored from an earlier pairing
also stops the connection. That is a re-pin or a revocation, and it needs
*Forget buddy* plus a new invite.

The invite is a bearer secret — keep it in the `0600` invite file on the array,
not in the flash config. See the project [README](../../README.md) and
[SECURITY.md](../../SECURITY.md).

# BuddyShare — share folders with your buddy (SMB, scoped)

> **Status:** shipped — binary **v3.0.0** (the scoped WireGuard door) + Unraid
> plugin **2026.07.04.1** (the BuddyShare section). The pattern is validated
> end to end by the project's **own lab test** (`lab/test-buddyshare.sh`, real
> smbd, real kernel WireGuard, two consecutive 8/8 runs) — that is our own
> structural testing, not an independent audit.

BuddyShare is why BuddyNet exists: **two people who back up to each other.**
Alice shares folders with Bob, Bob shares folders with Alice — each stays in
full control of what the other can see, and revoking is one click on your own
box.

It is deliberately **not a new file service**. BuddyShare combines two things
that already exist and are each good at their job:

| Layer | Who provides it | What it scopes |
|---|---|---|
| Tunnel scope (`--expose 445`) | BuddyNet | Your buddy reaches **only Samba** on your host — no SSH, no WebGUI, no Docker, nothing else. Fail-closed. |
| Folder rights (share user) | Unraid (stock SMB) | Inside Samba, your buddy sees **only the shares you grant** to their user — read-only or read-write, per share. |

Two independent layers of least privilege. The security boundary is the
**pinned, end-to-end-encrypted tunnel** — the SMB password only selects which
Unraid user your buddy is; it is not what keeps strangers out (strangers never
reach port 445 in the first place).

## Separation of duties

The plugin stays on its own turf:

- **The plugin configures only the tunnel**: enabling BuddyShare visibly fills
  in *WireGuard data plane = Enabled* and adds `445` to *Exposed ports* — you
  see exactly what will apply before you hit Apply.
- **Users, shares and permissions are yours, in Unraid's own UI.** The plugin
  never creates or changes users. It only *reads* system state to help you: it
  shows whether the share user you named exists, and warns about Public shares.

## Setup (Unraid ↔ Unraid)

On the **sharing** side (say Alice) — prerequisites: BuddyNet plugin installed,
tunnel to Bob pinned and working (see [TWO-BUDDIES.md](TWO-BUDDIES.md)), SMB
enabled in *Settings → SMB* (Unraid's default).

1. **Create a user for Bob** under **Users → Add User** (e.g. `bob`, strong
   password). Unraid share users can only use SMB/NFS/FTP — no WebGUI, no SSH.
2. **Grant rights** under **Shares**: set each share you want Bob to reach to
   *Secure* or *Private* and give `bob` Read-only or Read/Write. Shares he
   should not see: *No Access* (Private) — or leave them untouched if they are
   already Private.
3. In **Tools → BuddyNet**, set *BuddyShare = Enabled* (this fills in
   WireGuard + port 445 above — check the fields, then **Apply**) and enter
   `bob` as the share user. The page confirms the user exists and shows the
   exact server/user line Bob needs.
4. **Send Bob the SMB password** over a channel you trust (you already
   exchanged keys and a token for the tunnel — same idea).

Heed the **Public-share warning** on the page: shares set to *Public* are open
to **any** SMB client, so Bob can open them too once the tunnel is up — that is
what Public means. Unraid's default for a new share is Public; set anything
sensitive to Secure or Private.

On the **consuming** side (Bob), with the tunnel up:

- **Unraid:** install *Unassigned Devices* (Community Apps) → *Add Remote SMB
  Share* → enter Alice's virtual IP (shown on Alice's BuddyNet page, e.g.
  `10.66.23.42`), user `bob` + password, pick the share, mount.
- **Linux:** `mount -t cifs //10.66.23.42/<share> /mnt/alice -o user=bob,vers=3.0,soft`
- Prefer a **soft mount** (Unassigned Devices does this by default). With a
  hard mount, a dropped tunnel can leave processes — and on Unraid even the
  WebGUI — hanging on dead I/O until the tunnel returns; soft mounts return
  errors instead. BuddyNet reconnects automatically, but a mount that was
  mid-write when the line dropped is the backup tool's retry to handle, not
  something we can promise away.

Both directions are symmetric: repeat the same steps with the roles swapped and
each side mounts the other's share over the **same single tunnel**.

## Backing up to each other

A mounted share is just a path — point any tool at it:

- **rsync** (script or *User Scripts* plugin): `rsync -a /mnt/user/photos/ /mnt/remotes/ALICE_backup/photos/`
- **LuckyBackup / rclone / restic / kopia** containers: use the mount as the
  destination (for restic/kopia, as the repository path).
- The **QUIC door** (`-L` / `-forward`, see [TWO-BUDDIES.md](TWO-BUDDIES.md))
  remains the alternative for daemon-to-daemon backups (e.g. an rsync daemon on
  `:873`) — BuddyShare does not replace it; SMB is for *browsable folders*.

## Revoking access

Two independent layers, each sufficient on its own, both on **your** box:

| You want | Where | Effect |
|---|---|---|
| Bob loses one share | *Shares → SMB Security* → No Access | Immediate for new opens; his user stays |
| Bob loses all SMB | *Users* → disable/delete the user (or change the password) | Auth refused, tunnel still up |
| Bob loses the door | *Tools → BuddyNet*: BuddyShare = Disabled / remove `445` → Apply | Port 445 gone from the tunnel (SIGHUP live re-scope, no restart) |
| Bob is gone entirely | *Danger zone → Forget buddy* (and remove his pin/token) | No tunnel at all |

One honest caveat: removing the exposure blocks **new** connections instantly,
but an SMB session that is **already open** rides on an established connection,
which the scope deliberately keeps (return-traffic rule). To cut a live session
immediately, disable the user (Samba re-checks auth) or restart the tunnel/
array; otherwise it ends when the client disconnects.

## Windows PC on your LAN (optional)

The tunnel ends on your **server**, not on your PC — your Windows machine has
no route to Bob's virtual IP. The supported way to browse Bob's share from a
LAN PC is a **re-export**: mount Bob's share on your Unraid via Unassigned
Devices, then share that mountpoint like any other share (UD offers an SMB
share toggle per remote mount). Your PC sees `\\tower\bob-share`, behind your
own Unraid permissions; on Bob's side nothing changes — the access still
arrives as your server, scoped to :445.

BuddyNet deliberately does **not** NAT your LAN into the tunnel: that would
make every device on your network a client of Bob's port 445, which is the
opposite of scoped.

## Why SMB (and not WebDAV or NFS)?

- **SMB**: Unraid ships it first-class (per-user, per-share rights in the stock
  UI), every OS mounts it natively, and it needs exactly one port (445) — a
  perfect fit for a scoped door. Nothing new to install, nothing new we could
  get wrong.
- **WebDAV** would mean bundling and maintaining a file server inside BuddyNet
  (a third app dependency) for a worse client experience. Not worth it while
  Samba is already there.
- **NFS** is the leaner protocol between two Linux boxes, but on Unraid
  specifically it has a long-standing failure mode for exactly our use case:
  user shares are FUSE (`shfs`), and when the **mover** relocates a file
  between cache and array its file ID changes — long-lived NFS mounts then hit
  *stale file handle* errors (see the Unraid forums, recurring across
  versions). A nightly backup onto a permanent mount is the worst case for
  that, so BuddyShare does not offer NFS. SMB is path-based and unaffected.

## Requirements & edge cases

- Both sides on **v3.0.0+**, tunnel on the WireGuard data plane (Linux/Unraid;
  `--wireguard` on both buddies). The plugin sets this for you.
- Windows SMB clients can only speak to port 445, which is why BuddyShare is a
  WireGuard-plane feature (real VIP, real :445) — there is no QUIC-door variant.
- Unraid's Samba answers on interfaces that appear after it starts (verified in
  the lab — `bnet0` comes up with the tunnel, smbd serves it without a
  restart). If you have manually set `bind interfaces only = yes` in your SMB
  extra configuration, Samba will **not** pick up `bnetN` — remove that line or
  add the interface.
- Non-Unraid Linux works the same way without the plugin:
  `--wireguard --expose 445` plus your own Samba with a dedicated share user.

## Security notes

See [SECURITY.md](../SECURITY.md) (BuddyShare paragraph) for the posture in
threat-model terms: what the buddy's reachable surface is, why the SMB password
is not the boundary, and what Public shares change.

Thanks, as ever, to the OSS that carries this: Samba, the kernel's WireGuard
and nftables, and the Unassigned Devices plugin.

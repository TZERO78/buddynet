# BuddyNet Lab — Live Test Environment

A self-contained Docker environment to run BuddyNet end-to-end on a single machine.
No VPS required: the containers simulate a full deployment — server, Peer A, and Peer B.

```
┌──────────────────────────────────────────────────────────┐
│                     Docker Lab Network                   │
│                                                          │
│  ┌──────────┐      REGISTER/PEER_LIST       ┌─────────┐ │
│  │ buddy-a  │◄─────────────────────────────►│ server  │ │
│  │ httpd    │     (signed, server-pinned)   │ HS+RLY  │ │
│  │ :7777    │                               └─────────┘ │
│  └────┬─────┘                                            │
│       │  QUIC tunnel (encrypted, hole-punched or relayed) │
│  ┌────▼─────┐                                            │
│  │ buddy-b  │◄─── curl http://localhost:7070             │
│  │ :7070    │     (forwarded through tunnel)             │
│  └──────────┘                                            │
└──────────────────────────────────────────────────────────┘
```

## Container roles

| Container  | Role             | What it does |
|------------|------------------|--------------|
| `server`   | `handshake,relay`| Matchmaking + blind relay fallback. Equivalent to a VPS deployment. |
| `buddy-a`  | `buddy`          | Runs a busybox httpd on `:7777`; forwards incoming tunnel streams to it. |
| `buddy-b`  | `buddy`          | Listens on `:7070` (host-mapped); forwards connections through the tunnel to buddy-a. |

## Prerequisites

- Docker with Compose v2 (`docker compose version`)
- Ports `51820/udp`, `51821/udp`, `7070/tcp` free on the host
- For the application-tunnel tests: `rsync` installed on the host; `sudo` with `ebtables` for the relay-fallback test

## Quickstart

```bash
cd lab
./setup.sh
```

`setup.sh`:
1. Builds the `buddynet-lab-server` and `buddynet-lab-buddy` images.
2. Bootstraps the server's Ed25519 identity key in a persistent Docker volume.
3. Writes the server's public key into `lab/.env` as `BUDDYNET_SERVER_KEY`.
4. Starts all containers with `docker compose up -d`.

## Testing the basic tunnel

```bash
# From the host — response comes through the BuddyNet tunnel end-to-end:
curl http://localhost:7070
# Expected: BuddyNet Lab - Peer A

# Or from inside buddy-b:
docker compose exec buddy-b curl http://localhost:7070
```

## Application-tunnel tests (rsync + kopia)

The overlay compose file `docker-compose.apps.yml` adds two additional peer pairs:

| Pair | Token | What it tests |
|------|-------|---------------|
| `rsync-a` / `rsync-b` | `lab-rsync-token` | rsync daemon over BuddyNet (`--forward` + `-L`) |
| `kopia-a` / `kopia-b` | `lab-kopia-token` | kopia SFTP repository backup over BuddyNet |

```
rsync-a  --forward 127.0.0.1:873  ──BuddyNet──►  rsync-b  -L 0.0.0.0:8873
                                                    │
                                               host port 8873
                                        rsync://localhost:8873/share/

kopia-a  -L 127.0.0.1:2222        ──BuddyNet──►  kopia-b  --forward 127.0.0.1:22
                                                    │
                                               sshd (SFTP, user=kopia pass=labpass)
                                        kopia SFTP backend → /data/repo
```

### Start the apps stack

```bash
cd lab
docker compose -f docker-compose.yml -f docker-compose.apps.yml build
docker compose -f docker-compose.yml -f docker-compose.apps.yml up -d
```

### Run the integration tests

```bash
./test-apps.sh
```

`test-apps.sh` runs in sequence:

1. **rsync** — lists the share, downloads 20 files, uploads a file back.
2. **kopia SFTP** — initialises a kopia repository on kopia-b via SFTP through the tunnel, creates a snapshot of `/data/source`.
3. **Relay fallback** — blocks direct P2P UDP between kopia-a and kopia-b with `ebtables`, waits for BuddyNet to reconnect via the relay (`handshake server as relay`), then creates a second snapshot to confirm data transfer still works over the relay path.

Expected output (abbreviated):

```
  [PASS] rsync listing works
  [PASS] rsync download: 20 files transferred
  [PASS] rsync upload works
  [PASS] SSH SFTP tunnel kopia-a → kopia-b (password auth)
  [PASS] kopia SFTP repository ready on kopia-b
  [PASS] kopia snapshot 1 (source, direct P2P)
  [PASS] relay fallback: tunnel switched away from direct P2P
  [PASS] kopia snapshot 2 (source, via relay)
  [PASS] kopia snapshot list: 2 snapshot(s) on kopia-b

  PASSED: 9   FAILED: 0
All tests passed.
```

### kopia-b SFTP credentials (lab only)

| Setting | Value |
|---------|-------|
| Host (from kopia-a) | `127.0.0.1:2222` (via BuddyNet tunnel) |
| Username | `kopia` |
| Password | `labpass` |
| Repo path | `/data/repo` |
| SSH host key | persisted in `kopia-b-key` volume; published to `/data/kopia-b-hostkey.pub` on startup |

## VIP-routing test (Phase 1.3: Loopback-VIP-Bind)

The overlay `docker-compose.vip.yml` validates `--vip-listen`: a buddy binds its
connected partner's virtual IP (`10.66.X.Y`) on its own loopback interface (via a
raw netlink `RTM_NEWADDR`, no `ip`/root subprocess) and routes connections to it
through the tunnel. Unlike `-L` (one fixed local port → one peer), this is the
per-buddy routing path that scales to many buddies.

```
vip-a  --forward 127.0.0.1:7777   ──BuddyNet──►  vip-b  --vip-listen 7777
(alice, httpd :7777)                              (bob binds alice's VIP on lo)

inside vip-b:  curl http://alice.buddy:7777  →  alice's httpd, via the tunnel
```

`vip-b` runs with `cap_add: [NET_ADMIN]` for the loopback address bind (without
it the feature degrades gracefully — a `WARNING` and no VIP route, tunnel still up).

```bash
cd lab
docker compose -f docker-compose.yml -f docker-compose.vip.yml up -d --build
./test-vip.sh
```

`test-vip.sh` checks, in sequence:

1. Both tunnels come up (`CONNECTED`).
2. `vip-b` bound alice's VIP on `lo` and is listening on it (also confirmed via `ip addr`).
3. `curl http://<alice-vip>:7777` inside `vip-b` reaches alice's httpd through the tunnel.
4. `curl http://alice.buddy:7777` works (name → VIP via the stub resolver → tunnel).
5. **No over-binding**: a VIP that is not a connected buddy is unbound and unreachable.

```
  [PASS] vip-b bound 10.66.X.Y on lo and is listening on :7777
  [PASS] ip addr confirms 10.66.X.Y/32 on vip-b's lo
  [PASS] HTTP over VIP routing (vip-b → alice:7777 via tunnel) works
  [PASS] alice.buddy resolves to 10.66.X.Y on vip-b's stub
  [PASS] HTTP via name alice.buddy:7777 works end to end
  [PASS] unrelated VIP 10.66.200.201 is not bound/reachable (no over-binding)

  Results: 6 passed, 0 failed
```

## BuddyParty test (Phase 1.4: multi-peer, 3–5 buddies)

The overlay `docker-compose.party.yml` runs one **hub** that holds **five tunnels
at once** and routes to each buddy by name — the end-to-end proof of the
multi-peer supervisor (`--peers-file`) plus VIP routing (`--vip-listen`).

```
party-{beta,gamma,delta,epsilon,zeta} (each httpd)  ──BuddyNet──►  party-hub
                                                              --vip-listen 8080
                                                       (--peers-file lists all 5)

inside party-hub:  curl http://beta.buddy:8080 … zeta.buddy:8080  → each buddy's httpd
```

Every node is pinned by key (Model A) and pairs via a per-pair bootstrap token.
`setup-party.sh` bootstraps an identity key for each node, then writes the
manifests (`lab/party/*.peers`, git-ignored — they hold keys + tokens):

```bash
cd lab
./setup-party.sh          # build, extract keys, write manifests, start 6 containers
./test-party.sh           # verify all 5 tunnels + isolation when one buddy fails
```

`test-party.sh` checks:

1. The hub binds all 5 buddy VIPs on `lo` (5 simultaneous tunnels).
2. `curl <name>.buddy:8080` on the hub reaches the **correct** buddy (each serves
   a page naming itself, so routing is verified per buddy).
3. **Isolation**: stopping one buddy (`zeta`) leaves the other four reachable and
   releases only its VIP — one failing worker never affects the others.

```
  [PASS] hub is listening on 5 buddy VIPs
  [PASS] beta.buddy:8080 → beta's httpd …  (×5)
  [PASS] beta/gamma/delta/epsilon still reachable after zeta went down
  [PASS] zeta unreachable after stop (its VIP released)

  Results: 11 passed, 0 failed
```

To run with fewer buddies (3–4), trim the `BUDDIES` list in `setup-party.sh` /
`test-party.sh` and remove the matching `party-<name>` services from
`docker-compose.party.yml`. Live add/remove on the hub works too — edit
`party/hub.peers` (or use `buddynet … peers add/remove`) and `kill -HUP` the hub.

## Observing the tunnels

```bash
# Follow all logs:
docker compose -f docker-compose.yml -f docker-compose.apps.yml logs -f

# Structured audit events only:
docker compose -f docker-compose.yml -f docker-compose.apps.yml logs kopia-a kopia-b \
    | grep -E "CONNECTED:|DISCONNECTED:|TRUST:|PAIRED:|SECURITY:"
```

Key log events:

| Log line | Meaning |
|----------|---------|
| `CONNECTED: … via="direct P2P"` | Hole-punched path established |
| `DISCONNECTED: reason=peer-closed-or-idle` | Tunnel dropped (P2P cut or idle timeout) |
| `CONNECTED: … via="handshake server as relay"` | Relay fallback active |
| `TRUST: action=insecure` | Buddy accepted without peer-key pin (lab only) |

## Checking the server key pin

```bash
docker compose run --rm server --key /var/lib/buddynet/id.key identity
```

Must match `BUDDYNET_SERVER_KEY` in `lab/.env`.

## Teardown

```bash
# Stop — volumes (server key, kopia repo) persist:
docker compose -f docker-compose.yml -f docker-compose.apps.yml down

# Full reset — removes all keys and data:
docker compose -f docker-compose.yml -f docker-compose.apps.yml down -v
rm -f .env
```

After `down -v` the next `./setup.sh` generates a fresh server identity.

## How this maps to a real deployment

In production you would:
- Run `server` on a VPS with a real public IP (see `deployments/docker-compose.yml`)
- Run buddies on separate machines behind NAT
- Use `--invite` / `--join` instead of a shared `--token` for one-time pairing
- Remove `--insecure` and pin `--peer-key` or use the TOFU/SAS flow

The lab uses `--insecure` and a fixed shared token to avoid interactive prompts.
Everything else — the handshake protocol, PEER_LIST signing, QUIC tunnel, relay fallback — is identical to production.

## Security model (what this lab exercises)

- **Signed `PEER_LIST`**: buddies reject any peer list not signed by the pinned server key.
- **Blind relay**: when the relay is used, the server sees only encrypted QUIC packets, never plaintext.
- **Relay fallback timing**: with `--idle-timeout=20s` (lab setting), BuddyNet detects a dead P2P path and reconnects via relay within ~5 seconds.
- **Buddy identity**: `--insecure` in the lab skips peer key verification; in production use `--peer-key`.

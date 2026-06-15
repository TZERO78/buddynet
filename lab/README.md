# BuddyNet Lab — 3-Container Live Test

A self-contained Docker environment to run BuddyNet end-to-end on a single machine.
No VPS required: the three containers simulate a full deployment — server, Peer A, and Peer B.

```
┌──────────────────────────────────────────────────────┐
│                   Docker Lab Network                 │
│                                                      │
│  ┌──────────┐      REGISTER/PEER_LIST      ┌───────┐ │
│  │ buddy-a  │◄───────────────────────────►│server │ │
│  │          │      (signed, pinned)        │       │ │
│  │ httpd    │◄───────────────────────────►│HS+RLY │ │
│  │ :7777    │                              └───────┘ │
│  └────┬─────┘                                        │
│       │  QUIC tunnel (encrypted, hole-punched)        │
│  ┌────▼─────┐                                        │
│  │ buddy-b  │                                        │
│  │          │◄── curl http://localhost:7070           │
│  │ :7070    │    (forwarded through tunnel)           │
│  └──────────┘                                        │
└──────────────────────────────────────────────────────┘
```

## Container roles

| Container | Role | What it does |
|-----------|------|--------------|
| `server`  | `handshake,relay` | Matchmaking (control plane) + blind relay fallback. Equivalent to a VPS deployment. |
| `buddy-a` | `buddy` | Runs a busybox httpd test page on `:7777`. BuddyNet forwards all incoming tunnel streams there. |
| `buddy-b` | `buddy` | Listens on `:7070` (mapped to the host). Every connection is forwarded through the QUIC tunnel to buddy-a → httpd. |

## Prerequisites

- Docker with Compose v2 (`docker compose version`)
- Ports 51820/udp, 51821/udp, 7070/tcp free on the host

## Quickstart

```bash
# From the project root:
cd lab
./setup.sh
```

`setup.sh` does exactly four things:
1. Builds `buddynet-lab-server` (distroless) and `buddynet-lab-buddy` (alpine) images.
2. Runs the server image once to bootstrap its Ed25519 identity key in a persistent Docker volume.
3. Writes the server's base64 public key into `lab/.env` as `BUDDYNET_SERVER_KEY`.
4. Starts all three containers with `docker compose up -d`.

## Testing the tunnel

Wait ~5 seconds for the tunnel to establish after startup, then:

```bash
# From the host — proxied through BuddyNet end-to-end:
curl http://localhost:7070
# Expected: BuddyNet Lab - Peer A HTML page

# Or from inside buddy-b:
docker compose exec buddy-b curl http://localhost:7070
```

A successful response means:
1. buddy-b received the HTTP request on `:7070`
2. Tunnelled it through QUIC to buddy-a (via server matchmaking + hole-punch or relay)
3. buddy-a forwarded it to its local httpd on `:7777`
4. The response traversed back the same path

## Observing the tunnel

```bash
# All logs combined:
docker compose logs -f

# Per container:
docker compose logs -f server
docker compose logs -f buddy-a
docker compose logs -f buddy-b
```

What to look for in the logs:

| Log line | Meaning |
|----------|---------|
| `registered peer … token=lab-test-token-42` | Handshake server paired the buddies |
| `hole-punch succeeded` | Direct P2P path established (ideal path) |
| `relay … session` | Relay fallback used (still encrypted; server sees only ciphertext) |
| `tunnel up` | QUIC session is live, forwarding active |

## Checking the server key pin

The server's public key is stored in `lab/.env` and pinned by both buddies via
`BUDDYNET_SERVER_KEY`. If you want to inspect it independently:

```bash
docker compose run --rm server --key /var/lib/buddynet/id.key identity
```

This must match the value in `lab/.env`.

## Teardown

```bash
# Stop containers, keep volumes (server key persists for next run):
docker compose down

# Full reset — removes all volumes and keys:
docker compose down -v
rm -f .env
```

After `down -v`, the next `./setup.sh` generates a fresh server identity.

## How it maps to a real deployment

In production you would:
- Run `server` on a VPS with a real public IP (see `deployments/docker-compose.yml`)
- Run `buddy-a` and `buddy-b` on separate machines behind NAT
- Use `--invite` / `--join` instead of the shared `--token` for one-time pairing
- Remove `--insecure` and pin `--peer-key` or use the TOFU SAS flow for buddy identity

The lab uses `--insecure` and a fixed shared token (`BUDDYNET_TOKEN=lab-test-token-42`)
to avoid interactive prompts in an automated container environment. Everything else —
the handshake protocol, PEER_LIST signing, QUIC tunnel, relay fallback — is identical
to production.

## Security model (what this lab tests)

- **Server signs every `PEER_LIST`**: buddy-a and buddy-b reject any peer list not
  signed by the pinned server key. MitM on the control plane is blocked.
- **Relay is blind**: if hole-punching fails and the relay is used, the `server`
  container only sees encrypted QUIC packets, never plaintext.
- **Buddy identity**: both buddies use `--insecure` in the lab (skips peer key check).
  In production, replace with `--peer-key` (strongest) or the TOFU/SAS flow.

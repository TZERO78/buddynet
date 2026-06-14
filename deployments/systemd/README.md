# BuddyNet systemd units (hardened)

Sandboxed units for running BuddyNet natively (no Docker). All three roles run
under `DynamicUser` with a full systemd sandbox (`ProtectSystem=strict`, dropped
capabilities, syscall and address-family allowlists, `MemoryDenyWriteExecute`,
resource ceilings). The server roles need no capabilities — their ports are
above 1024.

| File | Role |
|---|---|
| `buddynet-handshake.service` | matchmaking server (`--role=handshake`) |
| `buddynet-relay.service` | blind relay (`--role=relay`) |
| `buddynet-buddy@.service` | per-tunnel buddy, one instance per `<name>.env` |
| `buddynet-tmpfiles.conf` | enforces `0700`/`0600` on `/etc/buddynet` (token files) |
| `journald@buddynet.conf` | size-capped private journal (see "Logging") |

## Install

```bash
sudo install -m0755 buddynet /usr/local/bin/buddynet

# size-capped log namespace FIRST, so the units have somewhere to log
sudo install -m0644 deployments/systemd/journald@buddynet.conf /etc/systemd/journald@buddynet.conf
sudo systemctl restart systemd-journald@buddynet

sudo install -m0644 deployments/systemd/*.service /etc/systemd/system/
sudo install -m0644 deployments/systemd/buddynet-tmpfiles.conf /etc/tmpfiles.d/buddynet.conf
sudo systemd-tmpfiles --create
sudo systemctl daemon-reload
```

### Server (VPS)

```bash
sudo systemctl enable --now buddynet-handshake
sudo systemctl enable --now buddynet-relay      # optional fallback relay
# print the server key your buddies pin:
sudo systemctl show -p MainPID --value buddynet-handshake  # then:
sudo -u "$(...)" buddynet --role=handshake --key /var/lib/buddynet-handshake/id.key identity
```

Change a port without editing the unit:

```bash
sudo systemctl edit buddynet-handshake     # add: [Service] Environment=BUDDYNET_LISTEN=[::]:7000
```

The handshake control plane defaults to UDP (with a source-address cookie, so the
server is never a reflector). To use QUIC instead, set `Environment=BUDDYNET_QUIC=1`
on the handshake unit **and** in every buddy's `.env` — the transport must match
on both ends.

### Buddy (per tunnel)

```bash
sudo install -d -m0700 /etc/buddynet
sudoedit /etc/buddynet/backup.env          # see header of buddynet-buddy@.service
sudo chmod 600 /etc/buddynet/backup.env
sudo systemctl enable --now buddynet-buddy@backup
```

## Logging — why the disk can't fill

Each unit sets `LogNamespace=buddynet`, so all BuddyNet logs go to a **separate**
journald instance governed by `journald@buddynet.conf`, not the system journal.
That file hard-caps the size (`SystemMaxUse=50M`, `SystemMaxFileSize=10M`,
`MaxRetentionSec=1week`) and keeps `SystemKeepFree=200M` on the disk. Combined
with per-unit `LogRateLimitIntervalSec`/`LogRateLimitBurst`, a UDP flood or a
chatty `--debug` run cannot grow BuddyNet logs beyond the cap or starve the rest
of the system.

```bash
journalctl --namespace=buddynet -u buddynet-handshake -f
```

## Firewall

See [`../nftables.conf`](../nftables.conf) / [`../iptables.rules`](../iptables.rules)
for a default-drop ruleset that opens only SSH and the two BuddyNet UDP ports
(rate-limited against floods).

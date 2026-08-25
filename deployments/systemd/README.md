# BuddyNet systemd units (hardened)

Sandboxed units for running BuddyNet natively (no Docker). All three roles run
under `DynamicUser` with a full systemd sandbox (`ProtectSystem=strict`, dropped
capabilities, syscall and address-family allowlists, `MemoryDenyWriteExecute`,
resource ceilings). The server roles need no capabilities — their ports are
above 1024.

| File | Role |
|---|---|
| `buddynet-handshake.service` | handshake server (`--role=handshake`) |
| `buddynet-relay.service` | blind relay (`--role=relay`) |
| `buddynet-buddy@.service` | per-tunnel buddy, one instance per `<name>.env` |
| `buddynet-public-handshake.service` | the single-purpose `buddynet-handshake` binary for a PUBLIC matchmaker: no relay, no data path, no writable state, identity injected read-only via `LoadCredential` |
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
# print the server key your buddies pin (the unit stores it in its
# StateDirectory, which is root-readable):
sudo buddynet --role=handshake --key /var/lib/buddynet-handshake/id.key identity
```

Change a port without editing the unit:

```bash
sudo systemctl edit buddynet-handshake     # add: [Service] Environment=BUDDYNET_LISTEN=[::]:7000
```

The handshake control plane is **QUIC/TLS 1.3 unconditionally** since protocol
v8 — there is no plaintext UDP transport to choose any more, and no flag to
switch between them. The source-address validation that the old UDP path did
with a cookie is QUIC's own address validation now.

> ⚠️ In an override, never write a bare `Environment=`. An empty assignment
> resets **every** `Environment=` the unit set — including `BUDDYNET_LISTEN`,
> which `ExecStart` expands. Always assign a value, as in the example above.

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
for a default-drop ruleset that opens only SSH and the two BuddyNet UDP ports.
Only the **handshake** port carries a packet-rate limit; the **relay** port
deliberately does not, because it carries tunnel data and a control-plane rate
would throttle the tunnel itself. The handshake limit is two rules in a
load-bearing order — a per-source meter, then a global ceiling — so one loud
source cannot spend everybody's budget. It still does not guarantee availability
under attack: many sources together fill the global ceiling, and a saturated
uplink never reaches the firewall.

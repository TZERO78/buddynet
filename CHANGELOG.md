# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Kernel-WireGuard data plane (`--wireguard`, Phase 3).** Opt-in second data
  plane (set on both buddies): instead of QUIC streams, the tunnel runs over a
  kernel WireGuard interface and the partner is reachable natively at its VIP
  (`10.66.X.Y`). The WireGuard X25519 keys and the VIP are derived deterministically
  from the long-term Ed25519 identity, so `identity = key = VIP` carries onto the
  data plane with nothing exchanged over the wire. Configured over raw netlink (no
  `wg`/`ip` subprocess, zero new runtime dependencies). Reuses the entire control
  plane and the direct→relay fallback chain — **no `protocol.Version` bump**.
  - **Direct** (hole-punch → socket handoff to kernel WG, reusing the punched port
    so the NAT mapping survives) and **relay** (the blind relay forwards the
    encrypted WireGuard packets, never a WireGuard peer, holds no key).
  - **First contact** is verified with a Short Authentication String bound to an
    ephemeral-DH exchange over the punched UDP socket (RFC 6189), since there is no
    TLS exporter on this path; pinned peers skip it. Reconnects use a deterministic
    static-DH secret. Fails closed: WG unavailable / no path / rejected SAS → error,
    never a silent fall back to another plane.
  - **MultiPeer** (`--wireguard` + `--peers-file`): one interface per buddy
    (`bnet0`, `bnet1`, …), since kernel WireGuard has one listen port per device.
    Keeps every buddy peer-to-peer (no central hub/"switch") and the relay working
    per buddy.
  - `-L`/`-forward`/`--vip-listen` are not needed on this path (the VIP is native)
    and are ignored with a `NOTE`.
  - Lab-validated (own netns tests): `lab/test-wg-buddy.sh`, `test-wg-relay.sh`,
    `test-wg-multipeer.sh`. See [docs/WIREGUARD.md](docs/WIREGUARD.md).
  - On the `phase3/wireguard` integration branch; **not yet in a tagged release**.

### Fixed

- `tunnel.ControlServer.Close` is now idempotent (`sync.Once`): the previous
  check-then-close on the done channel could double-close under concurrent callers
  and panic ("close of closed channel"). Surfaced as a `-race` flake.

## [v2.3.0] — 2026-06-20

### Security

- `--insecure` renamed to `--lab`; env guard renamed to `BUDDYNET_LAB=1`.
  Semantically clearer: production configs never mention an "insecure" flag.
  Internal `BuddyConfig.Insecure` field unchanged (no protocol/API impact).
  **Breaking:** `--insecure` and `BUDDYNET_ALLOW_INSECURE` are removed with no
  alias — old lab scripts fail loudly instead of silently running wrong.
- **Key file refused if it is a symlink.** `LoadOrCreateKey` no longer follows a
  symlinked key path (it used `os.Stat`/`os.Chmod`/`os.WriteFile`, all of which
  follow links), so a key path pointing at e.g. `/etc/shadow` could chmod or
  clobber the target — now refused fail-closed via `os.Lstat`.

### Changed

- **Hard limit of 48 simultaneous peers per node (`MaxBuddies`).** BuddyNet is a
  personal overlay for small, trusted groups, not a large-scale mesh VPN — this is
  a deliberate design limit, not a performance one, with no flag to raise it.
  Enforced fail-closed at peer assembly and `peers add` (a manifest over the limit
  is refused, never silently truncated); an over-large session store is capped
  with a warning instead of bricking startup. Over-limit errors point to using a
  scalable solution without naming any product — operators choose their own.
- **VIP collision detection at peer assembly.** Two keys whose deterministic
  virtual IPs collide are now rejected with an explicit error instead of producing
  silent per-buddy routing ambiguity (the VIP is an address, never an auth
  boundary).
- **`maxAuthorizedKeys` lowered from 100,000 to 1,024** to match the threat model:
  generous headroom over `MaxBuddies` for key rotation, no longer effectively
  unbounded.
- **Relay abuse ceilings are now configurable** via `--relay-max-sessions` and
  `--relay-max-legs-per-ip` (0 = previous defaults 4096 / 64), so a small private
  relay can tighten them further.

### Tests

- **Lab pentest probe expanded to 17 scenarios**: VIP-collision (identity ≠ VIP),
  enrollment-flood boundedness, relay 3rd-leg rejection (a known token can't join
  an active pair), and a token-squat slot-DoS check (the per-token slot is capped
  at 2; the rest are squat-rejected). See `lab/pentest/`.

## [v2.2.1] — 2026-06-20

### Fixed

- **Re-pair deadlock on one-sided session loss.** A MultiPeer worker only ever
  registered under its session-derived rendezvous token once a session existed,
  with no fallback. If the two sides' session state desynced — a one-sided
  restore-from-backup, or a `peers remove` + `peers add` re-invite on the far end
  — they registered under different tokens and the matchmaking server parked both
  forever. A stale session now falls back to the manifest bootstrap token after a
  few failed rounds (key stays pinned, so no impersonation; never under
  `--insecure`), and re-pairing self-heals.

### Changed

- **Readable `peers list`** — header row + aligned `VIP / NAME / STATUS / KEY /
  TOKEN / SOURCE` columns, 6-char key handles; `peers remove` accepts the short
  key.
- **Connection lifecycle is now in the log schema** — the previously prefix-less
  bring-up/retry lines are structured `CONNECT: action=…` / `RECONNECT: action=…`
  (`key=value`), documented in `docs/OPERATIONS.md`.

### Security

- **Allowlist (approval-mode) hardening**: file-permission tightening, a cap on
  authorized keys, and `flock`-guarded approve/revoke.

### Docs

- Two recorded terminal demos in the README (deployment walkthrough as the hero;
  a dedicated MultiPeer section), reproducible from `lab/`.

## [v2.2.0] — 2026-06-20

### Security

- **Pairing token sealed to the server's pinned key on the wire** (Protocol v6,
  `TokenEnc` NaCl sealed box) — an on-path observer sees only ciphertext, never
  the secret.
- **Panic isolation at all untrusted-input seams** (`safe.Do` / `safe.Go`): a
  crafted datagram can no longer crash a 24/7 daemon.
- **`--insecure` requires `BUDDYNET_ALLOW_INSECURE=1`** env opt-in — a lab command
  can't be copy-pasted into production.
- **Identity key fail-closed on wrong permissions**: a `chmod` to `0600` is
  attempted, and the process refuses to start if it fails (SSH-style).
- **Enrollment code no longer logged in cleartext** — hash only.
- **`resolvectl` invoked by absolute path with an empty environment** — the
  `PATH`-hijack vector is closed.

### Performance

- **Relay hot path is lock-free**: `forward()` uses `sync.Map` + atomic ops instead
  of a global mutex — one busy session no longer stalls all others (the
  noisy-neighbour ceiling is removed).

### Changed (Breaking)

- **Protocol Version 5 → 6.** Server and buddies must be upgraded together. Old
  buddies sending a plaintext `Token` are still accepted as a fallback for one
  release cycle.

### Added

- `appVersion()` derives `dev-<commit>[-dirty]` from embedded VCS build info — a
  plain `go build` always shows a meaningful version.

### Fixed

- VIP stale-address cleanup on startup after `kill -9` (F-21).

## [v2.1.0] — 2026-06-20

### Added

- **MultiPeer**: `--peers-file` manifest, `--vip-listen` routing, `peers`
  subcommands, and live reload.
- **BuddyDNS**: `.buddy` names and a stub resolver.

## [v2.0.0] — 2026-06-19

### Added

- QUIC data plane (TLS 1.3 end-to-end).
- Blind relay role.
- ARM64 support (Raspberry Pi, Unraid).
- cosign / SBOM supply-chain signing.

## [v1.0.0] — 2026-06-15

### Added

- Initial release: two-buddy tunnel over UDP with Ed25519 identity, NAT traversal,
  and SAS verification.

[Unreleased]: https://github.com/TZERO78/buddynet/compare/v2.2.0...HEAD
[v2.2.0]: https://github.com/TZERO78/buddynet/compare/v2.1.0...v2.2.0
[v2.1.0]: https://github.com/TZERO78/buddynet/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/TZERO78/buddynet/compare/v1.0.0...v2.0.0
[v1.0.0]: https://github.com/TZERO78/buddynet/releases/tag/v1.0.0

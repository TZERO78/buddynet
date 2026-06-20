# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

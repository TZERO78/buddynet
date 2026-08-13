# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **One IPv6 /64 could exhaust a public relay (unauthenticated remote DoS).** The
  relay charged its abuse budgets — the per-source bind rate limit and the
  per-source leg cap — against the **exact** source address, while the control
  plane already aggregated IPv6 to a `/64`. Every address inside a `/64` is free
  to mint, so a single one handed an attacker an unlimited supply of "distinct
  sources": each with a fresh leg budget and a fresh token bucket, enough to fill
  the relay's global session table and lock unrelated users out. No account, no
  pairing and no spoofing were needed — the cookie challenge was answered
  honestly from each address.

  The accounting rule now lives in **one** place (`internal/netkey`) and every
  per-source budget calls it: the relay's bind limiter and leg cap, the control
  plane's connection cap, and the handshake server's request and enrollment
  limiters. IPv4 is still charged per exact address (addresses are scarce enough
  there that rotation is no lever, and aggregating would fold unrelated customers
  of one provider together); IPv6 is charged per `/64`; IPv4-mapped IPv6
  (`::ffff:a.b.c.d`) is unmapped first so it can no longer be a second budget for
  the same host. The leg's accounting key is stored when it binds and reused when
  it expires, so charging and releasing cannot drift apart. Cookies stay bound to
  the exact address and forwarding stays keyed by exact address **and** port —
  neither is affected.

  Two copies of one rule is how this happened, so a test now asserts that the
  control plane and the relay derive the *same* key for the same address.

  Aggregating to `/64` removes **free** rotation inside one `/64`; it is a ceiling
  on cheap abuse, not access control. A site delegated a `/56` or `/60`, or a
  botnet, still commands several budgets. A public relay that should not be open
  to strangers belongs behind `--allow-cidr` or a firewall.

- **A refused bind no longer costs a global session slot.** The relay inserted a
  session into the global table *before* checking the per-source leg cap, and left
  it there when the leg was then refused. The per-source cap therefore bounded only
  how many legs a source could hold, not how much of the table it could occupy: a
  throttled source could still fill `--relay-max-sessions` with legless sessions,
  one per token, and lock everyone else out — the same denial of service by another
  route. A bind that is refused now takes the empty session back out. A session that
  already belongs to another party is never touched, so refusing a third leg leaves
  an established pair intact.

  Found by the network-namespace lab after the fix above, not by the unit tests;
  both cases are covered by regression tests now.

### Added

- **`lab/test-relay-accounting.sh`** — a root-only network-namespace lab that
  claims relay legs from 65 addresses of one IPv6 `/64` (and one address of
  another) against the real relay binary, through the real client bind path, and
  asserts the `/64` shares one budget and cannot lock out an unrelated prefix.
  Point `BNBIN=` at an older build to watch it fail.

## [v4.0.0] — 2026-08-11

> **Breaking: `protocol.Version` 6 → 7, with no compatibility shim.** A v3.x
> buddy cannot pair with a v4 handshake server, or the other way round — hence a
> MAJOR release under SemVer. Once the source address is validated a mismatched
> client is answered with a version-stamped reply and reports "update buddynet"
> instead of timing out. **Upgrade the handshake server and every buddy
> together**, or run v6 and v7 side by side on two ports and migrate pair by
> pair — see *Migrating a running server to v7* in
> [docs/PROTOCOL.md](docs/PROTOCOL.md). Unraid users need the plugin bumped
> (BINVER + a verified BINSHA) in step with the server.

### Added

- **`buddynet-handshake` — a second, single-purpose binary for a stateless public
  matchmaker.** It runs the handshake control plane and nothing else: no relay, no
  data path, no client roles, and no writable state beyond its identity key. The
  point is a public rendezvous server whose blast radius is as small as the job
  allows — it cannot be talked into forwarding traffic or terminating a tunnel,
  because that code is not in the binary. The full multi-role `buddynet` is
  unchanged and still the right choice everywhere else. Releases now build,
  checksum and keyless-sign **both** binaries (linux/amd64 and linux/arm64); the
  existing asset name `buddynet-linux-amd64` is unchanged, so the Unraid plugin's
  checksum gate keeps working.

### Security

- **Protocol 6 → 7 (BREAKING): per-attempt `REGISTER` nonce and a full-coverage
  registration signature.** A buddy used to build its `REGISTER` once and re-send
  the same signed bytes on every poll, while the server's replay cache keyed on
  the signature — so the buddy's *own* second attempt looked like a replay and was
  dropped. In approval mode that left a single-attempt window in which pairing
  could work at all. Every attempt now carries a fresh 128-bit nonce, timestamp
  and signature (UDP, QUIC, the retry after a cookie challenge, and once per
  server address so a dual-stacked server's v4 and v6 datagrams do not collide),
  and the replay cache is keyed on `(pubkey, nonce)`. The signature now covers
  version, role, plaintext token, id, pubkey, virtual IP, name, timestamp, nonce
  and the sealed enrollment code, so a captured code can no longer be grafted onto
  another key. The server also derives the virtual IP from the public key instead
  of trusting the claim. **Server and buddies must be upgraded together**; once the
  source is validated, a mismatched client gets a version-stamped reply and
  reports "update buddynet" instead of timing out silently. For a public server,
  run v6 and v7 side by side on two ports and migrate buddies pair by pair —
  see *Migrating a running server to v7* in [docs/PROTOCOL.md](docs/PROTOCOL.md).
  Deliberately no compatibility shim: a v6 signature does not cover the fields v7
  relies on, so honouring one would mean accepting a weaker proof.

- **The approval transition no longer opens a replay window.** Because unapproved
  keys are (correctly) kept out of the replay cache, a registration captured while
  a key was still an outsider stayed replayable for the rest of its freshness
  window the moment the operator approved it. Nonces from unapproved keys are now
  remembered in a **separate** pre-auth cache with its own cap, TTL and eviction,
  and both caches are consulted once a key is approved — so a flood of outsiders
  can still only ever evict each other, never an approved buddy's entry.

  A timestamp comparison against the approval instant is kept as a second line of
  defence but is **not** sufficient on its own, and was wrong as the only check:
  the timestamp is the sender's to choose and may legitimately sit up to `regSkew`
  in the *future*, so a registration dated `now + 59 s` and sent before approval
  passes such a comparison afterwards. Only remembering the nonce closes it.

- **Code-based enrollment works again over QUIC, and is bound to the TLS key.**
  The QUIC control server refused any client key that was not already on the
  allowlist, during the TLS handshake — which made `--code` enrollment impossible
  on the default transport: an un-approved client could not complete the handshake,
  so its encrypted code never reached the application layer, so the operator could
  never approve it. TLS now *authenticates* every client (Ed25519 client
  certificate + proof of possession) but *authorizes* none; the authenticated key
  is handed up and `REGISTER.pubkey` must equal it, or the connection is closed
  and nothing is stored. Unknown keys run under a much stricter rate limit than
  approved ones.

- **Cookie before decryption on the UDP control plane.** The sealed pairing token
  was opened (X25519 + NaCl box) *before* the address-validation cookie was
  checked, so an IP-spoofed source could reach a full asymmetric operation with a
  single datagram. The cookie is now the gate ahead of everything asymmetric.

- **Replay cache no longer floodable by outsiders.** The bounded cache was
  populated before the allowlist check, so any stranger with a self-signed but
  valid registration could fill it and evict entries protecting approved buddies.
  Authorization now comes first: only approved keys occupy a slot.

- **QUIC control connections bounded per source and in time.** Only a global cap
  existed, so one host could fill it and lock everyone else out, and nothing
  bounded how long a handshaked-but-idle connection could sit there. Adds a
  per-source cap (address families normalised), a first-stream deadline, a
  per-request read deadline, no server-side keepalive, guaranteed slot release on
  every exit path, and throttled refusal logging.

- **A peer is cached only after its identity is confirmed.** `peers.json` was
  written as soon as the handshake server's roster passed its consistency checks —
  before the tunnel existed and before the SAS. A hostile server or a token squat
  could thereby get an unverified key cached and its self-asserted `.buddy` name
  TOFU-pinned, and a first contact whose SAS the human *rejected* still left both
  behind. Persistence now happens only after the data plane is up and, on first
  contact, after the SAS is confirmed. Known and pinned peers are still refreshed
  on every successful authenticated connection.

- **The allowlist stays fail-closed when its file disappears.** The watcher
  skipped the tick on any stat error, so deleting the allowlist left the
  last-loaded keys authorized for the life of the process — revoking everyone with
  `rm` did nothing, silently. A missing allowlist now means zero authorized
  clients, warned once and reloaded when the file returns. `--authorized` alone
  decides the mode; the docs claimed a missing file fell back to open mode and
  have been corrected.

### Known / deferred

- **~100 unhandled-error sites (gosec G104) are still excluded wholesale.** The
  exclusion is long-standing project policy (see `.github/workflows/ci.yml`) and
  most sites are best-effort writes on UDP or on a stream that is being torn down
  anyway. They have **not** been classified individually. The ones in the
  production packages — `internal/role` (38) and `internal/tunnel` (16) — deserve
  a pass of their own, keeping the exclusion only where a dropped error genuinely
  cannot matter and handling the rest. Out of scope here so it does not ride along
  with the remote- and approval-path fixes.
- **`internal/tunnel/quic.go` still allows TLS session resumption** (gosec G123).
  The control plane now disables it, because a resumed session does not re-run
  `VerifyPeerCertificate`; the data plane was left alone in this changeset.

## [v3.0.0] — 2026-07-04

Phase 3. One theme: the WireGuard data plane arrives **scoped and secure by
default**. Three breaking changes — WireGuard sharing is fail-closed
(`--expose`), the control plane is encrypted by default (`--quic-handshake`),
and the peers manifest is YAML (`peers migrate` converts) — each detailed below.

### Changed

- **BREAKING — WireGuard sharing is now SCOPED and fail-closed by default
  (`--expose`).** On the `--wireguard` data plane a buddy can now reach **only**
  the port(s) you name with `--expose` (e.g. `--expose 873`, or per buddy via
  `expose:` in the manifest) — **without the flag, nothing on your host is
  reachable** over the tunnel (ping stays allowed for diagnosis). Anyone relying
  on the previous whole-host behaviour must now say so explicitly with
  `--expose all`. The scope is enforced in the kernel's nftables subsystem via a
  private `table inet buddynet` (programmed over raw netlink — no dependence on
  nft/iptables/ufw/firewalld being installed, no interference with an existing
  firewall setup) and is installed before the interface comes up; if it cannot be
  enforced, the tunnel refuses to start rather than exposing the host. See
  [docs/WIREGUARD.md](docs/WIREGUARD.md).
- **The `--peers-file` manifest is now YAML** — per-buddy fields outgrew the old
  line format: each entry takes `key` (required), plus optional `name`, `token`
  and `expose` (the per-buddy WireGuard scope, overriding `--expose`). The legacy
  `<key> [token]` line format is still read for one release with a deprecation
  warning; convert with the new **`peers migrate`** subcommand (the old file is
  kept as `.bak`). `peers add` gains `--name` and `--expose`; `peers list` shows
  the per-buddy scope. This adds `gopkg.in/yaml.v3` as the project's second
  approved application dependency (after `miekg/dns`); the manifest is parsed
  strictly (unknown fields are errors) with bounded size. See
  [docs/PEERS.md](docs/PEERS.md).

- **The handshake control plane is now QUIC/TLS 1.3 by default (security by
  default).** Previously plain UDP (cleartext token) was the default and
  `--quic-handshake` opted in; now encryption is on unless you explicitly opt out
  with `--quic-handshake=false` (or `BUDDYNET_QUIC=0`). **Set the same on the server
  and every buddy** — a QUIC buddy cannot pair with a plain-UDP server (and vice
  versa), so when upgrading, upgrade/align both sides, or pass `--quic-handshake=false`
  on both for the old behaviour.
- **BuddyDNS names can no longer take the fingerprint-alias shape.** A `--name`
  that is exactly 8 hexadecimal characters is now rejected: that shape is reserved
  for the `<fp8>.buddy` fingerprint alias, so a peer's self-asserted name can no
  longer shadow another peer's fingerprint entry in the resolver. A vanity name
  like `deadbeef` is disallowed for this reason; `deadbeefx` or `web01` are fine.
  See [docs/BUDDYDNS.md](docs/BUDDYDNS.md).
- **systemd units gain a crash-loop circuit breaker.** `StartLimitIntervalSec=60`
  / `StartLimitBurst=5` on the handshake, relay and buddy units: a deterministic
  start failure now stops after 5 attempts instead of restarting forever under
  `Restart=on-failure`. Transient network reconnects are unaffected (handled
  in-process with jittered backoff).

### Added

- **Known-buddies control plane: QUIC client-key pinning in approval mode.** With
  `--quic-handshake --authorized`, the handshake server now pins clients by key at
  the **TLS handshake** — every buddy presents its Ed25519 identity certificate and
  a key not on the allowlist is refused *before* it can send a `REGISTER` (the same
  early rejection a firewall gives, enforced cryptographically; no PKI — the key is
  pinned directly, mirroring how the buddy already pins the server key). Open mode
  (no `--authorized`) is unchanged: any client may connect and pairing is gated by
  the secret token at the application layer. See [docs/OPERATIONS.md](docs/OPERATIONS.md).
  The control plane is always QUIC/plain — never WireGuard — so per-buddy endpoint
  discovery and MultiPeer keep working.
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

- **Recovered-panic count in the per-minute stats line.** The handshake and relay
  `stats (last …)` line now reports `panics=N` in its `ALERT:` segment — the
  per-interval number of request/connection handler panics contained by the safety
  net. A reliably-triggerable parser panic is otherwise only logged once per
  throttle window; a rising count is now a standing operational signal. See
  [SECURITY.md](SECURITY.md).

### Fixed

- `tunnel.ControlServer.Close` is now idempotent (`sync.Once`): the previous
  check-then-close on the done channel could double-close under concurrent callers
  and panic ("close of closed channel"). Surfaced as a `-race` flake.

### Security

- **CI security tooling is pinned to exact versions.** `gosec` and `govulncheck`
  are installed at `@v2.27.1` / `@v1.5.0` instead of `@latest`, verified against
  the Go checksum database. A security tool runs in CI with repository/token
  access, so an upstream compromise or a bad release can no longer be pulled in
  automatically — matching how the GitHub Actions and the Docker base image are
  already pinned by digest.

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

[Unreleased]: https://github.com/TZERO78/buddynet/compare/v3.0.0...HEAD
[v3.0.0]: https://github.com/TZERO78/buddynet/compare/v2.3.0...v3.0.0
[v2.3.0]: https://github.com/TZERO78/buddynet/compare/v2.2.1...v2.3.0
[v2.2.1]: https://github.com/TZERO78/buddynet/compare/v2.2.0...v2.2.1
[v2.2.0]: https://github.com/TZERO78/buddynet/compare/v2.1.0...v2.2.0
[v2.1.0]: https://github.com/TZERO78/buddynet/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/TZERO78/buddynet/compare/v1.0.0...v2.0.0
[v1.0.0]: https://github.com/TZERO78/buddynet/releases/tag/v1.0.0

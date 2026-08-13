# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v5.0.0] — 2026-08-13

> **Breaking: `protocol.Version` 7 → 8, and two flags are gone.** A v4 buddy
> cannot pair with a v5 handshake server, or the other way round — a MAJOR
> release under SemVer. Upgrade the server and every buddy together, or run v7
> and v8 side by side on two ports and migrate pair by pair (see *Migrating a
> running server* in [docs/PROTOCOL.md](docs/PROTOCOL.md)).
>
> **Also breaking: a relay refuses to start without an authorization policy.**
> `--role=relay` now needs `--server-key` (verify tickets from your handshake
> server) or `--allow-cidr` (serve named networks), or both. A relay carries your
> bandwidth, and a stranger who hoards its capacity takes away the fallback the
> two people it was built for need. See *Relay authorization* below.
>
> **Also breaking, `--wireguard` only: traffic arriving on `bnetN` is no longer
> forwarded anywhere.** `--expose` now covers this host and nothing behind it. If
> you route a LAN machine to a buddy through this node — or a buddy into your LAN —
> that stops working; see *A buddy is no longer routed THROUGH your host* below.

### Added (Breaking) — relay authorization

- **Relay tickets: a relay no longer takes anyone's word for a session.** The
  handshake server issues every paired buddy a short-lived permit signed with its
  identity key, and the relay verifies it with the matching **public** key. The
  relay learns *that* a session was authorised and nothing about who is in it —
  no buddy list, no identity in the bind, no record of who talks to whom. It
  holds no signing key, so compromising it yields no ability to authorise a
  session anywhere.

  Turn it on with **one flag on each side**: `buddynet gen-relay-id` once, then
  the same `--relay-id` on the handshake server and on the relay. On the usual
  one-VPS `--role=handshake,relay` the relay derives the key it trusts from the
  server in its own process, so that id is all you add.

  A bare ticket would be a bearer token, so each buddy also mints a **fresh
  ephemeral key per connection attempt** (`epk` on the `REGISTER`, covered by the
  registration signature) and signs the bind with it, over the relay's own
  address-bound, rotating cookie. A captured ticket — or a whole captured bind —
  is inert without that private key, which never leaves the buddy.

  Details, including the exact lifetime arithmetic (worst case 140 s, not 120)
  and the check order on the relay's permanently open UDP port, in
  [docs/PROTOCOL.md](docs/PROTOCOL.md); operator setup in
  [docs/OPERATIONS.md](docs/OPERATIONS.md).

- **A relay refuses to start without a policy**, and `--allow-cidr 0.0.0.0/0` (or
  `::/0`) is refused with its own message rather than accepted as one. There is
  deliberately no `--relay-open`: an "I know what I am doing" switch ends up in
  production. Both policies together are an AND — the CIDR list is hardening on
  top of tickets, never an alternative that a ticket bypasses.

  **This is the change that will stop an existing relay from starting.** Add
  `--server-key`/`--relay-id`, or `--allow-cidr`. Every shipped artifact is
  updated: `deployments/docker-compose.yml`, `deployments/systemd/buddynet-relay.service`
  (as an overridable `BUDDYNET_RELAY_POLICY=`), and the labs.

- **`buddynet gen-relay-id`** mints the id. It is configuration, not a secret,
  and both sides print theirs at startup — a mismatch otherwise surfaces only as
  "every ticket rejected" with nothing in either log naming the cause.

- **New operational dependency: clocks.** Relay and handshake server must agree
  within 10 s. NTP handles it, it is invisible until it breaks, and then every
  ticket is refused — so the relay logs a distinguishable reason that names both
  possible causes (clock skew *or* a wrongly-issued ticket). It cannot tell them
  apart, and does not pretend to.

- **`--punch` is capped at 60 s** and refused above it at startup rather than
  silently clipped: a ticket is valid for at most 120 s and has to cover the
  punch *and* the bind that follows it.

- **A half-open relay session now expires after an absolute 60 s.** Its idle
  timer is refreshed by any packet from a bound source, so one leg plus a trickle
  of traffic used to hold a session slot indefinitely with no partner ever
  arriving.

- **When the direct path fails and no relay is configured, the buddy says so.**
  It does not claim a relay would have helped — it cannot know that — but
  "no path: the direct connection failed and no relay is configured" is the
  difference between an operator who knows what to do and one who concludes
  BuddyNet is broken.

### Removed (Breaking)

- **The plain-UDP control plane is gone; matchmaking is QUIC/TLS 1.3 only.**
  `--quic-handshake` and `BUDDYNET_QUIC` are removed from both binaries — there
  is nothing left to select. With the transport go its address-validation cookie
  (`TypeCookie`, `Message.cookie`) and the cleartext pairing token: `Message.token`
  now carries `json:"-"`, so it never leaves the process. `token_enc`, sealed to
  the server's pinned key, is the only form on the wire, and the server requires it.

  The cookie only ever reproduced what QUIC's handshake does anyway, while the
  `REGISTER` — pairing token included — travelled in the clear. That is what made
  an on-path token squat possible, and with it the roster and candidate poisoning
  that follows. Both open-mode findings from the v4 security audit were reachable
  **only** on that transport. The RELAY keeps its own cookie: a relay bind is
  always plain UDP.

- **`--token` (and `BUDDYNET_TOKEN`) is removed.** Pairing is one-time only:
  `--invite` mints a token, `--join` carries the one your buddy gave you, and both
  retire it after the first pairing in favour of the stored session secret.
  `--token` was a long-lived bearer secret replayed on every reconnect, so anyone
  who ever learned it — an old chat message, a shell history, a backup — could
  squat the pairing for as long as the pair existed. The mechanism is unchanged:
  `--join` already fed the same internal path, so this removes a flag and a
  failure mode, not a code path. `--status` now takes `--join <TOKEN>` (or runs
  where a session is already stored).

- **`allowclient CODE` is removed, and the control server no longer writes
  anything at runtime.** `authorized.pending` — a `code → key` mapping the server
  maintained on disk so a separate CLI process could resolve a code — is gone.
  Pending enrolments now live in memory only: bounded, pruned after 30 minutes,
  and gone when the process stops. The server's only persistent state is its
  identity key and the allowlist, both of which are operator configuration.

  **This is a security improvement, not just a simplification.** That file was
  written by two processes and `allowclient` *trusted* its contents: anyone able
  to write it could swap the recorded key, and typing the correct code would then
  approve the **wrong** key with nothing looking out of place. Approving the key
  the server printed removes the indirection — you authorise exactly what the
  server saw. It also means an enrolment exists only while the client is actually
  running and talking to the server, so there is no waiting entry to tamper with.
  As a side effect it removes the last instance of the pattern behind every
  persistence bug this project has had: two writers on one file.

  **What to do instead:** approve by key. The server already logs the complete
  command when a client enrols:

  ```
  AUTHZ: action=pending key=abc12345 code=78c86dc0 — approve with:
    buddynet --role=handshake --authorized FILE approve <CLIENT_KEY>
  ```

  Running `allowclient` now prints that guidance and exits non-zero, so existing
  scripts fail loudly instead of silently doing nothing. A leftover `.pending`
  file from an older version is ignored and can be deleted.

  **The cost:** if the client is no longer running, there is nothing to approve —
  start it again. Previously the entry survived 30 minutes regardless. In practice
  this lands once per buddy, ever: it is the first-contact step, and after it the
  key is on the allowlist and the pair holds a session secret. Later reconnects —
  including after a provider hands a buddy a new IP — are unattended: the handshake
  server still does the matchmaking, it just no longer needs an operator, because
  the key is already approved.

- **A server never creates its own identity any more; `init` does.** The key file
  was created whenever the `--key` path did not exist. That is right on a genuine
  first run and wrong every time after — and from inside the process the two are
  indistinguishable. A volume that did not mount, a typo in `--key`, an empty
  credentials directory, or a fresh container expected to inherit a key all led to
  the same outcome: the server came up happily with a **new identity**, logged one
  warning, and every buddy that had pinned the old key refused it as a possible
  MITM. For the public matchmaker — whose entire job is to be the one key everyone
  pinned — that is the worst silent failure available.

  Creating an identity is now an explicit act:

  ```bash
  buddynet --key PATH init                    # creates it, once; refuses to replace one
  buddynet --key PATH identity                # READS only; errors if the file is missing
  buddynet --role=handshake --key PATH        # refuses to start without it
  ```

  `identity` used to create the key as a side effect, which meant any wrapper that
  read the key ("print the pubkey, then start the server") could mint a fresh
  identity after a volume was lost. It only reads now, so no automation can do
  that by accident — creating one requires typing a command whose name nobody puts
  in a start-up path.

  **Buddies are unchanged:** a buddy still creates its key on first start. Setting
  one up is a person on their own machine, and a buddy that loses its key has to
  be re-pinned by its one partner — it does not lock a network out.

  Both refusals name the path and print the exact command, and say what the two
  possible causes are (first run vs. lost key), because that is the decision only
  the operator can make.

### Changed (Breaking, `--wireguard` only)

- **A buddy is no longer routed THROUGH your host: `--expose` covers this host,
  not your LAN.** `--expose` installed its rules only on the nftables **input**
  hook. A packet that arrives on `bnetN` and is routed onward never traverses that
  hook — and WireGuard's AllowedIPs pins only the **source** of a decrypted packet,
  never its destination. So a buddy could put its own permitted VIP in the source
  field, any LAN address behind you in the destination field, and — on a host that
  forwards, which includes anything running Docker — reach it. This held with ports
  exposed, with **nothing** exposed, and under `--expose all`.

  BuddyNet now also programs a `fwd` chain (forward hook, policy accept) that drops
  everything arriving on `bnetN`, for every buddy interface and every scope. Ports
  you expose are still reachable on the host itself; connections **you** open to a
  buddy still get their replies (those traverse the input hook, where
  established/related already accepts); and forwarding that never touches `bnetN`
  is untouched — the rules are not a host-wide filter.

  **What stops working:** routing a LAN machine to a buddy through this node, or a
  buddy into your LAN. It was never a documented feature and it bypassed `--expose`,
  which is why it is closed rather than grandfathered. Subnet routing over a buddy
  tunnel is a legitimate thing to want and will return as its **own explicit
  option**, with the destination networks named by you — never implied by
  `--expose all`.

  The forward rule is deliberately an unconditional drop: an established/related
  accept there would already permit replies to *forwarded* connections, i.e. a
  slice of subnet routing shipped early under a flag that says "expose ports on
  this host".

### Added

- **`lab/test-relay-accounting.sh`** — a root-only network-namespace lab that
  claims relay legs from 65 addresses of one IPv6 `/64` (and one address of
  another) against the real relay binary, through the real client bind path, and
  asserts the `/64` shares one budget and cannot lock out an unrelated prefix.
  Point `BNBIN=` at an older build to watch it fail.

### Changed

- The Unraid plugin loses its *Encrypt the control plane* option (there is only
  one control plane now) and passes the pairing token as `--join`.
- The lab scripts, compose files and the pentest probe follow: the probe drops
  every scenario that targeted the UDP plane. Those attacks are not untested now,
  they are **unreachable** — QUIC will not carry a connection without a valid
  Ed25519 client certificate, and the server binds `REGISTER.pubkey` to it. A
  QUIC-native scenario set is separate work.

### Fixed

- **Two overstated security claims corrected.** The docs said the long-lived
  session secret is "never transmitted" / "never sent over the wire". It is
  *derived* locally from the TLS channel binding, so nothing an observer sees
  yields it — but on every reconnect it **is** sent to the handshake server, sealed
  to that server's pinned key, and the server **unseals** it: it is the value the
  server matches the two buddies on. Never in the clear, never in a log, but **not
  a secret from the server**. A hostile server therefore knows the rendezvous value
  and can squat a pairing; it still cannot read traffic (end-to-end between the two
  pinned identities) or impersonate a buddy to one that pins with `--peer-key` or
  has TOFU-pinned it. Corrected in PROTOCOL.md, ARCHITECTURE.md and TWO-BUDDIES.md.

- **The Sigstore verification example was too loose to be worth much.**
  `--certificate-identity-regexp '^https://github.com/TZERO78/buddynet'` matched
  *any* workflow in the repo, on *any* ref, and — with no `/` after the repo name —
  also any same-owner repository whose name merely starts with `buddynet`. It now
  pins the release workflow **and** a version tag:

  ```
  ^https://github\.com/TZERO78/buddynet/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$
  ```

  Verified against the five cases the old pattern wrongly accepted (another
  workflow, a branch instead of a tag, a different same-owner repo, a
  prefix-matching repo, a non-SemVer tag).



- **Concurrent peer updates no longer lose entries from `peers.json`.** `Upsert`
  mutated the roster under a lock, took a snapshot, released the lock, and only
  then wrote the file. Two updates landing together could therefore rename an
  older snapshot over a newer one — the in-memory roster stayed correct, so the
  loss surfaced only after a restart, which is exactly when the file matters: it
  is the offline link of the connection fallback chain (a peer that vanished from
  it can no longer be reached without the handshake server). A second mutex now
  spans both the snapshot and the write, so the file order matches the map order;
  the registry lock itself is still not held across disk I/O, since BuddyDNS reads
  it on every lookup. A write that fails is reported instead of swallowed.

- **A sealing failure no longer falls back to a cleartext token.** `setToken`
  used to drop the pairing token onto the wire unsealed if `SealCode` failed —
  i.e. exactly when something was already wrong. It returns an error now; there
  is no cleartext field left to fall back to either.

### Security

- **The shipped firewall rate limit did nothing once a flow was established.** In
  `deployments/nftables.conf` and `deployments/iptables.rules`, the generic
  `established,related accept` sat *above* the UDP rate limits. Netfilter marks a
  UDP flow established as soon as it has seen traffic in both directions — so from
  the moment the server answered the first packet (a QUIC Initial, a relay cookie
  challenge), every later packet of that 5-tuple matched the accept and the limit
  was never reached. QUIC also multiplexes many connections over one UDP flow, so
  conntrack is not a per-connection quota either.

  The control port is now limited *before* the established accept, and the excess
  is dropped explicitly — without that drop, over-limit packets simply fall through
  to the accept below.

  The **relay port deliberately gets no packet-rate limit**: it carries tunnel
  data, so a rate that is safe for a control plane would throttle the tunnel
  itself. Its ceilings belong in the relay (per-source bind limit, legs per source,
  session cap) and bandwidth is a shaping/provider problem — `tc`, an nftables
  meter sized for your link, or an egress budget. Restrict *who* may reach it
  instead. Saying so beats shipping a number that looks like protection.

  Measured with rule counters in `lab/test-firewall-order.sh` (new), including two
  positive controls — traffic *within* the allowance must still be accepted, and a
  burst on the relay port must pass untouched — so "the excess is dropped" cannot
  be satisfied by a ruleset that simply blocks everything. On the old ordering the
  limit accepted 147 packets and dropped **none**; on the new one 253 over-limit
  packets are dropped on an established flow while all 300 relay packets pass. The
  lab fails against the old ruleset *and* against one that rate-limits the relay
  port, so it tells the three states apart.


- **The public QUIC port did work before it could refuse anyone.** Two findings
  from an independent audit pass, both confirmed against the code:

  **QUIC Retry was not enabled.** `quic.Transport` was created without
  `VerifySourceAddress`, so quic-go built a full connection — including the TLS
  and Ed25519 handshake — for any peer that sent a well-formed Initial, *including
  a spoofed one*. BuddyNet's own caps (256 connections, 16 per IPv4/IPv6-/64) only
  apply once a connection exists, so they never saw that traffic at all. Source
  validation (RFC 9000 §8.1.2) is now required for every unvalidated source: a
  spoofed address gets a small stateless Retry token and nothing else. It costs one
  extra round trip on connection setup, which for a node that dials once per
  reconnect is nothing. Deliberately unconditional rather than gated on a
  "suspicious rate" threshold — one less number to tune wrong.

  **`--allow-cidr` was checked too late to do what its help text claimed.** The
  flag promised sources outside the list are dropped "before any crypto"; in fact
  the check sat in the REGISTER handler — after TLS and after the connection had
  taken one of the 256 slots. A refused source could therefore still occupy
  capacity until the idle timeout, which is most of the value of the flag. The
  allowlist is now enforced in the listener, before a slot is handed out; the help
  text says what actually happens (TLS runs first regardless — that is unavoidable
  with this library — but no BuddyNet capacity is spent).

  Also: a **version mismatch** now closes the whole connection after answering,
  instead of only the stream. It is a final refusal — that peer cannot become
  compatible on this connection — so leaving it open only let it hold a slot. Rate
  limiting and "no partner yet" deliberately do NOT close: both are transient, and
  a buddy polling for its partner or for an operator's approval must be able to
  keep polling.


- **Log injection through client-supplied fields (regression, v8 only).** The
  removal of the plain-UDP control plane also took out two controls that had been
  added together on `main`: `validField` no longer confined free-form fields to
  the base64url alphabet, and the `PAIRED` line printed ids unquoted. An id
  carrying a newline therefore wrote a **second, forged line into the operator's
  audit trail**, in the exact format this project uses for security events. In
  open mode any anonymous client could do it — and `buddynet-handshake`, the
  public matchmaker, deliberately never wires an allowlist, so it always runs open
  mode. Both controls are restored (reject at the boundary, quote at the log
  call), together with the two regression tests that were deleted with them.

  `TestValidField` had been changed to assert that **128 NUL bytes are a valid
  field** — the exact shape the original fix called out as "the test blessing the
  hole". It asserts the opposite again.

- **A live rescope to `--expose all` REMOVED the rules (regression, v8 only).**
  The same mistake as below, one function over and one degree worse:
  `reprogramScope` — the SIGHUP manifest-reload path — called `nft.Remove` for the
  `all` scope. Editing a buddy's `expose:` to `all` and reloading therefore did not
  merely fail to install the forward drop, it **took the existing one away**, live,
  on a tunnel that stayed up, with nothing in the log to say that buddy had just
  become a route into the LAN. Found by asking which other functions branch on
  `scope.All` after fixing the one below.

- **`--expose all` installed no nftables rules at all (regression, v8 only).**
  `applyScope` returned before `nft.Apply` for the `all` scope, on the old
  reasoning that "whole host" means "nothing to install". That stopped being true
  when the forward-hook chain arrived: `all` opens this HOST, never the networks
  behind it, and that drop is a rule like any other. The ruleset was built
  correctly and simply never reached the kernel, so a buddy on an `--expose all`
  node could still be routed into the LAN — the very thing the forward chain
  exists to stop.

  **Behaviour change:** `--expose all` now also requires kernel nftables support,
  where it previously came up without. Without nftables the forward drop cannot
  exist, and starting anyway would mean routing into your LAN with nothing able to
  say so.

  Worth recording *why* this survived review: every test and the network-namespace
  lab drove `nft.buildBatch` or `nft.Apply` **directly**, so all of them stayed
  green through a gap that sat in the layer between them. There is now a test at
  that layer (`internal/role/applyscope_test.go`) asserting the rules are
  programmed for every scope, and the lab tooling says in its own docs which layer
  it does *not* cover.

- **`PAIRED` was logged on every registration (regression, v8 only).** The
  once-per-token latch went out with the same commit. A waiting buddy re-registers
  about once a second for as long as the tunnel lives, so this wrote a line per
  second per pair in **normal** operation — and let anyone who knows a token turn
  it into a flood that fills the disk. The latch is back, including its release on
  eviction, on reap, and when a token loses its partner between reap ticks.


- **A revoked buddy can no longer be resurrected by a concurrent reconnect.** The
  `known_peers` session store is written by TWO processes — the running buddy
  (`saveSession`, on every reconnect) and the operator's CLI (`peers remove`, the
  revoke path) — but its read-modify-write was serialised only by an in-process
  mutex. Two processes hold different mutexes, so one could rename its snapshot
  over the other's: a stored session silently dropped, or a session the operator
  had just revoked written back and reconnectable again. Both directions are now
  serialised by the same advisory file lock the allowlist already uses, taken
  across the read-modify-write and fail-closed (a lock that cannot be taken means
  another process is mid-update — exactly when writing anyway loses data).

- **One IPv6 /64 could exhaust a public relay (unauthenticated remote DoS).** The
  relay charged its abuse budgets — the per-source bind rate limit and the
  per-source leg cap — against the **exact** source address, while the control
  plane already aggregated IPv6 to a `/64`. Every address inside a `/64` is free
  to mint, so a single one handed an attacker an unlimited supply of "distinct
  sources": each with a fresh leg budget and a fresh token bucket, enough to fill
  the relay's global session table and lock unrelated users out. No account, no
  pairing and no spoofing were needed — the cookie challenge is answered honestly
  from each address. The relay is plain UDP by design and keeps its own cookie, so
  dropping the plain-UDP *control* plane in this release did not touch this.

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

  Also shipped as **v4.1.1** for the v4 line.

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

## [v4.1.1] — 2026-08-13

A single security fix for the v4 line, released before v5 so the v4 branch was
not left carrying an unauthenticated remote DoS while v5 was still in progress:
**one IPv6 /64 could exhaust a public relay**. It is described in full under
v5.0.0 above (*One IPv6 /64 could exhaust a public relay*, and *A refused bind no
longer costs a global session slot*), because v5.0.0 contains the same fix — the
text is not repeated here rather than drifting into two versions of one story.

The Unraid plugin was pinned to this release in the same step: installs had still
been pulling the v4.0.0 binary, so they carried the DoS until the plugin moved.

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
(`--expose`), the control plane is encrypted by default,
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
  default).** Previously plain UDP (cleartext token) was the default and opted in; now encryption is on unless you explicitly opt out
  with (or. **Set the same on the server
  and every buddy** — a QUIC buddy cannot pair with a plain-UDP server (and vice
  versa), so when upgrading, upgrade/align both sides, or
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

- **Known-buddies control plane: QUIC client-key pinning in approval mode.** With --authorized`, the handshake server now pins clients by key at
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

[Unreleased]: https://github.com/TZERO78/buddynet/compare/v5.0.0...HEAD
[v5.0.0]: https://github.com/TZERO78/buddynet/compare/v4.1.1...v5.0.0
[v4.1.1]: https://github.com/TZERO78/buddynet/compare/v4.1.0...v4.1.1
[v4.0.0]: https://github.com/TZERO78/buddynet/compare/v3.0.1...v4.0.0
[v3.0.0]: https://github.com/TZERO78/buddynet/compare/v2.3.0...v3.0.0
[v2.3.0]: https://github.com/TZERO78/buddynet/compare/v2.2.1...v2.3.0
[v2.2.1]: https://github.com/TZERO78/buddynet/compare/v2.2.0...v2.2.1
[v2.2.0]: https://github.com/TZERO78/buddynet/compare/v2.1.0...v2.2.0
[v2.1.0]: https://github.com/TZERO78/buddynet/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/TZERO78/buddynet/compare/v1.0.0...v2.0.0
[v1.0.0]: https://github.com/TZERO78/buddynet/releases/tag/v1.0.0

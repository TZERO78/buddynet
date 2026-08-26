# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v5.4.0] — 2026-08-26

Two ways to run BuddyNet without renting anything, both measured in new labs
rather than asserted: the coordinator may be one of the two buddies, and with
`--direct` there need be no coordinator at all.

### Added — `--direct`: a tunnel with no handshake server at all

Two buddies can now reach each other from configuration alone. Each side is told
**where** its buddy is (`--peer-endpoint HOST:PORT`, a dynamic-DNS name is fine)
and **who** its buddy is (`--peer-key`), and that is the entire setup: no
matchmaking, no pairing token, no relay ticket, no third party.

`--listen-port PORT` pins the tunnel's UDP socket to a fixed port instead of an
ephemeral one, so a port forward can be aimed at it. It is what makes a buddy
dialable, and it is useful in server mode too.

Which side listens is decided locally and identically on both ends: the side that
can only be dialled listens, the side that can only dial dials, and when both are
reachable the lower public key listens — the same tie-break server mode already
used, so the two agree without exchanging anything first.

**Security — what this mode does and does not change.** The pinned key is the
*entire* authentication here, so the rules around it are fail-closed:

- `--peer-key` is **mandatory**. There is no rendezvous channel to run a SAS
  over, so an unpinned partner is refused rather than learned.
- `--direct` **cannot be combined with `--lab`**, which switches partner
  verification off; nor with `--server`/`--server-key`, `--peers-file`,
  `--invite`/`--join`, `--code` or `--status`. Each is refused at startup with an
  actionable message.
- The configured address is **route-finding only**. It is re-resolved on every
  attempt, and whatever it resolves to must still prove the pinned key in the TLS
  handshake — so a hijacked DNS record, a poisoned resolver or a spoofed route
  costs availability and nothing else. `lab/test-direct.sh` demonstrates this
  against a live impostor.
- The virtual IP is **derived** from the pinned key, never configured, so the
  "identity is address" invariant holds here by construction.

There is deliberately **no DynDNS client and no provider token** in BuddyNet:
updating the record stays your router's or cron's job.

**The listening side arms every path at once** in this mode instead of walking
the fallback chain in turn. With a handshake server both buddies start from the
same roster at the same moment, so a sequential walk stays in step; in direct
mode they start whenever their processes did, and each attempt takes ~10s — long
enough for the two to settle permanently out of phase, one listening directly
exactly while the other is bound to the relay. That was measured, not assumed
(the relay logged both legs paired while each end had already moved on). Since
every path arrives on the same UDP socket, the listening side now primes them all
and listens once. The dialling side and the server-based mode are unchanged.

**Both data planes work with `--direct`.** The default is QUIC; `--wireguard`
swaps in the kernel WireGuard plane, and then no QUIC is involved at all — the
partner's identity is proven by the WireGuard handshake against the X25519 key
derived from its pinned Ed25519 identity, with `wg.ConfirmHandshake` requiring a
completed handshake before anything counts as connected. This needed real work
rather than a flag: WireGuard has no "listen" call, so the dialled side is now
configured as a peer with **no endpoint** and adopts the address the handshake
arrives from (only the key-holder can complete it, so nothing else can trigger
that). Covered by `lab/test-wg-direct.sh`, which asserts the no-endpoint path was
actually the one exercised.

Not supported in this mode: MultiPeer (`--peers-file` — one endpoint and port per
buddy would be needed). The relay fallback (`--peer-relay`)
works, but the relay
must authorize by source network (`--allow-cidr`), since there is no server to
mint a ticket — and a CIDR list cannot follow a buddy whose address keeps
changing, which is documented rather than papered over.

New: `lab/test-direct.sh` (offline: the working setup, an impostor refused on the
pin, and the record moving back), `lab/test-direct-dynv6.sh` (opt-in, against a
real provider; credentials in the git-ignored `secrets/`), `internal/role/direct.go`
with unit tests, and CLI tests covering every refusal above.

### Added — you do not need a rented VPS if one of the two buddies is reachable

`--role=buddy,handshake,relay` has always been accepted, so a pair in which one
side has a reachable address never needed a third machine. Nothing said so: the
README listed "one machine with a stable public address" as a requirement without
mentioning it may be one of the two buddies, and `docs/SETUP.md` carried a single
sentence with no instructions behind it. Documented now as
[step 0 of the setup guide](docs/SETUP.md#0-do-you-need-a-vps-at-all), with the
conditions measured rather than assumed:

- **Both UDP ports must be forwarded**, and the router must allow **NAT loopback**
  (hairpinning). Without it the setup does not work at all, and the coordinator
  logs `QUIC control dial failed`, which reads like a wrong key. Pointing
  `--server` at `127.0.0.1` does not work around it, because the relay is
  advertised to the partner under its public address.
- **A direct P2P tunnel is impossible in this topology, by construction.** A buddy
  offers the addresses its handshake server *observed*; when the buddy is that
  server, its registration never leaves the LAN, so the only candidate it can
  offer is private. The coordinator's own relay leg carries the tunnel
  (`via="handshake server as relay"`), which is why the relay role is not optional
  here.

New `lab/test-coordinator.sh` brings the whole thing up behind two simulated NAT
routers and covers the working setup plus those three failure modes;
`lab/entrypoint-nat.sh` gained a `fwd` mode (port forward + `NAT_HAIRPIN` switch)
for it. `TestAllInOneCoordinatorRoles` guards the role combination in CI, which
the Docker lab cannot do.

## [v5.3.3] — 2026-08-26

### Fixed (Security/DoS) — the buddy's own QUIC listener had no source validation

The **control** plane validates every source address with QUIC Retry
(`VerifySourceAddress`, added in v4.1.1) and pins that in a test. A buddy's
**data** plane — the tunnel socket itself — did neither, so the same weakness sat
one layer over: quic-go built a connection and ran a full TLS handshake (key
exchange plus signature, ~10s of state) for any well-formed Initial, **including a
spoofed one**, and answered forged source addresses while doing it. The pinned
partner key means none of that could ever reach the tunnel — this is a
CPU/memory cost an outsider could impose, not a way in.

Two changes, both in `internal/tunnel/quic.go`:

- **QUIC Retry for every unvalidated source**, verbatim the control plane's rule
  (no threshold to tune wrong). An unvalidated source now gets a small stateless
  token and nothing else. Costs one extra round trip on bring-up.
- **The listener is closed once a session is accepted.** A buddy has exactly one
  partner, so after bring-up the listener has no work left — and leaving it open
  kept a port answering strangers for the *whole life of the tunnel*, hours on a
  long transfer, not the seconds of connection setup. It survives a *failed*
  attempt, because the fallback chain (direct, then relay) listens again on the
  same socket and re-binding would lose the punched NAT mapping.

Verified in `lab/test-cgnat.sh`: cone NAT still comes up `via="direct P2P"` and
symmetric CGNAT still falls back to the relay, i.e. Retry breaks neither the hole
punch nor the relay splice. The new tests in
`internal/tunnel/dataplane_perimeter_test.go` fail against the previous code.

No protocol change and no `protocol.Version` bump — both changes are
transport-level, and Retry is part of QUIC itself, so a buddy on this version
pairs with one still on v5.3.2 unchanged.

### Fixed (Lab) — every lab image build was broken

v5.3.2's `.dockerignore` (`1fc21b5`) excluded `lab` wholesale, but the lab images
are built from the repo root and `COPY lab/entrypoint-*.sh` / `lab/pentest/` out of
it, so `docker compose build` failed with `"/lab/entrypoint-nat.sh": not found` —
and a run that skips the build silently uses a stale image instead. Two narrow
exceptions restore the builds while keeping the lab's runtime state (which is what
the exclusion is for) out of the build context.

## [v5.3.2] — 2026-08-25

### Fixed (Docs) — the IPv6 `srcmask` guidance stated the wrong mechanism

An external review measured the actual `ip6tables` hashlimit bucketing and it does
not match what v5.3.1's comment and this changelog claimed. `--hashlimit-srcmask`
is the prefix length hashlimit groups sources by, and there are **three** cases,
not two:

- **no mask (`/128`)** — one bucket per address. An attacker's `/64` multiplies its
  *own* throughput (measured 2169 vs 252 packets from 16 addresses), but the global
  `limit` still bounds the box, so a buddy in a *different* `/32` is **not** locked
  out (measured 94%). Multiplied buckets prove wasted fairness/bandwidth, not buddy
  starvation — the earlier "1245 vs 249" number showed the former, never the latter.
- **shipped `/32`** — caps an attacker's whole `/64` to one bucket (so "the
  per-source limit buys nothing", as v5.3.1 put it, was wrong). It only crowds out a
  buddy that shares the attacker's `/32` — same ISP-sized provider block, which the
  attacker cannot force (measured: 100% for a buddy in a different `/32`, 6% in the
  same one).
- **`/64`** — one bucket per subscriber allocation: the intended granularity,
  protecting a buddy in **all** cases.

The shipped `deployments/iptables.rules` now hoists the `srcmask 32 → 64` edit into
the quick-start header (next to the `icmp → icmpv6` edit) and states the three-case
mechanism at the rule and in the IPv6 section. The rule value is unchanged; iptables
(v4) still refuses a mask above 32, so the file documents the per-family edit rather
than carrying both. nftables was and is unaffected (it masks to `/64` in the rule).

Follow-up (not in this change): `lab/test-firewall-fairness.sh --ipv6` places the
attacker and buddy in the same `/32`, so its `32`-vs-`64` result rests on exactly
that co-location; a variant asserting a buddy in a *different* `/32` would make the
distinction explicit.

## [v5.3.1] — 2026-08-25

Follow-ups reported against v5.3.0. One of them is a real defect in a shipped
file, and it was introduced by v5.3.0 itself.

### Fixed — `deployments/iptables.rules` could not be loaded at all

Adding the per-source limit in v5.3.0 broke the rule across two lines with a
trailing backslash, for readability. **`iptables-restore` has no line
continuation** and rejects the whole file with ``Bad argument `\'``. nftables
tolerates the same edit, so a change verified against nftables looked fine while
the iptables ruleset had stopped loading. Rules are back on one line, and
`TestShippedIptablesRulesAreLoadable` now fails on a trailing backslash.

### Fixed (Security) — IPv6 per-source fairness needs an explicit /64 mask

`hashlimit` keys on the full address unless told otherwise. On IPv6 that is a
/128, while a /64 is what one subscriber routinely gets — so an attacker holding
a single /64 uses a different address per packet and collects a bucket for each,
and the per-source limit buys nothing. Measured with the extended lab test: five
attacking addresses in one /64 get **1245** packets through with /128 keying and
**249** with /64 keying.

`--hashlimit-srcmask 32` is now explicit in the file, with the ip6tables edit
(`32` → `64`) documented at the rule and in a dedicated IPv6 section; iptables(v4)
refuses a mask above 32, so one file cannot carry both. nftables was never
affected — it masks to /64 in the rule itself.

### Added — the fairness test covers all four combinations

`lab/test-firewall-fairness.sh` gained `--iptables` and `--ipv6`, so the shipped
iptables ruleset is now actually loaded and measured rather than assumed to match
the nftables one. The IPv6 runs flood from five addresses inside one /64 and
assert that the **whole prefix** was held to one source's share — without that
assertion the run was green even with /128 keying, because the buddy still
survives as long as the flood stays under the global ceiling. That is precisely
the kind of vacuously-green check this project has been bitten by before.

### Fixed (Docs) — the last M-01 leftovers

- Both firewall files introduced the two limits with "in this order" and then
  numbered them global-first, while the rules (correctly) run per-source first.
  Fixed, and gated by `TestShippedFirewallLimitsPerSourceBeforeGlobal`, which
  asserts the rule order in CI — the lab test measures the same property but
  needs root and minutes, so it cannot catch a swap on an ordinary change.
- `SECURITY.md` and `docs/PROTOCOL.md` called the invite "valid only until the
  first pairing" and corrected it two paragraphs later. Both now say it in one
  breath: the legitimate clients use it until the first successful pairing, and
  the server neither expires it nor marks it spent.
- `docs/PROTOCOL.md` had a link labelled `SETUP.md` pointing at `SECURITY.md`, an
  artifact of the consolidation's mass rewrite.

## [v5.3.0] — 2026-08-25

Closes an external re-audit of v5.2.1 (M-01, M-02, L-01) and, more importantly,
removes the thing that produced its findings: the same statement living in three
to five places, so that every sweep which changed the behaviour updated only some
of them. No protocol change — the wire format stays at v8.

### Changed (Security) — the handshake port is rate-limited per source, not just globally

`deployments/nftables.conf` and `deployments/iptables.rules` now limit the
handshake port with a **per-source meter first, then a global ceiling**. A plain
`limit` is attached to the rule rather than to the sender, so a single loud
source could spend the whole shared budget and crowd out legitimate pairings
(audit finding M-02).

The order is load-bearing, the same way the position of the
`established,related` accept is. A global limit is source-blind: put it first and
it drops a share of everybody's packets, the buddy you are protecting included.
Put the per-source meter first and the global ceiling only ever sees traffic that
has already been tamed.

Measured with the new [`lab/test-firewall-fairness.sh`](lab/test-firewall-fairness.sh)
— one flooding source, one legitimate buddy, counted against that buddy's
unopposed throughput:

| ruleset | buddy keeps |
|---|---:|
| global limit only (before) | 15% |
| global first, then per-source | 77% |
| per-source first, then global (now) | 100% |

This is not immunity, and the docs say so: many sources together still fill the
global ceiling, and traffic that saturates the uplink never reaches the firewall.

### Changed (Security, BEHAVIOUR CHANGE) — the shipped private server templates are fail-closed

`deployments/systemd/buddynet-handshake.service` and the `handshake` service in
`deployments/docker-compose.yml` now pass **`--authorized`**. They are the
templates for a PRIVATE matchmaker, and a private matchmaker that pairs anyone
holding a token is not what their users are asking for: the server never marks a
token spent, so one leaked invite is enough for two strangers to pair on your box
and draw tickets for your relay. That is your bandwidth, used by people you never
approved.

**What changes for you:** if you adopt the new templates, no buddy pairs until
you approve its key. The server logs the exact command at startup:

```
buddynet --authorized /var/lib/buddynet-handshake/clients.txt approve <CLIENT_KEY>
```

Nothing changes for a running server until you install the new unit — these are
templates, not something an upgrade rewrites.

**If you deliberately run an open matchmaker**, do not strip the flag: use
`deployments/systemd/buddynet-public-handshake.service`, which runs the
single-purpose `buddynet-handshake` binary — no allowlist, no writable state past
its identity key. That split is the point: open is a different service, not a
weakened private one.

### Fixed (Security) — a partly-failed `peers remove` now says what already holds

`peers remove` writes tombstone, then session, then manifest, so an abort leaves
the SAFE state (revoked, possibly still configured). That was already right. What
was wrong was the report: a failure in the last step returned the bare I/O error,
so the command printed

```
error: rename /peers.tmp.82.3 -> /peers: device or resource busy
```

while `peers list` right afterwards showed the buddy as REVOKED. An operator
reading that concludes the revocation did not happen and that the buddy still has
access — the dangerous direction to be wrong in for a revocation command. The
error now leads with what is true (the key is already refused at every
reconnect), names the cleanup as the part that did not finish, and says how to
finish or undo it.

### Fixed (Docs) — four security claims that had outlived the code

Traced to the commits that left them behind, not just patched where the audit
pointed:

- **`--authorized` does not gate the TLS handshake.** `a023614` added allowlist
  pinning there and `761b6fb` documented it; `0081a42` removed it again (a
  TLS-layer gate makes code-based enrollment unreachable) and updated only
  `docs/APPROVAL.md`. `docs/OPERATIONS.md`, `docs/WIREGUARD.md` and `--help` kept
  the old claim for four releases, and OPERATIONS.md quoted a log line the server
  had stopped printing. TLS authenticates every client by key; the allowlist
  decides per signed `REGISTER`.
- **`--allow-cidr` is pre-crypto on the relay only.** The README told operators a
  private relay/handshake "needs no separate firewall" — advice to drop the one
  layer that caps pre-TLS cost. `SECURITY.md` §5.5 had said so correctly since
  v5.2.1; three other places had not caught up.
- **`--join` is not a fixed-token legacy mode.** `--token` was removed in v5;
  both `--invite` and `--join` are one-time.
- **An invite is not short-lived server-side.** "One-time" is a client-side
  property; the server never marks a token spent.

Plus two ruins from earlier removals: a heading reading `## QUIC control plane,
the secure default)` and an `### Environment variable` section whose body was the
empty string `export   # equivalent to`, left over from `--quic-handshake`.

### Changed (Docs) — one source per topic

`docs/` goes from 11 files to 5 (22,100 → 17,434 words) and the README from 3,848
to 1,220:

```
TWO-BUDDIES + INVITE + APPROVAL + VPS-HOWTO  ->  docs/SETUP.md
PEERS + CONNECTIVITY + BUDDYDNS              ->  docs/OPERATIONS.md
```

Flags are no longer a documentation topic: three files carried their own flag
tables restating what `buddynet --help` prints. `--help` is the source now, and
three copy-paste traps in it were fixed (`-forward` with one dash beside
`--invite`, a misaligned COMMANDS block running past 80 columns, and `gen-token`
described as "a strong shared token" — the vocabulary of the removed `--token`).

### Added — gates that make the old wording unsayable

- `TestDocsDoNotRestateRefutedClaims` walks the **whole repository**, unlike the
  docs/-scoped firewall test, which is exactly why the README sentence survived
  the previous audit round. Each pattern must still match its own historical
  sentence, so a rotted pattern fails loudly instead of passing vacuously.
- `TestMarkdownLinksAndAnchorsResolve` checks links **and** `#anchors`.
  `TestDocReferencesExist` only reads Go source, so prose links were unprotected;
  this consolidation left one dead anchor that nothing else would have caught.
  Dead anchors are worse than dead files: GitHub serves the page and silently
  drops the fragment.
- `lab/test-firewall-fairness.sh`, and a regression test for the revocation
  reporting above.

One class is deliberately **not** gated: "before any crypto". Every pattern broad
enough to catch the wrong claim also matches `SECURITY.md` §5.5, which quotes the
same words to refute them.

### Fixed — both demo recordings, and what made them rot

The README GIF showed `--role=handshake,relay` **without `--relay-id`**, a
command that has exited 1 since v5.0.0, when the relay stopped starting without
an authorization policy. Root cause: `lab/demo-deploy.sh` *types* its command
lines for legibility while the output beside them comes from a real container, so
the typed line could drift freely — a second source that is never checked against
the first, the same shape as the documentation drift above.

`verify_cmd()` now runs each server command against the real binary before the
recording shows it, and the relay id is read from the running container.
`media/multipeer-demo.gif` was rebuilt too: it had become unreferenced and
unbuildable, and now shows the permanent revocation v5.2.0 introduced.

Four lab scripts fetched a key with `init`, which only prints on the first run
and refuses afterwards — one of them labelled its own check "(identity
subcommand)" while calling `init`. All four use the `init || identity` fallback
now, inside the substitution, because under `set -e` a failing command
substitution in an assignment ends the script before any check runs.

## [v5.2.1] — 2026-08-24

Documentation-integrity release from an external audit. **No protocol change, no
new flags, no behaviour change in the binaries** — but two of the findings were
security-relevant, because an operator following the documentation got a weaker
system than the repository ships. The build pipeline also gains SLSA provenance.

Ordered by what it means for you:

- **If you set up your VPS firewall by copying the example out of
  `docs/VPS-HOWTO.md`, re-apply `deployments/nftables.conf` (or
  `iptables.rules`).** The page carried an older copy in which the generic
  `established,related` accept sat *before* the UDP rate limits, which made the
  limit on the handshake port unreachable after the server's first reply. The
  shipped files were always correct.
- **If your handshake server serves only people you know, turn on approval mode
  (`--authorized`).** It is now documented as the recommended setting rather than
  optional hardening, because a leaked invite does not expire the way these docs
  used to claim.
- **From this release on, artifacts carry a SLSA build provenance attestation**
  in addition to the cosign bundles.


### Fixed (Docs/Security) — trust and DoS semantics stated accurately (M-01, M-03, L-01)

From the same external audit as the firewall finding. All three reproduced
against the code before anything was rewritten.

**M-01 — "before any crypto" was true of the relay and false of the handshake
server.** Several documents (and two flag help strings) promised that
`--allow-cidr` and the rate limits drop traffic before any cryptography. The
relay does exactly that: it owns its UDP read loop, and its fixed order is size
cap → CIDR → per-source rate → cookie → signature checks. The handshake server
cannot: the control plane is QUIC, and quic-go only hands over a connection whose
**TLS 1.3 handshake, Ed25519 client certificate included, has already completed**
— the source code said so all along (`internal/tunnel/control.go`), the docs did
not. New **SECURITY.md §5.5** names the actual boundary:

- a **spoofing** source gets a stateless QUIC Retry token and nothing else — no
  connection, no memory, no handshake;
- a source that can receive at its claimed address can make the server perform
  **one TLS handshake per connection attempt** before `--allow-cidr` or
  `--authorized` are consulted. Neither flag prevents that; they bound what comes
  after it. The firewall's rate limit on the handshake port is what bounds that
  cost — which is also why its placement before `established,related` matters.

**M-03 — "one-time invite" is a client-side property, not a server-side one.**
SECURITY.md claimed a leaked invite was "worthless after 15 min or after the first
connect". It is not: the handshake server keeps **no list of spent tokens**, and
`--invite-timeout` bounds how long the *inviter waits*. What a leaked invite
actually gets someone in open mode is now written out in `docs/INVITE.md`:

- a slot already held by both buddies refuses a third registration as a squat
  (`SECURITY: event=squat-rejected`; a slot holds two identities);
- a **free** slot lets two *foreign* keys pair **with each other**, drawing signed
  `PEER_LIST`s and, where enabled, relay tickets — unauthorised use of your
  matchmaker and bandwidth;
- your tunnel stays out of reach, because the buddy is pinned by key.

The server's open-mode startup log now says this too, rather than only mentioning
endpoint harvesting.

**Approval mode is now documented as the recommended setting for a private
server**, not as optional hardening: `docs/VPS-HOWTO.md` §8 leads with it and says
why, and `docs/APPROVAL.md` states what a token-holder can do — including the
stranger-pairs-stranger case it previously omitted.

**L-01 — `docs/PROTOCOL.md` still described the relay's address-validation cookie
as `HMAC(key, epoch‖src-IP)`.** It has bound the **port** as well since v5.1.1;
without it, two hosts behind one NAT could hijack each other's leg. The
implementation was fixed then, the table was not.


### Fixed (Security) — the VPS guide documented a weaker firewall than it ships

Reported externally, reproduced here against `main`. `deployments/nftables.conf`
and `deployments/iptables.rules` are correct; **`docs/VPS-HOWTO.md` carried its
own, older copy of the ruleset**, and that copy was the one with the hole in it.
An operator who followed the page instead of applying the file got:

- **`ct state established,related accept` placed BEFORE the UDP rate limits.**
  Netfilter marks a UDP flow established once it has seen traffic in both
  directions, so after the server's first answer every later packet of that
  5-tuple matched the generic accept and the 100/s limit was never reached — on
  exactly the 24/7 port the limit exists to protect. The shipped files put the
  UDP rules first *and* drop the excess explicitly, and say why in a comment.
- **A 100 packets/s cap on the relay port**, which carries tunnel *data*. That
  throttles legitimate traffic and is not a bandwidth budget. The shipped files
  deliberately leave that port unlimited and point at `--allow-cidr` and traffic
  shaping instead.
- The page also called the two rulesets "the exact same policy" with "two
  rate-limited UDP ports" — neither is true any more.

The page no longer carries a second copy of the ruleset at all: it describes what
the shipped file does and why the ordering is load-bearing, and tells you to
apply the file. **`TestDocsDoNotRestateShippedFirewall`** enforces that no
document under `docs/` restates a BuddyNet UDP filter rule. It is proven against
the real case: restore the old `docs/VPS-HOWTO.md` and it fails, naming the
copied rule. It also fails loudly if the pattern stops matching the shipped
files, so it cannot go vacuously green. Same failure class as A-05, one artifact
over — see `internal/flagdrift`.

### Fixed — leftovers from removing `--quic-handshake`

Protocol v8 removed the flag and made the control plane QUIC/TLS 1.3
unconditional. The prose that used to explain the switch was edited down but not
repaired, leaving instructions that were wrong and, in one place, harmful:

- `docs/VPS-HOWTO.md` told operators to "turn on the encrypted control plane" by
  adding a **bare `Environment=`** to a systemd override — twice, once directly
  above an `ExecStart` that expands `${BUDDYNET_LISTEN}`. An empty assignment
  **resets every `Environment=` the unit set**, and the handshake unit sets
  `BUDDYNET_LISTEN=[::]:51820`, so following that instruction would start the
  service with an empty `--listen`. Both occurrences are gone, and the override
  example now assigns a value; the trap is documented where it can be stepped in.
- `deployments/systemd/README.md` still described the control plane as
  "defaults to UDP" with QUIC as an option, and its sentence was cut mid-string.
- `docs/VPS-HOWTO.md` said approval mode rejects outsiders "at the TLS
  handshake". It does not: TLS authenticates the key, and the allowlist decision
  is made when the signed `REGISTER` is handled (`authz.allowed` in
  `internal/role/handshake.go`). An unapproved client completes TLS and is
  refused before any pairing state exists for it.
- Both shipped firewall files claimed in their own headers that "the UDP ports
  are rate-limited", contradicting the rule comment a few lines below. Corrected
  to name the handshake port.
### Added — `docs/CONNECTIVITY.md`, and a test that keeps such pointers alive

- **`docs/CONNECTIVITY.md`.** The "no path to the partner" error already told
  operators to read that file (`noPathAdvice` in `internal/role/connect.go`) —
  but the file did not exist. A dead link, handed to somebody at the moment
  nothing works. It now covers what the fallback chain tried, why hole punching
  fails structurally behind symmetric NAT or CGNAT, and what actually fixes it.
- It also states plainly what does **not** fix it: forwarding a port to the
  buddy. A buddy binds an *ephemeral* UDP port (`net.ListenUDP` with `Port: 0`),
  so the number changes on every start and there is no flag to pin it. Port
  forwarding applies to the VPS side, not to a buddy.
- **`TestDocReferencesExist`** — every `docs/*.md` path named anywhere in this
  module's Go sources must resolve to a real file. The dead pointer above
  survived because a missing file is not a compile error and no test read the
  string. Proven to fail on the real case, not just to pass: with
  `docs/CONNECTIVITY.md` moved away, the test goes red naming
  `internal/role/connect.go`.


### Added — SLSA build provenance for release artifacts

- The release workflow now generates a **SLSA build provenance attestation** for
  both shipped binaries (`actions/attest`, pinned by commit SHA), alongside the
  existing keyless cosign bundles. Verified with:

  ```bash
  gh attestation verify buddynet-linux-amd64 --repo TZERO78/buddynet
  ```

  That command needs **GitHub CLI 2.49 or newer** (where the `attestation`
  command set landed); the docs say so, because distribution packages lag —
  Ubuntu 24.04 ships 2.45, which just answers `unknown command "attestation"`.

  This is additive: nothing about the cosign bundles, checksums or SBOM changes.
  The two checks are not redundant — the cosign bundle is a file next to the
  binary and verifies **offline**, while the attestation is fetched from GitHub
  and additionally binds the artifact to the source commit it was built from. It
  is therefore worth nothing if GitHub itself is your adversary; the bundle plus
  a rebuild remains the check that does not depend on GitHub.
- The build job gains `attestations: write`. It deliberately does **not** take
  `artifact-metadata: write`: that permission only covers storage records, which
  require `push-to-registry`, and this job attests files rather than an OCI image.
- **Attestations exist only for releases built after this change.** For v5.2.0
  and older, `gh attestation verify` correctly reports that it found none — the
  README and SECURITY.md §8.3 say so rather than implying blanket coverage.


### Changed — toolchain and pinned base images

- **Toolchain pin moved from `go1.26.6` to `go1.26.7`** in `go.mod`, and the
  `FROM golang:` line in `deployments/Dockerfile` moved with it (exact version
  **and** digest, `sha256:28d89ee9…`) — that build path does not read `go.mod`,
  so the two pins have to be bumped together or they drift apart (A-07).
  go1.26.7 is a bug-fix release for `net/http`; the last security fixes were in
  go1.26.6, so this is not a security-driven bump.
- **Deliberately not go1.27.x.** Go 1.27.0 was released the same day as 1.26.7
  and is a fresh major release. Building, `go vet` and `go test -race` all pass
  under go1.27.0 here, so nothing blocks the move — it is simply left for a
  separate, deliberate step once that line has had a patch release or two.
- The version-drift explanation above the toolchain gate in `ci.yml`,
  `fuzz.yml` and `release.yml` no longer names a specific patch version. The
  gate itself always read the `toolchain` line dynamically; only the comment
  had to be re-edited on every bump, which is the same drift it warns about.
- `deployments/Dockerfile` runtime base bumped to the current
  `gcr.io/distroless/static:nonroot` digest (`sha256:1c2c046…`).
- `github.com/miekg/dns` 1.1.72 → 1.1.73. Upstream replaced its `tools.go` with
  a `tool` directive, which drops **three indirect dependencies**
  (`golang.org/x/mod`, `golang.org/x/sync`, `golang.org/x/tools`) from this
  module's graph. No API change; BuddyDNS is unaffected.

### Fixed (Security) — three findings from the parallel 2026-08-20 audit pass

These were reproduced on `main` **after** v5.2.0 shipped, from a second audit
branch whose tests had not been merged. All three are low severity; all three had
a reproducing test before they had a fix.

- **The `-L` Unix socket existed group/world-accessible before it was chmodded.**
  `net.Listen` creates the socket with `0777 &^ umask` and the listener starts
  accepting immediately, so narrowing it on the next statement closes a door
  somebody may already be through — and `-L` has no authentication of its own:
  the file mode **is** the access control, and whoever connects is spliced onto
  the tunnel to the partner. The window was measured, not assumed: an observer
  polling the path saw it open in 127 of 200 rounds. The socket is now created
  owner-only under a tightened umask, with the `chmod` kept as a second layer.

- **`REGISTER.Role` was neither validated nor bounded, and was retained.** Every
  neighbouring field is length- or format-checked; this one was stored verbatim,
  up to the 8 KB request cap, which worked out to tens of megabytes of
  attacker-chosen bytes held in a registry whose stated purpose is bounded
  memory. Nothing in the tree ever read it back, so the field is gone. The wire
  field remains (it is covered by the signature); the server simply keeps
  nothing from it.

- **Evicting the stalest pairing scanned the whole table under the global lock.**
  Once the token table was full — which a client can cause, since it picks its
  own token — every registration carrying a fresh token walked all 4096 buckets
  while holding the one mutex every registration needs: ~300 µs per packet
  against ~1.3 µs on an empty table, about a third of the server's own admitted
  packet budget spent where nothing else can proceed. Eviction now samples eight
  buckets and takes the oldest of those: **~2.8 µs per packet**, a hundredfold
  less lock time. The trade is deliberate and documented — the victim is the
  oldest of a sample, not the globally oldest. A test pins the age bias
  (aged buckets were evicted 100 out of 100 times) and fails if the sampling is
  removed.

## [v5.2.0] — 2026-08-20

Hardening release from the 2026-08-20 audit: it closes two controls that were
failing **silently** — a `--peer-key` that stopped being consulted, and a
revocation a still-running buddy could undo — plus the shipped systemd unit that
could not start, a self-test that reported green while authorizing nothing, and a
toolchain pin that did not pin.

**Two behaviour changes to know before you update:**

1. A `--peer-key` that contradicts the key stored from an earlier pairing now
   **refuses the connection** instead of being ignored. If your buddy rotated
   their key and you updated the flag, you also have to drop the stored session:
   `peers remove <old key>`, then pair again with a new invite.
2. `peers remove` (and *Forget buddy* in the Unraid plugin) is now **permanent
   until you lift it** with `peers allow`. A revoked buddy cannot return through
   a stored session or an old bootstrap token.

No wire-format change: `protocol.Version` stays at **8**, so v5.1.x and v5.2.0
nodes pair with each other.

### Changed (Security, BEHAVIOUR CHANGE) — `--peer-key` is enforced on every connect

- **`--peer-key` stopped being consulted as soon as a buddy had paired once.**
  On a reconnect the pin came from the stored session (`known_peers`), and the
  branch that compares it never reached the code that enforces `--peer-key`. So
  changing the flag — which `SECURITY.md` §8.2 offered as one of four ways to
  revoke a buddy — silently did nothing: the old key kept connecting.

  Now **both** pins must match. If the configured `--peer-key` contradicts the
  stored session pin, the buddy **refuses to connect at all**, and it stops
  *before* registering with the handshake server — both keys are local, so the
  outcome is already decided and there is no reason to hand the server this
  node's rendezvous token and observed endpoints for a pairing that must not
  happen. The partner key the server (or the offline cache) then vouches for is
  checked against both pins as well, which covers the other case: a server that
  names a different partner.

  **What you may notice:** a node whose buddy legitimately rotated its key, and
  whose `--peer-key` was updated to the new one, is now refused instead of
  quietly connecting to the old key. That refusal is the point. It names both
  keys and the way out:

  ```
  buddynet --known-peers <path> peers remove <old key>   # or "Forget buddy" in the plugin
  ```

  followed by a new invite. The stored session is **not** deleted automatically —
  a mismatch is a suspicion, not an instruction to destroy state.

  **`--peer-key` is deliberately not enforced** where it cannot mean one buddy:
  it is already rejected together with `--peers-file`, and with several stored
  sessions and no manifest the buddy now logs a `WARNING` instead of pretending
  the flag applies.

### Fixed (Security) — a revoked buddy stays revoked

- **`peers remove` could be undone by the buddy process that was still running,
  and the undo survived the `SIGHUP` the command told you to send.** The removal
  dropped the manifest line and the stored session, and both files were correct
  immediately afterwards — but the running worker still held the bootstrap token
  in memory from when it started. With the session gone it fell back to that
  token, re-paired, and wrote the session line back; since the worker set is the
  manifest UNION the stored sessions, the `SIGHUP` restarted the buddy as a
  session-only peer. The revocation was gone, and it stayed gone across restarts.

  Revocation is now a **permanent local list of keys** (`<known_peers>.revoked`,
  `0600`, atomically written). The presence of a key IS the revocation: no
  expiry, no garbage collection — a tombstone that ages out is precisely when the
  zombie comes back. It is enforced at every door: the reconnect attempt (the
  worker stops with `peer-stopped … buddy revoked`), `saveSession` (no session
  can be stored for a revoked key), `learnPeer` (no trust-on-first-use), the
  trust decision itself, and the worker set assembled on `SIGHUP`.

  `peers remove` also stopped reading the bootstrap token from the copy frozen at
  worker start — it re-reads the manifest each round, so a removed entry takes
  effect immediately rather than at the next restart.

- **Lifting a revocation is now possible, and explicit.** `peers allow <key>`
  lifts one (no manifest needed — the single-buddy setup the Unraid plugin runs),
  and `peers add` on a revoked buddy lifts it instead of reporting
  `already listed`, which is what used to leave a buddy silently locked out with
  no way back. Pair again with a **new** invite: the old session secret is gone.
  `peers list` shows revoked buddies with status `REVOKED`.

- **The whole local trust state is written under one lock, in a fixed order.**
  Manifest, session lines, TOFU lines and revocations are one state, not four.
  Revoking writes tombstone → session → manifest; allowing runs the other way,
  so a crash between any two steps leaves the *safe* side (refused) rather than
  "no longer configured but still allowed back".

- **`learnPeer` took no lock at all (A-02).** Every other writer of `known_peers`
  does a locked read-modify-write; this one was a bare `O_APPEND`, so a
  trust-on-first-use line written inside another writer's window was lost when
  that writer renamed its snapshot into place. It now takes the same lock and
  writes the same atomic way.

- **The peers manifest was written with a plain `os.WriteFile` (A-12)** — neither
  atomic nor locked, the one trust file left out. A crash mid-write left a
  truncated YAML, which reads as "no buddies". It now goes through the same
  atomic rename as everything else.

### Fixed (Supply chain) — the toolchain pin did not pin

- **`go.mod` declared `toolchain go1.25.13`, and the shipped v5.1.1 binary was
  built with go1.26.6.** The `toolchain` directive is a minimum/preference, not a
  ceiling: under `GOTOOLCHAIN=auto` a newer installed toolchain wins, and
  `setup-go` with `go-version: stable` installs the newest. Three official build
  paths, two Go versions.

  The reproducibility mismatch is not the damage. The damage is that
  **`govulncheck` covered the 1.25.13 standard library, not the one in the
  artifact** — the blocking CVE gate was scanning a different stdlib than the one
  being released.

  Pinned **forward**, to the version that actually produced the release:
  `toolchain go1.26.6` in `go.mod`, `go-version-file: go.mod` in ci/release/fuzz
  (setup-go honours the `toolchain` line since v6, and it wins over the `go`
  line), `GOTOOLCHAIN: local` so nothing can fetch anything else, and
  `golang:1.26.6-alpine` **by exact version and digest** in the Dockerfile. The
  `go` line stays at 1.25.0, so a distro packager on Go 1.25.x with
  `GOTOOLCHAIN=local` can still build; only `GOTOOLCHAIN=auto` fetches 1.26.6.
  `govulncheck` against 1.26.6: no vulnerabilities.

  Reproducing a release build (the `--depth 1 --no-tags` is **not** optional —
  with tags, Go stamps a different module version into the binary and the hash
  will not match):

  ```bash
  git clone --depth 1 --no-tags --branch vX.Y.Z https://github.com/TZERO78/buddynet
  cd buddynet
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=go1.26.6 \
    go build -trimpath -ldflags="-s -w -X main.version=vX.Y.Z" -o bn ./cmd/buddynet
  sha256sum bn   # == buddynet-linux-amd64.sha256
  ```

### Fixed — an interrupted `flock` no longer looks like a refused lock

- The advisory file lock waited with a single `flock(LOCK_EX)` and reported any
  error as "cannot lock". That wait sits in the kernel, and the Go runtime's
  asynchronous preemption delivers `SIGURG` to running threads, so an unrelated
  preemption can return `EINTR` — which, with the deliberate fail-closed policy,
  would turn a scheduling event into a refused write. The wait is now retried on
  `EINTR`. This is hardening, not a fix for an observed failure: it was suspected
  behind a flaky test, but the flake turned out to be the test's own doing (it
  left a goroutine parked on the lock, which then wrote into a temp directory the
  framework was already removing). The retry is correct regardless; the test now
  drains that goroutine.

### Fixed — the shipped public-handshake systemd unit could not start

- **`deployments/systemd/buddynet-public-handshake.service` passed
  `--quic-handshake`**, which protocol v8 removed. The binary exits 2 on an
  unknown flag, so the service failed on every start for a full release, and
  nothing in CI ever looked at a shipped file. The flag is gone from the unit.

  Two texts recommended the same removed flag — one of them inside a *security*
  warning printed when approval mode is off, which is the worst place to send an
  operator after a flag that makes the binary refuse to start. Both now say what
  is true: the control plane is QUIC/TLS 1.3 unconditionally since v8, so there
  is nothing to select and no flag to select it with. (A leftover half-sentence
  in the README from the same removal is fixed too.)

- **New gate: flag drift.** Both binaries now register their flags in one
  `registerFlags(fs *flag.FlagSet)`, and a test enumerates them through a
  throwaway `FlagSet` — asking the flag package itself rather than pattern-
  matching `main.go`, because a pattern is a second definition that can drift
  from the first. It scans the *active* artifacts only (systemd units, the
  compose file, the Unraid plugin, the lab scripts) by explicit list: the
  CHANGELOG and `docs/plans/` are supposed to name removed flags, and a gate with
  false alarms gets switched off. It ignores comments, and it resolves `$BIN`
  per file, so a lab script pointing that name at another tool is not charged to
  buddynet. A positive control plants a removed flag in a temporary artifact and
  requires the scan to report it — a gate that silently matches nothing looks
  exactly like a clean run.

  CI additionally runs `systemd-analyze verify` over the units, with the binaries
  installed first so `ExecStart` resolves. To be honest about it: that validates
  the *unit*, not whether the binary accepts the flags, and it would **not** have
  caught this finding. The flag-drift test is the gate; `systemd-analyze` is the
  complement. `systemd-analyze security` runs informational only — its score
  moves with the systemd version.

### Fixed — `docker compose up relay` pulled an old release

- The compose file had `build:` on the handshake service and a
  `ghcr.io/tzero78/buddynet:v5.0.0` tag on **both**. `up --build` built locally
  and tagged the result v5.0.0, but starting the relay on its own **pulled**
  v5.0.0 from the registry — a different, older binary than the rest of the
  deployment, silently. Both services now build from this checkout and carry a
  local tag; nothing is pulled. The file documents the release-deployment
  variant explicitly: no `build:` at all, both services pinned to the same
  immutable **digest** — never a floating tag, and never a digest next to a
  `build:`.

### Added — the relay ticket verifier is fuzzed nightly

- `internal/ticket`'s `FuzzParse` and `FuzzVerify` were shipped but missing from
  the nightly fuzz matrix — the one parser that is permanently reachable from the
  internet on every relay bind. Both are in it now.

### Removed — dead code and comments that described a vanished world

- `clonePending` and the `authorizer.writeMu` field have been unreachable since
  the stateless-server rewrite (v5.0.0): there is no pending file to snapshot or
  serialise any more. `go vet` does not see unused unexported functions or
  fields, so they sat there. The CI comment listing gosec exclusions named two
  rules (`G123`, `G703`) that the command has not excluded for some time — the
  comment was *stricter*-wrong than reality, but wrong.

### Fixed (Testing) — the pentest probe was authorizing nothing on the relay

- **Two relay scenes reported PASS without a single leg ever being admitted.**
  The relay has verified tickets since v5.0.0, but the probe still bound legs
  with a bare session token, so every bind was dropped at the ticket gate. For
  `relay-3rd-leg` and `wg-relay-blind` that showed up as a FAIL for the wrong
  reason; for `relay-reflection` and `relay-hoard` it showed up as **green**,
  because "no ack" means both "the cap held" and "refused for want of a ticket"
  and the probe could not tell them apart.

  The relay scenes are rebuilt around the real scheme: the probe registers two
  buddies with the handshake server, collects the signed permits it issues, and
  binds with a proof of possession over the relay's current cookie — exactly as a
  buddy does. Every scene now starts from a pair that **demonstrably forwards**
  before it asserts that anything is refused. New scenes cover a captured ticket
  without (and with a forged) proof, a bind claiming a session its ticket does not
  name, a fresh valid ticket that must not displace a leg held by another
  ephemeral key, a ticket minted for a different relay id, and the per-source leg
  cap — the last one against a relay started with `--relay-max-legs-per-ip 2`, so
  two legs are accepted and forwarding before the third is refused. Verified by
  falsification: pointed at an uncapped relay, the cap scene fails.

  `./lab/pentest/run-probe.sh`: 26 passed / 2 failed before, 32 passed / 0 failed
  after, with the relay's own refusal reasons asserted in the server log.

### Added (Testing) — a live revocation lab, with the old binary as the control

- `lab/test-revocation.sh` runs the operator's actual sequence on loopback: pair
  two buddies through their manifests, pull a payload across, revoke one **while
  the other is running**, then `SIGHUP`, then a full restart — and finally allow
  it back and require the tunnel to return, because a revocation has to be a door
  and not a wall. It counts a completed tunnel *or* a re-verified partner as
  "came back": a pairing that gets as far as `partner-verified` has already
  defeated the revocation, and on loopback the hole punch that follows is the
  flakier half.

  The A/B is external: the same scenario runs a second time against the binary
  built from the audited commit, which **must** show the resurrection. Without
  that half, "nothing came back" is also what a broken harness produces — and the
  first two versions of this lab were exactly that, one counting `DISCONNECTED`
  as a new connection (it ends in `CONNECTED:`) and one restarting a buddy with
  empty paths because bash functions do not close over another function's locals.

### Changed — Unraid plugin: "Forget buddy" is a real revocation now

- The button used to wipe `known_peers` and restart the service. That was never a
  revocation: the buddy key and the invite live in `buddynet.cfg` on the flash,
  untouched by the wipe, so the same buddy re-paired within seconds — and the
  dialog claimed the key would be "re-learned on the next connect
  (trust-on-first-use)", which cannot happen at all in the plugin (it always runs
  `--no-interactive`, where an unknown key is refused, never learned).

  It now runs `peers remove` for the configured buddy — tombstone plus session —
  and leaves the service stopped, because the node has no buddy any more. A new
  **Allow buddy again** button lifts the revocation and starts the service; it
  refuses unless a key *and* an invite are configured, so the revocation is never
  lifted before there is something new to pin. `reset identity` and uninstall
  still delete everything, revocation list included — there the identity is gone,
  so there is nothing left for a tombstone to protect.

### Fixed (Docs)

- `SECURITY.md` §8.2 claimed that *removing* the `--peer-key` pin revokes a
  buddy. It does not, and it will not: with no pin there is nothing to compare
  and the stored session pin governs. Revocation is `peers remove <key>` (or
  "Forget buddy") **plus a new invite**; the section now says so.

## [v5.1.1] — 2026-08-19

### Fixed (Security) — the relay cookie now covers the source PORT

- **A captured relay bind could be replayed from another port behind the same
  public IP, and the relay would follow it.** The address-validation cookie was
  `HMAC(key, epoch ‖ source-IP)` — no port — while everything else that
  identifies a leg (the forwarding map, the migration check) compares full
  `IP:PORT` addresses. It was the one place two different addresses looked alike:
  an on-path observer sharing the public IP (same NAT or LAN) could replay a
  verbatim capture from a different source port; the cookie still validated, the
  proof of possession covers exactly that cookie so it still verified, and the
  relay read the result as a legitimate NAT migration and moved the leg to the
  attacker's address.

  **Impact:** redirection of the buddy's relayed traffic, i.e. a denial of
  service and a metadata leak. **No plaintext is exposed** — the tunnel is
  end-to-end encrypted and the relay never holds a key to it — and this does not
  reopen the relay to strangers: it needs a captured valid bind *and* the same
  public IP.

  The cookie is now `HMAC(key, epoch ‖ source-IP ‖ source-port)`. A legitimate
  mover is unaffected: a bind from a new address draws a challenge for **that**
  address and the buddy re-signs the proof with its ephemeral key — which is
  exactly what a captured bind cannot do. No wire-format or protocol change.

- **The test that was supposed to cover this proved nothing.**
  `TestCapturedBindIsUselessElsewhere` minted a second cookie to compare against
  the first, but within one 30 s epoch both mints return the same bytes, so its
  assertion sat behind an `if` that was never true. It now builds a genuinely
  different, simultaneously-valid cookie (the previous epoch, which `validCookie`
  still accepts) and additionally asserts the positive control, so the negative
  case cannot pass for the trivial reason that an old cookie is refused.
  Two new tests cover the port case directly, including the leg-hijack itself.

### Fixed (Privacy) — the leg-cap warning no longer names the source

- `SECURITY: event=leg-cap-hit` printed the source accounting key (an IPv4
  address or an IPv6 `/64`) unconditionally, contradicting the guarantee stated
  in `docs/OPERATIONS.md` and enforced everywhere else in the relay: **a shipped
  relay log does not record who used it.** The address now appears only under
  `--debug`, like every other address the relay logs; without it the operator
  still sees that a source is at the cap. `lab/test-relay-accounting.sh` asserts
  both halves — and its `/64` check, previously an `info` that could never fail,
  is now a real assertion.

### Fixed — the security docs described the protocol we no longer speak

`docs/PROTOCOL.md` still said `Version: 7` (the code has been at 8 since v5.0.0),
its migration guide walked through v6 → v7, and it printed the removed
plain-UDP `COOKIE` exchange as if it were current. `docs/ARCHITECTURE.md` still
offered a choice of two handshake transports with plain UDP as the **default**,
and `SECURITY.md` had two sentences left broken mid-clause by an earlier edit
that removed `--quic-handshake` (*"Set the same transport on the server and every
buddy, or; a mismatch…"*). All corrected to the shipped design: QUIC-only control
plane, protocol 8, with what was removed and why kept as an explicit note rather
than silently dropped.

## [v5.1.0] — 2026-08-19

### Added — the invite carries the inviter's identity

- **`--invite` now mints `bnet1.<token>.<public-key>` instead of a bare token,
  and `--join` pins the key inside it.** The invite already travelled over a
  channel the two people trust (phone, Signal); it now carries an *identity*
  over that channel and not just a secret. The joining side pins the inviter
  before it ever contacts the handshake server, so a hostile or compromised
  server cannot put a different buddy on that end — it is refused, with no human
  comparing anything. That direction is now exactly as strong as `--peer-key`,
  by default, with no extra step for the user.

- **First contact is asymmetric, and the remaining human step cannot be
  self-satisfied.** The joiner (already pinned) only **displays** its
  six-character code; the inviter **types that code in and is shown no code of
  its own**. Previously both ends showed the same code and both typed one, which
  left a way out for someone in a hurry: type what is on your own screen and
  never make the call. Under a man in the middle that shortcut confirms the
  attack on both ends at once. With nothing on screen to copy, the six
  characters can only have come from the buddy.

- A **bare** token from an older inviter still pairs, by trust-on-first-use with
  the symmetric code as before. A **malformed** `bnet1.…` invite is an error —
  never a silent fall back to the weaker unpinned path. A `--peer-key` that
  contradicts the key inside the invite is refused rather than resolved.

- **Client-side only: no protocol change, no `protocol.Version` bump.** The
  handshake server still sees nothing but the opaque rendezvous token; the blob
  and the key never go on the wire. Old and new peers interoperate.

- **Headless nodes:** a joiner with a key-bearing invite is unattended-safe (it
  has nothing to confirm, and logs its code). The **inviter** is the verifying
  side and needs a terminal — for an unattended inviter, pin the joiner with
  `--peer-key` as before. See *Daemon setup* in
  `docs/INVITE.md`.

### Changed

- Dependency bumps: `golang.org/x/crypto` 0.54.0 → 0.55.0, and the
  `distroless/static` base image for the shipped container.

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
  `docs/PEERS.md`.

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
  See `docs/BUDDYDNS.md`.
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

[Unreleased]: https://github.com/TZERO78/buddynet/compare/v5.4.0...HEAD
[v5.4.0]: https://github.com/TZERO78/buddynet/compare/v5.3.3...v5.4.0
[v5.3.3]: https://github.com/TZERO78/buddynet/compare/v5.3.2...v5.3.3
[v5.3.2]: https://github.com/TZERO78/buddynet/compare/v5.3.1...v5.3.2
[v5.3.1]: https://github.com/TZERO78/buddynet/compare/v5.3.0...v5.3.1
[v5.3.0]: https://github.com/TZERO78/buddynet/compare/v5.2.1...v5.3.0
[v5.2.1]: https://github.com/TZERO78/buddynet/compare/v5.2.0...v5.2.1
[v5.2.0]: https://github.com/TZERO78/buddynet/compare/v5.1.1...v5.2.0
[v5.1.1]: https://github.com/TZERO78/buddynet/compare/v5.1.0...v5.1.1
[v5.1.0]: https://github.com/TZERO78/buddynet/compare/v5.0.0...v5.1.0
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

#!/usr/bin/env bash
# BuddyNet relay accounting test (finding H-01: one IPv6 /64 must be ONE budget)
# =============================================================================
# The relay's abuse budgets — the per-source bind rate limit and the per-source
# leg cap — used to be keyed by the EXACT source address, while the control plane
# aggregated IPv6 to a /64. Every address inside a /64 is free to mint, so one
# /64 handed an attacker an unlimited supply of "distinct sources": enough to
# fill the relay's global session table and lock out unrelated users.
#
# Both sides now derive their key from internal/netkey (IPv4 per address, IPv6
# per /64, IPv4-mapped unmapped first). This test proves that end to end against
# the REAL relay binary, with legs claimed through the REAL client path
# (relay.BindLeg) — so every leg completes an honest cookie challenge round-trip
# from its own address.
#
#   bnacct-a (attacker)                        bnacct-r (relay)
#     veth fd00:cafe::2/64      <----->        veth fd00:cafe::1/64
#     65 addresses fd00:beef:1::1..65  (ONE /64)
#      1 address   fd00:beef:2::1     (a different /64)
#
# Everything runs in two throwaway network namespaces with ULA addressing only.
# Nothing touches the host network or any external system.
#
# Prerequisites: root (sudo), ip/netns. No Docker, no lab/.env.
#
# Usage (from the repo root or lab/):
#   sudo -v && ./lab/test-relay-accounting.sh
#
# To watch it FAIL against a pre-fix build (A/B control):
#   BNBIN=/path/to/old/buddynet ./lab/test-relay-accounting.sh

set -u
cd "$(dirname "$0")/.."

NSA=bnacct-a
NSR=bnacct-r
PORT=51821
MAXLEGS=64          # per-source leg cap for the first scenario
# This lab drives the relay with a raw flood tool that holds no ticket — it is
# testing the PER-SOURCE ACCOUNTING, not the authorization. So the relay runs in
# network mode, which is also the only policy a lab like this can use: with
# tickets, every one of these binds would be refused before it reached the
# accounting that is under test. A relay must have SOME policy since v5.
LABNET=fd00::/16
DPORT=51822
DMAX=64             # global session cap for the DoS scenario
DLEGS=8             # per-source cap — a FRACTION of the global cap, mirroring the
                    # shipped defaults (64 legs vs 4096 sessions). Setting the two
                    # equal would make the per-source cap meaningless by design.
TMP=$(mktemp -d /tmp/bnacct.XXXXXX)

PASS=0; FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
info() { printf '  ....   %s\n' "$*"; }
ns()   { sudo -n ip netns exec "$1" "${@:2}"; }

cleanup() {
  for n in "$NSA" "$NSR"; do
    sudo -n ip netns pids "$n" 2>/dev/null | xargs -r sudo -n kill 2>/dev/null
    sudo -n ip netns del "$n" 2>/dev/null
  done
  echo "logs kept in $TMP"
}
trap cleanup EXIT

if ! sudo -n true 2>/dev/null; then
  echo "BLOCKER: this test needs passwordless sudo (network namespaces)." >&2
  exit 1
fi

say "build"
BNBIN="${BNBIN:-$TMP/buddynet}"
if [ "$BNBIN" = "$TMP/buddynet" ]; then
  go build -o "$TMP/buddynet" ./cmd/buddynet || { echo "build failed"; exit 1; }
fi
go build -o "$TMP/relayflood" ./lab/pentest/relayflood || { echo "build failed"; exit 1; }
info "relay binary: $BNBIN"

say "topology"
cleanup 2>/dev/null
for n in "$NSA" "$NSR"; do sudo -n ip netns add "$n"; ns "$n" ip link set lo up; done
sudo -n ip link add vA type veth peer name vR
sudo -n ip link set vA netns "$NSA"
sudo -n ip link set vR netns "$NSR"
ns "$NSA" ip -6 addr add fd00:cafe::2/64 dev vA
ns "$NSA" ip link set vA up
ns "$NSR" ip -6 addr add fd00:cafe::1/64 dev vR
ns "$NSR" ip link set vR up

SRC=""
for i in $(seq 1 65); do
  ns "$NSA" ip -6 addr add "fd00:beef:1::$i/128" dev vA
  SRC="$SRC,fd00:beef:1::$i"
done
ns "$NSA" ip -6 addr add fd00:beef:2::1/128 dev vA
SRC="${SRC#,}"
ns "$NSR" ip -6 route add fd00:beef::/32 via fd00:cafe::2

for _ in $(seq 1 20); do
  ns "$NSA" ip -6 addr show dev vA | grep -q tentative || break
  sleep 0.5
done
if ns "$NSA" ip -6 addr show dev vA | grep -q tentative; then
  bad "addresses still tentative after DAD wait"; exit 1
fi
info "attacker holds $(ns "$NSA" ip -6 addr show dev vA | grep -c 'inet6 fd00:beef') addresses"

if ns "$NSA" ping -6 -c1 -W2 fd00:cafe::1 >/dev/null 2>&1; then
  ok "IPv6 transport A<->R up"
else
  bad "no IPv6 connectivity between the namespaces"; exit 1
fi

say "start the relay (--relay-max-legs-per-ip $MAXLEGS)"
# --debug ON PURPOSE: the leg-cap warning names its accounting key only in debug
# mode (a shipped relay does not log who used it), and the /64 in that key is
# exactly what this test has to see. The second relay below runs WITHOUT it, so
# the other half of that rule gets checked too.
ns "$NSR" "$BNBIN" --role=relay --relay-listen "[fd00:cafe::1]:$PORT" \
    --allow-cidr "$LABNET" --debug \
    --relay-max-legs-per-ip "$MAXLEGS" --relay-max-sessions 4096 --ttl 600s \
    > "$TMP/relay.log" 2>&1 &
for _ in $(seq 1 20); do grep -q "action=listening" "$TMP/relay.log" 2>/dev/null && break; sleep 0.5; done
if grep -q "action=listening" "$TMP/relay.log"; then
  ok "relay listening"
else
  bad "relay did not start"; cat "$TMP/relay.log"; exit 1
fi

say "positive control: a single leg binds at all (cookie round-trip)"
ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$PORT" -tag ctrl01 \
    -sources fd00:beef:2::1 > "$TMP/ctrl.log" 2>&1
if grep -q "bound=1" "$TMP/ctrl.log"; then
  ok "single leg bound: $(tail -1 "$TMP/ctrl.log")"
else
  bad "a single leg could not be bound — the test proves nothing"; cat "$TMP/ctrl.log"; exit 1
fi

say "claim 65 legs from ONE /64 (cap: $MAXLEGS)"
ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$PORT" -tag flood1 \
    -sources "$SRC" > "$TMP/flood.log" 2>&1
BOUND=$(awk -F'bound=' '/^summary/{split($2,a," ");print a[1]}' "$TMP/flood.log")
REFUSED=$(awk -F'refused=' '/^summary/{split($2,a," ");print a[1]}' "$TMP/flood.log")
info "bound=$BOUND refused=$REFUSED from a single /64"
if [ "${BOUND:-0}" -le "$MAXLEGS" ] && [ "${REFUSED:-0}" -ge 1 ]; then
  ok "the /64 shares ONE budget and was capped at $MAXLEGS legs"
else
  bad "H-01: $BOUND legs bound from ONE /64 (cap $MAXLEGS) — each address got its own budget"
fi
if grep -q "leg-cap-hit src=fd00:beef:1::/64" "$TMP/relay.log"; then
  ok "the cap warning names the /64, not a single address"
else
  # Was an `info` (i.e. it could never fail) — with --debug the line MUST be
  # there, so a missing one now means the accounting key regressed to a single
  # address, or the warning stopped firing at all.
  bad "no /64-keyed leg-cap warning under --debug — the accounting key regressed"
  grep "leg-cap-hit" "$TMP/relay.log" | head -3
fi

say "positive control: a different /64 is still admitted"
ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$PORT" -tag ctrl02 \
    -sources fd00:beef:2::1 > "$TMP/other.log" 2>&1
if grep -q "bound=1" "$TMP/other.log"; then
  ok "a leg from a different /64 is admitted (the relay is not simply full)"
else
  bad "a different /64 was refused too — the refusal above may be a global cap"
fi

say "denial of service: can one /64 fill the GLOBAL session table?"
sudo -n ip netns pids "$NSR" 2>/dev/null | xargs -r sudo -n kill 2>/dev/null
sleep 1
ns "$NSR" "$BNBIN" --role=relay --relay-listen "[fd00:cafe::1]:$DPORT" \
    --allow-cidr "$LABNET" \
    --relay-max-legs-per-ip "$DLEGS" --relay-max-sessions "$DMAX" --ttl 600s \
    > "$TMP/relay-dos.log" 2>&1 &
for _ in $(seq 1 20); do grep -q "action=listening" "$TMP/relay-dos.log" 2>/dev/null && break; sleep 0.5; done
if grep -q "action=listening" "$TMP/relay-dos.log"; then
  ok "relay listening: --relay-max-sessions $DMAX, --relay-max-legs-per-ip $DLEGS"
else
  bad "second relay did not start"; cat "$TMP/relay-dos.log"; exit 1
fi

ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$DPORT" -tag dpre01 \
    -sources fd00:beef:2::1 > "$TMP/dos-pre.log" 2>&1
if grep -q "bound=1" "$TMP/dos-pre.log"; then
  ok "before the flood, an unrelated /64 can bind a leg"
else
  bad "unrelated user could not bind even before the flood — test invalid"; exit 1
fi

DSRC=""
for i in $(seq 1 63); do DSRC="$DSRC,fd00:beef:1::$i"; done
DSRC="${DSRC#,}"
ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$DPORT" -tag dflood -timeout 1s \
    -sources "$DSRC" > "$TMP/dos-flood.log" 2>&1
info "attacker bound $(awk -F'bound=' '/^summary/{split($2,a," ");print a[1]}' "$TMP/dos-flood.log") of 63 legs from one /64"

ns "$NSA" "$TMP/relayflood" -relay "[fd00:cafe::1]:$DPORT" -tag dpost1 \
    -sources fd00:beef:2::1 > "$TMP/dos-post.log" 2>&1
if grep -q "bound=1" "$TMP/dos-post.log"; then
  ok "an unrelated /64 can STILL get a session — no global lockout"
else
  bad "H-01 DoS: one /64 filled the table and locked out an unrelated /64"
fi

say "privacy: a relay WITHOUT --debug names no source"
# The second relay ran without --debug and hit its per-IP cap during the flood
# above, so its log is the natural place to check the rule the shipped relay
# claims: it says a source is hoarding, never which one. An address here would
# mean a production relay writes down who used it.
if grep -q "leg-cap-hit" "$TMP/relay-dos.log"; then
  if grep "leg-cap-hit" "$TMP/relay-dos.log" | grep -q "src="; then
    bad "the leg-cap warning printed a source address WITHOUT --debug"
    grep "leg-cap-hit" "$TMP/relay-dos.log" | head -3
  else
    ok "the cap warning fired without naming a source (addresses stay behind --debug)"
  fi
else
  info "no leg-cap warning on the non-debug relay — nothing to check here"
fi
if grep -qE "src=fd00:beef" "$TMP/relay-dos.log"; then
  bad "a source address leaked into a non-debug relay log"
  grep -E "src=fd00:beef" "$TMP/relay-dos.log" | head -3
else
  ok "no source address anywhere in the non-debug relay log"
fi

say "result"
printf '  passed: %d   failed: %d\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

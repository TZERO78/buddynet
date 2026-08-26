#!/usr/bin/env bash
# Direct mode — two buddies, NO handshake server, no rendezvous, no token.
#
# Proves the three claims docs/SETUP.md makes about --direct:
#
#   1  a tunnel comes up from configuration alone and carries real traffic
#   2  the NAME is re-resolved: move the record, and the next attempt follows it
#      (this is what makes a dynamic-DNS name enough)
#   3  DNS is route-finding ONLY: point the same name at an impostor that is up,
#      listening and speaking BuddyNet, and the connection dies on the pinned key
#
# Case 3 is the security argument of the whole mode. Direct mode has no handshake
# server, so no signed roster, no SAS and no relay ticket — the pin is the entire
# authentication. A hijacked DNS record must therefore cost availability and
# nothing else.
#
# sarah's /etc/hosts stands in for the dynamic-DNS record; rewriting it is exactly
# what a DynDNS update does from the resolver's point of view.
#
# Needs Docker. Run from lab/:  ./test-direct.sh
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
CF=docker-compose.direct.yml
PROJECT=bndirect
dc(){ docker compose -p "$PROJECT" -f "$CF" "$@"; }

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

KEYDIR=keys
cleanup(){ dc down -v >/dev/null 2>&1; rm -rf "$KEYDIR"; rm -f "${BN:-}" 2>/dev/null; }
trap cleanup EXIT

echo "== build =="
dc build >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }

BN=$(mktemp /tmp/bndirectbin.XXXXXX)
go build -o "$BN" "$ROOT/cmd/buddynet" || { echo "FAIL: go build"; exit 1; }
rm -rf "$KEYDIR"; mkdir -p "$KEYDIR"
for who in bob sarah mallory relay; do
  "$BN" --key "$KEYDIR/$who.key" init >/dev/null 2>&1
  chmod 644 "$KEYDIR/$who.key"
done
export BOB_PUB=$("$BN" --key "$KEYDIR/bob.key" identity)
export SARAH_PUB=$("$BN" --key "$KEYDIR/sarah.key" identity)
MALLORY_PUB=$("$BN" --key "$KEYDIR/mallory.key" identity)
[ -n "$BOB_PUB" ] && [ -n "$SARAH_PUB" ] || { echo "FAIL: no identities"; exit 1; }
echo "  bob=${BOB_PUB:0:8}… sarah=${SARAH_PUB:0:8}… mallory=${MALLORY_PUB:0:8}…"

# point <ip> — rewrite the "DNS record" sarah resolves bob.dyn.test to.
point(){
  dc exec -T sarah sh -c "grep -v ' bob.dyn.test\$' /etc/hosts > /tmp/h; echo '$1 bob.dyn.test' >> /tmp/h; cat /tmp/h > /etc/hosts"
}

# Log marking by LINE COUNT, not by timestamp. `docker compose logs --since` was
# the obvious choice and it silently let a line from the previous phase through
# (container clocks/zones vs. the host's), which made the hijack case look like a
# pass of the wrong thing. Counting lines cannot drift.
mark(){ MARK=$(dc logs sarah 2>/dev/null | wc -l); }
newlog(){ dc logs sarah 2>/dev/null | tail -n +$((MARK + 1)); }

# wait_connected — sarah's first CONNECTED line AFTER the mark ("" if none).
wait_connected(){ # $1 = seconds
  local line=""
  for _ in $(seq 1 "$1"); do
    line=$(newlog | grep -m1 'CONNECTED:' || true)
    [ -n "$line" ] && break
    sleep 1
  done
  echo "$line"
}

# wait_for — wait until a pattern shows up after the mark; returns 1 on timeout.
wait_for(){ # $1 = pattern, $2 = seconds
  for _ in $(seq 1 "$2"); do
    newlog | grep -qE "$1" && return 0
    sleep 1
  done
  return 1
}

echo
echo "== 1: a tunnel with no server at all =="
dc down -v >/dev/null 2>&1
dc up -d >/dev/null 2>&1
sleep 3
point 172.40.0.10   # the record points at the real bob
mark
GOT=$(wait_connected 40)
if echo "$GOT" | grep -q 'CONNECTED:'; then
  ok "tunnel came up with no handshake server"
  echo "$GOT" | grep -qF 'via="direct (configured endpoint)"' \
    && ok "carried by the configured endpoint (no punch, no relay)" \
    || no "unexpected path: $(echo "$GOT" | grep -oE 'via="[^"]*"')"
  BODY=$(dc exec -T sarah curl -s --max-time 8 http://localhost:9099/ 2>/dev/null)
  echo "$BODY" | grep -iq 'Peer A' && ok "partner's service reachable through the tunnel" \
    || no "service not reachable through the tunnel"
  # Nothing may have contacted a server, because there is none configured.
  dc logs sarah 2>&1 | grep -q 'action=direct' \
    && ok "sarah logged direct mode (partner pinned by key, no server)" \
    || no "no direct-mode line in sarah's log"
else
  no "no tunnel in the supported direct-mode configuration"
  dc logs --tail=15 sarah 2>&1 | sed 's/^/    /'
fi

echo
echo "== 2: the record moves to an impostor (expect: refused on the pin) =="
# mallory is a REAL buddynet on the same port with a different identity. If the
# pin were not enforced, sarah would happily tunnel to him.
dc stop bob >/dev/null 2>&1
mark
point 172.40.0.66
# Wait for sarah to actually ATTEMPT the impostor. Without this the case could
# "pass" simply because the reconnect backoff had not fired yet.
if ! wait_for 'path-try|path-failed' 60; then
  no "sarah never attempted a reconnect — case 2 proves nothing"
else
  GOT=$(newlog | grep -m1 'CONNECTED:' || true)
  if [ -n "$GOT" ]; then
    no "sarah connected to the impostor — the pin did NOT hold: $GOT"
  elif newlog | grep -q 'path-failed.*QUIC failed'; then
    # The handshake was reached and rejected — not a network error. That is the
    # difference between "pinning worked" and "mallory happened to be down".
    ok "refused the impostor at the QUIC handshake (pinned key did not match)"
  else
    no "no tunnel, but not visibly a rejected handshake"
    newlog | tail -12 | sed 's/^/    /'
  fi
  dc ps mallory 2>/dev/null | grep -q "Up" \
    && ok "the impostor was up and listening throughout (so this was a refusal, not an outage)" \
    || no "mallory was not running — case 2 proves nothing"
fi

echo
echo "== 3: the record moves back (expect: re-resolved, tunnel returns) =="
# This is the dynamic-DNS property: the NAME is constant, the address behind it
# changed twice, and nothing was reconfigured or restarted on sarah's side.
mark
point 172.40.0.10
dc start bob >/dev/null 2>&1
GOT=$(wait_connected 90)
if echo "$GOT" | grep -q 'CONNECTED:'; then
  ok "followed the record back to the real buddy without a restart"
  BODY=$(dc exec -T sarah curl -s --max-time 8 http://localhost:9099/ 2>/dev/null)
  echo "$BODY" | grep -iq 'Peer A' && ok "traffic flows again after the address change" \
    || no "tunnel up but no traffic after the address change"
else
  no "did not reconnect after the record moved back"
  newlog | tail -15 | sed 's/^/    /'
fi

echo
echo "== 4: direct path impossible, relay fallback (expect: via the relay) =="
# --peer-relay is the one fallback direct mode has. It has no ticket (there is no
# handshake server to mint one), so the relay authorizes by source CIDR — and
# nothing synchronises the two legs, which is the part worth testing: both sides
# have to give up on the direct path and arrive at the relay on their own.
export PEER_RELAY=172.40.0.99:51921
dc up -d --force-recreate bob sarah relay >/dev/null 2>&1
sleep 2
point 172.40.0.254   # a black hole: nothing answers there, so direct cannot work
# --force-recreate gives these services BRAND NEW containers, whose logs start at
# line 0 — so a mark carried over from the previous phase would skip past
# everything they say. Reset it instead of calling mark().
MARK=0
GOT=$(wait_connected 90)
if echo "$GOT" | grep -qF 'via="configured relay'; then
  ok "fell back to the configured relay with no server to arrange it"
  dc exec -T sarah curl -s --max-time 8 http://localhost:9099/ 2>/dev/null | grep -iq 'Peer A' \
    && ok "traffic flows over the relay" || no "relay path up but no traffic"
elif [ -n "$GOT" ]; then
  no "connected, but not over the relay: $(echo "$GOT" | grep -oE 'via="[^"]*"')"
else
  no "no tunnel over the relay fallback"
  newlog | tail -12 | sed 's/^/    /'
fi
unset PEER_RELAY

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

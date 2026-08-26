#!/usr/bin/env bash
# Coordinator lab — "I have no VPS": one of the two BUDDIES runs the coordinator.
#
# Proves the claim docs/SETUP.md makes, and the three ways it fails, in a real
# NAT topology (bob behind his own home router with a port forward, sarah behind
# an ordinary cone NAT):
#
#   1  hairpin on,  all three roles      → tunnel comes up, carries real traffic,
#                                          and does so via bob's OWN RELAY —
#                                          direct P2P is structurally impossible
#                                          here, see below
#   2  hairpin off, public address       → no tunnel at all: bob cannot reach his
#                                          own server through his own router
#   3  hairpin off, --server=127.0.0.1   → still no tunnel: localhost is not a way
#                                          around a router that cannot hairpin,
#                                          because bob's own RELAY is advertised
#                                          under its public address too
#   4  hairpin on,  no relay role        → no tunnel: with direct P2P impossible,
#                                          the relay role is not optional here
#
# WHY DIRECT P2P CANNOT WORK IN THIS TOPOLOGY (the finding this lab exists for):
# a buddy's candidates are the addresses its handshake server OBSERVES
# (`hsPeer.observe`). When the buddy IS the server, its own registration never
# leaves its LAN, so the only candidate it can ever offer the partner is a private
# address. The partner therefore has nothing punchable, in every NAT mode. The
# relay leg is what carries the tunnel — which is why both ports must be forwarded
# and the relay role must run.
#
# Needs Docker. Run from lab/:  ./test-coordinator.sh
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
CF=docker-compose.coordinator.yml
PROJECT=bncoord
dc(){ docker compose -p "$PROJECT" -f "$CF" "$@"; }

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

KEYDIR=keys
cleanup(){ dc down -v >/dev/null 2>&1; rm -rf "$KEYDIR"; rm -f "${BN:-}" 2>/dev/null; }
trap cleanup EXIT

echo "== build =="
dc build >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }

# Identities are minted on the host so both public keys are known before start —
# bob has to pin HIMSELF as --server-key, which is the whole trick of this setup.
BN=$(mktemp /tmp/bncoordbin.XXXXXX)
go build -o "$BN" "$ROOT/cmd/buddynet" || { echo "FAIL: go build"; exit 1; }
rm -rf "$KEYDIR"; mkdir -p "$KEYDIR"
"$BN" --key "$KEYDIR/bob.key" init >/dev/null 2>&1
"$BN" --key "$KEYDIR/sarah.key" init >/dev/null 2>&1
chmod 644 "$KEYDIR/bob.key" "$KEYDIR/sarah.key"
export BOB_PUB=$("$BN" --key "$KEYDIR/bob.key" identity)
export SARAH_PUB=$("$BN" --key "$KEYDIR/sarah.key" identity)
[ -n "$BOB_PUB" ] && [ -n "$SARAH_PUB" ] || { echo "FAIL: no identities"; exit 1; }

# run <hairpin> <server-addr> <roles> — brings the scenario up and echoes the
# CONNECTED line sarah saw (empty if none within the timeout).
run(){
  export NAT_HAIRPIN="$1" COORD_SERVER="$2" COORD_ROLES="$3" INVITE_TOKEN=unset
  dc down -v >/dev/null 2>&1
  dc up -d nat-bob nat-sarah bob >/dev/null 2>&1
  local tok=""
  for _ in $(seq 1 40); do
    tok=$(dc logs bob 2>&1 | grep -m1 -oE 'bnet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    [ -n "$tok" ] && break
    sleep 0.5
  done
  # A missing invite means the stack never came up. Say so loudly — a negative
  # case that silently passes because nothing started is worse than no test.
  [ -n "$tok" ] || { echo "NOTOKEN"; return; }
  export INVITE_TOKEN="$tok"
  dc up -d sarah >/dev/null 2>&1
  local line=""
  for _ in $(seq 1 "${WAIT:-45}"); do
    line=$(dc logs sarah 2>&1 | grep -m1 'CONNECTED:' || true)
    [ -n "$line" ] && break
    sleep 1
  done
  echo "$line"
}

# ── 1 — the setup docs/SETUP.md tells people to build ────────────────────────
echo
echo "== 1: coordinator is one of the buddies (hairpin on, all three roles) =="
GOT=$(run on 172.30.0.2:51820 buddy,handshake,relay)
if echo "$GOT" | grep -q 'CONNECTED:'; then
  ok "tunnel came up without any rented server"
  # Nail down HOW it comes up: if a future change ever makes this read
  # "direct P2P", the reasoning in docs/SETUP.md needs revisiting, not the test.
  if echo "$GOT" | grep -qF 'via="handshake server as relay"'; then
    ok "carried by the coordinator's own relay (direct P2P is impossible here)"
  else
    no "unexpected path: $(echo "$GOT" | grep -oE 'via="[^"]*"')"
  fi
  BODY=$(dc exec -T sarah curl -s --max-time 8 http://localhost:9099/ 2>/dev/null)
  echo "$BODY" | grep -iq 'Peer A' && ok "partner's service reachable through the tunnel" \
    || no "service not reachable through the tunnel"
  # The partner must never be handed a private address as a usable endpoint.
  dc logs sarah 2>&1 | grep -q 'path-failed path="direct P2P"' \
    && ok "direct punch was tried and failed (candidate is bob's private address)" \
    || no "expected a failed direct attempt before the relay"
else
  no "no tunnel in the supported configuration"
  dc logs sarah 2>&1 | tail -12 | sed 's/^/    /'
fi

# fails <label> <container> <cause-regex> <alive-container> <alive-regex>
#
# A negative case only counts if the stack is demonstrably ALIVE and failed for
# the stated reason. "no CONNECTED line" on its own would be just as true of a lab
# that never started — which is how a broken lab passes as a proof.
#
# The cause is matched on the EVENT (which path failed), never on the detail text:
# the detail varies with timing (a relay leg that cannot be reached reports either
# "relay did not acknowledge" or a plain QUIC deadline, depending on how far the
# ticket got), and pinning the test to one of them makes it flap.
fails(){
  local label="$1" who="$2" cause="$3" alive_who="$4" alive="$5"
  if [ "$GOT" = "NOTOKEN" ]; then
    no "$label — stack never came up (no invite minted); the lab is broken, not the config"
    dc logs bob 2>&1 | tail -8 | sed 's/^/    /'
  elif [ -n "$GOT" ]; then
    no "$label — unexpectedly connected: $GOT"
  elif ! dc logs "$alive_who" 2>&1 | grep -qE "$alive"; then
    no "$label — no tunnel, but $alive_who never got as far as \"$alive\"; lab broken?"
    dc logs "$alive_who" 2>&1 | tail -8 | sed 's/^/    /'
  elif dc logs "$who" 2>&1 | grep -qE "$cause"; then
    ok "$label"
  else
    no "$label — no tunnel, but not for the expected reason (wanted $who: /$cause/)"
    dc logs "$who" 2>&1 | tail -8 | sed 's/^/    /'
  fi
}

# ── 2 — the router cannot hairpin ────────────────────────────────────────────
echo
echo "== 2: same, but the router cannot hairpin (expect: no tunnel) =="
WAIT=35 GOT=$(run off 172.30.0.2:51820 buddy,handshake,relay)
# bob's own control dial is what breaks: he cannot reach his own public address.
# Alive proof: his server role IS listening — it is the buddy role in the same
# process that cannot get to it.
fails "correctly fails: coordinator cannot reach its own public address" \
  bob "QUIC control dial failed" bob "HANDSHAKE: action=listening"

# ── 3 — pointing at localhost does not rescue it ─────────────────────────────
echo
echo "== 3: no hairpin, --server=127.0.0.1 (expect: still no tunnel) =="
WAIT=35 GOT=$(run off 127.0.0.1:51820 buddy,handshake,relay)
# Here the pair DOES meet on the server (bob reaches it over loopback) — which is
# the alive proof — and it is the relay leg that cannot be bound, because the relay
# is advertised under its public address.
fails "correctly fails: localhost is no substitute for NAT loopback" \
  sarah 'path-failed path="handshake server as relay"' sarah "partner-verified"

# ── 4 — the relay role is not optional here ──────────────────────────────────
echo
echo "== 4: hairpin on, but the relay role was never started (expect: no tunnel) =="
WAIT=35 GOT=$(run on 172.30.0.2:51820 buddy,handshake)
fails "correctly fails: without the relay role there is no path left" \
  sarah 'path-failed path="handshake server as relay"' sarah "partner-verified"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

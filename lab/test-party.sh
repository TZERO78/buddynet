#!/usr/bin/env bash
# BuddyNet BuddyParty integration test (Phase 1.4: multi-peer, 3–5 buddies)
# ========================================================================
# Verifies that one hub holds N tunnels at once and routes to each buddy by
# name, and that the per-peer workers are isolated:
#
#   curl <name>.buddy:8080 on the hub → that buddy's httpd, for every buddy
#   stop one buddy → all the OTHERS stay reachable (one failure never spreads)
#
# Prerequisites:
#   ./setup-party.sh   (builds, bootstraps keys + manifests, starts the stack)
#
# Usage (from lab/):
#   ./test-party.sh

set -euo pipefail
cd "$(dirname "$0")"

BUDDIES=(beta gamma delta epsilon zeta)   # keep in sync with setup-party.sh
VICTIM=zeta                               # the buddy we stop for the isolation test

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.party.yml"
PORT=8080
STUB="127.0.0.153"
N=${#BUDDIES[@]}
PASS=0; FAIL=0

pass()    { echo "  [PASS] $*"; ((PASS++)) || true; }
fail()    { echo "  [FAIL] $*"; ((FAIL++)) || true; }
section() { echo ""; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }

hubresolve() { $COMPOSE exec -T party-hub dig +short +timeout=3 +tries=1 "@${STUB}" "$1" A 2>/dev/null | tr -d '\r' | tail -1; }
hubcurl()    { $COMPOSE exec -T party-hub curl -sf --max-time 5 --resolve "$1:${PORT}:$2" "http://$1:${PORT}" 2>/dev/null; }

# ── 1. Wait for the hub to bring up ALL tunnels ──────────────────────────────
section "Waiting for the hub to bind ${N} buddy VIPs (up to 90s)"
for i in $(seq 1 90); do
    BOUND=$($COMPOSE logs party-hub 2>/dev/null | grep -c -- "--vip-listen: listening on" || true)
    if [ "${BOUND:-0}" -ge "$N" ]; then
        pass "hub is listening on ${N} buddy VIPs"
        break
    fi
    sleep 1
    if [ "$i" -eq 90 ]; then
        fail "hub bound only ${BOUND:-0}/${N} VIPs in time"
        $COMPOSE logs party-hub | grep -E "SUPERVISOR:|CONNECTED:|--vip-listen:|WARNING" | tail -15
        echo "  Results: $PASS passed, $FAIL failed"; exit 1
    fi
done

# ── 2. Every tunnel carries traffic, to the RIGHT buddy ──────────────────────
section "All ${N} tunnels live — and each routed to the correct buddy"
declare -A VIP
for b in "${BUDDIES[@]}"; do
    VIP[$b]=$(hubresolve "${b}.buddy")
    if [ -z "${VIP[$b]}" ]; then
        fail "${b}.buddy did not resolve on the hub"
        continue
    fi
    if hubcurl "${b}.buddy" "${VIP[$b]}" | grep -q "Party - ${b}"; then
        pass "${b}.buddy:${PORT} → ${b}'s httpd (${VIP[$b]})"
    else
        fail "${b}.buddy:${PORT} did not return ${b}'s page"
    fi
done

# ── 3. Isolation — stopping one buddy must not affect the others ─────────────
section "Isolation — stop ${VICTIM}, the other $((N-1)) must keep working"
$COMPOSE stop "party-${VICTIM}" >/dev/null 2>&1
sleep 5

for b in "${BUDDIES[@]}"; do
    if [ "$b" = "$VICTIM" ]; then
        if hubcurl "${b}.buddy" "${VIP[$b]}" >/dev/null 2>&1; then
            fail "${VICTIM} still reachable after being stopped"
        else
            pass "${VICTIM} unreachable after stop (its VIP released)"
        fi
        continue
    fi
    if hubcurl "${b}.buddy" "${VIP[$b]}" | grep -q "Party - ${b}"; then
        pass "${b} still reachable after ${VICTIM} went down"
    else
        fail "${b} broke when ${VICTIM} went down — workers are NOT isolated!"
    fi
done

# Bring the victim back for a clean re-run next time.
$COMPOSE start "party-${VICTIM}" >/dev/null 2>&1 || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1

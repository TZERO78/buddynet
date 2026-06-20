#!/usr/bin/env bash
# BuddyNet VIP-routing integration test (Phase 1.3: Loopback-VIP-Bind)
# ====================================================================
# Verifies that --vip-listen binds a connected buddy's virtual IP on the local
# loopback interface and routes traffic to it through the tunnel:
#
#   vip-b binds alice's VIP (10.66.X.Y) on lo and listens on :7777
#   curl http://<alice-vip>:7777  inside vip-b → alice's httpd, via the tunnel
#   curl http://alice.buddy:7777  (name → VIP via the stub) works too
#   a VIP that is NOT a connected buddy is NOT bound (no over-binding)
#
# Prerequisites:
#   - lab/.env exists (run ./setup.sh first)
#   - VIP stack is running:
#       docker compose -f docker-compose.yml -f docker-compose.vip.yml up -d --build
#
# Usage (from lab/ directory):
#   ./test-vip.sh

set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vip.yml"
PORT="7777"
STUB="127.0.0.153"
# A virtual IP in the 10.66.0.0/16 overlay that is NOT a connected buddy here,
# used for the negative test (must be unbound → connection refused).
UNRELATED_VIP="10.66.200.201"
PASS=0; FAIL=0

pass()    { echo "  [PASS] $*"; ((PASS++)) || true; }
fail()    { echo "  [FAIL] $*"; ((FAIL++)) || true; }
section() { echo ""; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }

# ── 1. Wait for both tunnels ─────────────────────────────────────────────────
section "Waiting for tunnels (up to 40s)"
for svc in vip-a vip-b; do
    echo -n "  $svc: "
    for i in $(seq 1 40); do
        if $COMPOSE logs "$svc" 2>/dev/null | grep -q "CONNECTED:"; then
            echo "connected"
            break
        fi
        sleep 1
        if [ "$i" -eq 40 ]; then
            echo "TIMEOUT"
            $COMPOSE logs "$svc" | tail -5
            exit 1
        fi
    done
done

# ── 2. Extract alice's VIP from startup logs ─────────────────────────────────
section "Identities"
ALICE_VIP=$($COMPOSE logs vip-a 2>/dev/null | grep "buddynet buddy" | grep -oE "vip=[0-9.]+" | tail -1 | cut -d= -f2)
echo "  alice VIP: ${ALICE_VIP:-<not found>}"
if [ -z "$ALICE_VIP" ]; then
    echo "  ERROR: could not extract alice's VIP from logs"
    exit 1
fi

# ── 3. Confirm vip-b actually bound the VIP and is listening on it ───────────
# net.Listen on the VIP only succeeds once the address is on lo, so this log
# line is direct proof the netlink RTM_NEWADDR bind worked.
section "VIP bind — vip-b listening on alice's VIP"
for i in $(seq 1 20); do
    if $COMPOSE logs vip-b 2>/dev/null | grep -q -- "--vip-listen: listening on ${ALICE_VIP}:${PORT}"; then
        pass "vip-b bound ${ALICE_VIP} on lo and is listening on :${PORT}"
        break
    fi
    sleep 1
    if [ "$i" -eq 20 ]; then
        fail "vip-b never reported listening on ${ALICE_VIP}:${PORT}"
        $COMPOSE logs vip-b | grep -i "vip\|WARNING" | tail -5 || true
    fi
done

# Belt-and-braces: the address is present on lo (best effort — `ip` may be absent).
if $COMPOSE exec -T vip-b ip -4 addr show dev lo 2>/dev/null | grep -q "$ALICE_VIP"; then
    pass "ip addr confirms ${ALICE_VIP}/32 on vip-b's lo"
else
    echo "  [INFO] could not confirm via 'ip addr' (applet absent?) — relying on the listener log"
fi

# ── 4. Data path — curl alice's VIP through the tunnel ───────────────────────
section "TCP over VIP — curl http://${ALICE_VIP}:${PORT} (inside vip-b)"
if $COMPOSE exec -T vip-b curl -sf --max-time 5 "http://${ALICE_VIP}:${PORT}" | grep -q "BuddyNet Lab"; then
    pass "HTTP over VIP routing (vip-b → alice:7777 via tunnel) works"
else
    fail "HTTP over VIP routing failed"
fi

# ── 5. Name → VIP → tunnel (the operator-facing path) ────────────────────────
section "Name routing — curl http://alice.buddy:${PORT}"
# Resolve alice.buddy on the local stub, then curl the name (forced to that VIP).
RESOLVED=$($COMPOSE exec -T vip-b dig +short +timeout=3 +tries=1 "@${STUB}" alice.buddy A 2>/dev/null | tr -d '\r' | tail -1)
if [ "$RESOLVED" = "$ALICE_VIP" ]; then
    pass "alice.buddy resolves to ${RESOLVED} on vip-b's stub"
else
    fail "alice.buddy resolved to '${RESOLVED}' (expected ${ALICE_VIP})"
fi
if $COMPOSE exec -T vip-b curl -sf --max-time 5 \
        --resolve "alice.buddy:${PORT}:${ALICE_VIP}" \
        "http://alice.buddy:${PORT}" | grep -q "BuddyNet Lab"; then
    pass "HTTP via name alice.buddy:${PORT} works end to end"
else
    fail "HTTP via name alice.buddy:${PORT} failed"
fi

# ── 6. Security — only connected buddies' VIPs are bound ─────────────────────
section "No over-binding — an unrelated VIP must be unreachable"
# A VIP that is not a connected buddy must not be on lo, so connecting refuses
# fast. (curl exits non-zero; we assert it does NOT succeed.)
if $COMPOSE exec -T vip-b curl -sf --max-time 3 "http://${UNRELATED_VIP}:${PORT}" >/dev/null 2>&1; then
    fail "unrelated VIP ${UNRELATED_VIP} was reachable — over-binding!"
else
    pass "unrelated VIP ${UNRELATED_VIP} is not bound/reachable (no over-binding)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1

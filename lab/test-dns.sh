#!/usr/bin/env bash
# BuddyNet MagicDNS integration test
# ====================================
# Verifies that --name + --dns work end-to-end over a live tunnel:
#
#   alice.buddy  resolves on bob's stub to alice's 10.66.0.X virtual IP
#   bob.buddy    resolves on alice's stub to bob's 10.66.0.X virtual IP
#   <fp8>.buddy  fingerprint aliases work for both peers
#   NXDOMAIN     for unknown .buddy names and non-.buddy queries
#   TCP          curl alice.buddy via the tunnel (HTTP over VIP)
#
# Prerequisites:
#   - lab/.env exists (run ./setup.sh first)
#   - DNS stack is running:
#       docker compose -f docker-compose.yml -f docker-compose.dns.yml up -d
#
# Usage (from lab/ directory):
#   ./test-dns.sh

set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dns.yml"
STUB="127.0.0.153"
PASS=0; FAIL=0

pass()    { echo "  [PASS] $*"; ((PASS++)) || true; }
fail()    { echo "  [FAIL] $*"; ((FAIL++)) || true; }
section() { echo ""; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }

# dig inside a container, querying our stub resolver.
# Usage: cdns <container> <qname> [<type>]
cdns() {
    local ctr=$1 qname=$2 qtype=${3:-A}
    $COMPOSE exec -T "$ctr" dig +short +timeout=3 +tries=1 "@${STUB}" "$qname" "$qtype" 2>/dev/null || true
}

# Return code of a dig query (0 = NOERROR, 3 = NXDOMAIN).
cdns_rc() {
    local ctr=$1 qname=$2 qtype=${3:-A}
    $COMPOSE exec -T "$ctr" dig +timeout=3 +tries=1 "@${STUB}" "$qname" "$qtype" 2>/dev/null \
        | awk '/status:/{print $6}' | tr -d ','
}

# ── 1. Wait for tunnels ──────────────────────────────────────────────────────
section "Waiting for tunnels (up to 40s)"
for svc in dns-a dns-b; do
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

# ── 2. Wait for stub resolver to be up ──────────────────────────────────────
section "Waiting for .buddy stub resolvers (up to 20s)"
for svc in dns-a dns-b; do
    echo -n "  $svc stub: "
    for i in $(seq 1 20); do
        # A query for anything should return either NOERROR or NXDOMAIN — both
        # mean the server is listening; a timeout or SERVFAIL means it is not up yet.
        STATUS=$(cdns_rc "$svc" "probe.buddy" A)
        if [ "$STATUS" = "NOERROR" ] || [ "$STATUS" = "NXDOMAIN" ]; then
            echo "ready ($STATUS)"
            break
        fi
        sleep 1
        if [ "$i" -eq 20 ]; then
            echo "TIMEOUT (last status: $STATUS)"
            $COMPOSE logs "$svc" | grep -i "dns\|WARNING\|stub" | tail -5 || true
            exit 1
        fi
    done
done

# ── 3. Extract VIPs and pubkeys from startup logs ────────────────────────────
section "Extracting identities from startup logs"

ALICE_VIP=$($COMPOSE logs dns-a 2>/dev/null | grep "buddynet buddy" | grep -oE "vip=[0-9.]+" | tail -1 | cut -d= -f2)
BOB_VIP=$($COMPOSE logs dns-b 2>/dev/null | grep "buddynet buddy" | grep -oE "vip=[0-9.]+" | tail -1 | cut -d= -f2)
ALICE_PUB=$($COMPOSE logs dns-a 2>/dev/null | grep "buddynet buddy" | grep -oE "identity [A-Za-z0-9+/=]+" | tail -1 | awk '{print $2}')
BOB_PUB=$($COMPOSE logs dns-b 2>/dev/null | grep "buddynet buddy" | grep -oE "identity [A-Za-z0-9+/=]+" | tail -1 | awk '{print $2}')

echo "  alice VIP:    ${ALICE_VIP:-<not found>}"
echo "  bob VIP:      ${BOB_VIP:-<not found>}"
echo "  alice pubkey: ${ALICE_PUB:0:16}… (${#ALICE_PUB} chars)"
echo "  bob pubkey:   ${BOB_PUB:0:16}… (${#BOB_PUB} chars)"

if [ -z "$ALICE_VIP" ] || [ -z "$BOB_VIP" ]; then
    echo "  ERROR: could not extract VIPs from logs — check container startup"
    exit 1
fi

# Compute fingerprints: sha256(pubkeyB64) → first 8 hex chars.
ALICE_FP=$(echo -n "$ALICE_PUB" | sha256sum | cut -c1-8)
BOB_FP=$(echo -n "$BOB_PUB" | sha256sum | cut -c1-8)
echo "  alice fp8:    ${ALICE_FP}"
echo "  bob fp8:      ${BOB_FP}"

# ── 4. Name resolution tests ─────────────────────────────────────────────────
section "Name resolution — alice.buddy and bob.buddy"

# alice.buddy from bob's resolver → must equal alice's VIP
RESOLVED=$(cdns dns-b "alice.buddy")
if [ "$RESOLVED" = "$ALICE_VIP" ]; then
    pass "alice.buddy on bob → $RESOLVED (matches alice VIP)"
else
    fail "alice.buddy on bob → '$RESOLVED' (expected $ALICE_VIP)"
fi

# bob.buddy from alice's resolver → must equal bob's VIP
RESOLVED=$(cdns dns-a "bob.buddy")
if [ "$RESOLVED" = "$BOB_VIP" ]; then
    pass "bob.buddy on alice → $RESOLVED (matches bob VIP)"
else
    fail "bob.buddy on alice → '$RESOLVED' (expected $BOB_VIP)"
fi

# Own name should resolve to own VIP (self-entry in table)
RESOLVED=$(cdns dns-a "alice.buddy")
if [ "$RESOLVED" = "$ALICE_VIP" ]; then
    pass "alice.buddy on alice → $RESOLVED (self-entry works)"
else
    fail "alice.buddy on alice → '$RESOLVED' (expected $ALICE_VIP)"
fi

# Case-insensitive
RESOLVED=$(cdns dns-b "Alice.Buddy")
if [ "$RESOLVED" = "$ALICE_VIP" ]; then
    pass "Alice.Buddy (mixed case) resolves correctly → $RESOLVED"
else
    fail "Alice.Buddy case-insensitive: '$RESOLVED' (expected $ALICE_VIP)"
fi

# ── 5. Fingerprint aliases ────────────────────────────────────────────────────
section "Fingerprint aliases — <fp8>.buddy"

RESOLVED=$(cdns dns-b "${ALICE_FP}.buddy")
if [ "$RESOLVED" = "$ALICE_VIP" ]; then
    pass "${ALICE_FP}.buddy (alice fp) on bob → $RESOLVED"
else
    fail "${ALICE_FP}.buddy on bob → '$RESOLVED' (expected $ALICE_VIP)"
fi

RESOLVED=$(cdns dns-a "${BOB_FP}.buddy")
if [ "$RESOLVED" = "$BOB_VIP" ]; then
    pass "${BOB_FP}.buddy (bob fp) on alice → $RESOLVED"
else
    fail "${BOB_FP}.buddy on alice → '$RESOLVED' (expected $BOB_VIP)"
fi

# ── 6. NXDOMAIN tests ────────────────────────────────────────────────────────
section "NXDOMAIN — unknown names and non-.buddy queries"

STATUS=$(cdns_rc dns-b "nonexistent.buddy" A)
if [ "$STATUS" = "NXDOMAIN" ]; then
    pass "nonexistent.buddy → NXDOMAIN"
else
    fail "nonexistent.buddy → $STATUS (expected NXDOMAIN)"
fi

STATUS=$(cdns_rc dns-b "alice.example.com" A)
if [ "$STATUS" = "NXDOMAIN" ]; then
    pass "alice.example.com (non-.buddy) → NXDOMAIN"
else
    fail "alice.example.com → $STATUS (expected NXDOMAIN)"
fi

STATUS=$(cdns_rc dns-b "sub.alice.buddy" A)
if [ "$STATUS" = "NXDOMAIN" ]; then
    pass "sub.alice.buddy (multi-label) → NXDOMAIN"
else
    fail "sub.alice.buddy → $STATUS (expected NXDOMAIN)"
fi

# ── 7. TCP reachability via VIP ───────────────────────────────────────────────
section "TCP reachability — curl alice.buddy via tunnel"
# dns-b has a -L 7080 that forwards to alice's httpd on :7777
if curl -sf --max-time 5 "http://localhost:7080" | grep -q "BuddyNet Lab"; then
    pass "HTTP over tunnel (localhost:7080 → alice:7777) works"
else
    fail "HTTP over tunnel failed"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1

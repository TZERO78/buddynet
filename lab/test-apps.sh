#!/usr/bin/env bash
# BuddyNet application-tunnel integration test
# =============================================
# Tests rsync and kopia running over BuddyNet tunnels, including a relay-
# fallback scenario where the direct P2P path is cut while kopia is connected.
#
# Prerequisites:
#   - lab/.env exists (run ./setup.sh first)
#   - The apps stack is running:
#       docker compose -f docker-compose.yml -f docker-compose.apps.yml up -d
#   - sudo is available (ebtables needed for the relay-fallback test)
#
# Usage (from lab/ directory):
#   ./test-apps.sh

set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.apps.yml"
PASS=0; FAIL=0

pass()    { echo "  [PASS] $*"; ((PASS++)) || true; }
fail()    { echo "  [FAIL] $*"; ((FAIL++)) || true; }
section() { echo ""; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }

DEST=$(mktemp -d)
cleanup() { rm -rf "$DEST"; _ebtables_restore; }
trap cleanup EXIT

# ── ebtables helpers ─────────────────────────────────────────────────────────
EBTABLES_SET=false

_ebtables_block() {
    local mac_a mac_b
    mac_a=$(docker inspect lab-kopia-a-1 \
        --format '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' 2>/dev/null)
    mac_b=$(docker inspect lab-kopia-b-1 \
        --format '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' 2>/dev/null)
    if [ -z "$mac_a" ] || [ -z "$mac_b" ]; then return 1; fi
    sudo ebtables -I FORWARD -p IPv4 --ip-proto udp -s "$mac_a" -d "$mac_b" -j DROP 2>/dev/null
    sudo ebtables -I FORWARD -p IPv4 --ip-proto udp -s "$mac_b" -d "$mac_a" -j DROP 2>/dev/null
    EBTABLES_SET=true
    echo "  [+] ebtables: UDP kopia-a ↔ kopia-b blocked (MAC $mac_a ↔ $mac_b)"
}

_ebtables_restore() {
    if [ "$EBTABLES_SET" = "true" ]; then
        local mac_a mac_b
        mac_a=$(docker inspect lab-kopia-a-1 \
            --format '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' 2>/dev/null || true)
        mac_b=$(docker inspect lab-kopia-b-1 \
            --format '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' 2>/dev/null || true)
        sudo ebtables -D FORWARD -p IPv4 --ip-proto udp -s "$mac_a" -d "$mac_b" -j DROP 2>/dev/null || true
        sudo ebtables -D FORWARD -p IPv4 --ip-proto udp -s "$mac_b" -d "$mac_a" -j DROP 2>/dev/null || true
        EBTABLES_SET=false
        echo "  [+] ebtables: P2P UDP restored"
    fi
}

# ── Wait for tunnels ─────────────────────────────────────────────────────────
section "Waiting for tunnels (up to 30s)"
for svc in rsync-a rsync-b kopia-a kopia-b; do
    echo -n "  $svc: "
    for i in $(seq 1 30); do
        if $COMPOSE logs "$svc" 2>/dev/null | grep -q "CONNECTED:"; then
            echo "connected"
            break
        fi
        sleep 1
        if [ "$i" -eq 30 ]; then echo "TIMEOUT"; $COMPOSE logs "$svc" | tail -3; exit 1; fi
    done
done

# ── rsync test ───────────────────────────────────────────────────────────────
section "rsync over BuddyNet tunnel"

mkdir -p "$DEST/rsync"
echo "[*] listing rsync://localhost:8873/share/ ..."
if rsync --list-only rsync://localhost:8873/share/ 2>/dev/null | grep -q "\.dat"; then
    pass "rsync listing works"
else
    fail "rsync listing failed"
fi

echo "[*] downloading all files from rsync-a..."
rsync -a --stats rsync://localhost:8873/share/ "$DEST/rsync/" 2>&1 \
    | grep -E "files transferred|Total file size" || true
COUNT=$(ls "$DEST/rsync/" 2>/dev/null | wc -l)
[ "$COUNT" -ge 20 ] \
    && pass "rsync download: $COUNT files transferred" \
    || fail "rsync download: only $COUNT files (expected ≥20)"

echo "[*] uploading a file back through tunnel..."
echo "uploaded at $(date -u)" > "$DEST/upload.txt"
if rsync -a "$DEST/upload.txt" rsync://localhost:8873/share/; then
    pass "rsync upload works"
else
    fail "rsync upload failed"
fi

# ── kopia SFTP setup ─────────────────────────────────────────────────────────
section "kopia SFTP repository via BuddyNet tunnel"
# Architecture:
#   kopia-a  -L 127.0.0.1:2222  ──BuddyNet──►  kopia-b  --forward 127.0.0.1:22
#   kopia (on kopia-a) uses SFTP backend at 127.0.0.1:2222 (user=kopia pass=labpass)

echo "[*] waiting for kopia-b host key in shared volume (up to 15s)..."
for i in $(seq 1 30); do
    if $COMPOSE exec -T kopia-a sh -c 'test -f /root/.ssh/known_hosts' 2>/dev/null; then
        echo "  [+] known_hosts ready"
        break
    fi
    sleep 0.5
    if [ "$i" -eq 30 ]; then fail "known_hosts not set up on kopia-a"; fi
done

echo "[*] testing SSH tunnel connectivity..."
if $COMPOSE exec -T kopia-a sh -c \
        'sshpass -p labpass ssh \
             -o StrictHostKeyChecking=yes \
             -o UserKnownHostsFile=/root/.ssh/known_hosts \
             -p 2222 kopia@127.0.0.1 echo "SSH OK" 2>&1' \
        2>/dev/null | grep -q "SSH OK"; then
    pass "SSH SFTP tunnel kopia-a → kopia-b (password auth)"
else
    fail "SSH tunnel failed — check sshd on kopia-b"
fi

echo "[*] initialising kopia SFTP repository (create or connect)..."
KOPIA_INIT=$($COMPOSE exec -T kopia-a sh -c '
    KOPIA_PASSWORD=lab-repo-password kopia repository create sftp \
        --host=127.0.0.1 --port=2222 \
        --username=kopia --sftp-password=labpass \
        --path=/data/repo \
        --known-hosts=/root/.ssh/known_hosts \
        --override-username=lab --override-hostname=kopia-a 2>&1 ||
    KOPIA_PASSWORD=lab-repo-password kopia repository connect sftp \
        --host=127.0.0.1 --port=2222 \
        --username=kopia --sftp-password=labpass \
        --path=/data/repo \
        --known-hosts=/root/.ssh/known_hosts \
        --override-username=lab --override-hostname=kopia-a 2>&1
' 2>&1)
if echo "$KOPIA_INIT" | grep -qiE "connected to repository|already exists"; then
    pass "kopia SFTP repository ready on kopia-b"
else
    fail "kopia SFTP repository init failed"
    echo "$KOPIA_INIT" | tail -5
fi

echo "[*] creating snapshot of /data/source (via direct P2P)..."
SNAP1=$($COMPOSE exec -T kopia-a sh -c \
    'KOPIA_PASSWORD=lab-repo-password kopia snapshot create /data/source 2>&1' 2>&1)
echo "$SNAP1" | grep -E "Created snapshot|snapshot.*ID" | head -2 || echo "$SNAP1" | tail -3
if echo "$SNAP1" | grep -qiE "Created snapshot"; then
    pass "kopia snapshot 1 (source, direct P2P)"
else
    fail "kopia snapshot 1 failed"
fi

# ── Relay fallback test ───────────────────────────────────────────────────────
section "Relay fallback: cut direct P2P, verify tunnel survives via relay"

if ! sudo ebtables -L FORWARD > /dev/null 2>&1; then
    echo "  [!] ebtables not available — relay test skipped"
    fail "relay test skipped (no ebtables)"
else
    # If a relay session from a previous run is still active in the server,
    # wait for it to close (idle-timeout is 1 minute on the relay).
    # A "session-paired" without a subsequent "session-closed" in the last 90s
    # means an active session exists — wait for it to expire.
    echo "[*] checking for stale relay sessions..."
    for i in $(seq 1 90); do
        LAST_EVENT=$(docker compose logs server 2>/dev/null \
            | grep -E "session-paired|session-closed" | tail -1)
        if echo "$LAST_EVENT" | grep -q "session-closed"; then
            echo "  [+] relay idle — no active session"
            break
        fi
        if [ "$i" -eq 90 ]; then
            echo "  [!] relay session did not close in 90s — proceeding anyway"
        fi
        if [ "$i" -eq 1 ] && echo "$LAST_EVENT" | grep -q "session-paired"; then
            echo "  [~] waiting for stale relay session to close (up to 90s)..."
        fi
        sleep 1
    done

    echo "[*] blocking direct UDP (P2P) between kopia-a and kopia-b..."
    if _ebtables_block; then
        # Capture the last CONNECTED: line so we can detect a NEW one.
        # Log format: "kopia-a-1  | HH:MM:SS CONNECTED: ..."
        # Strip the "container | " prefix with sed before comparing.
        DIRECT_CONN=$($COMPOSE logs kopia-a 2>/dev/null \
            | grep " CONNECTED:" | tail -1 | sed 's/^[^ ]* *| //')
        echo "[*] waiting for DISCONNECTED + relay reconnect (idle-timeout=20s)..."
        echo "    (current: $DIRECT_CONN)"
        RELAY_UP=false
        for i in $(seq 1 60); do
            # " CONNECTED:" avoids matching "DISCONNECTED:"
            NEW_CONN=$($COMPOSE logs kopia-a 2>/dev/null \
                | grep " CONNECTED:" | tail -1 | sed 's/^[^ ]* *| //')
            if [ "$NEW_CONN" != "$DIRECT_CONN" ] \
               && echo "$NEW_CONN" | grep -qv '"direct P2P"'; then
                echo "  [+] relay active after ${i}s: $NEW_CONN"
                RELAY_UP=true
                break
            fi
            sleep 1
        done

        _ebtables_restore

        if [ "$RELAY_UP" = "true" ]; then
            pass "relay fallback: tunnel reconnected via relay"
        else
            fail "relay fallback: no relay CONNECTED seen within 60s"
            $COMPOSE logs kopia-a 2>/dev/null \
                | grep -E "CONNECTED|DISCONNECTED|path" | tail -10
        fi

        echo "[*] creating snapshot over relay/new-P2P path..."
        SNAP2=$($COMPOSE exec -T kopia-a sh -c '
            KOPIA_PASSWORD=lab-repo-password kopia repository connect sftp \
                --host=127.0.0.1 --port=2222 \
                --username=kopia --sftp-password=labpass \
                --path=/data/repo \
                --known-hosts=/root/.ssh/known_hosts \
                --override-username=lab --override-hostname=kopia-a 2>/dev/null || true
            KOPIA_PASSWORD=lab-repo-password kopia snapshot create /data/source 2>&1
        ' 2>&1)
        echo "$SNAP2" | grep -E "Created snapshot|snapshot.*ID" | head -2 \
            || echo "$SNAP2" | tail -5
        if echo "$SNAP2" | grep -qiE "Created snapshot"; then
            pass "kopia snapshot 2 (source, after relay reconnect)"
        else
            fail "kopia snapshot 2 after relay reconnect failed"
        fi
    else
        fail "relay test: could not set ebtables rules (no container IPs?)"
    fi
fi

echo "[*] verifying snapshot list on kopia-b..."
SNAPS=$($COMPOSE exec -T kopia-a sh -c \
    'KOPIA_PASSWORD=lab-repo-password kopia snapshot list 2>/dev/null' 2>&1 \
    | grep -c "@kopia-a" || true)
[ "$SNAPS" -ge 1 ] \
    && pass "kopia snapshot list: $SNAPS snapshot(s) on kopia-b" \
    || fail "kopia snapshot list empty"

# ── Audit log summary ─────────────────────────────────────────────────────────
section "Audit log (last 30 min)"
$COMPOSE logs rsync-a rsync-b kopia-a kopia-b --since=30m 2>/dev/null \
    | grep -E "CONNECTED:|DISCONNECTED:|SECURITY:|PAIRED:|TRUST:|stats.*role=|via=" \
    | sed 's/^[^ ]* //' \
    | sort -t' ' -k1,1

# ── Results ───────────────────────────────────────────────────────────────────
section "Results"
echo "  PASSED: $PASS   FAILED: $FAIL"
echo ""
[ "$FAIL" -eq 0 ] && echo "All tests passed." || { echo "Some tests FAILED."; exit 1; }

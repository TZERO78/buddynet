#!/usr/bin/env bash
# CGNAT lab: brings the stack up in both NAT modes and checks how the real
# buddynet punch behaves.
#   cone      → expect CONNECTED via="direct P2P"      (hole punch succeeds)
#   symmetric → expect CONNECTED via="handshake server as relay"  (punch fails → relay)
#
# Proves: hole-punching gets through ordinary CGNAT, and the relay catches the
# hard/symmetric case. Needs Docker. Run from lab/:  ./test-cgnat.sh
set -euo pipefail
cd "$(dirname "$0")"
CF=docker-compose.cgnat.yml
PROJECT=bncgnat
dc() { docker compose -p "$PROJECT" -f "$CF" "$@"; }

cleanup() { dc down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== build images =="
dc build >/dev/null

echo "== bootstrap server identity =="
KEY=$(dc run --rm server --key /var/lib/buddynet/id.key identity 2>/dev/null | tr -d '\r\n')
[ -n "$KEY" ] || { echo "FAIL: no server key"; exit 1; }
echo "BUDDYNET_SERVER_KEY=$KEY" > .env
echo "server key: $KEY"

FAIL=0
check() {
  local mode="$1" want="$2"
  echo "== NAT_MODE=$mode (expect via=\"$want\") =="
  dc down >/dev/null 2>&1 || true
  NAT_MODE="$mode" dc up -d >/dev/null
  local got=""
  for _ in $(seq 1 40); do
    got=$(dc logs buddy-b 2>/dev/null | grep -m1 'CONNECTED:' || true)
    [ -n "$got" ] && break
    sleep 2
  done
  echo "  ${got:-<no CONNECTED line within timeout>}"
  if echo "$got" | grep -qF "via=\"$want\""; then
    echo "  [PASS] $mode → $want"
  else
    echo "  [FAIL] $mode: expected via=\"$want\""
    echo "  --- buddy-b recent logs ---"; dc logs --tail=15 buddy-b 2>/dev/null | sed 's/^/    /'
    FAIL=1
  fi
}

check cone      "direct P2P"
check symmetric "handshake server as relay"

if [ "$FAIL" = 0 ]; then
  echo "RESULT: PASS — punch works through cone NAT; relay catches symmetric CGNAT"
else
  echo "RESULT: FAIL"
  exit 1
fi

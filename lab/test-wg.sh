#!/usr/bin/env bash
# P3.1 step-3 lab e2e for internal/wg (kernel WireGuard via raw netlink).
#
# Stands up TWO kernel WireGuard interfaces — each configured entirely by our own
# internal/wg.Up (no `wg`/`ip` for the WG config) — in two network namespaces
# connected by a veth pair (the underlay), then pings each node's overlay virtual
# IP (10.66.X.Y) across the tunnel. This verifies our netlink encoding is accepted
# by a real kernel and that a real handshake + data path comes up.
#
# Needs root (sudo) and the wireguard kernel module. Builds the spike binary as
# the invoking user, runs the privileged parts via sudo.
#
#   ./lab/test-wg.sh
#
set -euo pipefail

NS_A=wgspike-a
NS_B=wgspike-b
VETH_A=veth-a
VETH_B=veth-b
UNDER_A=10.123.0.1
UNDER_B=10.123.0.2
PORT_A=51820
PORT_B=51821
IF_A=wgs-a
IF_B=wgs-b
BIN=/tmp/wg-spike
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do sudo kill "$p" 2>/dev/null; done
  sudo ip netns del "$NS_A" 2>/dev/null
  sudo ip netns del "$NS_B" 2>/dev/null
}
trap cleanup EXIT

echo "== build spike =="
( cd "$ROOT" && go build -o "$BIN" ./lab/wg-spike )

echo "== keys (real Ed25519→X25519→VIP derivation) =="
SEED_A="$(head -c32 /dev/urandom | base64 -w0)"
SEED_B="$(head -c32 /dev/urandom | base64 -w0)"
read -r PUB_A VIP_A < <("$BIN" pubkey --seed "$SEED_A")
read -r PUB_B VIP_B < <("$BIN" pubkey --seed "$SEED_B")
echo "A: vip=$VIP_A"
echo "B: vip=$VIP_B"

echo "== underlay: namespaces + veth =="
sudo modprobe wireguard
sudo ip netns add "$NS_A"
sudo ip netns add "$NS_B"
sudo ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"
sudo ip -n "$NS_A" addr add "$UNDER_A/24" dev "$VETH_A"
sudo ip -n "$NS_B" addr add "$UNDER_B/24" dev "$VETH_B"
sudo ip -n "$NS_A" link set "$VETH_A" up
sudo ip -n "$NS_B" link set "$VETH_B" up
sudo ip -n "$NS_A" link set lo up
sudo ip -n "$NS_B" link set lo up

echo "== bring up WireGuard via internal/wg.Up in each namespace =="
sudo ip netns exec "$NS_A" "$BIN" up \
  --seed "$SEED_A" --peer-pub "$PUB_B" --ifname "$IF_A" \
  --listen-port "$PORT_A" --peer-endpoint "$UNDER_B:$PORT_B" --keepalive 5 &
PIDS+=($!)
sudo ip netns exec "$NS_B" "$BIN" up \
  --seed "$SEED_B" --peer-pub "$PUB_A" --ifname "$IF_B" \
  --listen-port "$PORT_B" --peer-endpoint "$UNDER_A:$PORT_A" --keepalive 5 &
PIDS+=($!)

sleep 2
echo "== state =="
sudo ip -n "$NS_A" addr show "$IF_A" || true
sudo ip -n "$NS_A" route show || true

echo "== ping overlay VIP across the tunnel (A -> B) =="
rc=0
sudo ip netns exec "$NS_A" ping -c 5 -W 2 "$VIP_B" || rc=$?
echo "== ping back (B -> A) =="
sudo ip netns exec "$NS_B" ping -c 5 -W 2 "$VIP_A" || rc=$?

if [ "$rc" -eq 0 ]; then
  echo "RESULT: PASS — kernel accepted internal/wg config and tunnel carries traffic"
else
  echo "RESULT: FAIL — ping did not get through (rc=$rc)"
fi
exit "$rc"

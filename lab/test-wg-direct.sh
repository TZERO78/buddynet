#!/usr/bin/env bash
# Direct mode ON THE WIREGUARD DATA PLANE — `--direct --wireguard`, with no
# handshake server anywhere.
#
# Two netns on a bridge (no NAT; reachability is the point, not traversal):
#   ns-bob    10.51.0.20   --direct --wireguard --listen-port 51820   (is dialled)
#   ns-sarah  10.51.0.30   --direct --wireguard --peer-endpoint bob   (dials)
#
# WHAT THIS PROVES, and why the mode needs its own lab:
#
# On the QUIC plane the listening side calls Listen() and waits. WireGuard has no
# such call — a peer is configured with an endpoint and initiates, or is
# configured WITHOUT one and can only answer. Direct mode's listening side has no
# endpoint to configure (nothing introduced the partner, so no address was ever
# observed), which is exactly the case the WG path did not handle: it took the
# first path it could prime and would have carried a nil endpoint into the
# interface configuration.
#
# So bob is now brought up as a peer with NO endpoint. He adopts whatever address
# the completed handshake came from (WireGuard roaming), which is why his
# CONNECTED line reads remote=adopted-from-handshake — asserted below, because it
# is the difference between "this path is implemented" and "it happened to work".
#
# Phase 2 re-runs the same pair on the default QUIC plane, so a regression in
# either plane is visible in one run.
#
# Needs root (sudo) and the wireguard module. Run from the repo root or lab/:
#   ./lab/test-wg-direct.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgd/bn
D=/tmp/wgd

cleanup() {
	set +e
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	for ns in ns-bob ns-sarah ns-sw2; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
PIDS=""

rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
sudo modprobe wireguard

echo "== identities (exchanged out of band; there is no server to introduce them) =="
BOBPUB=$("$BN" --key "$D/bob.key" init)
SARAHPUB=$("$BN" --key "$D/sarah.key" init)
echo "  bob=${BOBPUB:0:12}…  sarah=${SARAHPUB:0:12}…"

echo "== topology =="
sudo ip netns add ns-sw2; sudo ip netns add ns-bob; sudo ip netns add ns-sarah
sudo ip netns exec ns-sw2 ip link add br0 type bridge
sudo ip netns exec ns-sw2 ip link set br0 up
add_node() { # $1 short-name, $2 addr
	sudo ip link add "v-$1" netns "ns-$1" type veth peer name "b-$1" netns ns-sw2
	sudo ip netns exec ns-sw2 ip link set "b-$1" master br0
	sudo ip netns exec ns-sw2 ip link set "b-$1" up
	sudo ip -n "ns-$1" link set "v-$1" up
	sudo ip -n "ns-$1" link set lo up
	sudo ip -n "ns-$1" addr add "$2/24" dev "v-$1"
}
add_node bob 10.51.0.20
add_node sarah 10.51.0.30

run_direct() { # $1 ns-short, $2 keyfile, $3 peerpub, $4 extra-flags, $5 log
	# NOTE: no --server, no --server-key, no token. That is the whole point.
	sudo ip netns exec "ns-$1" "$BN" --role=buddy --direct \
		--key "$2" --peer-key "$3" \
		--known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive $4 >"$5" 2>&1 &
	PIDS="$PIDS $!"
}

assert_connected() { # $1 log, $2 expected-via, $3 label
	for _ in $(seq 1 40); do grep -q 'CONNECTED:' "$1" 2>/dev/null && break; sleep 1; done
	line=$(grep -m1 'CONNECTED:' "$1" 2>/dev/null || true)
	echo "  $3: ${line:-<none>}"
	echo "$line" | grep -qF "via=\"$2\""
}

FAIL=0

echo "== PHASE 1: --direct --wireguard, no server =="
run_direct bob "$D/bob.key" "$SARAHPUB" "--wireguard --listen-port 51820" "$D/bob.log"
sleep 2
run_direct sarah "$D/sarah.key" "$BOBPUB" "--wireguard --peer-endpoint 10.51.0.20:51820" "$D/sarah.log"

if assert_connected "$D/sarah.log" "direct (configured endpoint) (WireGuard)" "sarah" && \
   assert_connected "$D/bob.log" "direct (configured endpoint) (WireGuard)" "bob"; then
	# The listening side must have had NO endpoint and learned it from the
	# handshake. Without this assertion the case could pass on a build that still
	# configured an endpoint from somewhere.
	if grep -q 'remote=adopted-from-handshake' "$D/bob.log"; then
		echo "  [PASS] the listening side ran with no endpoint and adopted the partner's"
	else
		echo "  [FAIL] bob had an endpoint configured — the no-endpoint path was not exercised"
		FAIL=1
	fi
	VIP_BOB=$(grep -m1 'CONNECTED:' "$D/sarah.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	echo "  ping bob's VIP ($VIP_BOB) from ns-sarah over the WireGuard interface..."
	if sudo ip netns exec ns-sarah ping -c 3 -W 2 "$VIP_BOB" >/dev/null 2>&1; then
		echo "  [PASS] WireGuard data plane carries traffic with no server involved"
	else
		echo "  [FAIL] VIP ping over the WireGuard interface"; FAIL=1
	fi
else
	echo "  [FAIL] did not come up on the WireGuard plane"; FAIL=1
	tail -8 "$D/bob.log" | sed 's/^/    bob| /'
	tail -8 "$D/sarah.log" | sed 's/^/    sarah| /'
fi

for p in $PIDS; do sudo kill "$p" 2>/dev/null; done; PIDS=""; sleep 2

echo "== PHASE 2: same pair on the default QUIC plane — no regression =="
run_direct bob "$D/bob.key" "$SARAHPUB" "--listen-port 51820 --forward 127.0.0.1:9" "$D/bob2.log"
sleep 2
run_direct sarah "$D/sarah.key" "$BOBPUB" "--peer-endpoint 10.51.0.20:51820 -L 127.0.0.1:0" "$D/sarah2.log"
if assert_connected "$D/sarah2.log" "direct (configured endpoint)" "sarah"; then
	echo "  [PASS] QUIC plane unaffected"
else
	echo "  [FAIL] QUIC plane regressed"; FAIL=1; tail -6 "$D/sarah2.log" | sed 's/^/    sarah| /'
fi

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

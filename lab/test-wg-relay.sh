#!/usr/bin/env bash
# e2e for relay-over-WireGuard (Phase 3 4d) with the REAL binary.
#
# Same three-netns bridge as test-wg-buddy.sh, but the DIRECT path between the two
# buddies is firewalled off, so the fallback chain must drop to the relay:
#   ns-srv  10.50.0.10  handshake+relay (advertises itself via --relay-endpoint)
#   ns-a    10.50.0.20  buddy A (--wireguard, pins B) — DROPs traffic to/from B
#   ns-b    10.50.0.30  buddy B (--wireguard, pins A) — DROPs traffic to/from A
# Both can still reach the relay (10.50.0.10), so the punch fails and each binds a
# leg on the relay; kernel WG then runs with the relay address as its endpoint and
# the relay blindly forwards the encrypted WG packets between the two legs (it is
# never a WG peer and holds no key — RELAY_OFFER is unchanged, no protocol bump).
#
# Asserts: both log CONNECTED via="handshake server as relay (WireGuard)", and ns-a
# can ping B's overlay VIP over bnet0 (data crosses the relayed tunnel). Needs root
# + wg module.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgr/bn
D=/tmp/wgr
TOKEN=lab-wg-relay-token

cleanup() {
	set +e
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	for ns in ns-srv ns-a ns-b ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
PIDS=""

rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
sudo modprobe wireguard

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" identity)
APUB=$("$BN" --key "$D/a.key" identity)
BPUB=$("$BN" --key "$D/b.key" identity)
echo "server=$SRVPUB"; echo "A=$APUB"; echo "B=$BPUB"

echo "== bridge topology (ns-srv/a/b on br0 in ns-sw) =="
sudo ip netns add ns-sw; sudo ip netns add ns-srv; sudo ip netns add ns-a; sudo ip netns add ns-b
sudo ip netns exec ns-sw ip link add br0 type bridge
sudo ip netns exec ns-sw ip link set br0 up
add_node() { # $1 ns, $2 addr
	sudo ip link add "v-$1" netns "ns-$1" type veth peer name "b-$1" netns ns-sw
	sudo ip netns exec ns-sw ip link set "b-$1" master br0
	sudo ip netns exec ns-sw ip link set "b-$1" up
	sudo ip -n "ns-$1" link set "v-$1" up
	sudo ip -n "ns-$1" link set lo up
	sudo ip -n "ns-$1" addr add "$2/24" dev "v-$1"
}
add_node srv 10.50.0.10
add_node a 10.50.0.20
add_node b 10.50.0.30

echo "== firewall the DIRECT path (force relay) =="
# Drop A<->B both directions; the relay (10.50.0.10) stays reachable. The punch
# packets to the peer's candidate are dropped, so the chain falls to the relay.
sudo ip netns exec ns-a iptables -A OUTPUT -d 10.50.0.30 -j DROP
sudo ip netns exec ns-a iptables -A INPUT  -s 10.50.0.30 -j DROP
sudo ip netns exec ns-b iptables -A OUTPUT -d 10.50.0.20 -j DROP
sudo ip netns exec ns-b iptables -A INPUT  -s 10.50.0.20 -j DROP

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 logfile
	sudo ip netns exec "ns-$1" env BUDDYNET_TOKEN="$TOKEN" "$BN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive --wireguard >"$4" 2>&1 &
	PIDS="$PIDS $!"
}

echo "== handshake+relay server (advertises itself as relay) =="
sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
	--relay-endpoint 10.50.0.10:51821 \
	--key "$D/srv.key" >"$D/srv.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1

assert_connected() { # $1 logfile, $2 expected-via, $3 label
	for _ in $(seq 1 40); do grep -q 'CONNECTED:' "$1" 2>/dev/null && break; sleep 1; done
	line=$(grep -m1 'CONNECTED:' "$1" 2>/dev/null || true)
	echo "  $3: ${line:-<none>}"
	echo "$line" | grep -qF "via=\"$2\""
}

FAIL=0
echo "== relay-over-WireGuard =="
run_buddy a "$D/a.key" "$BPUB" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "$D/b.log"
VIA="handshake server as relay (WireGuard)"
if assert_connected "$D/a.log" "$VIA" "buddy-a" && \
   assert_connected "$D/b.log" "$VIA" "buddy-b"; then
	VIP_B=$(grep -m1 'CONNECTED:' "$D/a.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	echo "  ping partner B's VIP ($VIP_B) from ns-a over bnet0 (via relay)..."
	if sudo ip netns exec ns-a ping -c 3 -W 2 "$VIP_B" >/dev/null 2>&1; then
		echo "  [PASS] relay-over-WireGuard + VIP ping"
	else
		echo "  [FAIL] VIP ping over relayed bnet0"; FAIL=1
	fi
else
	echo "  [FAIL] did not reach via=\"$VIA\""; FAIL=1
	tail -8 "$D/a.log" | sed 's/^/    a| /'
fi

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

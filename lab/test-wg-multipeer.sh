#!/usr/bin/env bash
# e2e for MultiPeer over WireGuard (Phase 3) with the REAL binary: one interface
# per buddy (bnet0, bnet1, …), NOT one shared device — so N buddies never fight
# over a single WG listen port.
#
# Full mesh of three buddies on one bridge (direct punch trivially works), each
# running --wireguard --peers-file with the other two listed:
#   ns-srv  10.50.0.10  handshake+relay
#   ns-a    10.50.0.20  buddy A  (peers: B,C)
#   ns-b    10.50.0.30  buddy B  (peers: A,C)
#   ns-c    10.50.0.40  buddy C  (peers: A,B)
# Each pair shares a bootstrap token; every buddy is pinned by key (no SAS).
#
# Asserts: each node reaches TWO partners (two CONNECTED lines, on bnet0 + bnet1),
# and can ping BOTH partner VIPs over their per-buddy interfaces. Needs root + wg.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgm/bn
D=/tmp/wgm

cleanup() {
	set +e
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	for ns in ns-srv ns-a ns-b ns-c ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
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
CPUB=$("$BN" --key "$D/c.key" identity)

echo "== per-pair bootstrap tokens + manifests =="
TAB=tok-ab; TAC=tok-ac; TBC=tok-bc
printf '%s %s\n%s %s\n' "$BPUB" "$TAB" "$CPUB" "$TAC" > "$D/a.peers"
printf '%s %s\n%s %s\n' "$APUB" "$TAB" "$CPUB" "$TBC" > "$D/b.peers"
printf '%s %s\n%s %s\n' "$APUB" "$TAC" "$BPUB" "$TBC" > "$D/c.peers"

echo "== bridge topology =="
sudo ip netns add ns-sw; for n in srv a b c; do sudo ip netns add "ns-$n"; done
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
add_node c 10.50.0.40

echo "== handshake+relay server =="
sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
	--relay-endpoint 10.50.0.10:51821 \
	--key "$D/srv.key" >"$D/srv.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1

run_buddy() { # $1 ns, $2 keyfile, $3 peersfile, $4 logfile
	sudo ip netns exec "ns-$1" "$BN" --role=buddy --wireguard \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peers-file "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive >"$4" 2>&1 &
	PIDS="$PIDS $!"
}
run_buddy a "$D/a.key" "$D/a.peers" "$D/a.log"
run_buddy b "$D/b.key" "$D/b.peers" "$D/b.log"
run_buddy c "$D/c.key" "$D/c.peers" "$D/c.log"

# Wait until a node has TWO distinct CONNECTED partners.
wait_two() { # $1 logfile
	for _ in $(seq 1 40); do
		[ "$(grep -c 'CONNECTED:' "$1" 2>/dev/null)" -ge 2 ] && return 0
		sleep 1
	done
	return 1
}

FAIL=0
check_node() { # $1 ns, $2 logfile, $3 label
	if ! wait_two "$2"; then
		echo "  [FAIL] $3 did not reach 2 partners"; tail -4 "$2" | sed "s/^/    $3| /"; FAIL=1; return
	fi
	echo "  $3 CONNECTED lines:"; grep 'CONNECTED:' "$2" | sed "s/^/    $3| /"
	# Ping each partner VIP that appears on this node's CONNECTED lines.
	local vips; vips=$(grep 'CONNECTED:' "$2" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2 | sort -u)
	for vip in $vips; do
		if sudo ip netns exec "ns-$1" ping -c 2 -W 2 "$vip" >/dev/null 2>&1; then
			echo "    [PASS] $3 → $vip over its bnetN"
		else
			echo "    [FAIL] $3 → $vip ping failed"; FAIL=1
		fi
	done
	# Sanity: this node should have brought up two interfaces (bnet0 + bnet1).
	local n; n=$(sudo ip netns exec "ns-$1" sh -c 'ip -o link show | grep -c bnet')
	echo "    $3 bnet interfaces: $n"
	[ "$n" -ge 2 ] || { echo "    [FAIL] $3 expected >=2 bnet interfaces"; FAIL=1; }
}

echo "== assert full mesh =="
check_node a "$D/a.log" buddy-a
check_node b "$D/b.log" buddy-b
check_node c "$D/c.log" buddy-c

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

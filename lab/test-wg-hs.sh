#!/usr/bin/env bash
# e2e for the WireGuard CONTROL plane (WG handshake, Phase 3 slice 2+3) with the
# REAL binary. Matchmaking runs over an ephemeral WireGuard tunnel to the server
# instead of plain UDP / QUIC: the server's WG peers ARE the --authorized allowlist,
# so kernel WireGuard itself is the admission control.
#
# Bridge topology (ns-srv/a/b on br0 in ns-sw):
#   ns-srv 10.50.0.10  handshake server (--wireguard --authorized A,B)
#   ns-a   10.50.0.20  buddy A (--wireguard, pins B)
#   ns-b   10.50.0.30  buddy B (--wireguard, pins A)
#
# Asserts:
#   1) A and B pair OVER THE WG HANDSHAKE and bring up the data tunnel; A can ping
#      B's overlay VIP over bnetN (full WG-only stack: control + data).
#   2) An UNAUTHORIZED buddy C (key not in the allowlist) cannot pair — its WG
#      handshake to the server is rejected by the kernel, so its REGISTER never
#      arrives. (the allowlist = network admission control.)
# Needs root + the wg module.
set -euo pipefail
cd "$(dirname "$0")/.."
D=/tmp/wghs-e2e
BN="$D/bn"
TOKEN=lab-wg-hs-token

kill_actors() { set +e; sudo pkill -f "$BN" 2>/dev/null; set -e; }
cleanup() {
	set +e
	kill_actors
	for ns in ns-srv ns-a ns-b ns-c ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

sudo rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
sudo modprobe wireguard

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" identity)
APUB=$("$BN" --key "$D/a.key" identity)
BPUB=$("$BN" --key "$D/b.key" identity)
CPUB=$("$BN" --key "$D/c.key" identity)
printf '%s buddy-a\n%s buddy-b\n' "$APUB" "$BPUB" > "$D/auth.txt"
echo "server=$SRVPUB"; echo "A=$APUB"; echo "B=$BPUB"; echo "C=$CPUB (NOT authorized)"

echo "== bridge topology =="
sudo ip netns add ns-sw
for ns in srv a b c; do sudo ip netns add "ns-$ns"; done
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

echo "== handshake server (WireGuard control plane, allowlist=A,B) =="
sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 --relay-endpoint 10.50.0.10:51821 \
	--wireguard --authorized "$D/auth.txt" --key "$D/srv.key" >"$D/srv.log" 2>&1 &
sleep 1.5

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 logfile
	sudo ip netns exec "ns-$1" env BUDDYNET_TOKEN="$TOKEN" "$BN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" \
		--no-interactive --wireguard >"$4" 2>&1 &
}

FAIL=0

echo
echo "########## TEST 1: A<->B pair over the WG handshake + data tunnel ##########"
run_buddy a "$D/a.key" "$BPUB" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "$D/b.log"
for _ in $(seq 1 40); do grep -q 'CONNECTED:' "$D/a.log" 2>/dev/null && grep -q 'CONNECTED:' "$D/b.log" 2>/dev/null && break; sleep 1; done
LA=$(grep -m1 'CONNECTED:' "$D/a.log" 2>/dev/null || true)
LB=$(grep -m1 'CONNECTED:' "$D/b.log" 2>/dev/null || true)
echo "  buddy-a: ${LA:-<none>}"
echo "  buddy-b: ${LB:-<none>}"
grep -q 'transport=wireguard' "$D/srv.log" && echo "  (server served the control plane over WireGuard)"
if [ -n "$LA" ] && [ -n "$LB" ]; then
	VIP_B=$(echo "$LA" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	echo "  ping B's VIP ($VIP_B) from ns-a over bnetN..."
	if sudo ip netns exec ns-a ping -c 3 -W 2 "$VIP_B" >/dev/null 2>&1; then
		echo "  [PASS] paired over WG handshake + data tunnel up + VIP ping"
	else
		echo "  [FAIL] VIP ping failed"; FAIL=1
	fi
else
	echo "  [FAIL] A and B did not both reach CONNECTED over the WG handshake"; FAIL=1
	tail -6 "$D/a.log" | sed 's/^/    a| /'
fi
kill_actors; sleep 2

echo
echo "########## TEST 2: unauthorized key C is rejected by kernel WG ##########"
# restart the server (kill_actors stopped it too) and try C, which is NOT allowlisted.
sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 --relay-endpoint 10.50.0.10:51821 \
	--wireguard --authorized "$D/auth.txt" --key "$D/srv.key" >"$D/srv2.log" 2>&1 &
sleep 1.5
run_buddy c "$D/c.key" "$APUB" "$D/c.log"
sleep 8
if grep -q 'CONNECTED:' "$D/c.log" 2>/dev/null; then
	echo "  [FAIL] unauthorized buddy C reached CONNECTED — admission control breached!"; FAIL=1
elif grep -q 'PAIRED:' "$D/srv2.log" 2>/dev/null; then
	echo "  [FAIL] server PAIRED an unauthorized key"; FAIL=1
else
	echo "  [PASS] C never paired (kernel WG dropped its handshake; REGISTER never reached the server)"
fi

echo
if [ "$FAIL" = 0 ]; then echo "RESULT: PASS — WG handshake pairs authorized buddies, rejects the rest"; else echo "RESULT: FAIL"; exit 1; fi

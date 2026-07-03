#!/usr/bin/env bash
# e2e for scoped exposure (--expose) on the --wireguard data plane, REAL binary.
#
# Three netns on one bridge (no NAT → direct punch trivially works):
#   ns-srv  10.50.0.10  handshake+relay
#   ns-a    10.50.0.20  buddy A  (--wireguard --expose 873; serves :873 and :2222)
#   ns-b    10.50.0.30  buddy B  (--wireguard --expose all)
#
# Asserts:
#   1. B reaches A's exposed port :873 over the tunnel        (scoped door open)
#   2. B canNOT reach A's unexposed port :2222                (fail-closed floor)
#   3. B can still ping A's VIP                               (diagnosis allowed)
#   4. A reaches any port on B (--expose all = explicit full host)
#   5. after teardown the `inet buddynet` nft table is gone in ns-a (idempotent)
#   6. fail-closed default: buddy WITHOUT --expose exposes NOTHING (port blocked)
# Needs root + wireguard module + kernel nftables.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgexp/bn
D=/tmp/wgexp
TOKEN=lab-wg-expose-token

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

echo "== unit smoke (kernel nftables reachable as root) =="
sudo go test ./internal/nft/ -run TestKernelSmoke -count=1 >/dev/null

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" identity)
APUB=$("$BN" --key "$D/a.key" identity)
BPUB=$("$BN" --key "$D/b.key" identity)

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

start_server() {
	sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
		--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
		--key "$D/srv.key" --relay-endpoint 10.50.0.10:51821 >"$D/srv.log" 2>&1 &
	PIDS="$PIDS $!"
}

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 extra-flags, $5 logfile
	sudo ip netns exec "ns-$1" env BUDDYNET_TOKEN="$TOKEN" "$BN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive $4 >"$5" 2>&1 &
	PIDS="$PIDS $!"
}

assert_connected() { # $1 logfile, $2 label
	for _ in $(seq 1 30); do grep -q 'CONNECTED:' "$1" 2>/dev/null && break; sleep 1; done
	line=$(grep -m1 'CONNECTED:' "$1" 2>/dev/null || true)
	echo "  $2: ${line:-<none>}"
	echo "$line" | grep -qF 'via="direct P2P (WireGuard)"'
}

# Dummy TCP services in ns-a: the shared one on :873 and the "private" one on :2222.
sudo ip netns exec ns-a sh -c 'while true; do echo shared | nc -l -p 873 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
sudo ip netns exec ns-a sh -c 'while true; do echo private | nc -l -p 2222 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
# One service in ns-b to prove --expose all keeps whole-host reach.
sudo ip netns exec ns-b sh -c 'while true; do echo b-service | nc -l -p 8080 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"

FAIL=0
probe() { # $1 ns, $2 vip, $3 port → 0 if TCP connect succeeds
	sudo ip netns exec "ns-$1" nc -z -w 2 "$2" "$3" >/dev/null 2>&1
}

echo "== PHASE 1: A scoped to :873, B explicit all =="
start_server; sleep 1
run_buddy a "$D/a.key" "$BPUB" "--wireguard --expose 873" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard --expose all" "$D/b.log"
if assert_connected "$D/a.log" "buddy-a" && assert_connected "$D/b.log" "buddy-b"; then
	VIP_A=$(grep -m1 'CONNECTED:' "$D/b.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	VIP_B=$(grep -m1 'CONNECTED:' "$D/a.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	grep -q 'exposed=tcp/873' "$D/a.log" || { echo "  [FAIL] A did not log its scope"; FAIL=1; }

	if probe b "$VIP_A" 873; then echo "  [PASS] B reaches A's exposed :873"
	else echo "  [FAIL] B cannot reach the exposed :873"; FAIL=1; fi

	if probe b "$VIP_A" 2222; then echo "  [FAIL] B reached the UNEXPOSED :2222 — scope broken"; FAIL=1
	else echo "  [PASS] B is blocked from the unexposed :2222"; fi

	if sudo ip netns exec ns-b ping -c 2 -W 2 "$VIP_A" >/dev/null 2>&1; then
		echo "  [PASS] ping still works (diagnosis)"
	else echo "  [FAIL] ping to A's VIP blocked"; FAIL=1; fi

	if probe a "$VIP_B" 8080; then echo "  [PASS] A reaches B freely (--expose all)"
	else echo "  [FAIL] --expose all did not keep whole-host reach"; FAIL=1; fi
else
	echo "  [FAIL] tunnel did not come up"; FAIL=1
	tail -5 "$D/a.log" | sed 's/^/    a| /'; tail -5 "$D/b.log" | sed 's/^/    b| /'
fi

echo "== PHASE 2: teardown removes the nft table =="
for p in $PIDS; do sudo kill "$p" 2>/dev/null; done; PIDS=""; sleep 2
if sudo ip netns exec ns-a nft list table inet buddynet >/dev/null 2>&1; then
	echo "  [FAIL] inet buddynet table lingers in ns-a after shutdown"; FAIL=1
else
	echo "  [PASS] nft table removed on teardown"
fi

echo "== PHASE 3: fail-closed default (no --expose at all) =="
sudo ip netns exec ns-a sh -c 'while true; do echo shared | nc -l -p 873 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
start_server; sleep 1
: > "$D/a3.log"; : > "$D/b3.log"
run_buddy a "$D/a.key" "$BPUB" "--wireguard" "$D/a3.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard --expose all" "$D/b3.log"
if assert_connected "$D/a3.log" "buddy-a" && assert_connected "$D/b3.log" "buddy-b"; then
	VIP_A=$(grep -m1 'CONNECTED:' "$D/b3.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	grep -q 'exposed=NONE' "$D/a3.log" || { echo "  [FAIL] A did not log exposed=NONE"; FAIL=1; }
	if probe b "$VIP_A" 873; then echo "  [FAIL] default exposed :873 — NOT fail-closed"; FAIL=1
	else echo "  [PASS] no --expose → nothing reachable (fail-closed)"; fi
else
	echo "  [FAIL] phase-3 tunnel did not come up"; FAIL=1
	tail -5 "$D/a3.log" | sed 's/^/    a| /'
fi

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

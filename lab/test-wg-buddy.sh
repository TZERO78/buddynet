#!/usr/bin/env bash
# e2e for the --wireguard buddy data path (Phase 3 4c) with the REAL binary.
#
# Three netns on one bridge (no NAT → direct punch trivially works):
#   ns-srv  10.50.0.10  handshake+relay
#   ns-a    10.50.0.20  buddy A  (--wireguard, pins B)
#   ns-b    10.50.0.30  buddy B  (--wireguard, pins A)
# Buddies pin each other (--peer-key) so no SAS prompt; --no-interactive.
#
# Asserts: both log CONNECTED via="direct P2P (WireGuard)", and ns-a can ping B's
# overlay VIP over bnet0. Then a QUIC smoke run (no --wireguard) to confirm the
# default path still reaches via="direct P2P" (no regression). Needs root + wg module.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgb/bn
D=/tmp/wgb
TOKEN=lab-wg-e2e-token

kill_actors() { set +e; sudo pkill -f "$BN" 2>/dev/null; set -e; }
cleanup() {
	set +e
	kill_actors
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
# WG-only control plane (phase 1): the server's WG peers ARE the allowlist.
printf '%s a\n%s b\n' "$APUB" "$BPUB" > "$D/auth.txt"

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

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 extra-flags, $5 logfile
	sudo ip netns exec "ns-$1" env BUDDYNET_TOKEN="$TOKEN" "$BN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive $4 >"$5" 2>&1 &
	PIDS="$PIDS $!"
}

start_server() { # $1 mode: wg (WireGuard control plane) | plain (UDP control plane)
	local extra=""
	[ "${1:-plain}" = wg ] && extra="--wireguard --authorized $D/auth.txt"
	# shellcheck disable=SC2086
	sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
		--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
		--key "$D/srv.key" --relay-endpoint 10.50.0.10:51821 $extra >"$D/srv.log" 2>&1 &
	PIDS="$PIDS $!"
}

assert_connected() { # $1 logfile, $2 expected-via, $3 label
	for _ in $(seq 1 30); do grep -q 'CONNECTED:' "$1" 2>/dev/null && break; sleep 1; done
	line=$(grep -m1 'CONNECTED:' "$1" 2>/dev/null || true)
	echo "  $3: ${line:-<none>}"
	echo "$line" | grep -qF "via=\"$2\""
}

FAIL=0
echo "== PHASE 1: --wireguard direct P2P (WireGuard control plane) =="
start_server wg; sleep 1.5
run_buddy a "$D/a.key" "$BPUB" "--wireguard" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard" "$D/b.log"
if assert_connected "$D/a.log" "direct P2P (WireGuard)" "buddy-a" && \
   assert_connected "$D/b.log" "direct P2P (WireGuard)" "buddy-b"; then
	# Partner's VIP is the one on buddy-a's CONNECTED line (NOT a's own identity line).
	VIP_B=$(grep -m1 'CONNECTED:' "$D/a.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	echo "  ping partner B's VIP ($VIP_B) from ns-a over bnet0..."
	if sudo ip netns exec ns-a ping -c 3 -W 2 "$VIP_B" >/dev/null 2>&1; then
		echo "  [PASS] WireGuard direct P2P + VIP ping"
	else
		echo "  [FAIL] VIP ping over bnet0"; FAIL=1
	fi
else
	echo "  [FAIL] did not reach via=\"direct P2P (WireGuard)\""; FAIL=1
	tail -5 "$D/a.log" | sed 's/^/    a| /'
fi

# Phase 1 used a WireGuard control plane; phase 2 (QUIC) needs a plain UDP one, so
# restart everything and bring the server back in plain mode.
kill_actors; sleep 2; PIDS=""
start_server plain; sleep 1.5

echo "== PHASE 2: QUIC default (no --wireguard) — no regression =="
: > "$D/a2.log"; : > "$D/b2.log"
run_buddy a "$D/a.key" "$BPUB" "-L 127.0.0.1:0" "$D/a2.log"
run_buddy b "$D/b.key" "$APUB" "-L 127.0.0.1:0" "$D/b2.log"
if assert_connected "$D/a2.log" "direct P2P" "buddy-a"; then
	echo "  [PASS] QUIC default still reaches direct P2P"
else
	echo "  [FAIL] QUIC default regressed"; FAIL=1; tail -5 "$D/a2.log" | sed 's/^/    a| /'
fi

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

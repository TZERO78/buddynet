#!/usr/bin/env bash
# WG-4 live VIP<->pubkey binding on the WireGuard path (Phase 3).
#
# identity = key = VIP (10.66.X.Y = SHA-256(pubkey)). A peer that advertises a VIP
# inconsistent with its key — a hostile/buggy roster, or a squat with a forged VIP —
# must be REFUSED before any data plane comes up. The check is in the shared
# pre-connect step (connect.go), so it gates the WireGuard path exactly like QUIC.
#
# Topology (one bridge, three netns):
#   ns-srv 10.50.0.10  handshake server
#   ns-atk 10.50.0.30  wg-vip attacker (parks claiming a VIP; forged or correct)
#   ns-vic 10.50.0.20  victim buddy (--wireguard, pins the attacker's key)
#
# Phase 1 (attack):  attacker advertises a FORGED VIP → victim logs
#                    SECURITY: event=vip-mismatch and brings up NO bnet interface.
# Phase 2 (control): attacker advertises the CORRECT VIP → victim passes the check
#                    (action=partner-verified), no vip-mismatch.
# Needs root + the wg module.
set -euo pipefail
cd "$(dirname "$0")/.."
D=/tmp/wgvip
BN="$D/bn"
ATK="$D/wg-vip"
FORGED_VIP=10.66.0.1
TOK1=lab-wg-vip-forged
TOK2=lab-wg-vip-correct

# kill_phase tears down the per-phase actors (victim buddy + attacker) but leaves
# the handshake server running across both phases.
kill_phase() { set +e; sudo pkill -f "$BN --role=buddy" 2>/dev/null; sudo pkill -f "$ATK" 2>/dev/null; set -e; }
cleanup() {
	set +e
	kill_phase
	sudo pkill -f "$BN" 2>/dev/null
	for ns in ns-srv ns-atk ns-vic ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

sudo rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
go build -o "$ATK" ./lab/wg-vip
sudo modprobe wireguard

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" identity)
ATKPUB=$("$BN" --key "$D/atk.key" identity)     # attacker's REAL key (victim pins it)
VICPUB=$("$BN" --key "$D/vic.key" identity)
echo "server=$SRVPUB"; echo "attacker=$ATKPUB"; echo "victim=$VICPUB"

echo "== bridge topology =="
sudo ip netns add ns-sw
for ns in srv atk vic; do sudo ip netns add "ns-$ns"; done
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
add_node atk 10.50.0.30
add_node vic 10.50.0.20

echo "== handshake server =="
sudo ip netns exec ns-srv "$BN" --role=handshake --listen 0.0.0.0:51820 \
	--key "$D/srv.key" >"$D/srv.log" 2>&1 &
PIDS=$!
sleep 1

start_attacker() { # $1 token, $2 vip-arg ("" = correct)
	local vipflag=""
	[ -n "$2" ] && vipflag="-vip $2"
	# shellcheck disable=SC2086
	sudo ip netns exec ns-atk "$ATK" -server 10.50.0.10:51820 -server-key "$SRVPUB" \
		-key "$D/atk.key" -token "$1" $vipflag >"$D/atk.log" 2>&1 &
	sleep 1
}

run_victim() { # $1 token, $2 logfile
	sudo ip netns exec ns-vic env BUDDYNET_TOKEN="$1" "$BN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$D/vic.key" --peer-key "$ATKPUB" --no-interactive --wireguard >"$2" 2>&1 &
	# let it pair, run the pre-connect check, and (not) bring up the interface
	for _ in $(seq 1 12); do
		grep -qE 'event=vip-mismatch|action=partner-verified|does not match its key' "$2" 2>/dev/null && break
		sleep 1
	done
	sleep 1
}

bnet_count() { sudo ip netns exec ns-vic ip -o link show 2>/dev/null | grep -c -E 'bnet[0-9]' || true; }

FAIL=0

echo
echo "########## PHASE 1: forged VIP (attacker claims $FORGED_VIP) ##########"
start_attacker "$TOK1" "$FORGED_VIP"
run_victim "$TOK1" "$D/vic.forged.log"
NB=$(bnet_count)
echo "  attacker advertised vip=$FORGED_VIP ; attacker key derives a different vip"
if grep -qE 'event=vip-mismatch|does not match its key' "$D/vic.forged.log" && [ "$NB" = "0" ]; then
	echo "  [PASS] victim rejected the forged VIP (vip-mismatch) and brought up NO bnet interface"
	grep -m1 'vip-mismatch' "$D/vic.forged.log" | sed 's/^/    /'
else
	echo "  [FAIL] expected a vip-mismatch reject and no bnet (bnet count=$NB)"; FAIL=1
	tail -6 "$D/vic.forged.log" | sed 's/^/    /'
fi
kill_phase; sleep 2

echo
echo "########## PHASE 2: correct VIP (control — check must PASS) ##########"
start_attacker "$TOK2" ""
run_victim "$TOK2" "$D/vic.ok.log"
if grep -q 'action=partner-verified' "$D/vic.ok.log" && ! grep -q 'event=vip-mismatch' "$D/vic.ok.log"; then
	echo "  [PASS] victim accepted the consistent VIP (partner-verified, no vip-mismatch)"
	grep -m1 'action=partner-verified' "$D/vic.ok.log" | sed 's/^/    /'
else
	echo "  [FAIL] expected partner-verified and no vip-mismatch on the correct VIP"; FAIL=1
	tail -6 "$D/vic.ok.log" | sed 's/^/    /'
fi

echo
if [ "$FAIL" = 0 ]; then echo "RESULT: PASS — WG-4 VIP<->pubkey binding holds on the WireGuard path"; else echo "RESULT: FAIL"; exit 1; fi

#!/usr/bin/env bash
# Live proof that a per-buddy exposure scope edited in the --peers-file manifest
# takes effect on SIGHUP — the reconnect-only gap this test was written to close.
#
# Topology (bridge, direct punch trivially works):
#   ns-srv  10.50.0.10  handshake+relay
#   ns-a    10.50.0.20  buddy A: --peers-file manifest (buddy B, expose: [873]),
#                       --wireguard; serves :873 and :2222
#   ns-b    10.50.0.30  buddy B: --wireguard --expose all, probes A
#
# Steps:
#   1. Initial scope [873]: B reaches A:873, NOT A:2222.
#   2. Rewrite A's manifest to expose: [2222] (drop 873), send SIGHUP to A.
#   3. After the supervisor restarts A's worker: B reaches A:2222, NOT A:873 —
#      i.e. the TIGHTENING (873 revoked) actually took effect without a manual
#      restart. This is the case that previously only healed on reconnect.
# Needs root + wireguard module + kernel nftables.
set -euo pipefail

# Relay tickets: the same id on the handshake server and the relay. Fixed here
# rather than minted so a failing run is reproducible; production mints one with
# `buddynet gen-relay-id`. In this lab both roles are one process, so the relay
# derives the server key it trusts from --key and only needs the id.
RID=YnVkZHluZXQtbGFiLXJpZA
cd "$(dirname "$0")/.."
BN=/tmp/wgexpr/bn
D=/tmp/wgexpr
TOKEN=lab-wg-expose-reload

cleanup() {
	set +e
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	sudo pkill -f "$BN --role=buddy" 2>/dev/null
	for ns in ns-srv ns-a ns-b ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
PIDS=""

rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
sudo modprobe wireguard

SRVPUB=$("$BN" --key "$D/srv.key" init)
APUB=$("$BN" --key "$D/a.key" init)
BPUB=$("$BN" --key "$D/b.key" init)

echo "== topology =="
sudo ip netns add ns-sw; sudo ip netns add ns-srv; sudo ip netns add ns-a; sudo ip netns add ns-b
sudo ip netns exec ns-sw ip link add br0 type bridge
sudo ip netns exec ns-sw ip link set br0 up
add_node() {
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

# A's manifest: buddy B pinned, initial scope tcp/873.
cat > "$D/a-peers.yaml" <<EOF
buddies:
  - name: bob
    key: $BPUB
    token: $TOKEN
    expose: [873]
EOF

sudo ip netns exec ns-srv "$BN" --role=handshake,relay --relay-id "$RID" \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
	--key "$D/srv.key" --relay-endpoint 10.50.0.10:51821 >"$D/srv.log" 2>&1 &
PIDS="$PIDS $!"

# Services on A.
sudo ip netns exec ns-a sh -c 'while true; do echo p873 | nc -l -p 873 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
sudo ip netns exec ns-a sh -c 'while true; do echo p2222 | nc -l -p 2222 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"

sleep 1
# A supervises B from the manifest (--peers-file drives per-buddy expose).
sudo ip netns exec ns-a "$BN" --role=buddy \
	--server 10.50.0.10:51820 --server-key "$SRVPUB" --key "$D/a.key" \
	--known-peers "$D/a.kp" --peers "$D/a.pj" --peers-file "$D/a-peers.yaml" \
	--no-interactive --wireguard >"$D/a.log" 2>&1 &
A_PID=$!; PIDS="$PIDS $A_PID"

# B pins A and probes.
sudo ip netns exec ns-b "$BN" --join "$TOKEN" --role=buddy \
	--server 10.50.0.10:51820 --server-key "$SRVPUB" --key "$D/b.key" \
	--peer-key "$APUB" --known-peers "$D/b.kp" --peers "$D/b.pj" \
	--no-interactive --wireguard --expose all >"$D/b.log" 2>&1 &
PIDS="$PIDS $!"

wait_connected() { for _ in $(seq 1 40); do grep -q 'CONNECTED:' "$1" 2>/dev/null && return 0; sleep 1; done; return 1; }
wait_connected "$D/a.log" && wait_connected "$D/b.log" || { echo "[FAIL] tunnel"; tail -5 "$D/a.log"; exit 1; }
VIP_A=$(grep -m1 'CONNECTED:' "$D/b.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)

FAIL=0
probe() { sudo ip netns exec ns-b nc -z -w 2 "$VIP_A" "$1" >/dev/null 2>&1; }
expect() { # $1 port, $2 open|blocked, $3 label
	if probe "$1"; then got=open; else got=blocked; fi
	if [ "$got" = "$2" ]; then echo "  [PASS] $3 (:$1 $got)"; else echo "  [FAIL] $3 (:$1 $got, want $2)"; FAIL=1; fi
}

echo "== PHASE 1: initial scope expose:[873] =="
expect 873 open "exposed :873 reachable"
expect 2222 blocked "unexposed :2222 blocked"

echo "== PHASE 2: rewrite manifest to expose:[2222], SIGHUP A =="
cat > "$D/a-peers.yaml" <<EOF
buddies:
  - name: bob
    key: $BPUB
    token: $TOKEN
    expose: [2222]
EOF
# The supervisor reprograms bnet0's scope IN PLACE — the tunnel stays up, no
# reconnect, no partner involvement. Wait for the reload-rescope log line.
sudo kill -HUP "$A_PID"
for _ in $(seq 1 20); do
	grep -q 'action=reload-rescope' "$D/a.log" 2>/dev/null && break
	sleep 1
done
grep -q 'action=reload-rescope' "$D/a.log" || { echo "  [FAIL] no reload-rescope after SIGHUP"; FAIL=1; }
# The tunnel must NOT have dropped (still exactly one CONNECTED, no DISCONNECTED).
if [ "$(grep -c 'CONNECTED:' "$D/a.log")" -ne 1 ] || grep -q 'DISCONNECTED:' "$D/a.log"; then
	echo "  [FAIL] tunnel bounced on rescope (should reprogram in place)"; FAIL=1
else
	echo "  [PASS] tunnel stayed up across the rescope (in-place reprogram)"
fi
sleep 1

echo "== PHASE 3: after SIGHUP the tightened scope is live =="
expect 2222 open "newly exposed :2222 reachable"
expect 873 blocked "revoked :873 now blocked (tightening took effect on SIGHUP)"

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; tail -8 "$D/a.log" | sed 's/^/  a| /'; exit 1; fi

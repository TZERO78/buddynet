#!/usr/bin/env bash
# Coexistence test: scoped exposure (--expose) alongside the host's OWN firewall
# tooling — iptables-nft, iptables-legacy (x_tables) and a ufw-style default-deny
# posture — plus the documented `nft flush ruleset` limitation. firewalld is not
# exercised directly (it drives the same kernel subsystems as iptables-nft; its
# reload behaviour is covered by the restore/reload scenario).
#
# Topology as in test-wg-expose.sh: ns-srv (handshake+relay), ns-a (--expose 873,
# services on :873/:2222), ns-b (--expose all, probes A).
#
# Asserts, all inside ns-a's netns:
#   1. Baseline: :873 open, :2222 blocked.
#   2. iptables-nft explicitly ACCEPTs :2222 on bnet0 → STILL blocked
#      (a DROP in any table wins; the host firewall cannot open what BuddyNet scopes).
#   3. Same via iptables-legacy (x_tables path).
#   4. A host-firewall reload (iptables-restore) does NOT touch the buddynet table.
#   5. ufw-style default-deny INPUT → the exposed :873 is blocked TOO (both
#      firewalls must allow — honest, documented interplay); allowing :873 in the
#      host firewall opens it again while :2222 stays blocked.
#   6. `nft flush ruleset` clears the buddynet table (documented limitation) and a
#      buddy restart re-asserts it.
# Needs root + wireguard module + kernel nftables + iptables/iptables-legacy.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/wgfw/bn
D=/tmp/wgfw
TOKEN=lab-wg-fw-token

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

SRVPUB=$("$BN" --key "$D/srv.key" identity)
APUB=$("$BN" --key "$D/a.key" identity)
BPUB=$("$BN" --key "$D/b.key" identity)

echo "== bridge topology =="
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

sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
	--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
	--key "$D/srv.key" --relay-endpoint 10.50.0.10:51821 >"$D/srv.log" 2>&1 &
PIDS="$PIDS $!"

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 extra, $5 log
	sudo ip netns exec "ns-$1" "$BN" --join "$TOKEN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive $4 >"$5" 2>&1 &
	PIDS="$PIDS $!"
}
wait_connected() {
	for _ in $(seq 1 30); do grep -q 'CONNECTED:' "$1" 2>/dev/null && return 0; sleep 1; done
	return 1
}

sudo ip netns exec ns-a sh -c 'while true; do echo shared | nc -l -p 873 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
sudo ip netns exec ns-a sh -c 'while true; do echo private | nc -l -p 2222 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"

sleep 1
run_buddy a "$D/a.key" "$BPUB" "--wireguard --expose 873" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard --expose all" "$D/b.log"
wait_connected "$D/a.log" && wait_connected "$D/b.log" || { echo "[FAIL] tunnel"; exit 1; }
VIP_A=$(grep -m1 'CONNECTED:' "$D/b.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)

FAIL=0
probe() { sudo ip netns exec ns-b nc -z -w 2 "$VIP_A" "$1" >/dev/null 2>&1; }
check() { # $1 port, $2 expect(open|blocked), $3 label
	if probe "$1"; then got=open; else got=blocked; fi
	if [ "$got" = "$2" ]; then echo "  [PASS] $3 (:$1 $got)"; else echo "  [FAIL] $3 (:$1 $got, want $2)"; FAIL=1; fi
}
ipt()  { sudo ip netns exec ns-a iptables "$@"; }
iptl() { sudo ip netns exec ns-a iptables-legacy "$@"; }

echo "== 1: baseline (only buddynet table) =="
check 873 open "exposed port"
check 2222 blocked "unexposed port"

echo "== 2: iptables-nft tries to ACCEPT the unexposed port =="
ipt -A INPUT -i bnet0 -p tcp --dport 2222 -j ACCEPT
check 2222 blocked "host-firewall ACCEPT cannot override the buddynet DROP"
check 873 open "exposed port unaffected"
ipt -D INPUT -i bnet0 -p tcp --dport 2222 -j ACCEPT

echo "== 3: same via iptables-legacy (x_tables) =="
iptl -A INPUT -i bnet0 -p tcp --dport 2222 -j ACCEPT
check 2222 blocked "legacy x_tables ACCEPT cannot override either"
iptl -F INPUT

echo "== 4: host-firewall reload (iptables-restore) leaves our table alone =="
printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n' | \
	sudo ip netns exec ns-a iptables-restore
if sudo ip netns exec ns-a nft list table inet buddynet >/dev/null 2>&1; then
	echo "  [PASS] buddynet table survives iptables-restore"
else
	echo "  [FAIL] iptables-restore clobbered the buddynet table"; FAIL=1
fi
check 873 open "exposed port still open after reload"
check 2222 blocked "unexposed port still blocked after reload"

echo "== 5: ufw-style default-deny on the host (both firewalls must allow) =="
ipt -P INPUT DROP
ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
check 873 blocked "host default-deny also gates the exposed port (defense in depth)"
ipt -I INPUT -i bnet0 -p tcp --dport 873 -j ACCEPT
check 873 open "host-firewall allow + --expose 873 → open"
check 2222 blocked "unexposed port blocked regardless"
ipt -P INPUT ACCEPT; ipt -F INPUT

echo "== 6: nft flush ruleset (documented limitation) + reconnect re-asserts =="
sudo ip netns exec ns-a nft flush ruleset
if probe 2222; then
	echo "  [INFO] after flush the scope is gone (documented — only a global flush does this)"
else
	echo "  [FAIL] expected :2222 open after a global flush (did the flush not run?)"; FAIL=1
fi
# Restart BOTH buddies: a standing kernel-WG tunnel does not notice a partner
# restart (documented semantics), so B must re-register too for A to re-pair.
# The bring-up must then re-assert the scope.
sudo pkill -f "$BN --role=buddy" 2>/dev/null || true
sleep 1
: > "$D/a2.log"; : > "$D/b2.log"
run_buddy a "$D/a.key" "$BPUB" "--wireguard --expose 873" "$D/a2.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard --expose all" "$D/b2.log"
wait_connected "$D/a2.log" || { echo "  [FAIL] reconnect after flush"; FAIL=1; }
sleep 1
check 873 open "scope re-asserted on reconnect: exposed open"
check 2222 blocked "scope re-asserted on reconnect: unexposed blocked"

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

#!/usr/bin/env bash
# e2e for RELAY TICKETS with the REAL binary, over real UDP, in network namespaces.
#
# Three netns on one bridge; the DIRECT path between the buddies is firewalled off,
# so the fallback chain must drop to the relay and every scenario below is decided
# by what the relay does with the ticket:
#   ns-srv  10.50.0.10  handshake + relay (advertises itself via --relay-endpoint)
#   ns-a    10.50.0.20  buddy A (-L 9000, pins B) — DROPs traffic to/from B
#   ns-b    10.50.0.30  buddy B (--forward to a local HTTP server, pins A)
#
# Scenarios:
#   0  positive control — the direct path really IS blocked (else everything below
#      is vacuous: the buddies would pair directly and the relay would be idle)
#   1  matching --relay-id on both sides: pairing succeeds THROUGH the relay and
#      real payload crosses it (curl over the tunnel)
#   2  MISMATCHED --relay-id: the same buddies, the same tickets, refused — and the
#      relay says why. This is the A/B that proves scenario 1 was decided by the
#      ticket check and not by the check being absent
#   3  a relay with no authorization policy refuses to START
#   4  the relay log does not carry source addresses next to session ids
#   5  no relay configured at all: the buddy says so plainly instead of timing out
#
# Needs root (netns) — no WireGuard module, this is the QUIC data plane.
set -euo pipefail

cd "$(dirname "$0")/.."
D=/tmp/bnrt
BN=$D/bn
TOKEN=lab-relay-ticket-token
# The same id on both sides. Fixed rather than minted so a failing run is
# reproducible; production mints one with `buddynet gen-relay-id`.
RID=YnVkZHluZXQtbGFiLXJpZA
# A DIFFERENT, equally valid id — scenario 2 configures the relay with this one
# while the handshake server keeps issuing for RID.
OTHER_RID=YnVkZHluZXQtbGFiLW90aA

PIDS=""
FAIL=0
cleanup() {
	set +e
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	for ns in ns-srv ns-a ns-b ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAIL=1; }

rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" init)
APUB=$("$BN" --key "$D/a.key" init)
BPUB=$("$BN" --key "$D/b.key" init)
echo "  server=$SRVPUB"

echo "== topology (ns-srv/a/b on br0 in ns-sw) =="
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

echo "== firewall the DIRECT path (force the relay) =="
sudo ip netns exec ns-a iptables -A OUTPUT -d 10.50.0.30 -j DROP
sudo ip netns exec ns-a iptables -A INPUT  -s 10.50.0.30 -j DROP
sudo ip netns exec ns-b iptables -A OUTPUT -d 10.50.0.20 -j DROP
sudo ip netns exec ns-b iptables -A INPUT  -s 10.50.0.20 -j DROP

echo
echo "########## 0: positive control — the direct path is really blocked ##########"
# Without this the whole lab could pass while the buddies quietly paired directly
# and the relay was never involved.
if sudo ip netns exec ns-a ping -c1 -W1 10.50.0.30 >/dev/null 2>&1; then
	fail "ns-a can still reach ns-b directly — every scenario below would be vacuous"
else
	pass "direct A<->B path is blocked; the fallback chain must use the relay"
fi
if sudo ip netns exec ns-a ping -c1 -W1 10.50.0.10 >/dev/null 2>&1; then
	pass "the relay is reachable from ns-a"
else
	fail "the relay is unreachable — the lab cannot test a relayed path"
fi

# The service the tunnel actually carries, so a PASS means bytes moved.
sudo ip netns exec ns-b python3 -m http.server 8080 --bind 127.0.0.1 >"$D/http.log" 2>&1 &
PIDS="$PIDS $!"

start_server() { # $1 extra args...
	sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
		--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
		--key "$D/srv.key" "$@" >"$D/srv.log" 2>&1 &
	SRVPID=$!
	PIDS="$PIDS $SRVPID"
	sleep 1
}

run_buddies() { # $1 tag
	sudo ip netns exec ns-a "$BN" --join "$TOKEN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$D/a.key" --peer-key "$BPUB" --known-peers "$D/a.kp" --peers "$D/a.pj" \
		--no-interactive -L 127.0.0.1:9000 >"$D/a.$1.log" 2>&1 &
	PIDS="$PIDS $!"
	sudo ip netns exec ns-b "$BN" --join "$TOKEN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$D/b.key" --peer-key "$APUB" --known-peers "$D/b.kp" --peers "$D/b.pj" \
		--no-interactive --forward 127.0.0.1:8080 >"$D/b.$1.log" 2>&1 &
	PIDS="$PIDS $!"
}

kill_buddies() {
	set +e
	sudo pkill -f "$BN --join" 2>/dev/null
	sleep 1
	set -e
}

wait_connected() { # $1 logfile, $2 seconds
	for _ in $(seq 1 "$2"); do
		grep -q 'CONNECTED:' "$1" 2>/dev/null && return 0
		sleep 1
	done
	return 1
}

echo
echo "########## 1: matching --relay-id — pairing and payload THROUGH the relay ##########"
start_server --relay-endpoint 10.50.0.10:51821 --relay-id "$RID"
grep -q 'relay tickets ON' "$D/srv.log" || fail "the server did not turn relay tickets on"
run_buddies ok
if wait_connected "$D/a.ok.log" 40 && wait_connected "$D/b.ok.log" 40; then
	VIA=$(grep -m1 'CONNECTED:' "$D/a.ok.log" | grep -oE 'via="[^"]*"')
	echo "  buddy-a $VIA"
	if echo "$VIA" | grep -q 'relay'; then
		pass "paired over the relay with a valid ticket"
	else
		fail "paired, but NOT over the relay ($VIA) — the direct block leaked"
	fi
	if sudo ip netns exec ns-a curl -s --max-time 10 http://127.0.0.1:9000/ >"$D/curl.out" 2>&1 &&
		[ -s "$D/curl.out" ]; then
		pass "payload crossed the relayed tunnel ($(wc -c <"$D/curl.out") bytes)"
	else
		fail "no payload over the relayed tunnel"
	fi
	if grep -q 'action=session-paired sid=' "$D/srv.log"; then
		pass "the relay logged the session by id"
	else
		fail "no session-paired line on the relay"
	fi
else
	fail "the buddies never connected with a valid ticket"
	tail -5 "$D/a.ok.log" | sed 's/^/    a| /'
	tail -5 "$D/srv.log" | sed 's/^/    srv| /'
fi
kill_buddies
sudo kill "$SRVPID" 2>/dev/null || true
sleep 1

echo
echo "########## 2: A/B — the SAME setup with a mismatched --relay-id must fail ##########"
# A combined process takes ONE --relay-id, so the mismatch is driven the way an
# operator actually hits it: handshake and relay as two processes, configured with
# two different ids. Everything else — keys, tokens, buddies — is unchanged from
# scenario 1, so the only difference between PASS and FAIL is the ticket check.
sudo ip netns exec ns-srv "$BN" --role=handshake \
	--listen 0.0.0.0:51820 --key "$D/srv.key" \
	--relay-endpoint 10.50.0.10:51821 --relay-id "$RID" >"$D/hs.log" 2>&1 &
PIDS="$PIDS $!"; HSPID=$!
sudo ip netns exec ns-srv "$BN" --role=relay \
	--relay-listen 0.0.0.0:51821 --server-key "$SRVPUB" --relay-id "$OTHER_RID" >"$D/relay.log" 2>&1 &
PIDS="$PIDS $!"; RELPID=$!
sleep 1
run_buddies bad
if wait_connected "$D/a.bad.log" 25; then
	fail "the buddies paired through a relay whose id the ticket does not name"
else
	pass "no pairing: the relay refused a ticket minted for another relay"
fi
if grep -q 'reason="ticket is for a different relay"' "$D/relay.log"; then
	pass "the relay named the reason in its log"
else
	fail "the relay did not log the mismatch reason"
	tail -5 "$D/relay.log" | sed 's/^/    relay| /'
fi
kill_buddies
sudo kill "$HSPID" "$RELPID" 2>/dev/null || true
sleep 1

echo
echo "########## 3: a relay with no authorization policy refuses to start ##########"
set +e
OUT=$(sudo ip netns exec ns-srv "$BN" --role=relay --relay-listen 0.0.0.0:51823 2>&1)
RC=$?
set -e
if [ "$RC" != 0 ] && echo "$OUT" | grep -q 'no authorization policy'; then
	pass "refused to start (exit $RC) and said what to pass"
else
	fail "a relay with no policy started (exit $RC): $OUT"
fi
set +e
OUT=$(sudo ip netns exec ns-srv "$BN" --role=relay --relay-listen 0.0.0.0:51823 --allow-cidr 0.0.0.0/0 2>&1)
RC=$?
set -e
if [ "$RC" != 0 ] && echo "$OUT" | grep -q 'allows every source'; then
	pass "--allow-cidr 0.0.0.0/0 refused with its own message"
else
	fail "an allow-everything relay started (exit $RC): $OUT"
fi

echo
echo "########## 4: rejection logs carry no source addresses ##########"
if grep -q 'action=ticket-rejected' "$D/relay.log"; then
	if grep 'action=ticket-rejected' "$D/relay.log" | grep -qE 'src=|10\.50\.0\.'; then
		fail "a ticket-rejection line carries a source address (that is who-talks-to-whom)"
	else
		pass "ticket-rejection lines carry sid/leg/reason only"
	fi
else
	fail "no rejection lines to check (scenario 2 did not produce any)"
fi

echo
echo "########## 5: no relay configured — the buddy says so ##########"
sudo ip netns exec ns-srv "$BN" --role=handshake --listen 0.0.0.0:51820 \
	--key "$D/srv.key" >"$D/hs2.log" 2>&1 &
PIDS="$PIDS $!"; HS2PID=$!
sleep 1
run_buddies norelay
sleep 20
if grep -q 'no relay is configured' "$D/a.norelay.log"; then
	pass "the buddy reported the missing relay instead of a bare timeout"
else
	fail "no actionable message when the direct path failed and no relay existed"
	tail -5 "$D/a.norelay.log" | sed 's/^/    a| /'
fi
kill_buddies
sudo kill "$HS2PID" 2>/dev/null || true

echo
if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

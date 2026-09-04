#!/usr/bin/env bash
# WG-1 live MITM interposition for the WireGuard data plane (Phase 3).
#
# Proves the EKM-free first-contact SAS (internal/role/binding.go, RFC 6189)
# detects a man in the middle: on the WG path there is no TLS exporter, so the SAS
# is bound to an ephemeral-DH + hash-commitment exchange run over the rendezvous
# socket. A relay that TERMINATES that exchange separately with each side (instead
# of splicing it blind) makes the two buddies derive different bindings — so their
# SAS codes DIVERGE and a human comparing them out of band aborts.
#
# Topology (one bridge, four netns):
#   ns-srv  10.50.0.10  handshake server (pairs A+B, advertises a relay endpoint)
#   ns-mitm 10.50.0.40  the relay endpoint — wg-mitm (attacker) OR the honest relay
#   ns-a    10.50.0.20  buddy A (--wireguard, TOFU: no --peer-key) — DROPs A<->B
#   ns-b    10.50.0.30  buddy B (--wireguard, TOFU: no --peer-key) — DROPs A<->B
# The direct A<->B path is firewalled, so both fall back to the advertised relay.
#
# Three phases:
#   OFFER  — server advertises wg-mitm (a FOREIGN host) and the buddies carry no
#            --peer-relay → assert both log relay-offer-untrusted and the attacker
#            sees no bind (the relay endpoint comes from local trust only).
#   MITM   — same, but the buddies opt in with --peer-relay → assert the two SAS
#            DIFFER (a hostile relay, even a configured one, is caught).
#   HONEST — relay endpoint = real relay on the server host → SAS MATCH (clean).
#
# Buddies must be "interactive" for the first-contact SAS (secret.Interactive()
# needs a TTY), so each runs under `script` which allocates a pty; the SAS the
# buddy prints to that pty is captured and scraped. Needs root + the wg module.
set -euo pipefail

# Relay tickets: the same id on the handshake server and the relay. Fixed here
# rather than minted so a failing run is reproducible; production mints one with
# `buddynet gen-relay-id`. In this lab both roles are one process, so the relay
# derives the server key it trusts from --key and only needs the id.
RID=YnVkZHluZXQtbGFiLXJpZA
cd "$(dirname "$0")/.."
D=/tmp/wgmitm
BN="$D/bn"
MITM="$D/wg-mitm"
TOKEN=lab-wg-mitm-token

kill_actors() { # kill every process we spawned, by their unique temp paths
	set +e
	sudo pkill -f "$BN" 2>/dev/null
	sudo pkill -f "$MITM" 2>/dev/null
	set -e
}
cleanup() {
	set +e
	kill_actors
	for ns in ns-srv ns-mitm ns-a ns-b ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
PIDS=""

sudo rm -rf "$D"; mkdir -p "$D"
echo "== build =="
go build -o "$BN" ./cmd/buddynet
go build -o "$MITM" ./lab/wg-mitm
sudo modprobe wireguard

echo "== identities =="
SRVPUB=$("$BN" --key "$D/srv.key" init)
APUB=$("$BN" --key "$D/a.key" init)
BPUB=$("$BN" --key "$D/b.key" init)
echo "server=$SRVPUB"; echo "A=$APUB"; echo "B=$BPUB"

echo "== bridge topology =="
sudo ip netns add ns-sw
for ns in srv mitm a b; do sudo ip netns add "ns-$ns"; done
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
add_node mitm 10.50.0.40
add_node a 10.50.0.20
add_node b 10.50.0.30

echo "== firewall the DIRECT A<->B path (force the advertised relay) =="
sudo ip netns exec ns-a iptables -A OUTPUT -d 10.50.0.30 -j DROP
sudo ip netns exec ns-a iptables -A INPUT  -s 10.50.0.30 -j DROP
sudo ip netns exec ns-b iptables -A OUTPUT -d 10.50.0.20 -j DROP
sudo ip netns exec ns-b iptables -A INPUT  -s 10.50.0.20 -j DROP

# run_buddy_tofu: TOFU (no --peer-key), interactive via a pty (script) so the
# first-contact SAS is computed and printed; we scrape it, then kill the buddy.
run_buddy_tofu() { # $1 ns, $2 keyfile, $3 logfile, $4 store-suffix, [$5 extra flags]
	sudo ip netns exec "ns-$1" script -qec \
		"$BN --role=buddy --join $TOKEN --server 10.50.0.10:51820 \
		 --server-key $SRVPUB --key $2 --known-peers $D/$4.kp --peers $D/$4.pj \
		 --sas-timeout 25s --wireguard ${5:-}" "$3" </dev/null >/dev/null 2>&1 &
	PIDS="$PIDS $!"
}

# The relay endpoint a buddy binds to comes from LOCAL trust only (relaytrust.go):
# --peer-relay, or a server offer on the --server host. The attacker's relay in
# phase 1 lives on ANOTHER host (10.50.0.40 vs 10.50.0.10), so phase 0 first
# proves the buddies refuse the bare offer, and phase 1 then opts in with
# --peer-relay — the scenario becomes "a relay the operator configured is
# hostile, and nothing rests on it", which is the claim the SAS binding makes.
MITM_RELAY="--peer-relay 10.50.0.40:51821"

# run_buddy_pinned: phase 0 needs no SAS (nothing comes up), so no pty — the
# buddies pin each other with --peer-key and log straight to a file. (`script`
# buffers its typescript until exit, which a kill can lose.)
run_buddy_pinned() { # $1 ns, $2 keyfile, $3 logfile, $4 store-suffix, $5 peer key
	sudo ip netns exec "ns-$1" "$BN" --role=buddy --join "$TOKEN" --server 10.50.0.10:51820 \
		--server-key "$SRVPUB" --key "$2" --known-peers "$D/$4.kp" --peers "$D/$4.pj" \
		--peer-key "$5" --no-interactive --wireguard >"$3" 2>&1 &
	PIDS="$PIDS $!"
}

# scrape_sas: pull the 6-char Crockford SAS out of the PromptSAS block.
scrape_sas() { # $1 logfile
	for _ in $(seq 1 20); do
		grep -aq 'Safety check' "$1" 2>/dev/null && break; sleep 1
	done
	grep -aA5 'Safety check' "$1" 2>/dev/null | tr -d '\r' \
		| grep -aoE '[0-9A-HJKMNP-TV-Z]{6}' | head -1
}

start_server() { # $1 roles, $2 relay-endpoint, [relay-listen]
	local extra=""
	[ -n "${3:-}" ] && extra="--relay-listen $3"
	# --relay-id is passed in both phases: in phase 2 it is what lets the honest
	# relay in this same process accept the pairing at all, and in phase 1 it
	# changes nothing — the attacker's fake relay never checks a ticket, which is
	# the point of the phase (a relay cannot be trusted, so nothing rests on it).
	sudo ip netns exec ns-srv "$BN" --role="$1" --relay-id "$RID" \
		--listen 0.0.0.0:51820 --relay-endpoint "$2" $extra \
		--key "$D/srv.key" >"$D/srv.log" 2>&1 &
	SRVPID=$!
	PIDS="$PIDS $SRVPID"
	sleep 1
}

FAIL=0

echo
echo "########## PHASE 0: server offers a relay on a FOREIGN host, no --peer-relay ##########"
sudo ip netns exec ns-mitm "$MITM" -listen 0.0.0.0:51821 >"$D/mitm0.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1
start_server handshake 10.50.0.40:51821
run_buddy_pinned a "$D/a.key" "$D/a.offer.log" a.offer "$BPUB"
run_buddy_pinned b "$D/b.key" "$D/b.offer.log" b.offer "$APUB"
for _ in $(seq 1 20); do
	grep -aq 'event=relay-offer-untrusted' "$D/a.offer.log" 2>/dev/null && \
	grep -aq 'event=relay-offer-untrusted' "$D/b.offer.log" 2>/dev/null && break; sleep 1
done
sleep 3 # give a bind every chance to reach the attacker if the offer were trusted
if grep -aq 'event=relay-offer-untrusted' "$D/a.offer.log" && grep -aq 'event=relay-offer-untrusted' "$D/b.offer.log"; then
	echo "  [PASS] both buddies logged SECURITY: relay-offer-untrusted for 10.50.0.40:51821"
else
	echo "  [FAIL] expected relay-offer-untrusted in both buddy logs"; FAIL=1
fi
if grep -aq 'leg bound' "$D/mitm0.log"; then
	echo "  [FAIL] the attacker's relay saw a bind although the offer was on a foreign host"; FAIL=1
else
	echo "  [PASS] attacker's relay saw NO bind (offer skipped, direct path exhausted, no relayed path)"
fi
kill_actors
sleep 2

echo
echo "########## PHASE 1: MITM (relay endpoint = wg-mitm attacker, opted in via --peer-relay) ##########"
sudo ip netns exec ns-mitm "$MITM" -listen 0.0.0.0:51821 >"$D/mitm.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1
start_server handshake 10.50.0.40:51821
run_buddy_tofu a "$D/a.key" "$D/a.mitm.log" a.mitm "$MITM_RELAY"
run_buddy_tofu b "$D/b.key" "$D/b.mitm.log" b.mitm "$MITM_RELAY"
SAS_A_M=$(scrape_sas "$D/a.mitm.log")
SAS_B_M=$(scrape_sas "$D/b.mitm.log")
echo "  buddy-a SAS = ${SAS_A_M:-<none>}"
echo "  buddy-b SAS = ${SAS_B_M:-<none>}"
grep -q 'terminating binding on BOTH legs' "$D/mitm.log" && echo "  (wg-mitm terminated the binding on both legs)"
if [ -n "$SAS_A_M" ] && [ -n "$SAS_B_M" ] && [ "$SAS_A_M" != "$SAS_B_M" ]; then
	echo "  [PASS] SAS DIVERGED under MITM → a human comparing them aborts (key NOT trusted)"
else
	echo "  [FAIL] expected two different SAS codes under MITM (got '$SAS_A_M' vs '$SAS_B_M')"; FAIL=1
fi
# stop ALL phase-1 actors (the buddies run under `script`, so kill by path, not PID)
kill_actors
sleep 2

echo
echo "########## PHASE 2: HONEST relay (control — SAS must MATCH) ##########"
# honest relay co-located on ns-srv, advertised to the buddies.
start_server handshake,relay 10.50.0.10:51821 0.0.0.0:51821
run_buddy_tofu a "$D/a.key" "$D/a.ok.log" a.ok
run_buddy_tofu b "$D/b.key" "$D/b.ok.log" b.ok
SAS_A_OK=$(scrape_sas "$D/a.ok.log")
SAS_B_OK=$(scrape_sas "$D/b.ok.log")
echo "  buddy-a SAS = ${SAS_A_OK:-<none>}"
echo "  buddy-b SAS = ${SAS_B_OK:-<none>}"
if [ -n "$SAS_A_OK" ] && [ "$SAS_A_OK" = "$SAS_B_OK" ]; then
	echo "  [PASS] SAS MATCHED on the honest relay → first contact verifiable"
else
	echo "  [FAIL] expected identical SAS on the honest path (got '$SAS_A_OK' vs '$SAS_B_OK')"; FAIL=1
fi

echo
if [ "$FAIL" = 0 ]; then echo "RESULT: PASS — WG-1 SAS detects a live first-contact MITM"; else echo "RESULT: FAIL"; exit 1; fi

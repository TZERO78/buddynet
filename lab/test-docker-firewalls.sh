#!/usr/bin/env bash
# Docker firewall-coexistence lab for scoped exposure (--expose). Unlike the
# netns lab (test-wg-firewalls.sh) this runs REAL host firewall daemons —
# firewalld, ufw, and a hand-written host nft table — each ACTIVELY managing the
# buddy's own ruleset, to prove BuddyNet's per-bnetN scope coexists no matter
# what the host firewall is.
#
# Topology (one docker bridge network):
#   fw-server            handshake + relay
#   fw-a-<FIREWALL>      buddy A: the chosen host firewall + services :873/:2222,
#                        buddynet --wireguard --expose 873
#   fw-b-<FIREWALL>      buddy B: buddynet --wireguard --expose all, probes A
#
# For each firewall (firewalld, ufw, nft, none) it asserts:
#   - the tunnel comes up despite the host firewall,
#   - A's exposed :873 is reachable by B over the tunnel,
#   - A's unexposed :2222 is NOT reachable (scope holds regardless of firewall),
#   - the buddynet nft table lives ALONGSIDE the host firewall's tables.
#
# Needs: docker, the wireguard kernel module on the host, NET_ADMIN (containers
# run --privileged so firewalld/ufw can manage the ruleset and kernel-WG works).
set -euo pipefail

# Relay tickets: the same id on the handshake server and the relay. Fixed here
# rather than minted so a failing run is reproducible; production mints one with
# `buddynet gen-relay-id`. In this lab both roles are one process, so the relay
# derives the server key it trusts from --key and only needs the id.
RID=YnVkZHluZXQtbGFiLXJpZA
cd "$(dirname "$0")/.."

IMG=buddynet-fw-lab
NET=buddynet-fwnet
SUBNET=172.30.0.0/24
SRVIP=172.30.0.10
TOKEN=lab-docker-fw-token

cleanup() {
	set +e
	docker rm -f fw-server >/dev/null 2>&1
	for f in firewalld ufw nft none; do docker rm -f "fw-a-$f" "fw-b-$f" >/dev/null 2>&1; done
	docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

echo "== build image (buddynet + firewalld/ufw/nftables on Debian) =="
docker build -q -f lab/Dockerfile.firewalls -t "$IMG" . >/dev/null
sudo modprobe wireguard

# Static IPs, no embedded DNS: firewalld resets the nat table and would clobber
# Docker's per-container DNS DNAT (127.0.0.11) — so reference everything by IP.
docker network create --subnet "$SUBNET" "$NET" >/dev/null

# One shared identity per role, generated inside a throwaway container so the
# pubkeys match the in-container binary exactly.
gen_key() { docker run --rm -v "$1":/state "$IMG" --key /state/id.key identity 2>/dev/null | tail -1; }
KD=$(mktemp -d); chmod 777 "$KD"
mkdir -p "$KD/srv" "$KD/a" "$KD/b"
SRVPUB=$(gen_key "$KD/srv")
APUB=$(gen_key "$KD/a")
BPUB=$(gen_key "$KD/b")

echo "== start server (handshake + relay) =="
docker run -d --name fw-server --network "$NET" --ip "$SRVIP" \
	-v "$KD/srv":/var/lib/buddynet --entrypoint buddynet "$IMG" \
	--role=handshake,relay --relay-id "$RID" --listen "0.0.0.0:51820" --relay-listen "0.0.0.0:51821" \
	--key /var/lib/buddynet/id.key --relay-endpoint "$SRVIP:51821" >/dev/null

wait_log() { # $1 container, $2 pattern
	for _ in $(seq 1 40); do docker logs "$1" 2>&1 | grep -q "$2" && return 0; sleep 1; done
	return 1
}

FAIL=0
run_buddy() { # $1 name, $2 firewall, $3 keydir, $4 peerpub, $5 services, $6 expose
	docker run -d --name "$1" --network "$NET" --privileged \
		-e FIREWALL="$2" -e SERVICES="$5" -e LAB_SUBNET="$SUBNET" \
		-e X_UNUSED=1 -v "$3":/var/lib/buddynet "$IMG" \
		--role=buddy --server "$SRVIP:51820" --server-key "$SRVPUB" \
		--key /var/lib/buddynet/id.key --peer-key "$4" --no-interactive \
		--wireguard --expose "$6" >/dev/null
}

test_firewall() { # $1 firewall
	local fw="$1" a="fw-a-$1" b="fw-b-$1"
	echo "== FIREWALL = $fw =="
	run_buddy "$a" "$fw" "$KD/a" "$BPUB" "873 2222" "873"
	run_buddy "$b" "$fw" "$KD/b" "$APUB" "" "all"

	if ! wait_log "$a" 'CONNECTED:' || ! wait_log "$b" 'CONNECTED:'; then
		echo "  [FAIL] tunnel did not come up under $fw"
		docker logs "$a" 2>&1 | grep -Ei 'firewall|error|expose|CONNECT' | tail -6 | sed 's/^/    a| /'
		FAIL=1; docker rm -f "$a" "$b" >/dev/null 2>&1; return
	fi
	docker logs "$a" 2>&1 | grep -m1 'FIREWALL:' | sed 's/^/  /'
	docker logs "$a" 2>&1 | grep -m1 'EXPOSE: action=' | sed 's/^/  /'

	local vip_a
	vip_a=$(docker logs "$b" 2>&1 | grep -m1 'CONNECTED:' | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)

	probe() { docker exec "$b" nc -z -w 2 "$vip_a" "$1" >/dev/null 2>&1; }
	if probe 873; then echo "  [PASS] exposed :873 reachable through the tunnel"; else echo "  [FAIL] exposed :873 unreachable"; FAIL=1; fi
	if probe 2222; then echo "  [FAIL] unexposed :2222 reachable — scope broken under $fw"; FAIL=1; else echo "  [PASS] unexposed :2222 blocked (scope holds under $fw)"; fi

	# Show the coexistence directly: buddynet's table lives next to the host's.
	echo "  nft tables in buddy-a: $(docker exec "$a" nft list tables 2>/dev/null | awk '{print $2"/"$3}' | tr '\n' ' ')"
	if docker exec "$a" nft list table inet buddynet >/dev/null 2>&1; then
		echo "  [PASS] inet buddynet table present alongside the host firewall"
	else
		echo "  [FAIL] buddynet table missing under $fw"; FAIL=1
	fi
	docker rm -f "$a" "$b" >/dev/null 2>&1
}

test_firewall none
test_firewall nft
test_firewall ufw
test_firewall firewalld

rm -rf "$KD"
echo
if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

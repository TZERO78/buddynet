#!/usr/bin/env bash
# Validates docs/VPS-HOWTO.md end to end — the "run your own VPS coordinator"
# walkthrough — in two parts:
#
#   Part 1 (firewall): loads the SHIPPED deployments/nftables.conf into a network
#     namespace and proves it functionally: default-drop, opens only 51820/51821
#     udp + ssh 22 + ICMP, drops everything else. Nothing else tests that file.
#
#   Part 2 (coordinator + pairing): brings up the base lab server (handshake+relay,
#     the VPS equivalent), bootstraps its key into .env exactly as the HowTo's
#     "get the server key" step, then runs a real --invite / --join / --peer-key /
#     -L pairing and reaches the partner's service through the tunnel.
#
# Uses sudo INTERNALLY for the netns/nft steps (do NOT run the whole script under
# sudo — that breaks Docker-as-user and /tmp). sudo must be passwordless or cached.
# Needs Docker too. Run from lab/ as your normal user:  ./test-vps-howto.sh
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
TMPD="$(mktemp -d)"

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

NS=bnfw; H=bnfw_h; P=bnfw_p; HIP=10.99.0.1; PIP=10.99.0.2
fw_cleanup(){ sudo ip netns del $NS 2>/dev/null; sudo ip link del $H 2>/dev/null; }
lab_cleanup(){ docker rm -f howto-inviter howto-joiner >/dev/null 2>&1; }
cleanup(){ fw_cleanup; lab_cleanup; rm -rf "$TMPD" "${KEYDIR:-}"; }
trap cleanup EXIT

# ─────────────────────────── Part 1: the firewall ───────────────────────────
echo "== Part 1: deployments/nftables.conf in a netns =="
fw_cleanup
sudo ip netns add $NS
sudo ip link add $H type veth peer name $P
sudo ip link set $P netns $NS
sudo ip addr add $HIP/24 dev $H; sudo ip link set $H up
sudo ip netns exec $NS ip addr add $PIP/24 dev $P
sudo ip netns exec $NS ip link set $P up
sudo ip netns exec $NS ip link set lo up

if sudo ip netns exec $NS nft -f "$ROOT/deployments/nftables.conf" 2>$TMPD/nfterr; then
  ok "nftables.conf loads without error"
else
  no "ruleset failed to load: $(cat $TMPD/nfterr)"
fi
RS=$(sudo ip netns exec $NS nft list table inet buddynet 2>/dev/null)
echo "$RS" | grep -q 'policy drop' && ok "input policy is DROP (default-deny)" || no "input policy is not drop"
echo "$RS" | grep -q 'udp dport 51820' && ok "handshake 51820 rule present" || no "51820 rule missing"
echo "$RS" | grep -q 'udp dport 51821' && ok "relay 51821 rule present" || no "51821 rule missing"
echo "$RS" | grep -q 'tcp dport 22 accept' && ok "ssh 22 accept present" || no "ssh rule missing"
echo "$RS" | grep -q 'limit rate 100/second' && ok "udp rate-limit present" || no "rate-limit missing"
ping -c1 -W2 $PIP >/dev/null 2>&1 && ok "ICMP to coordinator works (diagnostics)" || no "ICMP blocked"

udp_probe(){ # $1=port -> GOT / NONE
  sudo ip netns exec $NS python3 - "$1" >$TMPD/udpres 2>/dev/null <<'PY' &
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",int(sys.argv[1])));s.settimeout(3.0)
try: s.recvfrom(64);print("GOT")
except Exception: print("NONE")
PY
  local lp=$!; sleep 0.5
  python3 - "$HIP" "$PIP" "$1" <<'PY'
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],0))
s.sendto(b"probe",(sys.argv[2],int(sys.argv[3])))
PY
  wait $lp 2>/dev/null; cat $TMPD/udpres
}
[ "$(udp_probe 51820)" = "GOT" ]  && ok "UDP 51820 (allowed) reaches the socket" || no "UDP 51820 did not pass"
[ "$(udp_probe 9999)"  = "NONE" ] && ok "UDP 9999 (not exposed) is dropped"      || no "UDP 9999 leaked through"

tcp_probe(){ # $1=port -> OPEN / SHUT
  sudo ip netns exec $NS python3 - "$1" >$TMPD/tcpres 2>/dev/null <<'PY' &
import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",int(sys.argv[1])));s.listen(1);s.settimeout(3.0)
try: s.accept();print("OPEN")
except Exception: print("SHUT")
PY
  local lp=$!; sleep 0.5
  timeout 2 python3 - "$PIP" "$1" <<'PY' 2>/dev/null
import socket,sys
try: socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1.5).close()
except Exception: pass
PY
  wait $lp 2>/dev/null; cat $TMPD/tcpres
}
[ "$(tcp_probe 22)"   = "OPEN" ] && ok "TCP 22 (ssh) SYN accepted"      || no "TCP 22 blocked — would lock you out!"
[ "$(tcp_probe 8080)" = "SHUT" ] && ok "TCP 8080 (random) is dropped"   || no "TCP 8080 leaked through"
fw_cleanup

# ──────────────────── Part 2: coordinator + invite/join ─────────────────────
echo
echo "== Part 2: coordinator + --invite/--join/--peer-key/-L =="
NET=lab_default; IMG=buddynet-lab-buddy
docker compose build >/dev/null 2>&1
docker compose up -d server >/dev/null 2>&1

# HowTo step 5: read the server key and pin it (also repairs a stale .env).
KEY=$(docker compose run --rm server --key /var/lib/buddynet/id.key init 2>/dev/null | tr -d '\r\n')
[ -n "$KEY" ] && ok "coordinator server key read (identity subcommand)" || no "could not read server key"
grep -q '^BUDDYNET_SERVER_KEY=' .env 2>/dev/null && sed -i "s|^BUDDYNET_SERVER_KEY=.*|BUDDYNET_SERVER_KEY=${KEY}|" .env || echo "BUDDYNET_SERVER_KEY=${KEY}" > .env

# Keys live in a per-run, docker-visible dir owned by the invoking user (never
# /tmp fixed names — a stale root-owned leftover would block the next run).
KEYDIR="$(mktemp -d /tmp/bnhowto.XXXXXX)"; chmod 755 "$KEYDIR"
BN="$KEYDIR/buddynet"; go build -o "$BN" "$ROOT/cmd/buddynet" 2>/dev/null
lab_cleanup
APUB=$("$BN" --key "$KEYDIR/HA.key" init); BPUB=$("$BN" --key "$KEYDIR/HB.key" init)

# Machine A: serve httpd:7777, mint a one-time invite, pin B.
docker run -d --name howto-inviter --network "$NET" \
  -v "$KEYDIR/HA.key":/var/lib/buddynet/id.key:ro --entrypoint /entrypoint-a.sh "$IMG" \
  --role=buddy --key /var/lib/buddynet/id.key --server server:51820 --server-key "$KEY" \
  --peer-key "$BPUB" --forward 127.0.0.1:7777 --invite --no-interactive >/dev/null 2>&1
TOK=""
for i in $(seq 1 30); do TOK=$(docker logs howto-inviter 2>&1 | grep -m1 -oE '^[A-Za-z0-9_-]{40,}$'); [ -n "$TOK" ] && break; sleep 0.5; done
[ -n "$TOK" ] && ok "machine A minted a one-time invite token" || no "no invite token minted"

# Machine B: join with the token, pin A, forward :9099 → A.
docker run -d --name howto-joiner --network "$NET" \
  -v "$KEYDIR/HB.key":/var/lib/buddynet/id.key:ro "$IMG" \
  --role=buddy --key /var/lib/buddynet/id.key --server server:51820 --server-key "$KEY" \
  --peer-key "$APUB" --join="$TOK" -L 0.0.0.0:9099 --no-interactive >/dev/null 2>&1
CONN=""
for i in $(seq 1 40); do docker logs howto-joiner 2>&1 | grep -q CONNECTED && { CONN=y; break; }; sleep 1; done
[ -n "$CONN" ] && ok "tunnel came up ($(docker logs howto-joiner 2>&1 | grep -m1 -oE 'via=\"[^\"]*\"'))" || no "tunnel did not connect"
BODY=$(docker exec howto-joiner curl -s --max-time 8 http://localhost:9099/ 2>/dev/null)
echo "$BODY" | grep -iq 'Peer A' && ok "partner service reachable through the tunnel (curl -L)" || no "service not reachable"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

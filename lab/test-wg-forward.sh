#!/usr/bin/env bash
# BuddyNet forward-path test (finding M-1: --expose must not be a route into the LAN)
# ===================================================================================
# `--expose` used to install its rules only on the nftables INPUT hook. A packet
# that arrives on bnetN and is ROUTED onward never traverses that hook, and
# WireGuard's AllowedIPs pins only the SOURCE of a decrypted packet, never its
# destination. So a buddy could send a packet with its own permitted VIP as source
# and any LAN address behind the host as destination and — on a host that forwards,
# which Docker turns on — reach it. That held with ports exposed, with NOTHING
# exposed, and under `--expose all`.
#
# BuddyNet now also programs a FORWARD-hook chain that drops everything arriving on
# bnetN. This test proves it end to end with a real WireGuard tunnel and the real
# rule builder (internal/nft.Apply, via lab/pentest/applyscope).
#
#   bnfwd-a (buddy/attacker)      bnfwd-v (victim)        bnfwd-l  (LAN target)
#     wgA 10.66.1.1/32  ==WG==>  bnet0 10.66.2.2/32
#     veth 172.31.0.1/24 <---->  veth 172.31.0.2/24
#                                veth 192.168.77.1/24 <-> veth 192.168.77.10/24
#                                veth 192.168.88.1/24 <-> veth 192.168.88.10/24
#                                                          bnfwd-l2 (second segment,
#                                                          for the untouched path)
#
# Four throwaway namespaces, RFC 5737/1918 addressing, fully isolated — nothing
# touches the host network or any external system.
#
# Every "blocked" result is paired with a "reached" positive control, so a timeout
# is never reported as a security property on its own.
#
# Prerequisites: root (sudo), ip/netns, the wireguard kernel module.
#
# Usage (from the repo root or lab/):
#   sudo -v && ./lab/test-wg-forward.sh

set -u
cd "$(dirname "$0")/.."

NSA=bnfwd-a
NSV=bnfwd-v
NSL=bnfwd-l
NSL2=bnfwd-l2
TMP=$(mktemp -d /tmp/bnfwd.XXXXXX)

PASS=0; FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
info() { printf '  ....   %s\n' "$*"; }
ns()   { sudo -n ip netns exec "$1" "${@:2}"; }

cleanup() {
  for n in "$NSA" "$NSV" "$NSL" "$NSL2"; do
    sudo -n ip netns pids "$n" 2>/dev/null | xargs -r sudo -n kill 2>/dev/null
    sudo -n ip netns del "$n" 2>/dev/null
  done
  echo "logs kept in $TMP"
}
trap cleanup EXIT

if ! sudo -n true 2>/dev/null; then
  echo "BLOCKER: this test needs passwordless sudo (network namespaces)." >&2
  exit 1
fi
if ! sudo -n modprobe wireguard 2>/dev/null; then
  echo "BLOCKER: the wireguard kernel module is not available." >&2
  exit 1
fi

say "build"
# APPLYSCOPE= points the test at a different rule builder — set it to a pre-fix
# build to watch this test FAIL (the A/B control: a lab that cannot fail proves
# nothing).
if [ -n "${APPLYSCOPE:-}" ]; then
  cp "$APPLYSCOPE" "$TMP/applyscope" || exit 1
  info "using an external rule builder: $APPLYSCOPE"
else
  go build -o "$TMP/applyscope" ./lab/pentest/applyscope || exit 1
fi
(cd lab/pentest/labtool && go build -o "$TMP/labtool" .) || exit 1   # own module, see its package comment

say "topology"
cleanup 2>/dev/null
for n in "$NSA" "$NSV" "$NSL" "$NSL2"; do sudo -n ip netns add "$n"; ns "$n" ip link set lo up; done

link() { # $1 ns-a $2 if-a $3 addr-a  $4 ns-b $5 if-b $6 addr-b
  sudo -n ip link add "$2" type veth peer name "$5"
  sudo -n ip link set "$2" netns "$1"; sudo -n ip link set "$5" netns "$4"
  ns "$1" ip addr add "$3" dev "$2"; ns "$1" ip link set "$2" up
  ns "$4" ip addr add "$6" dev "$5"; ns "$4" ip link set "$5" up
}
link "$NSA" tA 172.31.0.1/24    "$NSV" tV  172.31.0.2/24
link "$NSV" lV 192.168.77.1/24  "$NSL" lL  192.168.77.10/24
link "$NSV" mV 192.168.88.1/24  "$NSL2" mL 192.168.88.10/24

if ns "$NSA" ping -c1 -W2 172.31.0.2 >/dev/null 2>&1; then
  ok "transport link A<->V up"
else
  bad "transport link down — lab cannot proceed"; exit 1
fi

say "real WireGuard tunnel"
KA=$(wg genkey); PA=$(printf '%s' "$KA" | wg pubkey)
KV=$(wg genkey); PV=$(printf '%s' "$KV" | wg pubkey)
FA="$TMP/a.key"; FV="$TMP/v.key"
printf '%s' "$KA" > "$FA"; printf '%s' "$KV" > "$FV"; chmod 600 "$FA" "$FV"

ns "$NSA" ip link add wgA type wireguard
ns "$NSA" wg set wgA listen-port 51820 private-key "$FA"
# The attacker configures its OWN AllowedIPs — it wants the victim's LAN routed in.
ns "$NSA" wg set wgA peer "$PV" allowed-ips 10.66.2.2/32,192.168.77.0/24 \
    endpoint 172.31.0.2:51820 persistent-keepalive 5
ns "$NSA" ip addr add 10.66.1.1/32 dev wgA
ns "$NSA" ip link set wgA up
ns "$NSA" ip route add 10.66.2.2/32 dev wgA
ns "$NSA" ip route add 192.168.77.0/24 dev wgA

# The victim is a stock buddy: AllowedIPs is the partner's VIP /32 only
# (internal/wg/wg.go — AllowedIPs: peerVIP).
ns "$NSV" ip link add bnet0 type wireguard
ns "$NSV" wg set bnet0 listen-port 51820 private-key "$FV"
ns "$NSV" wg set bnet0 peer "$PA" allowed-ips 10.66.1.1/32 endpoint 172.31.0.1:51820
ns "$NSV" ip addr add 10.66.2.2/32 dev bnet0
ns "$NSV" ip link set bnet0 up
ns "$NSV" ip route add 10.66.1.1/32 dev bnet0

HS=0
for _ in $(seq 1 10); do
  ns "$NSA" ping -c1 -W1 10.66.2.2 >/dev/null 2>&1
  HS=$(ns "$NSV" wg show bnet0 latest-handshakes | awk '{print $2}')
  [ -n "${HS:-}" ] && [ "$HS" != "0" ] && break
  sleep 1
done
if [ -n "${HS:-}" ] && [ "$HS" != "0" ]; then
  ok "WireGuard handshake confirmed"
else
  bad "no WireGuard handshake — lab cannot proceed"; ns "$NSV" wg show; exit 1
fi

say "victim forwards; the LAN knows a route back"
ns "$NSV" sysctl -qw net.ipv4.ip_forward=1
ns "$NSL" ip route add 10.66.1.1/32 via 192.168.77.1
ns "$NSL" ip route add 192.168.88.0/24 via 192.168.77.1
ns "$NSL2" ip route add 192.168.77.0/24 via 192.168.88.1
info "ip_forward=$(ns "$NSV" sysctl -n net.ipv4.ip_forward), FORWARD policy accept (kernel default)"

say "services"
ns "$NSV"  "$TMP/labtool" serve -listen 10.66.2.2:445      -banner "VICTIM-HOST-445"  >/dev/null 2>&1 &
ns "$NSV"  "$TMP/labtool" serve -listen 10.66.2.2:22       -banner "VICTIM-HOST-22"   >/dev/null 2>&1 &
ns "$NSL"  "$TMP/labtool" serve -listen 192.168.77.10:8080 -banner "LAN-TARGET-8080"  >/dev/null 2>&1 &
ns "$NSL2" "$TMP/labtool" serve -listen 192.168.88.10:8080 -banner "LAN2-TARGET-8080" >/dev/null 2>&1 &
ns "$NSA"  "$TMP/labtool" serve -listen 10.66.1.1:9100     -banner "BUDDY-9100"       >/dev/null 2>&1 &
sleep 1

probe() { ns "$1" "$TMP/labtool" probe -connect "$2" -timeout 2s; }

say "positive controls (before any BuddyNet rules)"
if out=$(probe "$NSV" 192.168.77.10:8080); then ok "victim reaches the LAN target: $out"; else bad "victim cannot reach the LAN: $out"; fi
if out=$(probe "$NSL" 192.168.77.10:8080); then ok "LAN service answers inside the LAN: $out"; else bad "LAN service dead: $out"; fi
if out=$(probe "$NSA" 10.66.2.2:445);      then ok "buddy reaches the victim host port 445: $out"; else bad "tunnel data path broken: $out"; fi
if out=$(probe "$NSL" 192.168.88.10:8080); then ok "LAN->LAN2 forwarding works (the path BuddyNet must not touch): $out"; else bad "LAN->LAN2 broken before rules: $out"; fi
if out=$(probe "$NSA" 192.168.77.10:8080); then ok "baseline: buddy->LAN routing works BEFORE rules: $out"; else bad "baseline routing broken, later 'blocked' would be meaningless: $out"; fi

check_lan_blocked() { # $1 label
  printf '  --- SECURITY CHECK: %s ---\n' "$1"
  if out=$(probe "$NSA" 192.168.77.10:8080); then
    bad "M-1: buddy reached the LAN target through the victim: $out"
  else
    ok "buddy cannot reach the LAN target: $out"
  fi
}

say "scenario 1: --expose tcp/445"
ns "$NSV" "$TMP/applyscope" -if bnet0 -expose tcp/445 >/dev/null || { bad "applyscope failed"; exit 1; }
ns "$NSV" nft list table inet buddynet | sed 's/^/  | /'
if out=$(probe "$NSA" 10.66.2.2:445); then ok "exposed port 445 reachable: $out"; else bad "--expose tcp/445 broke the exposed port: $out"; fi
if out=$(probe "$NSA" 10.66.2.2:22);  then bad "unexposed port 22 reachable: $out"; else ok "unexposed port 22 blocked: $out"; fi
if ns "$NSA" ping -c1 -W2 10.66.2.2 >/dev/null 2>&1; then ok "ICMP to the victim VIP still allowed (by design)"; else info "ICMP blocked"; fi
check_lan_blocked "buddy -> LAN host behind the victim"

say "scenario 2: no --expose (fail-closed)"
ns "$NSV" "$TMP/applyscope" -if bnet0 -expose "" >/dev/null || bad "applyscope (empty scope) failed"
if out=$(probe "$NSA" 10.66.2.2:445); then bad "port 445 reachable with nothing exposed: $out"; else ok "host closed with no --expose: $out"; fi
check_lan_blocked "LAN reachable with NOTHING exposed?"

say "scenario 3: --expose all"
ns "$NSV" "$TMP/applyscope" -if bnet0 -expose all >/dev/null || bad "applyscope all failed"
if out=$(probe "$NSA" 10.66.2.2:22); then ok "--expose all opens the victim HOST as intended: $out"; else bad "--expose all did not open the host: $out"; fi
check_lan_blocked "does --expose all also open the LAN?"

say "scenario 4: forwarding that never touches bnetN must stay untouched"
ns "$NSV" "$TMP/applyscope" -if bnet0 -expose tcp/445 >/dev/null
# LAN -> LAN2 traverses FORWARD with iifname lV and oifname mV. BuddyNet matches
# neither, so this must keep working — the rules must not become a host-wide filter.
if out=$(probe "$NSL" 192.168.88.10:8080); then
  ok "unrelated forward path (LAN -> LAN2) still works: $out"
else
  bad "BuddyNet rules broke a forward path that has nothing to do with bnetN: $out"
fi

say "scenario 5: replies to connections the VICTIM itself opened"
# These arrive addressed to the victim's own VIP, so they traverse INPUT (where
# established/related accepts), not FORWARD. The forward drop must not affect them.
if out=$(probe "$NSV" 10.66.1.1:9100); then
  ok "victim-initiated connection to its buddy works (ct established on INPUT): $out"
else
  bad "the forward block broke the victim's own outbound connections: $out"
fi

say "scenario 6: LAN -> buddy forwarding is now BLOCKED (deliberate)"
# The request enters on lV, but the buddy's REPLY enters on bnet0 and is forwarded
# — so it hits the drop. Routing a LAN host to a buddy through this node is subnet
# routing, which is a separate feature with its own opt-in; until it exists, this
# direction is off. Anyone relying on it must wait for that feature.
if out=$(probe "$NSL" 10.66.1.1:9100); then
  bad "LAN -> buddy still forwards: the drop is not covering the reply path: $out"
else
  ok "LAN -> buddy is blocked, as intended until subnet routing exists: $out"
fi

say "result"
printf '  passed: %d   failed: %d\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

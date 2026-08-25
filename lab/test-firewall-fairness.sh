#!/usr/bin/env bash
# BuddyNet firewall fairness test  (audit finding M-02)
# =====================================================
# The handshake port is rate-limited twice: a PER-SOURCE bucket and a GLOBAL
# ceiling. A plain `limit`/`-m limit` attaches its bucket to the RULE, not to the
# sender, so on its own one loud source spends the shared budget and crowds
# everybody else out. This test measures that instead of arguing about it.
#
#   ./lab/test-firewall-fairness.sh                      # nftables, IPv4
#   ./lab/test-firewall-fairness.sh --iptables           # iptables, IPv4
#   ./lab/test-firewall-fairness.sh --ipv6               # nftables, IPv6 /64
#   ./lab/test-firewall-fairness.sh --iptables --ipv6    # iptables, IPv6 /64
#   ./lab/test-firewall-fairness.sh --conf other.conf    # a candidate ruleset
#
# The IPv6 runs are not a formality. Per-source fairness keyed on a full /128 is
# worth nothing there: a /64 is what one subscriber routinely gets, so an attacker
# just uses a different address per packet and collects a bucket for each. In
# --ipv6 mode the attacker therefore floods from FIVE addresses inside ONE /64
# while the buddy sits in a different /64, and the run only passes if the whole
# attacking prefix was held to roughly one source's share.
#
# Exit 0 when the buddy keeps at least $THRESHOLD% of the throughput it reaches
# unopposed. That baseline is measured first, so losses in the harness itself
# cannot be mistaken for policy.
#
# Prerequisites: root (sudo), ip/netns, python3, and nft or iptables/ip6tables.

set -u
cd "$(dirname "$0")/.."

FW=nft; IPV=4; CONF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --iptables) FW=iptables ;;
    --nftables) FW=nft ;;
    --ipv6)     IPV=6 ;;
    --ipv4)     IPV=4 ;;
    --conf)     shift; CONF="${1:-}" ;;
    -h|--help)  sed -n '2,28p' "$0"; exit 0 ;;
    *)          CONF="$1" ;;
  esac
  shift
done
if [ -z "$CONF" ]; then
  [ "$FW" = nft ] && CONF=deployments/nftables.conf || CONF=deployments/iptables.rules
fi

NS=bnfair
THRESHOLD=80
BUDDY_PKTS=40
FLOOD_RATE=600
WINDOW=4

if [ "$IPV" = 4 ]; then
  SRV=10.99.1.2; MASK=24; ATT="10.99.1.1"; BUD=10.99.1.3
  IPT=iptables; PY_FAM=AF_INET
else
  # Addresses are configured out of a common /48 so every party is on-link, while
  # the SOURCE addresses still sit in different /64s — which is what the rule
  # groups by. With /64 prefixes here the buddy and the server would be in
  # separate subnets with no route between them, and the rig would measure zero.
  SRV=fd00:99:0:9::2; MASK=48
  # five addresses, ONE /64 — the case a /128-keyed limit fails
  ATT="fd00:99:0:1::1 fd00:99:0:1::2 fd00:99:0:1::3 fd00:99:0:1::4 fd00:99:0:1::5"
  BUD=fd00:99:0:2::3
  IPT=ip6tables; PY_FAM=AF_INET6
fi

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
info() { printf '  ....   %s\n' "$*"; }

cleanup() {
  sudo -n ip netns pids "$NS" 2>/dev/null | xargs -r sudo -n kill 2>/dev/null
  sudo -n ip netns del "$NS" 2>/dev/null
  sudo -n ip link del fairA 2>/dev/null
}
trap cleanup EXIT

NEED="sudo ip python3"; [ "$FW" = nft ] && NEED="$NEED nft" || NEED="$NEED $IPT"
for t in $NEED; do
  command -v "$t" >/dev/null || { echo "BLOCKER: $t missing"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "BLOCKER: needs passwordless sudo"; exit 1; }

echo "BuddyNet firewall fairness — $FW / IPv$IPV — $CONF"
echo

cleanup
sudo -n ip netns add "$NS"
sudo -n ip netns exec "$NS" ip link set lo up
sudo -n ip link add fairA type veth peer name fairB
sudo -n ip link set fairB netns "$NS"
for a in $ATT $BUD; do sudo -n ip addr add "$a/$MASK" dev fairA; done
sudo -n ip link set fairA up
sudo -n ip netns exec "$NS" ip addr add "$SRV/$MASK" dev fairB
sudo -n ip netns exec "$NS" ip link set fairB up
# IPv6 DAD would leave the addresses tentative for a second; wait it out.
[ "$IPV" = 6 ] && sleep 2

PORT=$(grep -oE 'define port_handshake[[:space:]]*=[[:space:]]*[0-9]+' "$CONF" 2>/dev/null | grep -oE '[0-9]+$')
[ -n "${PORT:-}" ] || PORT=$(grep -oE '\-\-dport [0-9]+' "$CONF" | head -1 | grep -oE '[0-9]+')
PORT=${PORT:-51820}

if [ "$FW" = nft ]; then
  sudo -n ip netns exec "$NS" nft -f "$CONF" || { echo "BLOCKER: cannot load $CONF"; exit 1; }
else
  # The shipped file carries the IPv4 mask; IPv6 needs /64, which iptables(v4)
  # refuses — exactly the per-family edit the file documents. Apply it here so
  # the test exercises what an operator following those notes would load.
  RULES=$(cat "$CONF")
  if [ "$IPV" = 6 ]; then
    RULES=$(printf '%s\n' "$RULES" | sed 's/--hashlimit-srcmask 32/--hashlimit-srcmask 64/; s/-p icmp /-p icmpv6 /')
  fi
  printf '%s\n' "$RULES" | sudo -n ip netns exec "$NS" "$IPT"-restore \
    || { echo "BLOCKER: cannot load $CONF with $IPT-restore"; exit 1; }
fi
info "ruleset loaded into netns $NS (port $PORT)"

recv() {  # $1 = output file
  sudo -n ip netns exec "$NS" python3 - "$PORT" "$WINDOW" "$PY_FAM" > "$1" <<'PY' &
import socket, sys, time
port, window, fam = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
s = socket.socket(getattr(socket, fam), socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
s.bind(("::" if fam == "AF_INET6" else "0.0.0.0", port))
s.settimeout(0.2)
end = time.monotonic() + window + 1.5
n = {"ATT": 0, "LEG": 0}
while time.monotonic() < end:
    try: data, _ = s.recvfrom(2048)
    except socket.timeout: continue
    tag = data[:3].decode("ascii", "ignore")
    if tag in n: n[tag] += 1
print(f"{n['ATT']} {n['LEG']}")
PY
}

send_buddy() {
  python3 - "$PORT" "$BUDDY_PKTS" "$WINDOW" "$PY_FAM" "$BUD" "$SRV" <<'PY'
import socket, sys, time
port, pkts, window, fam, src, dst = (int(sys.argv[1]), int(sys.argv[2]),
                                     float(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6])
s = socket.socket(getattr(socket, fam), socket.SOCK_DGRAM); s.bind((src, 0))
gap = window / pkts
for _ in range(pkts):
    try: s.sendto(b"LEG" + b"y" * 60, (dst, port))
    except OSError: pass
    time.sleep(gap)
PY
}

# ── baseline: the buddy alone ────────────────────────────────────────────────
# Whatever this loses is the rig (veth queue, socket buffer, timing), not policy.
BASE=$(mktemp); recv "$BASE"; BASE_PID=$!
sleep 0.6
send_buddy
wait "$BASE_PID" 2>/dev/null
read -r _ BASE_LEG < "$BASE"; rm -f "$BASE"
BASE_LEG=${BASE_LEG:-0}
info "baseline (no flood): $BASE_LEG of $BUDDY_PKTS buddy packets arrived"
[ "$BASE_LEG" -gt 0 ] || { bad "the buddy cannot reach the port unopposed — rig broken"; exit 1; }
echo

# ── contended: flood + buddy at the same time ────────────────────────────────
RECV=$(mktemp); recv "$RECV"; RECV_PID=$!
sleep 0.6

python3 - "$PORT" "$FLOOD_RATE" "$WINDOW" "$PY_FAM" "$SRV" $ATT <<'PY' &
import socket, sys, time, itertools
port, rate, window, fam, dst = (int(sys.argv[1]), int(sys.argv[2]),
                                float(sys.argv[3]), sys.argv[4], sys.argv[5])
srcs = sys.argv[6:]
socks = []
for a in srcs:
    s = socket.socket(getattr(socket, fam), socket.SOCK_DGRAM); s.bind((a, 0)); socks.append(s)
gap, end = 1.0 / rate, time.monotonic() + window
for s in itertools.cycle(socks):
    if time.monotonic() >= end: break
    try: s.sendto(b"ATT" + b"x" * 60, (dst, port))
    except OSError: pass
    time.sleep(gap)
PY
FLOOD_PID=$!
send_buddy
wait "$FLOOD_PID" 2>/dev/null
wait "$RECV_PID" 2>/dev/null
read -r GOT_ATT GOT_LEG < "$RECV"; rm -f "$RECV"
GOT_ATT=${GOT_ATT:-0}; GOT_LEG=${GOT_LEG:-0}
PCT=$(( GOT_LEG * 100 / BASE_LEG ))

NSRC=$(echo $ATT | wc -w)
info "attacker: $NSRC source address(es), ~$((FLOOD_RATE * WINDOW)) packets sent, $GOT_ATT through"
info "buddy:    $BUDDY_PKTS packets sent, $GOT_LEG through"
info "->        ${PCT}% of what the same buddy achieves unopposed ($BASE_LEG)"
echo

if [ "$GOT_ATT" -ge $(( FLOOD_RATE * WINDOW * 80 / 100 )) ]; then
  bad "the flood was barely limited ($GOT_ATT through) — is the limit rule loaded?"
elif [ "$GOT_ATT" -eq 0 ] && [ "$GOT_LEG" -eq 0 ]; then
  bad "nothing arrived at all — the namespace path is broken, not the policy"
else
  ok "the flood was throttled ($GOT_ATT of ~$((FLOOD_RATE * WINDOW)) got through)"
fi

# With several attacking addresses inside ONE /64, the whole prefix must be held
# to roughly a single source's share. Without this assertion the run is green
# whenever the buddy survives — and the buddy survives even with /128 keying, as
# long as the flood stays under the GLOBAL ceiling. That would report a working
# /64 grouping while the attacker quietly collects one bucket per address:
# measured, 249 packets through with /64 keying vs 1245 with /128, five sources.
if [ "$IPV" = 6 ] && [ "$NSRC" -gt 1 ]; then
  # one source's share over the window: rate*window + burst, plus slack
  ALLOW=$(( 50 * WINDOW + 50 ))
  CEIL=$(( ALLOW * 3 / 2 ))
  if [ "$GOT_ATT" -le "$CEIL" ]; then
    ok "the whole attacking /64 was held to one source's share ($GOT_ATT <= $CEIL)"
  else
    bad "$NSRC addresses from ONE /64 got $GOT_ATT packets through (> $CEIL): the"
    info "per-source limit is keyed on the full /128, so each address gets its own"
    info "bucket. nftables masks to /64 in the rule; iptables needs"
    info "--hashlimit-srcmask 64, which iptables(v4) refuses and ip6tables requires."
  fi
fi

if [ "$PCT" -ge "$THRESHOLD" ]; then
  ok "the buddy kept ${PCT}% of its unopposed throughput (>= ${THRESHOLD}%)"
else
  bad "the buddy kept only ${PCT}% of its unopposed throughput (< ${THRESHOLD}%)"
  if [ "$IPV" = 6 ] && [ "$NSRC" -gt 1 ]; then
    info "IPv6: the attacker used $NSRC addresses from ONE /64. If the per-source"
    info "limit keys on the full /128, each of them gets its own bucket and the"
    info "fairness rule buys nothing. nftables masks to /64 in the rule; iptables"
    info "needs --hashlimit-srcmask 64 (the shipped file documents this)."
  else
    info "This is finding M-02: a shared bucket lets one source starve the rest."
  fi
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

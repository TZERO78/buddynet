#!/usr/bin/env bash
# BuddyNet firewall fairness test  (audit finding M-02)
# =====================================================
# The shipped ruleset rate-limits the handshake port with
#
#     udp dport $port_handshake limit rate 100/second burst 50 packets accept
#     udp dport $port_handshake drop
#
# `limit` is a token bucket attached to the RULE, not to the source. It bounds
# what a flood costs the box — the thing it is there for — but it is shared, so
# one loud source can spend the whole budget and crowd out everybody else. The
# audit called this out; this test measures it instead of arguing about it.
#
# Two sources, one namespace:
#   attacker  10.99.1.1  floods the handshake port
#   buddy     10.99.1.3  sends a slow, legitimate trickle at the same time
# and we count how much of the BUDDY's traffic survives.
#
#   ./lab/test-firewall-fairness.sh                      # the shipped ruleset
#   ./lab/test-firewall-fairness.sh /path/to/other.conf  # compare a candidate
#
# Exit code is 0 when the buddy keeps at least $THRESHOLD% of its packets. Run it
# against a ruleset BEFORE and AFTER adding per-source fairness: that A/B is the
# point, and a single run in isolation proves much less.
#
# Prerequisites: root (sudo), ip/netns, nft, python3.

set -u
cd "$(dirname "$0")/.."
CONF="${1:-deployments/nftables.conf}"
NS=bnfair
THRESHOLD=80          # percent of the buddy's packets that must get through
BUDDY_PKTS=40         # legitimate packets, sent slowly over the window
FLOOD_RATE=600        # attacker packets per second — well over the 100/s limit
WINDOW=4              # seconds

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

for t in sudo ip nft python3; do
  command -v $t >/dev/null || { echo "BLOCKER: $t missing"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "BLOCKER: needs passwordless sudo"; exit 1; }

echo "BuddyNet firewall fairness — $CONF"
echo

cleanup
sudo -n ip netns add "$NS"
sudo -n ip netns exec "$NS" ip link set lo up
sudo -n ip link add fairA type veth peer name fairB
sudo -n ip link set fairB netns "$NS"
# Two source addresses on the host end: attacker and buddy.
sudo -n ip addr add 10.99.1.1/24 dev fairA
sudo -n ip addr add 10.99.1.3/24 dev fairA
sudo -n ip link set fairA up
sudo -n ip netns exec "$NS" ip addr add 10.99.1.2/24 dev fairB
sudo -n ip netns exec "$NS" ip link set fairB up

# Load the ruleset under test. SSH is irrelevant in a namespace, but the file is
# taken verbatim — the point is to test what is shipped, not a paraphrase.
sudo -n ip netns exec "$NS" nft -f "$CONF" || { echo "BLOCKER: cannot load $CONF"; exit 1; }
info "ruleset loaded into netns $NS"

PORT=$(grep -oE 'define port_handshake[[:space:]]*=[[:space:]]*[0-9]+' "$CONF" | grep -oE '[0-9]+$')
PORT=${PORT:-51820}
info "handshake port under test: $PORT"

# Receiver inside the namespace: counts packets per source, by payload tag.
# ── baseline: the buddy alone, no flood ──────────────────────────────────────
# Whatever this loses is the measurement rig (veth queue, socket buffer, timing),
# not the policy. Comparing the contended run against 100% instead of against
# this would blame the firewall for the harness.
BASE=$(mktemp)
sudo -n ip netns exec "$NS" python3 - "$PORT" "$WINDOW" > "$BASE" <<'PY' &
import socket, sys, time
port, window = int(sys.argv[1]), float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
s.bind(("0.0.0.0", port)); s.settimeout(0.2)
end = time.monotonic() + window + 1.5
n = 0
while time.monotonic() < end:
    try: data, _ = s.recvfrom(2048)
    except socket.timeout: continue
    if data[:3] == b"LEG": n += 1
print(n)
PY
BASE_PID=$!
sleep 0.6
python3 - "$PORT" "$BUDDY_PKTS" "$WINDOW" <<'PY'
import socket, sys, time
port, pkts, window = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.1.3", 0))
gap = window / pkts
for _ in range(pkts):
    try: s.sendto(b"LEG" + b"y" * 60, ("10.99.1.2", port))
    except OSError: pass
    time.sleep(gap)
PY
wait "$BASE_PID" 2>/dev/null
read -r BASE_LEG < "$BASE"; rm -f "$BASE"
BASE_LEG=${BASE_LEG:-0}
info "baseline (no flood): $BASE_LEG of $BUDDY_PKTS buddy packets arrived"
[ "$BASE_LEG" -gt 0 ] || { bad "the buddy cannot reach the port even unopposed — rig broken"; exit 1; }
echo

RECV=$(mktemp); trap 'rm -f "$RECV"' RETURN
sudo -n ip netns exec "$NS" python3 - "$PORT" "$WINDOW" > "$RECV" <<'PY' &
import socket, sys, time
port, window = int(sys.argv[1]), float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
s.bind(("0.0.0.0", port)); s.settimeout(0.2)
end = time.monotonic() + window + 1.5
n = {"ATT": 0, "LEG": 0}
while time.monotonic() < end:
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        continue
    tag = data[:3].decode("ascii", "ignore")
    if tag in n:
        n[tag] += 1
print(f"{n['ATT']} {n['LEG']}")
PY
RECV_PID=$!
sleep 0.6

# Attacker: flood from 10.99.1.1. Buddy: a slow trickle from 10.99.1.3, spread
# evenly across the same window so it cannot simply ride the initial burst.
python3 - "$PORT" "$FLOOD_RATE" "$WINDOW" <<'PY' &
import socket, sys, time
port, rate, window = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.1.1", 0))
gap, end = 1.0 / rate, time.monotonic() + window
while time.monotonic() < end:
    try: s.sendto(b"ATT" + b"x" * 60, ("10.99.1.2", port))
    except OSError: pass
    time.sleep(gap)
PY
FLOOD_PID=$!

python3 - "$PORT" "$BUDDY_PKTS" "$WINDOW" <<'PY'
import socket, sys, time
port, pkts, window = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.1.3", 0))
gap = window / pkts
for _ in range(pkts):
    try: s.sendto(b"LEG" + b"y" * 60, ("10.99.1.2", port))
    except OSError: pass
    time.sleep(gap)
PY

wait "$FLOOD_PID" 2>/dev/null
wait "$RECV_PID" 2>/dev/null
read -r GOT_ATT GOT_LEG < "$RECV"
GOT_ATT=${GOT_ATT:-0}; GOT_LEG=${GOT_LEG:-0}

PCT=$(( GOT_LEG * 100 / BASE_LEG ))
echo
info "attacker sent ~$((FLOOD_RATE * WINDOW)) packets, $GOT_ATT got through"
info "buddy sent $BUDDY_PKTS packets, $GOT_LEG got through"
info "-> ${PCT}% of what the same buddy achieved unopposed ($BASE_LEG)"
echo

# Guard against a vacuously green run: if the flood was never throttled at all,
# the ruleset under test is not doing its job and the fairness number is
# meaningless.
if [ "$GOT_ATT" -ge $(( FLOOD_RATE * WINDOW * 80 / 100 )) ]; then
  bad "the flood was barely limited ($GOT_ATT through) — is the limit rule loaded?"
elif [ "$GOT_ATT" -eq 0 ] && [ "$GOT_LEG" -eq 0 ]; then
  bad "nothing arrived at all — the namespace path is broken, not the policy"
else
  ok "the global limit is doing its job: the flood was throttled"
fi

if [ "$PCT" -ge "$THRESHOLD" ]; then
  ok "the buddy kept ${PCT}% of its unopposed throughput alongside the flood (>= ${THRESHOLD}%)"
else
  bad "the buddy kept only ${PCT}% of its unopposed throughput (< ${THRESHOLD}%) — one source can"
  info "spend the shared budget. This is finding M-02: the limit protects the box,"
  info "it does not protect availability for anyone else."
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

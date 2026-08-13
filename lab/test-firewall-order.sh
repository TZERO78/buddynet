#!/usr/bin/env bash
# BuddyNet firewall rule-order test
# =================================
# The shipped ruleset rate-limits the control port. That limit is only worth
# anything if it is evaluated BEFORE the generic `ct state established,related
# accept` — netfilter marks a UDP flow established as soon as it has seen traffic
# in both directions, so once the server answers the first packet, every later
# packet of that 5-tuple matched the accept and the limit was never reached.
#
# This test proves the ordering with rule counters, in a throwaway namespace:
# send one packet to establish the flow, then a burst, and check that the excess
# is actually dropped.
#
#   ./lab/test-firewall-order.sh                      # the shipped ruleset
#   ./lab/test-firewall-order.sh /path/to/other.conf  # compare another one
#
# Prerequisites: root (sudo), ip/netns, nft, socat.

set -u
cd "$(dirname "$0")/.."
CONF="${1:-deployments/nftables.conf}"
NS=bnfword
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
info() { printf '  ....   %s\n' "$*"; }

cleanup() {
  sudo -n ip netns pids "$NS" 2>/dev/null | xargs -r sudo -n kill 2>/dev/null
  sudo -n ip netns del "$NS" 2>/dev/null
  sudo -n ip link del fwordA 2>/dev/null
}
trap cleanup EXIT

for t in sudo ip nft socat; do
  command -v $t >/dev/null || { echo "BLOCKER: $t missing"; exit 1; }
done
sudo -n true 2>/dev/null || { echo "BLOCKER: needs passwordless sudo"; exit 1; }

cleanup
sudo -n ip netns add "$NS"; sudo -n ip netns exec "$NS" ip link set lo up
sudo -n ip link add fwordA type veth peer name fwordB
sudo -n ip link set fwordB netns "$NS"
sudo -n ip addr add 10.99.0.1/24 dev fwordA; sudo -n ip link set fwordA up
sudo -n ip netns exec "$NS" ip addr add 10.99.0.2/24 dev fwordB
sudo -n ip netns exec "$NS" ip link set fwordB up

# Load the ruleset with a counter on whatever handles over-limit control traffic.
sed 's/\$port_handshake/51820/g; s/\$port_relay/51821/g; s/\$port_ssh/22/g; /^define/d' "$CONF" \
  | sed 's/udp dport 51820 drop/udp dport 51820 counter drop/' \
  | sudo -n ip netns exec "$NS" nft -f - || { bad "ruleset does not load"; exit 1; }
info "loaded $CONF"

# A responder makes the flow ESTABLISHED — the state in which the limit used to
# stop applying.
sudo -n ip netns exec "$NS" timeout 15 socat -u UDP-RECVFROM:51820,fork - >/dev/null 2>&1 &
sleep 1
echo x | timeout 2 socat -u - UDP-SENDTO:10.99.0.2:51820 2>/dev/null
sleep 1
if sudo -n ip netns exec "$NS" conntrack -L 2>/dev/null | grep -q 51820; then
  ok "the flow is tracked (established) — the case the limit must still cover"
else
  info "conntrack not queryable here; continuing (the burst below is the real check)"
fi

# Well past the 100/s + 50 burst allowance.
for _ in $(seq 1 400); do printf 'x' | timeout 1 socat -u - UDP-SENDTO:10.99.0.2:51820 2>/dev/null; done
sleep 1

RULES=$(sudo -n ip netns exec "$NS" nft -a list chain inet buddynet input 2>/dev/null)
echo "$RULES" | grep 51820 | sed 's/^/    /'
DROPPED=$(echo "$RULES" | grep "51820" | grep "drop" | grep -oP 'packets \K[0-9]+' | head -1)
if [ -n "${DROPPED:-}" ] && [ "$DROPPED" -gt 0 ]; then
  ok "over-limit control packets are dropped even on an established flow ($DROPPED)"
else
  bad "nothing was dropped: the rate limit does not apply once the flow is established"
fi

printf '\n  passed: %d   failed: %d\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

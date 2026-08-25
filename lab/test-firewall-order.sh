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

# Load the ruleset with counters: one on the control port's final accept, one on
# every rule that drops control traffic. The port is filtered by more than one
# rule now (per-source meter, then the global ceiling, then accept), so counting a
# single "limit ... accept" rule would silently measure nothing.
sed 's/\$port_handshake/51820/g; s/\$port_relay/51821/g; s/\$port_ssh/22/g; /^define/d' "$CONF" \
  | perl -0pe 's/\\\n\s*/ /g' \
  | sed 's/^\([[:space:]]*\)udp dport 51820 accept$/\1udp dport 51820 counter accept/' \
  | sed 's/\(udp dport 51820 .*\)drop$/\1counter drop/' \
  | sed 's/udp dport 51821 accept/udp dport 51821 counter accept/' \
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
echo "$RULES" | grep -E "5182[01]" | sed 's/^/    /'

ACCEPTED=$(echo "$RULES" | grep 51820 | grep "counter packets" | grep " accept" | grep -oP 'packets \K[0-9]+' | head -1)
# Sum every drop on the control port: over-limit packets may be caught by the
# per-source meter or by the global ceiling, and either one is a correct drop.
DROPPED=$(echo "$RULES"  | grep 51820 | grep " drop" | grep -oP 'packets \K[0-9]+' | paste -sd+ | bc)

# POSITIVE CONTROL. Without this the test passes on a ruleset that drops
# EVERYTHING on the control port — "over-limit traffic is dropped" is only
# meaningful next to "within-limit traffic still gets through".
if [ -n "${ACCEPTED:-}" ] && [ "$ACCEPTED" -gt 0 ]; then
  ok "control traffic within the allowance is still accepted ($ACCEPTED)"
else
  bad "NOTHING was accepted on the control port — the ruleset is blocking legitimate traffic, so the drop count below proves nothing"
fi

if [ -n "${DROPPED:-}" ] && [ "$DROPPED" -gt 0 ]; then
  ok "over-limit control packets are dropped even on an established flow ($DROPPED)"
else
  bad "nothing was dropped: the rate limit does not apply once the flow is established"
fi

# The relay port carries tunnel DATA and must NOT be rate-limited here: a burst
# that trips the control-port limit has to pass on the relay port untouched.
sudo -n ip netns exec "$NS" timeout 12 socat -u UDP-RECVFROM:51821,fork - >/dev/null 2>&1 &
sleep 1
for _ in $(seq 1 300); do printf 'x' | timeout 1 socat -u - UDP-SENDTO:10.99.0.2:51821 2>/dev/null; done
sleep 1
RULES2=$(sudo -n ip netns exec "$NS" nft -a list chain inet buddynet input 2>/dev/null)
echo "$RULES2" | grep 51821 | sed 's/^/    /'
# Sum every accept counter on the relay port: a ruleset that rate-limits it has
# more than one rule, and an unthrottled one has a single accept carrying all of
# the burst.
RELAY_OK=$(echo "$RULES2" | grep 51821 | grep accept | grep -oP 'packets \K[0-9]+' | paste -sd+ | bc 2>/dev/null)
RELAY_OK=${RELAY_OK:-0}
if [ "$RELAY_OK" -ge 200 ]; then
  ok "relay data passes unthrottled ($RELAY_OK of 300) — a control-plane rate would have cut the tunnel"
elif echo "$RULES2" | grep 51821 | grep -q "limit rate"; then
  bad "the relay port is rate-limited ($RELAY_OK of 300 accepted): a packet rate safe for the control port strangles the data path"
else
  bad "only $RELAY_OK of 300 relay packets were accepted, and no rate limit explains it"
fi

printf '\n  passed: %d   failed: %d\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

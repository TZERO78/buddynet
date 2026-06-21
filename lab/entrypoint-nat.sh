#!/bin/sh
# NAT router for the CGNAT lab. Finds its WAN interface (the one on NAT_WAN_PREFIX),
# enables forwarding and MASQUERADEs LAN traffic out of it.
#   NAT_MODE=cone       (default) MASQUERADE — preserves source port -> punch works
#   NAT_MODE=symmetric  MASQUERADE --random-fully — random port per destination ->
#                       server-observed port is useless to the peer -> punch fails
set -e

# net.ipv4.ip_forward is set via the compose `sysctls:` key (/proc/sys is read-only
# in the container), so we do not touch it here.

WAN_IF=$(ip -o -4 addr show | awk -v p="$NAT_WAN_PREFIX" 'index($4, p) == 1 { print $2; exit }')
if [ -z "$WAN_IF" ]; then
	echo "[nat] FATAL: no WAN interface found for prefix '$NAT_WAN_PREFIX'"
	ip -o -4 addr show
	exit 1
fi

WAN_IP=$(ip -o -4 addr show dev "$WAN_IF" | awk '{print $4}' | cut -d/ -f1)
MODE="${NAT_MODE:-cone}"
if [ "$MODE" = "symmetric" ]; then
	# Symmetric: random source port PER destination → the server-observed port is
	# useless to the peer → hole punch fails. (Plain MASQUERADE is ALSO symmetric
	# because it allocates a new port when the original is already in use by another
	# flow, which is why a fixed-port SNAT is needed below to get a real cone NAT.)
	iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE --random-fully
else
	# Full cone (endpoint-independent mapping): SNAT all UDP to ONE fixed external
	# port, so the same internal socket appears under the same ip:port to BOTH the
	# server and the peer → server-observed port == punch port → punch succeeds.
	# (One buddy per NAT in this lab, so a single fixed port has no collisions.)
	iptables -t nat -A POSTROUTING -o "$WAN_IF" -p udp -j SNAT --to-source "$WAN_IP:50000"
	iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
fi

echo "[nat] WAN_IF=$WAN_IF WAN_IP=$WAN_IP mode=$MODE — forwarding + NAT active"
exec tail -f /dev/null

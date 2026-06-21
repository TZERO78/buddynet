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

	# Conntrack-poisoning guard — this is what actually makes the punch LAND.
	#
	# In a simultaneous hole punch BOTH peers fire at the other's WAN:50000 at the
	# same instant. The peer's inbound punch (src=peer:50000 dst=US:50000, where
	# US == this router's OWN WAN IP) routinely arrives BEFORE the local buddy's
	# matching outbound punch has created its conntrack mapping. Because the packet
	# is addressed to the router itself, the kernel tracks it as a brand-new,
	# unsolicited inbound flow and books a conntrack entry whose REPLY tuple is
	#   src=US:50000 dst=peer:50000.
	# That reply tuple is byte-for-byte the SNAT target the buddy's own outbound
	# punch needs (SNAT --to-source US:50000, dst=peer:50000). So when the buddy
	# then punches out, conntrack sees the :50000 source already taken by the stray
	# entry, the SNAT/port allocation collides, and the buddy's outbound punch is
	# dropped before POSTROUTING (visible as eth0-In with no eth1-Out, and a flat
	# SNAT counter). Net effect: NEITHER side's punch crosses → fallback to relay.
	# (Conntrack proof in the commit message / logs: a NEW [UNREPLIED] entry
	#  src=peer dst=US sport=50000 dport=50000 appears on the receiving NAT.)
	#
	# Fix: stop the unsolicited inbound punch from confirming a poisoning conntrack
	# entry. DROP inbound WAN UDP to :50000 whose ctstate is NEW — i.e. a datagram
	# that is NOT the reply to a flow the local buddy already started. A NEW entry is
	# only provisional until the chain ACCEPTs the packet; dropping it means the
	# stray entry is never committed, so it can't shadow the buddy's SNAT target.
	# We cover both paths it can take: INPUT (when addressed to the router's own WAN
	# IP, which is the actual case here) and FORWARD (belt-and-suspenders, in case
	# a future change DNATs it toward the LAN). The buddy keeps punching ~5x/s; the
	# moment ITS OWN outbound punch establishes the endpoint-independent mapping,
	# the peer's next inbound punch matches that mapping as ESTABLISHED (no longer
	# NEW), sails past this DROP, and is delivered to the buddy → the QUIC
	# handshake comes up over the direct path → via="direct P2P".
	# This is faithful full-cone behaviour: endpoint-independent MAPPING, with the
	# stray-packet race removed so the simultaneous punch can actually converge.
	# symmetric mode keeps plain --random-fully MASQUERADE and is untouched, so it
	# still (correctly) fails to punch and falls back to the relay.
	iptables -A INPUT  -i "$WAN_IF" -p udp --dport 50000 -m conntrack --ctstate NEW -j DROP
	iptables -A FORWARD -i "$WAN_IF" -p udp --dport 50000 -m conntrack --ctstate NEW -j DROP
fi

echo "[nat] WAN_IF=$WAN_IF WAN_IP=$WAN_IP mode=$MODE — forwarding + NAT active"
exec tail -f /dev/null

#!/bin/sh
# Buddy entrypoint for the CGNAT lab: point the default route at this node's NAT
# router (Docker otherwise routes via its own bridge), then run buddynet. The
# buddy reaches the server and its peers only through the NAT, so the lab exercises
# the real hole-punch / relay-fallback path through carrier-grade-style NAT.
set -e

ip route replace default via "$NAT_GW"
echo "[client] default route via $NAT_GW (${NODE_NAME:-buddy})"

# SERVE_HTTP=1 additionally starts the busybox httpd test service on :7777, so a
# node behind NAT can be the one that OFFERS something through the tunnel (used by
# the coordinator lab, where the coordinator is also a buddy).
if [ "${SERVE_HTTP:-}" = "1" ]; then
	mkdir -p /tmp/www
	echo "<h1>BuddyNet Lab - Peer A</h1>" > /tmp/www/index.html
	httpd -p 7777 -h /tmp/www
	echo "[client] httpd test service started on :7777"
fi

exec /usr/local/bin/buddynet "$@"

#!/bin/sh
# Buddy entrypoint for the CGNAT lab: point the default route at this node's NAT
# router (Docker otherwise routes via its own bridge), then run buddynet. The
# buddy reaches the server and its peers only through the NAT, so the lab exercises
# the real hole-punch / relay-fallback path through carrier-grade-style NAT.
set -e

ip route replace default via "$NAT_GW"
echo "[client] default route via $NAT_GW (${NODE_NAME:-buddy})"

exec /usr/local/bin/buddynet "$@"

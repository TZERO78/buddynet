#!/bin/sh
# Entrypoint for a BuddyParty service node (beta/gamma/…): serves a tiny httpd
# page that names the node (so the routing test can tell which buddy answered),
# then runs buddynet with the compose CMD plus --name from $NODE_NAME (so every
# buddy service can share one command list and differ only by NODE_NAME).
set -e

mkdir -p /tmp/www
echo "BuddyNet Party - ${NODE_NAME:-unknown}" > /tmp/www/index.html

httpd -p 7777 -h /tmp/www
echo "[lab] httpd for ${NODE_NAME:-unknown} started on :7777"

exec /usr/local/bin/buddynet "$@" --name "${NODE_NAME:-buddy}"

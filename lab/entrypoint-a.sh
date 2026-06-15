#!/bin/sh
# Entrypoint for buddy-a: starts a busybox httpd test service on :7777,
# then runs buddynet forwarding incoming tunnel streams to it.
set -e

# Create a minimal test page
mkdir -p /tmp/www
cat > /tmp/www/index.html << 'HTML'
<!DOCTYPE html>
<html>
<head><title>BuddyNet Lab</title></head>
<body>
  <h1>BuddyNet Lab - Peer A</h1>
  <p>If you see this, the tunnel is working correctly.</p>
  <p>Served by buddy-a via BuddyNet.</p>
</body>
</html>
HTML

# httpd from busybox-extras — daemonizes by default (no -f flag)
httpd -p 7777 -h /tmp/www
echo "[lab] httpd test service started on :7777"

# Hand off to buddynet with whatever flags docker-compose passed as CMD
exec /usr/local/bin/buddynet "$@"

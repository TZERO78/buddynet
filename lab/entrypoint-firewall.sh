#!/usr/bin/env bash
# Entrypoint for the firewall-coexistence lab buddy. It brings up a REAL host
# firewall (chosen by $FIREWALL) that actively manages this container's ruleset,
# starts the test services, then execs buddynet with the passed arguments.
#
#   FIREWALL=firewalld  run firewalld (its own nftables table) with a default zone
#   FIREWALL=ufw        enable ufw (default deny incoming, allow the tunnel underlay)
#   FIREWALL=nft        a hand-written host nft table (default input drop + allows)
#   FIREWALL=none       no host firewall (baseline)
#
#   SERVICES="873 2222" start a trivial TCP echo service on each port (background)
#
# All firewall setups deliberately do NOT know about bnetN — the point is that
# BuddyNet's own scoping coexists regardless of what the host firewall does.
set -euo pipefail

start_services() {
	for port in ${SERVICES:-}; do
		# A tiny always-on TCP responder; -k keeps listening across connections.
		( while true; do echo "port-$port" | nc -l -k -p "$port" >/dev/null 2>&1 || sleep 0.2; done ) &
	done
}

# Every host-firewall setup below is default-deny but explicitly PERMITS the
# tunnel: the WireGuard underlay/control ports and ALL inbound on bnetN. That is
# the realistic "locked-down host that runs the tunnel" — and it makes the point
# sharp: since the host firewall itself allows everything on bnetN, whatever
# still blocks the unexposed :2222 can ONLY be BuddyNet's own scope.
start_firewalld() {
	mkdir -p /run/dbus
	rm -f /run/dbus/pid
	dbus-daemon --system --fork
	firewalld --nofork &
	for _ in $(seq 1 30); do firewall-cmd --state >/dev/null 2>&1 && break; sleep 0.5; done
	firewall-cmd --state
	firewall-cmd --set-default-zone=public >/dev/null
	# Trust intra-lab underlay traffic (server + peer live on the lab subnet) and
	# the whole overlay range, so firewalld's OWN default-deny does not block the
	# tunnel — BuddyNet's per-port scope then does the least-privilege gating on
	# top. (A direct rule in ip/filter can't override firewalld's inet drop; a
	# trusted source in firewalld's own zone model can.)
	firewall-cmd --zone=trusted --add-source="${LAB_SUBNET:-172.30.0.0/24}" >/dev/null
	firewall-cmd --zone=trusted --add-source="10.66.0.0/16" >/dev/null
	echo "FIREWALL: firewalld active — public (default-deny) zone, nftables backend; underlay+bnet0 permitted"
	nft list tables 2>/dev/null | sed 's/^/  nft-table: /'
}

start_ufw() {
	ufw --force reset >/dev/null 2>&1 || true
	ufw default deny incoming >/dev/null
	ufw default allow outgoing >/dev/null
	ufw allow 51820:51821/udp >/dev/null
	ufw allow 51820:51821/tcp >/dev/null
	ufw allow in on bnet0 >/dev/null   # host firewall does NOT restrict the overlay
	ufw --force enable >/dev/null
	echo "FIREWALL: ufw active — default deny incoming; underlay+bnet0 permitted"
	ufw status verbose | sed 's/^/  ufw: /'
}

start_nft_host() {
	nft -f - <<-'EOF'
		table inet hostfw {
		  chain input {
		    type filter hook input priority 0; policy drop;
		    ct state established,related accept
		    iifname "lo" accept
		    meta l4proto icmp accept
		    udp dport 51820-51821 accept
		    tcp dport 51820-51821 accept
		    iifname "bnet0" accept
		  }
		}
	EOF
	echo "FIREWALL: host nft table 'hostfw' active — input policy drop; underlay+bnet0 permitted"
	nft list tables | sed 's/^/  nft-table: /'
}

case "${FIREWALL:-none}" in
	firewalld) start_firewalld ;;
	ufw)       start_ufw ;;
	nft)       start_nft_host ;;
	none)      echo "FIREWALL: none (baseline)" ;;
	*)         echo "unknown FIREWALL=$FIREWALL" >&2; exit 2 ;;
esac

start_services
exec buddynet "$@"

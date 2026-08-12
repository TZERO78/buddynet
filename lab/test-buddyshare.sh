#!/usr/bin/env bash
# e2e for the BuddyShare pattern (docs/plans/buddyshare.md): SMB over the
# --wireguard data plane, scoped to :445 with --expose. REAL binary, real smbd.
#
# Mirrors the Unraid↔Unraid setup: on the sharing side a stock smbd (bound to
# 0.0.0.0, like Unraid's) with a per-buddy share user; the buddy reaches it at
# the VIP over the tunnel — and nothing else.
#
# Three netns on one bridge (no NAT → direct punch trivially works):
#   ns-srv  10.50.0.10  handshake+relay
#   ns-a    10.50.0.20  buddy A — runs smbd, shares [buddyshare], --expose 445
#   ns-b    10.50.0.30  buddy B — the consuming side (fail-closed, no --expose)
#
# Asserts:
#   1. B reaches A's :445 over the tunnel; an unexposed :2222 stays blocked
#   2. smbd started BEFORE the tunnel answers on the VIP (hot-plugged bnet0 —
#      the "does Samba serve an interface that appears later" question)
#   3. smbclient auth + write/read roundtrip through the tunnel
#   4. wrong SMB password is refused (user layer works independently)
#   5. mount.cifs (the Unassigned-Devices path): mount, write, verify, umount
#   6. user revoke: smbpasswd -d → access refused while the port stays open
#   7. expose revoke: restart A without --expose → :445 gone (fail-closed)
# Needs root + wireguard module + kernel nftables + samba/smbclient/cifs-utils.
set -euo pipefail
cd "$(dirname "$0")/.."
BN=/tmp/bshare/bn
D=/tmp/bshare
TOKEN=lab-buddyshare-token
LABUSER=$(id -un)
SMBPW=lab-buddy-pw
SMBPW_WRONG=not-the-password

for tool in smbd smbclient mount.cifs smbpasswd; do
	command -v "$tool" >/dev/null || { echo "SKIP: $tool not installed"; exit 0; }
done

cleanup() {
	set +e
	sudo umount -l "$D/mnt" 2>/dev/null
	for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
	sleep 1
	sudo pkill -f '^smbd.*bshare' 2>/dev/null
	for ns in ns-srv ns-a ns-b ns-sw; do sudo ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
trap 'echo "[signal — aborting]" >&2; exit 1' INT TERM  # EXIT trap does the cleanup; never continue past a signal
PIDS=""

# smbd runs as root and leaves root-owned state — clean with sudo (cf. /tmp/wg* lab lesson)
sudo rm -rf "$D"; mkdir -p "$D"
echo "== [$(date +%T)] build =="
go build -o "$BN" ./cmd/buddynet
sudo modprobe wireguard

echo "== [$(date +%T)] identities =="
SRVPUB=$("$BN" --key "$D/srv.key" init)
APUB=$("$BN" --key "$D/a.key" init)
BPUB=$("$BN" --key "$D/b.key" init)

echo "== [$(date +%T)] bridge topology (ns-srv/a/b on br0 in ns-sw) =="
sudo ip netns add ns-sw; sudo ip netns add ns-srv; sudo ip netns add ns-a; sudo ip netns add ns-b
sudo ip netns exec ns-sw ip link add br0 type bridge
sudo ip netns exec ns-sw ip link set br0 up
add_node() { # $1 ns, $2 addr
	sudo ip link add "v-$1" netns "ns-$1" type veth peer name "b-$1" netns ns-sw
	sudo ip netns exec ns-sw ip link set "b-$1" master br0
	sudo ip netns exec ns-sw ip link set "b-$1" up
	sudo ip -n "ns-$1" link set "v-$1" up
	sudo ip -n "ns-$1" link set lo up
	sudo ip -n "ns-$1" addr add "$2/24" dev "v-$1"
}
add_node srv 10.50.0.10
add_node a 10.50.0.20
add_node b 10.50.0.30

echo "== [$(date +%T)] samba: private instance in ns-a (stock Unraid shape: bind 0.0.0.0) =="
mkdir -p "$D/share" "$D/smb-private" "$D/smb-lock" "$D/smb-state" "$D/smb-cache" "$D/smb-pid" "$D/smb-ncalrpc"
echo "hello from buddy A" > "$D/share/greeting.txt"
cat > "$D/smb.conf" <<CONF
[global]
  security = user
  map to guest = never
  passdb backend = smbpasswd:$D/smbpasswd
  private dir = $D/smb-private
  lock directory = $D/smb-lock
  state directory = $D/smb-state
  cache directory = $D/smb-cache
  pid directory = $D/smb-pid
  # Without this smbd falls back to /run/samba/ncalrpc and EXITS if that
  # directory is absent — which it is on any host where the system smbd has
  # never run. The instance is only "private" once every path it needs is here.
  ncalrpc dir = $D/smb-ncalrpc
  log file = $D/smb.log
  log level = 1
  server min protocol = SMB2
  disable netbios = yes
  smb ports = 445
  bind interfaces only = no

[buddyshare]
  path = $D/share
  valid users = $LABUSER
  read only = no
  guest ok = no
CONF
touch "$D/smbpasswd"; chmod 600 "$D/smbpasswd"
printf '%s\n%s\n' "$SMBPW" "$SMBPW" | sudo smbpasswd -s -c "$D/smb.conf" -a "$LABUSER" >/dev/null
# Start smbd BEFORE the tunnel exists — bnet0 must be served hot-plugged (2).
sudo ip netns exec ns-a smbd -F -s "$D/smb.conf" >"$D/smbd.log" 2>&1 &
PIDS="$PIDS $!"
# A second, PRIVATE service that must stay invisible behind --expose 445.
sudo ip netns exec ns-a sh -c 'while true; do echo private | nc -l -p 2222 -q1 >/dev/null 2>&1; done' &
PIDS="$PIDS $!"
sleep 1

start_server() {
	sudo ip netns exec ns-srv "$BN" --role=handshake,relay \
		--listen 0.0.0.0:51820 --relay-listen 0.0.0.0:51821 \
		--key "$D/srv.key" --relay-endpoint 10.50.0.10:51821 >"$D/srv.log" 2>&1 &
	PIDS="$PIDS $!"
}

run_buddy() { # $1 ns, $2 keyfile, $3 peerpub, $4 extra-flags, $5 logfile
	sudo ip netns exec "ns-$1" "$BN" --join "$TOKEN" --role=buddy \
		--server 10.50.0.10:51820 --server-key "$SRVPUB" \
		--key "$2" --peer-key "$3" --known-peers "$D/$1.kp" --peers "$D/$1.pj" --no-interactive $4 >"$5" 2>&1 &
	PIDS="$PIDS $!"
}

assert_connected() { # $1 logfile, $2 label
	for _ in $(seq 1 30); do grep -q 'CONNECTED:' "$1" 2>/dev/null && break; sleep 1; done
	line=$(grep -m1 'CONNECTED:' "$1" 2>/dev/null || true)
	echo "  $2: ${line:-<none>}"
	echo "$line" | grep -qF 'via="direct P2P (WireGuard)"'
}

FAIL=0
smbc() { # $1 user%pass, $2 -c command → runs smbclient from ns-b against A's VIP
	sudo ip netns exec ns-b timeout 25 smbclient "//$VIP_A/buddyshare" -U "$1" -m SMB3 -c "$2"
}

echo "== [$(date +%T)] PHASE 1: tunnel up, A scoped to :445 =="
start_server; sleep 1
run_buddy a "$D/a.key" "$BPUB" "--wireguard --expose 445" "$D/a.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard" "$D/b.log"
if assert_connected "$D/a.log" "buddy-a" && assert_connected "$D/b.log" "buddy-b"; then
	VIP_A=$(grep -m1 'CONNECTED:' "$D/b.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	grep -q 'EXPOSE: action=scoped iface=bnet0 ports=tcp/445' "$D/a.log" || { echo "  [FAIL] A did not log its :445 scope"; FAIL=1; }

	if sudo ip netns exec ns-b nc -z -w 2 "$VIP_A" 445; then echo "  [PASS] :445 reachable over the tunnel"
	else echo "  [FAIL] :445 unreachable"; FAIL=1; fi
	if sudo ip netns exec ns-b nc -z -w 2 "$VIP_A" 2222; then echo "  [FAIL] unexposed :2222 reachable — scope broken"; FAIL=1
	else echo "  [PASS] unexposed :2222 blocked"; fi

	echo "== [$(date +%T)] PHASE 2: smbd serves the hot-plugged bnet0 + auth + roundtrip =="
	if smbc "$LABUSER%$SMBPW" "ls" >"$D/ls.out" 2>&1 && grep -q greeting.txt "$D/ls.out"; then
		echo "  [PASS] smbd answers on the VIP (interface appeared after smbd start)"
	else echo "  [FAIL] smbclient ls failed"; sed 's/^/    | /' "$D/ls.out"; FAIL=1; fi

	echo "buddyshare roundtrip $(date +%s)" > "$D/up.txt"
	sudo cp "$D/up.txt" /tmp/bshare-up.txt
	if smbc "$LABUSER%$SMBPW" "lcd /tmp; put bshare-up.txt; get bshare-up.txt bshare-down.txt" >/dev/null 2>&1 \
		&& cmp -s "$D/up.txt" /tmp/bshare-down.txt; then
		echo "  [PASS] write/read roundtrip through the tunnel"
	else echo "  [FAIL] SMB roundtrip broken"; FAIL=1; fi

	if smbc "$LABUSER%$SMBPW_WRONG" "ls" >/dev/null 2>&1; then
		echo "  [FAIL] wrong password accepted"; FAIL=1
	else echo "  [PASS] wrong password refused"; fi

	echo "== [$(date +%T)] PHASE 3: mount.cifs (the Unassigned-Devices path) =="
	# NOTE: every `ip netns exec` gets its own MOUNT namespace, so mount, write,
	# read and umount must happen in ONE invocation — a mount does not survive it.
	mkdir -p "$D/mnt"
	if sudo ip netns exec ns-b timeout 25 sh -c "
		mount -t cifs //$VIP_A/buddyshare $D/mnt -o user=$LABUSER,pass=$SMBPW,vers=3.0,soft &&
		echo via-mount > $D/mnt/mounted.txt &&
		cat $D/mnt/greeting.txt &&
		umount $D/mnt" >"$D/mount.out" 2>"$D/mount.err" \
		&& grep -q hello "$D/mount.out" && grep -q via-mount "$D/share/mounted.txt"; then
		echo "  [PASS] cifs mount: read works, write lands in A's share"
	else
		echo "  [FAIL] cifs mount roundtrip failed:"
		sed 's/^/    | /' "$D/mount.err" 2>/dev/null || true
		FAIL=1
	fi

	echo "== [$(date +%T)] PHASE 4: user revoke (smbpasswd -d) — port open, access gone =="
	sudo smbpasswd -s -c "$D/smb.conf" -d "$LABUSER" >/dev/null
	if smbc "$LABUSER%$SMBPW" "ls" >/dev/null 2>&1; then
		echo "  [FAIL] disabled user still has access"; FAIL=1
	else echo "  [PASS] disabled user refused (folder layer revokes independently)"; fi
	sudo smbpasswd -s -c "$D/smb.conf" -e "$LABUSER" >/dev/null
else
	echo "  [FAIL] tunnel did not come up"; FAIL=1
	tail -5 "$D/a.log" | sed 's/^/    a| /'; tail -5 "$D/b.log" | sed 's/^/    b| /'
fi

echo "== [$(date +%T)] PHASE 5: expose revoke — restart A fail-closed, :445 gone =="
for p in $PIDS; do sudo kill "$p" 2>/dev/null || true; done; PIDS=""; sleep 2
ip netns list | grep -q ns-a || { echo "  [FAIL] ns-a vanished before phase 5"; exit 1; }
sudo ip netns exec ns-a smbd -F -s "$D/smb.conf" >>"$D/smbd.log" 2>&1 &
PIDS="$PIDS $!"
start_server; sleep 1
: > "$D/a5.log"; : > "$D/b5.log"
run_buddy a "$D/a.key" "$BPUB" "--wireguard" "$D/a5.log"
run_buddy b "$D/b.key" "$APUB" "--wireguard" "$D/b5.log"
if assert_connected "$D/a5.log" "buddy-a" && assert_connected "$D/b5.log" "buddy-b"; then
	VIP_A=$(grep -m1 'CONNECTED:' "$D/b5.log" | grep -oE 'vip=10\.66\.[0-9]+\.[0-9]+' | cut -d= -f2)
	if sudo ip netns exec ns-b nc -z -w 2 "$VIP_A" 445; then
		echo "  [FAIL] :445 still reachable without --expose"; FAIL=1
	else echo "  [PASS] no --expose → smbd invisible again (fail-closed)"; fi
else
	echo "  [FAIL] phase-5 tunnel did not come up"; FAIL=1
	tail -5 "$D/a5.log" | sed 's/^/    a| /'
fi

if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi

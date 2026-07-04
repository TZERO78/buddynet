#!/usr/bin/env bash
# P3.1 step-4c PRE-PROOF: the socket handoff punch->WG across a real NAT.
#
# The risk in 4c: today QUIC reuses the SAME socket/fd that hole-punched, so the
# NAT mapping is trivially kept. Kernel WireGuard uses its OWN (kernel) socket on
# the same local port. This proves that closing the punching socket and binding
# kernel-WG to the same port REUSES the NAT mapping (conntrack keys on the 4-tuple,
# not the socket), so the far side still reaches us at the punched public address.
#
# Topology (three netns):
#   nsA (behind NAT) ──10.1.0.0/24── nsNAT (MASQUERADE) ──10.2.0.0/24── nsB (public)
#
# Sequence: a UDP "punch" from nsA:P to nsB:Q opens a NAT mapping; nsB records the
# public address X it observed; nsA closes the socket; both sides bring up WG with
# our internal/wg (nsA listen=P, nsB peer-endpoint=X); a ping over the overlay must
# traverse the tunnel — proving the mapping survived the handoff.
#
# Needs root + the wireguard module. Run: ./lab/test-wg-handoff.sh
set -euo pipefail

NS_A=wgho-a NS_NAT=wgho-nat NS_B=wgho-b
P=51821          # nsA WireGuard / punch local port
Q=51820          # nsB WireGuard listen port
BIN=/tmp/wg-spike
OBS=/tmp/wgho_observed
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  set +e
  for p in ${PIDS:-}; do sudo kill "$p" 2>/dev/null; done
  for ns in "$NS_A" "$NS_NAT" "$NS_B"; do sudo ip netns del "$ns" 2>/dev/null; done
  sudo rm -f "$OBS"
}
trap cleanup EXIT
PIDS=""

echo "== build spike =="
( cd "$ROOT" && go build -o "$BIN" ./lab/wg-spike )
sudo modprobe wireguard

echo "== keys =="
SEED_A="$(head -c32 /dev/urandom | base64 -w0)"
SEED_B="$(head -c32 /dev/urandom | base64 -w0)"
read -r PUB_A VIP_A < <("$BIN" pubkey --seed "$SEED_A")
read -r PUB_B VIP_B < <("$BIN" pubkey --seed "$SEED_B")
echo "A vip=$VIP_A   B vip=$VIP_B"

echo "== topology: nsA - nsNAT(MASQUERADE) - nsB =="
for ns in "$NS_A" "$NS_NAT" "$NS_B"; do sudo ip netns add "$ns"; sudo ip -n "$ns" link set lo up; done
# veth nsA <-> nsNAT
sudo ip link add va-nat netns "$NS_A" type veth peer name vnat-a netns "$NS_NAT"
sudo ip -n "$NS_A"   addr add 10.1.0.2/24 dev va-nat
sudo ip -n "$NS_NAT" addr add 10.1.0.1/24 dev vnat-a
sudo ip -n "$NS_A"   link set va-nat up
sudo ip -n "$NS_NAT" link set vnat-a up
# veth nsNAT <-> nsB
sudo ip link add vnat-b netns "$NS_NAT" type veth peer name vb-nat netns "$NS_B"
sudo ip -n "$NS_NAT" addr add 10.2.0.1/24 dev vnat-b
sudo ip -n "$NS_B"   addr add 10.2.0.2/24 dev vb-nat
sudo ip -n "$NS_NAT" link set vnat-b up
sudo ip -n "$NS_B"   link set vb-nat up
# routing + NAT
sudo ip -n "$NS_A" route add default via 10.1.0.1
sudo ip netns exec "$NS_NAT" sysctl -q -w net.ipv4.ip_forward=1
sudo ip netns exec "$NS_NAT" iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o vnat-b -j MASQUERADE

echo "== punch: open NAT mapping nsA:$P -> nsB:$Q =="
sudo ip netns exec "$NS_B" python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",'"$Q"')); s.settimeout(10)
d,a=s.recvfrom(2048); open("'"$OBS"'","w").write("%s %d\n"%(a[0],a[1])); s.sendto(b"ok",a); s.close()
' &
PIDS="$PIDS $!"
sleep 0.5
sudo ip netns exec "$NS_A" python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",'"$P"')); s.settimeout(5)
s.sendto(b"probe",("10.2.0.2",'"$Q"'))
try: d,a=s.recvfrom(2048); print("punch reply:",d,a)
except Exception as e: print("NO punch reply:",e)
s.close()
'
sleep 0.5
sudo test -s "$OBS" || { echo "RESULT: FAIL — nsB never saw the punch"; exit 1; }
read -r X_IP X_PORT < <(sudo cat "$OBS")
echo "nsB observed nsA's public mapping as $X_IP:$X_PORT  (port preserved: $([ "$X_PORT" = "$P" ] && echo yes || echo no))"

echo "== handoff: punch socket closed; bring up kernel-WG on the same port =="
sudo ip netns exec "$NS_A" "$BIN" up --seed "$SEED_A" --peer-pub "$PUB_B" \
  --ifname wgh-a --listen-port "$P" --peer-endpoint "10.2.0.2:$Q" --keepalive 5 &
PIDS="$PIDS $!"
sudo ip netns exec "$NS_B" "$BIN" up --seed "$SEED_B" --peer-pub "$PUB_A" \
  --ifname wgh-b --listen-port "$Q" --peer-endpoint "$X_IP:$X_PORT" --keepalive 5 &
PIDS="$PIDS $!"
sleep 2

echo "== ping over the tunnel (nsA -> nsB VIP) — proves the mapping survived =="
rc=0
sudo ip netns exec "$NS_A" ping -c 4 -W 2 "$VIP_B" || rc=$?
echo "== conntrack entry at the NAT =="
sudo ip netns exec "$NS_NAT" conntrack -L 2>/dev/null | grep -E "dport=$Q" || true

if [ "$rc" -eq 0 ]; then
  echo "RESULT: PASS — kernel-WG reused the punched NAT mapping after the socket handoff"
else
  echo "RESULT: FAIL — tunnel did not come up through the NAT mapping (rc=$rc)"
fi
exit "$rc"

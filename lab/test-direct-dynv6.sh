#!/usr/bin/env bash
# Direct mode over a REAL dynamic-DNS name (dynv6), end to end.
#
# The sibling test-direct.sh proves the mechanism offline by rewriting /etc/hosts.
# This one closes the loop with an actual provider: it updates a real record, lets
# a real resolver answer, and brings the tunnel up over whatever address comes
# back. Nothing in BuddyNet talks to the provider — the update here is doing by
# hand exactly what a router or a cron job does in production, which is the point:
# there is no DynDNS provider integrated into BuddyNet and no API token in it.
#
# OPT-IN. It needs credentials and touches a public DNS record, so it is skipped
# unless they are present. Put them in ../secrets/dynv6.env (git-ignored; copy
# ../secrets/dynv6.env.example), which this script sources automatically:
#
#   cp ../secrets/dynv6.env.example ../secrets/dynv6.env && $EDITOR ../secrets/dynv6.env
#   ./test-direct-dynv6.sh
#
# The environment wins over the file if both are set. The token is an update
# credential — it can repoint the record your buddies resolve — so it belongs in
# that file and never in a command line, a shell history or a commit.
#
# WHAT THIS PROVES: the name is resolved fresh, the tunnel comes up over the
# resolved address, and the pinned key still decides who the peer is.
# WHAT IT DOES NOT PROVE: reachability from a FOREIGN host. Both buddies run here,
# so the connection reaches this machine's own global address. Whether your
# firewall lets a stranger in is a separate question, and your router's business.
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

# Credentials from secrets/dynv6.env unless already in the environment.
SECRETS="$ROOT/secrets/dynv6.env"
if [ -f "$SECRETS" ]; then
  # shellcheck disable=SC1090
  set -a; . "$SECRETS"; set +a
fi

if [ -z "${DYNV6_TOKEN:-}" ] || [ -z "${DYNV6_HOST:-}" ] || [ "${DYNV6_TOKEN:-}" = "replace-me" ]; then
  echo "SKIP: no dynamic-DNS credentials."
  echo "      cp secrets/dynv6.env.example secrets/dynv6.env, fill it in, and re-run."
  echo "      The offline equivalent needs no credentials at all: ./test-direct.sh"
  exit 0
fi

PORT="${DYNV6_PORT:-51844}"
D=$(mktemp -d /tmp/bndynv6.XXXXXX)
BN="$D/buddynet"
cleanup(){ kill $(jobs -p) 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

go build -o "$BN" "$ROOT/cmd/buddynet" || { echo "FAIL: go build"; exit 1; }

# A GLOBAL address of this host — the thing a DynDNS record is supposed to carry.
# Prefer IPv6: it has no NAT in the way, so this machine can reach its own global
# address directly, which is what lets the test run without a port forward.
ADDR=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/ {print $2}' \
  | cut -d/ -f1 | grep -v '^fd' | head -1)
FAMILY=ipv6
if [ -z "$ADDR" ]; then
  echo "NOTE: no global IPv6 on this host; falling back to IPv4, which needs a"
  echo "      port forward AND NAT loopback on your router to work at all."
  ADDR=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
  FAMILY=ipv4
fi
[ -n "$ADDR" ] || { echo "FAIL: no global address on this host"; exit 1; }
echo "== updating $DYNV6_HOST -> $ADDR ($FAMILY) =="

# This is the whole of the DynDNS integration: one HTTP GET, done by something
# that is not BuddyNet.
CODE=$(curl -s --max-time 20 -o "$D/update.out" -w '%{http_code}' \
  "https://dynv6.com/api/update?hostname=${DYNV6_HOST}&token=${DYNV6_TOKEN}&${FAMILY}=${ADDR}")
if [ "$CODE" = "200" ]; then
  ok "provider accepted the update ($(cat "$D/update.out"))"
else
  no "provider rejected the update (http $CODE): $(cat "$D/update.out")"
  echo "Results: $PASS passed, $FAIL failed"; exit 1
fi

# Wait for the record to actually carry our address before blaming BuddyNet for
# anything. A resolver that still has the old answer is not a tunnel bug.
RESOLVED=""
for _ in $(seq 1 24); do
  if [ "$FAMILY" = ipv6 ]; then
    RESOLVED=$(getent ahostsv6 "$DYNV6_HOST" 2>/dev/null | awk '{print $1}' | head -1)
  else
    RESOLVED=$(getent ahostsv4 "$DYNV6_HOST" 2>/dev/null | awk '{print $1}' | head -1)
  fi
  [ "$RESOLVED" = "$ADDR" ] && break
  sleep 5
done
if [ "$RESOLVED" = "$ADDR" ]; then
  ok "the name resolves to this host ($RESOLVED)"
else
  no "record did not propagate in time (got ${RESOLVED:-nothing}, want $ADDR)"
  echo "Results: $PASS passed, $FAIL failed"; exit 1
fi

"$BN" --key "$D/bob.key" init >/dev/null 2>&1
"$BN" --key "$D/sarah.key" init >/dev/null 2>&1
BOB=$("$BN" --key "$D/bob.key" identity)
SARAH=$("$BN" --key "$D/sarah.key" identity)

echo "served-by-bob-over-dynv6" > "$D/index.html"
python3 -m http.server 7788 --bind 127.0.0.1 --directory "$D" >/dev/null 2>&1 &
sleep 1

# Bob is only ever DIALLED: a fixed port, no endpoint of his own.
"$BN" --role=buddy --direct \
  --key "$D/bob.key" --known-peers "$D/bk" --peers "$D/bp.json" \
  --peer-key "$SARAH" --listen-port "$PORT" \
  --forward 127.0.0.1:7788 --no-interactive > "$D/bob.log" 2>&1 &
sleep 2

# Sarah knows the NAME and the pinned key. Nothing else: no address, no server,
# no token, no prior pairing.
"$BN" --role=buddy --direct \
  --key "$D/sarah.key" --known-peers "$D/sk" --peers "$D/sp.json" \
  --peer-key "$BOB" --peer-endpoint "${DYNV6_HOST}:${PORT}" \
  -L 127.0.0.1:9188 --no-interactive > "$D/sarah.log" 2>&1 &

for _ in $(seq 1 45); do grep -q CONNECTED "$D/sarah.log" 2>/dev/null && break; sleep 1; done

if grep -q CONNECTED "$D/sarah.log" 2>/dev/null; then
  ok "tunnel came up over the dynamic-DNS name, with no handshake server"
  # The dialled endpoint must be the RESOLVED address — proof the name was used
  # for route-finding and not, say, a stale cached peer.
  grep -q "endpoint=\[\?${ADDR}" "$D/sarah.log" \
    && ok "dialled the address the record resolved to" \
    || no "connected, but not to the resolved address: $(grep -m1 'path-try' "$D/sarah.log")"
  curl -s --max-time 8 http://127.0.0.1:9188/ 2>/dev/null | grep -q 'served-by-bob' \
    && ok "real traffic flows through the tunnel" \
    || no "tunnel up but no traffic"
else
  no "no tunnel over the dynamic-DNS name"
  tail -12 "$D/sarah.log" | sed 's/^/    /'
fi

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

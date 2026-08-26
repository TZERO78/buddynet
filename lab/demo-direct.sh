#!/usr/bin/env bash
# BuddyNet — DIRECT MODE ascii demo (no handshake server anywhere). Record with:
#   asciinema rec -c ./demo-direct.sh --cols 100 --rows 28 --overwrite ../media/direct-demo.cast
#   agg --theme asciinema ../media/direct-demo.cast ../media/direct-demo.gif
#
# Tells the whole "two buddies, nothing else" story in three real steps:
#   1) each side prints its identity   (buddynet identity)
#   2) the reachable side listens      (--direct --listen-port)
#   3) the other side dials it by NAME (--direct --peer-endpoint) → tunnel + traffic
#
# Every key, CONNECTED line and curl body below comes from a REAL pair of buddynet
# processes started by this script — there is no server involved, which is the
# point. The command LINES are typed out for legibility rather than executed, so
# verify_cmd() runs each one against the real binary first: a demo may only show a
# command that works. (The deployment GIF once shipped a headline command that
# exited 1 because it had drifted; hence this check.)
#
# The endpoint shown is `localhost` because the demo runs both buddies here. In a
# real setup it is your dynamic-DNS name — which is re-resolved on every attempt,
# so a changing address needs no reconfiguration. Said on screen, not implied.
#
# No prerequisites: no lab, no Docker, no server. ~35s.
set -u
cd "$(dirname "$0")"

D=$(mktemp -d /tmp/bndemo.XXXXXX)
BN="$D/buddynet"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$D"; }
trap cleanup EXIT

go build -o "$BN" ../cmd/buddynet || { echo "demo-direct: build failed" >&2; exit 1; }

# verify_cmd runs a to-be-typed command against the real binary on throwaway paths
# and fails the recording if it does not come up. Direct mode fails FAST on a bad
# flag combination (exit 2), so a timeout is the success signal here: it means the
# process got past validation and started its connect loop.
verify_cmd() {
  local cmd=$1 dir; dir=$(mktemp -d)
  cmd=$(echo "$cmd" | sed -e "s|buddynet|$BN|" -e "s|id.key|$dir/id.key|g" \
                          -e "s|:51820|:61833|g")
  "$BN" --key "$dir/id.key" init >/dev/null 2>&1
  timeout 3 bash -c "$cmd --known-peers $dir/kp --peers $dir/pj" >"$dir/log" 2>&1
  local rc=$?
  if [ "$rc" -ne 124 ]; then
    printf 'demo-direct: the command this demo would TYPE does not run (exit %s):\n  %s\n' "$rc" "$1" >&2
    sed 's/^/  | /' "$dir/log" >&2
    rm -rf "$dir"; exit 1
  fi
  rm -rf "$dir"
}

# ── pre-flight (silent): a real pair, so every line shown below is genuine ─────
NASPUB=$("$BN" --key "$D/nas.key" init 2>/dev/null | head -0; "$BN" --key "$D/nas.key" identity)
LAPPUB=$("$BN" --key "$D/laptop.key" init 2>/dev/null | head -0; "$BN" --key "$D/laptop.key" identity)
echo "BuddyNet direct mode — served from the NAS" > "$D/index.html"
(cd "$D" && python3 -m http.server 7777 --bind 127.0.0.1 >/dev/null 2>&1) &
PIDS="$PIDS $!"
sleep 1

NASCMD="buddynet --role=buddy --direct --key id.key --peer-key ${LAPPUB:0:10}… --listen-port 51820 --forward 127.0.0.1:7777"
LAPCMD="buddynet --role=buddy --direct --key id.key --peer-key ${NASPUB:0:10}… --peer-endpoint localhost:51820 -L 127.0.0.1:9000"
# Verify the real shape of both (full keys, real ports) before showing them.
verify_cmd "buddynet --role=buddy --direct --key id.key --peer-key $LAPPUB --listen-port 51820 --forward 127.0.0.1:7777 --no-interactive"
verify_cmd "buddynet --role=buddy --direct --key id.key --peer-key $NASPUB --peer-endpoint localhost:51820 -L 127.0.0.1:0 --no-interactive"

"$BN" --role=buddy --direct --key "$D/nas.key" --known-peers "$D/n.kp" --peers "$D/n.pj" \
  --peer-key "$LAPPUB" --listen-port 51820 --forward 127.0.0.1:7777 --no-interactive >"$D/nas.log" 2>&1 &
PIDS="$PIDS $!"
sleep 2
"$BN" --role=buddy --direct --key "$D/laptop.key" --known-peers "$D/l.kp" --peers "$D/l.pj" \
  --peer-key "$NASPUB" --peer-endpoint localhost:51820 -L 127.0.0.1:9000 --no-interactive >"$D/lap.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 40); do grep -q CONNECTED "$D/lap.log" 2>/dev/null && break; sleep 0.5; done
grep -q CONNECTED "$D/lap.log" || { echo "demo-direct: the pair did not connect" >&2; tail -5 "$D/lap.log" >&2; exit 1; }
# Real CONNECTED lines, with the timestamp and two redundant fields dropped so
# they fit the 100-column recording: key= repeats partner=, and remote= is the
# socket detail. Nothing is reworded — a wrapped headline is the first thing a
# visitor sees, and truncating beats rewriting.
trim() { sed -E 's/^[0-9:]* //; s/ key=[^ ]+//; s/ remote=[^ ]+//'; }
NASCONN=$(grep -m1 'CONNECTED:' "$D/nas.log" | trim)
LAPCONN=$(grep -m1 'CONNECTED:' "$D/lap.log" | trim)
BODY=$(curl -s --max-time 8 http://127.0.0.1:9000/ | head -1)
[ -n "$BODY" ] || { echo "demo-direct: no traffic through the tunnel" >&2; exit 1; }

# ── presentation ──────────────────────────────────────────────────────────────
G=$'\033[1;32m'; B=$'\033[1;34m'; D2=$'\033[2m'; C=$'\033[1;36m'; Y=$'\033[1;33m'; R=$'\033[0m'
typ() { local s=$1 i; for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; sleep 0.018; done; printf '\n'; }
say() { printf '%s%s%s\n' "$D2" "$1" "$R"; sleep 0.7; }
out() { printf '%s%s%s\n' "$D2" "$1" "$R"; }
hl()  { printf '%s%s%s\n' "$C" "$1" "$R"; }
host() { printf '%s%s%s:%s~%s$ ' "$G" "$1" "$R" "$B" "$R"; }

clear
printf '%s┌──────────────────────────────────────────────────────────────┐%s\n' "$C" "$R"
printf '%s│  BuddyNet — direct mode: no server at all                     │%s\n' "$C" "$R"
printf '%s│  no matchmaking · no token · no third party in the path       │%s\n' "$C" "$R"
printf '%s└──────────────────────────────────────────────────────────────┘%s\n\n' "$C" "$R"
sleep 1.3

say "# 1) Each side prints its identity — you swap these two lines by phone or Signal."
host "you@nas"; typ "buddynet --key id.key identity"
hl "$NASPUB"
sleep 0.5
host "you@laptop"; typ "buddynet --key id.key identity"
hl "$LAPPUB"
echo; sleep 1.2

say "# 2) The reachable side listens on a fixed port. It is told WHO may connect."
host "you@nas"; typ "buddynet --role=buddy --direct --key id.key \\"
printf '       '; typ "--peer-key ${LAPPUB:0:10}… --listen-port 51820 --forward 127.0.0.1:7777"
out "$NASCONN"
echo; sleep 1.2

say "# 3) The other side dials it BY NAME. No server was asked where to look."
host "you@laptop"; typ "buddynet --role=buddy --direct --key id.key \\"
printf '       '; typ "--peer-key ${NASPUB:0:10}… --peer-endpoint localhost:51820 -L 127.0.0.1:9000"
out "$LAPCONN"
echo; sleep 1.0
say "#    (here 'localhost' — in your setup a DynDNS name. It is re-resolved on"
say "#     every attempt, so a changing address needs no reconfiguration.)"
echo; sleep 1.2

say "# The NAS service is now reachable on the laptop, through the tunnel:"
host "you@laptop"; typ "curl http://127.0.0.1:9000"
hl "$BODY"
echo; sleep 1.0

printf '%s  Two machines, two pinned keys, one UDP port.%s\n' "$Y" "$R"
printf '%s  The address only finds your buddy — the KEY decides it is them.%s\n' "$Y" "$R"
sleep 2.5

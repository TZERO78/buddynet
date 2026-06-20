#!/usr/bin/env bash
# BuddyNet — MultiPeer ASCII demo. Record with:
#   asciinema rec -c ./demo.sh --cols 92 --rows 26 --overwrite demo.cast
#
# One hub holds 5 buddy tunnels (bob, alice, steven, markus, sandra) and manages
# them with the self-sovereign `peers` CLI + BuddyDNS, live against the lab. ~24s.
#
# Prereqs: party lab up with the demo name overlay, all 5 paired:
#   ./setup-party.sh
#   docker compose -f docker-compose.yml -f docker-compose.party.yml \
#       -f docker-compose.demo.yml up -d
set -u
cd "$(dirname "$0")"

DC="docker compose -f docker-compose.yml -f docker-compose.party.yml -f docker-compose.demo.yml"
hub() { $DC exec -T party-hub "$@"; }
BN="buddynet --peers-file /peers --known-peers /var/lib/buddynet/known_peers"

mapfile -t KEYS < <(grep -v '^#' party/hub.peers | awk '{print $1}')
SANDRA_KEY=${KEYS[4]}; SANDRA_SHORT=${SANDRA_KEY:0:6}; SANDRA_TOK="party-token-zeta"

# Pre-flight (silent): make sure all five are present so the demo always starts at 5.
hub sh -c "$BN peers add $SANDRA_KEY $SANDRA_TOK" >/dev/null 2>&1

# ── presentation ─────────────────────────────────────────────────────────────
G=$'\033[1;32m'; B=$'\033[1;34m'; D=$'\033[2m'; C=$'\033[1;36m'; Y=$'\033[1;33m'; R=$'\033[0m'
prompt() { printf '%shome%s:%s~%s$ ' "$G" "$R" "$B" "$R"; }
typ() { local s=$1 i; for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; sleep 0.020; done; printf '\n'; }
say() { printf '%s%s%s\n' "$D" "$1" "$R"; sleep 0.8; }
run() { prompt; typ "$1"; shift; "$@"; echo; sleep 1.15; }

clear
printf '%s┌──────────────────────────────────────────────────────────┐%s\n' "$C" "$R"
printf '%s│  BuddyNet — one hub, five buddies  (MultiPeer + BuddyDNS) │%s\n' "$C" "$R"
printf '%s└──────────────────────────────────────────────────────────┘%s\n\n' "$C" "$R"
sleep 1.3

say "# who is this node tunneled to? (one hub, five pinned buddies)"
run "buddynet peers list" hub sh -c "$BN peers list"

say "# reach a buddy by name — BuddyDNS resolves *.buddy → its virtual IP"
run "dig +short bob.buddy @127.0.0.153" hub dig +short @127.0.0.153 bob.buddy
run "curl http://sandra.buddy:8080" hub sh -c 'curl -s --max-time 4 --resolve sandra.buddy:8080:$(dig +short @127.0.0.153 sandra.buddy) http://sandra.buddy:8080'

say "# I no longer trust sandra — revoke her by her KEY (drops manifest + session)"
run "buddynet peers remove $SANDRA_SHORT" hub sh -c "$BN peers remove $SANDRA_SHORT"
run "kill -HUP \$(pidof buddynet)   # live reload, no restart" hub sh -c 'kill -HUP $(pidof buddynet)'
sleep 2.1

say "# sandra is gone — the other four keep tunneling, untouched"
run "buddynet peers list" hub sh -c "$BN peers list"

say "# changed my mind — invite her back (pinned key + one-time token)"
run "buddynet peers add <sandra-key> <token>" hub sh -c "$BN peers add $SANDRA_KEY $SANDRA_TOK >/dev/null && echo 'added buddy sandra (pinned key + bootstrap token)'"
run "kill -HUP \$(pidof buddynet)   # reload → her worker restarts and re-pairs" hub sh -c 'kill -HUP $(pidof buddynet)'

printf '\n%s  self-sovereign: throw one buddy out, invite them back — no central authority.%s\n' "$Y" "$R"
sleep 2.1

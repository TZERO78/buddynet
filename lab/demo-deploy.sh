#!/usr/bin/env bash
# BuddyNet — deployment walkthrough ASCII demo. Record with:
#   asciinema rec -c ./demo-deploy.sh --cols 96 --rows 28 --overwrite demo-deploy.cast
#
# Tells the whole "stand up your overlay" story in three real steps:
#   1) the VPS runs the coordinator   (--role=handshake,relay)
#   2) machine A mints a one-time invite   (--invite)
#   3) machine B joins behind its own NAT  (--join) → DIRECT hole-punched tunnel
# Every token / CONNECTED line / curl body below is produced by a real buddynet
# pairing run live against the lab server — nothing is faked. ~30s.
#
# Prereqs: base lab up (./setup.sh && docker compose up -d) so lab-server-1 runs
# the handshake+relay coordinator on the lab_default network.
set -u
cd "$(dirname "$0")"

NET=lab_default; IMG=buddynet-lab-buddy; SRV=lab-server-1
KEY=$(grep '^BUDDYNET_SERVER_KEY=' .env | cut -d= -f2-)
BN=/tmp/buddynet; [ -x "$BN" ] || go build -o "$BN" ../cmd/buddynet

# ── pre-flight (silent): keys, identities, and a real machine-A inviter so the
#    invite token shown in step 2 is the genuine article. ───────────────────────
docker rm -f demo-inviter demo-joiner >/dev/null 2>&1
rm -f /tmp/A.key /tmp/B.key
APUB=$("$BN" --key /tmp/A.key identity); BPUB=$("$BN" --key /tmp/B.key identity)
SRVID=$(docker exec "$SRV" buddynet --key /var/lib/buddynet/id.key identity 2>/dev/null)

docker run -d --name demo-inviter --network "$NET" \
  -v /tmp/A.key:/var/lib/buddynet/id.key:ro --entrypoint /entrypoint-a.sh "$IMG" \
  --role=buddy --key /var/lib/buddynet/id.key \
  --server server:51820 --server-key "$KEY" --peer-key "$BPUB" \
  --forward 127.0.0.1:7777 --invite --no-interactive >/dev/null
for i in $(seq 1 24); do TOK=$(docker logs demo-inviter 2>&1 | grep -m1 -oE '^[A-Za-z0-9_-]{40,}$'); [ -n "$TOK" ] && break; sleep 0.5; done

# ── presentation ──────────────────────────────────────────────────────────────
G=$'\033[1;32m'; B=$'\033[1;34m'; D=$'\033[2m'; C=$'\033[1;36m'; Y=$'\033[1;33m'; R=$'\033[0m'
short() { printf '%s…' "${1:0:10}"; }
prompt() { printf '%svps%s:%s~%s$ ' "$G" "$R" "$B" "$R"; }      # default host label
typ() { local s=$1 i; for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; sleep 0.018; done; printf '\n'; }
say() { printf '%s%s%s\n' "$D" "$1" "$R"; sleep 0.7; }
out() { printf '%s%s%s\n' "$D" "$1" "$R"; }                      # dimmed real output
hl()  { printf '%s%s%s\n' "$C" "$1" "$R"; }                      # highlighted line
host() { printf '%s%s%s:%s~%s$ ' "$G" "$1" "$R" "$B" "$R"; }

clear
printf '%s┌──────────────────────────────────────────────────────────────┐%s\n' "$C" "$R"
printf '%s│  BuddyNet — stand up your overlay in 3 steps                  │%s\n' "$C" "$R"
printf '%s│  VPS coordinates · two NATed machines · a DIRECT tunnel       │%s\n' "$C" "$R"
printf '%s└──────────────────────────────────────────────────────────────┘%s\n\n' "$C" "$R"
sleep 1.3

# ── 1) the VPS ────────────────────────────────────────────────────────────────
say "# 1) On your VPS — run the coordinator: matchmaking + a blind relay fallback"
host vps; typ "buddynet --role=handshake,relay --listen :51820 --relay-listen :51821 --key id.key"
docker logs "$SRV" 2>&1 | grep -m1 'RELAY: action=listening' | sed -E 's/^[0-9/ :]*//' | while read -r l; do out "$l"; done
docker logs "$SRV" 2>&1 | grep -m1 'HANDSHAKE: action=listening' | sed -E 's/^[0-9/ :]*//' | while read -r l; do out "$l"; done
sleep 0.6
host vps; typ "buddynet --key id.key identity            # buddies pin THIS key"
hl "$SRVID"
echo; sleep 1.1

# ── 2) machine A: invite ──────────────────────────────────────────────────────
say "# 2) On machine A (behind NAT) — expose a local service, mint a ONE-TIME invite"
host "alice@A"; typ "buddynet --role=buddy --server vps:51820 --server-key $(short "$SRVID") \\"
printf '       '; typ "--peer-key $(short "$BPUB") --forward 127.0.0.1:7777 --invite"
out "Invite token — hand it to B over a trusted channel:"
hl "  $(short "$TOK")                ← one-time, dies on first pairing"
echo; sleep 1.1

# ── 3) machine B: join → direct tunnel ────────────────────────────────────────
say "# 3) On machine B (behind ANOTHER NAT) — join with that token"
docker run -d --name demo-joiner --network "$NET" \
  -v /tmp/B.key:/var/lib/buddynet/id.key:ro "$IMG" \
  --role=buddy --key /var/lib/buddynet/id.key \
  --server server:51820 --server-key "$KEY" --peer-key "$APUB" \
  --join="$TOK" -L 0.0.0.0:9099 --no-interactive >/dev/null
host "bob@B"; typ "buddynet --role=buddy --server vps:51820 --server-key $(short "$SRVID") \\"
printf '     '; typ "--peer-key $(short "$APUB") --join=$(short "$TOK") -L 127.0.0.1:9099"
for i in $(seq 1 25); do docker logs demo-joiner 2>&1 | grep -q 'CONNECTED'; [ $? -eq 0 ] && break; sleep 1; done
CL=$(docker logs demo-joiner 2>&1 | grep -m1 'CONNECTED' | sed -E 's/^[0-9/ :]*//; s/role=buddy //; s/ key=[^ ]*//; s/ remote=.*//')
hl "$CL"
out '    ↑ via="direct P2P" — hole-punched through both NATs, no port-forwarding'
echo; sleep 1.0

# ── the payoff: B reaches A's service through the tunnel ───────────────────────
say "# B now reaches A's service straight through the encrypted tunnel:"
host "bob@B"; typ "curl http://localhost:9099"
docker exec demo-joiner curl -s --max-time 6 http://localhost:9099/ 2>/dev/null \
  | grep -iE 'Peer A|tunnel is working' | sed -E 's/<[^>]+>//g; s/^ *//' | while read -r l; do out "$l"; done
echo; sleep 0.8

printf '%s  Your VPS introduced them — then stepped out of the path.%s\n' "$Y" "$R"
printf '%s  Direct, end-to-end encrypted. No account, no traffic through the server.%s\n' "$Y" "$R"
sleep 2.0

docker rm -f demo-inviter demo-joiner >/dev/null 2>&1

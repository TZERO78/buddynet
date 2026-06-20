#!/usr/bin/env bash
# BuddyNet Lab — BuddyParty setup (Phase 1.4: multi-peer, 3–5 buddies)
#
# Builds the party image, bootstraps an identity key for the hub and each buddy
# (persisted in Docker volumes), then writes each node's --peers-file manifest
# with the OTHER nodes' pinned keys + a shared per-pair bootstrap token, and
# starts the stack. Safe to re-run: keys persist, so identities/manifests match.
#
# The buddy set is the BUDDIES list below (defaults to 5). To run with fewer,
# trim BUDDIES *and* remove the matching party-<name> services from
# docker-compose.party.yml.
set -euo pipefail
cd "$(dirname "$0")"

BUDDIES=(beta gamma delta epsilon zeta)

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.party.yml"

echo "==> Building party image..."
$COMPOSE build >/dev/null

# Placeholder manifests FIRST, so the compose bind-mounts resolve to files (not
# auto-created directories) during the key-extraction runs below.
mkdir -p party
touch party/hub.peers
for b in "${BUDDIES[@]}"; do touch "party/${b}.peers"; done

echo "==> Bootstrapping server identity..."
SERVER_KEY=$(docker compose -f docker-compose.yml run --rm \
    server --key /var/lib/buddynet/id.key identity 2>/dev/null | tr -d '\r' | tail -1)
echo "BUDDYNET_SERVER_KEY=${SERVER_KEY}" > .env
echo "    server: ${SERVER_KEY}"

# Extract a node's public key (generates it on first run). The entrypoint is
# overridden to the bare binary so the service entrypoints (httpd) don't run.
keyof() {
    $COMPOSE run --rm --entrypoint /usr/local/bin/buddynet "$1" \
        --key /var/lib/buddynet/id.key identity 2>/dev/null | tr -d '\r' | tail -1
}

echo "==> Bootstrapping node identities (${#BUDDIES[@]} buddies + hub)..."
HUB=$(keyof party-hub)
echo "    hub:   ${HUB}"
declare -A KEY
for b in "${BUDDIES[@]}"; do
    KEY[$b]=$(keyof "party-${b}")
    echo "    ${b}: ${KEY[$b]}"
    if [ -z "${KEY[$b]}" ]; then
        echo "ERROR: failed to extract key for ${b} — check the build" >&2
        exit 1
    fi
done
[ -n "$HUB" ] || { echo "ERROR: failed to extract hub key" >&2; exit 1; }

echo "==> Writing manifests (Model A: each peer pinned by key)..."
# hub talks to every buddy; each buddy talks only to the hub. The per-pair token
# is shared between the hub line and that buddy's line.
echo "# hub's buddies — one tunnel each" > party/hub.peers
for b in "${BUDDIES[@]}"; do
    tok="party-token-${b}"
    echo "${KEY[$b]} ${tok}" >> party/hub.peers
    echo "${HUB} ${tok}" > "party/${b}.peers"
done
chmod 600 party/*.peers

echo "==> Starting the party (${#BUDDIES[@]} buddies)..."
$COMPOSE up -d

echo ""
echo "════════════════════════════════════════════"
echo "  BuddyParty is up — test with ./test-party.sh"
echo "════════════════════════════════════════════"

#!/usr/bin/env bash
# BuddyNet Lab — one-time setup script
#
# Builds the images, bootstraps the handshake server identity, writes .env,
# and starts all three containers. Safe to re-run: the server key persists in
# a Docker volume so the same public key is reused on subsequent runs.
set -euo pipefail

cd "$(dirname "$0")"

echo "════════════════════════════════════════════"
echo "  BuddyNet Lab Setup"
echo "════════════════════════════════════════════"
echo ""

# ── 1. Build images ────────────────────────────────────────────────────────
echo "==> Building images (this takes a minute on first run)..."
docker compose build
echo ""

# ── 2. Bootstrap server identity ─────────────────────────────────────────
# Runs the server image with the persistent 'server-key' volume attached.
# On first run: generates an Ed25519 key and saves it to the volume.
# On subsequent runs: reads the existing key from the volume.
# The 'identity' subcommand prints the base64 public key and exits.
echo "==> Bootstrapping server identity..."
SERVER_KEY=$(docker compose run --rm server \
    --key /var/lib/buddynet/id.key identity 2>/dev/null)

if [ -z "$SERVER_KEY" ]; then
    echo ""
    echo "ERROR: Could not retrieve server public key." >&2
    echo "       Check that the server image built correctly." >&2
    exit 1
fi

echo "==> Server public key: ${SERVER_KEY}"
echo ""

# ── 3. Write .env ─────────────────────────────────────────────────────────
echo "BUDDYNET_SERVER_KEY=${SERVER_KEY}" > .env
echo "==> Wrote .env"
echo ""

# ── 4. Start everything ───────────────────────────────────────────────────
echo "==> Starting all containers..."
docker compose up -d
echo ""

echo "════════════════════════════════════════════"
echo "  Lab is running — follow logs or test now"
echo "════════════════════════════════════════════"
echo ""
echo "  Follow logs:   docker compose -f lab/docker-compose.yml logs -f"
echo "  Test tunnel:   curl http://localhost:7070   (wait ~5 s for tunnel)"
echo "  Tear down:     docker compose -f lab/docker-compose.yml down -v"
echo ""
echo "  See lab/README.md for the full walkthrough."
echo ""

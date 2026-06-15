#!/bin/sh
# kopia-a: backup source — generates test data, waits for kopia-b's SSH host
# key, builds known_hosts, then runs buddynet with -L so kopia can reach
# kopia-b's SFTP through the tunnel on 127.0.0.1:2222.
set -e

SOURCE=/data/source
mkdir -p "$SOURCE"

# Generate test data once (idempotent).
if [ ! -f "$SOURCE/blob-01.dat" ]; then
    echo "[kopia-a] generating source data..."
    for i in $(seq 1 20); do
        dd if=/dev/urandom bs=128k count=1 2>/dev/null \
            > "$SOURCE/blob-$(printf '%02d' $i).dat"
    done
    for i in $(seq 1 10); do
        printf "config entry %d\n" "$i" > "$SOURCE/config-$(printf '%02d' $i).txt"
    done
fi
echo "[kopia-a] source: $(du -sh $SOURCE | cut -f1) in $(ls $SOURCE | wc -l) files"

# Wait for kopia-b to publish its SSH host key via the shared volume.
for i in $(seq 1 40); do
    [ -f /data/kopia-b-hostkey.pub ] && break
    sleep 0.5
done
if [ ! -f /data/kopia-b-hostkey.pub ]; then
    echo "[kopia-a] WARNING: kopia-b host key not found — known_hosts will be empty"
else
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    # known_hosts entry: [host]:port <keytype> <pubkey>  (strip trailing comment)
    PUBKEY=$(awk '{print $1, $2}' /data/kopia-b-hostkey.pub)
    echo "[127.0.0.1]:2222 $PUBKEY" > /root/.ssh/known_hosts
    chmod 600 /root/.ssh/known_hosts
    echo "[kopia-a] known_hosts set for kopia-b SFTP"
fi

exec /usr/local/bin/buddynet "$@"

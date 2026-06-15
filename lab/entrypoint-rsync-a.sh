#!/bin/sh
# rsync-a entrypoint: start an rsync daemon exposing /data/share, then hand
# off to buddynet so the daemon is reachable from rsync-b through the tunnel.
set -e

DATA=/data/share
mkdir -p "$DATA"

# Populate with deterministic test data so the transfer is meaningful.
for i in $(seq 1 20); do
    dd if=/dev/urandom bs=64k count=1 2>/dev/null | base64 > "$DATA/file-$(printf '%02d' $i).dat"
done
echo "rsync test tree ready: $(du -sh $DATA | cut -f1) in $(ls $DATA | wc -l) files"

cat > /tmp/rsyncd.conf << 'CONF'
[share]
    path = /data/share
    read only = no
    list = yes
    uid = root
    gid = root
    use chroot = no
CONF

rsync --daemon --no-detach --config=/tmp/rsyncd.conf --port=873 &
echo "[rsync-a] rsync daemon started on :873"

exec /usr/local/bin/buddynet "$@"

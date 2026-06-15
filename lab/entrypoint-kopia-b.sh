#!/bin/sh
# kopia-b: backup target — SFTP-only SSH server with password auth (lab only).
set -e

REPO=/data/repo
mkdir -p "$REPO"

# SSH host key — persisted in the buddynet-key volume so it survives restarts
# and kopia-a's known_hosts stays valid without a new keyscan.
KEYDIR=/var/lib/buddynet/ssh
mkdir -p "$KEYDIR"
[ -f "$KEYDIR/ssh_host_ed25519_key" ] || \
    ssh-keygen -q -N "" -t ed25519 -f "$KEYDIR/ssh_host_ed25519_key"

# Publish public key to the shared volume so kopia-a can build known_hosts.
cat "$KEYDIR/ssh_host_ed25519_key.pub" > /data/kopia-b-hostkey.pub
echo "[kopia-b] host key published to /data/kopia-b-hostkey.pub"

# kopia user with a simple lab password (no SSH client key needed).
adduser -D -h "$REPO" -s /bin/sh kopia 2>/dev/null || true
printf 'kopia:labpass\n' | chpasswd 2>/dev/null || \
    echo "kopia:labpass" | chpasswd

cat > /tmp/sshd_config << 'EOF'
Port 22
HostKey /var/lib/buddynet/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
UsePAM no
PubkeyAuthentication no
AuthorizedKeysFile none
Subsystem sftp internal-sftp
EOF

/usr/sbin/sshd -f /tmp/sshd_config &
sleep 1
echo "[kopia-b] sshd on :22 ready — SFTP repo at $REPO (user=kopia pass=labpass)"

exec /usr/local/bin/buddynet "$@"

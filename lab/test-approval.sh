#!/usr/bin/env bash
# Live test of APPROVAL MODE and code-based ENROLLMENT against the real binary,
# on loopback — no Docker, no root.
#
# This is the flow that was broken: over the default QUIC control plane the TLS
# handshake refused any key that was not already on the allowlist, so an enrolling
# client could never deliver its --code and the operator could never approve it.
# It also pins the surrounding fail-closed behaviour: a missing allowlist means
# ZERO authorized clients, deleting the file at runtime revokes everyone, and an
# approved client starts pairing on its next attempt with no restart.
#
# Usage: lab/test-approval.sh [path-to-buddynet]
set -uo pipefail

BIN=${1:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "$BIN" ]; then
	BIN=$(mktemp -d)/buddynet
	echo "building $BIN"
	go build -o "$BIN" "$ROOT/cmd/buddynet" || exit 1
fi

DIR=$(mktemp -d)
PORT=$(( (RANDOM % 20000) + 40000 ))
ALLOW="$DIR/authorized_clients"
PIDS=()
PASS=0
FAIL=0

cleanup() {
	for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$DIR"
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n== %s ==\n' "$1"; }

# waitlog PATTERN FILE SECONDS — wait for PATTERN to appear in FILE.
waitlog() {
	local pat=$1 file=$2 secs=$3 i
	for ((i=0; i<secs*10; i++)); do
		grep -qE "$pat" "$file" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

step "handshake server, approval mode, NO allowlist file yet"
# The identity is created EXPLICITLY before the server runs: a server never mints
# one, so that a lost key surfaces as a refusal instead of a new identity nobody
# has pinned.
SRVKEY=$("$BIN" --role=handshake --key "$DIR/srv.key" init | tr -d '[:space:]')
[ -n "$SRVKEY" ] && ok "server identity created explicitly with init" || bad "init produced no identity"
"$BIN" --role=handshake --key "$DIR/srv.key" --listen "127.0.0.1:$PORT" \
	--authorized "$ALLOW" >"$DIR/srv.log" 2>&1 &
PIDS+=($!)
waitlog "action=listening" "$DIR/srv.log" 10 || { echo "server did not start"; cat "$DIR/srv.log"; exit 1; }

# Fail-closed must be stated at startup, not left as a silent surprise.
if grep -q "approval mode ON" "$DIR/srv.log" && grep -qi "NO client can pair yet" "$DIR/srv.log"; then
	ok "a missing allowlist starts fail-closed and says so"
else
	bad "a missing allowlist did not warn that nobody can pair"
	sed -n 1,10p "$DIR/srv.log"
fi
if grep -q "approval mode OFF" "$DIR/srv.log"; then
	bad "a missing allowlist fell back to OPEN mode"
else
	ok "a missing allowlist did not enable open mode"
fi

# A server must never invent an identity: with the key removed it refuses to
# start rather than coming up as a DIFFERENT server to every buddy that pinned it.
mv "$DIR/srv.key" "$DIR/srv.key.bak"
if "$BIN" --role=handshake --key "$DIR/srv.key" --listen "127.0.0.1:$((PORT+9))" >"$DIR/nokey.log" 2>&1; then
	bad "the server started WITHOUT an identity key"
else
	if grep -q "init" "$DIR/nokey.log"; then
		ok "a missing identity refuses to start and names the init command"
	else
		bad "the refusal does not tell the operator what to do: $(head -1 "$DIR/nokey.log")"
	fi
fi
[ -e "$DIR/srv.key" ] && bad "the refused start created a key anyway" || ok "the refused start created no identity"
mv "$DIR/srv.key.bak" "$DIR/srv.key"

# --- two buddies enroll with a code -----------------------------------------
ECHO_PORT=$(( PORT + 1 ))
LOCAL_PORT=$(( PORT + 2 ))
CODE_A="ENROLL-AAAA-$RANDOM"
CODE_B="ENROLL-BBBB-$RANDOM"
TOKEN="live-token-$RANDOM"

# A trivial TCP service for A to expose through the tunnel: it greets and closes.
( while true; do
	nc -l 127.0.0.1 "$ECHO_PORT" -q0 <<<"BUDDYNET-LIVE-OK" >/dev/null 2>&1
	sleep 0.1
  done ) &
PIDS+=($!)

# Create both buddy identities up front so each can PIN the other with
# --peer-key: this test is about the control plane, and pinning keeps the SAS
# (which needs a human) out of the picture without resorting to --lab.
KEY_A=$("$BIN" --role=buddy --key "$DIR/a.key" init | tr -d '[:space:]')
KEY_B=$("$BIN" --role=buddy --key "$DIR/b.key" init | tr -d '[:space:]')
if [ -n "$KEY_A" ] && [ -n "$KEY_B" ] && [ "$KEY_A" != "$KEY_B" ]; then
	ok "both buddy identities created"
else
	bad "could not create two distinct buddy identities"
	exit 1
fi

start_buddy() { # name code peer-key extra-args...
	local name=$1 code=$2 peerkey=$3; shift 3
	"$BIN" --role=buddy --server "127.0.0.1:$PORT" --server-key "$SRVKEY" \
		--key "$DIR/$name.key" --join "$TOKEN" --code "$code" \
		--peer-key "$peerkey" --peers "$DIR/$name-peers.json" \
		--known-peers "$DIR/$name-known_peers" \
		--reauth-interval 10s "$@" >"$DIR/$name.log" 2>&1 &
	PIDS+=($!)
}

step "un-approved buddies register with --code"
start_buddy a "$CODE_A" "$KEY_B" -forward "127.0.0.1:$ECHO_PORT"
start_buddy b "$CODE_B" "$KEY_A" -L "127.0.0.1:$LOCAL_PORT"

if waitlog "AUTHZ: action=pending" "$DIR/srv.log" 20; then
	ok "an un-approved client's enrollment code REACHED the server (this was broken)"
else
	bad "no pending enrollment — the code never reached the application layer"
	tail -5 "$DIR/srv.log"
fi
if grep -qE "code=[0-9a-f]{8}" "$DIR/srv.log"; then
	ok "the pending line carries a hashed code tag"
else
	bad "no hashed code tag in the pending line"
fi
if grep -q "$CODE_A" "$DIR/srv.log" || grep -q "$CODE_B" "$DIR/srv.log"; then
	bad "the CLEARTEXT enrollment code leaked into the server log"
else
	ok "no cleartext enrollment code in the server log"
fi
if grep -q "PAIRED" "$DIR/srv.log"; then
	bad "un-approved clients PAIRED — approval mode is not gating"
else
	ok "un-approved clients did not pair"
fi

step "the server keeps NO runtime state on disk (v5.0.0)"
if [ -e "$ALLOW.pending" ]; then
	bad "the server wrote $ALLOW.pending — pending enrolments must live in memory only"
else
	ok "no pending file: the control server keeps no runtime database"
fi
if "$BIN" --authorized "$ALLOW" allowclient "$CODE_A" >>"$DIR/admin.log" 2>&1; then
	bad "allowclient still succeeds — it was removed in v5.0.0"
else
	if grep -q "approve <CLIENT-PUBKEY>" "$DIR/admin.log"; then
		ok "allowclient refuses with an actionable message pointing at approve"
	else
		bad "allowclient failed without telling the operator what to do instead"
	fi
fi

step "operator approves both KEYS from the log line (server keeps running)"
# The log line is the only route now, so take the keys from it exactly as an
# operator would: AUTHZ: action=pending key=… — approve with: … approve <KEY>
PKEY_A=$(grep -o "approve [A-Za-z0-9+/=]\{40,\}" "$DIR/srv.log" | awk '{print $2}' | sed -n 1p)
PKEY_B=$(grep -o "approve [A-Za-z0-9+/=]\{40,\}" "$DIR/srv.log" | awk '{print $2}' | sed -n 2p)
if [ -z "$PKEY_A" ] || [ -z "$PKEY_B" ]; then
	bad "could not read the client keys from the server log — the approve hint is unusable"
else
	ok "the log line carries a ready-to-run approve command for each client"
fi
"$BIN" --authorized "$ALLOW" approve "$PKEY_A" >>"$DIR/admin.log" 2>&1 || bad "approve A failed"
"$BIN" --authorized "$ALLOW" approve "$PKEY_B" >>"$DIR/admin.log" 2>&1 || bad "approve B failed"
if [ "$(grep -c . "$ALLOW")" = "2" ]; then
	ok "both keys are on the allowlist"
else
	bad "allowlist holds $(grep -c . "$ALLOW") entries, want 2"
fi
if grep -qE "$CODE_A|$CODE_B" "$ALLOW"; then
	bad "the cleartext code was written into the allowlist"
else
	ok "the allowlist holds no cleartext enrollment code"
fi

step "the SAME running clients now pair — no restart"
if waitlog "PAIRED" "$DIR/srv.log" 30; then
	ok "approved clients paired on their next attempt, with no restart"
else
	bad "approved clients never paired"
	tail -8 "$DIR/srv.log"; tail -5 "$DIR/a.log"; tail -5 "$DIR/b.log"
fi
if waitlog "CONNECTED" "$DIR/a.log" 30 && waitlog "CONNECTED" "$DIR/b.log" 30; then
	ok "the tunnel came up on both ends"
else
	bad "the tunnel did not come up"
	tail -8 "$DIR/a.log"; tail -8 "$DIR/b.log"
fi

step "data flows through the tunnel"
GOT=$(timeout 10 nc 127.0.0.1 "$LOCAL_PORT" -q1 </dev/null 2>/dev/null | tr -d '\r\n')
if [ "$GOT" = "BUDDYNET-LIVE-OK" ]; then
	ok "payload echoed through the tunnel"
else
	bad "no payload through the tunnel (got: '${GOT:-<nothing>}')"
fi

step "no replay false-positives while polling"
if grep -q "event=replay-detected" "$DIR/srv.log"; then
	bad "normal polling was flagged as a replay"
	grep "replay-detected" "$DIR/srv.log" | head -3
else
	ok "repeated registrations were never mistaken for replays"
fi

step "deleting the allowlist revokes everyone"
rm -f "$ALLOW"
if waitlog "no longer exists" "$DIR/srv.log" 15; then
	ok "the server noticed the allowlist disappearing and warned"
else
	bad "deleting the allowlist went unnoticed"
	tail -5 "$DIR/srv.log"
fi
BEFORE=$(grep -c "PAIRED" "$DIR/srv.log")
# --reauth-interval tears the tunnels down, so the buddies must re-pair; with no
# allowlist they must NOT succeed.
sleep 18
AFTER=$(grep -c "PAIRED" "$DIR/srv.log")
if [ "$AFTER" -eq "$BEFORE" ]; then
	ok "no new pairing after the allowlist was deleted (fail-closed)"
else
	bad "clients kept pairing after the allowlist was deleted ($BEFORE -> $AFTER)"
fi
WARNS=$(grep -c "no longer exists" "$DIR/srv.log")
if [ "$WARNS" -le 2 ]; then
	ok "the missing-allowlist warning did not repeat per poll ($WARNS line(s))"
else
	bad "the warning repeated $WARNS times — it would fill the disk"
fi

printf '\n== result: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

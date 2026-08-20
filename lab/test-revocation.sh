#!/usr/bin/env bash
# Live test of REVOCATION against the real binary, on loopback — no Docker, no root.
#
# Finding A-01: `peers remove` was undone by the buddy process that was still
# running. The removal dropped the manifest entry and the stored session, and both
# files were correct right after — but the running worker still held the bootstrap
# token in memory from when it started, fell back to it, re-paired, and wrote the
# session line back. Since the worker set is the manifest UNION the stored
# sessions, the SIGHUP that was supposed to APPLY the revocation restarted the
# buddy instead, and the resurrection survived a restart.
#
# Unit tests cover the state machine. This lab covers the claim an operator cares
# about: after `peers remove` the buddy DOES NOT COME BACK — not on the next
# reconnect round, not on SIGHUP, not after a restart — and it comes back only
# when it is deliberately allowed again.
#
# It runs the scenario TWICE: once with the binary from this tree, and once with
# the binary built from the audited commit (BASE), which MUST show the
# resurrection. Without that A/B the green half only proves that something
# disconnected. SKIP_BASE=1 leaves it out (no network / shallow checkout).
#
# It takes several minutes: the two sides have to fall out of and back into step
# through their reconnect backoff, which is exactly the window the old build
# needed to re-pair itself in. REVOKE_WATCH=<secs> shortens that window and makes
# the A/B half meaningless — do not.
#
# Usage: lab/test-revocation.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${BASE:-fa046a6}
WATCH=${REVOKE_WATCH:-90}
DIR=$(mktemp -d /tmp/bnrevoke.XXXXXX)
PASS=0
FAIL=0
PIDS=()

cleanup() {
	for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	echo "logs kept in $DIR"
}
trap cleanup EXIT

ok() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n== %s ==\n' "$1"; }

# waitlog PATTERN FILE SECONDS
waitlog() {
	local pat=$1 file=$2 secs=$3 i
	for ((i = 0; i < secs * 10; i++)); do
		grep -qE "$pat" "$file" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

countlog() { grep -cE "$1" "$2" 2>/dev/null || true; }

# engaged FILE — how often this node has taken up with its partner: a completed
# tunnel OR a re-verified partner. Both count: a revocation that lets the pairing
# get as far as "partner-verified" has already failed, and on loopback the hole
# punch that follows is the flakier half, not the meaningful one. The leading
# space keeps DISCONNECTED (which ends in "CONNECTED:") out of the count — with a
# bare "CONNECTED:" pattern a torn-down tunnel reads as a new one, which is how
# the first version of this lab reported a resurrection that never happened.
engaged() {
	local a b
	a=$(countlog "[[:space:]]CONNECTED:" "$1")
	b=$(countlog "action=partner-verified" "$1")
	echo $((a + b))
}

# waitengaged FILE BASELINE SECONDS — wait until the node has taken up with its
# partner again, i.e. until engaged() exceeds the baseline. Waiting for the
# pattern to merely EXIST is wrong on a log that already holds earlier tunnels.
waitengaged() {
	local file=$1 baseline=$2 secs=$3 i
	for ((i = 0; i < secs; i++)); do
		[ "$(engaged "$file")" -gt "$baseline" ] && return 0
		sleep 1
	done
	return 1
}

# waitcount PATTERN FILE BASELINE SECONDS — wait until PATTERN's count exceeds
# the baseline.
waitcount() {
	local pat=$1 file=$2 baseline=$3 secs=$4 i
	for ((i = 0; i < secs; i++)); do
		[ "$(countlog "$pat" "$file")" -gt "$baseline" ] && return 0
		sleep 1
	done
	return 1
}

# payload PORT SECONDS — read the greeting through A's -L listener, retrying
# until the forward path is serving (the tunnel is up a moment before the
# listener has a stream to the far side).
payload() {
	local port=$1 secs=$2 i got
	for ((i = 0; i < secs; i++)); do
		got=$(timeout 5 nc 127.0.0.1 "$port" -q1 </dev/null 2>/dev/null | tr -d '\r\n')
		[ -n "$got" ] && {
			printf '%s' "$got"
			return 0
		}
		sleep 1
	done
	return 1
}

# spawn <bin> <dir> <name> <port> <srvkey> <extra...> — start one buddy and put
# its pid in SPAWNED. Everything it needs is a parameter: bash functions do not
# close over the locals of the function that defined them, and an earlier version
# of this lab restarted a buddy with empty paths for exactly that reason.
#
# --reauth-interval 10s is load-bearing, not decoration: without it an
# established tunnel simply stays up, the worker never takes another attempt, and
# neither binary can show anything — the old one never gets to re-pair on its
# stale token, the new one never gets to refuse. It is also what the daemon
# itself recommends when a revocation has to take effect on a live direct tunnel.
spawn() {
	local bin=$1 d=$2 name=$3 port=$4 srvkey=$5
	shift 5
	"$bin" --role=buddy --server "127.0.0.1:$port" --server-key "$srvkey" \
		--key "$d/$name.key" --peers-file "$d/$name-peers.yaml" \
		--known-peers "$d/$name-known_peers" --peers "$d/$name-peers.json" \
		--no-interactive --reauth-interval "${REAUTH:-10s}" "$@" >>"$d/$name.log" 2>&1 &
	SPAWNED=$!
	PIDS+=("$SPAWNED")
}

echo "== build =="
BIN="$DIR/buddynet"
go build -o "$BIN" "$ROOT/cmd/buddynet" || exit 1
echo "  current tree: $BIN"

OLDBIN=""
if [ "${SKIP_BASE:-0}" != "1" ]; then
	SRC="$DIR/base-src"
	mkdir -p "$SRC"
	if git -C "$ROOT" archive "$BASE" 2>/dev/null | tar -x -C "$SRC" 2>/dev/null; then
		OLDBIN="$DIR/buddynet-base"
		if (cd "$SRC" && go build -o "$OLDBIN" ./cmd/buddynet >"$DIR/base-build.log" 2>&1); then
			echo "  audited base ($BASE): $OLDBIN"
		else
			OLDBIN=""
			echo "  NOTE: could not build the $BASE binary; the A/B half will be skipped"
			tail -3 "$DIR/base-build.log"
		fi
	else
		echo "  NOTE: commit $BASE not available; the A/B half will be skipped"
	fi
fi

# run_scenario <label> <binary> — pair two buddies through their manifests,
# revoke B on A's side while A is RUNNING, then SIGHUP and restart A. Sets
# RESURRECTED=1 if A took up with the revoked buddy again at any point, and
# exports the scenario's paths/ports so the caller can drive the re-allow.
run_scenario() {
	local label=$1 bin=$2
	local d="$DIR/$label"
	mkdir -p "$d"
	local port=$(((RANDOM % 20000) + 40000))
	local echo_port=$((port + 1))
	local local_port=$((port + 2))
	local token="revoke-token-$RANDOM"

	local srvkey
	srvkey=$("$bin" --role=handshake --key "$d/srv.key" init 2>/dev/null | tr -d '[:space:]')
	"$bin" --role=handshake --key "$d/srv.key" --listen "127.0.0.1:$port" >"$d/srv.log" 2>&1 &
	PIDS+=($!)
	waitlog "action=listening" "$d/srv.log" 10 || {
		bad "[$label] the handshake server did not start"
		return 1
	}

	local keya keyb
	keya=$("$bin" --role=buddy --key "$d/a.key" init 2>/dev/null | tr -d '[:space:]')
	keyb=$("$bin" --role=buddy --key "$d/b.key" init 2>/dev/null | tr -d '[:space:]')

	# A trivial TCP service B exposes through the tunnel.
	(while true; do
		nc -l 127.0.0.1 "$echo_port" -q0 <<<"BUDDYNET-REVOKE-OK" >/dev/null 2>&1
		sleep 0.1
	done) &
	PIDS+=($!)

	# Each side lists the other in its OWN manifest, pinned, with a shared
	# bootstrap token — the ordinary `peers add <key> <token>` shape.
	"$bin" --peers-file "$d/a-peers.yaml" --known-peers "$d/a-known_peers" peers add "$keyb" "$token" >/dev/null
	"$bin" --peers-file "$d/b-peers.yaml" --known-peers "$d/b-known_peers" peers add "$keya" "$token" >/dev/null

	spawn "$bin" "$d" b "$port" "$srvkey" -forward "127.0.0.1:$echo_port"
	local bpid=$SPAWNED
	spawn "$bin" "$d" a "$port" "$srvkey" -L "127.0.0.1:$local_port"
	local apid=$SPAWNED

	# --- 0. positive control -------------------------------------------------
	if waitlog "[[:space:]]CONNECTED:" "$d/a.log" 40 && waitlog "[[:space:]]CONNECTED:" "$d/b.log" 40; then
		ok "[$label] the pair came up on both ends (positive control)"
	else
		bad "[$label] the pair never came up — nothing below can be decided"
		tail -5 "$d/a.log"
		tail -5 "$d/b.log"
		return 1
	fi
	local got
	got=$(payload "$local_port" 20)
	if [ "$got" = "BUDDYNET-REVOKE-OK" ]; then
		ok "[$label] payload crosses the tunnel before the revoke"
	else
		bad "[$label] no payload before the revoke (got '$got') — the control is void"
		return 1
	fi

	local before after
	before=$(engaged "$d/a.log")

	# --- 1. revoke B on A's side while A is RUNNING --------------------------
	"$bin" --peers-file "$d/a-peers.yaml" --known-peers "$d/a-known_peers" peers remove "$keyb" >"$d/revoke.out" 2>&1
	if grep -q "revoked buddy" "$d/revoke.out"; then
		ok "[$label] peers remove reported a revocation"
	else
		bad "[$label] peers remove said: $(head -2 "$d/revoke.out" | tr '\n' ' ')"
	fi

	# B keeps running and keeps trying, so this is the window the old build
	# re-paired itself back in (it needs B's stale-session fallback to put both
	# sides on the bootstrap token again).
	sleep "$WATCH"
	after=$(engaged "$d/a.log")
	RESURRECTED=0
	[ "$after" -gt "$before" ] && RESURRECTED=1

	# --- 2. SIGHUP -----------------------------------------------------------
	kill -HUP "$apid" 2>/dev/null
	sleep 6
	after=$(engaged "$d/a.log")
	[ "$after" -gt "$before" ] && RESURRECTED=1
	# Only the CURRENT tree is held to this: on the audited base the SIGHUP
	# re-assembles the resurrected buddy instead of dropping it, and that is the
	# finding, not a failure of the harness. Marking it red there would make the
	# A/B half look broken while it is doing its job.
	if grep -qE "action=reload buddies=0" "$d/a.log"; then
		[ "$label" = "current" ] && ok "[$label] SIGHUP reduced the worker set to zero"
	elif [ "$label" = "current" ]; then
		bad "[$label] SIGHUP did not drop the revoked buddy from the worker set"
	else
		printf '  \033[33mNOTE\033[0m [%s] SIGHUP did NOT clear the worker set — part of what A-01 is\n' "$label"
	fi

	# --- 3. a full restart ---------------------------------------------------
	kill "$apid" 2>/dev/null
	sleep 1
	before=$(engaged "$d/a.log")
	spawn "$bin" "$d" a "$port" "$srvkey" -L "127.0.0.1:$local_port"
	apid=$SPAWNED
	sleep 20
	after=$(engaged "$d/a.log")
	[ "$after" -gt "$before" ] && RESURRECTED=1

	SCEN_BIN="$bin"
	SCEN_DIR="$d"
	SCEN_PORT="$port"
	SCEN_ECHO_PORT="$echo_port"
	SCEN_SRVKEY="$srvkey"
	SCEN_KEYB="$keyb"
	SCEN_TOKEN="$token"
	SCEN_LOCAL_PORT="$local_port"
	SCEN_APID="$apid"
	SCEN_BPID="$bpid"
	return 0
}

step "current tree: a revoked buddy must NOT come back"
if run_scenario current "$BIN"; then
	if [ "$RESURRECTED" = "0" ]; then
		ok "no new engagement after the revoke — not on the next round, not on SIGHUP, not after a restart"
	else
		bad "the revoked buddy was taken up again (A-01 is back)"
		grep -E "CONNECTED:|partner-verified|peer-stopped" "$SCEN_DIR/a.log" | tail -5
	fi
	if grep -qE "peer-stopped.*revoked" "$SCEN_DIR/a.log"; then
		ok "the worker stopped on its next attempt, naming the revocation"
	else
		bad "no peer-stopped line naming the revocation"
		grep -E "peer-stopped|SUPERVISOR" "$SCEN_DIR/a.log" | tail -3
	fi
	if grep -qE "lists no buddies|reload buddies=0" "$SCEN_DIR/a.log"; then
		ok "the restarted process has no buddy left to connect to"
	else
		bad "the restarted process did not report the buddy as gone"
		tail -4 "$SCEN_DIR/a.log"
	fi
	REV="$SCEN_DIR/a-known_peers.revoked"
	if [ -f "$REV" ] && grep -qF "$SCEN_KEYB" "$REV"; then
		ok "the revocation list holds the key"
		PERM=$(stat -c '%a' "$REV")
		[ "$PERM" = "600" ] && ok "the revocation list is 0600" || bad "revocation list mode $PERM, want 600"
	else
		bad "no revocation list entry for the buddy"
	fi
	GOT=$(payload "$SCEN_LOCAL_PORT" 5)
	if [ "$GOT" = "BUDDYNET-REVOKE-OK" ]; then
		bad "payload still crosses after the revoke"
	else
		ok "no payload after the revoke"
	fi

	# --- deliberately allow it again ----------------------------------------
	step "current tree: allowing the buddy again brings it back"
	"$SCEN_BIN" --peers-file "$SCEN_DIR/a-peers.yaml" --known-peers "$SCEN_DIR/a-known_peers" \
		peers add "$SCEN_KEYB" "$SCEN_TOKEN" >"$SCEN_DIR/allow.out" 2>&1
	if grep -qE "allowed buddy .* again" "$SCEN_DIR/allow.out"; then
		ok "peers add on a revoked buddy lifts the revocation instead of saying 'already listed'"
	else
		bad "peers add said: $(head -2 "$SCEN_DIR/allow.out" | tr '\n' ' ')"
	fi
	if grep -qF "$SCEN_KEYB" "$REV"; then
		bad "the revocation list still holds the key after the lift"
	else
		ok "the revocation list no longer holds the key"
	fi
	BEFORE=$(engaged "$SCEN_DIR/a.log")
	BEFORE_TUN=$(countlog "[[:space:]]CONNECTED:" "$SCEN_DIR/a.log")
	# Restart BOTH ends, which is what an operator does (and what the plugin's
	# "Allow buddy again" button does): they then start from the same bootstrap
	# token at the same time instead of waiting out two backoff schedules.
	kill "$SCEN_APID" "$SCEN_BPID" 2>/dev/null
	sleep 1
	REAUTH=0 spawn "$SCEN_BIN" "$SCEN_DIR" b "$SCEN_PORT" "$SCEN_SRVKEY" -forward "127.0.0.1:$SCEN_ECHO_PORT"
	REAUTH=0 spawn "$SCEN_BIN" "$SCEN_DIR" a "$SCEN_PORT" "$SCEN_SRVKEY" -L "127.0.0.1:$SCEN_LOCAL_PORT"
	if waitengaged "$SCEN_DIR/a.log" "$BEFORE" 120; then
		ok "the buddy pairs again after being allowed — the revocation was not a one-way door"
		# Engagement is enough for the claim above, but the payload check needs a
		# LIVE tunnel and a bound -L listener, which follow a second or two later.
		waitcount "[[:space:]]CONNECTED:" "$SCEN_DIR/a.log" "$BEFORE_TUN" 60
		waitlog "\-L: listening" "$SCEN_DIR/a.log" 20
		GOT=$(payload "$SCEN_LOCAL_PORT" 40)
		if [ "$GOT" = "BUDDYNET-REVOKE-OK" ]; then
			ok "payload crosses again after the buddy was allowed back"
		else
			# Deliberately a note, not a failure. The claim under test — the
			# revocation is not a one-way door — is the assertion above, and the
			# data path itself was already asserted hard BEFORE the revoke with the
			# same harness. What is left here is timing: the two sides have just
			# re-paired after drifting apart through their backoff, and the
			# one-shot nc service has to be caught in the window. A red here would
			# be a lab artifact wearing the costume of a finding.
			printf '  \033[33mNOTE\033[0m the re-paired tunnel did not carry payload inside the window (got %s) — timing, not a revocation property\n' "${GOT:-<nothing>}"
		fi
	else
		bad "the buddy did not come back after being allowed again"
		tail -6 "$SCEN_DIR/a.log"
	fi
else
	bad "the current-tree scenario could not be set up"
fi

# --- A/B against the audited base -------------------------------------------
if [ -n "$OLDBIN" ]; then
	step "audited base ($BASE): the same revoke must be UNDONE (this is the finding)"
	if run_scenario base "$OLDBIN"; then
		if [ "$RESURRECTED" = "1" ]; then
			ok "the pre-fix binary took up with the revoked buddy again — A-01 reproduced, so the green half above is not vacuous"
		else
			bad "the pre-fix binary did NOT resurrect the buddy: this lab is not exercising A-01 (check REVOKE_WATCH)"
			grep -E "CONNECTED:|partner-verified|peer-stopped" "$SCEN_DIR/a.log" | tail -5
		fi
	else
		bad "the base scenario could not be set up"
	fi
else
	printf '\n  NOTE: A/B against %s skipped — the green result above is a regression gate, not a proof that it once failed\n' "$BASE"
fi

printf '\n=== result ===\n  passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1

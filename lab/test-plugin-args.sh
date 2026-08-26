#!/usr/bin/env bash
# What command line does the Unraid plugin actually start?
#
# The plugin builds buddynet's arguments in rc.buddynet, from fields on its
# settings page. Nothing checked that until now — the .plg is validated as XML
# and its shell blocks parse, but neither says anything about WHICH flags come
# out, or whether the daemon accepts them. That gap is exactly how a GIF once
# shipped a headline command that exited 1.
#
# So: extract rc.buddynet from the .plg, point its paths at a scratch dir, put a
# recording stub where the binary goes, and drive `start` with real configs. Then
# feed the recorded arguments to the REAL binary and require that it does not
# reject them as a usage error.
#
# Needs no Unraid, no root, no network. Run from lab/:  ./test-plugin-args.sh
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
PLG="$ROOT/unraid/BuddyNet/buddynet.plg"

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

D=$(mktemp -d /tmp/bnplg.XXXXXX)
cleanup(){ pkill -f "$D/fakebin" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

# ── extract rc.buddynet from the .plg (the CDATA of its <FILE> block) ─────────
python3 - "$PLG" "$D/rc.buddynet" <<'PY'
import re, sys, io
plg = io.open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'<FILE Name="/etc/rc\.d/rc\.buddynet".*?<!\[CDATA\[(.*?)\]\]>', plg, re.S)
if not m:
    print("could not find rc.buddynet in the .plg", file=sys.stderr); sys.exit(1)
io.open(sys.argv[2], "w", encoding="utf-8").write(m.group(1).lstrip("\n"))
PY
[ -s "$D/rc.buddynet" ] || { echo "FAIL: no rc.buddynet extracted"; exit 1; }

# Point every hardcoded path at the scratch dir, and stub the language install
# (it copies into /usr/local/emhttp, which does not exist here).
sed -i -e "s|^CFG=.*|CFG=$D/buddynet.cfg|" \
       -e "s|^BIN=.*|BIN=$D/fakebin|" \
       -e "s|^STATE=.*|STATE=$D/state|" \
       -e "s|^PIDFILE=.*|PIDFILE=$D/pid|" \
       -e "s|^LOG=.*|LOG=$D/log|" \
       -e "s|^  install_lang$|  :|" "$D/rc.buddynet"
bash -n "$D/rc.buddynet" || { echo "FAIL: extracted rc.buddynet does not parse"; exit 1; }

# The stub records argv and the ONE environment variable that matters, then
# lingers so the rc script's is_running/pid handling behaves normally.
cat > "$D/fakebin" <<'STUB'
#!/bin/bash
{ printf '%s\n' "$@"; printf 'ENV_JOIN=[%s]\n' "${BUDDYNET_JOIN:-}"; } > "$ARGS_OUT"
exec sleep 30
STUB
chmod +x "$D/fakebin"

# The real binary, to check the plugin's output is actually accepted.
REAL="$D/buddynet-real"
go build -o "$REAL" "$ROOT/cmd/buddynet" || { echo "FAIL: go build"; exit 1; }
"$REAL" --key "$D/id.key" init >/dev/null 2>&1
KEY_A=$("$REAL" --key "$D/id.key" identity)
"$REAL" --key "$D/buddy.key" init >/dev/null 2>&1
KEY_B=$("$REAL" --key "$D/buddy.key" identity)

# run_cfg <<CFG … CFG  — write a config, run `start`, leave argv in $D/args
run_cfg(){
  rm -f "$D/args" "$D/pid" "$D/log"
  cat > "$D/buddynet.cfg"
  ARGS_OUT="$D/args" bash "$D/rc.buddynet" start >"$D/start.out" 2>&1
  for _ in $(seq 1 20); do [ -s "$D/args" ] && break; sleep 0.2; done
  pkill -f "$D/fakebin" 2>/dev/null
}
has(){ grep -qxF -- "$1" "$D/args" 2>/dev/null; }
dump(){ echo "    --- argv the plugin produced ---"; sed 's/^/    | /' "$D/args" 2>/dev/null; }

# accepted_by_real — the arguments the plugin produced, handed to the real
# binary. Exit 2 is a usage error (the plugin built something invalid); anything
# else means it got past validation, which is all we can assert offline.
accepted_by_real(){
  mapfile -t a < <(grep -v '^ENV_JOIN=' "$D/args")
  local i
  for i in "${!a[@]}"; do
    case "${a[$i]}" in "$D/state/id.key") a[$i]="$D/id.key";; esac
  done
  timeout 3 "$REAL" "${a[@]}" >"$D/real.out" 2>&1
  local rc=$?
  [ "$rc" -ne 2 ]
}

echo "== 1: coordinator mode (a config with no MODE line, as upgrades have) =="
run_cfg <<CFG
SERVICE="enable"
SERVER="vps.example:51820"
SERVER_KEY="$KEY_B"
TOKEN=""
TOKEN_FILE=""
PEER_KEY="$KEY_B"
LISTEN="127.0.0.1:9000"
FORWARD="127.0.0.1:873"
CFG
if [ -s "$D/args" ]; then
  has "--server" && has "vps.example:51820" && ok "passes --server (unchanged behaviour)" \
    || no "no --server in coordinator mode"
  has "--direct" && no "--direct leaked into coordinator mode" \
    || ok "does not pass --direct"
  accepted_by_real && ok "the real binary accepts what the plugin built" \
    || no "the real binary rejected the plugin's arguments: $(head -2 "$D/real.out")"
else
  no "nothing started in coordinator mode"; cat "$D/start.out" | sed 's/^/    /'
fi

echo
echo "== 2: direct mode, dialling the buddy =="
run_cfg <<CFG
SERVICE="enable"
MODE="direct"
SERVER="vps.example:51820"
SERVER_KEY="$KEY_B"
TOKEN=""
TOKEN_FILE=""
PEER_KEY="$KEY_B"
PEER_ENDPOINT="buddy.duckdns.org:51820"
LISTEN_PORT=""
LISTEN="127.0.0.1:9000"
FORWARD=""
CFG
if [ -s "$D/args" ]; then
  has "--direct" && ok "passes --direct" || no "no --direct"
  has "--peer-endpoint" && has "buddy.duckdns.org:51820" && ok "passes the buddy endpoint" \
    || no "no --peer-endpoint"
  # The stale SERVER value above is deliberate: a user switching modes leaves it
  # behind, and --direct with --server is refused by the daemon (exit 2).
  has "--server" && no "passed --server in direct mode — the daemon refuses that combination" \
    || ok "drops the leftover --server (they are mutually exclusive)"
  accepted_by_real && ok "the real binary accepts what the plugin built" \
    || no "the real binary rejected it: $(head -2 "$D/real.out")"
else
  no "nothing started in direct mode"; cat "$D/start.out" | sed 's/^/    /'
fi

echo
echo "== 3: direct mode, being dialled (fixed port, no endpoint) =="
run_cfg <<CFG
SERVICE="enable"
MODE="direct"
PEER_KEY="$KEY_B"
PEER_ENDPOINT=""
LISTEN_PORT="51820"
FORWARD="127.0.0.1:873"
CFG
if [ -s "$D/args" ]; then
  has "--listen-port" && has "51820" && ok "passes the fixed listen port" || no "no --listen-port"
  has "--peer-endpoint" && no "passed an empty --peer-endpoint" || ok "omits the unset endpoint"
  accepted_by_real && ok "the real binary accepts what the plugin built" \
    || no "the real binary rejected it: $(head -2 "$D/real.out")"
else
  no "nothing started"; cat "$D/start.out" | sed 's/^/    /'
fi

echo
echo "== 4: direct mode drops a leftover invite (BUDDYNET_JOIN is --join) =="
run_cfg <<CFG
SERVICE="enable"
MODE="direct"
TOKEN="bnet1.sometoken.somekey"
TOKEN_FILE=""
PEER_KEY="$KEY_B"
PEER_ENDPOINT="buddy.duckdns.org:51820"
CFG
if [ -s "$D/args" ]; then
  grep -qxF 'ENV_JOIN=[]' "$D/args" \
    && ok "starts with an empty BUDDYNET_JOIN (the daemon refuses --join with --direct)" \
    || no "passed an invite into direct mode: $(grep '^ENV_JOIN=' "$D/args")"
  grep -q "does not use one" "$D/log" 2>/dev/null && ok "says so in the log" || no "ignored it silently"
else
  no "nothing started"; cat "$D/start.out" | sed 's/^/    /'
fi

echo
echo "== 5: refusals — a misconfiguration must not start a doomed daemon =="
run_cfg <<CFG
SERVICE="enable"
MODE="direct"
PEER_KEY=""
PEER_ENDPOINT="buddy.duckdns.org:51820"
CFG
[ -s "$D/args" ] && no "started without a buddy key — nothing would authenticate the peer" \
  || ok "refuses direct mode without a buddy key"
grep -q "only thing that authenticates" "$D/log" 2>/dev/null \
  && ok "and says which field is missing" || no "no actionable message in the log"

run_cfg <<CFG
SERVICE="enable"
MODE="direct"
PEER_KEY="$KEY_B"
PEER_ENDPOINT=""
LISTEN_PORT=""
CFG
[ -s "$D/args" ] && no "started with no way for the two to meet" \
  || ok "refuses direct mode with neither an endpoint nor a listen port"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

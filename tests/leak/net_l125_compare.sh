#!/usr/bin/env bash
# L125 sub-checks against any hisn build, one `SUBCHECK <name> held|did-not-hold`
# line each (used to compare v0.6.0 with the 0.6.1 hardening). Hermetic:
#   unshare -Urn bash tests/leak/net_l125_compare.sh HISN WORKDIR TOKEN
set -u
HISN=${1:?usage: net_l125_compare.sh HISN WORKDIR TOKEN}
T=${2:?}; TOKEN=${3:?}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HELPER="$HERE/net_helper.py"
[ "$(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')" = "lo " ] || { echo "not in a fresh netns (use unshare -Urn)"; exit 2; }
mkdir -p "$T/run" "$T/state" "$T/data"; chmod 700 "$T/run"
export XDG_RUNTIME_DIR="$T/run" XDG_STATE_HOME="$T/state" XDG_DATA_HOME="$T/data"
unset HISN_SEAT_TOKEN
ip link set lo up && ip link add dummy0 type dummy && ip addr add 192.0.2.1/24 dev dummy0 &&
  ip addr add 192.0.2.2/24 dev dummy0 && ip link set dummy0 up || { echo "cannot create dummy0"; exit 2; }
python3 "$HELPER" serve "$T/helper.ready" "$T/host.sock" >"$T/helper.log" 2>&1 &
HP=$!
cleanup() { timeout 20 "$HISN" stop --session "$TOKEN-cmp" </dev/null >/dev/null 2>&1; kill "$HP" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT
for _ in $(seq 100); do [ -e "$T/helper.ready" ] && break; sleep 0.1; done
[ -e "$T/helper.ready" ] || { echo "listeners did not start"; exit 2; }
CWD="$T/cwd"; mkdir -p "$CWD"; cp "$HELPER" "$CWD/net_helper.py"
printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\nsession.cwd = "%s"\nsession.network = "open"\n[net]\nnameservers = ["192.0.2.2"]\n' "$CWD" >"$T/p.toml"
"$HISN" run --profile "$T/p.toml" --session-id "$TOKEN-cmp" -- sleep 600 </dev/null >"$T/run.log" 2>&1 &
for _ in $(seq 100); do
  "$HISN" ls --json </dev/null 2>/dev/null | python3 "$HELPER" ls-get "$TOKEN-cmp" state 2>/dev/null | grep -q running && break
  sleep 0.1
done
echo "build: $("$HISN" --version 2>&1 | head -n 1)"
timeout 60 "$HISN" exec --no-tty --session "$TOKEN-cmp" -- python3 net_helper.py in-hostsocket-report 18448 </dev/null 2>&1
if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1',19060))==0 else 1)"; then
  echo "SUBCHECK host-port-19060-closed did-not-hold"
else
  echo "SUBCHECK host-port-19060-closed held"
fi

#!/usr/bin/env bash
# hisn caj-readiness probe (settles the UNVERIFIED items of
# docs/plans/caj-readiness.md).
#
#   bash scripts/caj-probe.sh [--offline]
#
# Binary: ${HISN_BIN:-target/debug/hisn}. If it does not exist the script runs
# `cargo build --locked` (output under target/ only). Nothing is installed.
#
# Isolation: every hisn call runs with XDG_RUNTIME_DIR and XDG_STATE_HOME
# pointing into one temp directory of this run, so sessions, journals and seat
# stores never mix with real ones. That isolation is PARTIAL (hisn 0.6.2):
#   - the session-name registry lives in the fixed directory /tmp/hisn-<uid>
#     whatever XDG_RUNTIME_DIR says (src/registry.rs registry_root), and
#     `hisn ls` also scans /tmp/hisn-<uid> as a second runtime root
#     (src/session.rs runtime_roots). This script therefore never uses
#     --name (no registry write), never passes --prune/--purge, and only ever
#     stops sessions whose id starts with "cajprobe-" and that it started.
#   - probe I1 reports whether the registry file changed during the run.
#
# Output: one line per probe: PASS | FAIL | INFO | SKIP, an id, a description.
# Full log: target/caj-probe.log. Exit status: non-zero iff any FAIL.
# --offline skips the probes that need the internet (G1).
set -u

OFFLINE=0
case "${1:-}" in
  "") ;;
  --offline) OFFLINE=1 ;;
  *) echo "usage: bash scripts/caj-probe.sh [--offline]" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"
mkdir -p target
LOG="$ROOT/target/caj-probe.log"
: >"$LOG"

NPASS=0; NFAIL=0; NINFO=0; NSKIP=0
emit() { # emit KIND ID TEXT
  printf '%-5s %-4s %s\n' "$1" "$2" "$3" | tee -a "$LOG"
}
pass() { NPASS=$((NPASS + 1)); emit PASS "$1" "$2"; }
fail() { NFAIL=$((NFAIL + 1)); emit FAIL "$1" "$2"; }
info() { NINFO=$((NINFO + 1)); emit INFO "$1" "$2"; }
skip() { NSKIP=$((NSKIP + 1)); emit SKIP "$1" "$2"; }
logq() { printf '%s\n' "$*" >>"$LOG"; }

# ---- binary ---------------------------------------------------------------
HISN=${HISN_BIN:-target/debug/hisn}
case "$HISN" in /*) ;; *) HISN="$ROOT/$HISN" ;; esac
if [ ! -x "$HISN" ]; then
  echo "building $HISN (cargo build --locked, output under target/)" | tee -a "$LOG"
  if ! cargo build --locked >>"$LOG" 2>&1; then
    echo "FAIL  B0   cargo build --locked failed, see $LOG" | tee -a "$LOG"
    exit 1
  fi
fi
echo "hisn binary: $HISN ; version: $("$HISN" --version 2>&1 | head -n 1)" | tee -a "$LOG"
if ! "$HISN" --version >/dev/null 2>&1; then
  echo "FAIL  B0   the binary does not run on this host" | tee -a "$LOG"
  exit 1
fi

# ---- isolated state -------------------------------------------------------
STAMP=$(date -u +%H%M%S)$$
TMP=$(mktemp -d /tmp/cajprobe.XXXXXX) || exit 1
RUN="$TMP/run"; STATE="$TMP/state"; CWD="$TMP/cwd"
mkdir -p "$RUN" "$STATE" "$CWD"
chmod 700 "$RUN" "$TMP"
UIDN=$(id -u)
REGFILE="/tmp/hisn-$UIDN/names.json"
REG_BEFORE=$(stat -c %Y "$REGFILE" 2>/dev/null || echo none)
IDS=()       # session ids started by this script (all prefixed cajprobe-)
BGPIDS=()    # background client pids started by this script

H() { # H SECONDS hisn-args...  (stdin from /dev/null)
  local t=$1; shift
  XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" timeout "$t" "$HISN" "$@" </dev/null
}
HB() { # background hisn call, $! is the hisn client itself
  XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" "$HISN" "$@" </dev/null >>"$LOG" 2>&1 &
  BGPIDS+=("$!")
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  local p id
  for p in ${BGPIDS[@]+"${BGPIDS[@]}"}; do kill "$p" 2>/dev/null; done
  for id in ${IDS[@]+"${IDS[@]}"}; do
    case "$id" in cajprobe-*) H 30 stop --session "$id" >>"$LOG" 2>&1 ;; esac
  done
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT INT TERM

pyget() { # pyget JSON_TEXT 'expr on d'
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2" 2>/dev/null
}

lsget() { # lsget ID EXPR  (EXPR over the session object s)
  H 20 ls --json 2>/dev/null | python3 -c '
import json, sys
sid, expr = sys.argv[1], sys.argv[2]
d = json.load(sys.stdin)
for s in d["sessions"]:
    if s["id"] == sid:
        print(eval(expr)); break
' "$1" "$2" 2>/dev/null
}

start_session() { # start_session NAME NETWORK -> sets SID, appends to IDS
  local name=$1 net=$2
  SID="cajprobe-$STAMP-$name"
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "%s"\n' \
    "$CWD" "$net" >"$TMP/$name.toml"
  IDS+=("$SID")
  H 60 run --detach --policy "$TMP/$name.toml" --session-id "$SID" \
    --workspace "cajprobe-$STAMP" >"$TMP/$name.start" 2>&1
  START_RC=$?
  logq "start $name rc=$START_RC: $(cat "$TMP/$name.start")"
  [ "$START_RC" -eq 0 ] && [ "$(lsget "$SID" 's["state"]')" = running ]
}

X() { # X SID cmd...  : exec --no-tty, stderr merged
  local sid=$1; shift
  H 60 exec --no-tty --session "$sid" -- "$@" 2>&1
}

# ---- P: host facts (read-only) -------------------------------------------
info P1 "kernel $(uname -r); user $(id -un); XDG_RUNTIME_DIR(real)=${XDG_RUNTIME_DIR:-unset}"
if command -v loginctl >/dev/null 2>&1; then
  info P2 "linger: $(loginctl show-user "$(id -un)" -p Linger 2>&1 | head -n 1) (if no, /run/user/<uid> is removed at last logout)"
else
  skip P2 "loginctl not available"
fi

info P3 "filesystem types: /tmp=$(stat -f -c %T /tmp 2>&1) ; XDG_RUNTIME_DIR(real)=$( [ -n "${XDG_RUNTIME_DIR:-}" ] && stat -f -c %T "$XDG_RUNTIME_DIR" 2>&1 || echo unset) (tmpfs means session dirs vanish on reboot)"

# ---- sessions --------------------------------------------------------------
if ! start_session none none; then
  fail S0 "network=none session did not start: $(head -c 300 "$TMP/none.start")"
  echo "RESULT: pass=$NPASS fail=$NFAIL info=$NINFO skip=$NSKIP" | tee -a "$LOG"
  exit 1
fi
SNONE=$SID
pass S0 "run --detach (network none) printed: $(head -n 1 "$TMP/none.start")"
if [ "$(wc -l <"$TMP/none.start")" -eq 1 ] && grep -qE "^$SNONE - ready$" "$TMP/none.start"; then
  pass S1 "run --detach stdout is exactly '<id> - ready' for an unnamed session"
else
  fail S1 "run --detach stdout differs from '<id> - ready'"
fi

OPEN_OK=0
if start_session open open; then SOPEN=$SID; OPEN_OK=1; else
  fail S2 "network=open session did not start: $(head -c 300 "$TMP/open.start")"
fi

# ---- J: journal -------------------------------------------------------------
X "$SNONE" true >/dev/null
H 20 note --session "$SNONE" "probe note one" >/dev/null 2>&1
H 20 note --session "$SNONE" --marker "probe marker" >/dev/null 2>&1
JOUT=$(H 20 journal --session "$SNONE" --json 2>"$TMP/j.err"); JRC=$?
if [ "$JRC" -eq 0 ] && [ -n "$JOUT" ] && printf '%s\n' "$JOUT" | python3 -c '
import json, sys
n = 0
for l in sys.stdin:
    r = json.loads(l); n += 1
    assert "wseq" in r and "kind" in r and "ts" in r
assert n > 0
'; then
  pass J1 "journal --json is JSON lines, every record has ts, wseq, kind ($(printf '%s\n' "$JOUT" | wc -l) records)"
else
  fail J1 "journal --json is not clean JSON lines (rc=$JRC)"
fi
info J2 "record kinds seen: $(printf '%s\n' "$JOUT" | python3 -c '
import json, sys
print(sorted({json.loads(l)["kind"] for l in sys.stdin}))' 2>&1)"
L=$(H 20 journal --session "$SNONE" --json --last 2 2>/dev/null | wc -l)
[ "$L" -eq 2 ] && pass J3 "journal --last 2 --json returns exactly 2 records" || fail J3 "journal --last 2 --json returned $L lines"
K=$(H 20 journal --session "$SNONE" --json --kind note 2>/dev/null | wc -l)
info J4 "journal --kind note --json returned $K line(s) (the note op's kind name decides)"
SN=$(H 20 journal --session "$SNONE" --json --since 2000-01-01T00:00:00Z 2>/dev/null | wc -l)
[ "$SN" -gt 0 ] && pass J5 "journal --since RFC3339-Z works" || fail J5 "journal --since returned nothing"
if H 20 journal --session "$SNONE" --json --since 2000-01-01 >/dev/null 2>"$TMP/since.err"; then
  info J6 "journal --since without Z was accepted"
else
  info J6 "journal --since without Z refused (expected): $(head -c 120 "$TMP/since.err")"
fi
if "$HISN" journal --help 2>&1 | grep -qiE -- '--follow|--tail|--after'; then
  info J7 "journal has a follow/tail/after option"
else
  info J7 "journal has no --follow/--tail/--after option (gap: no cursor, no follow)"
fi
# Reader under concurrent writers: 150 notes in the background while reading.
( for i in $(seq 150); do H 20 note --session "$SNONE" "conc $i" >/dev/null 2>&1; done ) &
WPID=$!; BGPIDS+=("$WPID")
BAD=0
for _ in 1 2 3 4 5 6; do
  H 20 journal --session "$SNONE" --json 2>/dev/null | python3 -c '
import json, sys
for l in sys.stdin: json.loads(l)' || BAD=1
done
wait "$WPID" 2>/dev/null
[ "$BAD" -eq 0 ] && pass J8 "6 reads during 150 concurrent note writes: every line parsed" || fail J8 "a read during concurrent writes saw an unparseable line"
JFILE=$(ls "$STATE"/hisn/workspaces/*/journal.jsonl 2>/dev/null | head -n 1)
if [ -n "$JFILE" ]; then
  WS=$(stat -c %a "$JFILE")
  info J9 "journal file mode $WS; size $(stat -c %s "$JFILE") bytes; rotation at 64 MiB is code-only (not probed)"
fi

# ---- E: exec lifetime and exit codes ---------------------------------------
X "$SNONE" sh -c 'exit 3' >/dev/null; rc=$?
[ "$rc" -eq 3 ] && pass E1 "exec exit status propagates (3)" || fail E1 "exec exit 3 gave rc=$rc"
X "$SNONE" /nonexistent-prog >/dev/null; rc=$?
[ "$rc" -eq 127 ] && pass E2 "exec of a missing program exits 127" || fail E2 "missing program gave rc=$rc"
X "$SNONE" sh -c 'kill -9 $$' >/dev/null; rc=$?
[ "$rc" -eq 137 ] && pass E3 "exec killed by SIGKILL exits 137" || fail E3 "SIGKILL child gave rc=$rc"
H 20 exec --no-tty --session cajprobe-does-not-exist -- true >/dev/null 2>"$TMP/e4.err"; rc=$?
[ "$rc" -eq 125 ] && pass E4 "exec on an unknown session exits 125 ($(head -c 100 "$TMP/e4.err"))" || fail E4 "unknown session gave rc=$rc"
X "$SNONE" sh -c 'echo OUT; echo ERR >&2' >/dev/null 2>&1
O=$(H 20 exec --no-tty --session "$SNONE" -- sh -c 'echo OUT; echo ERR >&2' 2>"$TMP/e5.err")
[ "$O" = OUT ] && grep -q '^ERR$' "$TMP/e5.err" && pass E5 "exec --no-tty keeps stdout and stderr separate" || fail E5 "stdout/stderr not separated"
X "$SNONE" sh -c 'exit 126' >/dev/null; rc=$?
info E6 "a command that itself exits 126 yields rc=$rc (indistinguishable from a hisn 'cannot execute')"

# Client killed: -9 on the hisn exec client (no signal forwarding possible).
rm -f "$CWD/e7.pid"
HB exec --no-tty --session "$SNONE" -- sh -c 'echo $$ >e7.pid; exec sleep 300'
CPID=${BGPIDS[${#BGPIDS[@]}-1]}
for _ in $(seq 50); do [ -s "$CWD/e7.pid" ] && break; sleep 0.1; done
if [ -s "$CWD/e7.pid" ]; then
  INSB=$(cat "$CWD/e7.pid")
  NEX=$(lsget "$SNONE" 'len([e for e in s["execs"] if e["argv0"].endswith("sh")])')
  info E7 "while running, ls --json reports $NEX exec(s); exec fields: $(lsget "$SNONE" 'sorted(s["execs"][0].keys()) if s["execs"] else []')"
  kill -9 "$CPID" 2>/dev/null
  T0=$(date +%s%N)
  GONE=0
  for _ in $(seq 150); do
    if ! X "$SNONE" sh -c "kill -0 $INSB" >/dev/null 2>&1; then GONE=1; break; fi
    sleep 0.1
  done
  T1=$(date +%s%N)
  [ "$GONE" -eq 1 ] && pass E8 "exec'd process ended $(( (T1 - T0) / 1000000 )) ms after its client was killed -9" \
                    || fail E8 "exec'd process still running 15 s after the client was killed"
else
  fail E7 "background exec never wrote its pid"
fi
# A process that ignores TERM: the KILL grace (5 s in the code) should apply.
rm -f "$CWD/e9.pid"
HB exec --no-tty --session "$SNONE" -- sh -c 'trap "" TERM; echo $$ >e9.pid; while :; do sleep 1; done'
CPID=${BGPIDS[${#BGPIDS[@]}-1]}
for _ in $(seq 50); do [ -s "$CWD/e9.pid" ] && break; sleep 0.1; done
if [ -s "$CWD/e9.pid" ]; then
  INSB=$(cat "$CWD/e9.pid"); kill -9 "$CPID" 2>/dev/null
  T0=$(date +%s%N); GONE=0
  for _ in $(seq 200); do
    if ! X "$SNONE" sh -c "kill -0 $INSB" >/dev/null 2>&1; then GONE=1; break; fi
    sleep 0.1
  done
  T1=$(date +%s%N)
  [ "$GONE" -eq 1 ] && info E9 "TERM-ignoring process ended $(( (T1 - T0) / 1000000 )) ms after client kill (code: KILL after 5 s)" \
                    || fail E9 "TERM-ignoring process survived 20 s after client kill"
fi
# Is there any way to start a process that outlives its call?
if "$HISN" exec --help 2>&1 | grep -qiE -- '--detach|--background'; then
  info E10 "exec has a detach/background option"
else
  info E10 "exec has no detach/background option and ls/exec offer no status-by-exec_id (gap, confirmed by --help)"
fi
# Process started with setsid/nohup inside an exec: does it survive the exec's end?
rm -f "$CWD/e11.pid"
X "$SNONE" sh -c 'setsid sh -c "echo \$\$ >e11.pid; exec sleep 120" >/dev/null 2>&1 </dev/null &' >/dev/null
sleep 1.5
if [ -s "$CWD/e11.pid" ]; then
  if X "$SNONE" sh -c "kill -0 $(cat "$CWD/e11.pid")" >/dev/null 2>&1; then
    info E11 "a setsid'd child survives the end of its exec call (in-session workaround exists, no output capture)"
  else
    info E11 "a setsid'd child did NOT survive the end of its exec call"
  fi
else
  info E11 "setsid child never wrote its pid"
fi

# ---- N: netlink bind and interface enumeration (Block 1 decision) ----------
cat >"$CWD/nl.py" <<'PY'
import socket, errno
def attempt(label, make, addr):
    try:
        s = make()
    except OSError as e:
        print('%s: socket() %s' % (label, errno.errorcode.get(e.errno, e.errno)))
        return
    try:
        s.bind(addr)
        print('%s: bind OK' % label)
    except OSError as e:
        print('%s: bind %s' % (label, errno.errorcode.get(e.errno, e.errno)))
    finally:
        s.close()
attempt('NETLINK', lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0), (0, 0))
if hasattr(socket, 'AF_ALG'):
    attempt('ALG', lambda: socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0), ('hash', 'sha256'))
attempt('PACKET', lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW), ('lo', 0))
attempt('UNSPEC-low-port', lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM), ('0.0.0.0', 80))
PY
for pair in "none|$SNONE" "open|${SOPEN:-}"; do
  mode=${pair%%|*}; sid=${pair#*|}
  [ -n "$sid" ] || continue
  out=$(X "$sid" python3 nl.py | tr '\n' ';')
  info N1 "$mode: bind by family (v0.6.2 behaviour): ${out:-no output}; if_nameindex -> $(X "$sid" python3 -c 'import socket; print(socket.if_nameindex())' | tail -n 1 | head -c 120)"
done

# ---- L: loopback ---------------------------------------------------------------
cat >"$CWD/lo.py" <<'PY'
import socket, sys
mode, fam_arg = sys.argv[1], sys.argv[2]
fam = socket.AF_INET6 if fam_arg == '6' else socket.AF_INET
addr = '::1' if fam_arg == '6' else '127.0.0.1'
if mode == 'listen':
    s = socket.socket(fam)
    s.bind((addr, 0))
    s.listen(4)
    open(sys.argv[3], 'w').write(str(s.getsockname()[1]))
    s.settimeout(30)
    c, _ = s.accept()
    c.sendall(b'pong')
    c.close()
else:
    s = socket.socket(fam)
    s.settimeout(5)
    s.connect((addr, int(sys.argv[3])))
    print(s.recv(16).decode())
PY
loop_probe() { # loop_probe ID SID FAMILY(4|6) LABEL
  local id=$1 sid=$2 fam=$3 label=$4 pf
  pf="lo-$id.port"
  rm -f "$CWD/$pf"
  HB exec --no-tty --session "$sid" -- python3 lo.py listen "$fam" "$pf"
  for _ in $(seq 50); do [ -s "$CWD/$pf" ] && break; sleep 0.1; done
  if [ ! -s "$CWD/$pf" ]; then fail "$id" "$label: listener never reported a port (listen on loopback failed)"; return; fi
  local out; out=$(X "$sid" python3 lo.py connect "$fam" "$(cat "$CWD/$pf")")
  [ "$out" = pong ] && pass "$id" "$label: listen in one exec, connect from another exec" \
                    || fail "$id" "$label: connect failed: $(printf '%s' "$out" | tail -n 1 | head -c 150)"
}
loop_probe L1 "$SNONE" 4 "none 127.0.0.1"
loop_probe L2 "$SNONE" 6 "none ::1"
if [ "$OPEN_OK" -eq 1 ]; then
  loop_probe L3 "$SOPEN" 4 "open 127.0.0.1"
  loop_probe L4 "$SOPEN" 6 "open ::1"
fi
# A listener on the HOST's loopback must be unreachable from the session.
python3 - "$TMP/host.port" <<'PY' &
import socket, sys
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
s.settimeout(25)
try:
    s.accept()
except Exception:
    pass
PY
BGPIDS+=("$!")
for _ in $(seq 30); do [ -s "$TMP/host.port" ] && break; sleep 0.1; done
HP=$(cat "$TMP/host.port" 2>/dev/null)
for pair in "L5 $SNONE none"; do
  set -- $pair
  out=$(X "$2" python3 lo.py connect 4 "$HP"); 
  case "$out" in *pong*|"") fail "$1" "$3: session reached a host loopback listener" ;; *) pass "$1" "$3: host loopback listener not reachable from the session ($(printf '%s' "$out" | tail -n 1 | head -c 80))" ;; esac
done
if [ "$OPEN_OK" -eq 1 ]; then
  out=$(X "$SOPEN" python3 lo.py connect 4 "$HP")
  case "$out" in *pong*) fail L6 "open: session reached a host loopback listener" ;; *) pass L6 "open: host loopback listener not reachable from the session ($(printf '%s' "$out" | tail -n 1 | head -c 80))" ;; esac
fi
# Inbound: is anything on the host listening because of the session?
if command -v ss >/dev/null 2>&1; then
  info L7 "host TCP listeners owned by session processes: $(ss -ltnp 2>/dev/null | grep -c cajprobe) (expected 0; the session netns is private)"
fi

# ---- G: internet in open mode ------------------------------------------------------
if [ "$OPEN_OK" -eq 1 ]; then
  if [ "$OFFLINE" -eq 1 ]; then
    skip G1 "git ls-remote https://gitlab.com (--offline)"
  else
    if X "$SOPEN" sh -c 'command -v git' >/dev/null 2>&1; then
      out=$(H 90 exec --no-tty --session "$SOPEN" -- git ls-remote --heads https://gitlab.com/gitlab-org/gitlab-runner.git main 2>&1); rc=$?
      if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -qE '^[0-9a-f]{40}'; then
        pass G1 "open mode: git ls-remote over HTTPS to gitlab.com works"
      else
        fail G1 "git ls-remote to gitlab.com failed rc=$rc: $(printf '%s' "$out" | tail -n 2 | head -c 200)"
      fi
    else
      # no git in the session's filesystem view: same network path with python3 (HTTPS GET of the smart-http ref advertisement)
      out=$(H 90 exec --no-tty --session "$SOPEN" -- python3 -c 'import urllib.request as u; r=u.urlopen("https://gitlab.com/gitlab-org/gitlab-runner.git/info/refs?service=git-upload-pack", timeout=30); print(r.status, r.read(40)[:40])' 2>&1); rc=$?
      if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q '^200 '; then
        pass G1 "open mode: HTTPS to gitlab.com works (python3 urllib; git is not available in the session)"
      else
        fail G1 "HTTPS to gitlab.com failed rc=$rc: $(printf '%s' "$out" | tail -n 2 | head -c 200)"
      fi
    fi
  fi
else
  skip G1 "open session not available"
fi

# ---- M: machine interface ------------------------------------------------------------
jprobe() { # jprobe ID DESC EXPECT_JSON(yes|no) cmd...
  local id=$1 desc=$2 want=$3; shift 3
  local out rc isjson=no
  out=$(H 30 "$@" 2>"$TMP/m.err"); rc=$?
  printf '%s' "$out" | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    json.loads(t)
except Exception:
    lines = [l for l in t.splitlines() if l.strip()]
    assert lines and all(json.loads(l) is not None for l in lines)
' 2>/dev/null && isjson=yes
  if [ "$isjson" = "$want" ]; then
    pass "$id" "$desc: rc=$rc, stdout JSON=$isjson"
  else
    fail "$id" "$desc: rc=$rc, stdout JSON=$isjson (wanted $want)"
  fi
}
jprobe M1 "ls --json" yes ls --json
jprobe M2 "inspect --json" yes inspect --session "$SNONE" --json
jprobe M3 "check --json" yes check --json
jprobe M4 "journal --json" yes journal --session "$SNONE" --json
jprobe M5 "ls --session --json" yes ls --session "$SNONE" --json
for pair in "M6|seat ls|seat --session $SNONE ls" "M7|rootfs list|rootfs list" "M8|profile validate|profile validate" "M9|note|note --session $SNONE m9"; do
  id=${pair%%|*}; rest=${pair#*|}; desc=${rest%%|*}; cmd=${rest#*|}
  # shellcheck disable=SC2086
  out=$(H 30 $cmd 2>/dev/null); rc=$?
  if printf '%s' "$out" | python3 -c 'import json,sys; json.loads(sys.stdin.read())' 2>/dev/null; then j=yes; else j=no; fi
  info "$id" "$desc: rc=$rc, stdout is one JSON document: $j (no --json option exists in 0.6.2 for seat/rootfs/profile)"
done
info M10 "ls --json state/pid/started/lease of the none session: state=$(lsget "$SNONE" 's["state"]') pid=$(lsget "$SNONE" 's["pid"]') started=$(lsget "$SNONE" 's["started"]') lease=$(lsget "$SNONE" 's["lease"]')"
info M11 "ls --json session keys: $(lsget "$SNONE" 'sorted(s.keys())')"
H 20 inspect --session cajprobe-nope --json >"$TMP/m12.out" 2>"$TMP/m12.err"; rc=$?
info M12 "inspect on an unknown session: rc=$rc stdout='$(head -c 80 "$TMP/m12.out")' stderr='$(head -c 120 "$TMP/m12.err")' (error format)"
H 20 stop --session cajprobe-nope >"$TMP/m13.out" 2>"$TMP/m13.err"; rc=$?
info M13 "stop on an unknown session: rc=$rc stderr='$(head -c 120 "$TMP/m13.err")'"

# ---- T: seats ---------------------------------------------------------------------------
TOK=$(H 20 seat --session "$SNONE" add alice --role member 2>/dev/null)
if [ -n "$TOK" ] && [ "${#TOK}" -ge 32 ]; then
  pass T1 "seat add prints the credential alone on stdout (${#TOK} chars, shown once)"
  printf '%s\n' "$TOK" >"$TMP/alice.tok"; chmod 600 "$TMP/alice.tok"
  X_OUT=$(H 30 exec --no-tty --session "$SNONE" --seat-token-file "$TMP/alice.tok" -- echo seat-ok 2>&1)
  [ "$X_OUT" = seat-ok ] && pass T2 "exec with --seat-token-file succeeds" || fail T2 "exec with seat token failed: $X_OUT"
  N=$(H 20 journal --session "$SNONE" --json --seat alice 2>/dev/null | grep -c '"seat":"alice"')
  [ "$N" -ge 1 ] && pass T3 "journal records the seat name for that exec ($N matching record(s))" || fail T3 "no journal record carries seat alice"
  H 30 exec --no-tty --session "$SNONE" -- echo noseat >/dev/null 2>&1
  info T4 "last exec/request without credential has client: $(H 20 journal --session "$SNONE" --json --kind exec/request --last 1 2>/dev/null | python3 -c '
import json, sys
for l in sys.stdin:
    print(json.dumps(json.loads(l).get("client")))' 2>&1)"
  if [ -n "${JFILE:-}" ]; then
    LEAK=$(cat "$STATE"/hisn/workspaces/*/journal*.jsonl 2>/dev/null | grep -c -F "$TOK")
    [ "$LEAK" -eq 0 ] && pass T5 "the credential does not appear in any journal file" || fail T5 "credential found in a journal file ($LEAK line(s))"
  fi
  HB exec --no-tty --session "$SNONE" --seat-token-file "$TMP/alice.tok" -- sleep 4
  CP=${BGPIDS[${#BGPIDS[@]}-1]}; sleep 1
  ARGV_HITS=$(tr '\0' ' ' <"/proc/$CP/cmdline" 2>/dev/null | grep -c -F "$TOK")
  [ "$ARGV_HITS" -eq 0 ] && pass T6 "credential not in the argv of the hisn exec client" || fail T6 "credential visible in argv"
  ENV_HITS=0
  XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" HISN_SEAT_TOKEN="$TOK" "$HISN" exec --no-tty --session "$SNONE" -- sleep 4 </dev/null >>"$LOG" 2>&1 &
  CP2=$!; BGPIDS+=("$CP2"); sleep 1
  ENV_HITS=$(tr '\0' '\n' <"/proc/$CP2/environ" 2>/dev/null | grep -c -F "$TOK")
  info T7 "with HISN_SEAT_TOKEN the credential is in the client's /proc/<pid>/environ (same uid can read it): $ENV_HITS"
else
  fail T1 "seat add did not print a credential"
fi

# ---- A11: shell death --------------------------------------------------------------------
SD="cajprobe-$STAMP-die"; IDS+=("$SD")
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$CWD" >"$TMP/die.toml"
H 60 run --policy "$TMP/die.toml" --session-id "$SD" --workspace "cajprobe-$STAMP-die" -- sh -c 'kill -9 $$' >"$TMP/die.out" 2>"$TMP/die.err"; rc=$?
info D1 "foreground run whose command kills itself with SIGKILL: hisn rc=$rc (128+9 = 137 expected)"
H 20 journal --session "$SD" --workspace "cajprobe-$STAMP-die" --json 2>/dev/null >"$TMP/die.j"
info D2 "journal kinds after that death: $(python3 -c '
import json, sys
print([json.loads(l)["kind"] for l in open(sys.argv[1])])' "$TMP/die.j" 2>&1)"
info D3 "session/stop data: $(python3 -c '
import json, sys
for l in open(sys.argv[1]):
    r = json.loads(l)
    if r["kind"] == "session/stop":
        print(json.dumps(r["data"]))' "$TMP/die.j" 2>&1) (no exit status/signal field = diagnostic gap)"
info D4 "ls --json state of that session: $(lsget "$SD" 's["state"]')"

# ---- D: detached session survival ---------------------------------------------------------
SDET="cajprobe-$STAMP-det"; IDS+=("$SDET")
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$CWD" >"$TMP/det.toml"
bash -c "XDG_RUNTIME_DIR='$RUN' XDG_STATE_HOME='$STATE' '$HISN' run --detach --policy '$TMP/det.toml' --session-id '$SDET' --workspace 'cajprobe-$STAMP' >/dev/null 2>&1 </dev/null; exit 0"
sleep 1
[ "$(lsget "$SDET" 's["state"]')" = running ] \
  && pass D5 "detached session still running after the shell that started it exited" \
  || fail D5 "detached session not running after its parent shell exited"
if command -v ssh >/dev/null 2>&1 && ssh -o BatchMode=yes -o ConnectTimeout=3 localhost true >/dev/null 2>&1; then
  SSSH="cajprobe-$STAMP-ssh"; IDS+=("$SSSH")
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$CWD" >"$TMP/ssh.toml"
  ssh -o BatchMode=yes -o ConnectTimeout=5 localhost "XDG_RUNTIME_DIR='$RUN' XDG_STATE_HOME='$STATE' '$HISN' run --detach --policy '$TMP/ssh.toml' --session-id '$SSSH' --workspace 'cajprobe-$STAMP' </dev/null" >"$TMP/ssh.out" 2>&1
  sleep 2
  [ "$(lsget "$SSSH" 's["state"]')" = running ] \
    && pass D6 "session started over non-interactive ssh survives the ssh connection closing" \
    || fail D6 "session started over ssh is not running after ssh returned: $(head -c 150 "$TMP/ssh.out")"
else
  skip D6 "ssh to localhost with key auth not available (BatchMode)"
fi
SUPPID=$(cut -d' ' -f1 "$RUN/hisn/$SDET/supervisor.pid" 2>/dev/null)
[ -n "$SUPPID" ] && info D7 "detached supervisor: pid=$SUPPID sid=$(ps -o sid= -p "$SUPPID" 2>/dev/null | tr -d ' ') tty=$(ps -o tty= -p "$SUPPID" 2>/dev/null | tr -d ' ')"
info D8 "files in a detached session dir: $(ls "$RUN/hisn/$SDET" 2>/dev/null | tr '\n' ' ')"

# ---- S: systemd scope --------------------------------------------------------------------
if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet true >/dev/null 2>&1; then
  SSC="cajprobe-$STAMP-scope"; IDS+=("$SSC")
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$CWD" >"$TMP/scope.toml"
  # systemd-run --user finds the user manager through the REAL XDG_RUNTIME_DIR,
  # so the isolated directories are passed to hisn through env(1) instead.
  systemd-run --user --scope --quiet \
    -p MemoryMax=512M -p TasksMax=256 -- env XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" "$HISN" run --detach --policy "$TMP/scope.toml" \
    --session-id "$SSC" --workspace "cajprobe-$STAMP" </dev/null >"$TMP/scope.out" 2>&1
  sleep 1
  if [ "$(lsget "$SSC" 's["state"]')" = running ]; then
    pass C1 "run --detach inside systemd-run --user --scope reaches state running"
    SP=$(cut -d' ' -f1 "$RUN/hisn/$SSC/supervisor.pid" 2>/dev/null)
    CG=$(cat "/proc/$SP/cgroup" 2>/dev/null | head -n 1)
    case "$CG" in *.scope*) pass C2 "detached supervisor stays in the scope's cgroup ($CG)" ;; *) fail C2 "supervisor cgroup is not the scope: $CG" ;; esac
    CGP=${CG#0::}
    info C3 "scope limits: memory.max=$(cat "/sys/fs/cgroup$CGP/memory.max" 2>&1) pids.max=$(cat "/sys/fs/cgroup$CGP/pids.max" 2>&1)"
    X "$SSC" true >/dev/null && pass C4 "exec works in a session started inside the scope" || fail C4 "exec failed in the scoped session"
    INITCG=$(X "$SSC" cat /proc/self/cgroup 2>&1 | head -n 1)
    info C5 "cgroup as seen from an exec inside the scoped session: $INITCG"
    H 30 stop --session "$SSC" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 0 ] && pass C6 "stop of the scoped session exits 0" || fail C6 "stop of the scoped session rc=$rc"
  else
    fail C1 "session inside systemd-run scope did not reach running: $(head -c 200 "$TMP/scope.out")"
  fi
else
  skip C1 "systemd-run --user --scope not available (no user manager)"
fi

# ---- stop semantics and exit codes ------------------------------------------------------------
H 30 stop --session "$SDET" >/dev/null 2>&1; rc1=$?
H 30 stop --session "$SDET" >/dev/null 2>&1; rc2=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && pass R1 "stop twice: rc=$rc1 then $rc2 (already-stopped is success)" || fail R1 "stop twice: rc=$rc1 then $rc2"
info R2 "state after stop: $(lsget "$SDET" 's["state"]'); dir kept: $([ -d "$RUN/hisn/$SDET" ] && echo yes || echo no)"

# ---- isolation ---------------------------------------------------------------------------------
REG_AFTER=$(stat -c %Y "$REGFILE" 2>/dev/null || echo none)
if [ "$REG_BEFORE" = "$REG_AFTER" ]; then
  pass I1 "the shared name registry $REGFILE was not modified by this run"
else
  fail I1 "the shared name registry changed during the run ($REG_BEFORE -> $REG_AFTER)"
fi

echo "RESULT: pass=$NPASS fail=$NFAIL info=$NINFO skip=$NSKIP (log: target/caj-probe.log)" | tee -a "$LOG"
[ "$NFAIL" -eq 0 ]

#!/usr/bin/env bash
# hisn 0.6.0 host verification (ADR 0022, network = "open").
#
#   bash scripts/host-verify-network.sh [--real]
#
# Steps, in order:
#   1. cargo build --release (to target/ only; nothing is installed and no
#      other hisn binary is touched).
#   2. make release-gate without a rootfs, then again with
#      HISN_TEST_ROOTFS / HISN_BIG_TESTS (default: the rootfs named
#      wakil-dev in the rootfs store, HISN_BIG_TESTS=1; the environment
#      wins). The rootfs run is SKIPped only when no rootfs is found.
#   3. tests/leak/net_cases.sh inside `unshare -Urn`: the hermetic
#      open-mode cases (L90, L94, L96-L100, L102-L107, L109-L116). No
#      traffic leaves the machine.
#   4. only with --real: one open session against the real network (TCP
#      to 1.1.1.1:53, DNS, curl and git to github.com, and the LAN
#      gateway, which must be refused). This is the only step that sends
#      traffic off the machine.
#
# Steps 3 and 4 run hisn with its runtime and state directories inside
# a temp dir of this run, so they neither see nor disturb other hisn
# sessions on the machine.
#
# Output: PASS / FAIL: / SKIP lines and a last line
#   RESULT: pass=<n> fail=<n> timeout=<n> skipped=<n>
# A step passes only when its command exits 0, prints the expected text
# and prints no FAIL line. Before the RESULT line the script counts the
# PASS and FAIL lines it printed and fails if they differ from its
# counters. Exit 0 iff fail=0 and timeout=0.
#
# Full logs: .wakil/host-logs/<UTC timestamp>/ (gitignored). On every
# exit path the script stops the sessions it started and removes its
# temp dirs.
set -u

REAL=0
case "${1:-}" in
  "") ;;
  --real) REAL=1 ;;
  *) echo "usage: bash scripts/host-verify-network.sh [--real]" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

HISN="$ROOT/target/release/hisn"
HELPER="$ROOT/tests/leak/net_helper.py"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR="$ROOT/.wakil/host-logs/$TS"
mkdir -p "$LOGDIR" || exit 1
SUMMARY="$LOGDIR/summary.log"
: >"$SUMMARY"
TOKEN="hv$$"
TMP=$(mktemp -d /tmp/hisn-hostverify.XXXXXX) || exit 1
PIDS="$TMP/supervisor.pids"
: >"$PIDS"
REAL_ID=""

PASS=0 FAIL=0 TIMEOUT=0 SKIP=0
say()   { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
note()  { say "host-verify: $*"; }
pass()  { PASS=$((PASS + 1)); say "PASS  $1"; }
fail()  { FAIL=$((FAIL + 1)); say "FAIL: $1 -- $(printf '%s' "$2" | tr '\n' ' ' | head -c 600)"; }
tmout() { TIMEOUT=$((TIMEOUT + 1)); FAIL=$((FAIL + 1)); say "FAIL: $1 -- timeout after $2 s"; }
skip()  { SKIP=$((SKIP + 1)); say "SKIP  $1 -- $2"; }

cleanup() {
  local pid
  if [ -n "$REAL_ID" ]; then
    XDG_RUNTIME_DIR="$TMP/real/run" XDG_STATE_HOME="$TMP/real/state" \
      timeout 20 "$HISN" stop --session "$REAL_ID" </dev/null >/dev/null 2>&1
  fi
  # Supervisors recorded by this run that are still alive (a step was
  # killed or timed out): only pids from our own files, and only while
  # their command line still names this run's token.
  for f in "$PIDS" "$TMP/net/supervisor.pids"; do
    [ -f "$f" ] || continue
    while read -r pid; do
      [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] &&
        tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF -- "$TOKEN" && kill -9 "$pid" 2>/dev/null
    done <"$f"
  done
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 143' TERM INT HUP

finish() {
  # Cross-check: the lines printed must match the counters.
  local p f
  p=$(grep -c '^PASS  ' "$SUMMARY")
  f=$(grep -c '^FAIL: ' "$SUMMARY")
  if [ "$p" -ne "$PASS" ] || [ "$f" -ne "$FAIL" ]; then
    say "FAIL: tally -- printed $p PASS and $f FAIL lines, counters say pass=$PASS fail=$FAIL"
    FAIL=$((FAIL + 1))
  fi
  note "logs in $LOGDIR"
  say "RESULT: pass=$PASS fail=$FAIL timeout=$TIMEOUT skipped=$SKIP"
  [ "$FAIL" -eq 0 ] && [ "$TIMEOUT" -eq 0 ]
  exit $?
}

# run_step NAME TIMEOUT EXPECTED CMD...
# PASS iff CMD exits 0 within TIMEOUT, its output contains EXPECTED and
# has no line starting with FAIL. Output goes to $LOGDIR/NAME.log; on
# failure its last lines are shown.
run_step() {
  local name=$1 to=$2 want=$3 rc
  shift 3
  local log="$LOGDIR/$name.log"
  timeout "$to" "$@" >"$log" 2>&1 </dev/null
  rc=$?
  if [ "$rc" -eq 124 ]; then
    tmout "$name" "$to"
  elif [ "$rc" -ne 0 ]; then
    fail "$name" "exit $rc"
  elif grep -q '^FAIL[: ]' "$log"; then
    fail "$name" "output has a FAIL line: $(grep -m1 '^FAIL[: ]' "$log")"
  elif ! grep -qF -- "$want" "$log"; then
    fail "$name" "expected text [$want] is missing"
  else
    pass "$name"
    return 0
  fi
  say "--- last 30 lines of $log"
  tail -n 30 "$log" | tee -a "$SUMMARY"
  say "--- end"
  return 1
}

# gate_results NAME MIN: print the leak-suite RESULT lines of a gate log
# (pipe run and pty run) and require each to have 0 failed and at least
# MIN passed.
gate_results() {
  local name=$1 min=$2 log="$LOGDIR/$1.log" n=0 line passed failed
  while IFS= read -r line; do
    n=$((n + 1))
    say "$name leak suite run $n: $line"
    passed=$(printf '%s' "$line" | sed -n 's/^RESULT: \([0-9]*\) passed, \([0-9]*\) failed.*/\1/p')
    failed=$(printf '%s' "$line" | sed -n 's/^RESULT: \([0-9]*\) passed, \([0-9]*\) failed.*/\2/p')
    if [ -n "$passed" ] && [ "$failed" = 0 ] && [ "$passed" -ge "$min" ]; then
      pass "$name leak suite run $n: $passed passed (>= $min), 0 failed"
    else
      fail "$name leak suite run $n" "[$line] (want >= $min passed, 0 failed)"
    fi
  done < <(grep '^RESULT: ' "$log")
  [ "$n" -ge 1 ] || fail "$name leak suite" "no RESULT line in $log"
  say "$name: $(grep '^release-gate: summary' "$log" | tail -n 1)"
  grep '^WEAK' "$log" | sort -u | sed "s/^/$name: /" | tee -a "$SUMMARY"
}

note "logs in $LOGDIR"
note "step 1: build"
run_step build 1800 "Finished" cargo build --release
if [ ! -x "$HISN" ]; then
  fail "build produced the binary" "$HISN is not executable"
  finish
fi
note "binary under test: $HISN ($("$HISN" --version 2>&1 | head -n 1)), kernel $(uname -r)"

note "step 2: release gate without a rootfs"
if run_step release-gate-plain 3000 "release-gate: summary" \
  env -u HISN_TEST_ROOTFS -u HISN_BIG_TESTS make release-gate; then
  gate_results release-gate-plain 371
fi

note "step 2b: release gate with a rootfs and the big import test"
ROOTFS=${HISN_TEST_ROOTFS:-$("$HISN" rootfs path wakil-dev 2>/dev/null </dev/null || true)}
if [ -n "$ROOTFS" ] && [ -d "$ROOTFS/usr" ]; then
  note "rootfs: $ROOTFS"
  if run_step release-gate-rootfs 3600 "release-gate: summary" \
    env HISN_TEST_ROOTFS="$ROOTFS" HISN_BIG_TESTS="${HISN_BIG_TESTS:-1}" make release-gate; then
    gate_results release-gate-rootfs 384
  fi
else
  skip "release-gate-rootfs" "no rootfs: set HISN_TEST_ROOTFS, or import one as wakil-dev (hisn rootfs import wakil-dev --from-tar FILE)"
fi

note "step 3: hermetic open-mode cases (unshare -Urn; nothing leaves the machine)"
if ! command -v ip >/dev/null 2>&1 || ! timeout 10 unshare -Urn true 2>/dev/null; then
  fail "net cases" "unshare -Urn or the ip command is not available on this machine"
else
  mkdir -p "$TMP/net"
  NETLOG="$LOGDIR/net-cases.log"
  timeout 900 unshare -Urn bash "$ROOT/tests/leak/net_cases.sh" "$HISN" "$TMP/net" "$TOKEN" \
    </dev/null >"$NETLOG" 2>&1
  RC=$?
  NP=0 NF=0
  while IFS= read -r line; do
    case "$line" in
      "PASS  "*) NP=$((NP + 1)); pass "${line#PASS  }" ;;
      "FAIL: "*)
        NF=$((NF + 1))
        rest=${line#FAIL: }
        fail "${rest%% -- *}" "${rest#* -- }"
        ;;
      "INFO    "*) ;; # journal records: in the log, not repeated here
      "INFO  "*) say "$line" ;;
    esac
  done <"$NETLOG"
  TRAILER=$(grep '^NET-CASES: ' "$NETLOG" | tail -n 1)
  if [ "$RC" -eq 124 ]; then
    tmout "net cases complete" 900
  elif [ "$TRAILER" != "NET-CASES: pass=$NP fail=$NF" ]; then
    fail "net cases complete" "summary [$TRAILER] does not match the $NP PASS and $NF FAIL lines read (exit $RC)"
  elif [ "$RC" -ne 0 ] && [ "$NF" -eq 0 ]; then
    fail "net cases complete" "net_cases.sh exited $RC without a FAIL line"
  else
    pass "net cases complete: $NP passed, $NF failed, summary line agrees"
  fi
fi

note "step 4: real network"
if [ "$REAL" -ne 1 ]; then
  skip "real network" "run with --real (the only step that sends traffic off the machine)"
  finish
fi

# One open session, DNS upstream discovered from this machine's files.
R="$TMP/real"
mkdir -p "$R/run" "$R/state" "$R/cwd"
chmod 700 "$R/run"
cp "$HELPER" "$R/cwd/net_helper.py"
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$R/cwd" >"$R/open.toml"
rhisn() { XDG_RUNTIME_DIR="$R/run" XDG_STATE_HOME="$R/state" timeout "$1" "$HISN" "${@:2}" </dev/null; }
rfield() { rhisn 20 ls --json 2>/dev/null | python3 "$HELPER" ls-get "$REAL_ID" "$1"; }
rexec() { rhisn 60 exec --no-tty --session "$REAL_ID" -- "$@" 2>&1; }

REAL_ID="$TOKEN-real"
XDG_RUNTIME_DIR="$R/run" XDG_STATE_HOME="$R/state" \
  "$HISN" run --policy "$R/open.toml" --session-id "$REAL_ID" -- sleep 900 </dev/null >"$LOGDIR/real-session.log" 2>&1 &
for _ in $(seq 100); do [ "$(rfield state)" = running ] && break; sleep 0.1; done
RDIR=$(rfield dir)
if [ "$(rfield state)" != running ] || [ ! -r "$RDIR/supervisor.pid" ]; then
  fail "real: open session starts" "not running: [$(cat "$LOGDIR/real-session.log")]"
  finish
fi
cut -d' ' -f1 "$RDIR/supervisor.pid" >>"$PIDS"
pass "real: open session starts with this machine's DNS upstream"
RWS=$(rfield workspace.id)

# real_check NAME EXPECTED CMD...: PASS iff the command, run inside the
# session, exits 0, prints EXPECTED and prints no FAIL: line.
real_check() {
  local name=$1 want=$2 out rc
  shift 2
  out=$(rexec "$@")
  rc=$?
  printf '%s\n--- exit %s\n' "$out" "$rc" >>"$LOGDIR/real-steps.log"
  if [ "$rc" -ne 0 ]; then
    fail "$name" "exit $rc: [$out]"
  elif printf '%s\n' "$out" | grep -q '^FAIL:'; then
    fail "$name" "[$out]"
  elif ! printf '%s\n' "$out" | grep -q -- "$want"; then
    fail "$name" "expected [$want], got [$out]"
  else
    pass "$name"
  fi
}

TARGET=${HISN_REAL_TARGET:-1.1.1.1}
real_check "real: TCP connect to $TARGET:53" "^TCP-OK $TARGET:53" python3 net_helper.py in-tcp "$TARGET" 53
real_check "real: github.com resolves through the session resolver" "^RESOLVE-OK github.com " python3 net_helper.py in-resolve github.com
if [ -x /usr/bin/curl ]; then
  real_check "real: curl -sI https://github.com" "^HTTP/" /usr/bin/curl -sI --max-time 30 https://github.com
else
  skip "real: curl -sI https://github.com" "/usr/bin/curl is not installed"
fi
if [ -x /usr/bin/git ]; then
  real_check "real: git ls-remote https://github.com/treeol/hisn" "^[0-9a-f]\{40\}" /usr/bin/git ls-remote https://github.com/treeol/hisn HEAD
else
  skip "real: git ls-remote https://github.com/treeol/hisn" "/usr/bin/git is not installed (a session sees /usr, not a git elsewhere)"
fi
GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
if [ -n "$GATEWAY" ]; then
  real_check "real: LAN gateway $GATEWAY:80 is refused EACCES" "^REFUSED-OK" python3 net_helper.py in-refused "$GATEWAY" 80
else
  skip "real: LAN gateway is refused EACCES" "no default route found"
fi

sleep 1
say "real session network journal records:"
XDG_RUNTIME_DIR="$R/run" XDG_STATE_HOME="$R/state" timeout 20 "$HISN" journal --workspace "$RWS" --json </dev/null 2>/dev/null |
  python3 "$HELPER" journal-dump | tee "$LOGDIR/real-journal.jsonl" | python3 -c '
import json, sys
for line in sys.stdin:
    r = json.loads(line); d = r["data"]
    if r["kind"] == "network/connect":
        print("  connect  %-7s %-20s %s" % (d["verdict"], d["reason"], d["target"]))
    elif r["kind"] == "network/dns":
        print("  dns      %-7s %-20s %s %s via %s" % (d["verdict"], d["rcode"], d["name"], d["qtype"], d["upstream"]))
    else:
        print("  summary  " + json.dumps(d, sort_keys=True))' | tee -a "$SUMMARY"
N_ALLOW=$(python3 "$HELPER" journal-count kind=network/connect verdict=allow target="$TARGET:53" <"$LOGDIR/real-journal.jsonl")
if [ "$N_ALLOW" = 1 ]; then
  pass "real: journal has the allow record for $TARGET:53"
else
  fail "real: journal has the allow record for $TARGET:53" "$N_ALLOW matching records, want 1"
fi

if rhisn 30 stop --session "$REAL_ID" >/dev/null 2>&1; then
  pass "real: session stops cleanly"
else
  fail "real: session stops cleanly" "hisn stop exited non-zero"
fi
REAL_ID=""
finish

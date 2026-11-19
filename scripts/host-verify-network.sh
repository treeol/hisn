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
#      open-mode cases (L90, L94, L96-L100, L102-L107, L109-L117,
#      L119-L124). No traffic leaves the machine.
#   4. only with --real: one open session against the real network (TCP
#      to 1.1.1.1:53, DNS, curl, git, node fetch and Go http.Get to
#      github.com (L118), and the LAN gateway, which must be refused).
#      This is the only step that sends traffic off the machine.
#
# Node and Go (L117, L118): tests/leak/net_tools.sh takes the machine's
# own `node` and `go` from PATH, outside any session, builds the Go
# clients statically and copies them and the node binary into the
# session's working directory. If a tool is not installed on this
# machine its cases print a SKIP that names it; everything else must
# still pass.
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
  for sid in ${REAL_ID:-} ${TIMING_IDS:-}; do
    [ -n "$sid" ] || continue
    XDG_RUNTIME_DIR="$TMP/timing/run" XDG_STATE_HOME="$TMP/timing/state" \
      timeout 20 "$HISN" stop --session "$sid" </dev/null >/dev/null 2>&1
    XDG_RUNTIME_DIR="$TMP/real/run" XDG_STATE_HOME="$TMP/real/state" \
      timeout 20 "$HISN" stop --session "$sid" </dev/null >/dev/null 2>&1
  done
  if [ -n "${REAL_ID:-}" ]; then
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
  # Quoted log lines are indented: a nested PASS/FAIL line must not be
  # counted by the tally in finish().
  tail -n 30 "$log" | sed 's/^/    | /' | tee -a "$SUMMARY"
  say "--- end"
  return 1
}

# gate_results NAME MIN: print the leak-suite RESULT lines of a gate log
# (pipe run and pty run) and require each to have 0 failed and at least
# MIN passed, and the open-mode network cases to have run in each.
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
  # The open-mode cases must have run in every leak-suite run of the
  # gate; the pass count alone would not show that they were skipped.
  local net
  net=$(grep -c '^PASS  net cases complete' "$log")
  if [ "$n" -ge 1 ] && [ "$net" -eq "$n" ]; then
    pass "$name: the open-mode network cases ran in all $n leak suite runs"
  else
    fail "$name: the open-mode network cases ran in every leak suite run" "$net of $n runs have the line [PASS  net cases complete]"
  fi
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
  NP=0 NF=0 NS=0
  while IFS= read -r line; do
    case "$line" in
      "PASS  "*) NP=$((NP + 1)); pass "${line#PASS  }" ;;
      "SKIP  "*)
        NS=$((NS + 1))
        rest=${line#SKIP  }
        skip "${rest%% -- *}" "${rest#* -- }"
        ;;
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
  elif [ "$TRAILER" != "NET-CASES: pass=$NP fail=$NF skip=$NS" ]; then
    fail "net cases complete" "summary [$TRAILER] does not match the $NP PASS, $NF FAIL and $NS SKIP lines read (exit $RC)"
  elif [ "$RC" -ne 0 ] && [ "$NF" -eq 0 ]; then
    fail "net cases complete" "net_cases.sh exited $RC without a FAIL line"
  else
    pass "net cases complete: $NP passed, $NF failed, summary line agrees"
  fi
fi

# 0.6.1 timing probe (INFO only, never a gate, never counted): median of
# 5 `run --detach` until `ls --json` reports state=running, and the mean
# of 20 `exec --no-tty -- true`, for network=none, network=open, and a
# rootfs session when the rootfs is present. Own work directory; every
# session is stopped on every exit path (TIMING_IDS, stopped by cleanup).
# Runs before the real-network step so it happens with and without --real.
timing_probe() {
  local mode=$1 extra=$2 label=${3:-$1}
  T="$TMP/timing"
  mkdir -p "$T/run" "$T/state" "$T/cwd"
  chmod 700 "$T/run"
  cp "$HELPER" "$T/cwd/net_helper.py"
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "%s"\n%b\n' \
    "$T/cwd" "$mode" "$extra" >"$T/policy.toml"
  th() { XDG_RUNTIME_DIR="$T/run" XDG_STATE_HOME="$T/state" timeout 30 "$HISN" "$@" </dev/null; }
  local starts=() execs=() detach_ms=() sid st ms
  for _ in 1 2 3 4 5; do
    sid="$TOKEN-timing-$label"
    rm -rf "$T/state"
    mkdir -p "$T/run" "$T/state"; chmod 700 "$T/run"
    t0=$(date +%s%N)
    if th run --detach --policy "$T/policy.toml" --session-id "$sid" >/dev/null 2>&1; then
      tr=$(date +%s%N)
      detach_ms+=("$(( (tr - t0) / 1000000 ))")
      TIMING_IDS="$sid"
      for _ in $(seq 300); do
        st=$(XDG_RUNTIME_DIR="$T/run" XDG_STATE_HOME="$T/state" timeout 10 "$HISN" ls --json 2>/dev/null |
          python3 "$HELPER" ls-get "$sid" state || true)
        [ "$st" = running ] && break
        sleep 0.1
      done
      t1=$(date +%s%N)
      if [ "$st" = running ]; then
        starts+=("$(( (t1 - t0) / 1000000 ))")
      else
        note "timing $label: session did not reach running"
        starts+=(-1)
      fi
      th stop --session "$sid" >/dev/null 2>&1 || true
      TIMING_IDS=""
    else
      starts+=(-1)
    fi
    rm -rf "$T/state"
  done
  # Median of the successful runs.
  local sorted median
  sorted=$(printf '%s\n' "${starts[@]}" | grep -v '^-1$' | sort -n |
    awk '{a[NR]=$1} END {if (NR>0) print (NR%2 ? a[int(NR/2)+1] : (a[NR/2]+a[NR/2+1])/2); else print "n/a"}')
  median=$sorted
  # Mean of 20 exec true on a fresh session.
  sid="$TOKEN-timing-$label"
  rm -rf "$T/state"
  mkdir -p "$T/run" "$T/state"; chmod 700 "$T/run"
  if th run --detach --policy "$T/policy.toml" --session-id "$sid" >/dev/null 2>&1; then
    TIMING_IDS="$sid"
    for _ in $(seq 300); do
      st=$(XDG_RUNTIME_DIR="$T/run" XDG_STATE_HOME="$T/state" timeout 10 "$HISN" ls --json 2>/dev/null |
        python3 "$HELPER" ls-get "$sid" state || true)
      [ "$st" = running ] && break
      sleep 0.1
    done
    if [ "$st" = running ]; then
      for _ in $(seq 20); do
        t0=$(date +%s%N)
        th exec --no-tty --session "$sid" -- true >/dev/null 2>&1
        t1=$(date +%s%N)
        execs+=("$(( (t1 - t0) / 1000000 ))")
      done
      local sum=0 n=0 v
      for v in "${execs[@]}"; do sum=$((sum + v)); n=$((n + 1)); done
      if [ "$n" -gt 0 ]; then
        say "INFO timing $label: run --detach until ready median ${median} ms (5 runs: ${starts[*]}; run --detach command alone: ${detach_ms[*]} ms; the poll loop adds one hisn ls + python start per 100 ms step), exec --no-tty true mean $((sum / n)) ms (20 runs)"
      else
        say "INFO timing $label: run --detach until ready median ${median} ms, exec: no samples"
      fi
    else
      say "INFO timing $label: session did not reach running (exec timing skipped)"
    fi
    th stop --session "$sid" >/dev/null 2>&1 || true
    TIMING_IDS=""
  else
    say "INFO timing $label: session did not start"
  fi
  rm -rf "$T/state"
}

note "timing probe (INFO only, never a gate)"
timing_probe none ""
timing_probe open ""
if [ -n "${ROOTFS:-}" ] && [ -d "${ROOTFS:-/nonexistent}/usr" ]; then
  timing_probe open "[rootfs]\npath = \"$ROOTFS\"" open+rootfs
else
  skip "timing open+rootfs" "no rootfs: set HISN_TEST_ROOTFS, or import one as wakil-dev"
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
# L118: node fetch() and Go http.Get() to github.com through the
# interception. The clients are prepared outside the session by
# net_tools.sh and run from the session's working directory.
RTOOLS="$R/tools"
bash "$ROOT/tests/leak/net_tools.sh" "$RTOOLS" >"$LOGDIR/real-net-tools.log" 2>&1
tool_state() { [ -r "$1" ] && cut -d' ' -f1 "$1" || echo broken; }
tool_detail() { [ -r "$1" ] && cut -d' ' -f2- "$1" || echo "net_tools.sh wrote no $1"; }
REAL_URL=https://github.com
REAL_CLIENTS=0
L118N="L118 real: node fetch($REAL_URL)"
case "$(tool_state "$RTOOLS/node.status")" in
  ok)
    mkdir -p "$R/cwd/tools" && cp -R "$RTOOLS/node" "$RTOOLS/run-node" "$RTOOLS/lib" "$R/cwd/tools/" &&
      cp "$ROOT/tests/leak/nb_real.js" "$R/cwd/nb_real.js"
    note "node: $(tool_detail "$RTOOLS/node.status")"
    BEFORE=$PASS
    real_check "$L118N" "^NODE-REAL-OK " sh "$R/cwd/tools/run-node" "$R/cwd/nb_real.js" "$REAL_URL"
    [ "$PASS" -gt "$BEFORE" ] && REAL_CLIENTS=$((REAL_CLIENTS + 1))
    ;;
  missing) skip "$L118N" "$(tool_detail "$RTOOLS/node.status")" ;;
  *) fail "$L118N" "$(tool_detail "$RTOOLS/node.status")" ;;
esac
L118G="L118 real: go http.Get($REAL_URL)"
case "$(tool_state "$RTOOLS/go.status")" in
  ok)
    mkdir -p "$R/cwd/tools" && cp "$RTOOLS/nb_real" "$R/cwd/tools/nb_real"
    note "go: $(tool_detail "$RTOOLS/go.status")"
    BEFORE=$PASS
    real_check "$L118G" "^GO-REAL-OK " "$R/cwd/tools/nb_real" "$REAL_URL"
    [ "$PASS" -gt "$BEFORE" ] && REAL_CLIENTS=$((REAL_CLIENTS + 1))
    ;;
  missing) skip "$L118G" "$(tool_detail "$RTOOLS/go.status")" ;;
  *) fail "$L118G" "$(tool_detail "$RTOOLS/go.status")" ;;
esac
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
    elif r["kind"] == "network/connect-result":
        print("  result   %-7s %-20s %s (%s ms)" % ("", d["result"], d["target"], d["latency_ms"]))
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

# L118 journal: every node/go request that passed is an HTTPS connect
# from a non-blocking socket: one allow/injected-inprogress record and
# one connect-result `connected` each, to port 443. (curl and git use
# port 443 too, so the counts are lower bounds.)
if [ "$REAL_CLIENTS" -gt 0 ]; then
  N_INJ=$(python3 "$HELPER" journal-count kind=network/connect verdict=allow reason=injected-inprogress 'target$=:443' <"$LOGDIR/real-journal.jsonl")
  N_RES=$(python3 "$HELPER" journal-count kind=network/connect-result result=connected 'target$=:443' <"$LOGDIR/real-journal.jsonl")
  case "$N_INJ$N_RES" in *[!0-9]*|"") N_INJ=0; N_RES=0 ;; esac
  if [ "$N_INJ" -ge "$REAL_CLIENTS" ] && [ "$N_RES" -ge "$REAL_CLIENTS" ]; then
    pass "L118 real: journal has injected-inprogress ($N_INJ) and connect-result connected ($N_RES) records to port 443 for the $REAL_CLIENTS node/go requests"
  else
    fail "L118 real: journal has the node/go records" "$N_INJ injected-inprogress and $N_RES connect-result connected records to port 443, want at least $REAL_CLIENTS each"
  fi
fi

if rhisn 30 stop --session "$REAL_ID" >/dev/null 2>&1; then
  pass "real: session stops cleanly"
else
  fail "real: session stops cleanly" "hisn stop exited non-zero"
fi
REAL_ID=""
finish

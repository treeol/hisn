#!/usr/bin/env bash
# hisn 0.6.3 host verification: build, unit tests, release gate (plain and
# with a rootfs), and the new machine interface end to end.
#
#   bash scripts/host-verify-0.6.3.sh
#
# First output line: the sha256 of this file (computed from $0).
# Each step prints one line when it starts and one when it ends, with elapsed
# seconds; every step has its own timeout, and a step that hit it is named.
#
# Nothing is installed and sudo is never called. Binaries are built under
# target/ only. The end-to-end step starts only sessions whose id begins with
# "host063-", never uses --name, --prune or --purge, and isolates
# XDG_RUNTIME_DIR and XDG_STATE_HOME in a temp dir of this run. The name
# registry (/tmp/hisn-<uid>/names.json) is outside that isolation (hisn
# 0.6.3 keeps it in a fixed directory); the script checks it did not change.
#
# Last line:
#   HOST-VERIFY-063: pass=<n> fail=<n> timeout=<n> skipped=<n> log=<path>
# Exit status: non-zero on any fail or timeout.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SELF="$ROOT/scripts/host-verify-0.6.3.sh"
echo "sha256 $(sha256sum "$0" | cut -d' ' -f1)  $(basename "$0")"
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

# ===========================================================================
# Part 2: the end-to-end checks, run as `bash host-verify-0.6.3.sh __e2e DIR`
# ===========================================================================
if [ "${1:-}" = "__e2e" ]; then
  W=$2
  HISN="$ROOT/target/debug/hisn"
  RUN="$W/run"; STATE="$W/state"; CWD="$W/cwd"
  mkdir -p "$RUN" "$STATE" "$CWD"; chmod 700 "$RUN" "$W"
  STAMP=$(date -u +%H%M%S)$$
  A="host063-$STAMP-a"; B="host063-$STAMP-b"
  WS="host063-$STAMP"
  UIDN=$(id -u)
  REGFILE="/tmp/hisn-$UIDN/names.json"
  REG_BEFORE=$(stat -c '%Y %s' "$REGFILE" 2>/dev/null || echo none)
  P=0; F=0
  ok()  { P=$((P + 1)); echo "PASS  $1"; }
  bad() { F=$((F + 1)); echo "FAIL: $1 -- $(printf '%s' "${2:-}" | tr '\n' ' ' | head -c 400)"; }
  H() { local t=$1; shift
        XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" timeout "$t" "$HISN" "$@" </dev/null; }
  Hin() { local t=$1; shift   # stdin from the caller's pipe
        XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" timeout "$t" "$HISN" "$@"; }
  py() { python3 -c "$1" "${@:2}"; }
  cleanup() {
    local id
    for id in "$A" "$B"; do
      case "$id" in host063-*) H 30 stop --session "$id" >/dev/null 2>&1 ;; esac
    done
  }
  trap cleanup EXIT
  for n in a b; do
    printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$CWD" >"$W/$n.toml"
  done

  # --- run --detach --json
  out=$(H 60 run --detach --json --policy "$W/a.toml" --session-id "$A" --workspace "$WS" 2>"$W/err")
  rc=$?
  if [ $rc -eq 0 ] && py 'import json,sys; d=json.loads(sys.argv[1]); assert d["schema"]=="hisn-run/v1" and d["id"]==sys.argv[2] and d["state"]=="ready" and d["name"] is None' "$out" "$A" 2>/dev/null; then
    ok "run --detach --json prints a hisn-run/v1 object"
  else bad "run --detach --json" "rc=$rc out=$out err=$(cat "$W/err")"; fi
  # without --json: byte-identical text line
  H 60 run --detach --policy "$W/b.toml" --session-id "$B" --workspace "$WS" >"$W/b.out" 2>&1
  if [ "$(cat "$W/b.out")" = "$B - ready" ]; then ok "run --detach without --json prints '<id> - ready'"
  else bad "run --detach text output" "$(cat "$W/b.out")"; fi
  # a failing start with --json: error object on stderr, exit 125
  H 60 run --detach --json --policy "$W/a.toml" --session-id "$A" --workspace "$WS" >"$W/o" 2>"$W/e"; rc=$?
  if [ $rc -ne 0 ] && py 'import json,sys; d=json.loads(open(sys.argv[1]).read().strip().splitlines()[-1]); assert d["schema"]=="hisn-error/v1" and d["code"]' "$W/e" 2>/dev/null; then
    ok "failing run --detach --json: error object on stderr (exit $rc)"
  else bad "run --detach --json failure" "rc=$rc $(cat "$W/e")"; fi

  # --- ls --json
  H 20 ls --json >"$W/ls.json" 2>/dev/null
  if py '
import json, os, sys
d = json.load(open(sys.argv[1]))
s = [x for x in d["sessions"] if x["id"] == sys.argv[2]][0]
assert isinstance(s["supervisor_pid"], int), s["supervisor_pid"]
os.kill(s["supervisor_pid"], 0)
assert s["pid"] is None
j = s["journal"]
assert j["first_wseq"] >= 1 and j["last_wseq"] >= j["first_wseq"], j
' "$W/ls.json" "$A" 2>"$W/pyerr"; then
    ok "ls --json: supervisor_pid is a live pid, pid stays null, journal first/last wseq"
  else bad "ls --json fields" "$(cat "$W/pyerr")"; fi

  # --- journal --info and the cursor
  H 20 note --session "$A" "cursor one" >/dev/null 2>&1
  info=$(H 20 journal --workspace "$WS" --info 2>&1)
  last=$(py 'import json,sys; d=json.loads(sys.argv[1]); assert d["schema"]=="hisn-journal-info/v1"; print(d["last_wseq"])' "$info" 2>/dev/null)
  if [ -n "$last" ]; then ok "journal --info prints hisn-journal-info/v1 (last_wseq=$last)"
  else bad "journal --info" "$info"; fi
  H 20 note --session "$A" "cursor two" >/dev/null 2>&1
  H 20 note --session "$A" "cursor three" >/dev/null 2>&1
  H 20 journal --session "$A" --after-wseq "${last:-0}" --json >"$W/after.jsonl" 2>"$W/after.err"; rc=$?
  if [ $rc -eq 0 ] && py '
import json, sys
last = int(sys.argv[2])
w = [json.loads(l)["wseq"] for l in open(sys.argv[1])]
assert len(w) >= 2 and w[0] == last + 1 and w == list(range(w[0], w[0] + len(w))), w
' "$W/after.jsonl" "${last:-0}" 2>"$W/pyerr"; then
    ok "journal --after-wseq returns contiguous records starting at last+1"
  else bad "journal --after-wseq" "rc=$rc $(cat "$W/pyerr")"; fi
  H 20 journal --session "$A" --after-wseq 99999999 >/dev/null 2>"$W/e3"; rc=$?
  if [ $rc -eq 3 ]; then ok "journal --after-wseq beyond the journal exits 3"
  else bad "journal exit 3" "rc=$rc $(cat "$W/e3")"; fi
  H 20 journal --session "$A" --after-wseq 99999999 --json >/dev/null 2>"$W/e3"; rc=$?
  if [ $rc -eq 3 ] && py 'import json,sys; d=json.loads(open(sys.argv[1]).read()); assert d["code"]=="E_CURSOR_RESET"' "$W/e3" 2>/dev/null; then
    ok "journal --after-wseq --json reset: hisn-error/v1 E_CURSOR_RESET"
  else bad "journal exit 3 json" "rc=$rc $(cat "$W/e3")"; fi

  # --- seats
  tok=$(H 20 seat --session "$A" --json add alice --role member 2>"$W/e" | py 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="hisn-seat/v1" and d["action"]=="added"; print(d["credential"])' 2>/dev/null)
  if [ -n "$tok" ]; then ok "seat add --json carries the credential once"
  else bad "seat add --json" "$(cat "$W/e")"; fi
  if H 20 seat --session "$A" --json ls 2>/dev/null | py 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="hisn-seat-list/v1" and d["seats"][0]["name"]=="alice"; assert "credential" not in json.dumps(d)' 2>/dev/null; then
    ok "seat ls --json: hisn-seat-list/v1 without credentials"
  else bad "seat ls --json" ""; fi
  if H 20 seat --session "$A" --json set-role alice observer 2>/dev/null | py 'import json,sys; d=json.load(sys.stdin); assert d["action"]=="role-set" and d["role"]=="observer"' 2>/dev/null \
     && H 20 seat --session "$A" --json set-role alice member >/dev/null 2>&1; then
    ok "seat set-role --json"
  else bad "seat set-role --json" ""; fi

  # --- credential on stdin and its journal record
  printf '%s\n' "$tok" | Hin 60 exec --no-tty --seat-token-file - --session "$A" -- true >"$W/x.out" 2>"$W/x.err"; rc=$?
  if [ $rc -eq 0 ]; then ok "exec --no-tty --seat-token-file - runs the program (exit 0)"
  else bad "exec with credential on stdin" "rc=$rc $(cat "$W/x.err")"; fi
  H 20 journal --session "$A" --seat alice --json >"$W/seat.jsonl" 2>/dev/null
  if py '
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
assert any(r["kind"] == "exec/request" for r in recs), [r["kind"] for r in recs]
' "$W/seat.jsonl" 2>"$W/pyerr"; then ok "the journal attributes the exec/request to seat alice"
  else bad "seat attribution in the journal" "$(cat "$W/pyerr")"; fi
  if grep -qF -- "$tok" "$W/seat.jsonl" "$W/x.err" 2>/dev/null; then bad "the credential appears in the journal or stderr" ""
  else ok "the credential appears neither in the journal output nor in stderr"; fi
  printf '%s\n' "$tok" | Hin 60 exec --seat-token-file - --session "$A" -- true >/dev/null 2>"$W/x.err"; rc=$?
  if [ $rc -ne 0 ] && grep -q -- '--no-tty' "$W/x.err"; then ok "exec --seat-token-file - without --no-tty is refused ($rc)"
  else bad "exec - without --no-tty" "rc=$rc $(cat "$W/x.err")"; fi
  printf '\n' | Hin 60 exec --no-tty --seat-token-file - --session "$A" -- true >/dev/null 2>"$W/x.err"; rc=$?
  if [ $rc -ne 0 ] && grep -qi 'empty' "$W/x.err"; then ok "an empty credential line on stdin is refused"
  else bad "empty credential on stdin" "rc=$rc $(cat "$W/x.err")"; fi

  # --- the credential line is read unbuffered: what follows stays on the pipe
  rest=$( { printf '%s\nREST-OF-PIPE\n' "$tok" | { Hin 60 exec --no-tty --seat-token-file - --session "$A" -- true >/dev/null 2>&1; cat; }; } )
  if [ "$rest" = "REST-OF-PIPE" ]; then ok "--seat-token-file - leaves the rest of stdin unread"
  else bad "stdin read-ahead" "left: [$rest]"; fi

  # --- the error object of a failing call
  H 20 stop --session "host063-nosuch" --json >"$W/o" 2>"$W/e"; rc=$?
  if [ $rc -eq 125 ] && py 'import json,sys; d=json.loads(open(sys.argv[1]).read()); assert d["schema"]=="hisn-error/v1" and d["code"] and d["message"]' "$W/e" 2>/dev/null; then
    ok "stop --json on an unknown session: exit 125 and a hisn-error/v1 object"
  else bad "error object" "rc=$rc $(cat "$W/e")"; fi
  H 20 stop --session "host063-nosuch" >/dev/null 2>"$W/e"; rc=$?
  if [ $rc -eq 125 ] && grep -q '^hisn: ' "$W/e"; then ok "stop without --json keeps the plain 'hisn: ...' error (exit 125)"
  else bad "plain error text" "rc=$rc $(cat "$W/e")"; fi

  # --- exec diagnostics: exit record fields, and a killed client
  H 60 exec --no-tty --session "$A" -- sh -c 'exit 7' >/dev/null 2>&1; rc=$?
  [ $rc -eq 7 ] && ok "exec exit status 7 propagates" || bad "exec exit status" "rc=$rc"
  XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE" "$HISN" exec --no-tty --session "$A" -- sleep 300 </dev/null >/dev/null 2>&1 &
  cpid=$!
  sleep 2; kill -9 "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null
  sleep 7
  H 20 journal --session "$A" --kind exec/exit --json >"$W/exit.jsonl" 2>/dev/null
  if py '
import json, sys
recs = [json.loads(l)["data"] for l in open(sys.argv[1])]
assert recs, "no exec/exit"
for d in recs:
    assert d["exec_id"].startswith("e-") and isinstance(d["pid"], int) and isinstance(d["attach"], bool), d
assert any(d.get("exit_code") == 7 for d in recs), recs
assert any(d.get("cancelled") or d.get("signal") for d in recs), "killed exec not recorded"
' "$W/exit.jsonl" 2>"$W/pyerr"; then ok "exec/exit records carry exec_id, pid, attach; code 7 and the killed exec are recorded"
  else bad "exec/exit records" "$(cat "$W/pyerr") $(tail -c 300 "$W/exit.jsonl")"; fi

  # --- stop: outcome object and the session/stop cause
  H 60 stop --session "$A" --json >"$W/stop.out" 2>"$W/stop.err"; rc=$?
  if [ $rc -eq 0 ] && py 'import json,sys; d=json.loads(open(sys.argv[1]).read()); assert d["schema"]=="hisn-stop/v1" and d["outcome"] in ("stopped","ended-before-stop")' "$W/stop.out" 2>/dev/null; then
    ok "stop --json prints a hisn-stop/v1 object ($(py 'import json,sys; print(json.loads(open(sys.argv[1]).read())["outcome"])' "$W/stop.out"))"
  else bad "stop --json" "rc=$rc $(cat "$W/stop.out") $(cat "$W/stop.err")"; fi
  H 20 journal --workspace "$WS" --session "$A" --kind session/stop --json >"$W/stop.jsonl" 2>/dev/null
  if py '
import json, sys
d = [json.loads(l)["data"] for l in open(sys.argv[1])][-1]
assert d["cause"] == "stop-request", d
assert "duration_ms" in d and ("exit_code" in d or "signal" in d), d
' "$W/stop.jsonl" 2>"$W/pyerr"; then ok "session/stop after hisn stop: cause stop-request with status and duration"
  else bad "session/stop cause after stop" "$(cat "$W/pyerr") $(tail -c 300 "$W/stop.jsonl")"; fi
  H 20 stop --session "$A" --json >"$W/o" 2>/dev/null
  if py 'import json,sys; assert json.loads(open(sys.argv[1]).read())["outcome"]=="not-live"' "$W/o" 2>/dev/null; then
    ok "stop --json on a stopped session: outcome not-live (exit 0)"
  else bad "stop of a stopped session" "$(cat "$W/o")"; fi

  # --- a command that exits by itself: cause command-exit
  H 60 stop --session "$B" >/dev/null 2>&1
  C="host063-$STAMP-c"
  H 120 run --policy "$W/b.toml" --session-id "$C" --workspace "$WS" -- sh -c 'exit 3' >/dev/null 2>&1; rc=$?
  H 20 journal --workspace "$WS" --session "$C" --kind session/stop --json >"$W/c.jsonl" 2>/dev/null
  if py '
import json, sys
d = [json.loads(l)["data"] for l in open(sys.argv[1])][-1]
assert d["cause"] == "command-exit" and d["exit_code"] == 3, d
' "$W/c.jsonl" 2>"$W/pyerr"; then ok "session/stop after a command that exits 3: command-exit, exit_code 3 (run exit $rc)"
  else bad "session/stop cause command-exit" "rc=$rc $(cat "$W/pyerr") $(tail -c 300 "$W/c.jsonl")"; fi

  # --- a command killed by a signal: cause command-signal, SIGKILL
  D="host063-$STAMP-d"
  H 120 run --policy "$W/b.toml" --session-id "$D" --workspace "$WS" -- sh -c 'kill -9 $$' >/dev/null 2>&1; rc=$?
  H 20 journal --workspace "$WS" --session "$D" --kind session/stop --json >"$W/d.jsonl" 2>/dev/null
  if py '
import json, sys
d = [json.loads(l)["data"] for l in open(sys.argv[1])][-1]
assert d["cause"] == "command-signal" and d["signal"] == 9 and d["signal_name"] == "KILL", d
' "$W/d.jsonl" 2>"$W/pyerr"; then ok "session/stop after a command killed by SIGKILL: command-signal, signal 9 (run exit $rc)"
  else bad "session/stop cause command-signal" "rc=$rc $(cat "$W/pyerr") $(tail -c 300 "$W/d.jsonl")"; fi

  # --- run --json without --detach is refused; ls --json errors are objects
  H 20 run --json --policy "$W/b.toml" -- true >/dev/null 2>"$W/e"; rc=$?
  [ $rc -ne 0 ] && ok "run --json without --detach is refused (exit $rc)" || bad "run --json without --detach" "rc=$rc"
  H 20 ls --json --session host063-nosuch >/dev/null 2>"$W/e"; rc=$?
  if [ $rc -ne 0 ] && py 'import json,sys; d=json.loads(open(sys.argv[1]).read().strip().splitlines()[-1]); assert d["schema"]=="hisn-error/v1"' "$W/e" 2>/dev/null; then
    ok "ls --json on an unknown session: hisn-error/v1 object (exit $rc)"
  else bad "ls --json error object" "rc=$rc $(cat "$W/e")"; fi

  # --- the readable journal shows the cause
  if H 20 journal --workspace "$WS" --session "$C" 2>/dev/null | grep -q 'session stopped (command-exit, exit 3)'; then
    ok "the readable journal shows 'session stopped (command-exit, exit 3)'"
  else bad "readable session/stop line" "$(H 20 journal --workspace "$WS" --session "$C" 2>&1 | tail -n 3)"; fi

  # --- a hole in the journal: exit 4 (last, it edits the journal file)
  JF=$(ls "$STATE"/hisn/workspaces/*/journal.jsonl 2>/dev/null | head -n 1)
  if [ -n "$JF" ] && [ "$(wc -l <"$JF")" -gt 6 ]; then
    cp "$JF" "$W/journal.bak"
    sed -i '3d' "$JF"
    H 20 journal --workspace "$WS" --after-wseq 0 >/dev/null 2>"$W/e4"; rc=$?
    if [ $rc -eq 4 ]; then ok "a hole in the journal: --after-wseq exits 4"
    else bad "journal exit 4" "rc=$rc $(cat "$W/e4")"; fi
    cp "$W/journal.bak" "$JF"
  else bad "journal exit 4" "no journal file with enough records found under the isolated state"; fi

  # --- rootfs list --json
  H 20 rootfs list --json 2>/dev/null | py 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="hisn-rootfs-list/v1" and isinstance(d["rootfs"], list)' 2>/dev/null \
    && ok "rootfs list --json" || bad "rootfs list --json" ""

  # --- the registry did not change
  REG_AFTER=$(stat -c '%Y %s' "$REGFILE" 2>/dev/null || echo none)
  if [ "$REG_BEFORE" = "$REG_AFTER" ]; then ok "/tmp/hisn-<uid>/names.json did not change"
  else bad "registry file changed" "$REG_BEFORE -> $REG_AFTER"; fi
  echo "E2E: pass=$P fail=$F"
  [ "$F" -eq 0 ]
  exit $?
fi

# ===========================================================================
# Part 1: the steps
# ===========================================================================
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR="$ROOT/.wakil/host-logs/$TS-063"
mkdir -p "$LOGDIR" || exit 1
SUMMARY="$LOGDIR/summary.log"
: >"$SUMMARY"
TMP=$(mktemp -d /tmp/hisn-hv063.XXXXXX) || exit 1
PASS=0 FAIL=0 TIMEOUT=0 SKIP=0
say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
trap 'rm -rf "$TMP"' EXIT
trap 'exit 143' TERM INT HUP

# step NAME TIMEOUT EXPECTED CMD... : PASS iff exit 0 within TIMEOUT, the log
# contains EXPECTED and no line starts with FAIL. Prints start and end lines
# with elapsed seconds; names a step that timed out.
step() {
  local name=$1 to=$2 want=$3 rc t0 t1 log="$LOGDIR/$1.log"
  shift 3
  t0=$(date +%s)
  say "step $name: start (timeout ${to}s)"
  timeout "$to" "$@" >"$log" 2>&1 </dev/null
  rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 124 ]; then
    TIMEOUT=$((TIMEOUT + 1)); FAIL=$((FAIL + 1))
    say "step $name: TIMEOUT after $((t1 - t0))s (limit ${to}s)"
  elif [ "$rc" -ne 0 ]; then
    FAIL=$((FAIL + 1)); say "step $name: FAIL exit $rc after $((t1 - t0))s"
  elif grep -q '^FAIL[: ]' "$log"; then
    FAIL=$((FAIL + 1)); say "step $name: FAIL ($(grep -m1 '^FAIL[: ]' "$log" | head -c 200)) after $((t1 - t0))s"
  elif ! grep -qF -- "$want" "$log"; then
    FAIL=$((FAIL + 1)); say "step $name: FAIL expected text [$want] missing after $((t1 - t0))s"
  else
    PASS=$((PASS + 1)); say "step $name: PASS in $((t1 - t0))s"
    return 0
  fi
  say "--- last 30 lines of $log"
  tail -n 30 "$log" | sed 's/^/    | /' | tee -a "$SUMMARY"
  say "--- end"
  return 1
}

# counts NAME : passed/failed/skipped counts from the RESULT lines of a gate log
counts() {
  local log="$LOGDIR/$1.log" line n=0
  while IFS= read -r line; do
    n=$((n + 1))
    say "$1 leak suite run $n: $line"
  done < <(grep '^RESULT: ' "$log")
  [ "$n" -ge 1 ] || say "$1: no leak-suite RESULT line"
  say "$1: $(grep '^release-gate: summary' "$log" | tail -n 1)"
}

# unit_counts: passed/failed/ignored summed over the "test result" lines
unit_counts() {
  awk '/^test result:/ { p += $4; f += $6; i += $8 }
       END { printf "unit tests: passed=%d failed=%d ignored=%d\n", p, f, i }' "$LOGDIR/unit-tests.log" | tee -a "$SUMMARY"
}

say "host-verify-0.6.3: kernel $(uname -r), user $(id -un), logs in $LOGDIR"

step build 1800 "Finished" cargo build --locked
BIN="$ROOT/target/debug/hisn"
if [ ! -x "$BIN" ]; then
  say "FAIL: $BIN is missing after the build"
  FAIL=$((FAIL + 1))
else
  say "binary under test: $BIN ($("$BIN" --version 2>&1 | head -n 1))"
fi

step unit-tests 1800 "test result: ok" cargo test --locked
unit_counts

step e2e 900 "E2E: pass=" bash "$SELF" __e2e "$TMP/e2e"
grep -E '^(PASS|FAIL)' "$LOGDIR/e2e.log" | sed 's/^/    e2e: /' | tee -a "$SUMMARY"
E2E_P=$(grep -c '^PASS  ' "$LOGDIR/e2e.log")
E2E_F=$(grep -c '^FAIL: ' "$LOGDIR/e2e.log")
say "e2e checks: passed=$E2E_P failed=$E2E_F"

if command -v script >/dev/null 2>&1; then
  say "pty leg of the gate: \`script\` found"
else
  say "SKIP pty leg of the gate: \`script\` is not installed, the gate skips it"
  SKIP=$((SKIP + 1))
fi

if step release-gate-plain 3000 "release-gate: summary" \
  env -u HISN_TEST_ROOTFS -u HISN_BIG_TESTS make release-gate; then
  counts release-gate-plain
else
  counts release-gate-plain
fi

ROOTFS=${HISN_TEST_ROOTFS:-$("$ROOT/target/release/hisn" rootfs path wakil-dev 2>/dev/null </dev/null || "$BIN" rootfs path wakil-dev 2>/dev/null </dev/null || true)}
if [ -n "$ROOTFS" ] && [ -d "$ROOTFS/usr" ]; then
  say "rootfs: $ROOTFS"
  if step release-gate-rootfs 3600 "release-gate: summary" \
    env HISN_TEST_ROOTFS="$ROOTFS" HISN_BIG_TESTS="${HISN_BIG_TESTS:-1}" make release-gate; then
    counts release-gate-rootfs
  else
    counts release-gate-rootfs
  fi
else
  say "SKIP release-gate-rootfs: no rootfs found (set HISN_TEST_ROOTFS or import one named wakil-dev)"
  SKIP=$((SKIP + 1))
fi

say "log=$LOGDIR"
say "HOST-VERIFY-063: pass=$PASS fail=$FAIL timeout=$TIMEOUT skipped=$SKIP log=$LOGDIR"
[ "$FAIL" -eq 0 ] && [ "$TIMEOUT" -eq 0 ]

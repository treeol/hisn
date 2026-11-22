#!/usr/bin/env bash
# 0.6.4 B3: compatibility with v0.6.3, both directions.
#
# Usage: tests/leak/compat_063.sh NEW_HISN OLD_HISN
#   NEW_HISN  the binary built at this tree
#   OLD_HISN  a binary built from tag v0.6.3 (a git worktree under its own
#             target dir; nothing is installed)
#
# Part 1 (no session): the request lines NEW_HISN sends for every existing
#   command equal the lines OLD_HISN sends, and equal the fixture recorded once
#   from a v0.6.3 build (tests/fixtures/v063-wire.json, see plan section 10.4).
# Part 2 (OLD supervisor, NEW cli): every existing command works; the four
#   revision-4 commands fail with exit 125 and a hisn-error/v1 object with code
#   E_UNSUPPORTED naming the required revision.
# Part 3 (NEW supervisor, OLD cli): start, exec, ls (and its --json parse),
#   note, grant, journal, seat commands and stop work.
#
# Sessions run in a private runtime and state dir under a temp dir; nothing is
# installed and no existing session is touched. Needs unprivileged user
# namespaces: without them parts 2 and 3 print SKIP and the script exits 0 after
# part 1 (the host run is the acceptance evidence for them).
# Output: PASS / FAIL / SKIP lines like the leak suite; exit 1 on any FAIL.
set -u

NEW=$(realpath -e -- "${1:?usage: compat_063.sh NEW_HISN OLD_HISN}") || exit 2
OLD=$(realpath -e -- "${2:?usage: compat_063.sh NEW_HISN OLD_HISN}") || exit 2
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
FIXTURE=$ROOT/tests/fixtures/v063-wire.json

PASSES=0 FAILS=0 SKIPS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %s -- %s\n' "$1" "$2"; }
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP  %s -- %s\n' "$1" "$2"; }

W=$(mktemp -d /tmp/hisn-compat.XXXXXX)
RT=$W/run
ST=$W/state
mkdir -m 700 "$RT" "$ST" "$W/home"
# A grant target outside the runtime dir (the private dirs live under $W).
GR=$(mktemp -d /tmp/hisn-compat-grant.XXXXXX)
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  rm -rf "$W" "$GR"
}
trap cleanup EXIT
trap 'exit 143' TERM INT HUP

# ------------------------------------------------------------------ part 1
python3 "$HERE/compat_wire.py" "$OLD" >"$W/wire-old.json" 2>"$W/wire-old.err"
python3 "$HERE/compat_wire.py" "$NEW" >"$W/wire-new.json" 2>"$W/wire-new.err"
if [ -s "$W/wire-old.json" ] && cmp -s "$W/wire-old.json" "$W/wire-new.json"; then
  pass "B3 wire: every existing command sends the same request as the v0.6.3 CLI"
else
  fail "B3 wire: every existing command sends the same request as the v0.6.3 CLI" \
    "$(diff "$W/wire-old.json" "$W/wire-new.json" | head -c 600)"
fi
if cmp -s "$FIXTURE" "$W/wire-new.json"; then
  pass "B3 wire: the requests equal the fixture recorded from the v0.6.3 build"
else
  fail "B3 wire: the requests equal the fixture recorded from the v0.6.3 build" \
    "$(diff "$FIXTURE" "$W/wire-new.json" | head -c 600)"
fi
if python3 - "$W/wire-new.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d) >= 15 and all(v for v in d.values()), "a case captured nothing"
for name, lines in d.items():
    for l in lines:
        r = json.loads(l)
        assert "detach" not in r, name
        assert r.get("client") is None or r["client"].get("protocol_version") in (None, 3), name
PY
then
  pass "B3 wire: no new key, declared protocol_version stays 3"
else
  fail "B3 wire: no new key, declared protocol_version stays 3" "see $W/wire-new.json"
fi

# ------------------------------------------------------- sessions (parts 2, 3)
if ! unshare -Ur true >/dev/null 2>&1 || ! "$NEW" check >/dev/null 2>&1; then
  skip "B3 live sessions" "this host cannot run hisn sessions"
  printf '\nRESULT: %d passed, %d failed, %d skipped\n' $PASSES $FAILS $SKIPS
  [ "$FAILS" -eq 0 ]
  exit
fi

# h BIN ARGS...: run one command with the private dirs, bounded, no stdin.
h() {
  local bin=$1
  shift
  HOME=$W/home XDG_RUNTIME_DIR=$RT XDG_STATE_HOME=$ST timeout 60 "$bin" "$@" </dev/null
}

# start BIN ID: a detached session with the given supervisor; its cwd is $W/ID
start() {
  local bin=$1 id=$2
  mkdir -p "$W/$id"
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n[mounts]\ngrantable_rw = ["%s"]\n' "$W/$id" "$GR" >"$W/$id.toml"
  if ! h "$bin" run --policy "$W/$id.toml" --session-id "$id" --detach >"$W/$id.start" 2>&1; then
    echo "start of $id failed:"
    sed 's/^/    /' "$W/$id.start"
    return 1
  fi
  local i pf
  for i in $(seq 50); do
    pf=$RT/hisn/$id/supervisor.pid
    if [ -f "$pf" ]; then
      PIDS+=("$(cut -d' ' -f1 <"$pf")")
      return 0
    fi
    sleep 0.1
  done
  return 0
}

# wsid ID: the workspace id recorded in the session's session.json
wsid() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["workspace"]["id"])' "$RT/hisn/$1/session.json"; }

# check NAME CMD...: pass when the command exits 0
check() {
  local name=$1
  shift
  if out=$("$@" 2>&1); then pass "$name"; else fail "$name" "$(printf %s "$out" | head -c 300)"; fi
}

# ------------------------------------------------------------------ part 2
OS=compat-old
if start "$OLD" "$OS"; then
  REV=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("protocol_revision"))' "$RT/hisn/$OS/session.json")
  [ "$REV" = 3 ] && pass "B3 old supervisor records protocol revision 3" || fail "B3 old supervisor records protocol revision 3" "got [$REV]"
  # every existing command, new CLI against the old supervisor
  OUT=$(h "$NEW" exec --no-tty --session "$OS" -- echo compat-hi 2>&1)
  [ "$OUT" = compat-hi ] && pass "B3 new CLI exec against a v0.6.3 supervisor" || fail "B3 new CLI exec against a v0.6.3 supervisor" "[$OUT]"
  RC=0
  h "$NEW" exec --no-tty --session "$OS" -- sh -c 'exit 7' >/dev/null 2>&1 || RC=$?
  [ "$RC" = 7 ] && pass "B3 new CLI exec keeps the program's exit code against v0.6.3" || fail "B3 new CLI exec keeps the program's exit code against v0.6.3" "rc=$RC"
  check "B3 new CLI ls --session against v0.6.3" h "$NEW" ls --session "$OS" --json
  if h "$NEW" ls --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert any(s["id"] == sys.argv[1] for s in d["sessions"])' "$OS"; then
    pass "B3 new CLI ls --json lists the v0.6.3 session"
  else
    fail "B3 new CLI ls --json lists the v0.6.3 session" "not listed"
  fi
  check "B3 new CLI note against v0.6.3" h "$NEW" note --session "$OS" "from the new cli"
  check "B3 new CLI grant against v0.6.3" h "$NEW" grant --session "$OS" "$GR"
  check "B3 new CLI revoke against v0.6.3" h "$NEW" revoke --session "$OS" "$GR"
  check "B3 new CLI inspect against v0.6.3" h "$NEW" inspect --session "$OS" --json
  check "B3 new CLI journal against v0.6.3" h "$NEW" journal --session "$OS"
  check "B3 new CLI journal --info against v0.6.3" h "$NEW" journal --workspace "$(wsid "$OS")" --info
  check "B3 new CLI seat add/ls/revoke" bash -c "
    export HOME='$W/home' XDG_RUNTIME_DIR='$RT' XDG_STATE_HOME='$ST'
    '$NEW' seat --session '$OS' add compat-seat --role member </dev/null >/dev/null &&
    '$NEW' seat --session '$OS' ls </dev/null >/dev/null &&
    '$NEW' seat --session '$OS' revoke compat-seat </dev/null >/dev/null"
  # the revision-4 commands: exit 125, hisn-error/v1, E_UNSUPPORTED, revision named
  for c in "exec --detach --session $OS -- true" \
    "exec-status --session $OS --exec e-0 --json" \
    "exec-output --session $OS --exec e-0 --json" \
    "exec-signal --session $OS --exec e-0 --signal TERM"; do
    RC=0
    # shellcheck disable=SC2086
    h "$NEW" $c >"$W/r4.out" 2>"$W/r4.err" || RC=$?
    if [ "$RC" = 125 ] && python3 - "$W/r4.err" <<'PY'
import json, sys
o = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
assert o["schema"] == "hisn-error/v1" and o["code"] == "E_UNSUPPORTED", o
assert "revision 4" in o["message"], o
PY
    then
      pass "B3 '${c%% --*}' against v0.6.3: exit 125, E_UNSUPPORTED naming revision 4"
    else
      fail "B3 '${c%% --*}' against v0.6.3: exit 125, E_UNSUPPORTED naming revision 4" "rc=$RC err=[$(head -c 300 "$W/r4.err")]"
    fi
  done
  h "$NEW" stop --session "$OS" >/dev/null 2>&1
  [ -d "$RT/hisn/$OS" ] && ! h "$NEW" ls --session "$OS" >/dev/null 2>&1 || true
  check "B3 new CLI stop against v0.6.3 (state stopped or gone)" bash -c "
    ! HOME='$W/home' XDG_RUNTIME_DIR='$RT' XDG_STATE_HOME='$ST' '$NEW' ls --json </dev/null 2>/dev/null |
    python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(s[\"id\"]==\"$OS\" and s[\"state\"]==\"running\" for s in d[\"sessions\"]) else 1)'"
else
  fail "B3 start a v0.6.3 supervisor" "see output above"
fi

# ------------------------------------------------------------------ part 3
NS=compat-new
if start "$NEW" "$NS"; then
  REV=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("protocol_revision"))' "$RT/hisn/$NS/session.json")
  [ "$REV" = 4 ] && pass "B3 new supervisor records protocol revision 4" || fail "B3 new supervisor records protocol revision 4" "got [$REV]"
  OUT=$(h "$OLD" exec --no-tty --session "$NS" -- echo compat-hi 2>&1)
  [ "$OUT" = compat-hi ] && pass "B3 v0.6.3 CLI exec against the new supervisor" || fail "B3 v0.6.3 CLI exec against the new supervisor" "[$OUT]"
  RC=0
  h "$OLD" exec --no-tty --session "$NS" -- sh -c 'exit 5' >/dev/null 2>&1 || RC=$?
  [ "$RC" = 5 ] && pass "B3 v0.6.3 CLI exec keeps the exit code against the new supervisor" || fail "B3 v0.6.3 CLI exec keeps the exit code against the new supervisor" "rc=$RC"
  check "B3 v0.6.3 CLI ls --session against the new supervisor" h "$OLD" ls --session "$NS" --json
  # the old CLI's own parse of ls --json (new fields: incarnation, detached execs)
  h "$NEW" exec --detach --session "$NS" -- sleep 30 >/dev/null 2>&1
  if h "$OLD" ls --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
s = [x for x in d["sessions"] if x["id"] == sys.argv[1]]
assert s and s[0]["state"] == "running"
for k in ("id", "name", "state", "execs", "clients", "journal"):
    assert k in s[0], k' "$NS"; then
    pass "B3 v0.6.3 CLI ls --json parses the new supervisor's reply (with a detached exec)"
  else
    fail "B3 v0.6.3 CLI ls --json parses the new supervisor's reply (with a detached exec)" "see ls --json"
  fi
  check "B3 v0.6.3 CLI note against the new supervisor" h "$OLD" note --session "$NS" "from the old cli"
  check "B3 v0.6.3 CLI grant against the new supervisor" h "$OLD" grant --session "$NS" "$GR"
  check "B3 v0.6.3 CLI journal against the new supervisor" h "$OLD" journal --session "$NS"
  check "B3 v0.6.3 CLI journal --after-wseq against the new supervisor's journal" h "$OLD" journal --session "$NS" --after-wseq 0 --json
  check "B3 v0.6.3 CLI journal --info against the new supervisor's journal" h "$OLD" journal --workspace "$(wsid "$NS")" --info
  check "B3 v0.6.3 CLI seat add/ls/revoke" bash -c "
    export HOME='$W/home' XDG_RUNTIME_DIR='$RT' XDG_STATE_HOME='$ST'
    '$OLD' seat --session '$NS' add compat-seat2 --role member </dev/null >/dev/null &&
    '$OLD' seat --session '$NS' ls </dev/null >/dev/null &&
    '$OLD' seat --session '$NS' revoke compat-seat2 </dev/null >/dev/null"
  # journal: the new CLI reads the same journal the old one does, same records
  A=$(h "$OLD" journal --session "$NS" --json 2>/dev/null | md5sum)
  B=$(h "$NEW" journal --session "$NS" --json 2>/dev/null | md5sum)
  [ "$A" = "$B" ] && pass "B3 journal --json is byte-identical from the v0.6.3 and the new CLI" || fail "B3 journal --json is byte-identical from the v0.6.3 and the new CLI" "$A vs $B"
  A=$(h "$OLD" journal --session "$NS" --after-wseq 1 --json 2>/dev/null | md5sum)
  B=$(h "$NEW" journal --session "$NS" --after-wseq 1 --json 2>/dev/null | md5sum)
  [ "$A" = "$B" ] && pass "B3 journal --after-wseq --json is byte-identical from both CLIs" || fail "B3 journal --after-wseq --json is byte-identical from both CLIs" "$A vs $B"
  h "$OLD" stop --session "$NS" >/dev/null 2>&1
  if h "$OLD" ls --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(1 if any(x["id"] == sys.argv[1] and x["state"] == "running" for x in d["sessions"]) else 0)' "$NS"; then
    pass "B3 v0.6.3 CLI stop ends a new supervisor's session"
  else
    fail "B3 v0.6.3 CLI stop ends a new supervisor's session" "still running"
  fi
else
  fail "B3 start a new supervisor" "see output above"
fi

printf '\nRESULT: %d passed, %d failed, %d skipped\n' $PASSES $FAILS $SKIPS
[ "$FAILS" -eq 0 ]

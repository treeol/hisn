#!/usr/bin/env bash
# hisn 0.6.7 host verification: build, unit tests, the 0.6.4 end-to-end
# checks (detached exec, journal cursor, idle, compat live part), the
# 0.6.5 caller additions, plus the 0.6.7 additions (journal --wait,
# caller agent socket, validate --json multi-error), then the release
# gate (plain and with a rootfs).
#
#   cd <repo> && git switch work/0.6.7 && bash scripts/host-verify-0.6.7.sh
#
# First output line: the sha256 of this file (sha256sum "$0").
# Each step prints one line when it starts and one when it ends, with elapsed
# seconds; every step has its own timeout, and a step that hit it is named.
#
# Nothing is installed and sudo is never called. Binaries are built under
# target/ only (the v0.6.4 comparison binary comes from a git worktree of the
# tag with its own target dir under target/; the worktree is removed at the
# end). The end-to-end steps start only sessions whose id begins with
# "host067-", stop only those, and never use --name, --prune or --purge.
# XDG_RUNTIME_DIR and XDG_STATE_HOME are isolated in a temp dir of this run.
# The name registry (/tmp/hisn-<uid>/names.json) is outside that isolation;
# the script checks that entries with this script's own "host067-" prefix did
# not change across the end-to-end steps (other live sessions may differ).
#
# Steps: build, build-v065, unit-tests, e2e-detached, e2e-idle (five runs,
# each reported), e2e-journal (timing v0.6.5 vs HEAD, unreadable lines),
# e2e-caller (Blocks 1-5 plus the 0.6.7 --wait and validate --json checks
# against host067- sessions), e2e-wait067 (caller agent socket + ssh/sign),
# names-registry, release-gate-plain, release-gate-rootfs (when a rootfs
# named wakil-dev or HISN_TEST_ROOTFS exists). The release gate itself runs
# the net harness (DX cases included) and tests/leak/compat_063.sh; their
# counts are printed from the gate's summary. The pty leg and the
# cross-target lint skip cleanly when `script` or rustup are missing
# (the gate does this itself; this script additionally counts a skip line
# for the pty leg).
#
# Last line:
#   HOST-VERIFY-067: pass=<n> fail=<n> timeout=<n> skipped=<n> log=<path>
# (pass/fail count steps; the checks inside a step are listed in its output).
# Exit status: non-zero on any fail or timeout.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SELF="$ROOT/scripts/host-verify-0.6.7.sh"
sha256sum "$0"
cd "$ROOT" || exit 1
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"
HISN="$ROOT/target/release/hisn"
OLDDIR="$ROOT/target/hv067-v065-wt"
OLDTGT="$ROOT/target/hv067-v065-target"
OLD="$OLDTGT/release/hisn"

# ===========================================================================
# Part 2: sub-commands run as `bash host-verify-0.6.7.sh __<name> DIR [ARG]`
# ===========================================================================
case "${1:-}" in
__detached | __idle | __journal | __caller | __wait067)
  MODE=${1#__}
  W=$2
  RUN="$W/run"; STATE="$W/state"; CWD="$W/cwd"
  mkdir -p "$RUN" "$STATE" "$CWD"; chmod 700 "$RUN" "$W"
  export XDG_RUNTIME_DIR="$RUN" XDG_STATE_HOME="$STATE"
  STAMP=$(date -u +%H%M%S)$$
  P=0; F=0
  ok()  { P=$((P + 1)); echo "PASS  $1"; }
  bad() { F=$((F + 1)); echo "FAIL: $1 -- $(printf '%s' "${2:-}" | tr '\n' ' ' | head -c 500)"; }
  H() { local t=$1; shift; timeout "$t" "$HISN" "$@" </dev/null; }
  jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(d if not isinstance(d,bool) else str(d).lower())' "$1" 2>/dev/null; }
  SESSIONS=()
  cleanup() {
    local id
    for id in "${SESSIONS[@]:-}"; do
      case "$id" in host067-*) H 30 stop --session "$id" >/dev/null 2>&1 ;; esac
    done
  }
  trap cleanup EXIT
  trap 'exit 143' TERM INT HUP
  # policy FILE CWD NETWORK [IDLE]
  policy() {
    printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "%s"\n' "$2" "$3" >"$1"
    [ -n "${4:-}" ] && printf 'idle_timeout = "%s"\n' "$4" >>"$1"
    return 0
  }
  # start_session ID WORKSPACE POLICY: a --detach session with a keeper command
  start_session() {
    SESSIONS+=("$1")
    H 60 run --detach --json --policy "$3" --session-id "$1" --workspace "$2" >"$W/start.$1" 2>&1
  }
  sfield() { H 20 ls --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
s=[x for x in d["sessions"] if x["id"]==sys.argv[1]]
v=s[0] if s else {}
for k in sys.argv[2].split("."):
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else v)' "$1" "$2"; }
  dx() { H 20 exec --detach --session "$1" -- "${@:2}" 2>&1; }          # prints the start object
  dxid() { printf '%s' "$1" | jget exec_id; }
  xstate() { H 20 exec-status --session "$1" --exec "$2" --json 2>/dev/null | jget state; }
  wait_state() { # SESSION ID WANT [TOKEN]
    local i st
    for i in $(seq 150); do
      if [ -n "${4:-}" ]; then st=$(HISN_SEAT_TOKEN="$4" xstate "$1" "$2"); else st=$(xstate "$1" "$2"); fi
      [ "$st" = "$3" ] && return 0
      sleep 0.1
    done
    return 1
  }
  wait_total() { # SESSION ID STREAM
    local i n
    for i in $(seq 150); do
      n=$(H 20 exec-output --session "$1" --exec "$2" --stream "$3" --json 2>/dev/null | jget total)
      [ "${n:-0}" -gt 0 ] 2>/dev/null && return 0
      sleep 0.1
    done
    return 1
  }
  wait_file() { local i; for i in $(seq $(($2 * 10))); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }

  case "$MODE" in
  # ------------------------------------------------------------------------
  detached)
    A="host067-$STAMP-a"; O="host067-$STAMP-o"; S="host067-$STAMP-s"
    WS="host067-$STAMP"
    policy "$W/a.toml" "$CWD" none
    mkdir -p "$W/cwd-o" "$W/cwd-s"
    policy "$W/o.toml" "$W/cwd-o" open
    policy "$W/s.toml" "$W/cwd-s" none
    if ! start_session "$A" "$WS" "$W/a.toml"; then bad "start session A" "$(cat "$W/start.$A")"; echo "E2E: pass=$P fail=$F"; exit 1; fi
    ADIR=$(sfield "$A" dir)

    # --- returns at once, runs, survives the client
    t0=$(date +%s%N)
    out=$(dx "$A" sh -c "echo ran >'$CWD/d1.out'")
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    if printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="hisn-exec-start/v1" and d["exec_id"].startswith("e-") and d["incarnation"] and d["pid"]>0' 2>/dev/null; then
      ok "exec --detach prints hisn-exec-start/v1 (exec_id, incarnation, pid) in ${ms} ms"
    else bad "exec --detach start object" "$out"; fi
    [ "$ms" -lt 5000 ] && ok "exec --detach returned at once (${ms} ms, program not awaited)" || bad "exec --detach returned at once" "${ms} ms"
    if wait_file "$CWD/d1.out" 10 && [ "$(cat "$CWD/d1.out")" = ran ]; then ok "the detached program ran"; else bad "the detached program ran" "no file"; fi
    python3 - "$ADIR/control.sock" "$CWD" <<'PY' >"$W/raw.out" 2>&1
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
req = {"op": "exec", "argv": ["sh", "-c", "sleep 3; echo alive >" + sys.argv[2] + "/d2.out"],
       "cwd": None, "env": {}, "tty": False, "detach": True, "client": {"protocol_version": 4}}
s.sendall((json.dumps(req) + "\n").encode())
assert json.loads(s.makefile().readline())["detached"] is True
s.close()
PY
    if wait_file "$CWD/d2.out" 15 && [ "$(cat "$CWD/d2.out")" = alive ]; then ok "a detached exec survives the death of its client connection"; else bad "survives client death" "$(cat "$W/raw.out")"; fi
    # the CLI process killed with SIGKILL once the program has started (the
    # CLI has normally exited by then; the raw-socket case above is the
    # strict client-death test): the exec goes on and finishes its work
    H 20 exec --detach --session "$A" -- sh -c "touch '$CWD/d2b.started'; sleep 3; echo alive >'$CWD/d2b.out'" >/dev/null 2>&1 &
    cli=$!
    wait_file "$CWD/d2b.started" 10
    kill -9 "$cli" 2>/dev/null; wait "$cli" 2>/dev/null
    if wait_file "$CWD/d2b.out" 15; then ok "a detached exec finishes after SIGKILL of its CLI (sent after the program started)"; else bad "finishes after SIGKILL of its CLI" "no file"; fi

    # --- status, output by offset, signal (owner)
    o=$(dx "$A" sh -c "echo out-1; echo err-1 >&2; sleep 300"); id=$(dxid "$o"); inc=$(printf '%s' "$o" | jget incarnation)
    wait_total "$A" "$id" stdout; wait_total "$A" "$id" stderr
    st=$(H 20 exec-status --session "$A" --exec "$id" --json 2>&1)
    if [ "$(printf '%s' "$st" | jget state)" = running ] && [ "$(printf '%s' "$st" | jget incarnation)" = "$inc" ]; then ok "exec-status: running, incarnation matches"; else bad "exec-status running" "$st"; fi
    so=$(H 20 exec-output --session "$A" --exec "$id" 2>"$W/o.err"); se=$(H 20 exec-output --session "$A" --exec "$id" --stream stderr 2>/dev/null)
    if [ "$so" = out-1 ] && [ "$se" = err-1 ] && grep -q '^next=6' "$W/o.err" && ! grep -q eof "$W/o.err"; then ok "exec-output: separate streams, next=6, no eof while running"; else bad "exec-output streams" "[$so] [$se] [$(cat "$W/o.err")]"; fi
    r=$(H 20 exec-output --session "$A" --exec "$id" --offset 4 2>/dev/null)
    [ "$r" = "1" ] && ok "exec-output --offset 4 returns the rest" || bad "exec-output --offset 4" "[$r]"
    H 20 exec-signal --session "$A" --exec "$id" --signal TERM >/dev/null 2>"$W/sig.err"; rc=$?
    if [ $rc -eq 0 ] && wait_state "$A" "$id" signalled; then
      st=$(H 20 exec-status --session "$A" --exec "$id" --json 2>&1)
      if [ "$(printf '%s' "$st" | jget cause)" = exec-signal ] && [ "$(printf '%s' "$st" | jget signal_name)" = TERM ]; then ok "exec-signal TERM: state signalled, cause exec-signal"; else bad "exec-signal cause" "$st"; fi
    else bad "exec-signal TERM" "rc=$rc $(cat "$W/sig.err")"; fi
    fin=$(H 20 exec-output --session "$A" --exec "$id" --json 2>&1)
    if [ "$(printf '%s' "$fin" | jget eof)" = true ] && [ "$(printf '%s' "$fin" | jget next)" = 6 ]; then ok "finished exec: output readable, eof true"; else bad "eof of a finished exec" "$fin"; fi

    # --- rotation: 20 MiB on stdout, offset 0 is rotated_away, the tail has no gap
    o=$(dx "$A" python3 -c "
import sys
p = b'0123456789abcdef\n'
n = 20 * 1024 * 1024
sys.stdout.buffer.write((p * (n // len(p) + 1))[:n]); sys.stdout.buffer.flush()
sys.stderr.write('rot-err')")
    id=$(dxid "$o")
    if wait_state "$A" "$id" exited; then
      res=$(timeout 150 python3 - "$HISN" "$A" "$id" <<'PY'
import base64, json, subprocess, sys
hisn, sess, eid = sys.argv[1:4]
def out(off):
    r = subprocess.run([hisn, "exec-output", "--session", sess, "--exec", eid, "--offset", str(off), "--json"],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)
PAT = b"0123456789abcdef\n"
r = first = out(0); off = first["offset"]; got = 0; ok = True; eof = False
while True:
    d = base64.b64decode(r["data_b64"])
    if r["offset"] != off or d[:64] != bytes(PAT[(off + i) % 17] for i in range(min(len(d), 64))):
        ok = False; break
    got += len(d); off = r["next"]
    if r["eof"]: eof = True; break
    if not d: break
    r = out(off)
print("rotated_away=%s oldest=%d total=%d contiguous=%s bytes=%d eof=%s late_rotated=%s" % (
    str(first["rotated_away"]).lower(), first["oldest"], first["total"], str(ok).lower(), got,
    str(eof).lower(), str(out(off - 5)["rotated_away"]).lower()))
PY
)
      want="rotated_away=true oldest=8388608 total=20971520 contiguous=true bytes=12582912 eof=true late_rotated=false"
      [ "$res" = "$want" ] && ok "20 MiB output: offset 0 rotated_away, 12 MiB tail contiguous, eof" || bad "rotation" "got [$res] want [$want]"
      e=$(H 20 exec-output --session "$A" --exec "$id" --stream stderr 2>/dev/null)
      [ "$e" = rot-err ] && ok "stderr stayed small and separate" || bad "rotation stderr" "[$e]"
    else bad "20 MiB writer finishes" "$o"; fi

    # --- roles, both signal paths
    seat() { H 20 seat --session "$A" --json add "$1" --role "$2" 2>/dev/null | jget credential; }
    BOB=$(seat hvbob member); DAVE=$(seat hvdave member); CAROL=$(seat hvcarol observer)
    if [ -z "$BOB" ] || [ -z "$DAVE" ] || [ -z "$CAROL" ]; then bad "seat add" "no credential"; else
      o=$(HISN_SEAT_TOKEN="$DAVE" dx "$A" sh -c "echo dave-out; sleep 300"); did=$(dxid "$o"); dpid=$(printf '%s' "$o" | jget pid)
      oo=$(dx "$A" sleep 300); oid=$(dxid "$oo"); opid=$(printf '%s' "$oo" | jget pid)
      wait_total "$A" "$did" stdout
      # exec-signal path
      HISN_SEAT_TOKEN="$BOB" H 20 exec-signal --session "$A" --exec "$did" --signal KILL >/dev/null 2>"$W/e1"; rc=$?
      if [ $rc -eq 125 ] && grep -q E_UNAUTHORIZED "$W/e1" && wait_state "$A" "$did" running; then ok "exec-signal: a member cannot signal another seat's exec"; else bad "member exec-signal other seat" "rc=$rc $(cat "$W/e1")"; fi
      HISN_SEAT_TOKEN="$BOB" H 20 exec-signal --session "$A" --exec "$oid" --signal KILL >/dev/null 2>"$W/e1"; rc=$?
      if [ $rc -eq 125 ] && wait_state "$A" "$oid" running; then ok "exec-signal: a member cannot signal an owner-started exec"; else bad "member exec-signal owner exec" "rc=$rc $(cat "$W/e1")"; fi
      r=$(HISN_SEAT_TOKEN="$BOB" H 20 exec-output --session "$A" --exec "$did" 2>/dev/null)
      [ "$r" = dave-out ] && ok "a member reads another seat's output" || bad "member reads output" "[$r]"
      HISN_SEAT_TOKEN="$CAROL" H 20 exec-status --session "$A" --exec "$did" --json >"$W/e2" 2>&1; rc=$?
      [ $rc -eq 0 ] && [ "$(jget state <"$W/e2")" = running ] && ok "observer reads status" || bad "observer status" "rc=$rc $(cat "$W/e2")"
      HISN_SEAT_TOKEN="$CAROL" H 20 exec-output --session "$A" --exec "$did" >"$W/e3" 2>"$W/e3e"; rc=$?
      [ $rc -eq 125 ] && grep -q E_UNAUTHORIZED "$W/e3e" && ! grep -q dave-out "$W/e3" && ok "observer is refused output" || bad "observer output" "rc=$rc $(cat "$W/e3e")"
      HISN_SEAT_TOKEN="$CAROL" H 20 exec-signal --session "$A" --exec "$did" --signal KILL >/dev/null 2>&1; rc=$?
      [ $rc -eq 125 ] && wait_state "$A" "$did" running && ok "observer cannot exec-signal" || bad "observer exec-signal" "rc=$rc"
      # legacy signal path (raw request): refused for a detached target for every role
      legacy() { # TOKEN-or-empty EXEC_ID PID -> "<err-by-id> <err-by-pid>" with a hint check
        python3 - "$ADIR/control.sock" "$1" "$2" "$3" <<'PY'
import json, socket, sys
sock, tok, eid, pid = sys.argv[1:5]
def ask(extra):
    s = socket.socket(socket.AF_UNIX); s.connect(sock)
    c = {"protocol_version": 3}
    if tok: c["seat_token"] = tok
    req = {"op": "signal", "signal": "KILL", "client": c}; req.update(extra)
    s.sendall((json.dumps(req) + "\n").encode())
    r = json.loads(s.makefile().readline()); s.close(); return r
a = ask({"exec_id": eid}); b = ask({"pid": int(pid)})
print(a.get("error"), "exec-signal" in a.get("message", ""), b.get("error"), "exec-signal" in b.get("message", ""))
PY
      }
      r=$(legacy "" "$did" "$dpid")
      [ "$r" = "E_BAD_REQUEST True E_BAD_REQUEST True" ] && wait_state "$A" "$did" running && ok "legacy signal (owner) by id and pid refuses a detached exec" || bad "legacy signal owner" "[$r]"
      r=$(legacy "$BOB" "$did" "$dpid")
      [ "$r" = "E_BAD_REQUEST True E_BAD_REQUEST True" ] && wait_state "$A" "$did" running && ok "legacy signal (member) by id and pid refuses a detached exec" || bad "legacy signal member" "[$r]"
      r=$(legacy "$CAROL" "$oid" "$opid")
      case "$r" in "E_UNAUTHORIZED "*" E_UNAUTHORIZED "*) wait_state "$A" "$oid" running && ok "legacy signal (observer) is refused as unauthorized" ;; *) bad "legacy signal observer" "[$r]" ;; esac
      HISN_SEAT_TOKEN="$DAVE" H 20 exec-signal --session "$A" --exec "$did" --signal TERM >/dev/null 2>&1; rc=$?
      [ $rc -eq 0 ] && wait_state "$A" "$did" signalled && ok "the starting seat may exec-signal its own exec" || bad "own seat exec-signal" "rc=$rc"
      H 20 exec-signal --session "$A" --exec "$oid" --signal KILL >/dev/null 2>&1; rc=$?
      [ $rc -eq 0 ] && wait_state "$A" "$oid" signalled && ok "the owner may exec-signal any exec" || bad "owner exec-signal" "rc=$rc"
      H 20 journal --session "$A" --json >"$W/j.jsonl" 2>/dev/null
      c=$(python3 -c '
import json,sys
k={}
for l in open(sys.argv[1]):
    r=json.loads(l); k[r["kind"]]=k.get(r["kind"],0)+1
print(k.get("execsignal/refused",0)>=3, k.get("execoutput/refused",0)>=1, k.get("execsignal/delivered",0)>=3)' "$W/j.jsonl")
      [ "$c" = "True True True" ] && ok "journal: execsignal/refused, execoutput/refused, execsignal/delivered" || bad "journal refusals" "[$c]"
    fi

    # --- open mode: the network policy applies to a detached exec
    if start_session "$O" "$WS-o" "$W/o.toml"; then
      o=$(dx "$O" python3 -c "
import socket
s = socket.socket()
try:
    s.connect(('10.1.2.3', 80)); print('CONNECTED')
except OSError as e:
    print('ERRNO', e.errno)")
      id=$(dxid "$o")
      wait_state "$O" "$id" exited
      r=$(H 20 exec-output --session "$O" --exec "$id" 2>/dev/null)
      [ "$r" = "ERRNO 13" ] && ok "open mode: a detached exec's connect to a private address is refused (EACCES)" || bad "open-mode refusal" "[$r] start=[$o]"
      sleep 1
      H 20 journal --session "$O" --json >"$W/jo.jsonl" 2>/dev/null
      c=$(python3 -c '
import json,sys
n=0
for l in open(sys.argv[1]):
    r=json.loads(l); d=r["data"]
    if r["kind"]=="network/connect" and d.get("target")=="10.1.2.3:80" and d.get("verdict")=="refuse" and d.get("reason")=="private-or-unlisted": n+=1
print(n)' "$W/jo.jsonl")
      [ "$c" = 1 ] && ok "journal: network/connect 10.1.2.3:80 refuse private-or-unlisted" || bad "open-mode journal" "records=$c"
      H 30 stop --session "$O" >/dev/null 2>&1
    else bad "start open session" "$(cat "$W/start.$O")"; fi

    # --- session stop ends a detached exec; the journal records the cause
    if start_session "$S" "$WS-s" "$W/s.toml"; then
      o=$(dx "$S" sh -c "sleep 300; true # hv067-marker-$STAMP"); id=$(dxid "$o")
      pgrep -f "hv067-marker-$STAMP" >/dev/null && ok "the detached sleeper runs before the stop" || bad "sleeper runs" "$o"
      H 60 stop --session "$S" >/dev/null 2>&1
      sleep 2
      pgrep -f "hv067-marker-$STAMP" >/dev/null && bad "the detached exec ends at session stop" "still running" || ok "the detached exec ends at session stop"
      H 30 journal --session "$S" --json >"$W/js.jsonl" 2>/dev/null
      c=$(python3 -c '
import json,sys
eid=sys.argv[2]; e=s=False
for l in open(sys.argv[1]):
    r=json.loads(l); d=r["data"]
    if r["kind"]=="exec/exit" and d.get("exec_id")==eid and d.get("cause")=="session-stop": e=True
    if r["kind"]=="session/stop" and any(x.get("exec_id")==eid for x in d.get("detached_execs_ended",[])): s=True
print("exit=%s stop=%s"%(e,s))' "$W/js.jsonl" "$id")
      [ "$c" = "exit=True stop=True" ] && ok "journal: exec/exit cause session-stop, session/stop lists the exec" || bad "stop journal" "[$c] id [$id]"
    else bad "start session S" "$(cat "$W/start.$S")"; fi
    H 30 stop --session "$A" >/dev/null 2>&1
    echo "E2E: pass=$P fail=$F"
    [ "$F" -eq 0 ]
    ;;
  # ------------------------------------------------------------------------
  idle)
    N=${3:-1}
    I="host067-$STAMP-i$N"
    mkdir -p "$W/cwd-i"
    policy "$W/i.toml" "$W/cwd-i" none 3s
    if start_session "$I" "host067-$STAMP-i$N" "$W/i.toml"; then
      o=$(dx "$I" sleep 600); id=$(dxid "$o")
      sleep 8
      if [ "$(sfield "$I" state)" = running ] && [ "$(xstate "$I" "$id")" = running ]; then ok "idle run $N: session with a 3 s idle timeout and a running detached exec is alive after 8 s"; else bad "idle run $N alive" "session=$(sfield "$I" state) exec=$(xstate "$I" "$id")"; fi
      H 20 exec-signal --session "$I" --exec "$id" --signal KILL >/dev/null 2>&1
      gone=1
      for _ in $(seq 200); do [ "$(sfield "$I" state)" != running ] && { gone=0; break; }; sleep 0.2; done
      [ $gone -eq 0 ] && ok "idle run $N: after the exec ended the session idled out ($(sfield "$I" state))" || bad "idle run $N idles out" "still running after 40 s"
    else bad "idle run $N start" "$(cat "$W/start.$I")"; fi
    echo "E2E: pass=$P fail=$F"
    [ "$F" -eq 0 ]
    ;;
  # ------------------------------------------------------------------------
  journal)
    OLDBIN="$OLD"
    ws() { mkdir -p -m 700 "$STATE/hisn/workspaces/$1"; echo "$STATE/hisn/workspaces/$1"; }
    gen() { python3 - "$1" "$2" "${3:-}" "${4:-}" <<'PY'
import json, sys
path, n, bad, drop = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
with open(path, "w") as f:
    for i in range(1, n + 1):
        if drop and i == int(drop):
            continue
        if bad and i == int(bad):
            f.write('{"v":1,"wseq":oops garbage\n'); continue
        f.write(json.dumps({"v": 1, "ts": "2026-11-22T00:00:00Z", "wseq": i, "session": "s", "kind": "note",
                            "data": {"i": i, "pad": "x" * 40}}, separators=(",", ":")) + "\n")
PY
      chmod 600 "$1"; }
    # --- timing and identical output on 100 000 records
    BIG=0000000000000b64
    d=$(ws $BIG); gen "$d/journal.jsonl" 100000
    med() { python3 - "$@" <<'PY'
import statistics, subprocess, sys, time
bins, after, n = sys.argv[1], sys.argv[2], 5
ts = []
for _ in range(n):
    t = time.perf_counter()
    r = subprocess.run([bins, "journal", "--workspace", "0000000000000b64", "--after-wseq", after, "--json"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=120)
    ts.append((time.perf_counter() - t) * 1000)
    assert r.returncode == 0, r.returncode
print("%.1f" % statistics.median(ts))
PY
    }
    if [ ! -x "$OLDBIN" ]; then bad "v0.6.5 binary missing" "$OLDBIN"; else
      "$OLDBIN" journal --workspace $BIG --after-wseq 99990 --json >"$W/old.out" 2>/dev/null </dev/null
      t_cold0=$(date +%s%N)
      H 120 journal --workspace $BIG --after-wseq 99990 --json >"$W/new.out" 2>/dev/null
      cold=$(( ($(date +%s%N) - t_cold0) / 1000000 ))
      if cmp -s "$W/old.out" "$W/new.out" && [ "$(wc -l <"$W/new.out")" = 10 ]; then ok "journal --after-wseq 99990 on 100000 records: v0.6.5 and HEAD output identical (10 records)"; else bad "identical output (tail)" "$(diff "$W/old.out" "$W/new.out" | head -c 300)"; fi
      "$OLDBIN" journal --workspace $BIG --after-wseq 50000 --json >"$W/old2.out" 2>/dev/null </dev/null
      H 120 journal --workspace $BIG --after-wseq 50000 --json >"$W/new2.out" 2>/dev/null
      if cmp -s "$W/old2.out" "$W/new2.out" && [ "$(wc -l <"$W/new2.out")" = 50000 ]; then ok "journal --after-wseq 50000: identical output (50000 records)"; else bad "identical output (half)" "$(wc -l <"$W/old2.out") vs $(wc -l <"$W/new2.out")"; fi
      mo=$(med "$OLDBIN" 99990); mn=$(med "$HISN" 99990)
      echo "INFO  journal --after-wseq 99990, 100000 records, median of 5: v0.6.4 ${mo} ms, HEAD ${mn} ms (HEAD first call, builds the index: ${cold} ms)"
      # At ~2 ms, a 1 ms median difference is noise; tolerate it (the point
      # is that the index is not a regression, not microbenchmarking).
      python3 -c 'import sys; sys.exit(0 if float(sys.argv[2]) <= float(sys.argv[1]) + 1 else 1)' "$mo" "$mn" && ok "HEAD cursor read is within 1 ms of v0.6.5 (${mn} ms vs ${mo} ms)" || bad "HEAD slower" "v0.6.4 ${mo} ms, HEAD ${mn} ms"
    fi
    # --- an unreadable line yields journal/unreadable and the cursor moves on
    U=0000000000000c01
    d=$(ws $U); gen "$d/journal.jsonl" 50 20
    H 30 journal --workspace $U --after-wseq 10 --json >"$W/u.out" 2>"$W/u.err"; rc=$?
    c=$(python3 -c '
import json,sys
rs=[json.loads(l) for l in open(sys.argv[1])]
w=[r["wseq"] for r in rs]
u=[r for r in rs if r["kind"]=="journal/unreadable"]
print(w==list(range(11,51)), len(u), u[0]["wseq"] if u else None)' "$W/u.out" 2>&1)
    [ $rc -eq 0 ] && [ "$c" = "True 1 20" ] && ok "an unreadable line: exit 0, one journal/unreadable record at wseq 20, wseq 11..50 contiguous" || bad "unreadable line" "rc=$rc [$c] $(cat "$W/u.err")"
    H 30 journal --workspace $U --after-wseq 20 --json >"$W/u2.out" 2>/dev/null; rc=$?
    c=$(python3 -c '
import json,sys
w=[json.loads(l)["wseq"] for l in open(sys.argv[1])]
print(w==list(range(21,51)))' "$W/u2.out" 2>&1)
    [ $rc -eq 0 ] && [ "$c" = True ] && ok "the cursor moves on: after wseq 20 returns 21..50, exit 0" || bad "cursor moves on" "rc=$rc [$c]"
    c=$(H 30 journal --workspace $U --info 2>/dev/null | jget unreadable)
    [ "$c" = 1 ] && ok "journal --info reports unreadable=1" || bad "journal --info unreadable" "[$c]"
    G=0000000000000c02
    d=$(ws $G); gen "$d/journal.jsonl" 50 "" 20
    H 30 journal --workspace $G --after-wseq 10 --json >/dev/null 2>"$W/g.err"; rc=$?
    [ $rc -eq 4 ] && grep -q E_CURSOR_GAP "$W/g.err" && ok "a real hole (no corrupt line) is still exit 4, E_CURSOR_GAP" || bad "real hole" "rc=$rc $(cat "$W/g.err")"
    if [ -x "$OLDBIN" ]; then
      "$OLDBIN" journal --workspace $U --after-wseq 10 --json >/dev/null 2>&1 </dev/null; echo "INFO  v0.6.4 on the same corrupt journal: exit $? (the cursor is stuck there)"
    fi
    echo "E2E: pass=$P fail=$F"
    [ "$F" -eq 0 ]
    ;;
  # ------------------------------------------------------------------------
  caller)
    A="host067-$STAMP-a"; WS="host067-$STAMP"
    policy "$W/a.toml" "$CWD" none
    if ! start_session "$A" "$WS" "$W/a.toml"; then bad "start session A" "$(cat "$W/start.$A")"; echo "E2E: pass=$P fail=$F"; exit 1; fi
    ADIR=$(sfield "$A" dir)
    # Block 1: prune while a detached exec is writing -> output complete.
    cat > "$CWD/pump.py" <<'PY'
import sys, time
for i in range(12):
    sys.stdout.buffer.write(b"hv067-line-%02d\n" % i); sys.stdout.buffer.flush()
    time.sleep(0.3)
PY
    o=$(dx "$A" python3 "$CWD/pump.py"); id=$(dxid "$o")
    wait_state "$A" "$id" exited || { bad "pump exec exits" "$o"; }
    for i in 1 2 3; do dx "$A" true >/dev/null; done
    tot=""; eof=""
    for i in $(seq 100); do
      r=$(H 20 exec-output --session "$A" --exec "$id" --offset 0 --json 2>/dev/null)
      eof=$(printf '%s' "$r" | jget eof)
      [ "$eof" = true ] && { tot=$(printf '%s' "$r" | jget total); break; }
      sleep 0.2
    done
    [ "$eof" = true ] && [ "$tot" = 168 ] \
      && ok "Block 1: prune while a pump is writing keeps output complete (168 bytes)" \
      || bad "Block 1: prune while a pump is writing" "eof=$eof total=$tot"
    # Block 1: exec/request carries detach: true (via the public journal API).
    c=$(H 20 journal --workspace "$WS" --json 2>/dev/null | python3 -c '
import json,sys
found=False
for l in sys.stdin:
    try: d=json.loads(l)
    except Exception: continue
    if d.get("kind")=="exec/request" and d.get("data", {}).get("detach"):
        found=True; break
print("detach:true" if found else "missing")' 2>/dev/null)
    [ "$c" = "detach:true" ] && ok "Block 1: exec/request carries detach: true" || bad "Block 1: exec/request detach" "$c"
    # Block 2: oversized request -> exit 125, E_TOO_LARGE naming 65536.
    BIG=$(python3 -c 'print("x" * 70000)')
    out=$(H 20 exec --no-tty --session "$A" -- sh -c "echo $BIG" 2>"$W/big.err"; echo "rc=$?")
    if printf '%s' "$out" | grep -q 'rc=125' && grep -q E_TOO_LARGE "$W/big.err" && grep -q 65536 "$W/big.err"; then
      ok "Block 2: oversized request: exit 125, E_TOO_LARGE naming the limit"
    else bad "Block 2: oversized request" "[$out] [$(cat "$W/big.err")]"; fi
    # Block 3: stdin passthrough under --stdin-limit. (Uses the bare binary:
    # H feeds /dev/null as the CLI's stdin by design.)
    printf 'hv067-in' | timeout 20 "$HISN" exec --no-tty --stdin-limit 1048576 --session "$A" -- cat >"$W/in.out" 2>/dev/null
    [ "$(cat "$W/in.out")" = hv067-in ] && ok "Block 3: stdin passes through under --stdin-limit" || bad "Block 3: stdin passthrough" "[$(cat "$W/in.out")]"
    head -c 1001 /dev/zero | tr '\0' 'z' | timeout 20 "$HISN" exec --no-tty --stdin-limit 1000 --session "$A" -- cat >"$W/in2.out" 2>"$W/in2.err"; rc=$?
    if [ "$rc" = 125 ] && grep -q E_TOO_LARGE "$W/in2.err"; then ok "Block 3: stdin over the cap: exit 125 E_TOO_LARGE"; else bad "Block 3: stdin over the cap" "rc=$rc [$(cat "$W/in2.err")]"; fi
    # Block 4: capabilities (0.6.7: 13 features, the original 11 first).
    caps=$("$HISN" capabilities --json 2>/dev/null)
    c=$(printf '%s' "$caps" | python3 -c '
import json,sys
d=json.load(sys.stdin)
names=[f["name"] for f in d["features"]]
print(d["schema"]=="hisn-capabilities/v1", "detached-exec" in names, "network-open" in names, len(names)==13, names[11]=="journal-wait", names[12]=="caller-agent-socket")' 2>/dev/null)
    [ "$c" = "True True True True True True" ] && ok "Block 4: capabilities schema and 13 features (original 11 first, journal-wait, caller-agent-socket)" || bad "Block 4: capabilities" "[$c]"
    # Block 5: profile validate --json.
    printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\nsession = { hostname = "-bad" }\n' > "$W/cwd/bad.toml"
    pv=$("$HISN" profile validate --json "$W/cwd/bad.toml" 2>/dev/null); rc=$?
    c=$(printf '%s' "$pv" | python3 -c '
import json,sys
d=json.load(sys.stdin)
e=d["errors"][0]
print(d["ok"]==False, e["code"], e.get("path"))' 2>/dev/null)
    [ "$rc" = 125 ] && [ "$c" = "True E_PROFILE_VALUE session.hostname" ] && ok "Block 5: profile validate --json names the path" || bad "Block 5: profile validate --json" "rc=$rc [$c]"
    printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\n' > "$W/cwd/good.toml"
    pv=$("$HISN" profile validate --json "$W/cwd/good.toml" 2>/dev/null)
    printf '%s' "$pv" | grep -q '"ok": true' && ok "Block 5: a valid profile validates ok:true" || bad "Block 5: valid profile" "[$pv]"
    # 0.6.7 (C4): validate --json reports all post-parse errors.
    printf 'version = "wrong"\n[policy]\nversion = "hisn-policy/v1"\n[[services]]\nname = ""\nexec = ["true"]\n[[forward]]\nname = "f"\nsocket = "relative"\nexpose = "/x"\n' > "$W/cwd/multi.toml"
    pv=$("$HISN" profile validate --json "$W/cwd/multi.toml" 2>/dev/null); rc=$?
    c=$(printf '%s' "$pv" | python3 -c '
import json,sys
d=json.load(sys.stdin)
msgs=[e["message"] for e in d["errors"]]
print(d["ok"]==False, len(msgs)>=3, any("version" in m for m in msgs), any("name must not be empty" in m for m in msgs), any("absolute path" in m for m in msgs))' 2>/dev/null)
    [ "$rc" = 125 ] && [ "$c" = "True True True True True" ] && ok "0.6.7: profile validate --json reports all errors (version, service, forward)" || bad "0.6.7: validate --json multi-error" "rc=$rc [$c] [$pv]"
    # 0.6.7: journal --wait wakes on a later append, exit 0.
    info=$(H 20 journal --workspace "$WS" --info 2>/dev/null)
    las=$(printf '%s' "$info" | jget last_wseq)
    ( sleep 0.5; H 20 note --workspace "$WS" "hv067-wait-wake-$STAMP" >/dev/null 2>&1 ) &
    wout=$(timeout 10 "$HISN" journal --workspace "$WS" --after-wseq "${las:-0}" --wait 8 --kind note 2>"$W/w.err"); wrc=$?
    if [ $wrc -eq 0 ] && printf '%s' "$wout" | grep -q "hv067-wait-wake-$STAMP"; then
      ok "0.6.7: journal --wait wakes on a later append and exits 0"
    else bad "0.6.7: journal --wait wakes" "rc=$wrc out=[$(printf '%s' "$wout" | head -c 200)] err=[$(cat "$W/w.err")]"; fi
    # 0.6.7: journal --wait timeout exits 6 with E_WAIT_TIMEOUT.
    werr=$(timeout 10 "$HISN" journal --workspace "$WS" --after-wseq 989999 --wait 1 2>&1); wrc=$?
    if [ $wrc -eq 6 ] && printf '%s' "$werr" | grep -q E_WAIT_TIMEOUT; then
      ok "0.6.7: journal --wait timeout exits 6 with E_WAIT_TIMEOUT"
    else bad "0.6.7: journal --wait timeout" "rc=$wrc [$werr]"; fi
    # 0.6.7: --wait 0 is an immediate poll (exit 6, no sleep).
    werr=$(timeout 10 "$HISN" journal --workspace "$WS" --after-wseq 989999 --wait 0 2>&1); wrc=$?
    [ $wrc -eq 6 ] && ok "0.6.7: journal --wait 0 is an immediate poll (exit 6)" || bad "0.6.7: wait 0 poll" "rc=$wrc [$werr]"
    echo "E2E: pass=$P fail=$F"
    [ "$F" -eq 0 ]
    ;;
  # ------------------------------------------------------------------------
  # 0.6.7: caller-provided ssh-agent socket + ssh/sign journaling.
  # Two throwaway agents (host one = env SSH_AUTH_SOCK, caller one = the
  # flag). The flag's agent must win; the sign journals an ssh/sign record
  # with fingerprint/seat/exec id and no payload; add/remove are refused.
  wait067)
    if ! command -v ssh-agent >/dev/null 2>&1 || ! command -v ssh-add >/dev/null 2>&1 \
       || ! command -v ssh-keygen >/dev/null 2>&1; then
      echo "SKIP  0.6.7 caller agent socket (ssh-agent/ssh-add/ssh-keygen missing)"
      echo "E2E: pass=$P fail=$F"; exit 0
    fi
    SAVED_SOCK="${SSH_AUTH_SOCK:-}"; SAVED_PID="${SSH_AGENT_PID:-}"
    unset SSH_AUTH_SOCK SSH_AGENT_PID
    eval "$(ssh-agent -s 2>/dev/null)" >/dev/null 2>&1
    HOST_SOCK="${SSH_AUTH_SOCK:-}"; HOST_PID="${SSH_AGENT_PID:-}"
    mkdir -p "$W/keys"
    ssh-keygen -t ed25519 -f "$W/keys/k1" -N "" -q 2>/dev/null
    ssh-keygen -t ed25519 -f "$W/keys/k2" -N "" -q 2>/dev/null
    if [ -n "$HOST_SOCK" ] && [ "$HOST_SOCK" != "$SAVED_SOCK" ] && [ -n "$HOST_PID" ]; then
      ssh-add "$W/keys/k1" >/dev/null 2>&1
    fi
    if [ -z "$HOST_SOCK" ] || [ "$HOST_SOCK" = "$SAVED_SOCK" ] || [ -z "$HOST_PID" ] \
       || [ "$(ssh-add -l 2>/dev/null | grep -c SHA256:)" != 1 ]; then
      echo "SKIP  0.6.7 caller agent socket (host agent fixture unavailable)"
      [ -n "$HOST_PID" ] && kill "$HOST_PID" 2>/dev/null
      echo "E2E: pass=$P fail=$F"; exit 0
    fi
    FP1=$(ssh-keygen -lf "$W/keys/k1.pub" | awk '{print $2}')
    # The caller agent: a second throwaway agent holding only k2.
    eval "$(ssh-agent -s 2>/dev/null)" >/dev/null 2>&1
    CALLER_SOCK="${SSH_AUTH_SOCK:-}"; CALLER_PID="${SSH_AGENT_PID:-}"
    if [ -z "$CALLER_SOCK" ] || [ "$CALLER_SOCK" = "$HOST_SOCK" ] || [ -z "$CALLER_PID" ]; then
      echo "SKIP  0.6.7 caller agent socket (second agent unavailable)"
      kill "$HOST_PID" 2>/dev/null
      echo "E2E: pass=$P fail=$F"; exit 0
    fi
    ssh-add "$W/keys/k2" >/dev/null 2>&1
    FP2=$(ssh-keygen -lf "$W/keys/k2.pub" | awk '{print $2}')
    # Restore the env agent: SSH_AUTH_SOCK points at the host (k1) agent,
    # and the flag hands the session the caller (k2) agent instead.
    export SSH_AUTH_SOCK="$HOST_SOCK" SSH_AGENT_PID="$HOST_PID"
    B="host067-$STAMP-b"; BWS="host067-$STAMP-b"
    mkdir -p "$CWD/pub"
    cp "$W/keys/k2.pub" "$CWD/pub/k2.pub"
    printf 'hv067-sign-marker' >"$CWD/msg"
    {
      printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\n'
      printf '[session]\ncwd = "%s"\n' "$CWD"
      printf '[ssh]\nagent = true\n'
    } >"$W/b.toml"
    if ! H 60 run --detach --json --profile "$W/b.toml" --session-id "$B" --workspace "$BWS" --ssh-agent-socket "$CALLER_SOCK" >"$W/start.$B" 2>&1; then
      bad "0.6.7: session with --ssh-agent-socket starts" "$(cat "$W/start.$B")"
      kill "$HOST_PID" "$CALLER_PID" 2>/dev/null
      echo "E2E: pass=$P fail=$F"; exit 1
    fi
    SESSIONS+=("$B")
    r=$(H 20 exec --no-tty --session "$B" -- ssh-add -l 2>&1)
    if [ "$(printf '%s\n' "$r" | grep -c SHA256:)" = 1 ] && printf '%s' "$r" | grep -q "$FP2" \
       && ! printf '%s' "$r" | grep -q "$FP1"; then
      ok "0.6.7: --ssh-agent-socket wins over SSH_AUTH_SOCK (lists key2 only)"
    else bad "0.6.7: caller socket wins" "[$r]"; fi
    r=$(H 20 exec --no-tty --session "$B" -- ssh-keygen -Y sign -n hisnleak -f "$CWD/pub/k2.pub" "$CWD/msg" 2>&1; echo "rc=$?")
    if printf '%s' "$r" | grep -q 'rc=0' && [ -s "$CWD/msg.sig" ]; then
      ok "0.6.7: sign via the caller socket succeeds"
    else bad "0.6.7: sign via caller socket" "[$r]"; fi
    r=$(H 20 exec --no-tty --session "$B" -- ssh-add "$CWD/pub/k2.pub" 2>&1; echo "rc=$?")
    [ "$(printf '%s' "$r" | grep -o 'rc=[0-9]*' | tail -1)" != "rc=0" ] \
      && ok "0.6.7: ssh-add (add) still refused with the caller socket" \
      || bad "0.6.7: add still refused" "[$r]"
    H 30 journal --workspace "$BWS" --json >"$W/b.jsonl" 2>/dev/null
    c=$(python3 - "$W/b.jsonl" "$FP2" <<'PY'
import json,sys
rec=None
for l in open(sys.argv[1]):
    try: d=json.loads(l)
    except Exception: continue
    if d.get("kind")=="ssh/sign":
        rec=d
if rec is None: print("no-record"); sys.exit(0)
got = (rec["data"].get("fingerprint")==sys.argv[2] and rec["data"].get("result")=="ok"
       and rec["data"].get("exec_id") and str(rec["data"].get("exec_id")).startswith("e-")
       and rec["data"].get("attributed")==True)
print("record-ok" if got else "record-bad:"+json.dumps(rec["data"]))
PY
)
    [ "$c" = "record-ok" ] && ok "0.6.7: ssh/sign record carries fingerprint, exec id, result ok" || bad "0.6.7: ssh/sign record" "[$c]"
    H 30 stop --session "$B" >/dev/null 2>&1
    kill "$HOST_PID" "$CALLER_PID" 2>/dev/null
    echo "E2E: pass=$P fail=$F"
    [ "$F" -eq 0 ]
    ;;
  esac
  exit $?
  ;;
esac

# ===========================================================================
# Part 1: the steps
# ===========================================================================
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR="$ROOT/.wakil/host-logs/$TS-067"
mkdir -p "$LOGDIR" || exit 1
SUMMARY="$LOGDIR/summary.log"
: >"$SUMMARY"
TMP=$(mktemp -d /tmp/hisn-hv067.XXXXXX) || exit 1
PASS=0 FAIL=0 TIMEOUT=0 SKIP=0
say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
cleanup_all() {
  git worktree remove --force "$OLDDIR" >/dev/null 2>&1
  git worktree prune >/dev/null 2>&1
  rm -rf "$TMP" "$OLDTGT"
}
trap cleanup_all EXIT
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

# e2e_lines NAME: the PASS/FAIL/INFO lines of an e2e step and its counts
e2e_lines() {
  local log="$LOGDIR/$1.log"
  grep -E '^(PASS|FAIL|INFO)' "$log" | sed "s/^/    $1: /" | tee -a "$SUMMARY"
  say "$1 checks: passed=$(grep -c '^PASS  ' "$log") failed=$(grep -c '^FAIL: ' "$log")"
}

# gate_counts NAME: the leak-suite, net-harness and compat counts of a gate log
gate_counts() {
  local log="$LOGDIR/$1.log" line n=0
  while IFS= read -r line; do
    n=$((n + 1)); say "$1 RESULT line $n (leak suite, then compat_063): $line"
  done < <(grep '^RESULT: ' "$log")
  [ "$n" -ge 1 ] || say "$1: no RESULT line"
  grep -E '^release-gate: OK (net-harness|compat-063)' "$log" | sed "s/^/$1: /" | tee -a "$SUMMARY"
  grep '^release-gate: SKIP' "$log" | sed "s/^/$1: /" | tee -a "$SUMMARY"
  say "$1: $(grep '^release-gate: summary' "$log" | tail -n 1)"
}

unit_counts() {
  awk '/^test result:/ { p += $4; f += $6; i += $8 }
       END { printf "unit tests: passed=%d failed=%d ignored=%d\n", p, f, i }' "$LOGDIR/unit-tests.log" | tee -a "$SUMMARY"
}

say "host-verify-0.6.7: kernel $(uname -r), user $(id -un), commit $(git rev-parse --short HEAD), logs in $LOGDIR"
REG="/tmp/hisn-$(id -u)/names.json"

step build 1800 "Finished" cargo build --locked --release
if [ ! -x "$HISN" ]; then
  say "FAIL: $HISN is missing after the build"
  FAIL=$((FAIL + 1))
else
  say "binary under test: $HISN ($("$HISN" --version 2>&1 | head -n 1))"
fi

# The v0.6.4 comparison binary: a worktree of the tag, its own target dir.
build_old() {
  git rev-parse -q --verify "refs/tags/v0.6.5^{commit}" >/dev/null \
    || { echo "FAIL: tag v0.6.5 is missing (git fetch --tags)"; return 1; }
  git worktree remove --force "$OLDDIR" >/dev/null 2>&1
  git worktree add --detach "$OLDDIR" v0.6.5 >/dev/null 2>&1 || { echo "FAIL: git worktree add failed"; return 1; }
  (cd "$OLDDIR" && CARGO_TARGET_DIR="$OLDTGT" cargo build --locked --release 2>&1 | tail -n 3) || return 1
  [ -x "$OLD" ] && echo "built: $("$OLD" --version 2>&1 | head -n 1)"
}
export -f build_old
export OLDDIR OLDTGT OLD
step build-v065 1800 "built:" bash -c build_old

step unit-tests 1800 "test result: ok" cargo test --locked
unit_counts

# Snapshot of the name registry entries carrying this script's own prefix,
# taken after the unit tests (they may touch it). Only those entries are
# compared: other live sessions' entries must not fail this check.
reg_snapshot() {
  python3 - "$REG" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("none"); sys.exit(0)
items = d.get("names", d) if isinstance(d, dict) else d
if isinstance(items, dict):
    sel = {k: v for k, v in items.items() if str(k).startswith("host067-")}
else:
    sel = [x for x in items if isinstance(x, dict) and str(x.get("name", "")).startswith("host067-")]
print(json.dumps(sel, sort_keys=True))
PY
}
REG_BEFORE="$(reg_snapshot)"
export HISN OLD
step e2e-detached 900 "E2E: pass=" bash "$SELF" __detached "$TMP/e2e-d"
e2e_lines e2e-detached
for n in 1 2 3 4 5; do
  step "e2e-idle-$n" 240 "E2E: pass=" bash "$SELF" __idle "$TMP/e2e-i$n" "$n"
  e2e_lines "e2e-idle-$n"
done
step e2e-journal 600 "E2E: pass=" bash "$SELF" __journal "$TMP/e2e-j"
e2e_lines e2e-journal
step e2e-caller 900 "E2E: pass=" bash "$SELF" __caller "$TMP/e2e-c"
e2e_lines e2e-caller
step e2e-wait067 900 "E2E: pass=" bash "$SELF" __wait067 "$TMP/e2e-w"
e2e_lines e2e-wait067

REG_AFTER="$(reg_snapshot)"
if [ "$REG_BEFORE" = "$REG_AFTER" ]; then
  PASS=$((PASS + 1)); say "step names-registry: PASS (host067- entries unchanged by the end-to-end steps)"
else
  FAIL=$((FAIL + 1)); say "step names-registry: FAIL (host067- entries changed: [$REG_BEFORE] -> [$REG_AFTER])"
fi

if command -v script >/dev/null 2>&1; then
  say "pty leg of the gate: \`script\` found"
else
  say "SKIP pty leg of the gate: \`script\` is not installed, the gate skips it"
  SKIP=$((SKIP + 1))
fi

step release-gate-plain 3600 "release-gate: summary" \
  env -u HISN_TEST_ROOTFS -u HISN_BIG_TESTS make release-gate
gate_counts release-gate-plain

ROOTFS=${HISN_TEST_ROOTFS:-$("$HISN" rootfs path wakil-dev 2>/dev/null </dev/null || true)}
if [ -n "$ROOTFS" ] && [ -d "$ROOTFS/usr" ]; then
  say "rootfs: $ROOTFS"
  step release-gate-rootfs 3600 "release-gate: summary" \
    env HISN_TEST_ROOTFS="$ROOTFS" HISN_BIG_TESTS="${HISN_BIG_TESTS:-1}" make release-gate
  gate_counts release-gate-rootfs
else
  say "SKIP release-gate-rootfs: no rootfs found (set HISN_TEST_ROOTFS or import one named wakil-dev)"
  SKIP=$((SKIP + 1))
fi

git worktree remove --force "$OLDDIR" >/dev/null 2>&1
git worktree prune >/dev/null 2>&1
say "worktrees left: $(git worktree list | wc -l) (1 = only the repo itself)"
say "log=$LOGDIR"
say "HOST-VERIFY-067: pass=$PASS fail=$FAIL timeout=$TIMEOUT skipped=$SKIP log=$LOGDIR"
[ "$FAIL" -eq 0 ] && [ "$TIMEOUT" -eq 0 ]
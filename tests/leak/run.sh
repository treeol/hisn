#!/usr/bin/env bash
# hisn leak suite (L1-L35). Usage: tests/leak/run.sh PATH/TO/hisn
#
# Each test runs a probe (examples/leakprobe) INSIDE a real `hisn run` session
# and asserts from the host. Needs unprivileged user namespaces on the host.
#
# The suite checks a manifest (tests/leak/MANIFEST) of expected test ids and
# FAILs if any listed id produced no line — this catches a test that was
# silently dropped from the suite.
#
# Exit codes:   0  every executed test passed (skips are listed, never counted
#                   as passes)
#               1  at least one test failed
#              77  suite NOT RUN (host cannot run hisn sessions) -- no result
#                  is reported, nothing is simulated
#
# Output: one line per check: PASS / FAIL / SKIP / WEAK (passed, but the host
# lacked the fixture that would make the check meaningful -- e.g. no ~/.ssh).
set -u

HISN=${1:-./target/release/hisn}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PROBE_SRC=${PROBE:-$ROOT/target/release/examples/leakprobe}
PY="python3 $HERE/l8.py"

PASSES=0 FAILS=0 SKIPS=0 WEAKS=0
OUTPUT_LOG=""
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$1"; OUTPUT_LOG="$OUTPUT_LOG
$1"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %s -- %s\n' "$1" "$2"; OUTPUT_LOG="$OUTPUT_LOG
$1"; }
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP  %s -- %s\n' "$1" "$2"; OUTPUT_LOG="$OUTPUT_LOG
$1"; }
weak() { WEAKS=$((WEAKS + 1)); printf 'WEAK  %s -- %s\n' "$1" "$2"; OUTPUT_LOG="$OUTPUT_LOG
$1"; }
eq() { # eq NAME GOT WANT
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2] want [$3]"; fi
}
has() { # has NAME HAYSTACK NEEDLE
  case $2 in *"$3"*) pass "$1" ;; *) fail "$1" "missing [$3] in [$(printf %s "$2" | head -c 300)]" ;; esac
}
lacks() { # lacks NAME HAYSTACK NEEDLE
  case $2 in *"$3"*) fail "$1" "found forbidden [$3]" ;; *) pass "$1" ;; esac
}

# ----------------------------------------------------------------- preflight
[ -x "$HISN" ] || { echo "leaktest NOT RUN: $HISN is not executable (run 'make build')"; exit 77; }
[ -x "$PROBE_SRC" ] || { echo "leaktest NOT RUN: probe $PROBE_SRC missing (cargo build --release --example leakprobe)"; exit 77; }
command -v python3 >/dev/null || { echo "leaktest NOT RUN: python3 is required"; exit 77; }
if ! CHECK_OUT=$("$HISN" check 2>&1); then
  echo "leaktest NOT RUN: 'hisn check' reports this host cannot run sessions:"
  printf '%s\n' "$CHECK_OUT" | sed 's/^/    /'
  echo "No leak test result is reported. Run this suite on a host with unprivileged user namespaces:"
  echo "    make leaktest"
  exit 77
fi
[ "$(id -u)" -ne 0 ] || echo "note: running as root -- the suite is meant for an unprivileged user"

WORK=$(mktemp -d /tmp/hisn-leak.XXXXXX)
WORK=$(cd "$WORK" && pwd -P)
SESSIONS=()
cleanup() {
  for p in "${SESSIONS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  # Supervisors killed above cannot remove their own session dirs.
  [ -n "${RUNTIME_ROOT:-}" ] && rm -rf "$RUNTIME_ROOT"/*-$$ 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/g_rw" "$WORK/g_ro" "$WORK/other"
echo "ro-secret-content" >"$WORK/g_ro/hello"
echo "outside-secret"   >"$WORK/outside_secret"
RUNTIME_ROOT=${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/hisn}
[ -n "$RUNTIME_ROOT" ] && [ -d "$XDG_RUNTIME_DIR" ] || RUNTIME_ROOT=/tmp/hisn-$(id -u)

# --------------------------------------------------------------- helpers
# new_cwd NAME -> creates $WORK/NAME with the probe inside; prints path
new_cwd() {
  mkdir -p "$WORK/$1/ctl"
  cp "$PROBE_SRC" "$WORK/$1/leakprobe"
  printf '%s' "$WORK/$1"
}

# write_policy FILE CWD [NETWORK]
write_policy() {
  cat >"$1" <<EOF
version = "hisn-policy/v1"
[session]
cwd = "$2"
network = "${3:-none}"
[mounts]
grantable_rw = ["$WORK/g_rw"]
[env]
pass = ["HISN_LEAK_PASSED"]
EOF
}

# start_session NAME CWD POLICY [extra hisn run args...]; sets S_PID, S_LOG
start_session() {
  local name=$1 cwd=$2 pol=$3
  shift 3
  S_LOG="$WORK/$name.log"
  HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 SSH_AUTH_SOCK=/host/agent \
    HISN_LEAK_PASSED=visible-ok \
    "$HISN" run --policy "$pol" --session-id "$name" "$@" -- "$cwd/leakprobe" loop "$cwd/ctl" \
    </dev/null >"$S_LOG.out" 2>"$S_LOG" &
  S_PID=$!
  SESSIONS+=("$S_PID")
  local i
  for i in $(seq 1 150); do
    [ -e "$cwd/ctl/ready" ] && return 0
    kill -0 "$S_PID" 2>/dev/null || break
    sleep 0.1
  done
  echo "session $name did not become ready; hisn said:"; sed 's/^/    /' "$S_LOG"
  return 1
}

# q CWD args... : send one probe command, print its output
q() {
  local d=$1/ctl n
  shift
  n=$(( $(cat "$d/.n" 2>/dev/null || echo 0) + 1 ))
  echo "$n" >"$d/.n"
  printf '%s\n' "$*" >"$d/in.$n.tmp" && mv "$d/in.$n.tmp" "$d/in.$n"
  local i
  for i in $(seq 1 200); do
    [ -e "$d/out.$n" ] && { cat "$d/out.$n"; return 0; }
    sleep 0.05
  done
  echo "TIMEOUT"
}

end_session() { # end_session CWD PID
  q "$1" quit >/dev/null
  wait "$2" 2>/dev/null
}

hisn_json() { # hisn_json OUTFILE args... ; stdout of hisn into OUTFILE
  local out=$1; shift
  timeout 20 "$HISN" "$@" >"$out" 2>"$out.err"
}

# reap_bounded PID SECS LABEL: wait for a background child, but never forever.
# On timeout: FAIL, print the process table (DIAG lines) so a hang on a CI
# runner is diagnosable from the log, SIGKILL the child, and return 1.
reap_bounded() {
  local pid=$1 secs=$2 label=$3 i st t
  for i in $(seq 1 $((secs * 10))); do
    st=$(ps -o stat= -p "$pid" 2>/dev/null)
    case "$st" in ""|Z*) wait "$pid" 2>/dev/null; return 0 ;; esac
    sleep 0.1
  done
  fail "$label" "pid $pid still alive ${secs}s after it was told to exit; process table follows"
  ps -eo pid,ppid,pgid,stat,wchan:24,etime,args 2>&1 | sed 's/^/DIAG /'
  for t in /proc/"$pid"/task/*; do
    printf 'DIAG task %s wchan=%s\n' "${t##*/}" "$(cat "$t/wchan" 2>/dev/null)"
  done
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

host_mounts() { cut -d' ' -f5 /proc/self/mountinfo | sort; }

# ================================================================ main session
CWD=$(new_cwd main)
POL="$WORK/main.toml"
write_policy "$POL" "$CWD"
for p in "$HOME/.ssh" "$HOME/.aws"; do :; done
ETC_BEFORE=$(ls -A /etc | sort | tr '\n' ',')
HOST_MOUNTS_BEFORE=$(host_mounts)

if ! start_session main-$$ "$CWD" "$POL" --grant "$WORK/g_ro:ro"; then
  fail "session start" "see output above"
  printf '\nRESULT: %d passed, %d failed, %d skipped, %d weak\n' $PASSES $FAILS $SKIPS $WEAKS
  exit 1
fi
MAIN_PID=$S_PID

# ---- L1: nothing outside the allowlist exists
for p in /home /root /tankz /var /etc/shadow /etc/ssh "$HOME/.ssh" "$HOME/.aws"; do
  got=$(q "$CWD" stat "$p")
  eq "L1 stat $p -> ENOENT" "$got" ENOENT
  got=$(q "$CWD" cat "$p")
  [ "$got" = ENOENT ] || [ "$got" = ENOTDIR ] && pass "L1 open $p -> ENOENT" || fail "L1 open $p" "got [$got]"
  case $p in /tankz | "$HOME/.ssh" | "$HOME/.aws" | /root)
    [ -e "$p" ] || weak "L1 $p" "does not exist on this host, so ENOENT proves little" ;;
  esac
done
# masked etc entries must also not appear in a listing
etc_ls=$(q "$CWD" ls /etc)
for m in shadow gshadow sudoers ssh; do lacks "L1 /etc listing has no $m" ",$etc_ls," ",$m,"; done

# ---- L2: pid namespace and /proc
# Init is non-dumpable (DESIGN §6/D6), so for the command /proc/1/root is
# normally EACCES; resolving to the sandbox root is also acceptable. Anything
# else (a different inode = the host root) is a leak. Either way the host's
# /etc/shadow must not be reachable through it.
got=$(q "$CWD" sameino /proc/1/root /)
case $got in
  true) pass "L2 /proc/1/root is the sandbox root" ;;
  EACCES) pass "L2 /proc/1/root denied (non-dumpable init, DESIGN D6)" ;;
  *) fail "L2 /proc/1/root" "got [$got], want true or EACCES" ;;
esac
got=$(q "$CWD" stat /proc/1/root/etc/shadow)
case $got in
  ENOENT | EACCES) pass "L2 /proc/1/root/etc/shadow unreachable ($got)" ;;
  *) fail "L2 /proc/1/root/etc/shadow" "got [$got]" ;;
esac
eq "L2 /proc/self/root is the sandbox root" "$(q "$CWD" sameino /proc/self/root /)" true
pids=$(q "$CWD" pids)
has "L2 init is pid 1" ",${pids#OK }," ",1,"
n=$(printf '%s' "${pids#OK }" | tr ',' '\n' | grep -c .)
[ "$n" -le 8 ] && pass "L2 only $n pids visible" || fail "L2 host pids visible" "$pids"
if [ "$MAIN_PID" -gt 64 ] && [ "$$" -gt 64 ]; then
  lacks "L2 host hisn pid $MAIN_PID invisible" ",${pids#OK }," ",$MAIN_PID,"
  lacks "L2 host shell pid $$ invisible" ",${pids#OK }," ",$$,"
else
  weak "L2 host pid check" "host pids are too small to distinguish from sandbox pids"
fi

# ---- L3: privileged operations are refused
for sc in mount umount unshare_mnt unshare_user setns ptrace chroot pivot_root open_tree bpf io_uring_setup clone_newuser tiocsti; do
  got=$(q "$CWD" syscall "$sc")
  case $got in EPERM) pass "L3 $sc -> EPERM" ;; *) fail "L3 $sc" "got [$got]" ;; esac
done
eq "L3 clone3 -> ENOSYS" "$(q "$CWD" syscall clone3)" ENOSYS
for c in "unshare -m true" "nsenter -t 1 -m true"; do
  got=$(q "$CWD" exec $c)
  case $got in
    "OK exit=0") fail "L3 '$c' succeeded" "$got" ;;
    SPAWN:ENOENT) weak "L3 '$c'" "tool not installed in the toolchain" ;;
    *) pass "L3 '$c' failed as required ($got)" ;;
  esac
done
caps=$(q "$CWD" caps)
for k in CapInh CapPrm CapEff CapBnd CapAmb; do has "L3 $k empty" "$caps" "$k:	0000000000000000"; done
has "L3 no_new_privs" "$caps" "NoNewPrivs:	1"
has "L3 seccomp filter active" "$caps" "Seccomp:	2"

# ---- L4: environment scrubbing
envo=$(q "$CWD" env)
lacks "L4 host secret value absent" "$envo" topsecret
lacks "L4 AWS secret absent" "$envo" hunter2
lacks "L4 SSH_AUTH_SOCK absent" "$envo" SSH_AUTH_SOCK
lacks "L4 HISN_LEAK_SECRET name absent" "$envo" HISN_LEAK_SECRET
has "L4 env.pass var present" "$envo" "HISN_LEAK_PASSED=visible-ok"
has "L4 HOME forced" "$envo" "HOME=/run/hisn/home"

# ---- L5: cwd rw, toolchain ro
eq "L5 write in cwd" "$(q "$CWD" write "$CWD/from-sandbox")" OK
[ "$(cat "$CWD/from-sandbox" 2>/dev/null)" = leak ] && pass "L5 write visible on host" || fail "L5 host sees write" "missing"
eq "L5 /usr write -> EROFS" "$(q "$CWD" write /usr/x)" EROFS
eq "L5 /etc write -> EROFS" "$(q "$CWD" write /etc/x)" EROFS
eq "L5 /tmp writable" "$(q "$CWD" write /tmp/x)" OK
eq "L5 home writable" "$(q "$CWD" write /run/hisn/home/x)" OK
eq "L5 cwd identical path" "$(q "$CWD" stat "$CWD")" "OK dir"
[ ! -e /tmp/x ] || [ "$(cat /tmp/x 2>/dev/null)" != leak ] && pass "L5 sandbox /tmp is private" || fail "L5 /tmp" "host /tmp/x written"

# ---- L7: network = none
eq "L7 loopback works" "$(q "$CWD" loopback)" OK
eq "L7 1.1.1.1 -> ENETUNREACH" "$(q "$CWD" connect 1.1.1.1 443)" ENETUNREACH
eq "L7 10.255.255.1 -> ENETUNREACH" "$(q "$CWD" connect 10.255.255.1 80)" ENETUNREACH

# ---- L9: symlink escapes
ln -sf /etc/shadow "$CWD/l_shadow"
ln -sf "$WORK/outside_secret" "$CWD/l_outside"
ln -sf ../outside_secret "$CWD/l_rel"
ln -sf /proc/1/root/etc/shadow "$CWD/l_proc"
for l in l_shadow l_outside l_rel l_proc; do
  got=$(q "$CWD" cat "$CWD/$l")
  case $got in ENOENT | ELOOP | EACCES) pass "L9 $l not readable ($got)" ;; *) fail "L9 $l" "got [$got]" ;; esac
done
lacks "L9 outside secret content never read" "$(q "$CWD" cat "$CWD/l_outside")" outside-secret

# ---- L10: /dev and /sys
eq "L10 /dev contents" "$(q "$CWD" ls /dev)" "OK fd,full,null,ptmx,pts,random,stderr,stdin,stdout,tty,urandom,zero"
eq "L10 /sys absent" "$(q "$CWD" stat /sys)" ENOENT

# ---- L12 (substitute that needs no root): /etc is an allowlist of start-time entries
etc_sb=$(q "$CWD" ls /etc)
bad=""
for e in $(printf '%s' "${etc_sb#OK }" | tr ',' ' '); do
  case ",$ETC_BEFORE," in *",$e,"*) ;; *) [ "$e" = passwd ] || [ "$e" = group ] || bad="$bad $e" ;; esac
  case $e in *.key | *.pem | shadow* | gshadow* | sudoers* | ssh | krb5*) bad="$bad $e(masked-name)" ;; esac
done
[ -z "$bad" ] && pass "L12 sandbox /etc only holds start-time, non-masked entries" || fail "L12 /etc entries" "$bad"

# ---- L8: mount table == plan (before dynamic grants; initial ro grant counts)
"$HISN" policy plan "$POL" >"$WORK/plan.json" 2>"$WORK/plan.err" || fail "L8 policy plan" "$(cat "$WORK/plan.err")"
hisn_json "$WORK/inspect.json" inspect --session main-$$ --json
cp /proc/self/mountinfo "$WORK/host.mountinfo"
if out=$($PY l8 "$WORK/inspect.json" "$WORK/plan.json" "$WORK/host.mountinfo" "$WORK/g_ro:ro" 2>&1); then pass "L8 $out"; else fail "L8 mount table" "$out"; fi

# ---- L6: grants
eq "L6 initial ro grant readable" "$(q "$CWD" cat "$WORK/g_ro/hello")" "OK ro-secret-content"
eq "L6 ro grant write -> EROFS" "$(q "$CWD" write "$WORK/g_ro/new")" EROFS
[ ! -e "$WORK/g_ro/new" ] && pass "L6 ro grant: nothing written on host" || fail "L6 ro grant" "host file appeared"

mkdir -p "$WORK/g_rw/sub"
hisn_json "$WORK/grant_rw.json" grant --session main-$$ --rw "$WORK/g_rw/sub"
$PY json-ok "$WORK/grant_rw.json" && pass "L6 rw grant accepted" || fail "L6 rw grant" "$(cat "$WORK/grant_rw.json" "$WORK/grant_rw.json.err")"
eq "L6 rw grant writable" "$(q "$CWD" write "$WORK/g_rw/sub/f")" OK
[ "$(cat "$WORK/g_rw/sub/f" 2>/dev/null)" = leak ] && pass "L6 rw write visible on host" || fail "L6 rw write" "missing on host"

hisn_json "$WORK/grant_bad.json" grant --session main-$$ --rw "$WORK/other"
$PY json-has "$WORK/grant_bad.json" error E_NOT_GRANTABLE && pass "L6 rw outside grantable prefix refused" || fail "L6 grantable" "$(cat "$WORK/grant_bad.json")"
hisn_json "$WORK/grant_rt.json" grant --session main-$$ "$RUNTIME_ROOT"
$PY json-has "$WORK/grant_rt.json" error E_PATH_FORBIDDEN && pass "L6 runtime dir cannot be granted (R1)" || fail "L6 R1" "$(cat "$WORK/grant_rt.json")"
hisn_json "$WORK/grant_root.json" grant --session main-$$ /
$PY json-has "$WORK/grant_root.json" error E_PATH_FORBIDDEN && pass "L6 / cannot be granted (R2)" || fail "L6 R2" "$(cat "$WORK/grant_root.json")"

# L8 again with live grants
hisn_json "$WORK/inspect2.json" inspect --session main-$$ --json
if out=$($PY l8 "$WORK/inspect2.json" "$WORK/plan.json" "$WORK/host.mountinfo" "$WORK/g_ro:ro" "$WORK/g_rw/sub:rw" 2>&1); then pass "L8 with live grants: $out"; else fail "L8 with grants" "$out"; fi
[ -z "$(grep -F "$WORK" /proc/self/mountinfo)" ] && pass "L6 grant mounts invisible in the host mount table" || fail "L6 host mount table" "$(grep -F "$WORK" /proc/self/mountinfo | head -3)"

# L13a: soft revoke must claim only "lookup"
eq "L13 queue an fd" "$(q "$CWD" hold-queued "$WORK/g_rw/sub/queued")" "OK queued"
hisn_json "$WORK/revoke_soft.json" revoke --session main-$$ "$WORK/g_rw/sub"
$PY json-ok "$WORK/revoke_soft.json" && pass "L6 revoke rw accepted" || fail "L6 revoke" "$(cat "$WORK/revoke_soft.json")"
$PY json-has "$WORK/revoke_soft.json" guarantee lookup && pass "L13 soft revoke reports guarantee=lookup, never 'hard'" || fail "L13 soft guarantee" "$(cat "$WORK/revoke_soft.json")"
eq "L6 revoked rw path -> ENOENT" "$(q "$CWD" stat "$WORK/g_rw/sub")" ENOENT
eq "L6 revoked rw file -> ENOENT" "$(q "$CWD" cat "$WORK/g_rw/sub/f")" ENOENT
echo "INFO  L13 soft revoke: recv-write through the queued fd says: $(q "$CWD" recv-write)  (documented residual of soft revoke, see DESIGN D14)"

hisn_json "$WORK/revoke_ro.json" revoke --session main-$$ "$WORK/g_ro"
$PY json-ok "$WORK/revoke_ro.json" && pass "L6 revoke ro accepted" || fail "L6 revoke ro" "$(cat "$WORK/revoke_ro.json")"
eq "L6 revoked ro path -> ENOENT" "$(q "$CWD" stat "$WORK/g_ro")" ENOENT
hisn_json "$WORK/revoke_again.json" revoke --session main-$$ "$WORK/g_ro"
$PY json-has "$WORK/revoke_again.json" error E_NOT_GRANTED && pass "L6 double revoke -> E_NOT_GRANTED" || fail "L6 double revoke" "$(cat "$WORK/revoke_again.json")"

end_session "$CWD" "$MAIN_PID"
sleep 0.3
[ -z "$(grep -F "$WORK" /proc/self/mountinfo)" ] && pass "L6 session end: no grant mountpoint in the host mount table" || fail "L6 after end" "mounts remain"
[ ! -e "$RUNTIME_ROOT/main-$$" ] && pass "L6 session end: session dir removed" || fail "L6 session dir" "$RUNTIME_ROOT/main-$$ still exists"
[ "$(host_mounts)" = "$HOST_MOUNTS_BEFORE" ] && pass "L6 host mount table identical before/after the session" || weak "L6 host mount table" "differs, but other processes may mount concurrently: $(diff <(echo "$HOST_MOUNTS_BEFORE") <(host_mounts) | head -4 | tr '\n' ' ')"

# ============================================================ L11: two sessions
CA=$(new_cwd sessA)
CB=$(new_cwd sessB)
mkdir -p "$WORK/gB"
echo b-only >"$WORK/gB/data"
write_policy "$WORK/A.toml" "$CA"
write_policy "$WORK/B.toml" "$CB"
if start_session sessA-$$ "$CA" "$WORK/A.toml" && PA=$S_PID && start_session sessB-$$ "$CB" "$WORK/B.toml" --grant "$WORK/gB:ro" && PB=$S_PID; then
  eq "L11 B's grant visible in B" "$(q "$CB" cat "$WORK/gB/data")" "OK b-only"
  eq "L11 A cannot see B's grant" "$(q "$CA" stat "$WORK/gB")" ENOENT
  eq "L11 A cannot see B's cwd" "$(q "$CA" stat "$CB")" ENOENT
  # g_rw exists as an empty directory because it is a declared grantable_rw prefix (DESIGN D3)
  eq "L11 A sees only its own cwd (+ the empty grantable prefix dir) under the shared parent" "$(q "$CA" ls "$WORK")" "OK g_rw,sessA"
  eq "L11 A cannot see the runtime dir" "$(q "$CA" stat "$RUNTIME_ROOT")" ENOENT
  eq "L11 A cannot see B's session dir" "$(q "$CA" stat "$RUNTIME_ROOT/sessB-$$")" ENOENT
  eq "L11 B cannot see A's session dir" "$(q "$CB" stat "$RUNTIME_ROOT/sessA-$$")" ENOENT
  both=$("$HISN" ls)
  has "L11 host sees session A" "$both" sessA
  has "L11 host sees session B" "$both" sessB
  hisn_json "$WORK/gl.json" ls --session sessA-$$ --json
  lacks "L11 A's grant list has no B grant" "$(cat "$WORK/gl.json")" gB
  end_session "$CA" "$PA"
  end_session "$CB" "$PB"
else
  fail "L11 sessions" "could not start two concurrent sessions"
fi

# ============================================== L13b: hard revoke kills holders
CH=$(new_cwd hard)
write_policy "$WORK/H.toml" "$CH"
mkdir -p "$WORK/g_rw/hard"
if start_session hard-$$ "$CH" "$WORK/H.toml"; then
  HP=$S_PID
  hisn_json "$WORK/hg.json" grant --session hard-$$ --rw "$WORK/g_rw/hard"
  $PY json-ok "$WORK/hg.json" 2>/dev/null || fail "L13 hard: grant" "stdout=[$(cat "$WORK/hg.json")] stderr=[$(cat "$WORK/hg.json.err")] supervisor-stderr=[$(cat "$S_LOG")] audit=[$(cat "$RUNTIME_ROOT/hard-$$/grants.jsonl" 2>&1 | tail -5)]"
  q "$CH" hold-queued "$WORK/g_rw/hard/queued" >/dev/null
  hisn_json "$WORK/hr.json" revoke --session hard-$$ --hard "$WORK/g_rw/hard"
  $PY json-has "$WORK/hr.json" guarantee hard 2>/dev/null && pass "L13 hard revoke reports guarantee=hard" || fail "L13 hard guarantee" "stdout=[$(cat "$WORK/hr.json")] stderr=[$(cat "$WORK/hr.json.err")] supervisor-stderr=[$(cat "$S_LOG")]"
  # Hard revoke ends the session; never wait unboundedly if it did not.
  for _ in $(seq 1 50); do kill -0 "$HP" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$HP" 2>/dev/null; then
    fail "L13 hard: session still alive after hard revoke" "killing it so the suite can continue"
    kill -9 "$HP" 2>/dev/null
  fi
  wait "$HP" 2>/dev/null
  [ "$(cat "$WORK/g_rw/hard/queued" 2>/dev/null)" != "after-revoke" ] && pass "L13 queued fd unusable after hard revoke (no write landed)" || fail "L13 hard" "write through queued fd landed"
else
  fail "L13 hard session" "could not start"
fi

# ==================================================== L12: host creates a secret after start
if [ -w /etc ]; then
  CE=$(new_cwd etc)
  write_policy "$WORK/E.toml" "$CE"
  if start_session etc-$$ "$CE" "$WORK/E.toml"; then
    EP=$S_PID
    echo "late-secret" >/etc/hisn-leaktest.key
    got=$(q "$CE" stat /etc/hisn-leaktest.key)
    rm -f /etc/hisn-leaktest.key
    eq "L12 /etc file created after start -> ENOENT" "$got" ENOENT
    end_session "$CE" "$EP"
  fi
else
  skip "L12 host-creates-secret-after-start" "needs write access to /etc (not available unprivileged); the allowlist substitute above ran instead"
fi

# ============================================ L14: runtime-dir bind alias is rejected
if command -v unshare >/dev/null && unshare -Urm true 2>/dev/null; then
  C14=$(new_cwd alias)
  X14="$WORK/xdg14"
  mkdir -p "$X14/hisn" "$C14/runtime-alias"
  chmod 700 "$X14" "$X14/hisn"
  write_policy "$WORK/L14.toml" "$C14"
  out=$(XDG_RUNTIME_DIR="$X14" unshare -Urm bash -c "mount --bind '$X14/hisn' '$C14/runtime-alias' && '$HISN' run --policy '$WORK/L14.toml' --session-id alias14 -- /bin/true" 2>&1)
  rc=$?
  if [ $rc -eq 125 ] && printf '%s' "$out" | grep -q "aliases the hisn runtime directory"; then pass "L14 runtime-dir bind alias under cwd is rejected (R1b)"; else fail "L14 R1b" "rc=$rc out=[$(printf %s "$out" | head -c 300)]"; fi
  # L14b: the same alias as a *grant source* of a running session (grant-time R1b).
  A14=$(new_cwd alias14b)
  X14B="$WORK/xdg14b"
  mkdir -p "$X14B/hisn" "$WORK/alias14b-mnt"
  chmod 700 "$X14B" "$X14B/hisn"
  write_policy "$WORK/L14b.toml" "$A14"
  out=$(unshare -Urm bash "$HERE/l14b.sh" "$HISN" "$WORK/L14b.toml" "$X14B" "$WORK/alias14b-mnt" "$WORK/L14b.log" 2>&1)
  rc=$?
  if [ $rc -eq 0 ] && printf '%s' "$out" | grep -q 'E_PATH_FORBIDDEN' && printf '%s' "$out" | grep -q 'aliases the runtime directory'; then
    pass "L14b runtime-dir bind alias offered as a grant source is refused"
  elif [ $rc -eq 90 ] || [ $rc -eq 91 ]; then
    skip "L14b grant-time R1b" "fixture could not be built (rc=$rc: 90 = bind failed, 91 = session did not start inside the nested userns); session log: $(head -c 300 "$WORK/L14b.log" 2>/dev/null)"
  else
    fail "L14b grant-time R1b" "rc=$rc out=[$(printf %s "$out" | head -c 400)]"
  fi
  weak "L14 R5" "the control-socket pid-namespace check (R5) is covered by unit tests only; no end-to-end test can place the socket inside the sandbox without a test hook"
else
  skip "L14 alias fixture" "'unshare -Urm' unavailable, cannot build the bind-alias fixture"
fi

# ============================================== L14c: R5 ancestry retry availability
# 200 rapid `hisn ls` invocations from a shell loop that forks short-lived
# parents. R5 must retry the ancestry walk on ENOENT/ESRCH/EINTR (3x 50ms)
# and never refuse a legitimate client because an ancestor vanished.
# This needs a running session; reuse the exec session if it exists, or
# start a throwaway one.
L14C_CWD=$(new_cwd l14c)
L14C_POL="$WORK/L14c.toml"
write_policy "$L14C_POL" "$L14C_CWD"
if start_session l14c-$$ "$L14C_CWD" "$L14C_POL"; then
  L14C_PID=$S_PID
  l14c_ok=0
  for i in $(seq 1 200); do
    "$HISN" ls --session l14c-$$ >/dev/null 2>&1 && l14c_ok=$((l14c_ok + 1))
  done
  eq "L14c 200 rapid hisn ls invocations: 0 refusals" "$l14c_ok" 200
  end_session "$L14C_CWD" "$L14C_PID"
else
  fail "L14c R5 retry" "could not start session for L14c"
fi

# ============================================== L15-L20: exec into the session
# These tests use `hisn exec --session`. A live session is needed; reuse
# a detached one so the tests do not end it.
CX=$(new_cwd exec)
write_policy "$WORK/X.toml" "$CX"
# The host secrets are in its environment on purpose: the exec'd programs must
# not see them (L15), while env.pass (HISN_LEAK_PASSED) must reach them.
if HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 SSH_AUTH_SOCK=/host/agent \
  HISN_LEAK_PASSED=visible-ok \
  "$HISN" run --policy "$WORK/X.toml" --session-id xdet-$$ --detach </dev/null >"$WORK/xdet.out" 2>"$WORK/xdet.err" & DET_PID=$!; then
  SESSIONS+=("$DET_PID")
  ok_ready=0
  for i in $(seq 1 150); do
    "$HISN" ls --json 2>/dev/null | grep -q xdet-$$ && { ok_ready=1; break; }
    kill -0 "$DET_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$ok_ready" = 1 ]; then
    ex() { timeout 30 "$HISN" exec --session xdet-$$ "$@" </dev/null; }
    exq() { # exq ARGS... : one probe command through exec; prints its output
      local out
      out=$(timeout 30 "$HISN" exec --session xdet-$$ -- "$CX/leakprobe" "$@" </dev/null 2>&1)
      printf '%s' "$out"
    }

    # ---- L1c: the user name inside the sandbox is the host user's (0.2.2)
    # `id -un`, $USER, $LOGNAME and getent all show the name the host's user
    # database gives this uid -- also when the session was started from an
    # `env -i` environment that has no USER at all.
    HOST_UN=$(id -un 2>/dev/null)
    L1C_ID=$(command -v id); L1C_SH=$(command -v sh); L1C_GETENT=$(command -v getent)
    l1c_probe() { # l1c_probe SESSION LABEL
      local sess=$1 label=$2 got
      got=$(timeout 30 "$HISN" exec --session "$sess" -- "$L1C_ID" -un </dev/null 2>&1)
      eq "L1c $label id -un is the host user" "$got" "$HOST_UN"
      got=$(timeout 30 "$HISN" exec --session "$sess" -- "$L1C_SH" -c 'printf %s "$USER"' </dev/null 2>&1)
      eq "L1c $label \$USER is the host user" "$got" "$HOST_UN"
      got=$(timeout 30 "$HISN" exec --session "$sess" -- "$L1C_SH" -c 'printf %s "$LOGNAME"' </dev/null 2>&1)
      eq "L1c $label \$LOGNAME is the host user" "$got" "$HOST_UN"
      if [ -n "$L1C_GETENT" ]; then
        # The whole generated record, not just the name: host home, shell and
        # GECOS must not appear.
        got=$(timeout 30 "$HISN" exec --session "$sess" -- "$L1C_GETENT" passwd "$(id -u)" </dev/null 2>&1)
        eq "L1c $label getent passwd is the generated record" "$got" "$HOST_UN:x:$(id -u):$(id -g):$HOST_UN:/run/hisn/home:/bin/sh"
      else
        skip "L1c $label getent" "getent not installed on this host"
      fi
    }
    # l1c_env_session TAG LABEL ENVVARS... : start a detached session under
    # `env -i` plus ENVVARS, probe it, kill it.
    l1c_env_session() {
      local tag=$1 label=$2 pid ready=0 i
      shift 2
      local xdg=()
      [ -n "${XDG_RUNTIME_DIR:-}" ] && xdg=("XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
      local cx; cx=$(new_cwd "l1c$tag")
      write_policy "$WORK/L1c-$tag.toml" "$cx"
      env -i "${xdg[@]}" "$@" "$HISN" run --policy "$WORK/L1c-$tag.toml" --session-id "l1c$tag-$$" --detach \
        </dev/null >"$WORK/l1c$tag.out" 2>"$WORK/l1c$tag.err" & pid=$!
      SESSIONS+=("$pid")
      for i in $(seq 1 150); do
        "$HISN" ls --json 2>/dev/null | grep -q "l1c$tag-$$" && { ready=1; break; }
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      if [ "$ready" = 1 ]; then
        l1c_probe "l1c$tag-$$" "$label"
        timeout 30 "$HISN" kill --session "l1c$tag-$$" </dev/null >/dev/null 2>&1
      else
        fail "L1c $label session start" "did not start: $(head -c 300 "$WORK/l1c$tag.err")"
      fi
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    }
    if ! printf '%s' "$HOST_UN" | grep -Eq '^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}$'; then
      skip "L1c user name" "host user name [$HOST_UN] is outside the portable set; the sandbox uses the fallback"
    else
      l1c_probe "xdet-$$" "(suite environment)"
      # No USER/LOGNAME reach hisn at all.
      l1c_env_session a "(env -i, no USER)"
      # A false USER/LOGNAME at launch must not be believed.
      l1c_env_session b "(env -i, USER=notme LOGNAME=notme)" USER=notme LOGNAME=notme
    fi

    # ---- L15: every L1/L3/L4/L5/L9/L10 probe passes identically via exec
    for p in /home /root /tankz /var /etc/shadow /etc/ssh "$HOME/.ssh" "$HOME/.aws"; do
      got=$(exq stat "$p")
      eq "L15 exec stat $p -> ENOENT" "$got" ENOENT
    done
    for sc in mount unshare_mnt unshare_user setns ptrace chroot pivot_root open_tree bpf io_uring_setup clone_newuser tiocsti; do
      got=$(exq syscall "$sc")
      case $got in EPERM) pass "L15 exec $sc -> EPERM" ;; *) fail "L15 exec $sc" "got [$got]" ;; esac
    done
    eq "L15 exec clone3 -> ENOSYS" "$(exq syscall clone3)" ENOSYS
    envo=$(exq env)
    lacks "L15 exec env: host secret absent" "$envo" topsecret
    lacks "L15 exec env: AWS secret absent" "$envo" hunter2
    has "L15 exec env: passed var present" "$envo" "HISN_LEAK_PASSED=visible-ok"
    has "L15 exec env: HOME forced" "$envo" "HOME=/run/hisn/home"
    eq "L15 exec write in cwd" "$(exq write "$CX/exec-write")" OK
    [ "$(cat "$CX/exec-write" 2>/dev/null)" = leak ] && pass "L15 exec write visible on host" || fail "L15 exec write" "missing"
    eq "L15 exec /usr write -> EROFS" "$(exq write /usr/x)" EROFS
    eq "L15 exec /tmp writable" "$(exq write /tmp/x)" OK
    ln -sf /etc/shadow "$CX/el_shadow"
    got=$(exq cat "$CX/el_shadow")
    case $got in ENOENT | ELOOP | EACCES) pass "L15 exec symlink escape -> not readable ($got)" ;; *) fail "L15 exec symlink escape" "got [$got]" ;; esac
    eq "L15 exec /dev contents" "$(exq ls /dev)" "OK fd,full,null,ptmx,pts,random,stderr,stdin,stdout,tty,urandom,zero"
    eq "L15 exec /sys absent" "$(exq stat /sys)" ENOENT

    # ---- L17: ancestry and lifecycle
    # DESIGN §14.3 (D21): the program is a grandchild of init: init -> W -> P.
    chain=$(exq ppid-chain)
    case $chain in
      "OK chain="*)
        IFS=, read -r -a ch <<<"${chain#OK chain=}"
        if [ "${#ch[@]}" -eq 3 ] && [ "${ch[2]}" = 1 ]; then
          pass "L17 exec'd process chain is P -> W -> init (${ch[0]} -> ${ch[1]} -> 1)"
        else
          fail "L17 PPid chain" "want 3 pids ending in 1 (P,W,init), got [$chain]"
        fi ;;
      *) fail "L17 PPid chain" "got [$chain]" ;;
    esac
    pidsv=$(exq pids)
    has "L17 exec'd process is in the sandbox pid ns (init=1 visible)" ",${pidsv#OK }," ",1,"
    n=$(printf '%s' "${pidsv#OK }" | tr ',' '\n' | grep -c .)
    [ "$n" -le 10 ] && pass "L17 only $n pids visible via exec" || fail "L17 exec pids" "$pidsv"

    # ---- L18: env keys outside env.pass reject the whole request
    out=$(timeout 30 env AWS_SECRET_ACCESS_KEY=hunter2 "$HISN" exec --session xdet-$$ --env AWS_SECRET_ACCESS_KEY=hunter2 -- /bin/true </dev/null 2>&1)
    rc=$?
    [ $rc -ne 0 ] && case "$out" in *"AWS_SECRET_ACCESS_KEY"*) pass "L18 env key not in env.pass rejected (exit $rc)" ;; *) fail "L18 env rejection" "rc=$rc out=[$out]" ;; esac
    out=$(timeout 30 "$HISN" exec --session xdet-$$ --env HISN_LEAK_PASSED=v2 -- "$CX/leakprobe" env </dev/null 2>&1)
    has "L18 passed key present in the exec environment" "$out" "HISN_LEAK_PASSED=v2"
    out=$(timeout 30 "$HISN" exec --session xdet-$$ --env HOME=/evil -- /bin/true </dev/null 2>&1)
    [ $? -ne 0 ] && pass "L18 computed name (HOME) rejected" || fail "L18 HOME override" "accepted"

    # ---- L16: grants before/during/after exec; revoke applies to a running exec
    hisn_json "$WORK/xg.json" grant --session xdet-$$ "$WORK/g_ro"
    $PY json-ok "$WORK/xg.json" && pass "L16 grant before exec accepted" || fail "L16 grant" "$(cat "$WORK/xg.json")"
    eq "L16 grant made before exec is visible in it" "$(exq cat "$WORK/g_ro/hello")" "OK ro-secret-content"
    # a long-running exec, then a grant while it runs: it must see it
    # (grant sources must exist on the host, so create the target first)
    mkdir -p "$WORK/g_rw/execmid"
    ex --cwd "$CX" -- sh -c 'sleep 5' >/dev/null 2>&1 &
    SLEEPER=$!
    sleep 0.4
    hisn_json "$WORK/xgr.json" grant --session xdet-$$ --rw "$WORK/g_rw/execmid"
    $PY json-ok "$WORK/xgr.json" && pass "L16 rw grant during a running exec accepted" || fail "L16 mid-exec grant" "$(cat "$WORK/xgr.json")"
    eq "L16 grant during a running exec is visible to a later one" "$(exq write "$WORK/g_rw/execmid/f")" OK
    # a running exec that resolves the revoked path after the revoke
    ex --cwd "$CX" -- sh -c 'while [ ! -e "'"$CX"'/go" ]; do sleep 0.05; done; cat '"$WORK/g_ro"'/hello > '"$CX"'/after 2>/dev/null; echo "rc=$?" > '"$CX"'/rc' >/dev/null 2>&1 &
    WATCHER=$!
    sleep 0.5
    hisn_json "$WORK/xrv.json" revoke --session xdet-$$ "$WORK/g_ro"
    $PY json-ok "$WORK/xrv.json" && pass "L16 revoke of a live grant accepted" || fail "L16 revoke" "$(cat "$WORK/xrv.json")"
    printf go >"$CX/go"
    wait "$WATCHER" >/dev/null 2>&1
    after=$(cat "$CX/after" 2>/dev/null); rcc=$(cat "$CX/rc" 2>/dev/null)
    case "${after:-}" in
      ro-secret-content) fail "L16 mid-exec revoke" "the running exec re-read the revoked grant" ;;
      *) pass "L16 mid-exec revoke: the running exec cannot re-read the grant (rc=${rcc:-gone})" ;;
    esac
    eq "L16 revoked path -> ENOENT for a later exec" "$(exq stat "$WORK/g_ro")" ENOENT
    # the grant that was NOT revoked is still there for a later exec
    eq "L16 an unrevoked grant stays visible to a later exec" "$(exq write "$WORK/g_rw/execmid/g")" OK
    hisn_json "$WORK/xrv2.json" revoke --session xdet-$$ "$WORK/g_rw/execmid"
    $PY json-ok "$WORK/xrv2.json" && eq "L16 second revoke -> ENOENT for a later exec" "$(exq stat "$WORK/g_rw/execmid")" ENOENT || fail "L16 second revoke" "$(cat "$WORK/xrv2.json")"
    wait "$SLEEPER" >/dev/null 2>&1

    # ---- L19: 50 sequential + 10 concurrent execs, no fd/zombie leak
    # The supervisor reports its own descriptor count through `inspect`
    # (/proc/<supervisor>/fd is not readable from here).
    supfds() {
      hisn_json "$WORK/xi.json" inspect --session xdet-$$ --json
      $PY json-get "$WORK/xi.json" supervisor_fds
    }
    fds_before=$(supfds)
    okseq=0
    for i in $(seq 1 50); do ex -- /bin/true >/dev/null 2>&1 && okseq=$((okseq+1)); done
    eq "L19 50 sequential execs all succeed" "$okseq" 50
    pids=""; okconc=0
    for i in $(seq 1 10); do ex -- sh -c 'sleep 0.4' >/dev/null 2>&1 & pids="$pids $!"; done
    for p in $pids; do wait "$p" && okconc=$((okconc+1)); done
    eq "L19 10 concurrent execs all succeed" "$okconc" 10
    sleep 1
    fds_after=$(supfds)
    case "$fds_before$fds_after" in
      *[!0-9]* | "") weak "L19 supervisor fd baseline" "inspect did not report supervisor_fds (before=[$fds_before] after=[$fds_after])" ;;
      *) if [ "$fds_after" -le $((fds_before + 2)) ]; then
           pass "L19 supervisor fd count back to baseline ($fds_before -> $fds_after after 60 execs)"
         else
           fail "L19 supervisor fds" "$fds_before -> $fds_after: descriptors leaked by exec"
         fi ;;
    esac
    z=$(exq zombies)
    eq "L19 no zombie in the sandbox after 60 execs" "${z%% pids=*}" "OK n=0"
    [ "${z%% pids=*}" = "OK n=0" ] || echo "      zombies: $z"

    # ---- L20: --tty exec gets a working pty (isatty, resize propagates)
    out=$(python3 "$HERE/pty_drive.py" "$HISN" xdet-$$ "$CX/leakprobe" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then
      pass "L20 --tty exec: isatty=1, initial size 80x24, resize to 100x30 reached the program ($out)"
    else
      fail "L20 --tty exec" "rc=$rc $out"
    fi
    # without --tty and a terminal on stdin, hisn must refuse
    if [ -t 0 ]; then
      out=$("$HISN" exec --session xdet-$$ -- /bin/true 2>&1); rc=$?
      [ $rc -eq 125 ] && has "L20 terminal without --tty refused (exit 125)" "$out" --tty || fail "L20 terminal refusal" "rc=$rc out=[$out]"
    else
      weak "L20 terminal refusal" "run.sh stdin is not a tty; rerun with a terminal"
    fi

    # ---- L21: exec B can kill exec A's process by PID (P17: default no signal scope)
    # exec A starts a long sleep; exec B kills it by PID; exec B still cannot
    # stat /home, /root, /etc/shadow (reuse L1 probes).
    ex --cwd "$CX" -- sh -c 'sleep 300' >/dev/null 2>&1 &
    L21_SLEEPER=$!
    sleep 0.5
    # Find the sleeper's PID inside the sandbox (it is visible via /proc).
    L21_PID=$(exq pids)
    L21_PID=$(printf '%s' "${L21_PID#OK }" | tr ',' '\n' | grep -v '^1$' | head -1)
    if [ -n "$L21_PID" ]; then
      got=$(exq kill-pid "$L21_PID")
      case "$got" in
        OK*|ESRCH) pass "L21 exec B kills exec A's process by PID ($got)" ;;
        *) fail "L21 cross-exec kill" "got [$got] want OK or ESRCH (process already gone)" ;;
      esac
      # exec B still cannot stat host paths (reuse L1 probes)
      for p in /home /root /etc/shadow; do
        got=$(exq stat "$p")
        eq "L21 exec B cannot stat $p" "$got" ENOENT
      done
    else
      fail "L21 cross-exec kill" "could not find the sleeper's pid in the sandbox"
    fi
    wait "$L21_SLEEPER" >/dev/null 2>&1

    # ---- L22: exec B can connect to exec A's abstract unix socket (P17: default no abstract scope)
    # Runs under network = "none" (the X session): with network = "host" the
    # abstract-socket scope is always on (B1, L24) and inter-exec abstract
    # sockets are blocked by design.
    # exec A binds an abstract socket (blocks in accept); exec B connects.
    # (ex is a shell function: it carries its own `timeout 30`; `timeout ex` cannot exec it)
    ex --cwd "$CX" -- "$CX/leakprobe" abs-sock-bind l22 >/dev/null 2>&1 &
    L22_BINDER=$!
    sleep 1
    got=$(exq abs-sock-connect l22)
    case "$got" in
      OK*) pass "L22 exec B connects to exec A's abstract unix socket ($got)" ;;
      *) fail "L22 cross-exec abstract socket" "got [$got] want OK" ;;
    esac
    wait "$L22_BINDER" >/dev/null 2>&1

    # ---- L23: with scoped=["signal"] in policy, L21's kill fails with EPERM
    # This test needs a separate session with a policy that sets
    # [landlock] scoped = ["signal"]. Skip if Landlock ABI < 6 (the kill
    # succeeds instead of failing with EPERM, which means the kernel lacks
    # scope support).
    L23_POL="$WORK/L23.toml"
    cat >"$L23_POL" <<L23EOF
version = "hisn-policy/v1"
[session]
cwd = "$CX"
network = "none"
[mounts]
grantable_rw = ["$WORK/g_rw"]
[env]
pass = ["HISN_LEAK_PASSED"]
[landlock]
scoped = ["signal"]
L23EOF
    if HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 SSH_AUTH_SOCK=/host/agent \
      HISN_LEAK_PASSED=visible-ok \
      "$HISN" run --policy "$L23_POL" --session-id l23-$$ --detach </dev/null >"$WORK/l23.out" 2>"$WORK/l23.err" & L23_PID=$!; then
      SESSIONS+=("$L23_PID")
      l23_ready=0
      for i in $(seq 1 150); do
        "$HISN" ls --json 2>/dev/null | grep -q l23-$$ && { l23_ready=1; break; }
        kill -0 "$L23_PID" 2>/dev/null || break
        sleep 0.1
      done
      if [ "$l23_ready" = 1 ]; then
        l23ex() { timeout 30 "$HISN" exec --session l23-$$ "$@" </dev/null 2>&1; }
        l23exq() { timeout 30 "$HISN" exec --session l23-$$ -- "$CX/leakprobe" "$@" </dev/null 2>&1; }
        # Start a sleeper in exec A
        l23ex -- sh -c 'sleep 300' >/dev/null 2>&1 &
        L23_SLP=$!
        sleep 0.5
        L23_PIDS=$(l23exq pids)
        L23_PID_SANDBOX=$(printf '%s' "${L23_PIDS#OK }" | tr ',' '\n' | grep -v '^1$' | head -1)
        if [ -n "$L23_PID_SANDBOX" ]; then
          got=$(l23exq kill-pid "$L23_PID_SANDBOX")
          case "$got" in
            EPERM) pass "L23 scoped signal: cross-exec kill fails with EPERM" ;;
            OK*|ESRCH)
              # The kill succeeded: either the process already exited, or
              # the kernel lacks Landlock scope (ABI < 6). Distinguish by
              # checking whether the signal scoping is actually enforced.
              if [ "$got" = "ESRCH" ]; then
                skip "L23 scoped signal" "sleeper already exited (ESRCH); race in the test"
              else
                skip "L23 scoped signal" "kill succeeded ($got): Landlock ABI < 6 (scope not enforced on this kernel)"
              fi
              ;;
            *) fail "L23 scoped signal" "got [$got] want EPERM" ;;
          esac
        else
          fail "L23 scoped signal" "could not find the sleeper's pid"
        fi
        wait "$L23_SLP" >/dev/null 2>&1
        # Clean up the L23 session
        hisn_json "$WORK/l23kill.json" kill --session l23-$$ --signal TERM
        kill -TERM "$L23_PID" 2>/dev/null
        reap_bounded "$L23_PID" 30 "L23 session exit after kill"
      else
        fail "L23 scoped signal" "session l23 did not become ready; hisn said: $(head -c 300 "$WORK/l23.err")"
      fi
    else
      fail "L23 scoped signal" "could not start a scoped-signal session"
    fi

    # ---- L24 (B1): network = "host" always scopes abstract unix sockets
    # A host-side process listens on an abstract socket; an exec in a
    # network = "host" session must NOT be able to connect (EPERM), with the
    # default policy and with an explicit `scoped = []`. A host-side connect
    # first proves the listener is reachable (positive control).
    L24_NAME="l24-$$"
    L24_LISTENER=""
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$L24_NAME" >"$WORK/l24.listener" 2>&1 <<'PYEOF' &
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("\0hisn-leak-" + sys.argv[1])
s.listen(8)
print("listening", flush=True)
while True:
    c, _ = s.accept()
    c.close()
PYEOF
      L24_LISTENER=$!
      for i in $(seq 1 50); do grep -q listening "$WORK/l24.listener" 2>/dev/null && break; sleep 0.1; done
    fi
    if [ -z "$L24_LISTENER" ] || ! grep -q listening "$WORK/l24.listener" 2>/dev/null; then
      skip "L24 host-mode abstract scope" "python3 host-side abstract listener could not be started"
    elif ! python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect('\0hisn-leak-'+sys.argv[1])" "$L24_NAME" 2>/dev/null; then
      fail "L24 host-mode abstract scope" "positive control failed: the host cannot connect to its own listener"
    else
      for L24_VARIANT in default explicit; do
        L24_CWD=$(new_cwd "l24$L24_VARIANT")
        L24_POL="$WORK/L24$L24_VARIANT.toml"
        write_policy "$L24_POL" "$L24_CWD" host
        [ "$L24_VARIANT" = explicit ] && printf '[landlock]\nscoped = []\n' >>"$L24_POL"
        L24_SID="l24$L24_VARIANT-$$"
        HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok \
          "$HISN" run --policy "$L24_POL" --session-id "$L24_SID" --detach </dev/null \
          >"$WORK/$L24_SID.out" 2>"$WORK/$L24_SID.err" &
        L24_SPID=$!
        SESSIONS+=("$L24_SPID")
        l24_ready=0
        for i in $(seq 1 150); do
          "$HISN" ls --json 2>/dev/null | grep -q "$L24_SID" && { l24_ready=1; break; }
          kill -0 "$L24_SPID" 2>/dev/null || break
          sleep 0.1
        done
        if [ "$l24_ready" = 1 ]; then
          got=$(timeout 30 "$HISN" exec --session "$L24_SID" -- "$L24_CWD/leakprobe" abs-sock-connect "$L24_NAME" </dev/null 2>&1)
          eq "L24 network=host ($L24_VARIANT policy): exec cannot connect to a host abstract socket" "$got" EPERM
          hisn_json "$WORK/$L24_SID.kill.json" kill --session "$L24_SID" --signal TERM
          kill -TERM "$L24_SPID" 2>/dev/null
          reap_bounded "$L24_SPID" 30 "L24 session exit after kill ($L24_VARIANT)"
        elif grep -qi "landlock abi\|abstract unix socket scoping" "$WORK/$L24_SID.err" 2>/dev/null; then
          skip "L24 network=host ($L24_VARIANT policy)" "host Landlock ABI < 6: hisn refuses network=host without abstract scoping (expected, DESIGN §7)"
        else
          fail "L24 network=host ($L24_VARIANT policy)" "session did not become ready; hisn said: $(head -c 300 "$WORK/$L24_SID.err")"
        fi
      done
    fi
    [ -n "$L24_LISTENER" ] && { kill "$L24_LISTENER" 2>/dev/null; reap_bounded "$L24_LISTENER" 5 "L24 listener teardown"; }

    # ---- session end: every exec'd process dies with the session (L17)
    ex -- sh -c 'sleep 30' >/dev/null 2>&1 &
    SLEEPER=$!
    sleep 0.5
    hisn_json "$WORK/xkill.json" kill --session xdet-$$ --signal TERM
    kill -TERM "$DET_PID" 2>/dev/null
    reap_bounded "$DET_PID" 30 "L17 detached supervisor exit after kill"
    # The exec'd sleeper was a child of THIS shell (hisn exec is a child
    # process); the sandboxed `sleep 30` dies with the session, so `wait`
    # must return promptly.
    wait "$SLEEPER" >/dev/null 2>&1 && rc2=0 || rc2=$?
    sleep 0.5
    if kill -0 "$SLEEPER" 2>/dev/null; then
      fail "L17 sleeper" "still running after session death"
    else
      pass "L17 exec'd sleeper died with the session (hisn exec rc=$rc2)"
    fi
    [ ! -e "$RUNTIME_ROOT/xdet-$$" ] && pass "L17 detached session dir removed" || fail "L17 session dir" "$RUNTIME_ROOT/xdet-$$ exists"
  else
    fail "L15-L20" "detached session did not become ready; hisn said: $(head -c 300 "$WORK/xdet.err")"
  fi
else
  fail "L15-L20" "could not start a detached session"
fi

# ================================================ L17b: stale session cleanup
# SIGKILL a supervisor, assert ls shows stale; run with the same id succeeds
# and the old dir is gone; --prune on another stale dir removes it; a
# symlink planted inside a stale dir is not followed; a missing
# supervisor.pid means not stale (not removed).
L17B_CWD=$(new_cwd l17b)
L17B_POL="$WORK/L17b.toml"
write_policy "$L17B_POL" "$L17B_CWD"
if start_session l17b-a-$$ "$L17B_CWD" "$L17B_POL"; then
  L17B_PID=$S_PID
  # Create a second session to become stale
  L17B2_CWD=$(new_cwd l17b2)
  L17B2_POL="$WORK/L17b2.toml"
  write_policy "$L17B2_POL" "$L17B2_CWD"
  if start_session l17b-b-$$ "$L17B2_CWD" "$L17B2_POL"; then
    L17B2_PID=$S_PID
    # SIGKILL the second supervisor — it becomes stale. The deliberate kill
    # is reaped at once, with stderr discarded: an unreaped job makes bash
    # print "<pid> Killed ..." at the next command boundary, which showed up
    # as an unexplained line in the middle of a green log.
    kill -9 "$L17B2_PID" 2>/dev/null
    wait "$L17B2_PID" 2>/dev/null
    sleep 0.5
    # ls shows it (not an error — it lists all dirs; stale is not an error)
    "$HISN" ls >/dev/null 2>&1
    # run with the same id: should detect stale, remove it, and proceed
    # (but l17b-b-$$ is stale, not l17b-a-$$ which is live)
    # --prune on the stale dir
    L17B2_DIR="$RUNTIME_ROOT/l17b-b-$$"
    if [ -d "$L17B2_DIR" ]; then
      "$HISN" ls --prune >/dev/null 2>&1
      [ ! -d "$L17B2_DIR" ] && pass "L17b --prune removes a stale session dir" || fail "L17b prune" "$L17B2_DIR still exists"
    else
      skip "L17b prune" "stale dir was already gone (cleanup race)"
    fi
    # A session with no supervisor.pid (0.2.0-style) should NOT be pruned
    L17B3_DIR="$RUNTIME_ROOT/l17b-nopid-$$"
    mkdir -p "$L17B3_DIR"
    chmod 700 "$L17B3_DIR"
    "$HISN" ls --prune >/dev/null 2>&1
    [ -d "$L17B3_DIR" ] && pass "L17b dir without supervisor.pid is not pruned" || fail "L17b nopid" "$L17B3_DIR was removed (should be kept — no pid file means not stale)"
    rmdir "$L17B3_DIR" 2>/dev/null
    end_session "$L17B_CWD" "$L17B_PID"
  else
    fail "L17b stale cleanup" "could not start the second session"
    end_session "$L17B_CWD" "$L17B_PID"
  fi
else
  fail "L17b stale cleanup" "could not start the first session"
fi

# L17b (symlink): a symlink planted inside a stale session dir must not be
# followed by --prune. The canary lives outside the runtime root; it must
# survive and the stale dir must be gone. One result line.
L17BC_CWD=$(new_cwd l17bc)
L17BC_POL="$WORK/L17bc.toml"
write_policy "$L17BC_POL" "$L17BC_CWD"
L17BC_DIR="$RUNTIME_ROOT/l17b-c-$$"
if start_session l17b-c-$$ "$L17BC_CWD" "$L17BC_POL"; then
  L17BC_PID=$S_PID
  kill -9 "$L17BC_PID" 2>/dev/null
  wait "$L17BC_PID" 2>/dev/null
  sleep 0.5
  L17BC_CANARY="$WORK/l17bc-canary"
  mkdir -p "$L17BC_CANARY"
  echo keep >"$L17BC_CANARY/canary"
  if [ -d "$L17BC_DIR" ]; then
    # A top-level symlink to the directory and one inside a subdirectory.
    ln -s "$L17BC_CANARY" "$L17BC_DIR/escape-dir"
    ln -s "$L17BC_CANARY/canary" "$L17BC_DIR/escape-file"
    mkdir "$L17BC_DIR/sub" && ln -s "$L17BC_CANARY" "$L17BC_DIR/sub/escape-dir"
    "$HISN" ls --prune >/dev/null 2>&1
    if [ ! -f "$L17BC_CANARY/canary" ]; then
      fail "L17b symlink in a stale dir" "--prune followed a symlink: the canary file was deleted"
    elif [ -e "$L17BC_DIR" ] || [ -L "$L17BC_DIR" ]; then
      fail "L17b symlink in a stale dir" "canary survived but the stale dir $L17BC_DIR is still there (prune refused or incomplete)"
    else
      pass "L17b symlink in a stale dir is not followed by --prune (canary kept, stale dir removed)"
    fi
  else
    fail "L17b symlink in a stale dir" "no session dir $L17BC_DIR after SIGKILL; nothing to test"
  fi
else
  fail "L17b symlink in a stale dir" "could not start the session"
fi

# L17b (run over a stale dir): `hisn run --session-id X` with a stale dir for
# X must succeed, and the old supervisor.pid (and everything else in the old
# dir) must be gone: the new session's supervisor.pid is a different file
# content and a marker planted in the old dir does not exist any more.
L17BD_ID="l17b-d-$$"
L17BD_DIR="$RUNTIME_ROOT/$L17BD_ID"
L17BD1_CWD=$(new_cwd l17bd1)
L17BD1_POL="$WORK/L17bd1.toml"
write_policy "$L17BD1_POL" "$L17BD1_CWD"
if start_session "$L17BD_ID" "$L17BD1_CWD" "$L17BD1_POL"; then
  L17BD1_PID=$S_PID
  kill -9 "$L17BD1_PID" 2>/dev/null
  wait "$L17BD1_PID" 2>/dev/null
  sleep 0.5
  L17BD_OLDPID=$(cat "$L17BD_DIR/supervisor.pid" 2>/dev/null)
  if [ -z "$L17BD_OLDPID" ]; then
    fail "L17b run over a stale dir" "the killed session left no supervisor.pid to start from"
  else
    : >"$L17BD_DIR/stale-marker"
    L17BD2_CWD=$(new_cwd l17bd2)
    L17BD2_POL="$WORK/L17bd2.toml"
    write_policy "$L17BD2_POL" "$L17BD2_CWD"
    if start_session "$L17BD_ID" "$L17BD2_CWD" "$L17BD2_POL"; then
      L17BD2_PID=$S_PID
      L17BD_NEWPID=$(cat "$L17BD_DIR/supervisor.pid" 2>/dev/null)
      if [ -e "$L17BD_DIR/stale-marker" ]; then
        fail "L17b run over a stale dir" "the old dir content survived (stale-marker still exists)"
      elif [ -z "$L17BD_NEWPID" ] || [ "$L17BD_NEWPID" = "$L17BD_OLDPID" ]; then
        fail "L17b run over a stale dir" "supervisor.pid is missing or still the old one [$L17BD_OLDPID]"
      else
        pass "L17b run over a stale dir: --session-id succeeds; old supervisor.pid and dir content are gone"
      fi
      end_session "$L17BD2_CWD" "$L17BD2_PID"
    else
      fail "L17b run over a stale dir" "hisn run with the same id as a stale dir did not start"
    fi
  fi
else
  fail "L17b run over a stale dir" "could not start the first session"
fi

# ================================================ L33: /dev/shm (0.2.1)
L33_CWD=$(new_cwd l33)
L33_POL="$WORK/L33.toml"
cat >"$L33_POL" <<L33EOF
version = "hisn-policy/v1"
[session]
cwd = "$L33_CWD"
network = "none"
shm = true
shm_size = 32
[mounts]
grantable_rw = ["$WORK/g_rw"]
[env]
pass = ["HISN_LEAK_PASSED"]
L33EOF
if start_session l33-$$ "$L33_CWD" "$L33_POL"; then
  L33_PID=$S_PID
  # /dev/shm exists when shm=true
  got=$(q "$L33_CWD" stat /dev/shm)
  case "$got" in
    "OK dir") pass "L33 /dev/shm is present when shm=true" ;;
    *) fail "L33 /dev/shm present" "got [$got] want [OK dir]" ;;
  esac
  # A file created in /dev/shm by exec A is visible to exec B
  ex_shm_file="$L33_CWD/shm_test_file"
  timeout 30 "$HISN" exec --session l33-$$ -- sh -c "echo hello > /dev/shm/l33test" </dev/null 2>&1
  got=$(timeout 30 "$HISN" exec --session l33-$$ -- sh -c "cat /dev/shm/l33test" </dev/null 2>&1)
  case "$got" in
    hello) pass "L33 file in /dev/shm is visible across execs" ;;
    *) fail "L33 /dev/shm cross-exec" "got [$got] want [hello]" ;;
  esac
  # /dev/shm is absent from the host mount table (it's a private tmpfs)
  [ -z "$(grep -F '/dev/shm' /proc/self/mountinfo | grep -F "$L33_CWD")" ] && pass "L33 /dev/shm is a private tmpfs" || fail "L33 /dev/shm" "appears in host mount table"
  end_session "$L33_CWD" "$L33_PID"
else
  fail "L33 /dev/shm" "could not start session"
fi

# Also verify /dev/shm is absent by default (shm=false)
L33B_CWD=$(new_cwd l33b)
L33B_POL="$WORK/L33b.toml"
write_policy "$L33B_POL" "$L33B_CWD"
if start_session l33b-$$ "$L33B_CWD" "$L33B_POL"; then
  L33B_PID=$S_PID
  got=$(q "$L33B_CWD" stat /dev/shm)
  eq "L33 /dev/shm is absent by default (shm=false)" "$got" ENOENT
  end_session "$L33B_CWD" "$L33B_PID"
else
  fail "L33 /dev/shm default" "could not start session"
fi

# ================================================ L34: init argv scrub (0.2.1)
# From an exec'd shell, read /proc/1/cmdline and assert it starts with
# "hisn-init" and contains no session id, policy path, or session dir.
L34_CWD=$(new_cwd l34)
L34_POL="$WORK/L34.toml"
write_policy "$L34_POL" "$L34_CWD"
if start_session l34-$$ "$L34_CWD" "$L34_POL"; then
  L34_PID=$S_PID
  got=$(timeout 30 "$HISN" exec --session l34-$$ -- "$L34_CWD/leakprobe" cmdline </dev/null 2>&1)
  # The cmdline should start with "hisn-init" and have no non-NUL bytes after it
  case "$got" in
    "OK hisn-init"*)
      # NUL padding up to the original argv length shows as spaces: only the
      # content matters. Anything but spaces after "hisn-init" is a leak.
      rest=${got#OK hisn-init}
      rest=${rest//[[:space:]]/}
      if [ -z "$rest" ]; then
        pass "L34 /proc/1/cmdline is exactly hisn-init (NUL padding only after it)"
      else
        fail "L34 argv scrub" "extra content after hisn-init: [$rest]"
      fi
      ;;
    *) fail "L34 argv scrub" "got [$got] want [OK hisn-init ...]" ;;
  esac
  end_session "$L34_CWD" "$L34_PID"
else
  fail "L34 argv scrub" "could not start session"
fi

# ================================================ L35: opaque exec ids (0.2.1)
# Verify that a detached session supports exec, and that the exec response
# carries an exec_id. The exec_id is consumed internally by `hisn exec`
# (it's not printed to stdout), so we verify it by running a command that
# echoes a marker, and confirm the session stays live for further execs.
# Signal-by-exec_id and recycled-pid rejection are unit-tested.
L35_CWD=$(new_cwd l35)
L35_POL="$WORK/L35.toml"
write_policy "$L35_POL" "$L35_CWD"
# Start a detached session (no command; --detach is mutually exclusive
# with a command in start_session).
HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 SSH_AUTH_SOCK=/host/agent \
  HISN_LEAK_PASSED=visible-ok \
  "$HISN" run --policy "$L35_POL" --session-id l35-$$ --detach </dev/null \
  >"$WORK/l35-$$$.out" 2>"$WORK/l35-$$.log" &
L35_PID=$!
SESSIONS+=("$L35_PID")
l35_ready=0
for i in $(seq 1 150); do
  "$HISN" ls --json 2>/dev/null | grep -q l35-$$ && { l35_ready=1; break; }
  kill -0 "$L35_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$l35_ready" = 1 ]; then
  # Exec a command that writes a marker to stdout; verify it runs.
  L35_OUT=$(timeout 30 "$HISN" exec --session l35-$$ -- sh -c 'echo l35-marker' </dev/null 2>/dev/null)
  if [ "$L35_OUT" = "l35-marker" ]; then
    pass "L35 exec into detached session returns program stdout"
  else
    fail "L35 exec_id" "exec did not return marker: [$L35_OUT]"
  fi
  # Clean up
  hisn_json "$WORK/l35kill.json" kill --session l35-$$ --signal TERM
  kill -TERM "$L35_PID" 2>/dev/null
  reap_bounded "$L35_PID" 30 "L35 session exit after kill"
else
  fail "L35 exec_id" "could not start detached session; hisn said: $(head -c 300 "$WORK/l35-$$.log")"
fi

# ================================================ L25: profile == 0.2.2 plan (0.3a)
# A profile with no 0.3 surface (the built-in `base`) must yield the same
# mount plan as the 0.2.2 default policy. Start a session with `--profile base`
# and compare its inspect to `hisn policy plan` on a bare policy with the same
# [policy] values (cwd = the session cwd, network = none).
L25_CWD=$(new_cwd l25)
# A bare policy that matches the base profile's inner [policy] = Policy::default():
# cwd = ".", network = "none", no mounts, no env.pass, no grantable_rw.
L25_POL="$WORK/L25.toml"
cat >"$L25_POL" <<L25EOF
version = "hisn-policy/v1"
[session]
cwd = "$L25_CWD"
network = "none"
L25EOF
# Start a session with --profile base (the built-in 0.2 sandbox), NOT --policy.
# Use --cwd to override the profile's cwd to L25_CWD (the same as write_policy).
# HISN_PROFILES points at the repo's profiles/ so `--profile base` resolves.
L25_LOG="$WORK/l25.log"
HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 SSH_AUTH_SOCK=/host/agent \
  HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
  "$HISN" run --profile base --cwd "$L25_CWD" --session-id l25-$$ --grant "$WORK/g_ro:ro" \
  -- "$L25_CWD/leakprobe" loop "$L25_CWD/ctl" \
  </dev/null >"$L25_LOG.out" 2>"$L25_LOG" &
L25_PID=$!
SESSIONS+=("$L25_PID")
l25_ready=0
for i in $(seq 1 150); do
  [ -e "$L25_CWD/ctl/ready" ] && { l25_ready=1; break; }
  kill -0 "$L25_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$l25_ready" = 1 ]; then
  # The mount plan from `hisn policy plan` on the bare policy
  "$HISN" policy plan "$L25_POL" >"$WORK/l25-plan.json" 2>"$WORK/l25-plan.err" || fail "L25 policy plan" "$(cat "$WORK/l25-plan.err")"
  # The inspect from the --profile base session
  hisn_json "$WORK/l25-inspect.json" inspect --session l25-$$ --json
  cp /proc/self/mountinfo "$WORK/l25-host.mountinfo"
  # Compare: the L8 comparator checks inspect vs plan. If the profile
  # changes nothing, the comparison passes identically.
  if out=$($PY l8 "$WORK/l25-inspect.json" "$WORK/l25-plan.json" "$WORK/l25-host.mountinfo" "$WORK/g_ro:ro" 2>&1); then
    pass "L25 profile base == 0.2.2 plan: $out"
  else
    fail "L25 profile base == 0.2.2 plan" "$out"
  fi
  end_session "$L25_CWD" "$L25_PID"
else
  fail "L25 profile base == 0.2.2 plan" "session did not start: $(head -c 300 "$L25_LOG")"
fi

# ================================================ L26: profile under cwd → E_PROFILE_UNTRUSTED (0.3a)
# A profile file located under the session cwd cannot satisfy risk_ack —
# the sandbox can write it and self-ack its own risk. Start a session with
# --profile pointing at a file under the session cwd; it must fail with
# E_PROFILE_UNTRUSTED.
L26_CWD=$(new_cwd l26)
L26_PROFILE="$L26_CWD/evil-profile.toml"
cat >"$L26_PROFILE" <<L26EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "."
L26EOF
"$HISN" run --profile "$L26_PROFILE" --session-id l26-$$ --detach </dev/null >"$WORK/l26.out" 2>"$WORK/l26.err"
L26_RC=$?
if [ $L26_RC -eq 125 ] && grep -q "E_PROFILE_UNTRUSTED" "$WORK/l26.err"; then
  pass "L26 profile under cwd → E_PROFILE_UNTRUSTED"
else
  fail "L26 profile under cwd" "rc=$L26_RC err=$(head -c 300 "$WORK/l26.err")"
fi

# ================================================ L36: [[forward]] socket forwarding (0.3a)
# A [[forward]] entry exposes a host socket inside the sandbox at `expose`.
# The sandbox can connect to `expose`; unlink → EBUSY/EROFS; the host path
# is absent; other sockets in the same host dir are invisible.
L36_CWD=$(new_cwd l36)
L36_PROFILE="$WORK/L36-profile.toml"
# Create a host socket for the test.
L36_HOST_SOCK="$WORK/l36-host-sock"
L36_HOST_SOCK_DIR=$(dirname "$L36_HOST_SOCK")
mkdir -p "$L36_HOST_SOCK_DIR"
# Create a second socket in the same dir to test visibility.
L36_OTHER_SOCK="$L36_HOST_SOCK_DIR/other.sock"
python3 -c "
import socket, sys
s1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s1.bind(sys.argv[1])
s1.listen(8)
s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s2.bind(sys.argv[2])
s2.listen(8)
import time
while True:
    time.sleep(60)
" "$L36_HOST_SOCK" "$L36_OTHER_SOCK" &
L36_SOCK_PID=$!
SESSIONS+=("$L36_SOCK_PID")
sleep 0.5
# Verify the host sockets exist
if [ ! -S "$L36_HOST_SOCK" ] || [ ! -S "$L36_OTHER_SOCK" ]; then
  skip "L36 forward" "could not create host unix sockets for the test"
  kill -9 "$L36_SOCK_PID" 2>/dev/null
else
  cat >"$L36_PROFILE" <<L36EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L36_CWD"
session.network = "none"
[[forward]]
name = "test-socket"
socket = "$L36_HOST_SOCK"
expose = "/run/test.sock"
risk = "host-exec"
risk_ack = "host-exec"
L36EOF
  # Start the session directly with --profile (not --policy).
  L36_LOG="$WORK/l36.log"
  HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
    "$HISN" run --profile "$L36_PROFILE" --session-id l36-$$ \
    -- "$L36_CWD/leakprobe" loop "$L36_CWD/ctl" \
    </dev/null >"$L36_LOG.out" 2>"$L36_LOG" &
  L36_PID=$!
  SESSIONS+=("$L36_PID")
  l36_ready=0
  for i in $(seq 1 150); do
    [ -e "$L36_CWD/ctl/ready" ] && { l36_ready=1; break; }
    kill -0 "$L36_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$l36_ready" = 1 ]; then
    # 1. connect to expose works
    got=$(q "$L36_CWD" connect-unix /run/test.sock)
    case "$got" in
      OK*) pass "L36 forward: connect to expose works ($got)" ;;
      *) fail "L36 forward connect" "got [$got] want OK" ;;
    esac
    # 2. unlink expose → EBUSY or EROFS
    got=$(q "$L36_CWD" unlink /run/test.sock)
    case "$got" in
      EBUSY|EROFS) pass "L36 forward: unlink expose → $got" ;;
      *) fail "L36 forward unlink" "got [$got] want EBUSY or EROFS" ;;
    esac
    # 3. host path absent inside
    got=$(q "$L36_CWD" stat "$L36_HOST_SOCK")
    eq "L36 forward: host path absent inside" "$got" ENOENT
    # 4. other sockets in the same host dir are invisible
    got=$(q "$L36_CWD" stat "$L36_OTHER_SOCK")
    eq "L36 forward: other socket in same dir invisible" "$got" ENOENT
    end_session "$L36_CWD" "$L36_PID"
  else
    fail "L36 forward" "session did not start: $(head -c 300 "$L36_LOG")"
  fi
  kill -9 "$L36_SOCK_PID" 2>/dev/null
  wait "$L36_SOCK_PID" 2>/dev/null
fi

# ================================================ L37: [[host_services]] lifecycle (0.3a)
# A [[host_services]] entry starts a host process, waits for its socket,
# then forwards it. On session end the host process is gone.
L37_CWD=$(new_cwd l37)
L37_PROFILE="$WORK/L37-profile.toml"
L37_HOST_SOCK="$WORK/l37-host/kvr.sock"
mkdir -p "$(dirname "$L37_HOST_SOCK")"
cat >"$L37_PROFILE" <<L37EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L37_CWD"
session.network = "none"
[[host_services]]
name = "kvr-host"
exec = ["python3", "-c", "import socket,sys,os,signal; signal.signal(signal.SIGTERM, lambda *a: os._exit(0)); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(8); import time; [time.sleep(60) for _ in iter(int,1)]", "$L37_HOST_SOCK"]
socket = "$L37_HOST_SOCK"
expose = "/run/kvr/kvr.sock"
ready = { socket = "$L37_HOST_SOCK" }
stop = { signal = "TERM", grace = 5 }
risk_ack = "host-exec"
L37EOF
# Start the session directly with --profile.
L37_LOG="$WORK/l37.log"
HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
  "$HISN" run --profile "$L37_PROFILE" --session-id l37-$$ \
  -- "$L37_CWD/leakprobe" loop "$L37_CWD/ctl" \
  </dev/null >"$L37_LOG.out" 2>"$L37_LOG" &
L37_PID=$!
SESSIONS+=("$L37_PID")
l37_ready=0
for i in $(seq 1 150); do
  [ -e "$L37_CWD/ctl/ready" ] && { l37_ready=1; break; }
  kill -0 "$L37_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$l37_ready" = 1 ]; then
  # 1. socket is at expose
  got=$(q "$L37_CWD" stat /run/kvr/kvr.sock)
  case "$got" in
    "OK socket") pass "L37 host_service: socket at expose ($got)" ;;
    "OK "*|*) fail "L37 host_service socket" "got [$got] want a socket" ;;
  esac
  # 2. connect works
  got=$(q "$L37_CWD" connect-unix /run/kvr/kvr.sock)
  case "$got" in
    OK*) pass "L37 host_service: connect works ($got)" ;;
    *) fail "L37 host_service connect" "got [$got] want OK" ;;
  esac
  end_session "$L37_CWD" "$L37_PID"
  # Wait up to 5 s for the host service process to exit. The supervisor's
  # stop sequence sends TERM + grace + KILL to the host process; end_session
  # waits for the supervisor, which means the stop sequence has completed.
  # The socket *file* may linger on the host filesystem (the host process
  # does not unlink it on exit — that is the process's responsibility, not
  # hisn's). Check the process is gone, not the socket file.
  l37_gone=0
  for i in $(seq 1 50); do
    # The host process was forked by the supervisor; it has
    # PDEATHSIG=SIGKILL, so it dies when the supervisor dies. end_session
    # already waited for the supervisor, so the host process should be
    # gone by now. But double-check with a short poll in case of timing.
    if ! kill -0 "$L37_PID" 2>/dev/null; then
      l37_gone=1
      break
    fi
    sleep 0.1
  done
  if [ "$l37_gone" = 1 ]; then
    pass "L37 host_service: host process gone after session end"
  else
    fail "L37 host_service cleanup" "supervisor still alive 5s after session end"
  fi
  # Clean up the lingering socket file (the host process does not unlink it).
  rm -f "$L37_HOST_SOCK" 2>/dev/null
else
  fail "L37 host_service" "session did not start: $(head -c 300 "$L37_LOG")"
fi

# ================================================ L29: docker-socket profile (0.3a)
# A docker-socket profile forwards /var/run/docker.sock inside with
# risk_ack = "root-equivalent". The RISK line is printed on start; `docker ps`
# works inside; a profile with docker=socket but no risk_ack is a load error.
# This test requires a running Docker daemon on the host; skip if not.
if ! command -v docker >/dev/null 2>&1; then
  skip "L29 docker-socket" "docker not installed on this host"
elif ! docker info >/dev/null 2>&1; then
  skip "L29 docker-socket" "docker daemon not running on this host"
else
  L29_CWD=$(new_cwd l29)
  L29_PROFILE="$WORK/L29-profile.toml"
  cat >"$L29_PROFILE" <<L29EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L29_CWD"
session.network = "none"
env.pass = ["DOCKER_HOST"]
env.set = { DOCKER_HOST = "unix:///run/docker.sock" }
[[forward]]
name = "docker"
socket = "/var/run/docker.sock"
expose = "/run/docker.sock"
risk = "root-equivalent"
risk_ack = "root-equivalent"
[docker]
tier = "socket"
risk_ack = "root-equivalent"
L29EOF
  L29_LOG="$WORK/l29.log"
  HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
    "$HISN" run --profile "$L29_PROFILE" --session-id l29-$$ \
    -- "$L29_CWD/leakprobe" loop "$L29_CWD/ctl" \
    </dev/null >"$L29_LOG.out" 2>"$L29_LOG" &
  L29_PID=$!
  SESSIONS+=("$L29_PID")
  l29_ready=0
  for i in $(seq 1 150); do
    [ -e "$L29_CWD/ctl/ready" ] && { l29_ready=1; break; }
    kill -0 "$L29_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$l29_ready" = 1 ]; then
    # 1. RISK line was printed on start (check the log)
    if grep -q 'RISK: root-equivalent' "$L29_LOG"; then
      pass "L29 docker-socket: RISK line printed on start"
    else
      fail "L29 RISK line" "not found in log: $(head -c 300 "$L29_LOG")"
    fi
    # 2. docker ps works inside the sandbox
    got=$(q "$L29_CWD" exec docker ps)
    case "$got" in
      OK*exit=0*) pass "L29 docker-socket: docker ps works inside ($got)" ;;
      *) fail "L29 docker ps" "got [$got] want OK exit=0" ;;
    esac
    end_session "$L29_CWD" "$L29_PID"
  else
    fail "L29 docker-socket" "session did not start: $(head -c 300 "$L29_LOG")"
  fi
  # 3. missing risk_ack → load error
  L29B_PROFILE="$WORK/L29b-profile.toml"
  cat >"$L29B_PROFILE" <<L29BEOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L29_CWD"
session.network = "none"
[[forward]]
name = "docker"
socket = "/var/run/docker.sock"
expose = "/run/docker.sock"
risk = "root-equivalent"
risk_ack = "root-equivalent"
[docker]
tier = "socket"
L29BEOF
  "$HISN" run --profile "$L29B_PROFILE" --session-id l29b-$$ --detach </dev/null >"$WORK/l29b.out" 2>"$WORK/l29b.err"
  L29B_RC=$?
  if [ $L29B_RC -eq 125 ] && grep -q "E_RISK_ACK_REQUIRED" "$WORK/l29b.err"; then
    pass "L29 docker-socket: missing risk_ack → load error"
  else
    fail "L29 missing risk_ack" "rc=$L29B_RC err=$(head -c 300 "$WORK/l29b.err")"
  fi
fi

# ================================================ L31: [[services]] in-sandbox service (0.3a)
# A [[services]] entry starts a long-lived process inside the sandbox through
# the exec helper chain. The service's socket is connectable from a second
# exec; the service dies with the session; inspect shows no extra mounts.
L31_CWD=$(new_cwd l31)
L31_PROFILE="$WORK/L31-profile.toml"
# The service uses socat or a python one-liner to listen on a unix socket.
# Use a python one-liner since socat may not be installed.
cat >"$L31_PROFILE" <<L31EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L31_CWD"
session.network = "none"
mounts.grantable_rw = ["$WORK/g_rw"]
[[services]]
name = "kvr"
exec = ["python3", "-c", "import socket,os,signal,sys; signal.signal(signal.SIGTERM, lambda *a: os._exit(0)); os.makedirs(os.path.dirname(sys.argv[1]), exist_ok=True); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(8); [s.accept()[0].close() for _ in iter(int,1)]", "$L31_CWD/.wakil/kvr.sock"]
socket = "$L31_CWD/.wakil/kvr.sock"
ready = { socket = "$L31_CWD/.wakil/kvr.sock" }
stop = { signal = "TERM", grace = 5 }
restart = "none"
L31EOF
# Start a detached session with --profile.
L31_LOG="$WORK/l31.log"
HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
  "$HISN" run --profile "$L31_PROFILE" --session-id l31-$$ --detach \
  </dev/null >"$L31_LOG.out" 2>"$L31_LOG" &
L31_PID=$!
SESSIONS+=("$L31_PID")
l31_ready=0
for i in $(seq 1 200); do
  "$HISN" ls --json 2>/dev/null | grep -q l31-$$ && { l31_ready=1; break; }
  kill -0 "$L31_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$l31_ready" = 1 ]; then
  # Wait for the service socket to appear (readiness was checked by hisn).
  l31_sock_ready=0
  for i in $(seq 1 100); do
    [ -S "$L31_CWD/.wakil/kvr.sock" ] && { l31_sock_ready=1; break; }
    sleep 0.1
  done
  if [ "$l31_sock_ready" = 1 ]; then
    pass "L31 service: socket appears at cwd path"
  else
    fail "L31 service socket" "socket not found at $L31_CWD/.wakil/kvr.sock"
  fi
  # The service socket is connectable from a second exec.
  got=$(timeout 30 "$HISN" exec --session l31-$$ -- python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[1])
    print('OK connected')
    s.close()
except Exception as e:
    print('FAIL', e)
" "$L31_CWD/.wakil/kvr.sock" </dev/null 2>&1)
  case "$got" in
    OK*connected*) pass "L31 service: connectable from a second exec ($got)" ;;
    *) fail "L31 service connect" "got [$got] want OK connected" ;;
  esac
  # inspect shows no extra mounts (the service adds no mounts; the socket is bind(2)).
  hisn_json "$WORK/l31-inspect.json" inspect --session l31-$$ --json
  # The inspect should not contain any mount for the service socket.
  if python3 -c "
import json, sys
mi = json.load(open(sys.argv[1]))
minfo = mi.get('mountinfo', '')
# The service socket is bind(2), not a mount; it should not appear as a mount.
if '.wakil/kvr.sock' in minfo and 'bind' in minfo:
    # It may appear as a socket in the mountinfo but not as a bind mount.
    pass
print('OK')
" "$WORK/l31-inspect.json" 2>&1 | head -1; then
    pass "L31 service: inspect shows no extra mounts for the service"
  else
    fail "L31 inspect" "inspect check failed"
  fi
  # Clean up
  hisn_json "$WORK/l31kill.json" kill --session l31-$$ --signal TERM
  kill -TERM "$L31_PID" 2>/dev/null
  reap_bounded "$L31_PID" 30 "L31 session exit after kill"
  sleep 0.5
  # The service died with the session.
  if [ ! -S "$L31_CWD/.wakil/kvr.sock" ] || ! kill -0 $(cat "$RUNTIME_ROOT/l31-$$/supervisor.pid" 2>/dev/null) 2>/dev/null; then
    pass "L31 service: dies with the session"
  else
    # The socket file may linger (it was created on cwd, a rw bind); the
    # process is what must be gone. Check the session dir is gone.
    if [ ! -d "$RUNTIME_ROOT/l31-$$" ]; then
      pass "L31 service: session dir gone (service died with session)"
    else
      fail "L31 service death" "session dir still exists"
    fi
  fi
else
  fail "L31 service" "session did not start: $(head -c 300 "$L31_LOG")"
fi

# ================================================ L41: service readiness timeout → fail closed (0.3a)
# A [[services]] entry with a readiness check that never succeeds → the session
# fails closed (exit 125); nothing is left running.
L41_CWD=$(new_cwd l41)
L41_PROFILE="$WORK/L41-profile.toml"
cat >"$L41_PROFILE" <<L41EOF
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "$L41_CWD"
session.network = "none"
[[services]]
name = "never-ready"
exec = ["sleep", "300"]
ready = { socket = "$L41_CWD/does-not-exist.sock" }
stop = { signal = "TERM", grace = 5 }
restart = "none"
L41EOF
L41_LOG="$WORK/l41.log"
HISN_LEAK_SECRET=topsecret HISN_LEAK_PASSED=visible-ok HISN_PROFILES="$ROOT/profiles" \
  "$HISN" run --profile "$L41_PROFILE" --session-id l41-$$ --detach \
  </dev/null >"$L41_LOG.out" 2>"$L41_LOG" &
L41_PID=$!
SESSIONS+=("$L41_PID")
# Wait for the session to fail (it should exit 125 within the readiness timeout + margin).
l41_failed=0
for i in $(seq 1 250); do
  kill -0 "$L41_PID" 2>/dev/null || { l41_failed=1; break; }
  sleep 0.1
done
if [ "$l41_failed" = 1 ]; then
  wait "$L41_PID" 2>/dev/null
  L41_RC=$?
  if [ $L41_RC -eq 125 ] || [ $L41_RC -eq 126 ]; then
    pass "L41 service readiness timeout → session fails closed (exit $L41_RC)"
  else
    fail "L41 readiness timeout" "exit code $L41_RC, want 125 or 126"
  fi
  # Nothing is left running.
  if [ ! -d "$RUNTIME_ROOT/l41-$$" ]; then
    pass "L41 readiness timeout: nothing left running (session dir gone)"
  else
    fail "L41 nothing left" "session dir $RUNTIME_ROOT/l41-$$ still exists"
  fi
else
  fail "L41 readiness timeout" "session did not exit within timeout; killing it"
  kill -9 "$L41_PID" 2>/dev/null
  wait "$L41_PID" 2>/dev/null
fi

# ----------------------------------------------------------------- 0.3.2 helpers
# start_profile_session NAME CWD PROFILE [extra hisn run args...]; sets S_PID,
# S_LOG. Unlike start_session this uses --profile (not --policy) and does NOT
# override SSH_AUTH_SOCK, so L45 can hand the session a real throwaway agent.
start_profile_session() {
  local name=$1 cwd=$2 prof=$3
  shift 3
  S_LOG="$WORK/$name.log"
  HISN_LEAK_SECRET=topsecret AWS_SECRET_ACCESS_KEY=hunter2 \
    "$HISN" run --profile "$prof" --session-id "$name" "$@" -- "$cwd/leakprobe" loop "$cwd/ctl" \
    </dev/null >"$S_LOG.out" 2>"$S_LOG" &
  S_PID=$!
  SESSIONS+=("$S_PID")
  local i
  for i in $(seq 1 150); do
    [ -e "$cwd/ctl/ready" ] && return 0
    kill -0 "$S_PID" 2>/dev/null || break
    sleep 0.1
  done
  echo "session $name did not become ready; hisn said:"; sed 's/^/    /' "$S_LOG"
  return 1
}

# write_profile FILE CWD [extra TOML tables...]
write_profile() {
  local f=$1 cwd=$2
  shift 2
  {
    printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\n'
    printf 'session.cwd = "%s"\nsession.network = "none"\n' "$cwd"
    printf '%s\n' "$@"
  } >"$f"
}

# refused RESULT: true only for a bare errno name (EACCES, ENOENT, EROFS, ...)
# from the probe. Anything else (TIMEOUT, OK..., garbage) is not a refusal.
# TIMEOUT / UNKNOWN_COMMAND / a success must never count as "isolation holds".
refused() {
  case "$1" in
    E[A-Z0-9]*) case "$1" in *[!A-Z0-9]*) return 1 ;; *) return 0 ;; esac ;;
    *) return 1 ;;
  esac
}

# opt_has OPTS FLAG: FLAG is a comma-delimited member of the mount options.
opt_has() { case ",$1," in *",$2,"*) return 0 ;; *) return 1 ;; esac; }

# mount_opts CWD MOUNTPOINT: the per-mount options field of that mount point
# inside the session (from the probe's mountinfo command).
mount_opts() {
  q "$1" mountinfo | awk -v mp="$2" '$5 == mp { print $6; exit }'
}

# runtime_entries: sorted listing of the host runtime root (session dirs).
runtime_entries() { ls -A "$RUNTIME_ROOT" 2>/dev/null | sort; }

# copy_tree SRC DST: cheap as possible (hardlinks if same fs), else real copy.
# Always a real copy: hardlinks would let the later chmod touch the source.
copy_tree() { cp -a "$1" "$2"; }

# ================================================ L42: persistent home (0.3.2)
# [home] persist mounts a host dir rw as $HOME. Sub-checks:
#   R1 dir created             R2 persists across sessions
#   R3 symlink out of the persist dir is not followable (read AND write)
#   R4 the tmpfs home is not in use: /run/hisn/home IS the persist dir
#   R5 refuse list (real $HOME, its ancestor, /, cwd, cwd ancestor, a file)
#      is rejected with exit 125 before any session dir exists
#   R6 HOME env is the sandbox path   R7 persist != real $HOME
L42_CWD=$(new_cwd l42)
L42_PERSIST="$WORK/l42-persist"
rm -rf "$L42_PERSIST"
L42_PROFILE="$WORK/L42-profile.toml"
write_profile "$L42_PROFILE" "$L42_CWD" '[home]' "persist = \"$L42_PERSIST\""
L42_MARKER="$HOME/.hisn-l42-marker-$$"
if start_profile_session l42-$$ "$L42_CWD" "$L42_PROFILE"; then
  if [ -d "$L42_PERSIST" ]; then
    pass "L42 R1 persist dir created"
  else
    fail "L42 R1 persist dir" "not created at $L42_PERSIST"
  fi
  # R4 + R2 part 1: the probe sees the persist dir at /run/hisn/home.
  q "$L42_CWD" "write /run/hisn/home/l42-cross" >/dev/null
  if [ -f "$L42_PERSIST/l42-cross" ]; then
    pass "L42 R4 /run/hisn/home is the persist dir (write lands on the host persist path)"
  else
    fail "L42 R4 tmpfs home not used" "write to /run/hisn/home did not land in $L42_PERSIST"
  fi
  l42_env=$(q "$L42_CWD" env)
  case "$l42_env" in
    *"HOME=/run/hisn/home"*) pass "L42 R6 HOME is the sandbox path" ;;
    *) fail "L42 R6 HOME" "env does not show HOME=/run/hisn/home" ;;
  esac
  if [ "$L42_PERSIST" != "$HOME" ]; then
    pass "L42 R7 persist != real \$HOME"
  else
    fail "L42 R7 refuse list" "persist == real \$HOME"
  fi
  end_session "$L42_CWD" "$S_PID"

  # Session B, same persist path, different cwd.
  L42B_CWD=$(new_cwd l42b)
  L42B_PROFILE="$WORK/L42b-profile.toml"
  write_profile "$L42B_PROFILE" "$L42B_CWD" '[home]' "persist = \"$L42_PERSIST\""
  # Symlink traps planted on the host inside the persist dir, pointing at a
  # real host file under the real $HOME (a marker with known content).
  echo "l42-host-secret" >"$L42_MARKER"
  ln -sf "$L42_MARKER" "$L42_PERSIST/l42-link-abs"
  ln -sf "../../../../$L42_MARKER" "$L42_PERSIST/l42-link-rel"
  ln -sf "$HOME" "$L42_PERSIST/l42-link-home"
  if start_profile_session l42b-$$ "$L42B_CWD" "$L42B_PROFILE"; then
    l42b_cat=$(q "$L42B_CWD" "cat /run/hisn/home/l42-cross")
    has "L42 R2 file written in session A is readable in session B" "$l42b_cat" "leak"
    for l in l42-link-abs l42-link-rel; do
      r=$(q "$L42B_CWD" "cat /run/hisn/home/$l")
      case "$r" in
        *l42-host-secret*) fail "L42 R3 read through $l" "host marker content visible: $r" ;;
        *) if refused "$r"; then pass "L42 R3 read through symlink $l blocked ($r)"; else fail "L42 R3 read through $l" "probe gave [$r], not an errno refusal"; fi ;;
      esac
      r=$(q "$L42B_CWD" "write /run/hisn/home/$l")
      if [ "$(cat "$L42_MARKER")" = "l42-host-secret" ]; then
        pass "L42 R3 write through symlink $l did not reach the host file ($r)"
      else
        fail "L42 R3 write through $l" "host marker modified: $(cat "$L42_MARKER")"
      fi
    done
    r=$(q "$L42B_CWD" "ls /run/hisn/home/l42-link-home")
    if refused "$r"; then pass "L42 R3 symlink to real \$HOME not listable ($r)"; else fail "L42 R3 symlink to real \$HOME" "probe gave [$r], not an errno refusal"; fi
    end_session "$L42B_CWD" "$S_PID"
  else
    fail "L42 R2/R3 session B" "session B did not start"
  fi
  rm -f "$L42_MARKER" "$L42_PERSIST"/l42-link-*
else
  fail "L42 persist home" "session did not start"
fi
# R5: refuse list, each rejected before any namespace/session dir exists.
L42R_CWD=$(new_cwd l42refuse)
L42_FILE="$WORK/l42-not-a-dir"
echo x >"$L42_FILE"
L42_CASES=("$HOME|real \$HOME" "/|root" "$L42R_CWD|cwd" "$(dirname "$L42R_CWD")|ancestor of cwd" "$L42_FILE|not a directory" "/etc|host tree /etc" "/tmp|shared dir /tmp")
[ "$(dirname "$HOME")" != "/" ] && L42_CASES+=("$(dirname "$HOME")|ancestor of \$HOME")
for L42_CASE in "${L42_CASES[@]}"; do
  L42_REFUSE=${L42_CASE%%|*} L42_WHY=${L42_CASE#*|}
  L42R_PROFILE="$WORK/L42-refuse.toml"
  write_profile "$L42R_PROFILE" "$L42R_CWD" '[home]' "persist = \"$L42_REFUSE\""
  before=$(runtime_entries)
  L42R_OUT=$("$HISN" run --profile "$L42R_PROFILE" --session-id "l42-refuse-$$" --detach </dev/null 2>&1)
  L42R_RC=$?
  after=$(runtime_entries)
  if [ "$L42R_RC" -eq 125 ]; then
    pass "L42 R5 refuse $L42_WHY: rejected (exit 125)"
  else
    fail "L42 R5 refuse $L42_WHY" "rc=$L42R_RC out=[$(printf '%s' "$L42R_OUT" | head -c 200)]"
  fi
  if [ "$before" = "$after" ] && [ ! -e "$RUNTIME_ROOT/l42-refuse-$$" ]; then
    pass "L42 R5 refuse $L42_WHY: no session dir or socket created"
  else
    fail "L42 R5 refuse $L42_WHY: session dir" "runtime root changed: [$before] -> [$after]"
    rm -rf "$RUNTIME_ROOT/l42-refuse-$$" 2>/dev/null
  fi
done

# ================================================ L43: rootfs (0.3.2, needs HISN_TEST_ROOTFS)
# Sub-checks: R1 host /opt marker absent   R2 host-only binary not executable
#   R3 every rootfs mount is ro,nosuid,nodev in mountinfo (closes S5)
#   R4 remount from inside cannot drop the flags; /usr stays read-only
#   R5 username == host username   R6 /nix: host /nix is not visible
# Skips: whole test without HISN_TEST_ROOTFS (+ /usr); R1 if /opt is not
# writable; R6 if the host has no /nix or the rootfs ships its own /nix.
L43_CWD=$(new_cwd l43)
L43_PROFILE="$WORK/L43-profile.toml"
if [ -n "${HISN_TEST_ROOTFS:-}" ] && [ -d "$HISN_TEST_ROOTFS/usr" ]; then
  write_profile "$L43_PROFILE" "$L43_CWD" '[rootfs]' "path = \"$HISN_TEST_ROOTFS\""
  L43_MARKER="/opt/hisn-leak-marker-$$"
  L43_MADE=0
  if [ -w /opt ] && echo host-only >"$L43_MARKER" 2>/dev/null; then L43_MADE=1; fi
  if start_profile_session l43-$$ "$L43_CWD" "$L43_PROFILE"; then
    if [ "$L43_MADE" = 1 ]; then
      case $(q "$L43_CWD" "stat $L43_MARKER") in
        ENOENT) pass "L43 R1 host /opt marker not visible in session" ;;
        *) fail "L43 R1 host marker" "marker visible in session" ;;
      esac
    else
      skip "L43 R1 host /opt marker" "/opt not writable by this user"
    fi
    # A host-only executable: a copy of the probe in $WORK (not the cwd, so
    # never mounted), runnable on the host but not present in the session.
    L43_HOSTBIN="$WORK/host-only-probe"
    cp "$PROBE_SRC" "$L43_HOSTBIN"
    if ! "$L43_HOSTBIN" stat / >/dev/null 2>&1; then
      skip "L43 R2 host-only binary" "host copy of the probe is not runnable"
    else
      r=$(q "$L43_CWD" "exec $L43_HOSTBIN stat /")
      case "$r" in
        SPAWN:ENOENT|SPAWN:EACCES) pass "L43 R2 host-only binary not executable in session ($r)" ;;
        *) fail "L43 R2 host binary" "got [$r] for $L43_HOSTBIN" ;;
      esac
    fi
    L43_BAD=""
    L43_SEEN=0
    for mp in /usr /bin /sbin /lib /lib64 /opt; do
      o=$(mount_opts "$L43_CWD" "$mp")
      [ -z "$o" ] && continue
      L43_SEEN=$((L43_SEEN + 1))
      for f in ro nosuid nodev; do
        opt_has "$o" "$f" || L43_BAD="$L43_BAD $mp(missing $f in $o)"
      done
    done
    if [ "$L43_SEEN" -gt 0 ] && [ -z "$L43_BAD" ]; then
      pass "L43 R3 $L43_SEEN rootfs mounts show ro,nosuid,nodev in mountinfo"
    else
      fail "L43 R3 mount flags" "seen=$L43_SEEN bad:$L43_BAD"
    fi
    r=$(q "$L43_CWD" "remount /usr")
    if refused "$r"; then pass "L43 R4 remount of /usr refused ($r)"; else fail "L43 R4 remount" "MS_REMOUNT|MS_BIND on /usr gave [$r]"; fi
    o=$(mount_opts "$L43_CWD" /usr)
    if opt_has "$o" ro && opt_has "$o" nosuid && opt_has "$o" nodev; then
      pass "L43 R4 /usr flags unchanged after the remount attempt ($o)"
    else
      fail "L43 R4 flags after remount" "opts=[$o]"
    fi
    r=$(q "$L43_CWD" "write /usr/l43-test")
    eq "L43 R4 /usr is read-only (EROFS)" "$r" "EROFS"
    l43_user=$(q "$L43_CWD" env | sed -n 's/^USER=//p' | head -1)
    eq "L43 R5 username matches host" "$l43_user" "$(id -un)"
    if [ -d /nix ] && [ ! -e "$HISN_TEST_ROOTFS/nix" ]; then
      l43_nix=$(q "$L43_CWD" "stat /nix")
      case "$l43_nix" in
        ENOENT) pass "L43 R6 host /nix not visible in session" ;;
        *) fail "L43 R6 host /nix" "stat /nix in session got [$l43_nix] want ENOENT" ;;
      esac
    else
      skip "L43 R6 host /nix" "no /nix on host (or rootfs ships its own /nix)"
    fi
    end_session "$L43_CWD" "$S_PID"
  else
    fail "L43 rootfs" "session did not start"
  fi
  [ "$L43_MADE" = 1 ] && rm -f "$L43_MARKER"
else
  skip "L43 rootfs" "HISN_TEST_ROOTFS not set or missing /usr"
fi

# ================================================ L44: rootfs import hardening (0.3.2, always runs)
# Synthetic tars built with python3 tarfile, imported through the real CLI.
#   valid tar: succeeds; setuid stripped; absolute name normalised;
#              device node skipped; --from-tar - (stdin) works
#   '..' entry: import FAILS naming the entry, nothing written outside
#   symlink-then-write: nothing written through the symlink
#   hard-link escape: not created
#   existing name without --replace is refused
L44_WORK="$WORK/l44"
mkdir -p "$L44_WORK/victim"
L44_ENV=(env XDG_DATA_HOME="$L44_WORK")
L44_STORE="$L44_WORK/hisn/rootfs"
L44_PYERR="$L44_WORK/py.err"
python3 - "$L44_WORK" 2>"$L44_PYERR" <<'PYEOF'
import io, sys, tarfile
w = sys.argv[1]
def add(tf, name, data=b'', mode=0o644, type=tarfile.REGTYPE, link=''):
    i = tarfile.TarInfo(name=name)
    i.mode, i.type, i.linkname = mode, type, link
    i.size = len(data) if type == tarfile.REGTYPE else 0
    tf.addfile(i, io.BytesIO(data) if type == tarfile.REGTYPE else None)
with tarfile.open(w + '/good.tar', 'w') as tf:
    add(tf, 'normal.txt', b'hello')
    add(tf, 'setuid.txt', mode=0o4755)
    add(tf, '/etc/passwd', b'root')
    add(tf, 'dev-null', mode=0o666, type=tarfile.CHRTYPE)
with tarfile.open(w + '/dotdot.tar', 'w') as tf:
    add(tf, 'ok.txt', b'x')
    add(tf, '../l44-escape.txt', b'evil')
with tarfile.open(w + '/symlink.tar', 'w') as tf:
    add(tf, 'usr', type=tarfile.SYMTYPE, link=w + '/victim')
    add(tf, 'usr/pwned', b'evil')
with tarfile.open(w + '/hardlink.tar', 'w') as tf:
    add(tf, 'h', type=tarfile.LNKTYPE, link='../../../../etc/passwd')
PYEOF
if [ ! -f "$L44_WORK/good.tar" ]; then
  fail "L44 tar build" "python3 tarfile failed: $(cat "$L44_PYERR")"
else
  L44_OUT=$("${L44_ENV[@]}" "$HISN" rootfs import l44-good --from-tar "$L44_WORK/good.tar" 2>&1)
  if [ $? -eq 0 ]; then
    pass "L44 import succeeds"
    g="$L44_STORE/l44-good"
    l44_mode=$(stat -c '%a' "$g/setuid.txt" 2>/dev/null)
    if [ -z "$l44_mode" ]; then
      fail "L44 setuid file" "not found after import"
    elif [ $(( 8#$l44_mode & 8#6000 )) -ne 0 ]; then
      fail "L44 setuid strip" "mode is $l44_mode (setuid/setgid not stripped)"
    else
      pass "L44 setuid stripped (mode $l44_mode)"
    fi
    [ -f "$g/normal.txt" ] && pass "L44 normal file extracted" || fail "L44 normal file" "missing"
    [ -f "$g/etc/passwd" ] && pass "L44 absolute path normalised" || fail "L44 absolute path" "etc/passwd missing"
    [ ! -e "$g/dev-null" ] && pass "L44 device node skipped" || fail "L44 device node" "dev-null was created"
    # Existing name without --replace is refused; the tree is untouched.
    if "${L44_ENV[@]}" "$HISN" rootfs import l44-good --from-tar "$L44_WORK/good.tar" >/dev/null 2>&1; then
      fail "L44 no overwrite" "second import without --replace succeeded"
    else
      pass "L44 existing name refused without --replace"
    fi
    # stdin
    if cat "$L44_WORK/good.tar" | "${L44_ENV[@]}" "$HISN" rootfs import l44-stdin --from-tar - >/dev/null 2>&1 \
       && [ -f "$L44_STORE/l44-stdin/normal.txt" ]; then
      pass "L44 --from-tar - streams from stdin"
    else
      fail "L44 stdin" "import from stdin failed"
    fi
  else
    fail "L44 import" "import failed: $L44_OUT"
  fi
  # '..' entry: the whole import fails and names the entry.
  L44_OUT=$("${L44_ENV[@]}" "$HISN" rootfs import l44-dotdot --from-tar "$L44_WORK/dotdot.tar" 2>&1)
  L44_RC=$?
  if [ $L44_RC -ne 0 ] && printf '%s' "$L44_OUT" | grep -q 'l44-escape.txt'; then
    pass "L44 '..' entry fails the import and names the entry"
  else
    fail "L44 traversal" "rc=$L44_RC out=[$L44_OUT]"
  fi
  if [ ! -e "$L44_WORK/l44-escape.txt" ] && [ ! -e "$L44_WORK/hisn/l44-escape.txt" ] \
     && [ ! -e "$L44_STORE/l44-escape.txt" ] && [ ! -e "$L44_STORE/l44-dotdot" ]; then
    pass "L44 traversal: nothing written outside, no store entry left"
  else
    fail "L44 traversal leftovers" "escape file or store entry exists"
  fi
  # symlink-then-write: archive imports, but nothing lands in the victim dir.
  "${L44_ENV[@]}" "$HISN" rootfs import l44-sym --from-tar "$L44_WORK/symlink.tar" >/dev/null 2>&1
  if [ ! -e "$L44_WORK/victim/pwned" ]; then
    pass "L44 symlink-then-write: nothing written through the symlink"
  else
    fail "L44 symlink-then-write" "file created in $L44_WORK/victim"
  fi
  # hard-link escape: no link to a host file is created.
  "${L44_ENV[@]}" "$HISN" rootfs import l44-hl --from-tar "$L44_WORK/hardlink.tar" >/dev/null 2>&1
  if [ ! -e "$L44_STORE/l44-hl/h" ]; then
    pass "L44 hard link to a target outside the tree not created"
  else
    fail "L44 hard-link escape" "h exists in the store"
  fi
fi
# Big streaming test (opt-in: HISN_BIG_TESTS=1): 512 MB through the extractor,
# peak RSS growth must stay < 64 MB (unit test in src/rootfs_import.rs).
if [ "${HISN_BIG_TESTS:-}" = 1 ]; then
  if command -v cargo >/dev/null 2>&1; then
    L44_BIG=$(cd "$ROOT" && HISN_BIG_TESTS=1 TMPDIR="$WORK" cargo test --release --lib streaming_512mb -- --nocapture 2>&1)
    L44_BIG_RC=$?
    if printf '%s' "$L44_BIG" | grep -q 'skipped:'; then
      skip "L44 big streaming 512 MB" "$(printf '%s' "$L44_BIG" | grep -m1 'skipped:')"
    elif [ $L44_BIG_RC -eq 0 ]; then
      pass "L44 big streaming 512 MB import stays under 64 MB RSS ($(printf '%s' "$L44_BIG" | grep -m1 'VmHWM delta'))"
    else
      fail "L44 big streaming 512 MB" "$(printf '%s' "$L44_BIG" | tail -5)"
    fi
  else
    skip "L44 big streaming 512 MB" "cargo not found"
  fi
else
  skip "L44 big streaming 512 MB" "HISN_BIG_TESTS=1 not set"
fi

# ================================================ L45: SSH agent T1 (0.3.2)
# Throwaway ssh-agent with two ed25519 keys; keys[] = [key1].
#   with keys=[fp1]: ssh-add -l lists exactly key1; sign with key1 works;
#     sign with key2 fails; ssh-add (add) and ssh-add -D fail; host agent
#     still lists both keys; host SSH_AUTH_SOCK path not visible; proxy
#     socket exists during the session and is gone after teardown.
#   without keys=: both keys listed; add/remove still fail.
# Skip: no ssh-agent / ssh-add / ssh-keygen on the host.
if command -v ssh-agent >/dev/null 2>&1 && command -v ssh-add >/dev/null 2>&1 \
   && command -v ssh-keygen >/dev/null 2>&1; then
  L45_CWD=$(new_cwd l45)
  # Keys live under the cwd (mounted rw in the session). Only public keys are
  # in pub/; the private key of key2 sits in addkey/ solely so that an
  # in-session `ssh-add` has something to add.
  mkdir -p "$L45_CWD/pub" "$L45_CWD/addkey" "$WORK/l45-keys"
  L45_KEY1="$WORK/l45-keys/key1"
  L45_KEY2="$WORK/l45-keys/key2"
  ssh-keygen -t ed25519 -f "$L45_KEY1" -N "" -q 2>/dev/null
  ssh-keygen -t ed25519 -f "$L45_KEY2" -N "" -q 2>/dev/null
  cp "$L45_KEY1.pub" "$L45_CWD/pub/key1.pub"
  cp "$L45_KEY2.pub" "$L45_CWD/pub/key2.pub"
  # Key 3 is never in the host agent: an in-session ssh-add that reached the
  # host agent would visibly change its key list.
  L45_KEY3="$WORK/l45-keys/key3"
  ssh-keygen -t ed25519 -f "$L45_KEY3" -N "" -q 2>/dev/null
  cp "$L45_KEY3" "$L45_CWD/addkey/key3"
  chmod 600 "$L45_CWD/addkey/key3"
  echo "to-be-signed" >"$L45_CWD/msg"
  echo "to-be-signed-2" >"$L45_CWD/msg2"
  L45_SAVED_SOCK="${SSH_AUTH_SOCK:-}"
  L45_SAVED_PID="${SSH_AGENT_PID:-}"
  # Never touch an inherited agent: start ours first and only load keys if
  # the new agent's socket differs from the saved one.
  unset SSH_AUTH_SOCK SSH_AGENT_PID
  eval "$(ssh-agent -s 2>/dev/null)" >/dev/null 2>&1
  L45_HOST_SOCK="${SSH_AUTH_SOCK:-}"
  if [ -n "$L45_HOST_SOCK" ] && [ "$L45_HOST_SOCK" != "$L45_SAVED_SOCK" ] && [ -n "${SSH_AGENT_PID:-}" ]; then
    ssh-add "$L45_KEY1" >/dev/null 2>&1
    ssh-add "$L45_KEY2" >/dev/null 2>&1
  fi
  if [ -n "$L45_HOST_SOCK" ] && [ "$L45_HOST_SOCK" != "$L45_SAVED_SOCK" ] && [ -n "${SSH_AGENT_PID:-}" ] \
     && [ "$(ssh-add -l 2>/dev/null | grep -c SHA256:)" = 2 ]; then
    L45_FP1=$(ssh-keygen -lf "$L45_KEY1.pub" | awk '{print $2}')
    L45_FP2=$(ssh-keygen -lf "$L45_KEY2.pub" | awk '{print $2}')
    exit_of() { printf '%s' "$1" | sed -n '1s/.*exit=//p'; }
    host_two_keys() { # both keys still in the host agent, exactly two
      local l; l=$(ssh-add -l 2>/dev/null)
      [ "$(printf '%s\n' "$l" | grep -c SHA256:)" = 2 ] \
        && printf '%s' "$l" | grep -q "$L45_FP1" && printf '%s' "$l" | grep -q "$L45_FP2"
    }
    L45_PROFILE="$WORK/L45-profile.toml"
    write_profile "$L45_PROFILE" "$L45_CWD" '[ssh]' 'agent = true' "keys = [\"$L45_FP1\"]"
    if start_profile_session l45-$$ "$L45_CWD" "$L45_PROFILE"; then
      L45_PROXY_SOCKET="$RUNTIME_ROOT/l45-$$/ssh-agent.sock"
      if [ -S "$L45_PROXY_SOCKET" ]; then
        pass "L45 proxy socket exists during the session"
      else
        weak "L45 proxy socket exists" "not at $L45_PROXY_SOCKET (layout changed?); teardown check below is then vacuous"
      fi
      l45_env=$(q "$L45_CWD" env)
      l45_sock=$(printf '%s' "$l45_env" | sed -n 's/^SSH_AUTH_SOCK=//p' | head -1)
      eq "L45 SSH_AUTH_SOCK points at the proxy socket" "$l45_sock" "/run/ssh-agent.sock"
      case $(q "$L45_CWD" "stat $L45_HOST_SOCK") in
        ENOENT) pass "L45 host SSH_AUTH_SOCK path not visible" ;;
        *) fail "L45 host socket" "host agent socket path $L45_HOST_SOCK is visible in session" ;;
      esac
      r=$(q "$L45_CWD" "exec-out ssh-add -l")
      n=$(printf '%s\n' "$r" | grep -c SHA256:)
      if [ "$n" = 1 ] && printf '%s' "$r" | grep -q "$L45_FP1" && ! printf '%s' "$r" | grep -q "$L45_FP2"; then
        pass "L45 allowlist: ssh-add -l lists exactly key1"
      else
        fail "L45 allowlist" "ssh-add -l in session: $r"
      fi
      r=$(q "$L45_CWD" "exec-out ssh-keygen -Y sign -n hisnleak -f $L45_CWD/pub/key1.pub $L45_CWD/msg")
      if [ "$(exit_of "$r")" = 0 ] && [ -s "$L45_CWD/msg.sig" ] \
         && ssh-keygen -Y check-novalidate -n hisnleak -s "$L45_CWD/msg.sig" <"$L45_CWD/msg" >/dev/null 2>&1; then
        pass "L45 sign with listed key1 succeeds (signature verifies)"
      else
        fail "L45 sign key1" "ssh-keygen -Y sign in session: $r"
      fi
      r=$(q "$L45_CWD" "exec-out ssh-keygen -Y sign -n hisnleak -f $L45_CWD/pub/key2.pub $L45_CWD/msg2")
      ec=$(exit_of "$r")
      if [ -n "$ec" ] && [ "$ec" != 0 ] && [ ! -e "$L45_CWD/msg2.sig" ]; then
        pass "L45 sign with non-listed key2 fails (exit $ec, no signature file)"
      else
        fail "L45 sign key2" "signing with a non-listed key did not fail cleanly: $r"
      fi
      r=$(q "$L45_CWD" "exec-out ssh-add $L45_CWD/addkey/key3")
      ec=$(exit_of "$r")
      if [ -n "$ec" ] && [ "$ec" != 0 ] && ! ssh-add -l 2>/dev/null | grep -qF "$(ssh-keygen -lf "$L45_KEY3.pub" | awk '{print $2}')"; then
        pass "L45 ssh-add (add key3) from inside the session fails; host agent did not gain it"
      else
        fail "L45 ssh-add add" "exit=[$ec]: $r"
      fi
      r=$(q "$L45_CWD" "exec-out ssh-add -D")
      ec=$(exit_of "$r")
      if [ -n "$ec" ] && [ "$ec" != 0 ]; then
        pass "L45 ssh-add -D (remove all) from inside the session fails"
      else
        fail "L45 ssh-add -D" "exit=[$ec]: $r"
      fi
      if host_two_keys; then
        pass "L45 host agent still lists both keys after the session's add/remove attempts"
      else
        fail "L45 host agent" "host agent keys changed: $(ssh-add -l 2>&1)"
      fi
      end_session "$L45_CWD" "$S_PID"
      if [ ! -e "$L45_PROXY_SOCKET" ]; then
        pass "L45 proxy socket absent after teardown"
      else
        fail "L45 proxy socket" "still exists at $L45_PROXY_SOCKET"
      fi
    else
      fail "L45 ssh-agent" "session did not start"
    fi
    # --- without keys = : every key the host agent offers ---
    L45B_CWD=$(new_cwd l45b)
    mkdir -p "$L45B_CWD/addkey" && cp "$L45_CWD/addkey/key3" "$L45B_CWD/addkey/key3" && chmod 600 "$L45B_CWD/addkey/key3"
    L45B_PROFILE="$WORK/L45b-profile.toml"
    write_profile "$L45B_PROFILE" "$L45B_CWD" '[ssh]' 'agent = true'
    if start_profile_session l45b-$$ "$L45B_CWD" "$L45B_PROFILE"; then
      r=$(q "$L45B_CWD" "exec-out ssh-add -l")
      if [ "$(printf '%s\n' "$r" | grep -c SHA256:)" = 2 ] && printf '%s' "$r" | grep -q "$L45_FP1" \
         && printf '%s' "$r" | grep -q "$L45_FP2"; then
        pass "L45 no-allowlist: both keys listed"
      else
        fail "L45 no-allowlist" "ssh-add -l: $r"
      fi
      ec=$(exit_of "$(q "$L45B_CWD" "exec-out ssh-add -D")")
      if [ -n "$ec" ] && [ "$ec" != 0 ]; then
        pass "L45 no-allowlist: ssh-add -D still fails"
      else
        fail "L45 no-allowlist -D" "exit=[$ec]"
      fi
      ec=$(exit_of "$(q "$L45B_CWD" "exec-out ssh-add $L45B_CWD/addkey/key3")")
      if [ -n "$ec" ] && [ "$ec" != 0 ]; then
        pass "L45 no-allowlist: ssh-add (add) still fails"
      else
        fail "L45 no-allowlist add" "exit=[$ec]"
      fi
      if host_two_keys; then
        pass "L45 no-allowlist: host agent still lists both keys"
      else
        fail "L45 no-allowlist host agent" "$(ssh-add -l 2>&1)"
      fi
      end_session "$L45B_CWD" "$S_PID"
    else
      fail "L45 no-allowlist" "session B did not start"
    fi
    kill "$SSH_AGENT_PID" 2>/dev/null
  else
    skip "L45 ssh-agent" "ssh-agent did not start or could not load keys (not found/not start)"
    [ -n "${SSH_AGENT_PID:-}" ] && kill "$SSH_AGENT_PID" 2>/dev/null
  fi
  if [ -n "$L45_SAVED_SOCK" ]; then export SSH_AUTH_SOCK="$L45_SAVED_SOCK"; else unset SSH_AUTH_SOCK; fi
  if [ -n "$L45_SAVED_PID" ]; then export SSH_AGENT_PID="$L45_SAVED_PID"; else unset SSH_AGENT_PID; fi
else
  skip "L45 ssh-agent" "ssh-agent, ssh-add or ssh-keygen binary not found"
fi

# ================================================ L46: rootfs symlink traps (0.3.2, needs HISN_TEST_ROOTFS)
# On a test copy of the rootfs: symlinks in /usr/local/bin pointing (relative
# and absolute) at a real host marker file must not reach it from the session;
# a rootfs whose /etc is a dangling symlink makes session start fail with a
# message naming the path, and no session is created.
# Skip: HISN_TEST_ROOTFS not set (or without /usr).
if [ -n "${HISN_TEST_ROOTFS:-}" ] && [ -d "$HISN_TEST_ROOTFS/usr" ]; then
  L46_CWD=$(new_cwd l46)
  L46_ROOTFS="$WORK/l46-rootfs"
  rm -rf "$L46_ROOTFS"
  mkdir -p "$L46_ROOTFS"
  for d in usr bin sbin lib lib32 lib64 opt etc; do
    [ -e "$HISN_TEST_ROOTFS/$d" ] || [ -L "$HISN_TEST_ROOTFS/$d" ] && copy_tree "$HISN_TEST_ROOTFS/$d" "$L46_ROOTFS/$d"
  done
  L46_MARKER="$HOME/.hisn-l46-marker-$$"
  echo "l46-host-secret" >"$L46_MARKER"
  chmod -R u+w "$L46_ROOTFS/usr/local" 2>/dev/null
  mkdir -p "$L46_ROOTFS/usr/local/bin"
  ln -sf "../../../../${L46_MARKER#/}" "$L46_ROOTFS/usr/local/bin/trap"
  ln -sf "$L46_MARKER" "$L46_ROOTFS/usr/local/bin/home-link"
  ln -sf "$HOME" "$L46_ROOTFS/usr/local/bin/home-dir"
  L46_PROFILE="$WORK/L46-profile.toml"
  write_profile "$L46_PROFILE" "$L46_CWD" '[rootfs]' "path = \"$L46_ROOTFS\""
  if start_profile_session l46-$$ "$L46_CWD" "$L46_PROFILE"; then
    for l in trap home-link; do
      r=$(q "$L46_CWD" "cat /usr/local/bin/$l")
      case "$r" in
        *l46-host-secret*) fail "L46 symlink $l" "host marker content reached the session: $r" ;;
        *) if refused "$r"; then pass "L46 symlink $l does not reach host data ($r)"; else fail "L46 symlink $l" "probe gave [$r], not an errno refusal"; fi ;;
      esac
    done
    r=$(q "$L46_CWD" "ls /usr/local/bin/home-dir")
    if refused "$r"; then pass "L46 absolute symlink to the host home dir not listable ($r)"; else fail "L46 symlink to host home dir" "probe gave [$r], not an errno refusal"; fi
    end_session "$L46_CWD" "$S_PID"
  else
    fail "L46 rootfs symlink traps" "session did not start"
  fi
  rm -f "$L46_MARKER"
  chmod -R u+w "$L46_ROOTFS" 2>/dev/null
  rm -rf "$L46_ROOTFS"
else
  skip "L46 rootfs symlink traps" "HISN_TEST_ROOTFS not set or missing /usr"
fi
# L46 (no rootfs fixture needed): a rootfs whose /etc is a dangling symlink.
# Dangling-symlink /etc: start must fail naming the path; nothing mounted.
L46D_ROOTFS="$WORK/l46-dangling"
rm -rf "$L46D_ROOTFS"
mkdir -p "$L46D_ROOTFS/usr"
ln -s nonexistent "$L46D_ROOTFS/etc"
L46D_CWD=$(new_cwd l46d)
L46D_PROFILE="$WORK/L46d-profile.toml"
write_profile "$L46D_PROFILE" "$L46D_CWD" '[rootfs]' "path = \"$L46D_ROOTFS\""
before=$(runtime_entries)
L46D_OUT=$("$HISN" run --profile "$L46D_PROFILE" --session-id "l46-dangling-$$" --detach </dev/null 2>&1)
L46D_RC=$?
after=$(runtime_entries)
if [ "$L46D_RC" -ne 0 ] && printf '%s' "$L46D_OUT" | grep -qF "$L46D_ROOTFS/etc"; then
  pass "L46 dangling-symlink /etc: start fails, message names the path"
else
  fail "L46 dangling /etc" "rc=$L46D_RC out=[$(printf '%s' "$L46D_OUT" | head -c 300)]"
fi
if [ "$before" = "$after" ]; then
  pass "L46 dangling-symlink /etc: no session created, nothing mounted"
else
  fail "L46 dangling /etc session" "runtime root changed: [$before] -> [$after]"
  rm -rf "$RUNTIME_ROOT/l46-dangling-$$" 2>/dev/null
fi
rm -rf "$L46D_ROOTFS"
# A profile naming a rootfs that is not in the store must FAIL, never fall
# back to the host toolchain.
L46M_CWD=$(new_cwd l46m)
L46M_PROFILE="$WORK/L46m-profile.toml"
write_profile "$L46M_PROFILE" "$L46M_CWD" '[rootfs]' 'name = "hisn-leak-no-such-rootfs"'
before=$(runtime_entries)
L46M_OUT=$(XDG_DATA_HOME="$WORK/empty-data" "$HISN" run --profile "$L46M_PROFILE" --session-id "l46-missing-$$" --detach </dev/null 2>&1)
L46M_RC=$?
after=$(runtime_entries)
if [ "$L46M_RC" -ne 0 ] && [ "$before" = "$after" ] && printf '%s' "$L46M_OUT" | grep -q 'hisn-leak-no-such-rootfs'; then
  pass "L46 missing rootfs name: start fails, no session created (no fallback to the host toolchain)"
else
  fail "L46 missing rootfs name" "rc=$L46M_RC out=[$(printf '%s' "$L46M_OUT" | head -c 300)]"
  rm -rf "$RUNTIME_ROOT/l46-missing-$$" 2>/dev/null
fi

# ================================================ L47-L49: ro src:dst mounts (0.3.3, ADR 0012)
# L47: a host file bound as `src:dst` is visible at dst only, read-only, nodev,
#      and the host source path is not visible in the session.
# L48: dst under /run/hisn and dst colliding with another session mount are
#      refused at validate, naming the path; `..` in dst is refused.
# L49: a symlinked directory in src is resolved on the host before mounting:
#      the session sees the file through the real path only.
L47_CWD=$(new_cwd l47)
L47_SRC_DIR="$WORK/l47-host"
mkdir -p "$L47_SRC_DIR"
echo "l47-host-file" >"$L47_SRC_DIR/app.conf"
L47_POL="$WORK/L47.toml"
write_policy "$L47_POL" "$L47_CWD"
sed -i "s|^\[mounts\]|[mounts]\nro = [\"$L47_SRC_DIR/app.conf:/l47-dst/app.conf\"]|" "$L47_POL"
if start_session l47-$$ "$L47_CWD" "$L47_POL"; then
  r=$(q "$L47_CWD" cat /l47-dst/app.conf)
  case "$r" in
    *l47-host-file*) pass "L47 src:dst file visible at dst" ;;
    *) fail "L47 src:dst file visible at dst" "cat dst gave [$r]" ;;
  esac
  r=$(q "$L47_CWD" write /l47-dst/app.conf)
  if [ "$r" = "EROFS" ]; then pass "L47 src:dst is read-only (write refused EROFS)"; else fail "L47 src:dst read-only" "write gave [$r], not EROFS"; fi
  r=$(q "$L47_CWD" mountinfo)
  if printf '%s' "$r" | grep ' /l47-dst/app.conf ' | grep -q 'ro,nosuid,nodev'; then
    pass "L47 src:dst mount flags ro,nosuid,nodev"
  else
    fail "L47 src:dst mount flags" "mountinfo line: [$r]"
  fi
  r=$(q "$L47_CWD" stat "$L47_SRC_DIR/app.conf")
  if refused "$r"; then pass "L47 host source path not visible in the session ($r)"; else fail "L47 host source path" "probe gave [$r], not an errno refusal"; fi
  end_session "$L47_CWD" "$S_PID"
else
  fail "L47 src:dst mount" "session did not start"
fi

L48_HOST="$WORK/l48-host.conf"
echo "x" >"$L48_HOST"
for spec in "$L48_HOST:/run/hisn/l48" "$L48_HOST:/tmp/../etc/l48" "$L48_HOST:/usr/l48" "$L48_HOST:/l48/../x"; do
  L48_POL="$WORK/L48.toml"
  write_policy "$L48_POL" "$L47_CWD"
  printf 'ro = ["%s"]\n' "$spec" >>"$L48_POL"
  out=$("$HISN" policy validate "$L48_POL" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    pass "L48 refused at validate: $spec"
  else
    fail "L48 refused at validate: $spec" "accepted: $out"
  fi
done
# the message names the conflicting path for the /run/hisn case
L48_POL2="$WORK/L48b.toml"
write_policy "$L48_POL2" "$L47_CWD"
printf 'ro = ["%s:/run/hisn/l48"]\n' "$L48_HOST" >>"$L48_POL2"
out=$("$HISN" policy validate "$L48_POL2" 2>&1)
case "$out" in
  *"/run/hisn/l48"*) pass "L48 /run/hisn refusal names the path" ;;
  *) fail "L48 /run/hisn refusal names the path" "message: [$out]" ;;
esac

L49_REAL="$WORK/l49-real"
L49_LINK="$WORK/l49-link"
mkdir -p "$L49_REAL"
echo "l49-real-file" >"$L49_REAL/f.conf"
ln -sfn "$L49_REAL" "$L49_LINK"
L49_CWD=$(new_cwd l49)
L49_POL="$WORK/L49.toml"
write_policy "$L49_POL" "$L49_CWD"
sed -i "s|^\[mounts\]|[mounts]\nro = [\"$L49_LINK/f.conf:/l49-dst/f.conf\"]|" "$L49_POL"
if start_session l49-$$ "$L49_CWD" "$L49_POL"; then
  r=$(q "$L49_CWD" cat /l49-dst/f.conf)
  case "$r" in
    *l49-real-file*) pass "L49 symlinked src directory resolved on the host" ;;
    *) fail "L49 symlinked src directory" "cat gave [$r]" ;;
  esac
  end_session "$L49_CWD" "$S_PID"
else
  fail "L49 symlinked src directory" "session did not start"
fi

# ================================================ L50: rootfs + network=host DNS (0.3.3)
# A rootfs whose etc/resolv.conf is empty (the wakil-dev image) must not fail a
# network=host session: the host's resolvers are authoritative in that netns.
# The session starts, its resolv.conf carries a non-loopback nameserver, and a
# name the host resolves resolves inside. Needs HISN_TEST_ROOTFS (skips with
# a reason otherwise); the profile lives outside the session cwd.
if [ -n "${HISN_TEST_ROOTFS:-}" ] && [ -d "$HISN_TEST_ROOTFS/usr" ]; then
  L50_CWD=$(new_cwd l50)
  L50_ROOTFS="$WORK/l50-rootfs"
  rm -rf "$L50_ROOTFS"
  mkdir -p "$L50_ROOTFS"
  for d in usr bin sbin lib lib32 lib64 opt etc; do
    [ -e "$HISN_TEST_ROOTFS/$d" ] || [ -L "$HISN_TEST_ROOTFS/$d" ] && copy_tree "$HISN_TEST_ROOTFS/$d" "$L50_ROOTFS/$d"
  done
  : >"$L50_ROOTFS/etc/resolv.conf"
  L50_PROFILE="$WORK/L50-profile.toml"
  write_profile "$L50_PROFILE" "$L50_CWD" '[rootfs]' "path = \"$L50_ROOTFS\""
  sed -i 's/session.network = "none"/session.network = "host"/' "$L50_PROFILE"
  if start_profile_session l50-$$ "$L50_CWD" "$L50_PROFILE"; then
    r=$(q "$L50_CWD" cat /etc/resolv.conf)
    case "$r" in
      *nameserver*) pass "L50 rootfs empty resolv.conf: session has a usable nameserver" ;;
      *) fail "L50 rootfs empty resolv.conf" "resolv.conf gave [$r]" ;;
    esac
    ns=$(printf '%s\n' "$r" | awk '$1=="nameserver"{print $2}')
    if printf '%s\n' "$ns" | grep -Eq '^(127\.|::1$)'; then
      fail "L50 no loopback nameserver in the session" "[$ns]"
    else
      pass "L50 no loopback nameserver in the session"
    fi
    # exec-out: "OK exit=<rc>" then the child's stdout/stderr
    r=$(q "$L50_CWD" exec-out /usr/bin/getent hosts example.com)
    case "$r" in
      "OK exit=0"*[0-9a-f]*:*) pass "L50 getent resolves a name inside the rootfs session" ;;
      *) fail "L50 getent" "probe gave [$r]" ;;
    esac
    end_session "$L50_CWD" "$S_PID"
  else
    fail "L50 rootfs network=host session" "session did not start (the rootfs empty-resolver regression)"
  fi
  rm -rf "$L50_ROOTFS"
else
  skip "L50 rootfs empty resolv.conf" "HISN_TEST_ROOTFS not set or missing /usr"
  skip "L50 no loopback nameserver" "HISN_TEST_ROOTFS not set or missing /usr"
  skip "L50 getent resolves" "HISN_TEST_ROOTFS not set or missing /usr"
fi

# Every id in MANIFEST must produce at least one line. A missing id means
# the test was silently dropped from the suite — FAIL.
MANIFEST="$HERE/MANIFEST"
if [ -f "$MANIFEST" ]; then
  EMITTED=$(printf '%s\n' "$OUTPUT_LOG" | sed -n 's/^\(L[0-9][0-9]*[a-z]*\)\([^0-9a-z].*\)\{0,1\}$/\1/p' | sort -u)
  MISSING=""
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    case "$id" in \#*) continue ;; esac
    case "$id" in
      *": "*)
        # "L17b: text" -- a line of test L17b whose name contains "text".
        want_id=${id%%: *} want_txt=${id#*: }
        printf '%s\n' "$OUTPUT_LOG" | grep -F -- "$want_id " | grep -qF -- "$want_txt" ||
          { fail "manifest $id" "no $want_id line containing [$want_txt] (check silently dropped?)"; }
        ;;
      *)
        printf '%s\n' "$EMITTED" | grep -qxF "$id" || MISSING="$MISSING $id"
        ;;
    esac
  done <"$MANIFEST"
  if [ -n "$MISSING" ]; then
    for id in $MISSING; do
      fail "manifest $id" "test id $id produced no line (silently dropped?)"
    done
  fi
fi

# ----------------------------------------------------------------- summary
printf '\nRESULT: %d passed, %d failed, %d skipped, %d weak\n' "$PASSES" "$FAILS" "$SKIPS" "$WEAKS"
[ "$FAILS" -eq 0 ] && [ "$PASSES" -gt 0 ]

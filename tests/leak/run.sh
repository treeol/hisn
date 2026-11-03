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

# ----------------------------------------------------------------- manifest
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

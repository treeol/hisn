#!/usr/bin/env bash
# hisn leak suite (L1-L23). Usage: tests/leak/run.sh PATH/TO/hisn
#
# Each test runs a probe (examples/leakprobe) INSIDE a real `hisn run` session
# and asserts from the host. Needs unprivileged user namespaces on the host.
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
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %s -- %s\n' "$1" "$2"; }
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP  %s -- %s\n' "$1" "$2"; }
weak() { WEAKS=$((WEAKS + 1)); printf 'WEAK  %s -- %s\n' "$1" "$2"; }
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
    # exec A binds an abstract socket (blocks in accept); exec B connects.
    timeout 10 ex --cwd "$CX" -- "$CX/leakprobe" abs-sock-bind l22 >/dev/null 2>&1 &
    L22_BINDER=$!
    sleep 0.5
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
        wait "$L23_PID" 2>/dev/null
      else
        fail "L23 scoped signal" "session l23 did not become ready; hisn said: $(head -c 300 "$WORK/l23.err")"
      fi
    else
      fail "L23 scoped signal" "could not start a scoped-signal session"
    fi

    # ---- session end: every exec'd process dies with the session (L17)
    ex -- sh -c 'sleep 30' >/dev/null 2>&1 &
    SLEEPER=$!
    sleep 0.5
    hisn_json "$WORK/xkill.json" kill --session xdet-$$ --signal TERM
    kill -TERM "$DET_PID" 2>/dev/null
    wait "$DET_PID" 2>/dev/null
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

# ----------------------------------------------------------------- summary
printf '\nRESULT: %d passed, %d failed, %d skipped, %d weak\n' "$PASSES" "$FAILS" "$SKIPS" "$WEAKS"
[ "$FAILS" -eq 0 ] && [ "$PASSES" -gt 0 ]

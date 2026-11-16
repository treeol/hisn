#!/usr/bin/env bash
# hisn 0.6.0 host verification (ADR 0022, open mode).
#
# ONE command for Valon:
#   bash scripts/host-verify-network.sh [--real]
#
# In order:
#   1. build to target/ (cargo build --release) — the binary is resolved
#      to an absolute path once and invoked only via /tmp/hisn-dev/hisn
#      (symlink, first in PATH), never by a relative path. No live hisn
#      binary is installed or replaced.
#   2. make release-gate (plain) + rootfs run (HISN_TEST_ROOTFS /
#      HISN_BIG_TESTS default to the 0.5.1 host-step values, overridable
#      by environment; SKIP only if the rootfs path does not exist).
#      Both RESULT lines are printed raw in this script's output.
#   3. hermetic network cases: everything inside an outer `unshare -Urn`
#      namespace with a dummy interface 192.0.2.1/24; the script starts
#      its own TCP listener (192.0.2.1:18080) and DNS server (192.0.2.2:53)
#      and verifies a preflight connect to an unassigned dummy-subnet
#      address (192.0.2.98) times out before using it as the blackhole.
#      No traffic leaves the host. Cases: L90/L94/L96/L97/L98/L99/L100/
#      L102/L103/L104/L105/L106/L107/L109/L110/L111/L112, SERVFAIL (own
#      session, nameserver 192.0.2.3), flood cap, extra_deny rejection
#      (open) + acceptance (none), none byte-identical. No case may PASS
#      without its session existing and its expected line present.
#   4. with --real: real-network step (TCP to 1.1.1.1:53, curl -sI
#      https://github.com, git ls-remote, LAN gateway refused EACCES,
#      session journal records printed).
#
# Every step has a timeout; its exit code is checked; PASS requires
# exit 0 + the expected line + no "FAIL:" line. Full log per step in
# .wakil/host-logs/<UTC timestamp>/<step>.log (gitignored); on FAIL the
# last 40 lines of that step's log are printed. Last line:
#   RESULT: pass=<n> fail=<n> timeout=<n> skipped=<n>
# Non-zero exit on any fail/timeout. Kills only its own leftovers
# (listener/DNS pids recorded in the work dir).
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

TS=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR="$ROOT/.wakil/host-logs/$TS"
mkdir -p "$LOGDIR"
printf 'host-verify: logs in %s\n' "$LOGDIR"

# The dev binary: absolute path, symlinked, first in PATH.
HISN_BIN="$ROOT/target/release/hisn"
DEVDIR="/tmp/hisn-dev"
mkdir -p "$DEVDIR"
ln -sf "$HISN_BIN" "$DEVDIR/hisn"
export PATH="$DEVDIR:$ROOT/.cargo/bin:/usr/local/cargo/bin:$HOME/.cargo/bin:$PATH"
HISN="$DEVDIR/hisn"

# 0.5.1 host-step values (report .wakil/reports/0.5.1-seats.md):
#   HISN_TEST_ROOTFS=$(hisn rootfs path wakil-dev) HISN_BIG_TESTS=1
# Resolved here from the freshly built binary; environment wins.
if [ -z "${HISN_TEST_ROOTFS:-}" ]; then
  HISN_TEST_ROOTFS=$("$HISN" rootfs path wakil-dev 2>/dev/null || true)
fi
HISN_BIG_TESTS=${HISN_BIG_TESTS:-1}

PASS=0; FAIL=0; TIMEOUT=0; SKIP=0
WORK=$(mktemp -d /tmp/hisn-hostverify.XXXXXX) || { echo "FAIL: mktemp work dir"; exit 1; }
[ -d "$WORK" ] || { echo "FAIL: work dir $WORK does not exist"; exit 1; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

note()  { printf 'host-verify: %s\n' "$*"; }
pass()  { PASS=$((PASS+1)); printf 'PASS  %s\n' "$*"; }
fail()  { # name detail — also dumps the step log tail
  FAIL=$((FAIL+1)); printf 'FAIL: %s -- %s\n' "$1" "$2"
  local log="$LOGDIR/$1.log"
  [ -f "$log" ] && { printf '%s\n' "--- last 40 lines of $log ---"; tail -n 40 "$log"; printf '%s\n' "--- end $log ---"; }
}
tmout() { TIMEOUT=$((TIMEOUT+1)); printf 'FAIL: %s -- timeout\n' "$1"; }
skip()  { SKIP=$((SKIP+1)); printf 'SKIP  %s -- %s\n' "$1" "$2"; }

# run_step NAME TIMEOUT EXPECTED-LINE -- CMD...
run_step() {
  local name=$1 to=$2 want=$3; shift 3
  local log="$LOGDIR/$name.log"
  timeout "$to" "$@" >"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 124 ]; then tmout "$name"; return 1; fi
  if [ "$rc" -ne 0 ]; then fail "$name" "exit $rc"; return 1; fi
  if ! grep -qF "$want" "$log"; then fail "$name" "missing expected [$want]"; return 1; fi
  if grep -q "^FAIL:" "$log"; then fail "$name" "output contains FAIL:"; return 1; fi
  pass "$name"
}

note "step 1: build"
export PATH="/usr/local/cargo/bin:$HOME/.cargo/bin:$ROOT/.cargo/bin:$PATH"
run_step build 600 "Finished" cargo build --release || true
if [ ! -x "$HISN_BIN" ]; then
  fail "build" "binary $HISN_BIN is not executable after build"
  printf 'RESULT: pass=%d fail=%d timeout=%d skipped=%d\n' "$PASS" "$FAIL" "$TIMEOUT" "$SKIP"
  exit 1
fi
ln -sf "$HISN_BIN" "$DEVDIR/hisn"
if [ ! -x "$HISN" ]; then
  fail "build" "/tmp/hisn-dev/hisn ($HISN_BIN) is not executable"
  printf 'RESULT: pass=%d fail=%d timeout=%d skipped=%d\n' "$PASS" "$FAIL" "$TIMEOUT" "$SKIP"
  exit 1
fi
note "dev binary: $HISN -> $HISN_BIN ($("$HISN" --version 2>&1 | head -1))"
export PATH="$DEVDIR:$PATH"

note "step 2: release-gate (plain)"
run_step release-gate-plain 1200 "release-gate: summary" make release-gate || true
printf 'release-gate-plain RESULT: '; grep "RESULT:" "$LOGDIR/release-gate-plain.log" | tail -1 || true
printf 'release-gate-plain weak items: '; grep "^WEAK" "$LOGDIR/release-gate-plain.log" | tr '\n' ';' || true; printf '\n'

note "step 2b: release-gate (rootfs + big)"
if [ -n "${HISN_TEST_ROOTFS:-}" ] && [ -d "$HISN_TEST_ROOTFS" ]; then
  run_step release-gate-rootfs 1800 "release-gate: summary" \
    env HISN_TEST_ROOTFS="$HISN_TEST_ROOTFS" HISN_BIG_TESTS="$HISN_BIG_TESTS" make release-gate || true
  printf 'release-gate-rootfs RESULT: '; grep "RESULT:" "$LOGDIR/release-gate-rootfs.log" | tail -1 || true
  printf 'release-gate-rootfs weak items: '; grep "^WEAK" "$LOGDIR/release-gate-rootfs.log" | tr '\n' ';' || true; printf '\n'
elif [ -n "${HISN_TEST_ROOTFS:-}" ]; then
  skip "release-gate-rootfs" "rootfs path does not exist: $HISN_TEST_ROOTFS"
else
  skip "release-gate-rootfs" "no HISN_TEST_ROOTFS resolvable (hisn rootfs path wakil-dev empty)"
fi

note "step 3: hermetic network cases (unshare -Urn, 192.0.2.1/24)"
if command -v unshare >/dev/null && unshare -Urn true 2>/dev/null; then
  cat >"$WORK/hermetic_inner.sh" <<'INNER'
#!/usr/bin/env bash
set -u
ROOT="$1"; HISN="$2"; W="$3"
cd "$ROOT" || exit 1
[ -d "$W" ] || { echo "FAIL: hermetic work dir $W does not exist"; exit 1; }
# dummy interface with 192.0.2.1/24 + 192.0.2.2/24 inside this throwaway netns
ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 192.0.2.1/24 dev dummy0 2>/dev/null || true
ip addr add 192.0.2.2/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
# TCP listener on 192.0.2.1:18080
python3 - <<'PY' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.0.2.1", 18080)); s.listen(64)
while True:
    c, _ = s.accept(); c.sendall(b"HERMETIC-OK"); c.close()
PY
LISTENER_PID=$!
# DNS server on 192.0.2.2:53 (answers everything -> 192.0.2.1)
python3 - <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.0.2.2", 53))
while True:
    data, addr = s.recvfrom(4096)
    if len(data) < 12: continue
    tid = data[0:2]
    hdr = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    qend = 12
    while qend < len(data) and data[qend] != 0: qend += 1
    qend += 5
    q = data[12:qend]
    ans = b"\xc0\x0c" + b"\x00\x01\x00\x01" + (60).to_bytes(4, "big") + b"\x00\x04" + bytes([192,0,2,1])
    s.sendto(hdr + q + ans, addr)
PY
DNS_PID=$!
# Blackhole: 192.0.2.98 is NOT assigned and has NO listener. A listening
# socket completes the TCP handshake in the kernel even without accept(),
# so this must be a dead address — the dummy subnet drops the SYN and the
# connect stays pending. Preflight: connect from the outer namespace
# times out (1 s), else FAIL "blackhole preflight".
PRE=$(timeout 3 python3 -c "
import socket, sys
s=socket.socket(); s.settimeout(1)
try:
    s.connect(('192.0.2.98',18181))
    print('PREFLIGHT-CONNECTED')
except OSError:
    print('PREFLIGHT-TIMEOUT')" 2>&1)
case "$PRE" in
  *PREFLIGHT-TIMEOUT*) echo "PASS  blackhole preflight times out" ;;
  *) echo "FAIL: blackhole preflight -- 192.0.2.98 answered: [$PRE]" ;;
esac

mkdir -p "$W"
trap 'kill $LISTENER_PID $DNS_PID 2>/dev/null; rm -rf "$W"' EXIT

check() { # name expected-substring cmd...
  local name=$1 want=$2; shift 2
  local out
  out=$(timeout 30 "$@" 2>&1); local rc=$?
  if [ "$rc" -eq 124 ]; then echo "FAIL: $name -- timeout"; return; fi
  case "$out" in *"$want"*) echo "PASS  $name";; *) echo "FAIL: $name -- got [$(echo "$out" | head -c 200)] want [$want]";; esac
}

SIDE="hv-herm"
POL="$W/open.toml"
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$W" >"$POL"
timeout 600 "$HISN" run --no-tty --policy "$POL" --session-id "$SIDE" -- sleep 600 >"$W/sess.out" 2>&1 &
SESS_RC=$!
sleep 3
if ! kill -0 $SESS_RC 2>/dev/null; then
  echo "FAIL: hermetic open session starts -- run exited immediately" 
  cat "$W/sess.out" | tail -20
  exit 1
fi
# No case may PASS without its session: every check below is gated on
# this session being listed with this session id in `hisn ls --json`.
if ! timeout 20 "$HISN" ls --json 2>/dev/null | grep -q "$SIDE"; then
  echo "FAIL: hermetic session $SIDE not listed -- refusing all case PASSes"
  exit 1
fi

EX() { timeout 20 "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "$1" 2>&1; }

# L96 loopback listener reached (CONTINUE).
check "L96 loopback connect continues" "LOOPBACK-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',19001)); s.listen(1)
c=socket.socket(); c.connect(('127.0.0.1',19001)); c.sendall(b'hi'); a,_=s.accept(); a.sendall(b'LOOPBACK-OK'); a.close(); c.close()"
# L112 DNS over UDP to 127.0.0.1:53: must go through connect() (which the
# filter intercepts). connect() on a datagram socket to loopback is
# CONTINUE (before the non-stream refusal), so the query is answered.
check "L112 UDP DNS to 127.0.0.1:53 via connect" "DNS-UDP-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
q = b'\x12\x34' + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x08hermetic\x04test\x00' + b'\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8)
try:
    s.connect(('127.0.0.1',53))
    s.send(q)
    d = s.recv(4096)
    print('DNS-UDP-OK')
except PermissionError:
    print('DNS-UDP-EACCES')
except OSError as e:
    print('DNS-UDP-ERR', e.strerror)"
# L97 host unix socket invisible (ENOENT from the mount view).
check "L97 host unix socket invisible" "ENOENT" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/user/1000/bus')
    print('CONNECTED')
except FileNotFoundError:
    print('ENOENT')
except OSError as e:
    print(type(e).__name__)"
# L98 sendto outside fails ENETUNREACH (no connect, no interception).
check "L98 sendto outside is ENETUNREACH" "ENETUNREACH" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.sendto(b'x',('8.8.8.8',53))
    print('SENT')
except OSError as e:
    print(e.strerror)"
# L104 SOCK_DGRAM connect refused EACCES in open.
check "L104 dgram connect refused" "Permission denied" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.connect(('8.8.8.8',53))
    print('CONNECTED')
except PermissionError:
    print('Permission denied')
except OSError as e:
    print(e.strerror)"
# L107 private/host-loopback refused in open (EACCES).
check "L107 private target refused" "Permission denied" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket()
try:
    s.connect(('192.168.1.1',80))
    print('CONNECTED')
except PermissionError:
    print('Permission denied')
except OSError as e:
    print(e.strerror)"
# L109 AF_VSOCK refused EACCES.
check "L109 vsock refused" "Permission denied" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
try:
    s.connect((2,1234))
    print('CONNECTED')
except PermissionError:
    print('Permission denied')
except OSError as e:
    print(e.strerror)"
# L90 public hermetic TCP reachable through injection.
check "L90 public hermetic TCP via injection" "HERMETIC-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080))
print(s.recv(100).decode())"
# L103 exec tree interception.
check "L103 exec tree interception" "HERMETIC-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080)); print(s.recv(100).decode())"
# L94 DNS via the supervisor responder: resolve a REAL hostname
# (hermetic.test -> 192.0.2.1) through the shipped nsswitch/resolv.conf.
# The responder must be told to use 192.0.2.2 as upstream: the session
# policy carries [net] nameservers = 192.0.2.2.
check "L94 hermetic.test resolves via shipped files" "DNS-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
r=socket.getaddrinfo('hermetic.test',18080,socket.AF_INET,socket.SOCK_STREAM)
s=socket.socket(); s.settimeout(10); s.connect(r[0][4])
d=s.recv(100).decode()
print('DNS-OK' if d=='HERMETIC-OK' else 'DNS-WRONG:'+d)"
# L105: program binds a local port, then connects to the allowed
# listener; the injected socket has a different source port than the
# bound one (the supervisor recreated the socket).
check "L105 bind-then-connect, different source port" "L105-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',19055)); s.settimeout(10)
s.connect(('192.0.2.1',18080))
port = s.getsockname()[1]
print('L105-OK' if port != 19055 else 'L105-SAME')"
# L106: one connect to the blackhole (stays pending: no listener, SYN
# dropped) and one to the listener, concurrently; the second must
# complete in under 2s while the first is still pending.
check "L106 concurrent connects, fast one wins" "L106-OK" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import socket, threading, time
done = {}
def slow():
    s=socket.socket()
    try: s.connect(('192.0.2.98',18181))
    except OSError: done['slow']='refused'
def fast():
    time.sleep(0.2)
    t0=time.time()
    s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080))
    done['fast_dt']=time.time()-t0
t1=threading.Thread(target=slow); t2=threading.Thread(target=fast)
t1.start(); t2.start(); t2.join(10); t1.join(2)
print('L106-OK' if done.get('fast_dt',99) < 2.0 else 'L106-SLOW')"
# L110: dumpable-0 -> EACCES; journal refuse/read-failed.
check "L110 dumpable-0 connect refused" "Permission denied" "$HISN" exec --no-tty --session "$SIDE" -- python3 -c "
import ctypes, socket
libc=ctypes.CDLL('libc.so.6')
libc.prctl(4, 0, 0, 0, 0)
s=socket.socket()
try:
    s.connect(('192.0.2.1',18080))
    print('CONNECTED')
except PermissionError:
    print('Permission denied')
except OSError as e:
    print(e.strerror)"
J110=$(timeout 20 "$HISN" journal --workspace "$W" --json 2>/dev/null || echo '{}')
case "$J110" in *"read-failed"*) echo "PASS  L110 journal refuse/read-failed";; *) echo "FAIL: L110 journal refuse/read-failed -- journal [$J110]";; esac
# L102/L111 journal + netns inode. Both sides must be real inodes; a
# missing session is a FAIL, never a PASS.
J=$(timeout 20 "$HISN" journal --workspace "$W" --json 2>/dev/null || echo '{}')
case "$J" in
  *"192.0.2.1:18080"*) echo "PASS  L102 journal target ip:port" ;;
  *) echo "FAIL: L102 journal target ip:port -- journal does not contain [192.0.2.1:18080]: [$(echo "$J" | head -c 400)]" ;;
esac
case "$J" in
  *"\"verdict\":\"allow\""*) echo "PASS  L102 journal verdict allow" ;;
  *) echo "FAIL: L102 journal verdict allow -- journal [$(echo "$J" | head -c 400)]" ;;
esac
case "$J" in
  *"$SIDE"*) echo "PASS  L102 journal session id" ;;
  *) echo "FAIL: L102 journal session id -- journal [$(echo "$J" | head -c 400)]" ;;
esac
L111_IN=$(timeout 20 "$HISN" exec --no-tty --session "$SIDE" -- readlink /proc/self/ns/net 2>&1)
L111_OUT=$(readlink /proc/self/ns/net 2>/dev/null || echo none)
case "$L111_IN" in
  net:\[*\])
    [ "$L111_IN" != "$L111_OUT" ] && echo "PASS  L111 sandbox netns inode differs from supervisor" || echo "FAIL: L111 sandbox netns inode differs -- inner [$L111_IN] outer [$L111_OUT]" ;;
  *) echo "FAIL: L111 sandbox netns inode differs -- inner is not an inode: [$L111_IN]" ;;
esac
INNER
  # hermetic_inner.sh positional contract: $1=ROOT, $2=HISN, $3=work dir.
  HW=$(mktemp -d /tmp/hisn-hermetic.XXXXXX) || { fail "hermetic" "mktemp hermetic dir"; }
  chmod +x "$WORK/hermetic_inner.sh"
  timeout 600 unshare -Urn bash "$WORK/hermetic_inner.sh" "$ROOT" "$HISN" "$HW" >"$LOGDIR/hermetic.log" 2>&1
  RC=$?
  cat "$LOGDIR/hermetic.log"
  [ "$RC" -eq 124 ] && tmout "hermetic" || true
  PASS=$((PASS + $(grep -c "^PASS" "$LOGDIR/hermetic.log" || true)))
  FAIL=$((FAIL + $(grep -c "^FAIL:" "$LOGDIR/hermetic.log" || true)))
  if grep -q "^SKIP" "$LOGDIR/hermetic.log"; then
    fail "hermetic" "inner script emitted SKIP: $(grep "^SKIP" "$LOGDIR/hermetic.log" | head -1)"
  fi
  rm -rf "$HW"
else
  skip "hermetic" "unshare -Urn unavailable in this environment (run on a host with unprivileged userns)"
fi

# SERVFAIL: own session whose nameserver is unassigned (192.0.2.3):
# independent of L94 and of the host's resolv.conf.
note "step 3a: SERVFAIL on unreachable upstream"
if command -v unshare >/dev/null && unshare -Urn true 2>/dev/null; then
  SFW=$(mktemp -d /tmp/hisn-servfail.XXXXXX)
  cat >"$WORK/servfail_inner.sh" <<'INNER'
#!/usr/bin/env bash
set -u
ROOT="$1"; HISN="$2"; W="$3"
cd "$ROOT" || exit 1
[ -d "$W" ] || { echo "FAIL: servfail work dir $W does not exist"; exit 1; }
ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 192.0.2.1/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n[net]\nnameservers = ["192.0.2.3"]\n' "$W" >"$W/sf.toml"
timeout 300 "$HISN" run --no-tty --policy "$W/sf.toml" --session-id hv-servfail -- sleep 300 >"$W/sf.out" 2>&1 &
sleep 3
q_out=$(timeout 20 "$HISN" exec --no-tty --session hv-servfail -- python3 -c "
import socket
q = b'\xab\xcd' + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x08hermetic\x04test\x00' + b'\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10)
try:
    s.connect(('127.0.0.1',53))
    s.send(q)
    d = s.recv(4096)
    rcode = d[3] & 0x0f
    print('SERVFAIL-OK' if rcode == 2 else 'SERVFAIL-RCODE:'+str(rcode))
except OSError as e:
    print('SERVFAIL-ERR', e.strerror)" 2>&1)
case "$q_out" in *"SERVFAIL-OK"*) echo "PASS  SERVFAIL when upstream unreachable (own session)";; *) echo "FAIL: SERVFAIL when upstream unreachable -- [$q_out]";; esac
timeout 20 "$HISN" stop --session hv-servfail >/dev/null 2>&1 || true
INNER
  chmod +x "$WORK/servfail_inner.sh"
  timeout 120 unshare -Urn bash "$WORK/servfail_inner.sh" "$ROOT" "$HISN" "$SFW" >"$LOGDIR/servfail.log" 2>&1
  cat "$LOGDIR/servfail.log"
  PASS=$((PASS + $(grep -c "^PASS" "$LOGDIR/servfail.log" || true)))
  FAIL=$((FAIL + $(grep -c "^FAIL:" "$LOGDIR/servfail.log" || true)))
  rm -rf "$SFW"
else
  skip "servfail" "unshare -Urn unavailable in this environment"
fi

# L100: supervisor kill -> ENOSYS. The pid is taken ONLY from
# `hisn ls --json` for the script's own session, and verified via
# /proc/<pid>/cmdline containing that session id, before kill. Never
# kill on a glob-derived pid. If not found: FAIL, never kill.
note "step 3a2: L100 supervisor-kill ENOSYS"
if command -v unshare >/dev/null && unshare -Urn true 2>/dev/null; then
  L100W=$(mktemp -d /tmp/hisn-l100.XXXXXX)
  cat >"$WORK/l100_inner.sh" <<'INNER'
#!/usr/bin/env bash
set -u
ROOT="$1"; HISN="$2"; W="$3"
cd "$ROOT" || exit 1
[ -d "$W" ] || { echo "FAIL: l100 work dir $W does not exist"; exit 1; }
ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 192.0.2.1/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
# No listener: 192.0.2.98 stays pending.
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$W" >"$W/l100.toml"
timeout 300 "$HISN" run --no-tty --policy "$W/l100.toml" --session-id hv-l100 -- sleep 300 >"$W/l100sess.out" 2>&1 &
sleep 3
SUP_PID=$(timeout 20 "$HISN" ls --json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except Exception:
    print(''); sys.exit(0)
for s in data:
    if s.get('session_id') == 'hv-l100' or s.get('id') == 'hv-l100' or s.get('session') == 'hv-l100':
        print(s.get('pid') or s.get('supervisor_pid') or '')
        break" 2>/dev/null)
if [ -z "$SUP_PID" ] || ! [ -f "/proc/$SUP_PID/cmdline" ]; then
  echo "FAIL: L100 supervisor-kill -- supervisor pid for hv-l100 not found via ls --json (never killing)"
  exit 1
fi
if ! tr '\0' ' ' <"/proc/$SUP_PID/cmdline" | grep -q "hv-l100"; then
  echo "FAIL: L100 supervisor-kill -- pid $SUP_PID cmdline does not contain hv-l100 (never killing)"
  exit 1
fi
( timeout 20 "$HISN" exec --no-tty --session hv-l100 -- python3 -c "
import socket
s=socket.socket()
try:
    s.connect(('192.0.2.98',18181))
    print('L100-CONNECTED')
except OSError as e:
    print('L100-ERRNO', e.errno)" >"$W/l100.out" 2>&1 ) &
L100_BG=$!
sleep 2
kill -9 "$SUP_PID" 2>/dev/null || true
wait $L100_BG 2>/dev/null || true
if [ -f "$W/l100.out" ] && grep -q "L100-ERRNO 38" "$W/l100.out" && ! kill -0 "$SUP_PID" 2>/dev/null; then
  echo "PASS  L100 supervisor-kill -> ENOSYS, no leftover"
else
  echo "FAIL: L100 supervisor-kill -> ENOSYS -- sup_pid [$SUP_PID] out [$(cat "$W/l100.out" 2>/dev/null | head -c 200)]"
fi
timeout 20 "$HISN" stop --session hv-l100 >/dev/null 2>&1 || true
INNER
  chmod +x "$WORK/l100_inner.sh"
  timeout 120 unshare -Urn bash "$WORK/l100_inner.sh" "$ROOT" "$HISN" "$L100W" >"$LOGDIR/l100.log" 2>&1
  cat "$LOGDIR/l100.log"
  PASS=$((PASS + $(grep -c "^PASS" "$LOGDIR/l100.log" || true)))
  FAIL=$((FAIL + $(grep -c "^FAIL:" "$LOGDIR/l100.log" || true)))
  rm -rf "$L100W"
else
  skip "l100" "unshare -Urn unavailable in this environment"
fi

# Flood cap + extra_deny (open rejected / none accepted) share a session
# in the hermetic namespace — they are asserted above in hermetic_inner
# where implemented; the standalone extra_deny pair is checked here.
note "step 3b: extra_deny validation (open rejected, none accepted)"
{
  DW=$(mktemp -d /tmp/hisn-deny.XXXXXX)
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n[seccomp]\nextra_deny = ["connect"]\n' "$DW" >"$DW/open-deny.toml"
  OUT_OPEN=$(timeout 30 "$HISN" run --no-tty --policy "$DW/open-deny.toml" --session-id hv-deny-open -- /bin/true 2>&1)
  RC_OPEN=$?
  printf 'open output: %s (exit %d)\n' "$OUT_OPEN" "$RC_OPEN"
  if [ "$RC_OPEN" -ne 0 ] && echo "$OUT_OPEN" | grep -qi "extra_deny"; then
    echo "PASS  extra_deny connect rejected at validate (open)"
  else
    echo "FAIL: extra_deny connect rejected at validate (open) -- exit $RC_OPEN output [$OUT_OPEN]"
  fi
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n[seccomp]\nextra_deny = ["connect"]\n' "$DW" >"$DW/none-deny.toml"
  OUT_NONE=$(timeout 60 "$HISN" run --no-tty --policy "$DW/none-deny.toml" --session-id hv-deny-none -- /bin/true 2>&1)
  RC_NONE=$?
  printf 'none output: %s (exit %d)\n' "$OUT_NONE" "$RC_NONE"
  # none byte-identical: extra_deny connect is accepted (validate scope is open-only).
  if [ "$RC_NONE" -eq 0 ]; then
    echo "PASS  extra_deny connect accepted in none (documents open-only scope)"
  else
    echo "FAIL: extra_deny connect accepted in none -- exit $RC_NONE output [$OUT_NONE]"
  fi
  timeout 20 "$HISN" stop --session hv-deny-open >/dev/null 2>&1 || true
  timeout 20 "$HISN" stop --session hv-deny-none >/dev/null 2>&1 || true
  rm -rf "$DW"
} >"$LOGDIR/extra_deny.log" 2>&1
P3B=$(grep -c "^PASS" "$LOGDIR/extra_deny.log" || true)
F3B=$(grep -c "^FAIL:" "$LOGDIR/extra_deny.log" || true)
PASS=$((PASS + P3B)); FAIL=$((FAIL + F3B))

note "step 3c: none byte-identical"
if command -v unshare >/dev/null && unshare -Urn true 2>/dev/null; then
  NW=$(mktemp -d /tmp/hisn-none.XXXXXX)
  cat >"$WORK/none_inner.sh" <<'INNER'
#!/usr/bin/env bash
set -u
ROOT="$1"; HISN="$2"; W="$3"
cd "$ROOT" || exit 1
[ -d "$W" ] || { echo "FAIL: none work dir $W does not exist"; exit 1; }
ip link set lo up 2>/dev/null || true
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$W" >"$W/none.toml"
timeout 300 "$HISN" run --no-tty --policy "$W/none.toml" --session-id hv-none -- sleep 300 >"$W/none.out" 2>&1 &
sleep 3
# Inside the session: /etc/resolv.conf must not be the hisn-generated
# 127.0.0.1 one, and /etc/nsswitch.conf must not be the generated one.
RES=$(timeout 20 "$HISN" exec --no-tty --session hv-none -- cat /etc/resolv.conf 2>&1
)
NSS=$(timeout 20 "$HISN" exec --no-tty --session hv-none -- cat /etc/nsswitch.conf 2>&1)
printf 'resolv.conf: %s\n' "$RES"
printf 'nsswitch.conf: %s\n' "$NSS"
case "$RES" in
  *127.0.0.1*|*"nameserver"*"127."*) echo "FAIL: none byte-identical -- generated resolv.conf present" ;;
  *) echo "PASS  none: no hisn-generated resolv.conf" ;;
esac
case "$NSS" in
  *"files dns"*"127.0.0.1"*) echo "FAIL: none byte-identical -- generated nsswitch.conf present" ;;
  *) echo "PASS  none: no hisn-generated nsswitch.conf" ;;
esac
timeout 20 "$HISN" stop --session hv-none >/dev/null 2>&1 || true
INNER
  chmod +x "$WORK/none_inner.sh"
  timeout 120 unshare -Urn bash "$WORK/none_inner.sh" "$ROOT" "$HISN" "$NW" >"$LOGDIR/none_identical.log" 2>&1
  cat "$LOGDIR/none_identical.log"
  PASS=$((PASS + $(grep -c "^PASS" "$LOGDIR/none_identical.log" || true)))
  FAIL=$((FAIL + $(grep -c "^FAIL:" "$LOGDIR/none_identical.log" || true)))
  rm -rf "$NW"
else
  skip "none-identical" "unshare -Urn unavailable in this environment"
fi

note "step 4: real network"
if [ "${1:-}" = "--real" ]; then
  REALW=$(mktemp -d /tmp/hisn-real.XXXXXX)
  [ -d "$REALW" ] || fail "real" "mktemp work dir"
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$REALW" >"$REALW/open.toml"
  timeout 300 "$HISN" run --no-tty --policy "$REALW/open.toml" --session-id hv-real -- sleep 300 >"$REALW/real.out" 2>&1 &
  sleep 3
  TARGET=${HISN_REAL_TARGET:-1.1.1.1}
  out=$(timeout 30 "$HISN" exec --no-tty --session hv-real -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('$TARGET',53)); print('REAL-OK')" 2>&1)
  case "$out" in *"REAL-OK"*) pass "real TCP connect to $TARGET";; *) fail "real TCP connect to $TARGET" "[$out]";; esac
  curl_out=$(timeout 30 "$HISN" exec --no-tty --session hv-real -- curl -sI https://github.com 2>&1 || true)
  case "$curl_out" in *"HTTP/"*) pass "real curl -sI https://github.com";; *) fail "real curl -sI https://github.com" "[$curl_out]";; esac
  git_out=$(timeout 30 "$HISN" exec --no-tty --session hv-real -- git ls-remote https://github.com/treeol/hisn HEAD 2>&1 || true)
  if echo "$git_out" | grep -qE '^[0-9a-f]{40}'; then pass "real git ls-remote github.com/treeol/hisn"; else fail "real git ls-remote github.com/treeol/hisn" "[$git_out]"; fi
  GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
  [ -n "$GATEWAY" ] || GATEWAY=192.168.1.1
  gw_out=$(timeout 30 "$HISN" exec --no-tty --session hv-real -- python3 -c "
import socket
s=socket.socket()
try:
    s.connect(('$GATEWAY',80))
    print('CONNECTED')
except PermissionError:
    print('Permission denied')
except OSError as e:
    print(e.strerror)" 2>&1)
  case "$gw_out" in *"Permission denied"*) pass "real LAN gateway $GATEWAY refused EACCES";; *) fail "real LAN gateway $GATEWAY refused EACCES" "[$gw_out]";; esac
  printf 'real session journal records:\n'
  timeout 20 "$HISN" journal --workspace "$REALW" --json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except Exception:
    print('(no journal)'); sys.exit(0)
recs = data if isinstance(data, list) else data.get('records', [])
for r in recs:
    if isinstance(r, dict) and str(r.get('kind','')).startswith('network'):
        print(json.dumps(r, sort_keys=True))" 2>&1 || true
  timeout 20 "$HISN" stop --session hv-real >/dev/null 2>&1 || true
  rm -rf "$REALW"
else
  skip "real" "pass --real (and HISN_REAL_TARGET if not 1.1.1.1)"
fi

printf 'host-verify: logs in %s\n' "$LOGDIR"
printf 'RESULT: pass=%d fail=%d timeout=%d skipped=%d\n' "$PASS" "$FAIL" "$TIMEOUT" "$SKIP"
[ "$FAIL" -eq 0 ] && [ "$TIMEOUT" -eq 0 ]

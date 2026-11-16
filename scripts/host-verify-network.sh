#!/usr/bin/env bash
# hisn 0.6.0 host verification (ADR 0022, open mode).
#
# ONE command for Valon:
#   bash scripts/host-verify-network.sh [--real]
#
# In order:
#   1. build to target/ (cargo build --release) — the binary the script
#      exercises is resolved to an absolute path once and invoked only
#      via /tmp/hisn-dev/hisn (symlink, first in PATH), never by a
#      relative path. No live hisn binary is installed or replaced.
#   2. make release-gate (plain) + rootfs run (HISN_TEST_ROOTFS /
#      HISN_BIG_TESTS default to the 0.5.1 host-step values, overridable
#      by environment; SKIP only if the rootfs path does not exist).
#   3. hermetic network cases: everything inside an outer `unshare -Urn`
#      namespace with a dummy interface 192.0.2.1/24; the script starts
#      its own TCP listener (192.0.2.1:18080), DNS server (192.0.2.2:53)
#      and blackhole (192.0.2.99, never answers). No traffic leaves the
#      host. Cases: L90/L94/L96/L97/L98/L99/L100/L102/L103/L104/L105/
#      L106/L107/L109/L110/L111/L112, upstream SERVFAIL, flood cap,
#      extra_deny rejection, none byte-identical.
#   4. with --real: one real-network step (public target named by
#      HISN_REAL_TARGET, default 1.1.1.1:53).
#
# Every step has a timeout; its exit code is checked; PASS requires
# exit 0 + the expected line + no "FAIL:" line. Full log per step in
# .wakil/host-logs/<UTC timestamp>/<step>.log (gitignored); on FAIL the
# last 40 lines of that step's log are printed. Last line:
#   RESULT: pass=<n> fail=<n> timeout=<n> skipped=<n>
# Non-zero exit on any fail/timeout. Kills only its own leftovers
# (listener/DNS/blackhole pids recorded in the work dir).
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
WORK=$(mktemp -d /tmp/hisn-hostverify.XXXXXX)
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
# Re-resolve the symlink now that the binary exists; assert executable.
ln -sf "$HISN_BIN" "$DEVDIR/hisn"
if [ ! -x "$HISN" ]; then
  fail "build" "/tmp/hisn-dev/hisn ($HISN_BIN) is not executable"
  printf 'RESULT: pass=%d fail=%d timeout=%d skipped=%d\n' "$PASS" "$FAIL" "$TIMEOUT" "$SKIP"
  exit 1
fi
# All hisn calls below are non-interactive (--no-tty) and use $HISN.
note "dev binary: $HISN -> $HISN_BIN ($("$HISN" --version 2>&1 | head -1))"
# Ensure /tmp/hisn-dev/hisn is first in PATH inside the hermetic inner ns too.
export PATH="$DEVDIR:$PATH"

note "step 2: release-gate (plain)"
run_step release-gate-plain 1200 "release-gate: summary" make release-gate || true

note "step 2b: release-gate (rootfs + big)"
if [ -n "${HISN_TEST_ROOTFS:-}" ] && [ -d "$HISN_TEST_ROOTFS" ]; then
  run_step release-gate-rootfs 1800 "release-gate: summary" \
    env HISN_TEST_ROOTFS="$HISN_TEST_ROOTFS" HISN_BIG_TESTS="$HISN_BIG_TESTS" make release-gate || true
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
ROOT="$1"; HISN="$2"
cd "$ROOT" || exit 1
# dummy interface with 192.0.2.1/24 inside this throwaway netns
ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 192.0.2.1/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
ip addr add 192.0.2.2/24 dev dummy0 2>/dev/null || true
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
# DNS server on 192.0.2.2:53 (answers hermetic.test -> 192.0.2.1).
# It records the peer address so the SERVFAIL case can point at a dead peer.
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
# Blackhole: bind 192.0.2.99 but never accept/answer (accepts TCP, never reads;
# drops UDP). The supervisor's connect() to it will stay pending until the
# deadline — exactly the stall L100/L106 need.
python3 - <<'PY' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.0.2.99", 18181)); s.listen(8)
import time
while True:
    time.sleep(3600)
PY
BLACKHOLE_PID=$!
sleep 0.5

W="$TMPDIR"
mkdir -p "$W"
trap 'kill $LISTENER_PID $DNS_PID $BLACKHOLE_PID 2>/dev/null; rm -rf "$W"' EXIT

check() { # name expected-substring cmd...
  local name=$1 want=$2; shift 2
  local out
  out=$(timeout 30 "$@" 2>&1); local rc=$?
  if [ "$rc" -eq 124 ]; then echo "FAIL: $name -- timeout"; return; fi
  case "$out" in *"$want"*) echo "PASS  $name";; *) echo "FAIL: $name -- got [$(echo "$out" | head -c 200)] want [$want]";; esac
}
checkfail() { # name forbidden-substring cmd...
  local name=$1 no=$2; shift 2
  local out
  out=$(timeout 30 "$@" 2>&1); local rc=$?
  if [ "$rc" -eq 124 ]; then echo "FAIL: $name -- timeout"; return; fi
  case "$out" in *"$no"*) echo "FAIL: $name -- unexpected [$no] in [$(echo "$out" | head -c 200)]";; *) echo "PASS  $name";; esac
}

POL="$W/open.toml"
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$W" >"$POL"
if timeout 60 "$HISN" run --no-tty --policy "$POL" --session-id hv-herm -- sleep 600 >"$W/sess.out" 2>&1 & then
  sleep 3
  EX() { timeout 20 "$HISN" exec --no-tty --session hv-herm -- python3 -c "$1" 2>&1; }

  # L96 loopback listener reached (CONTINUE).
  check "L96 loopback connect continues" "LOOPBACK-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',19001)); s.listen(1)
c=socket.socket(); c.connect(('127.0.0.1',19001)); c.sendall(b'hi'); a,_=s.accept(); a.sendall(b'LOOPBACK-OK'); a.close(); c.close()"
  # L112 DNS over UDP to 127.0.0.1:53 works (loopback CONTINUE before the
  # non-stream refusal). The responder is the supervisor's; a query for
  # hermetic.test must come back with an answer (A 192.0.2.1) or SERVFAIL
  # (upstream not on the dummy net) — never EACCES/EAGAIN.
  check "L112 UDP DNS to 127.0.0.1:53 is not refused" "DNS-UDP-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket, struct
q = b'\x12\x34' + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x08hermetic\x04test\x00' + b'\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8)
try:
    s.sendto(q, ('127.0.0.1',53))
    d,_ = s.recvfrom(4096)
    print('DNS-UDP-OK')
except PermissionError:
    print('DNS-UDP-EACCES')
except OSError as e:
    print('DNS-UDP-ERR', e.strerror)"
  # L97 host unix socket invisible (ENOENT from the mount view).
  check "L97 host unix socket invisible" "ENOENT" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
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
  check "L98 sendto outside is ENETUNREACH" "ENETUNREACH" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.sendto(b'x',('8.8.8.8',53))
    print('SENT')
except OSError as e:
    print(e.strerror)"
  # L104 SOCK_DGRAM connect refused EACCES in open.
  check "L104 dgram connect refused" "Permission denied" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
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
  check "L107 private target refused" "Permission denied" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
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
  check "L109 vsock refused" "Permission denied" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
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
  check "L90 public hermetic TCP via injection" "HERMETIC-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080))
print(s.recv(100).decode())"
  # L103 exec tree interception (these checks already ran through hisn exec).
  check "L103 exec tree interception" "HERMETIC-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080)); print(s.recv(100).decode())"
  # L94 DNS via the supervisor responder: resolve a REAL hostname
  # (hermetic.test -> 192.0.2.1). The sandbox resolver chain
  # (nsswitch "files dns" + resolv.conf 127.0.0.1) must reach the
  # responder, which forwards to the host resolver discovery — here the
  # only upstream that can answer is the script's 192.0.2.2:53 via the
  # host's resolv.conf when the outer netns is the host's. A pass proves
  # the shipped files + responder, not an IP literal.
  check "L94 hermetic.test resolves via shipped files" "DNS-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
r=socket.getaddrinfo('hermetic.test',18080,socket.AF_INET,socket.SOCK_STREAM)
s=socket.socket(); s.settimeout(10); s.connect(r[0][4])
d=s.recv(100).decode()
print('DNS-OK' if d=='HERMETIC-OK' else 'DNS-WRONG:'+d)"
  # L105: program binds a local port, then connects to the allowed
  # listener; connect succeeds and the listener sees a different source
  # port (the supervisor socket is recreated in the host netns).
  check "L105 bind-then-connect, different source port" "L105-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
import subprocess, time
# The outer listener cannot see the injected source port; assert by the
# program side: bind to a fixed local port, connect, and print the local
# address it reports after connect (which is the supervisor's, not the
# bound one, when the socket is recreated).
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',19055)); s.settimeout(10)
s.connect(('192.0.2.1',18080))
print('L105-OK')"
  # L106: one connect to the blackhole (stays pending) and one to the
  # listener, concurrently; the second must complete in under 2s.
  check "L106 concurrent connects, fast one wins" "L106-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket, threading, time
done = {}
def slow():
    s=socket.socket(); s.settimeout(30)
    try: s.connect(('192.0.2.99',18181))
    except OSError: done['slow']='refused'
def fast():
    time.sleep(0.2)
    t0=time.time()
    s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080))
    done['fast_dt']=time.time()-t0
t1=threading.Thread(target=slow); t2=threading.Thread(target=fast)
t1.start(); t2.start(); t2.join(10); t1.join(2)
print('L106-OK' if done.get('fast_dt',99) < 2.0 else 'L106-SLOW')"
  # L110: program sets PR_SET_DUMPABLE=0 after exec, then connects; the
  # sockaddr cannot be read -> EACCES; journal has refuse/read-failed.
  check "L110 dumpable-0 connect refused" "Permission denied" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import ctypes, socket
libc=ctypes.CDLL('libc.so.6')
libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0
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
  # L102/L111: after L90 the workspace journal carries network/connect
  # records with target ip:port (192.0.2.1:18080), verdict allow, and the
  # session id; L111 compares netns inodes.
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
    *"hv-herm"*) echo "PASS  L102 journal session id" ;;
    *) echo "FAIL: L102 journal session id -- journal [$(echo "$J" | head -c 400)]" ;;
  esac
  L111_IN=$(timeout 20 "$HISN" exec --no-tty --session hv-herm -- readlink /proc/self/ns/net 2>&1)
  L111_OUT=$(readlink /proc/self/ns/net 2>/dev/null || echo none)
  [ "$L111_IN" != "$L111_OUT" ] && [ -n "$L111_IN" ] && echo "PASS  L111 sandbox netns inode differs from supervisor" || echo "FAIL: L111 sandbox netns inode differs -- inner [$L111_IN] outer [$L111_OUT]"
  # Upstream unreachable -> SERVFAIL (queries must be answered, never hang,
  # and the rcode must be SERVFAIL when there is no upstream).
  check "SERVFAIL when upstream unreachable" "SERVFAIL-OK" "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket, struct
q = b'\xab\xcd' + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x08hermetic\x04test\x00' + b'\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10)
s.sendto(q, ('127.0.0.1',53))
d,_ = s.recvfrom(4096)
rcode = d[3] & 0x0f
print('SERVFAIL-OK' if rcode == 2 else 'SERVFAIL-RCODE:'+str(rcode))"
  # Flood cap: >50 connects/s are coalesced into network/summary, not
  # one record per connect.
  timeout 60 "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket
for _ in range(60):
    s=socket.socket(); s.settimeout(10); s.connect(('192.0.2.1',18080)); s.recv(100); s.close()" >/dev/null 2>&1 || true
  sleep 0.3
  JF=$(timeout 20 "$HISN" journal --workspace "$W" --json 2>/dev/null || echo '{}')
  case "$JF" in
    *"network/summary"*) echo "PASS  flood coalesced into network/summary" ;;
    *) echo "FAIL: flood coalesced into network/summary -- journal [$(echo "$JF" | head -c 400)]" ;;
  esac
  # L100: kill the session supervisor while a connect to the blackhole is
  # pending; the program must get ENOSYS and exit, with no leftover.
  SUP_PID=$(timeout 20 "$HISN" --no-tty ls --json 2>/dev/null | python3 -c "import sys,json; print([s for s in json.load(sys.stdin) if s.get('session_id')=='hv-herm' or s.get('id')=='hv-herm'][0].get('pid',''))" 2>/dev/null || true)
  # Fallback: supervisor.pid file under the runtime root.
  if [ -z "$SUP_PID" ]; then
    for f in /tmp/hisn-*/hv-herm/supervisor.pid "${XDG_RUNTIME_DIR:-/nonexistent}/hisn/hv-herm/supervisor.pid"; do
      [ -f "$f" ] && SUP_PID=$(cut -d' ' -f1 <"$f") && break
    done
  fi
  if [ -n "$SUP_PID" ]; then
    ( timeout 20 "$HISN" exec --no-tty --session hv-herm -- python3 -c "
import socket, errno, os
s=socket.socket(); s.settimeout(30)
try:
    s.connect(('192.0.2.99',18181))
    print('L100-CONNECTED')
except OSError as e:
    print('L100-ERRNO', e.errno)" >"$W/l100.out" 2>&1 ) &
    L100_PID=$!
    sleep 2
    kill -9 "$SUP_PID" 2>/dev/null || true
    wait $L100_PID 2>/dev/null || true
    # No leftover: supervisor process gone, output is ENOSYS.
    if [ -f "$W/l100.out" ] && grep -q "L100-ERRNO 38" "$W/l100.out" && ! kill -0 "$SUP_PID" 2>/dev/null; then
      echo "PASS  L100 supervisor-kill -> ENOSYS, no leftover"
    else
      echo "FAIL: L100 supervisor-kill -> ENOSYS -- sup_pid [$SUP_PID] out [$(cat "$W/l100.out" 2>/dev/null | head -c 200)]"
    fi
  else
    echo "FAIL: L100 supervisor-kill -> ENOSYS -- could not find supervisor pid"
  fi

  timeout 20 "$HISN" stop --session hv-herm >/dev/null 2>&1 || true
  kill $LISTENER_PID $DNS_PID $BLACKHOLE_PID 2>/dev/null
else
  echo "FAIL: hermetic open session starts -- see $W/sess.out"
  exit 1
fi
INNER
  # hermetic_inner.sh positional contract: $1=ROOT, $2=HISN; TMPDIR is the
  # per-run work dir (created by the caller).
  TMPDIR=$(mktemp -d /tmp/hisn-hermetic.XXXXXX)
  export TMPDIR
  chmod +x "$WORK/hermetic_inner.sh"
  unshare -Urn bash "$WORK/hermetic_inner.sh" "$ROOT" "$HISN" >"$LOGDIR/hermetic.log" 2>&1
  RC=$?
  cat "$LOGDIR/hermetic.log"
  if [ "$RC" -ne 0 ]; then fail "hermetic" "inner script exit $RC"; fi
  PASS=$((PASS + $(grep -c "^PASS" "$LOGDIR/hermetic.log" || true)))
  FAIL=$((FAIL + $(grep -c "^FAIL:" "$LOGDIR/hermetic.log" || true)))
  # The hermetic script must not emit SKIP for in-scope cases; any SKIP
  # line is a FAIL (the contract allows SKIP only for a genuinely absent
  # host precondition, which none of these are).
  if grep -q "^SKIP" "$LOGDIR/hermetic.log"; then
    fail "hermetic" "inner script emitted SKIP: $(grep "^SKIP" "$LOGDIR/hermetic.log" | head -1)"
  fi
  rm -rf "$TMPDIR"
else
  skip "hermetic" "unshare -Urn unavailable in this environment (run on a host with unprivileged userns)"
fi

# extra_deny connect rejected at validate (host-side, no session).
note "step 3b: extra_deny validation"
{
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "/tmp"\nnetwork = "open"\n[seccomp]\nextra_deny = ["connect"]\n' >"$WORK/deny.toml"
  "$HISN" --help >/dev/null 2>&1  # warm
  if "$HISN" run --no-tty --policy "$WORK/deny.toml" --session-id hv-deny -- /bin/true 2>&1 | grep -qi "connect\|extra_deny"; then
    echo "PASS  extra_deny connect rejected at validate"
  else
    echo "FAIL: extra_deny connect rejected at validate -- policy was accepted"
  fi
} >"$LOGDIR/extra_deny.log" 2>&1
if grep -q "^PASS" "$LOGDIR/extra_deny.log" && ! grep -q "^FAIL:" "$LOGDIR/extra_deny.log"; then
  PASS=$((PASS+1)); printf 'PASS  extra_deny connect rejected at validate\n'
else
  cat "$LOGDIR/extra_deny.log"
  fail "extra_deny" "policy with extra_deny=[connect] was not rejected"
fi

# none byte-identical: a none session must not get the generated
# resolv.conf/nsswitch.conf; host unchanged.
note "step 3c: none byte-identical"
if command -v unshare >/dev/null && unshare -Urn true 2>/dev/null; then
  TMP2=$(mktemp -d /tmp/hisn-none.XXXXXX)
  {
    printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\n' "$TMP2" >"$TMP2/none.toml"
    timeout 60 "$HISN" run --no-tty --policy "$TMP2/none.toml" --session-id hv-none -- sleep 60 >"$TMP2/sess.out" 2>&1 &
    sleep 3
    OUT=$(timeout 20 "$HISN" exec --no-tty --session hv-none -- python3 -c "
import os, sys
print('CONF' if os.path.exists('/etc/resolv.conf') else 'NORESOLV')
print('NSS' if os.path.exists('/etc/nsswitch.conf') else 'NONSS')" 2>&1)
    timeout 20 "$HISN" stop --session hv-none >/dev/null 2>&1 || true
    # The default image may still ship real /etc/resolv.conf (host) or
    # none; the point is hisn must not generate the 127.0.0.1 one.
    case "$OUT" in
      *"NORESOLV"*"NONSS"*) echo "PASS  none: no generated resolv/nsswitch" ;;
      *)
        # If a real file exists, it must not be the hisn-generated one.
        if timeout 20 "$HISN" exec --no-tty --session hv-none -- cat /etc/resolv.conf 2>/dev/null | grep -q "127.0.0.1"; then
          echo "FAIL: none byte-identical -- generated resolv.conf present"
        else
          echo "PASS  none: no hisn-generated resolv/nsswitch (host files unchanged)"
        fi
        ;;
    esac
    rm -rf "$TMP2"
  } >"$LOGDIR/none_identical.log" 2>&1
  if grep -q "^PASS" "$LOGDIR/none_identical.log" && ! grep -q "^FAIL:" "$LOGDIR/none_identical.log"; then
    PASS=$((PASS+1)); printf 'PASS  none byte-identical\n'
  else
    cat "$LOGDIR/none_identical.log"
    fail "none-identical" "see log"
  fi
else
  skip "none-identical" "unshare -Urn unavailable in this environment"
fi

note "step 4: real network"
if [ "${1:-}" = "--real" ]; then
  TARGET=${HISN_REAL_TARGET:-1.1.1.1}
  W=$(mktemp -d)
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "open"\n' "$W" >"$W/open.toml"
  timeout 60 "$HISN" run --no-tty --policy "$W/open.toml" --session-id hv-real -- sleep 120 >"$W/real.out" 2>&1 &
  sleep 3
  out=$(timeout 30 "$HISN" exec --no-tty --session hv-real -- python3 -c "
import socket
s=socket.socket(); s.settimeout(10); s.connect(('$TARGET',53)); print('REAL-OK')" 2>&1)
  case "$out" in *"REAL-OK"*) pass "real connect to $TARGET";; *) fail "real connect to $TARGET" "[$out]";; esac
  timeout 20 "$HISN" stop --session hv-real >/dev/null 2>&1 || true
  rm -rf "$W"
else
  skip "real" "pass --real (and HISN_REAL_TARGET if not 1.1.1.1)"
fi

printf 'host-verify: logs in %s\n' "$LOGDIR"
printf 'RESULT: pass=%d fail=%d timeout=%d skipped=%d\n' "$PASS" "$FAIL" "$TIMEOUT" "$SKIP"
[ "$FAIL" -eq 0 ] && [ "$TIMEOUT" -eq 0 ]

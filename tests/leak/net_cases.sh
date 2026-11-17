#!/usr/bin/env bash
# Hermetic network cases for hisn open mode (ADR 0022): L90, L94,
# L96-L100, L102-L107, L109-L113, the journal flood cap (L114), the
# none-mode comparison (L115) and extra_deny validation (L116).
#
# Usage (always through unshare; this script refuses to run otherwise):
#   unshare -Urn bash tests/leak/net_cases.sh HISN WORKDIR TOKEN
#
#   HISN     absolute path of the hisn binary under test
#   WORKDIR  an existing empty directory owned by the caller; everything
#            this script creates lives in it (the caller removes it)
#   TOKEN    short unique string; every session id starts with it
#
# It runs in a throwaway user + network namespace that has only loopback
# and a dummy interface (192.0.2.1 and 192.0.2.2), so nothing can leave
# the machine. hisn's runtime and state directories are redirected into
# WORKDIR, so sessions of this run are invisible to (and cannot disturb)
# any other hisn on the machine.
#
# Output: one line per check,
#   PASS  <name>
#   FAIL: <name> -- <detail>
#   SKIP  <name> -- <reason>
#   INFO  <text>
# and a last line `NET-CASES: pass=<n> fail=<n> skip=<n>`, which the
# caller compares with the lines it counted. Exit 0 iff fail=0 and
# pass>0.
#
# A check passes only when its command exits 0, prints the expected
# text, and prints no line starting with `FAIL:`. Every session-based
# check first requires its session to be listed as running.
#
# Supervisor pids of the sessions it starts are appended to
# WORKDIR/supervisor.pids; the caller uses that file to kill anything
# this script could not stop itself (e.g. when it was killed).
set -u

HISN=${1:?usage: net_cases.sh HISN WORKDIR TOKEN}
T=${2:?usage: net_cases.sh HISN WORKDIR TOKEN}
TOKEN=${3:?usage: net_cases.sh HISN WORKDIR TOKEN}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HELPER="$HERE/net_helper.py"

PASSES=0 FAILS=0 SKIPS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$1"; }
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP  %s -- %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL: %s -- %s\n' "$1" "$(printf '%s' "$2" | tr '\n' ' ' | head -c 600)"; }
info() { printf 'INFO  %s\n' "$*"; }
finish() {
  printf 'NET-CASES: pass=%d fail=%d skip=%d\n' "$PASSES" "$FAILS" "$SKIPS"
  [ "$FAILS" -eq 0 ] && [ "$PASSES" -gt 0 ]
  exit $?
}

[ -x "$HISN" ] || { fail "net harness setup" "hisn binary $HISN is not executable"; finish; }
[ -d "$T" ] || { fail "net harness setup" "work dir $T does not exist"; finish; }
OUTER_NETNS=$(readlink /proc/self/ns/net)
# A fresh network namespace has exactly one interface, lo. (Asked through
# netlink: /sys/class/net keeps showing the namespace sysfs was mounted in.)
IFACES=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')
if [ "$IFACES" != "lo " ]; then
  fail "net harness setup" "not in a fresh network namespace (interfaces: $IFACES); run through: unshare -Urn"
  finish
fi

mkdir -p "$T/run" "$T/state" "$T/data"
chmod 700 "$T/run"
export XDG_RUNTIME_DIR="$T/run" XDG_STATE_HOME="$T/state" XDG_DATA_HOME="$T/data"
unset HISN_SEAT_TOKEN
PIDS="$T/supervisor.pids"
: >"$PIDS"
HELPER_PID=""
STARTED=()

# session_field ID FIELD: one field of a session from `hisn ls --json`.
session_field() {
  timeout 20 "$HISN" ls --json </dev/null 2>/dev/null | python3 "$HELPER" ls-get "$1" "$2"
}

cleanup() {
  local id pid
  for id in "${STARTED[@]:-}"; do
    [ -n "$id" ] && timeout 20 "$HISN" stop --session "$id" </dev/null >/dev/null 2>&1
  done
  # Whatever `stop` did not end: kill the supervisor (the sandbox dies
  # with it). Only pids this script recorded, and only while their
  # command line still names this run's token.
  while read -r pid; do
    [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] &&
      tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF -- "$TOKEN" && kill -9 "$pid" 2>/dev/null
  done <"$PIDS"
  [ -n "$HELPER_PID" ] && kill "$HELPER_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT
trap 'exit 143' TERM INT HUP

# ------------------------------------------------------------ the network
ip link set lo up &&
  ip link add dummy0 type dummy &&
  ip addr add 192.0.2.1/24 dev dummy0 &&
  ip addr add 192.0.2.2/24 dev dummy0 &&
  ip link set dummy0 up ||
  { fail "net harness setup" "cannot create the dummy interface (needs ip and the dummy module)"; finish; }

python3 "$HELPER" serve "$T/helper.ready" "$T/host.sock" >"$T/helper.log" 2>&1 &
HELPER_PID=$!
for _ in $(seq 100); do
  [ -e "$T/helper.ready" ] && break
  kill -0 "$HELPER_PID" 2>/dev/null || break
  sleep 0.1
done
[ -e "$T/helper.ready" ] || { fail "net harness setup" "listeners did not start: $(cat "$T/helper.log")"; finish; }

# Preflight, from this namespace (not through hisn): the listener
# answers, and the blackhole address does not (no host has it, so the
# SYN is never answered and a connect stays pending).
PRE=$(timeout 20 python3 - <<'PY' 2>&1
import socket
s = socket.socket(); s.settimeout(5); s.connect(('192.0.2.1', 18080))
print('LISTENER', s.recv(100).decode())
b = socket.socket(); b.settimeout(1.5)
try:
    b.connect(('192.0.2.98', 18181)); print('BLACKHOLE connected')
except socket.timeout:
    print('BLACKHOLE pending')
except OSError as e:
    print('BLACKHOLE error', e.errno)
PY
)
case "$PRE" in
  *"LISTENER HERMETIC-OK"*"BLACKHOLE pending"*) pass "net harness: listener answers, blackhole address stays pending" ;;
  *) fail "net harness: listener answers, blackhole address stays pending" "[$PRE]"; finish ;;
esac

# ---------------------------------------------------------------- helpers
# write_open_profile FILE CWD: an open-mode profile whose DNS upstream is
# the helper's server. `[net]` exists only in profiles, and hisn refuses
# a profile that lies under the session cwd, so FILE is a sibling of CWD.
write_open_profile() {
  printf 'version = "hisn-profile/v1"\n[policy]\nversion = "hisn-policy/v1"\nsession.cwd = "%s"\nsession.network = "open"\n[net]\nnameservers = ["192.0.2.2"]\n' "$2" >"$1"
}
write_policy() { # FILE CWD NETWORK [EXTRA_DENY]
  printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "%s"\n' "$2" "$3" >"$1"
  [ -n "${4:-}" ] && printf '[seccomp]\nextra_deny = ["%s"]\n' "$4" >>"$1"
  return 0
}

# start_session ID CWD (--profile|--policy) FILE CMD...
# Starts in the background with stdin from /dev/null (`hisn run` has no
# --no-tty; it refuses a terminal on stdin). True when the session is
# listed as running; records the supervisor pid.
start_session() {
  local id=$1 cwd=$2 flag=$3 file=$4
  shift 4
  mkdir -p "$cwd"
  cp "$HELPER" "$cwd/net_helper.py"
  "$HISN" run "$flag" "$file" --session-id "$id" -- "$@" </dev/null >"$T/$id.log" 2>&1 &
  STARTED+=("$id")
  local i dir=""
  for i in $(seq 100); do
    if [ "$(session_field "$id" state)" = running ]; then
      dir=$(session_field "$id" dir)
      break
    fi
    sleep 0.1
  done
  [ -n "$dir" ] && [ -r "$dir/supervisor.pid" ] || return 1
  cut -d' ' -f1 "$dir/supervisor.pid" >>"$PIDS"
}

# in_session ID ARGS...: run the helper inside session ID, no terminal.
in_session() {
  local id=$1
  shift
  timeout 60 "$HISN" exec --no-tty --session "$id" -- python3 net_helper.py "$@" </dev/null 2>&1
}

# check NAME EXPECTED CMD...: PASS iff CMD exits 0, its output contains
# EXPECTED, and no output line starts with "FAIL:".
check() {
  local name=$1 want=$2 out rc
  shift 2
  out=$("$@")
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$name" "exit $rc: [$out]"
  elif printf '%s\n' "$out" | grep -q '^FAIL:'; then
    fail "$name" "[$out]"
  elif ! printf '%s\n' "$out" | grep -qF -- "$want"; then
    fail "$name" "expected [$want], got [$out]"
  else
    pass "$name"
  fi
}

journal() { timeout 20 "$HISN" journal --workspace "$1" --json </dev/null 2>/dev/null; }

# Outbound connects of a supervisor to the blackhole address that are in
# flight: sockets in SYN-SENT in this namespace (the supervisors run in
# it; the sandboxes have their own), read from /proc/net/tcp. This is
# how a test knows that a connect() really is pending in the supervisor.
pending_connects() { python3 "$HELPER" pending-count 2>/dev/null; }
wait_pending() { # WANT (0 or 1): true once "a connect is pending" equals WANT
  local i n
  for i in $(seq 100); do
    n=$(pending_connects)
    case "$n" in ""|*[!0-9]*) return 1 ;; esac # cannot tell: never a pass
    if [ "$1" -eq 0 ] && [ "$n" -eq 0 ]; then return 0; fi
    if [ "$1" -eq 1 ] && [ "$n" -ge 1 ]; then return 0; fi
    sleep 0.1
  done
  return 1
}

# journal_is NAME WS WANT K=V...: PASS iff exactly WANT journal records
# match every K=V. Network records are written by a queue, so the count
# is polled for up to 5 s before it is judged. A journal that cannot be
# read or has no records at all never matches, also not for WANT = 0.
journal_is() {
  local name=$1 ws=$2 want=$3 got="" i
  shift 3
  for i in $(seq 25); do
    got=$(journal "$ws" | python3 "$HELPER" journal-count "$@" 2>&1)
    [ "$got" = "$want" ] && break
    sleep 0.2
  done
  if [ "$got" = "$want" ]; then pass "$name"; else fail "$name" "$got records match [$*], want $want"; fi
}

# ============================================================ open session
A="$TOKEN-open"
ACWD="$T/a-cwd"
write_open_profile "$T/a.toml" "$ACWD"
if ! start_session "$A" "$ACWD" --profile "$T/a.toml" python3 "$ACWD/net_helper.py" in-main 18090 "$ACWD/main.out"; then
  fail "net harness: open session starts" "session $A is not running: [$(cat "$T/$A.log" 2>/dev/null)]"
  finish
fi
pass "net harness: open session starts (netns check, feature probe, DNS upstream found)"
AWS=$(session_field "$A" workspace.id)
[ -n "$AWS" ] || { fail "net harness: open session workspace id" "ls --json has no workspace.id for $A"; finish; }
check "net harness: open session is listed with network open" "open" session_field "$A" network

# L111: the sandbox is in its own network namespace.
INNER_NETNS=$(timeout 20 "$HISN" exec --no-tty --session "$A" -- readlink /proc/self/ns/net </dev/null 2>&1)
case "$INNER_NETNS|$OUTER_NETNS" in
  net:\[[0-9]*\]\|net:\[[0-9]*\])
    if [ "$INNER_NETNS" != "$OUTER_NETNS" ]; then
      pass "L111 sandbox netns differs from the supervisor's"
    else
      fail "L111 sandbox netns differs from the supervisor's" "both are $INNER_NETNS"
    fi
    ;;
  *) fail "L111 sandbox netns differs from the supervisor's" "inner [$INNER_NETNS] outer [$OUTER_NETNS]" ;;
esac

# L90: the session's main command (init's listener) reaches a public
# address; one journal record with target and verdict.
for _ in $(seq 100); do [ -s "$ACWD/main.out" ] && break; sleep 0.1; done
check "L90 main command connects out through interception" "MAIN-OK HERMETIC-OK" cat "$ACWD/main.out"
journal_is "L90 journal: allow 192.0.2.1:18090" "$AWS" 1 kind=network/connect target=192.0.2.1:18090 verdict=allow reason=injected-inprogress

# L103: a program started by `hisn exec` (the exec tree's own listener).
check "L103 exec'd program connects out through interception" "CONNECT-OK" in_session "$A" in-connect 18102
# L102: that connect is one record: session, target ip:port, verdict.
journal_is "L102 journal record: session, target ip:port, verdict, reason" "$AWS" 1 \
  kind=network/connect session="$A" target=192.0.2.1:18102 verdict=allow reason=injected-inprogress seat=null

# The same from a thread other than the program's main thread: the
# notification then carries a thread id, not a process id.
check "L103 connect from a second thread is intercepted and allowed" "THREAD-OK" in_session "$A" in-thread 18103
journal_is "L103 journal: allow 192.0.2.1:18103 (second thread)" "$AWS" 1 kind=network/connect target=192.0.2.1:18103 verdict=allow reason=injected-inprogress

# L94: a hostname resolves through the files hisn ships and its responder.
check "L94 hostname resolves through the shipped resolver files" "L94-OK" in_session "$A" in-dns
journal_is "L94 journal: dns hermetic.test ok NOERROR via 192.0.2.2" "$AWS" 1 \
  kind=network/dns name=hermetic.test qtype=A verdict=ok rcode=NOERROR upstream=192.0.2.2:53 proto=udp

# L112: DNS over a connected UDP socket (connect() to 127.0.0.1:53 is
# intercepted and continued), and DNS over TCP.
check "L112 UDP DNS through connect() to 127.0.0.1:53" "RCODE 0 ANSWERS 1" in_session "$A" in-dns-raw udp.hermetic.test udp-connect
check "L112 TCP DNS to 127.0.0.1:53" "RCODE 0 ANSWERS 1" in_session "$A" in-dns-raw tcp.hermetic.test tcp
journal_is "L112 journal: tcp query forwarded over tcp" "$AWS" 1 kind=network/dns name=tcp.hermetic.test proto=tcp verdict=ok

# L113: a failed lookup is never journaled as "ok".
check "L113 NXDOMAIN reaches the client" "RCODE 3 ANSWERS 0" in_session "$A" in-dns-raw nx.hermetic.test udp
journal_is "L113 journal: NXDOMAIN is verdict failed" "$AWS" 1 kind=network/dns name=nx.hermetic.test verdict=failed rcode=NXDOMAIN
check "L113 silent upstream gives SERVFAIL" "RCODE 2 ANSWERS 0" in_session "$A" in-dns-raw drop.hermetic.test udp
journal_is "L113 journal: upstream timeout is verdict error, SERVFAIL" "$AWS" 1 \
  kind=network/dns name=drop.hermetic.test verdict=error rcode=SERVFAIL error=upstream-timeout upstream=null
journal_is "L113 journal: no failed lookup recorded as ok" "$AWS" 0 kind=network/dns name=nx.hermetic.test verdict=ok
journal_is "L113 journal: no timed-out lookup recorded as ok" "$AWS" 0 kind=network/dns name=drop.hermetic.test verdict=ok

check "L96 loopback listener inside the sandbox is reached" "L96-OK" in_session "$A" in-loopback
journal_is "L96 journal: continue 127.0.0.1:19001" "$AWS" 1 kind=network/connect target=127.0.0.1:19001 verdict=continue
check "L97 host unix socket is not visible (ENOENT)" "L97-OK" in_session "$A" in-unix "$T/host.sock"
check "L98 sendto and fast-open to an outside address fail ENETUNREACH" "L98-OK" in_session "$A" in-sendto
check "L99 non-blocking connect completes and keeps O_NONBLOCK" "L99-OK" in_session "$A" in-nonblock
# L117: non-blocking connect() no longer blocks the program. The
# supervisor injects the replacement socket and replies EINPROGRESS at
# once; the program sees EINPROGRESS and later POLLOUT/SO_ERROR.
check "L117 non-blocking connect to the blackhole returns EINPROGRESS in under 100 ms" "NB-BLACKHOLE-OK" in_session "$A" in-nonblock-blackhole
check "L117 non-blocking connect to the listener gives POLLOUT, SO_ERROR 0 and data exchange" "NB-LISTEN-OK" in_session "$A" in-nonblock-listen 18081
check "L117 non-blocking connect to a closed port on the listener address gives ECONNREFUSED" "NB-REFUSED-OK" in_session "$A" in-nonblock-refused 18444
journal_is "L117 journal: connect-result ok for the non-blocking listener connect" "$AWS" 1 \
  kind=network/connect-result target=192.0.2.1:18081 result=ok
journal_is "L117 journal: connect-result ECONNREFUSED for the closed port" "$AWS" 1 \
  kind=network/connect-result target=192.0.2.1:18444 result=ECONNREFUSED
journal_is "L117 journal: injected-inprogress for the non-blocking blackhole connect" "$AWS" 1 \
  kind=network/connect target=192.0.2.98:18181 verdict=allow reason=injected-inprogress
# L117 (node step 4): a node script starts an HTTP request to the blackhole
# and one to the listener while a setInterval ticks every 10 ms; the
# listener request completes and the interval keeps ticking (no gap above
# 100 ms). Runs only when node is present in the session; SKIP names the
# missing tool otherwise.
cp "$HERE/nb_node.js" "$ACWD/nb_node.js"
NBSRC=$(in_session "$A" in-tool-probe 2>/dev/null)
if printf '%s\n' "$NBSRC" | grep -q '^TOOL node yes$'; then
  check "L117 node event loop: listener request completes while the blackhole request is pending, interval ticks" \
    "NODE-OK" timeout 60 "$HISN" exec --no-tty --session "$A" -- node "$ACWD/nb_node.js" \
    "http://192.0.2.1:18080" "http://192.0.2.98:18181"
else
  skip "L117 node event loop" "node is not present in the session"
fi
if printf '%s\n' "$NBSRC" | grep -q '^TOOL go yes$'; then
  # The Go case runs a statically linked binary built by the host script
  # (or by the caller of net_cases.sh, which must place it at $T/nb_go
  # before starting this script); the binary is copied into the session
  # cwd, which is mounted rw, so a running session can execute it.
  if [ -x "$T/nb_go" ]; then
    cp "$T/nb_go" "$ACWD/nb_go"
    check "L117 go client: http GET to the listener and a dial to the blackhole with a 1 s timeout" \
      "GO-OK" timeout 60 "$HISN" exec --no-tty --session "$A" -- "$ACWD/nb_go" \
      "http://192.0.2.1:18080" "192.0.2.98:18181"
  else
    skip "L117 go client" "no pre-built go test binary at $T/nb_go"
  fi
else
  skip "L117 go client" "go is not present in the session"
fi
check "L99 close-on-exec flag of the socket survives the connect" "CLOEXEC-OK" in_session "$A" in-cloexec
check "L99 connect() on a connected socket fails EISCONN, connection kept" "RECONNECT-OK" in_session "$A" in-reconnect
check "L104 connect() on a datagram socket is refused EACCES" "L104-OK" in_session "$A" in-dgram
journal_is "L104 journal: refuse non-stream" "$AWS" 1 kind=network/connect target=192.0.2.1:18080 verdict=refuse reason=non-stream
check "L105 bind before connect: connected, source port not kept" "L105-OK" in_session "$A" in-bind
check "L106 a pending connect does not delay another" "L106-OK" in_session "$A" in-concurrent
journal_is "L103 journal: no connect was refused for an unreadable task" "$AWS" 0 kind=network/connect reason=pidfd-open-failed
check "L107 private, link-local, CGNAT, ULA and embedded-IPv4 targets refused EACCES" "L107-OK" in_session "$A" in-private
journal_is "L107 journal: refuse 192.168.1.1:80" "$AWS" 1 kind=network/connect target=192.168.1.1:80 verdict=refuse reason=private-or-unlisted
journal_is "L107 journal: refuse 6to4 form of 10.0.0.1" "$AWS" 1 kind=network/connect target=2002:a00:1::1:80 verdict=refuse reason=private-or-unlisted
check "L109 netlink connect is refused EACCES" "NETLINK-REFUSED" in_session "$A" in-netlink
VSOCK=$(in_session "$A" in-vsock)
case "$VSOCK" in
  VSOCK-REFUSED) pass "L109 vsock connect is refused EACCES" ;;
  VSOCK-UNAVAILABLE*) skip "L109 vsock connect is refused EACCES" "this kernel cannot create a vsock socket ($VSOCK)" ;;
  *) fail "L109 vsock connect is refused EACCES" "[$VSOCK]" ;;
esac

# L110: a program that made itself non-dumpable is still intercepted,
# decided and journaled (the supervisor owns the sandbox's user
# namespace, so it can read the address; the program cannot hide).
check "L110 non-dumpable program: connect is intercepted and allowed" "L110-OK" in_session "$A" in-dumpable 18110
journal_is "L110 journal: allow 192.0.2.1:18110" "$AWS" 1 kind=network/connect target=192.0.2.1:18110 verdict=allow reason=injected-inprogress

# The open session's seccomp filter count, for the none comparison below.
OPEN_STATUS=$(in_session "$A" in-status)

# Flood cap: 300 connects in a burst. At most 50 records per second are
# written one by one; the rest are counted in network/summary.
check "L114 flood: 300 connects succeed" "FLOOD-DONE" in_session "$A" in-flood 18120 300
FLOOD=""
for _ in $(seq 30); do
  FLOOD=$(journal "$AWS" | python3 "$HELPER" journal-flood 18120 2>&1)
  singles=${FLOOD#singles=}; singles=${singles%% *}
  summarized=${FLOOD##*summarized=}
  case "$singles$summarized" in *[!0-9]*|"") singles=0; summarized=0 ;; esac
  [ $((singles + summarized)) -ge 300 ] && break
  sleep 0.2
done
if [ "$singles" -ge 1 ] && [ "$singles" -le 100 ] && [ $((singles + summarized)) -eq 300 ]; then
  pass "L114 flood: journal has $singles single records and $summarized summarized, 300 in total"
else
  fail "L114 flood: journal caps single records and summarizes the rest" "[$FLOOD] (want 1..100 single, 300 in total)"
fi

# Timing, informational: 100 connects through interception against 100
# direct ones from this namespace (median of three runs each).
info "timing intercepted: $(in_session "$A" in-timing)"
info "timing direct:      $(timeout 60 python3 "$HELPER" in-timing 2>&1)"
info "network records of session $A (first of each kind/verdict/reason):"
journal "$AWS" | python3 "$HELPER" journal-dump | python3 -c '
import json, sys
seen = set()
for line in sys.stdin:
    r = json.loads(line); d = r["data"]
    key = (r["kind"], d.get("verdict"), d.get("reason"), d.get("rcode"))
    if key not in seen:
        seen.add(key); print("INFO    " + line.strip())'

check "net harness: open session stops cleanly" "" timeout 30 "$HISN" stop --session "$A" </dev/null
for _ in $(seq 50); do [ "$(session_field "$A" state)" != running ] && break; sleep 0.1; done
check "net harness: open session is no longer running" "stopped" session_field "$A" state

# ====================================== L100: supervisor killed mid-connect
# The supervisor is found only through the file hisn writes for this
# session (<session dir>/supervisor.pid, dir from `ls --json`), and is
# killed only if its command line names this session.
B="$TOKEN-kill"
BCWD="$T/b-cwd"
write_open_profile "$T/b.toml" "$BCWD"
L100="L100 supervisor killed mid-connect: nothing hangs, the sandbox is gone"
if ! start_session "$B" "$BCWD" --profile "$T/b.toml" sleep 600; then
  fail "$L100" "session $B is not running: [$(cat "$T/$B.log" 2>/dev/null)]"
else
  BDIR=$(session_field "$B" dir)
  SUP=$(cut -d' ' -f1 "$BDIR/supervisor.pid" 2>/dev/null)
  case "$SUP" in ""|*[!0-9]*) SUP="" ;; esac
  if [ -z "$SUP" ] || ! tr '\0' ' ' <"/proc/$SUP/cmdline" 2>/dev/null | grep -qF -- "--session-id $B "; then
    fail "$L100" "no supervisor pid for $B in $BDIR/supervisor.pid whose command line names the session (pid [$SUP]); nothing was killed"
  else
    if ! wait_pending 0; then
      fail "$L100" "an outbound connect of an earlier case is still pending; cannot tell this one apart"
    else
      in_session "$B" in-pending "$B" >"$T/l100.out" 2>&1 &
      EXEC_PID=$!
      # Precondition: the supervisor's outbound connect is in flight.
      if ! wait_pending 1; then
        fail "$L100" "the supervisor never had the connect pending before the kill: [$(cat "$T/l100.out")]"
      else
        kill -9 "$SUP"
        GONE=1
        for _ in $(seq 100); do
          kill -0 "$EXEC_PID" 2>/dev/null || { GONE=0; break; }
          sleep 0.1
        done
        wait "$EXEC_PID" 2>/dev/null
        EXEC_RC=$?
        sleep 0.3
        LEFT=$(pgrep -f "net_helper.py in-pending $B" | tr '\n' ' ')
        STATE=$(session_field "$B" state)
        if [ "$GONE" -eq 0 ] && [ "$EXEC_RC" -ne 0 ] && [ -z "$LEFT" ] && ! kill -0 "$SUP" 2>/dev/null && [ "$STATE" = crashed ]; then
          pass "$L100"
        else
          fail "$L100" "exec client returned=$((1 - GONE)) rc=$EXEC_RC, programs left=[$LEFT], session state=[$STATE], output=[$(cat "$T/l100.out")]"
        fi
      fi
    fi
  fi
fi

# ============================ session end with a connect still pending
# The main command exits while a child of it sits in a connect() that
# the supervisor has in flight and that never completes. The session
# must end promptly, not after the 30 s connect deadline.
E="$TOKEN-end"
ECWD="$T/e-cwd"
L106E="L106 session ends within 10 s while a connect is still pending"
mkdir -p "$ECWD"
cp "$HELPER" "$ECWD/net_helper.py"
write_open_profile "$T/e.toml" "$ECWD"
if ! wait_pending 0; then
  fail "$L106E" "an outbound connect of an earlier case is still pending; cannot tell this one apart"
else
  STARTED+=("$E")
  "$HISN" run --profile "$T/e.toml" --session-id "$E" -- python3 "$ECWD/net_helper.py" in-leave-pending "$ECWD/go" </dev/null >"$T/$E.log" 2>&1 &
  E_PID=$!
  if ! wait_pending 1; then
    : >"$ECWD/go"
    fail "$L106E" "the supervisor never had the connect pending: [$(cat "$T/$E.log")]"
  else
    : >"$ECWD/go" # the main command exits now
    E_ENDED=1
    for _ in $(seq 100); do
      kill -0 "$E_PID" 2>/dev/null || { E_ENDED=0; break; }
      sleep 0.1
    done
    if [ "$E_ENDED" -ne 0 ]; then
      fail "$L106E" "hisn run is still running 10 s after its command exited"
    elif ! wait "$E_PID"; then
      fail "$L106E" "hisn run exited non-zero: [$(cat "$T/$E.log")]"
    else
      pass "$L106E"
    fi
  fi
fi

# ============================================================ none session
# network = "none" has no route, no interception and no generated
# resolver files; its /etc/nsswitch.conf is the host's own file.
N="$TOKEN-none"
NCWD="$T/n-cwd"
write_policy "$T/n.toml" "$NCWD" none
if ! start_session "$N" "$NCWD" --policy "$T/n.toml" sleep 600; then
  fail "L115 none session starts" "session $N is not running: [$(cat "$T/$N.log" 2>/dev/null)]"
else
  if [ -e /etc/nsswitch.conf ]; then
    HOST_NSS=$(sha256sum </etc/nsswitch.conf | cut -d' ' -f1)
  else
    HOST_NSS=absent
  fi
  check "L115 none: no route out, no resolv.conf, host's own nsswitch.conf" "NONE-OK nsswitch $HOST_NSS" in_session "$N" in-none
  NONE_STATUS=$(in_session "$N" in-status)
  o=${OPEN_STATUS#FILTERS }; o=${o%% *}
  n=${NONE_STATUS#FILTERS }; n=${n%% *}
  case "$o$n" in
    *[!0-9]*|"") fail "L115 none: one seccomp filter fewer than open (no connect filter)" "open [$OPEN_STATUS] none [$NONE_STATUS]" ;;
    *)
      if [ "$o" -eq $((n + 1)) ]; then
        pass "L115 none: one seccomp filter fewer than open (no connect filter): $n vs $o"
      else
        fail "L115 none: one seccomp filter fewer than open (no connect filter)" "open [$OPEN_STATUS] none [$NONE_STATUS]"
      fi
      ;;
  esac
  NWS=$(session_field "$N" workspace.id)
  journal_is "L115 none: journal has its session/start record" "$NWS" 1 kind=session/start session="$N"
  journal_is "L115 none: journal has no network records" "$NWS" 0 'kind=network/*'
  check "L115 none session stops cleanly" "" timeout 30 "$HISN" stop --session "$N" </dev/null
fi

# ================================================== extra_deny validation
# Under open, denying connect/socket would defeat interception and is
# rejected when the policy is loaded; under none it is accepted as before.
mkdir -p "$T/d-cwd"
write_policy "$T/d-open.toml" "$T/d-cwd" open connect
OUT=$(timeout 30 "$HISN" run --policy "$T/d-open.toml" --session-id "$TOKEN-deny-open" -- true </dev/null 2>&1)
RC=$?
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ] && printf '%s' "$OUT" | grep -q 'extra_deny'; then
  pass "L116 extra_deny connect is rejected under open"
else
  fail "L116 extra_deny connect is rejected under open" "exit $RC: [$OUT]"
fi
write_policy "$T/d-none.toml" "$T/d-cwd" none connect
check "L116 extra_deny connect is accepted under none" "" timeout 30 "$HISN" run --policy "$T/d-none.toml" --session-id "$TOKEN-deny-none" -- true </dev/null

finish

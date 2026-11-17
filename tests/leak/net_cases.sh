#!/usr/bin/env bash
# Hermetic network cases for hisn open mode (ADR 0022): L90, L94,
# L96-L100, L102-L107, L109-L113, the journal flood cap (L114), the
# none-mode comparison (L115), extra_deny validation (L116),
# non-blocking connects incl. a Node and a Go client (L117), plain
# blocking sockets (L119), connect() on a pending socket (L120),
# non-blocking behind blocking connects (L121), the connect deadline
# (L122) and session stop with a tracked connect (L123).
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
pending_connects() { python3 "$HELPER" pending-count "$@" 2>/dev/null; }
wait_pending() { # WANT (0 or 1) [PORT]: true once "a connect is pending" equals WANT
  local i n
  for i in $(seq 100); do
    n=$(pending_connects "${@:2}")
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

# tool_state FILE: first word of a status file of net_tools.sh (ok,
# missing, broken); tool_detail FILE: the rest of the line.
tool_state() { [ -r "$1" ] && cut -d' ' -f1 "$1" || echo broken; }
tool_detail() { [ -r "$1" ] && cut -d' ' -f2- "$1" || echo "net_tools.sh wrote no $1"; }

# The Node and Go clients, prepared here, outside any session: a session
# sees the host's /usr only, so they are copied into its working
# directory as a node binary and static Go binaries.
TOOLS="$T/tools"
bash "$HERE/net_tools.sh" "$TOOLS" >"$T/net_tools.log" 2>&1
info "node: $(tool_detail "$TOOLS/node.status" | sed "s/^/$(tool_state "$TOOLS/node.status") /")"
info "go:   $(tool_detail "$TOOLS/go.status" | sed "s/^/$(tool_state "$TOOLS/go.status") /")"

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
# The main command uses a socket with a timeout. Python implements the
# timeout by putting the socket into non-blocking mode; the helper prints
# the O_NONBLOCK flag it read with fcntl right before connect()
# (nonblock=1). Such a connect is injected while still in progress.
check "L90 main command connects out through interception (timeout socket: O_NONBLOCK set)" "MAIN-OK HERMETIC-OK nonblock=1" cat "$ACWD/main.out"
journal_is "L90 journal: allow 192.0.2.1:18090" "$AWS" 1 kind=network/connect target=192.0.2.1:18090 verdict=allow reason=injected-inprogress

# L103: a program started by `hisn exec` (the exec tree's own listener).
check "L103 exec'd program connects out through interception (timeout socket: O_NONBLOCK set)" "CONNECT-OK nonblock=1" in_session "$A" in-connect 18102
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
# L117: a non-blocking connect() returns at once. The supervisor injects
# its connecting socket and replies EINPROGRESS; the program sees
# POLLOUT / SO_ERROR on that socket like after any non-blocking connect.
check "L117 non-blocking connect to the blackhole returns EINPROGRESS in under 100 ms, poll times out at the client's 1 s" "NB-BLACKHOLE-OK" in_session "$A" in-nonblock-blackhole
journal_is "L117 journal: injected-inprogress for the non-blocking blackhole connect" "$AWS" 1 \
  kind=network/connect target=192.0.2.98:18181 verdict=allow reason=injected-inprogress
check "L117 non-blocking connect to the listener gives POLLOUT, SO_ERROR 0 and data exchange" "NB-LISTEN-OK" in_session "$A" in-nonblock-listen 18081
journal_is "L117 journal: injected-inprogress for the non-blocking listener connect" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18081 verdict=allow reason=injected-inprogress
journal_is "L117 journal: connect-result connected for the non-blocking listener connect" "$AWS" 1 \
  kind=network/connect-result target=192.0.2.1:18081 result=connected
# Regression (the supervisor once read SO_ERROR through its duplicate
# and so took the error away from the program): the program's own
# SO_ERROR, read one second after POLLOUT, i.e. after the supervisor's
# tracking has settled this connect, is still ECONNREFUSED.
check "L117 non-blocking connect to a closed port: the program's own SO_ERROR after POLLOUT is ECONNREFUSED" "NB-REFUSED-OK via=so_error SO_ERROR=ECONNREFUSED" in_session "$A" in-nonblock-refused 18444
journal_is "L117 journal: connect-result failed for the closed port" "$AWS" 1 \
  kind=network/connect-result target=192.0.2.1:18444 result=failed
journal_is "L117 journal: no connect-result carries an errno name" "$AWS" 0 \
  kind=network/connect-result result=ECONNREFUSED

# L117, Node: an HTTP request to the blackhole and one to the listener
# while a setInterval ticks every 10 ms. The node binary was copied into
# the session's working directory by net_tools.sh.
NODE_RUN=0 GO_RUN=0
L117N="L117 node event loop: listener request completes, 10 ms interval keeps ticking (no gap above 100 ms) while the blackhole request is pending"
case "$(tool_state "$TOOLS/node.status")" in
  ok)
    mkdir -p "$ACWD/tools" && cp -R "$TOOLS/node" "$TOOLS/run-node" "$TOOLS/lib" "$ACWD/tools/" &&
      cp "$HERE/nb_node.js" "$ACWD/nb_node.js"
    OUT=$(timeout 60 "$HISN" exec --no-tty --session "$A" -- sh "$ACWD/tools/run-node" "$ACWD/nb_node.js" \
      "http://192.0.2.1:18140/" "http://192.0.2.98:18181/" </dev/null 2>&1)
    RC=$?
    if [ "$RC" -eq 0 ] && printf '%s\n' "$OUT" | grep -q '^NODE-OK ' && ! printf '%s\n' "$OUT" | grep -q '^FAIL:'; then
      pass "$L117N: $(printf '%s\n' "$OUT" | grep '^NODE-OK ')"
      NODE_RUN=1
    else
      fail "$L117N" "exit $RC: [$OUT]"
    fi
    ;;
  missing) skip "$L117N" "$(tool_detail "$TOOLS/node.status")" ;;
  *) fail "$L117N" "$(tool_detail "$TOOLS/node.status")" ;;
esac

# L117, Go: net/http GET to the listener and a dial to the blackhole
# with a 1 s timeout. The binary was built statically by net_tools.sh.
L117G="L117 go client: net/http GET to the listener, dial to the blackhole times out at its own 1 s"
case "$(tool_state "$TOOLS/go.status")" in
  ok)
    mkdir -p "$ACWD/tools" && cp "$TOOLS/nb_go" "$ACWD/tools/nb_go"
    OUT=$(timeout 60 "$HISN" exec --no-tty --session "$A" -- "$ACWD/tools/nb_go" \
      "http://192.0.2.1:18140/" "192.0.2.98:18181" </dev/null 2>&1)
    RC=$?
    if [ "$RC" -eq 0 ] && printf '%s\n' "$OUT" | grep -q '^GO-OK ' && ! printf '%s\n' "$OUT" | grep -q '^FAIL:'; then
      pass "$L117G: $(printf '%s\n' "$OUT" | grep '^GO-OK ')"
      GO_RUN=1
    else
      fail "$L117G" "exit $RC: [$OUT]"
    fi
    ;;
  missing) skip "$L117G" "$(tool_detail "$TOOLS/go.status")" ;;
  *) fail "$L117G" "$(tool_detail "$TOOLS/go.status")" ;;
esac
if [ $((NODE_RUN + GO_RUN)) -gt 0 ]; then
  journal_is "L117 journal: injected-inprogress for the node/go requests to the listener ($((NODE_RUN + GO_RUN)))" "$AWS" $((NODE_RUN + GO_RUN)) \
    kind=network/connect target=192.0.2.1:18140 verdict=allow reason=injected-inprogress
  journal_is "L117 journal: connect-result connected for the node/go requests to the listener ($((NODE_RUN + GO_RUN)))" "$AWS" $((NODE_RUN + GO_RUN)) \
    kind=network/connect-result target=192.0.2.1:18140 result=connected
fi

# L119: plain blocking sockets (no timeout, O_NONBLOCK clear; the helper
# prints the flag: nonblock=0) keep the old behaviour: connect() returns
# when the supervisor's connect has finished, with 0 or its errno, and
# the journal reason is `injected`.
check "L119 blocking socket, exec'd program: connect() returns 0 connected (O_NONBLOCK clear)" "CONNECT-OK nonblock=0" in_session "$A" in-connect 18131 blocking
journal_is "L119 journal: blocking exec'd connect is allow/injected" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18131 verdict=allow reason=injected
journal_is "L119 journal: a blocking connect has no connect-result record" "$AWS" 0 \
  kind=network/connect-result target=192.0.2.1:18131
check "L119 blocking socket, closed port: connect() itself returns ECONNREFUSED" "BLOCKING-REFUSED-OK" in_session "$A" in-blocking-refused 18445
journal_is "L119 journal: blocking connect to a closed port is refuse/connect-error" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18445 verdict=refuse reason=connect-error

# L120: connect() again on the socket of a non-blocking connect.
check "L120 connect() on a socket whose connect is pending fails EALREADY, on a connected one EISCONN" "REPENDING-OK pending=EALREADY connected=EISCONN" in_session "$A" in-reconnect-pending
journal_is "L120 journal: refuse already-pending, nothing injected" "$AWS" 1 \
  kind=network/connect target=192.0.2.98:18181 verdict=refuse reason=already-pending

# L121: 64 blocking connects to the blackhole are pending in the
# supervisor (counted in /proc/net/tcp); a non-blocking connect is still
# answered EINPROGRESS in under 100 ms.
L121="L121 non-blocking connect returns EINPROGRESS in under 100 ms while 64 blocking connects are pending"
rm -f "$ACWD/pool.go"
in_session "$A" in-pool "$ACWD/pool.go" 64 >"$T/l121.out" 2>&1 &
POOL_PID=$!
POOL_N=0
for _ in $(seq 100); do
  POOL_N=$(pending_connects 18183)
  [ "$POOL_N" = 64 ] && break
  sleep 0.1
done
: >"$ACWD/pool.go"
wait "$POOL_PID"
POOL_RC=$?
if [ "$POOL_N" != 64 ]; then
  fail "$L121" "precondition: $POOL_N of 64 blocking connects were pending in the supervisor; output [$(cat "$T/l121.out")]"
elif [ "$POOL_RC" -eq 0 ] && grep -q '^POOL-OK ' "$T/l121.out" && ! grep -q '^FAIL:' "$T/l121.out"; then
  pass "$L121: $(grep '^POOL-OK ' "$T/l121.out")"
else
  fail "$L121" "exit $POOL_RC: [$(cat "$T/l121.out")]"
fi

# L122: the connect deadline (30 s) against the blackhole. A blocking
# connect() returns ETIMEDOUT at the deadline, as before. A non-blocking
# one got EINPROGRESS at once; the supervisor stops tracking it at the
# deadline and journals pending-at-deadline.
check "L122 blocking connect to the blackhole returns ETIMEDOUT at the 30 s deadline" "DEADLINE-OK" timeout 90 "$HISN" exec --no-tty --session "$A" -- python3 net_helper.py in-deadline
journal_is "L122 journal: blocking connect is refuse/deadline" "$AWS" 1 \
  kind=network/connect target=192.0.2.98:18182 verdict=refuse reason=deadline
journal_is "L122 journal: tracked non-blocking connect ends as pending-at-deadline" "$AWS" 1 \
  kind=network/connect-result target=192.0.2.98:18182 result=pending-at-deadline

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
info "network records of session $A (first of each kind/verdict/reason/result):"
journal "$AWS" | python3 "$HELPER" journal-dump | python3 -c '
import json, sys
seen = set()
for line in sys.stdin:
    r = json.loads(line); d = r["data"]
    key = (r["kind"], d.get("verdict"), d.get("reason"), d.get("rcode"), d.get("result"))
    if key not in seen:
        seen.add(key); print("INFO    " + line.strip())'

check "net harness: open session stops cleanly" "" timeout 30 "$HISN" stop --session "$A" </dev/null
for _ in $(seq 50); do [ "$(session_field "$A" state)" != running ] && break; sleep 0.1; done
check "net harness: open session is no longer running" "stopped" session_field "$A" state

# ================================= L119: blocking socket, main command
# The session's main command connects with a plain blocking socket.
M="$TOKEN-blocking"
MCWD="$T/m-cwd"
write_open_profile "$T/m.toml" "$MCWD"
if ! start_session "$M" "$MCWD" --profile "$T/m.toml" python3 "$MCWD/net_helper.py" in-main 18130 "$MCWD/main.out" blocking; then
  fail "L119 blocking socket, main command" "session $M is not running: [$(cat "$T/$M.log" 2>/dev/null)]"
else
  MWS=$(session_field "$M" workspace.id)
  for _ in $(seq 100); do [ -s "$MCWD/main.out" ] && break; sleep 0.1; done
  check "L119 blocking socket, main command: connect() returns 0 connected (O_NONBLOCK clear)" "MAIN-OK HERMETIC-OK nonblock=0" cat "$MCWD/main.out"
  journal_is "L119 journal: blocking main-command connect is allow/injected" "$MWS" 1 \
    kind=network/connect target=192.0.2.1:18130 verdict=allow reason=injected
  journal_is "L119 journal: blocking main-command connect has no connect-result record" "$MWS" 0 \
    kind=network/connect-result

  # L123: stop a session while the supervisor still tracks a connect.
  # The program started a non-blocking connect to the blackhole and has
  # exited; only the supervisor's duplicate keeps that socket alive
  # (seen in SYN-SENT in /proc/net/tcp). `hisn stop` must end the
  # session cleanly and the socket must be gone afterwards.
  L123="L123 session with a tracked pending connect stops cleanly and the socket is closed"
  if ! wait_pending 0 18184; then
    fail "$L123" "a connect to 192.0.2.98:18184 is pending before the case starts"
  else
    LEFT=$(in_session "$M" in-leave-tracked)
    if [ "$LEFT" != LEFT-TRACKED ] || ! wait_pending 1 18184; then
      fail "$L123" "precondition: the supervisor is not holding the pending socket after the program exited: [$LEFT], pending=$(pending_connects 18184)"
    else
      STOP_T0=$(date +%s)
      timeout 30 "$HISN" stop --session "$M" </dev/null >"$T/l123.out" 2>&1
      STOP_RC=$?
      STOP_S=$(($(date +%s) - STOP_T0))
      for _ in $(seq 50); do [ "$(session_field "$M" state)" != running ] && break; sleep 0.1; done
      STATE=$(session_field "$M" state)
      if [ "$STOP_RC" -eq 0 ] && [ "$STATE" = stopped ] && [ "$STOP_S" -le 10 ] && wait_pending 0 18184; then
        pass "$L123 (stop took ${STOP_S} s, state stopped, 0 sockets left in SYN-SENT)"
      else
        fail "$L123" "stop exit $STOP_RC after ${STOP_S} s, state [$STATE], sockets still pending: $(pending_connects 18184), output [$(cat "$T/l123.out")]"
      fi
    fi
  fi
fi

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

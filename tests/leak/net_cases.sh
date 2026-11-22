#!/usr/bin/env bash
# Hermetic network cases for hisn open mode (ADR 0022): L90, L94,
# L96-L100, L102-L107, L109-L113, the journal flood cap (L114), the
# none-mode comparison (L115), extra_deny validation (L116),
# non-blocking connects incl. a Node and a Go client (L117), plain
# blocking sockets (L119), connect() on a pending socket (L120),
# non-blocking behind blocking connects (L121), the connect deadline
# (L122), session stop with a tracked connect (L123) and connect() on a
# socket whose connect failed (L124) and a kept supervisor-side socket
# (L125).
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

# 0.6.1 seat attribution: network records caused by an exec'd program
# name the seat of that exec's client (the same value the exec records
# use); the main command's records stay null. A member seat is created
# for this workspace, its exec connects out, and the record names it.
# `hisn journal --seat <name>` selects it.
SEAT_TOK=$("$HISN" seat --workspace "$AWS" add member1 --role member 2>/dev/null)
if [ -n "$SEAT_TOK" ]; then
  OUT=$(HISN_SEAT_TOKEN="$SEAT_TOK" timeout 60 "$HISN" exec --no-tty --session "$A" -- python3 net_helper.py in-connect 18104 </dev/null 2>&1)
  RC=$?
  if [ "$RC" -eq 0 ] && printf '%s\n' "$OUT" | grep -q '^CONNECT-OK' && ! printf '%s\n' "$OUT" | grep -q '^FAIL:'; then
    pass "0.6.1 seat exec connects out through interception (member seat exec)"
  else
    fail "0.6.1 seat exec connects out through interception (member seat exec)" "exit $RC: [$OUT]"
  fi
  journal_is "0.6.1 journal: exec'd program's network/connect names its seat" "$AWS" 1 \
    kind=network/connect target=192.0.2.1:18104 verdict=allow reason=injected-inprogress seat=member1
  # 0.6.1: the same seat, from a child process and from a second thread
  # of the exec (attribution is by process ancestry, not the exec's pid).
  OUT=$(HISN_SEAT_TOKEN="$SEAT_TOK" timeout 60 "$HISN" exec --no-tty --session "$A" -- python3 net_helper.py in-child 18105 </dev/null 2>&1)
  if printf '%s\n' "$OUT" | grep -q '^CHILD-OK'; then pass "0.6.1 seat exec: connect from a child process"; else fail "0.6.1 seat exec: connect from a child process" "[$OUT]"; fi
  OUT=$(HISN_SEAT_TOKEN="$SEAT_TOK" timeout 60 "$HISN" exec --no-tty --session "$A" -- python3 net_helper.py in-thread 18106 </dev/null 2>&1)
  if printf '%s\n' "$OUT" | grep -q '^THREAD-OK'; then pass "0.6.1 seat exec: connect from a second thread"; else fail "0.6.1 seat exec: connect from a second thread" "[$OUT]"; fi
  journal_is "0.6.1 journal: child process connect names its seat" "$AWS" 1 \
    kind=network/connect target=192.0.2.1:18105 verdict=allow seat=member1
  journal_is "0.6.1 journal: second-thread connect names its seat" "$AWS" 1 \
    kind=network/connect target=192.0.2.1:18106 verdict=allow seat=member1
  SEATN=$(timeout 20 "$HISN" journal --workspace "$AWS" --seat member1 --kind network/connect --json </dev/null 2>/dev/null | grep -c '"seat":"member1"')
  if [ "$SEATN" = 3 ]; then pass "0.6.1 journal --seat selects exactly the three connects"; else fail "0.6.1 journal --seat selects exactly the three connects" "selected $SEATN"; fi
  # `journal --seat` must return the network/connect record itself (not
  # only the exec/* records the exec wrote): filter on the kind as
  # well.
  if timeout 20 "$HISN" journal --workspace "$AWS" --seat member1 --kind network/connect --json </dev/null 2>/dev/null | grep -q '"seat":"member1"'; then
    pass "0.6.1 journal --seat selects the seat's network record"
  else
    fail "0.6.1 journal --seat selects the seat's network record" "no member1 network/connect record selected"
  fi
  # The main command's connect has seat null (already checked above for
  # L102's exec; the main command is the init tree).
  journal_is "0.6.1 journal: main command's network/connect has seat null" "$AWS" 1 \
    kind=network/connect target=192.0.2.1:18090 verdict=allow seat=null
  if "$HISN" seat --workspace "$AWS" revoke member1 >/dev/null 2>&1; then
    pass "0.6.1 seat revoke"
  else
    fail "0.6.1 seat revoke" "revoke failed"
  fi
else
  skip "0.6.1 seat attribution" "seat add did not print a credential"
fi

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
journal_is "L96 journal: loopback connect is supervisor-executed" "$AWS" 1 kind=network/connect target=127.0.0.1:19001 verdict=allow reason=supervisor-executed-inprogress
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

# L124: connect() again on a socket whose non-blocking connect failed
# returns that failure (ECONNREFUSED; ECONNABORTED once SO_ERROR was
# read), as without hisn. It does not replace the socket and start a
# second connection: each port sees exactly one injected connect.
check "L124 connect() on a socket whose connect failed returns ECONNREFUSED (ECONNABORTED after SO_ERROR was read)" "REFAILED-OK unread=ECONNREFUSED read=ECONNABORTED" in_session "$A" in-reconnect-failed 18446 18447
journal_is "L124 journal: one injected connect to the first closed port, no second one" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18446 verdict=allow
journal_is "L124 journal: one injected connect to the second closed port, no second one" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18447 verdict=allow
journal_is "L124 journal: the second connect is refuse/earlier-connect-failed" "$AWS" 1 \
  kind=network/connect target=192.0.2.1:18446 verdict=refuse reason=earlier-connect-failed

# L125: a socket whose connect the supervisor made and which failed stays
# with the program, in the supervisor's namespace. It may not reach a
# host loopback daemon (18070 is one), bind or listen there, or send with
# fast-open. Nothing may be opened or reached on the host side.
check "L125 a kept supervisor-side socket: loopback connect and bind fail EACCES, listen refused EACCES, fast-open fails EOPNOTSUPP" "HOSTSOCKET-OK connect=EACCES bind=EACCES listen=EACCES fastopen=EOPNOTSUPP" in_session "$A" in-hostsocket 18448
journal_is "L125 journal: the loopback connect is refuse/host-socket-loopback-or-unix" "$AWS" 1 \
  kind=network/connect target=127.0.0.1:18070 verdict=refuse reason=host-socket-loopback-or-unix
journal_is "L125 journal: the bind is refuse/host-socket-bind" "$AWS" 1 \
  kind=network/implicit verdict=refuse reason=host-socket-bind
journal_is "L125 journal: the bind record names bind" "$AWS" 1 \
  kind=network/implicit "target=bind host-socket-bind"
# listen on a host socket is refused: journal has the refusal record.
journal_is "L125 journal: the listen is refuse/host-socket-listen" "$AWS" 1 \
  kind=network/implicit verdict=refuse reason=host-socket-listen
if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1',19060))==0 else 1)"; then
  fail "L125 host side: port 19060 is not open in the supervisor's namespace" "something listens on 127.0.0.1:19060"
else
  pass "L125 host side: port 19060 is not open in the supervisor's namespace"
fi

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
journal_is "L99 journal: second connect() on a connected socket to a private target is refuse/already-connected (0.6.1)" "$AWS" 1 \
  kind=network/connect target=192.168.1.1:18080 verdict=refuse reason=already-connected
check "L104 connect() on a datagram socket is refused EACCES" "L104-OK" in_session "$A" in-dgram
journal_is "L104 journal: refuse non-stream" "$AWS" 1 kind=network/connect target=192.0.2.1:18080 verdict=refuse reason=non-stream
check "L105 bind before connect: connected, source port not kept" "L105-OK" in_session "$A" in-bind
check "L106 a pending connect does not delay another" "L106-OK" in_session "$A" in-concurrent
journal_is "L103 journal: no connect was refused for an unreadable task" "$AWS" 0 kind=network/connect reason=pidfd-open-failed
check "L107 private, link-local, CGNAT, ULA and embedded-IPv4 targets refused EACCES" "L107-OK" in_session "$A" in-private
journal_is "L107 journal: refuse 192.168.1.1:80" "$AWS" 1 kind=network/connect target=192.168.1.1:80 verdict=refuse reason=private-or-unlisted
journal_is "L107 journal: refuse 6to4 form of 10.0.0.1" "$AWS" 1 kind=network/connect target=2002:a00:1::1:80 verdict=refuse reason=private-or-unlisted
check "L126 bind by socket domain: netlink, unix, high tcp ok; low port, AF_UNSPEC low port, packet refused" "L126-OK " in_session "$A" in-bind-families
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
# L-c (0.6.3): the two lines above connect to a public-class address, so they
# show network latency. This one is a local connect (127.0.0.1) inside the
# session: the interception cost alone.
info "timing local (127.0.0.1, in the session): $(in_session "$A" in-timing-local)"
info "network records of session $A (first of each kind/verdict/reason/result):"
journal "$AWS" | python3 "$HELPER" journal-dump | python3 -c '
import json, sys
seen = set()
for line in sys.stdin:
    r = json.loads(line); d = r["data"]
    key = (r["kind"], d.get("verdict"), d.get("reason"), d.get("rcode"), d.get("result"))
    if key not in seen:
        seen.add(key); print("INFO    " + line.strip())'

# ============================================ 0.6.2 I3 parity + concurrency
# Ordinary-program behaviour is unchanged: loopback server/client,
# AF_UNIX path and abstract, non-blocking and IPv6 all work inside an
# open session, and many threads doing socket work at once get the
# native answers.
check "0.6.2 I3 parity: loopback v4/v6, non-blocking, AF_UNIX path/abstract" "PARITY-OK" in_session "$A" in-parity
check "0.6.2 concurrency: 16 threads of ordinary socket work" "CONCURRENCY-OK" in_session "$A" in-concurrency 16

# ======================================================= detached exec (0.6.4)
# DX1-DX4 run in the open session A: a detached exec is started by
# `hisn exec --detach` (no client stdio), its work is seen through files in
# the session cwd, and it gets the same sandbox and open-mode network policy
# as a normal exec. DX5 uses its own session and stops it.
wait_file() { # FILE SECS: true once FILE exists
  local i
  for i in $(seq $(($2 * 10))); do
    [ -e "$1" ] && return 0
    sleep 0.1
  done
  return 1
}
dx_start() { # SESSION ARGV...: detached start; prints the JSON object
  local s=$1
  shift
  timeout 20 "$HISN" exec --detach --session "$s" -- "$@" </dev/null 2>&1
}
rm -f "$ACWD"/dx*.out

# DX1: the CLI returns at once with the identity, and the program ran.
DX1_T0=$(date +%s%N)
DX1_OUT=$(dx_start "$A" sh -c "echo dx1-ran >'$ACWD/dx1.out'")
DX1_MS=$(( ($(date +%s%N) - DX1_T0) / 1000000 ))
if printf '%s' "$DX1_OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="hisn-exec-start/v1" and d["exec_id"].startswith("e-") and d["incarnation"] and d["pid"]>0'; then
  pass "DX1 exec --detach prints hisn-exec-start/v1 with exec_id, incarnation, pid"
else
  fail "DX1 exec --detach prints hisn-exec-start/v1 with exec_id, incarnation, pid" "[$DX1_OUT]"
fi
if wait_file "$ACWD/dx1.out" 10 && [ "$(cat "$ACWD/dx1.out")" = dx1-ran ]; then
  pass "DX1 the detached program ran"
else
  fail "DX1 the detached program ran" "no $ACWD/dx1.out"
fi
DX1_SLEEP=$(dx_start "$A" sleep 7)
DX1_MS2=$(( ($(date +%s%N) - DX1_T0) / 1000000 ))
if [ "$DX1_MS" -lt 5000 ]; then pass "DX1 exec --detach returned at once ($DX1_MS ms)"; else fail "DX1 exec --detach returned at once" "$DX1_MS ms"; fi
DX1_LS=$(timeout 20 "$HISN" ls --json </dev/null 2>/dev/null | python3 -c '
import json,sys
for s in json.load(sys.stdin)["sessions"]:
    if s["id"] == sys.argv[1]:
        e=[x for x in s["execs"] if x.get("detached")]
        print(len(e), s.get("incarnation") is not None, e[0]["state"] if e else "-", e[0]["incarnation"]==s["incarnation"] if e else "-")
' "$A")
if [ "$DX1_LS" = "1 True running True" ]; then pass "DX1 ls --json lists the detached exec (detached, state, incarnation)"; else fail "DX1 ls --json lists the detached exec (detached, state, incarnation)" "[$DX1_LS]"; fi

# DX2: the exec survives the client. The control connection of a client that
# asked for a detached exec is closed right after the reply (the CLI is gone
# anyway); the program must still finish its work 3 s later.
DXDIR=$(session_field "$A" dir)
timeout 20 python3 - "$DXDIR/control.sock" "$ACWD" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
req = {"op": "exec", "argv": ["sh", "-c", "sleep 3; echo dx2-alive >" + sys.argv[2] + "/dx2.out"],
       "cwd": None, "env": {}, "tty": False, "detach": True,
       "client": {"protocol_version": 4}}
s.sendall((json.dumps(req) + "\n").encode())
line = s.makefile().readline()
assert json.loads(line)["detached"] is True, line
s.close()
PY
if wait_file "$ACWD/dx2.out" 12 && [ "$(cat "$ACWD/dx2.out")" = dx2-alive ]; then
  pass "DX2 a detached exec survives the death of its client connection"
else
  fail "DX2 a detached exec survives the death of its client connection" "no $ACWD/dx2.out"
fi

# DX3: the sandbox is the one of a normal exec. A file outside the grants is
# not readable (positive control: a file in the cwd is).
echo dx3-host-secret >"$T/dx3-secret"
echo dx3-inside >"$ACWD/dx3-inside"
dx_start "$A" sh -c "cat '$T/dx3-secret' >'$ACWD/dx3.out' 2>&1; echo rc=\$? >>'$ACWD/dx3.out'; cat '$ACWD/dx3-inside' >>'$ACWD/dx3.out'" >/dev/null
DX3_OK=0
for _ in $(seq 100); do
  grep -q dx3-inside "$ACWD/dx3.out" 2>/dev/null && { DX3_OK=1; break; }
  sleep 0.1
done
if [ "$DX3_OK" = 1 ] && ! grep -q dx3-host-secret "$ACWD/dx3.out" && ! grep -q '^rc=0$' "$ACWD/dx3.out"; then
  pass "DX3 a detached exec cannot read a host file outside the grants (the cwd file is readable)"
else
  fail "DX3 a detached exec cannot read a host file outside the grants (the cwd file is readable)" "[$(cat "$ACWD/dx3.out" 2>&1)]"
fi

# DX4: the open-mode network policy applies: a listed destination connects
# through interception, a private one is refused, both journaled with the
# same verdicts as for a normal exec.
dx_start "$A" sh -c "python3 '$ACWD/net_helper.py' in-connect 18102 >'$ACWD/dx4a.out' 2>&1; python3 '$ACWD/net_helper.py' in-refused 10.1.2.3 80 >'$ACWD/dx4b.out' 2>&1" >/dev/null
wait_file "$ACWD/dx4b.out" 20
sleep 1
if grep -q 'CONNECT-OK' "$ACWD/dx4a.out" 2>/dev/null; then pass "DX4 detached: a connect to the listener works through interception"; else fail "DX4 detached: a connect to the listener works through interception" "[$(cat "$ACWD/dx4a.out" 2>&1)]"; fi
if grep -q 'REFUSED-OK' "$ACWD/dx4b.out" 2>/dev/null; then pass "DX4 detached: a connect to a private address is refused EACCES"; else fail "DX4 detached: a connect to a private address is refused EACCES" "[$(cat "$ACWD/dx4b.out" 2>&1)]"; fi
journal_is "DX4 journal: the private target is refuse/private-or-unlisted" "$AWS" 1 \
  kind=network/connect target=10.1.2.3:80 verdict=refuse reason=private-or-unlisted

# ---- 0.6.4 A2: exec-status, exec-output, exec-signal, ownership (DX6-DX8)
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(d if not isinstance(d,bool) else str(d).lower())' "$1" 2>/dev/null; }
dx_id() { printf '%s' "$1" | jget exec_id; }
# dx_wait_state SESSION ID WANT [TOKEN]: poll exec-status until state == WANT
dx_wait_state() {
  local i st
  for i in $(seq 100); do
    if [ -n "${4:-}" ]; then
      st=$(HISN_SEAT_TOKEN="$4" timeout 20 "$HISN" exec-status --session "$1" --exec "$2" --json </dev/null 2>/dev/null | jget state)
    else
      st=$(timeout 20 "$HISN" exec-status --session "$1" --exec "$2" --json </dev/null 2>/dev/null | jget state)
    fi
    [ "$st" = "$3" ] && return 0
    sleep 0.1
  done
  return 1
}
# dx_wait_total SESSION ID STREAM: poll until the stream has data
dx_wait_total() {
  local i n
  for i in $(seq 100); do
    n=$(timeout 20 "$HISN" exec-output --session "$1" --exec "$2" --stream "$3" --json </dev/null 2>/dev/null | jget total)
    [ "${n:-0}" -gt 0 ] 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
unset HISN_SEAT_TOKEN

# DX6: the owner reads status and both streams of a running exec, signals it,
# and still reads status and output of the finished one.
DX6_OUT=$(dx_start "$A" sh -c "echo dx6-out; echo dx6-err >&2; sleep 300")
DX6_ID=$(dx_id "$DX6_OUT")
DX6_INC=$(printf '%s' "$DX6_OUT" | jget incarnation)
dx_wait_total "$A" "$DX6_ID" stdout
dx_wait_total "$A" "$DX6_ID" stderr
DX6_ST=$(timeout 20 "$HISN" exec-status --session "$A" --exec "$DX6_ID" --json </dev/null 2>&1)
if [ "$(printf '%s' "$DX6_ST" | jget state)" = running ] && [ "$(printf '%s' "$DX6_ST" | jget incarnation)" = "$DX6_INC" ] && [ "$(printf '%s' "$DX6_ST" | jget pid)" -gt 0 ] 2>/dev/null; then
  pass "DX6 exec-status of a running exec: state running, incarnation, pid"
else
  fail "DX6 exec-status of a running exec: state running, incarnation, pid" "[$DX6_ST]"
fi
DX6_O=$(timeout 20 "$HISN" exec-output --session "$A" --exec "$DX6_ID" </dev/null 2>"$T/dx6.err")
DX6_E=$(timeout 20 "$HISN" exec-output --session "$A" --exec "$DX6_ID" --stream stderr </dev/null 2>/dev/null)
if [ "$DX6_O" = dx6-out ] && [ "$DX6_E" = dx6-err ] && grep -q '^next=8' "$T/dx6.err" && ! grep -q eof "$T/dx6.err"; then
  pass "DX6 exec-output: stdout and stderr are separate, next=8, no eof while running"
else
  fail "DX6 exec-output: stdout and stderr are separate, next=8, no eof while running" "[$DX6_O] [$DX6_E] [$(cat "$T/dx6.err")]"
fi
DX6_O2=$(timeout 20 "$HISN" exec-output --session "$A" --exec "$DX6_ID" --offset 4 --incarnation "$DX6_INC" </dev/null 2>/dev/null)
if [ "$DX6_O2" = "out" ]; then pass "DX6 exec-output --offset 4 returns the rest"; else fail "DX6 exec-output --offset 4 returns the rest" "[$DX6_O2]"; fi
timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX6_ID" --signal TERM </dev/null >/dev/null 2>"$T/dx6.sig"
DX6_SRC=$?
if [ "$DX6_SRC" = 0 ] && dx_wait_state "$A" "$DX6_ID" signalled; then
  DX6_ST=$(timeout 20 "$HISN" exec-status --session "$A" --exec "$DX6_ID" --json </dev/null 2>&1)
  if [ "$(printf '%s' "$DX6_ST" | jget cause)" = exec-signal ] && [ "$(printf '%s' "$DX6_ST" | jget signal_name)" = TERM ]; then
    pass "DX6 exec-signal TERM ends the exec: state signalled, cause exec-signal"
  else
    fail "DX6 exec-signal TERM ends the exec: state signalled, cause exec-signal" "[$DX6_ST]"
  fi
else
  fail "DX6 exec-signal TERM ends the exec: state signalled, cause exec-signal" "rc=$DX6_SRC [$(cat "$T/dx6.sig")]"
fi
DX6_F=$(timeout 20 "$HISN" exec-output --session "$A" --exec "$DX6_ID" --json </dev/null 2>&1)
if [ "$(printf '%s' "$DX6_F" | jget eof)" = true ] && [ "$(printf '%s' "$DX6_F" | jget next)" = 8 ]; then
  pass "DX6 finished exec: output still readable, eof true"
else
  fail "DX6 finished exec: output still readable, eof true" "[$DX6_F]"
fi
DX6_TXT=$(timeout 20 "$HISN" exec-status --session "$A" --exec "$DX6_ID" </dev/null 2>&1)
if printf '%s' "$DX6_TXT" | grep -q 'signalled' && printf '%s' "$DX6_TXT" | grep -q 'cause    exec-signal'; then pass "DX6 exec-status plain text names state and cause"; else fail "DX6 exec-status plain text names state and cause" "[$DX6_TXT]"; fi
DX6_BAD=$(timeout 20 "$HISN" exec-status --session "$A" --exec e-9999 --json </dev/null 2>&1)
DX6_RC=$?
if [ "$DX6_RC" = 125 ] && printf '%s' "$DX6_BAD" | grep -q 'E_NOT_FOUND'; then pass "DX6 unknown exec: hisn-error/v1 E_NOT_FOUND, exit 125"; else fail "DX6 unknown exec: hisn-error/v1 E_NOT_FOUND, exit 125" "rc=$DX6_RC [$DX6_BAD]"; fi
DX6_INCBAD=$(timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX6_ID" --signal TERM --incarnation 19990101T000000Z-0000 </dev/null 2>&1)
DX6_RC=$?
if [ "$DX6_RC" = 125 ] && printf '%s' "$DX6_INCBAD" | grep -q 'incarnation'; then pass "DX6 exec-signal of another incarnation is a clear error, exit 125"; else fail "DX6 exec-signal of another incarnation is a clear error, exit 125" "rc=$DX6_RC [$DX6_INCBAD]"; fi
journal_is "DX6 journal: execsignal/delivered names the exec and the signal" "$AWS" 1 \
  kind=execsignal/delivered signal=TERM

# DX7: a member cannot signal an exec another seat started. dave starts an
# exec, bob (member) is refused and the exec lives on; dave may signal its own.
DX_BOB=$("$HISN" seat --workspace "$AWS" add dxbob --role member 2>/dev/null)
DX_DAVE=$("$HISN" seat --workspace "$AWS" add dxdave --role member 2>/dev/null)
DX_CAROL=$("$HISN" seat --workspace "$AWS" add dxcarol --role observer 2>/dev/null)
DX7_OUT=$(HISN_SEAT_TOKEN="$DX_DAVE" dx_start "$A" sh -c "echo dx7-out; sleep 300")
DX7_ID=$(dx_id "$DX7_OUT")
if [ -n "$DX7_ID" ]; then
  HISN_SEAT_TOKEN="$DX_BOB" timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX7_ID" --signal KILL </dev/null >/dev/null 2>"$T/dx7.err"
  DX7_RC=$?
  sleep 0.5
  if [ "$DX7_RC" = 125 ] && grep -q E_UNAUTHORIZED "$T/dx7.err" && dx_wait_state "$A" "$DX7_ID" running; then
    pass "DX7 a member cannot signal another seat's exec (exit 125, E_UNAUTHORIZED, exec still running)"
  else
    fail "DX7 a member cannot signal another seat's exec (exit 125, E_UNAUTHORIZED, exec still running)" "rc=$DX7_RC [$(cat "$T/dx7.err")]"
  fi
  journal_is "DX7 journal: execsignal/refused for the member, no delivery" "$AWS" 1 kind=execsignal/refused
  # the same member may read status and output of any exec (plan B2)
  DX7_R=$(HISN_SEAT_TOKEN="$DX_BOB" timeout 20 "$HISN" exec-output --session "$A" --exec "$DX7_ID" </dev/null 2>/dev/null)
  if [ "$DX7_R" = dx7-out ]; then pass "DX7 a member reads output of another seat's exec"; else fail "DX7 a member reads output of another seat's exec" "[$DX7_R]"; fi
  # an exec the owner started is not signalable by a member either
  DX7_OWN=$(dx_id "$(dx_start "$A" sleep 300)")
  HISN_SEAT_TOKEN="$DX_BOB" timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX7_OWN" --signal KILL </dev/null >/dev/null 2>&1
  if [ "$?" = 125 ] && dx_wait_state "$A" "$DX7_OWN" running; then pass "DX7 a member cannot signal an owner-started exec"; else fail "DX7 a member cannot signal an owner-started exec" "not refused or not running"; fi
  # the owning seat may
  HISN_SEAT_TOKEN="$DX_DAVE" timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX7_ID" --signal TERM </dev/null >/dev/null 2>"$T/dx7b.err"
  if [ "$?" = 0 ] && dx_wait_state "$A" "$DX7_ID" signalled "$DX_DAVE"; then pass "DX7 the starting seat may signal its own exec"; else fail "DX7 the starting seat may signal its own exec" "[$(cat "$T/dx7b.err")]"; fi
  timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX7_OWN" --signal KILL </dev/null >/dev/null 2>&1
  # DX7b: the legacy `signal` op refuses a detached target, by id and by pid.
  DX7B_OUT=$(HISN_SEAT_TOKEN="$DX_DAVE" dx_start "$A" sleep 300)
  DX7B_ID=$(dx_id "$DX7B_OUT")
  DX7B_PID=$(printf '%s' "$DX7B_OUT" | jget pid)
  DX7B=$(timeout 20 python3 - "$DXDIR/control.sock" "$DX_BOB" "$DX7B_ID" "$DX7B_PID" <<'PY'
import json, socket, sys
sock, tok, eid, pid = sys.argv[1:5]
def ask(extra):
    s = socket.socket(socket.AF_UNIX); s.connect(sock)
    req = {"op": "signal", "signal": "KILL", "client": {"protocol_version": 3, "seat_token": tok}}
    req.update(extra)
    s.sendall((json.dumps(req) + "\n").encode())
    r = json.loads(s.makefile().readline()); s.close()
    return r
a = ask({"exec_id": eid}); b = ask({"pid": int(pid)})
print(a.get("error"), "exec-signal" in a.get("message", ""), b.get("error"), "exec-signal" in b.get("message", ""))
PY
)
  sleep 0.5
  if [ "$DX7B" = "E_BAD_REQUEST True E_BAD_REQUEST True" ] && dx_wait_state "$A" "$DX7B_ID" running; then
    pass "DX7b legacy signal by id and by pid refuses a detached exec (member), exec still running"
  else
    fail "DX7b legacy signal by id and by pid refuses a detached exec (member), exec still running" "[$DX7B]"
  fi
  timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX7B_ID" --signal KILL </dev/null >/dev/null 2>&1
else
  fail "DX7 seat starts a detached exec" "[$DX7_OUT]"
fi

# DX8: an observer reads status, is refused output and signal.
DX8_OUT=$(dx_start "$A" sh -c "echo dx8-out; sleep 300")
DX8_ID=$(dx_id "$DX8_OUT")
dx_wait_total "$A" "$DX8_ID" stdout
HISN_SEAT_TOKEN="$DX_CAROL" timeout 20 "$HISN" exec-status --session "$A" --exec "$DX8_ID" --json </dev/null >"$T/dx8.st" 2>&1
DX8_RC=$?
if [ "$DX8_RC" = 0 ] && [ "$(jget state <"$T/dx8.st")" = running ]; then pass "DX8 an observer reads exec status"; else fail "DX8 an observer reads exec status" "rc=$DX8_RC [$(cat "$T/dx8.st")]"; fi
HISN_SEAT_TOKEN="$DX_CAROL" timeout 20 "$HISN" exec-output --session "$A" --exec "$DX8_ID" </dev/null >"$T/dx8.out" 2>"$T/dx8.err"
DX8_RC=$?
if [ "$DX8_RC" = 125 ] && grep -q E_UNAUTHORIZED "$T/dx8.err" && ! grep -q dx8-out "$T/dx8.out" "$T/dx8.err"; then pass "DX8 an observer is refused exec output (exit 125, no data)"; else fail "DX8 an observer is refused exec output (exit 125, no data)" "rc=$DX8_RC [$(cat "$T/dx8.out" "$T/dx8.err")]"; fi
HISN_SEAT_TOKEN="$DX_CAROL" timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX8_ID" --signal KILL </dev/null >/dev/null 2>&1
if [ "$?" = 125 ] && dx_wait_state "$A" "$DX8_ID" running; then pass "DX8 an observer cannot signal"; else fail "DX8 an observer cannot signal" "not refused or exec gone"; fi
journal_is "DX8 journal: execoutput/refused for the observer" "$AWS" 1 kind=execoutput/refused
timeout 20 "$HISN" exec-signal --session "$A" --exec "$DX8_ID" --signal KILL </dev/null >/dev/null 2>&1

# DX5: a detached exec ends when its session stops: the process is gone, the
# exec's journal record says session-stop, and session/stop lists it.
DX5="$TOKEN-dx5"
DX5CWD="$T/dx5-cwd"
write_policy "$T/dx5.toml" "$DX5CWD" none
if start_session "$DX5" "$DX5CWD" --policy "$T/dx5.toml" sleep 3600; then
  DX5WS=$(session_field "$DX5" workspace.id)
  DX5_OUT=$(dx_start "$DX5" sh -c "sleep 300; true # dx5-token-$TOKEN")
  DX5_ID=$(printf '%s' "$DX5_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["exec_id"])' 2>/dev/null)
  if pgrep -f "dx5-token-$TOKEN" >/dev/null 2>&1; then pass "DX5 the detached sleeper runs before the stop"; else fail "DX5 the detached sleeper runs before the stop" "[$DX5_OUT]"; fi
  timeout 60 "$HISN" stop --session "$DX5" </dev/null >/dev/null 2>&1
  sleep 1
  if pgrep -f "dx5-token-$TOKEN" >/dev/null 2>&1; then fail "DX5 the detached exec ends at session stop" "sleeper still running"; else pass "DX5 the detached exec ends at session stop"; fi
  DX5_J=$(journal "$DX5WS" | python3 -c '
import json,sys
eid=sys.argv[1]
exit_ok=stop_ok=False
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    r=json.loads(l)
    d=r.get("data",{})
    if r["kind"]=="exec/exit" and d.get("exec_id")==eid and d.get("cause")=="session-stop" and d.get("incarnation") and "seat" in d:
        exit_ok=True
    if r["kind"]=="session/stop" and any(x.get("exec_id")==eid for x in d.get("detached_execs_ended",[])):
        stop_ok=True
print("exit=%s stop=%s" % (exit_ok, stop_ok))
' "$DX5_ID")
  if [ "$DX5_J" = "exit=True stop=True" ]; then pass "DX5 journal: exec/exit cause session-stop and session/stop lists the exec"; else fail "DX5 journal: exec/exit cause session-stop and session/stop lists the exec" "[$DX5_J] id [$DX5_ID]"; fi
else
  fail "DX5 session starts" "[$(cat "$T/$DX5.log" 2>/dev/null)]"
fi

# DX10: a running detached exec keeps its session alive past the idle timeout;
# once it ends, the session idles out.
DX10="$TOKEN-dx10"
DX10CWD="$T/dx10-cwd"
printf 'version = "hisn-policy/v1"\n[session]\ncwd = "%s"\nnetwork = "none"\nidle_timeout = "3s"\n' "$DX10CWD" >"$T/dx10.toml"
if start_session "$DX10" "$DX10CWD" --policy "$T/dx10.toml" sleep 3600; then
  # the main command is a client-less sleep; stop it so only the exec counts
  DX10_OUT=$(dx_start "$DX10" sleep 600)
  DX10_ID=$(dx_id "$DX10_OUT")
  sleep 8
  if [ "$(session_field "$DX10" state)" = running ] && dx_wait_state "$DX10" "$DX10_ID" running; then
    pass "DX10 a session with a 3 s idle timeout and a running detached exec is alive after 8 s"
  else
    fail "DX10 a session with a 3 s idle timeout and a running detached exec is alive after 8 s" "state [$(session_field "$DX10" state)]"
  fi
  timeout 20 "$HISN" exec-signal --session "$DX10" --exec "$DX10_ID" --signal KILL </dev/null >/dev/null 2>&1
  DX10_GONE=1
  for _ in $(seq 150); do [ "$(session_field "$DX10" state)" != running ] && { DX10_GONE=0; break; }; sleep 0.2; done
  if [ "$DX10_GONE" = 0 ]; then pass "DX10 after the exec ended the session idled out ($(session_field "$DX10" state))"; else fail "DX10 after the exec ended the session idled out" "still running after 30 s"; fi
else
  fail "DX10 session starts" "[$(cat "$T/$DX10.log" 2>/dev/null)]"
fi

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

#!/usr/bin/env bash
# L14b helper -- runs INSIDE `unshare -Urm` (see run.sh).
# A bind alias of the hisn runtime dir sits OUTSIDE the session cwd, so the
# session starts normally (R1b only scans the trees it binds). Offering that
# alias as a grant *source* of the running session must be refused by the
# grant-time R1b check (supervisor::do_grant -> alias::check_tree).
#
# usage: l14b.sh HISN POLICY XDG_DIR ALIAS_DIR LOGFILE
# Prints the grant response on stdout. Exit: 0 ran; 90 bind failed; 91 session
# did not come up (fixture problem, not a verdict).
set -u
HISN=$1 POL=$2 X=$3 ALIAS=$4 LOG=$5
mount --bind "$X/hisn" "$ALIAS" || exit 90
XDG_RUNTIME_DIR=$X "$HISN" run --policy "$POL" --session-id alias14b -- /bin/sleep 60 \
  </dev/null >/dev/null 2>"$LOG" &
P=$!
up=0
for _ in $(seq 1 100); do
  [ -S "$X/hisn/alias14b/control.sock" ] && { up=1; break; }
  kill -0 "$P" 2>/dev/null || break
  sleep 0.1
done
if [ $up -ne 1 ]; then exit 91; fi
sleep 0.3
XDG_RUNTIME_DIR=$X "$HISN" grant --session alias14b "$ALIAS" 2>&1
kill -TERM "$P" 2>/dev/null
for _ in $(seq 1 50); do kill -0 "$P" 2>/dev/null || break; sleep 0.1; done
kill -9 "$P" 2>/dev/null
wait "$P" 2>/dev/null
exit 0

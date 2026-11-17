#!/usr/bin/env bash
# Prepare the Node and Go clients of the network cases (L117, L118).
#
#   bash tests/leak/net_tools.sh DIR
#
# Runs OUTSIDE any session, with the machine's own go and node (from
# PATH). A session sees only the host's /usr, so the clients are put
# into DIR as files that can be copied into a session's working
# directory and run from there:
#
#   DIR/nb_go, DIR/nb_real   the Go clients, built statically
#                            (CGO_ENABLED=0) from tests/leak/*.go
#   DIR/node                 a copy of the node binary
#   DIR/lib/                 shared libraries node needs that are not in
#                            the system's own library directories
#   DIR/run-node             sh script: runs DIR/node (through the
#                            dynamic loader with DIR/lib when DIR/lib
#                            is not empty)
#   DIR/go.status            one line: `ok <version> (<path>)`,
#   DIR/node.status          `missing <reason>` (the tool is not on this
#                            machine: the cases SKIP and name it) or
#                            `broken <reason>` (the tool is there but
#                            the client could not be prepared: the cases
#                            FAIL)
#
# HISN_NET_TOOL_LIBDIRS (colon-separated) and LD_LIBRARY_PATH are
# searched for libraries node needs and the system does not have.
#
# Always exits 0; the status files carry the result.
set -u

DIR=${1:?usage: net_tools.sh DIR}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$DIR" || exit 0
rm -rf "$DIR/lib" "$DIR/node" "$DIR/run-node" "$DIR/nb_go" "$DIR/nb_real"

# ----------------------------------------------------------------- go
if GO=$(command -v go 2>/dev/null); then
  GO_VERSION=$("$GO" version 2>/dev/null | awk '{print $3}')
  GO_STATUS="ok $GO_VERSION ($GO)"
  for name in nb_go nb_real; do
    if ! (cd "$HERE" && CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS='' GO111MODULE=off \
      "$GO" build -trimpath -o "$DIR/$name" "$name.go") >"$DIR/$name.build.log" 2>&1; then
      GO_STATUS="broken $GO build of tests/leak/$name.go failed: $(tr '\n' ' ' <"$DIR/$name.build.log" | head -c 300)"
      break
    fi
  done
else
  GO_STATUS="missing go is not installed on this machine (no go on PATH)"
fi
printf '%s\n' "$GO_STATUS" >"$DIR/go.status"

# --------------------------------------------------------------- node
node_status() { printf '%s\n' "$1" >"$DIR/node.status"; }
if ! NODE=$(command -v node 2>/dev/null); then
  node_status "missing node is not installed on this machine (no node on PATH)"
  exit 0
fi
# `node` may be a launcher script; the binary is what gets copied.
REAL=$("$NODE" -p 'process.execPath' 2>/dev/null) || REAL=""
[ -n "$REAL" ] && [ -x "$REAL" ] || REAL=$(readlink -f "$NODE")
if ! cp -L "$REAL" "$DIR/node"; then
  node_status "broken cannot copy $REAL"
  exit 0
fi
chmod 755 "$DIR/node"
LDD=$(ldd "$DIR/node" 2>&1)
LOADER=$(printf '%s\n' "$LDD" | awk '/ld-linux|ld-musl/ { for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; exit } }')
MISSING=$(printf '%s\n' "$LDD" | awk '/not found/ { print $1 }')
mkdir -p "$DIR/lib"
UNRESOLVED=""
for lib in $MISSING; do
  found=""
  IFS=: read -r -a dirs <<<"${HISN_NET_TOOL_LIBDIRS:-}:${LD_LIBRARY_PATH:-}"
  for d in "${dirs[@]}"; do
    [ -n "$d" ] && [ -e "$d/$lib" ] && { found="$d/$lib"; break; }
  done
  if [ -n "$found" ]; then
    cp -L "$found" "$DIR/lib/$lib"
  else
    UNRESOLVED="$UNRESOLVED $lib"
  fi
done
if [ -n "$UNRESOLVED" ]; then
  node_status "missing node ($REAL) needs$UNRESOLVED, which this machine does not have (looked in HISN_NET_TOOL_LIBDIRS and LD_LIBRARY_PATH)"
  exit 0
fi
if [ -n "$(ls -A "$DIR/lib")" ]; then
  if [ -z "$LOADER" ]; then
    node_status "broken cannot find the dynamic loader of $REAL in the ldd output"
    exit 0
  fi
  printf '#!/bin/sh\nd=$(dirname "$0")\nexec %s --library-path "$d/lib" "$d/node" "$@"\n' "$LOADER" >"$DIR/run-node"
else
  printf '#!/bin/sh\nd=$(dirname "$0")\nexec "$d/node" "$@"\n' >"$DIR/run-node"
fi
chmod 755 "$DIR/run-node"
if NODE_VERSION=$(sh "$DIR/run-node" --version 2>&1); then
  node_status "ok $NODE_VERSION ($REAL)"
else
  node_status "broken the copied node does not start: $(printf '%s' "$NODE_VERSION" | tr '\n' ' ' | head -c 300)"
fi
exit 0

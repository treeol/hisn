#!/usr/bin/env bash
# hisn release gate: run the full gate in order and stop at the first failure.
#
# Steps, in order:
#   1. cargo fmt --check
#   2. cargo clippy --all-targets -- -D warnings
#   3. make test
#   4. the leak suite with output through a pipe
#   5. the leak suite on a pseudo-terminal (via `script` when present)
#
# HISN_TEST_ROOTFS and HISN_BIG_TESTS, when set, are passed through to the
# leak suite; when they are not set the rootfs and big-import cases skip and
# this script prints a warning line saying so.
#
# The gate never installs anything and never touches sessions it did not
# start: every step is a read-only check or a self-contained test run.
set -u

cd "$(dirname "$0")/.." || exit 1

step() { printf 'release-gate: step %s: %s\n' "$1" "$2"; }
ok()   { printf 'release-gate: OK %s\n' "$1"; }
fail() { printf 'release-gate: FAIL %s: %s\n' "$1" "$2" >&2; exit 1; }

run_leak_pipe() {
  step 4 "leak suite through a pipe"
  set -o pipefail
  make leaktest 2>&1 | cat
  local rc=$?
  set +o pipefail
  [ "$rc" -eq 0 ] || fail "leak-suite-pipe" "make leaktest exited $rc"
  ok "leak-suite-pipe"
}

run_leak_pty() {
  step 5 "leak suite on a pseudo-terminal"
  if command -v script >/dev/null 2>&1; then
    set -o pipefail
    script -qec 'make leaktest' /dev/null
    local rc=$?
    set +o pipefail
    [ "$rc" -eq 0 ] || fail "leak-suite-pty" "make leaktest under script exited $rc"
    ok "leak-suite-pty"
    LEAK_PTY=ok
  else
    printf 'release-gate: SKIP leak-suite-pty: `script` (util-linux) not present on this host, so the pseudo-terminal run was skipped\n'
    LEAK_PTY=skipped-no-script
  fi
}

if [ -z "${HISN_TEST_ROOTFS:-}" ] || [ -z "${HISN_BIG_TESTS:-}" ]; then
  printf 'release-gate: warning: HISN_TEST_ROOTFS and/or HISN_BIG_TESTS not set; the rootfs and big-import leak cases will be skipped\n'
fi
# Pass the optional gates through when set (never invent values for them).
if [ -n "${HISN_TEST_ROOTFS:-}" ]; then export HISN_TEST_ROOTFS; fi
if [ -n "${HISN_BIG_TESTS:-}" ]; then export HISN_BIG_TESTS; fi

step 1 "cargo fmt --check"
cargo fmt --check || fail "fmt" "cargo fmt --check exited $?"
ok "fmt"

step 2 "cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings || fail "clippy" "cargo clippy exited $?"
ok "clippy"

step 3 "make test"
make test || fail "make-test" "make test exited $?"
ok "make-test"

run_leak_pipe
run_leak_pty

printf 'release-gate: summary fmt=ok clippy=ok make-test=ok leak-suite-pipe=ok leak-suite-pty=%s\n' "${LEAK_PTY:-skipped}"

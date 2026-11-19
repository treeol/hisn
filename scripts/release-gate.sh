#!/usr/bin/env bash
# hisn release gate: run the full gate in order and stop at the first failure.
#
# Steps, in order:
#   1. cargo fmt --check
#   2. cargo clippy --all-targets -- -D warnings (native target)
#   2b. cargo clippy --all-targets --target <t> -- -D warnings for each
#       non-native CI target that is installed (SKIP with a rustup hint when not)
#   3. make check (hisn check: host-capability report; exit 2 if a required
#      capability is missing)
#   4. make test
#   5. the leak suite with output through a pipe
#   6. the leak suite on a pseudo-terminal (via `script` when present)
#
# HISN_TEST_ROOTFS and HISN_BIG_TESTS, when set, are passed through to the
# leak suite; when they are not set the rootfs and big-import cases skip and
# this script prints a warning line saying so.
#
# The gate never installs anything and never touches sessions it did not
# start: every step is a read-only check or a self-contained test run.
set -u

# Private-details check (0.6.1 item 2d): shipped text must not name the
# author's machines or their LAN addresses. Shipped files are everything
# tracked except tests, fixtures and the gate's own allowlist; test-only
# files may keep fixture addresses. The pattern matches the author's
# host names, home path and user, and any address in 192.168.1.0/24 or
# 192.168.88.0/24. Matches are filtered through
# scripts/release-gate-allowlist.txt (one fixed substring per line); a
# surviving match fails the gate.
run_private_details() {
  step 0 "private-details check (shipped files)"
  local allow="scripts/release-gate-allowlist.txt" pat='rubin|smaragd|firecracker|pihole|/home/valon|valon@|192\.168\.(1|88)\.[0-9]+' # gate pattern (case-insensitive) (allowlisted below)
  local hits
  hits=$(git ls-files -- '*.md' '*.toml' '*.txt' '*.sh' '*.rs' '*.py' \
    ':!tests/*' ':!scripts/release-gate-allowlist.txt' | while IFS= read -r f; do
      grep -niE "$pat" -- "$f" 2>/dev/null | sed "s|^|$f:|"
    done)
  if [ -n "$hits" ]; then
    local bad=""
    while IFS= read -r line; do
      local ok=0 a
      [ -f "$allow" ] && while IFS= read -r a; do
        case "$a" in ''|'#'*) continue ;; esac
        case "$line" in *"$a"*) ok=1; break ;; esac
      done <"$allow"
      [ "$ok" -eq 0 ] && bad="${bad}
$line"
    done <<<"$hits"
    if [ -n "$bad" ]; then
      fail "private-details" "shipped files contain private host names/addresses:$bad"
    fi
  fi
  ok "private-details"
}

cd "$(dirname "$0")/.." || exit 1

step() { printf 'release-gate: step %s: %s\n' "$1" "$2"; }
ok()   { printf 'release-gate: OK %s\n' "$1"; }
fail() { printf 'release-gate: FAIL %s: %s\n' "$1" "$2" >&2; exit 1; }

# Cross-target clippy: CI builds these non-native targets exactly as
# `cargo clippy --locked --all-targets --target <t> -- -D warnings`.
# Dead-code constants fine on one arch fail on another, and
# target-specific type mismatches (e.g. libc::Ioctl on musl) compile
# only for their target. The gate runs clippy for each installed target
# and SKIPs (with a rustup hint) the rest. A non-zero exit fails the gate.
CROSS_TARGETS="aarch64-unknown-linux-gnu x86_64-unknown-linux-musl"

run_cross_clippy() {
  local installed
  installed="$(rustup target list --installed 2>/dev/null)"
  CROSS_SKIP=""
  for t in $CROSS_TARGETS; do
    if printf '%s\n' "$installed" | grep -qx "$t"; then
      step 2b "cargo clippy --locked --all-targets --target $t -- -D warnings"
      cargo clippy --locked --all-targets --target "$t" -- -D warnings \
        || fail "cross-clippy-$t" "cargo clippy --locked --target $t exited $?"
      ok "cross-clippy-$t"
    else
      printf 'release-gate: SKIP cross-clippy-%s: rustup target add %s\n' "$t" "$t"
      CROSS_SKIP="${CROSS_SKIP} $t"
    fi
  done
}

run_leak_pipe() {
  step 5 "leak suite through a pipe"
  set -o pipefail
  make leaktest 2>&1 | cat
  local rc=$?
  set +o pipefail
  [ "$rc" -eq 0 ] || fail "leak-suite-pipe" "make leaktest exited $rc"
  ok "leak-suite-pipe"
}

run_leak_pty() {
  step 6 "leak suite on a pseudo-terminal"
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

run_private_details

step 1 "cargo fmt --check"
cargo fmt --check || fail "fmt" "cargo fmt --check exited $?"
ok "fmt"

step 2 "cargo clippy --locked --all-targets -- -D warnings"
cargo clippy --locked --all-targets -- -D warnings || fail "clippy" "cargo clippy exited $?"
ok "clippy"

run_cross_clippy

step 3 "make check"
make check || fail "make-check" "make check exited $?"
ok "make-check"

step 4 "make test"
make test || fail "make-test" "make test exited $?"
ok "make-test"

run_leak_pipe
run_leak_pty

printf 'release-gate: summary fmt=ok clippy=ok cross-clippy=%s make-check=ok make-test=ok leak-suite-pipe=ok leak-suite-pty=%s\n' \
  "${CROSS_SKIP:-all-ok}" "${LEAK_PTY:-skipped}"

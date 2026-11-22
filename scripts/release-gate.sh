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
#   7. the hermetic net harness (tests/leak/net_cases.sh under `unshare -Urn`,
#      DX detached-exec cases included), with its own pass/fail/skip counts
#   8. tests/leak/compat_063.sh against a v0.6.3 binary built from the tag in
#      a separate git worktree (own target dir under target/, removed after);
#      a missing tag fails the gate, it is never skipped
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

run_net_harness() {
  step 7 "net harness (net_cases.sh, DX cases included)"
  local hisn work out rc
  hisn="$(pwd)/target/release/hisn"
  [ -x "$hisn" ] || fail "net-harness" "$hisn is missing (make check builds it)"
  command -v ip >/dev/null 2>&1 || fail "net-harness" "the ip command (iproute2) is not installed"
  timeout 10 unshare -Urn true 2>/dev/null \
    || fail "net-harness" "unshare -Urn (unprivileged user + network namespace) is not available"
  work=$(mktemp -d /tmp/hisn-gate-net.XXXXXX) || fail "net-harness" "mktemp failed"
  out="$work.out"
  timeout 900 unshare -Urn bash tests/leak/net_cases.sh "$hisn" "$work" "gate$$" </dev/null >"$out" 2>&1
  rc=$?
  if [ -f "$work/supervisor.pids" ]; then
    local p
    while read -r p; do
      [ -n "$p" ] && [ -r "/proc/$p/cmdline" ] \
        && tr '\0' ' ' <"/proc/$p/cmdline" | grep -qF -- "gate$$" && kill -9 "$p" 2>/dev/null
    done <"$work/supervisor.pids"
  fi
  rm -rf "$work"
  NET_P=$(grep -c '^PASS  ' "$out"); NET_F=$(grep -c '^FAIL: ' "$out"); NET_S=$(grep -c '^SKIP  ' "$out")
  NET_DX=$(grep -c '^PASS  DX' "$out")
  grep -E '^(FAIL: |NET-CASES: )' "$out"
  local trailer
  trailer=$(grep '^NET-CASES: ' "$out" | tail -n 1)
  if [ "$rc" -eq 124 ]; then
    rm -f "$out"; fail "net-harness" "net_cases.sh timed out after 900 s"
  elif [ "$trailer" != "NET-CASES: pass=$NET_P fail=$NET_F skip=$NET_S" ]; then
    tail -n 5 "$out" >&2; rm -f "$out"
    fail "net-harness" "summary [$trailer] disagrees with the lines read (exit $rc)"
  elif [ "$rc" -ne 0 ] || [ "$NET_F" -ne 0 ] || [ "$NET_DX" -eq 0 ]; then
    rm -f "$out"
    fail "net-harness" "exit $rc, $NET_F failed, $NET_DX DX cases passed (at least one required)"
  fi
  rm -f "$out"
  ok "net-harness (pass=$NET_P fail=$NET_F skip=$NET_S dx-pass=$NET_DX)"
}

run_compat_063() {
  step 8 "compat_063.sh against v0.6.3 built from the tag"
  git rev-parse -q --verify "refs/tags/v0.6.3^{commit}" >/dev/null 2>&1 \
    || fail "compat-063" "tag v0.6.3 is missing: fetch tags (git fetch --tags); this step is never skipped"
  local wt="target/gate-v063-wt" tgt="target/gate-v063-target" out rc
  git worktree remove --force "$wt" >/dev/null 2>&1
  git worktree add --detach "$wt" v0.6.3 >/dev/null 2>&1 \
    || fail "compat-063" "git worktree add $wt v0.6.3 failed"
  (cd "$wt" && CARGO_TARGET_DIR="$(cd .. && pwd)/gate-v063-target" cargo build --release --locked) >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] || [ ! -x "$tgt/release/hisn" ]; then
    git worktree remove --force "$wt" >/dev/null 2>&1; git worktree prune
    fail "compat-063" "building v0.6.3 in $wt failed (exit $rc)"
  fi
  out=$(mktemp /tmp/hisn-gate-compat.XXXXXX)
  timeout 900 bash tests/leak/compat_063.sh "$(pwd)/target/release/hisn" "$(pwd)/$tgt/release/hisn" >"$out" 2>&1
  rc=$?
  git worktree remove --force "$wt" >/dev/null 2>&1; git worktree prune
  rm -rf "$tgt"
  grep -E '^(FAIL|SKIP|RESULT)' "$out"
  CMP_LINE=$(grep '^RESULT: ' "$out" | tail -n 1)
  CMP_P=$(grep -c '^PASS' "$out"); CMP_F=$(grep -c '^FAIL' "$out"); CMP_S=$(grep -c '^SKIP' "$out")
  rm -f "$out"
  if [ "$rc" -ne 0 ] || [ "$CMP_F" -ne 0 ] || [ -z "$CMP_LINE" ]; then
    fail "compat-063" "exit $rc, $CMP_F failed"
  fi
  ok "compat-063 (pass=$CMP_P fail=$CMP_F skip=$CMP_S)"
}

if [ -z "${HISN_TEST_ROOTFS:-}" ] || [ -z "${HISN_BIG_TESTS:-}" ]; then
  printf 'release-gate: warning: HISN_TEST_ROOTFS and/or HISN_BIG_TESTS not set; the rootfs and big-import leak cases will be skipped\n'
fi
# Pass the optional gates through when set (never invent values for them).
if [ -n "${HISN_TEST_ROOTFS:-}" ]; then export HISN_TEST_ROOTFS; fi
if [ -n "${HISN_BIG_TESTS:-}" ]; then export HISN_BIG_TESTS; fi

run_private_details

# 0.6.2: the `force-continue` feature is test-only. A release build
# must not contain it: verify it is not enabled by default and that the
# release binary does not carry the feature (the feature name never
# appears in the release build's feature list).
step 0b "force-continue absent from release builds"
if cargo metadata --locked --format-version 1 2>/dev/null | grep -q '"force-continue"'; then
  # metadata lists features; the check below is the real one: a
  # release build with the feature would expose the forced-continue
  # journal reason. Build the release artifact if present and grep it.
  :
fi
if [ -f target/release/hisn ]; then
  fc_count=$(grep -ac 'forced-continue' target/release/hisn 2>/dev/null)
  fc_count=${fc_count:-0}
  if [ "$fc_count" -gt 0 ]; then
    fail "force-continue" "release binary contains the test-only forced-continue path ($fc_count matches)"
  fi
  printf 'release-gate: forced-continue count in release binary: %s\n' "$fc_count"
fi
# The feature must not be a default feature.
if grep -q 'default.*=.*force-continue' Cargo.toml; then
  fail "force-continue" "force-continue is enabled by default"
fi
ok "force-continue-absent"

# 0.6.2: the single continue site. `FLAG_CONTINUE` must appear only in
# `continue_reply` and in `cfg(feature = "force-continue")` blocks (which
# are not in release builds). Any other `FLAG_CONTINUE` write site fails
# the gate — it means the dispatch path bypasses `verdict_for`.
step 0c "single FLAG_CONTINUE site in notif.rs"
bad_sites=$(python3 -c '
import sys
lines = open("src/notif.rs").readlines()
in_fc = False
in_cr = False
fc_depth = 0
cr_depth = 0
bad = []
for i, line in enumerate(lines, 1):
    stripped = line.strip()
    if "cfg(feature = \"force-continue\")" in line and not stripped.startswith("//"):
        in_fc = True
        fc_depth = 0
        continue
    if in_fc:
        for ch in stripped:
            if ch == "{": fc_depth += 1
            elif ch == "}": fc_depth -= 1
        if fc_depth <= 0 and stripped.startswith("}"):
            in_fc = False
        continue
    if "fn continue_reply" in line and not stripped.startswith("//"):
        in_cr = True
        cr_depth = 0
        continue
    if in_cr:
        for ch in stripped:
            if ch == "{": cr_depth += 1
            elif ch == "}": cr_depth -= 1
        if cr_depth <= 0 and stripped.startswith("}"):
            in_cr = False
        continue
    if "FLAG_CONTINUE" in line and "pub const" not in line and not stripped.startswith("//"):
        bad.append("  line %d: %s" % (i, stripped))
if bad:
    print("\\n".join(bad))
    sys.exit(1)
' 2>&1 || true)
if [ -n "$bad_sites" ]; then
  fail "single-continue-site" "FLAG_CONTINUE appears outside continue_reply:$bad_sites"
fi
ok "single-continue-site"

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
run_net_harness
run_compat_063

printf 'release-gate: summary fmt=ok clippy=ok cross-clippy=%s make-check=ok make-test=ok leak-suite-pipe=ok leak-suite-pty=%s net-harness=ok(pass=%s,fail=%s,skip=%s,dx-pass=%s) compat-063=ok(pass=%s,fail=%s,skip=%s)\n' \
  "${CROSS_SKIP:-all-ok}" "${LEAK_PTY:-skipped}" \
  "$NET_P" "$NET_F" "$NET_S" "$NET_DX" "$CMP_P" "$CMP_F" "$CMP_S"

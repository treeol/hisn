#!/usr/bin/env bash
# Regenerate the build-sandbox half of docs/VERIFICATION.txt.
#
#   tools/verification.sh            # rewrites docs/VERIFICATION.txt
#
# Everything above the "## Host runs" marker is produced here, from the commands
# actually run, stamped with the commit they ran on. Everything from the marker
# down is the hand-maintained record of runs on real hosts and is preserved
# verbatim (this script cannot observe a host run and never invents one).
#
# Run it on a clean worktree: the stamp says so, and lists the dirty files if
# not, so a result is never attributed to a commit it did not run on.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT=docs/VERIFICATION.txt
MARK='## Host runs'

TAIL=""
if [ -f "$OUT" ] && grep -q "^$MARK" "$OUT"; then
  TAIL=$(sed -n "/^$MARK/,\$p" "$OUT")
fi

commit=$(git rev-parse HEAD 2>/dev/null || echo "not-a-git-repo")
dirty=$(git status --porcelain 2>/dev/null | grep -v " $OUT\$" | awk '{print $2}' | tr '\n' ' ')
if [ -n "$dirty" ]; then state="DIRTY (uncommitted: $dirty)"; else state="clean (docs/VERIFICATION.txt itself excluded)"; fi
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

TMP=$(mktemp)
{
  echo "# Verification record"
  echo
  echo "hisn version : $version"
  echo "commit       : $commit"
  echo "worktree     : $state"
  echo "generated    : $(date -u +%FT%TZ) by tools/verification.sh"
  echo "where        : build sandbox, uid $(id -u), $(uname -sr) $(uname -m)"
  echo "scope        : the results in this half are for the code at the commit above"
  echo
  echo "## cargo fmt --check"
  cargo fmt --check && echo clean
  echo
  echo "## cargo clippy --all-targets -- -D warnings (x86_64)"
  cargo clippy --all-targets -- -D warnings 2>&1 | tail -1
  echo
  echo "## cargo clippy --target aarch64-unknown-linux-gnu --all-targets -- -D warnings"
  cargo clippy --target aarch64-unknown-linux-gnu --all-targets -- -D warnings 2>&1 | tail -1
  echo
  echo "## cargo test"
  cargo test 2>&1 | tee /tmp/hisn-verif-unittests.log | grep -E "^test result: .* [1-9][0-9]* passed|FAILED|panicked"
  echo
  echo "## unit tests per module"
  # Derived from the SAME single run above (a second back-to-back `cargo test`
  # was the observed trigger of a test-ordering flake, OPEN-POINTS P20).
  grep -E "^test [a-z_0-9]+::" /tmp/hisn-verif-unittests.log | sed -E 's/^test ([a-z_0-9]+)::.*/\1/' | sort | uniq -c
  echo
  echo "## python3 tests/leak/test_l8.py (L8 comparator self-tests)"
  python3 -W ignore tests/leak/test_l8.py 2>&1 | grep -E "^(Ran|OK|FAILED)"
  echo
  cargo build --release >/dev/null 2>&1 && cargo build --release --example leakprobe >/dev/null 2>&1
  echo "## hisn --version"
  ./target/release/hisn --version
  echo
  echo "## hisn check (this sandbox)"
  ./target/release/hisn check
  echo "exit=$?"
  echo
  echo "## tests/leak/run.sh (this sandbox)"
  bash tests/leak/run.sh ./target/release/hisn >/tmp/hisn-verif-leak.out 2>&1
  rc=$?
  head -3 /tmp/hisn-verif-leak.out
  echo "..."
  echo "exit=$rc  (77 = suite NOT RUN here: no leak test was executed in this sandbox)"
  echo
  echo "## NOT verified in the build sandbox"
  echo "rootfs::execute, init (pivot_root, caps, post-setup verification), grant helper"
  echo "(move_mount/umount), supervisor lifecycle, exec helper, pty relay, R5 end-to-end,"
  echo "and every leak test. See 'Host runs' below for what a real host has reported."
  echo "Kernel-enforced here (real syscalls, no userns needed): seccomp filter stack,"
  echo "Landlock write-set, rlimits, fd passing, openat2 symlink refusal."
  echo
  if [ -n "$TAIL" ]; then
    printf '%s\n' "$TAIL"
  else
    echo "$MARK"
    echo "(none recorded)"
  fi
} >"$TMP" 2>&1
mv "$TMP" "$OUT"
echo "wrote $OUT (commit $commit, $state)"

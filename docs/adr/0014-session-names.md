# ADR 0014 — Session names: a file in the session dir is authoritative; the per-user index is a cache

Title: Session names are stored with the session; the index is derived.
Status: accepted. Date: 2026-11-07. Origin: PLAN-0.4 §1.

## Decision
- `--name <name>` is validated like rootfs names (`[A-Za-z0-9._-]{1,64}`, not `.`/`..`), unique per user.
- The authoritative record is `<session-dir>/name` (0600, written once with `O_EXCL`).
- `<runtime-root>/names.json` (`hisn-names/v1`) is a cache, rewritten atomically under `names.lock`.
- `ls --prune` is the only writer that repairs the index. Plain `ls` reads it, falls back to scanning `name` files if it is missing or invalid, and never writes.

## Why
A session dir is created atomically and is the unit that already gets
pruned. A crash between creating the dir and writing a separate index would
leave a live session with no name, so the dir has to carry its own name. The
index exists only to make name lookup O(1) and to detect collisions across the
two runtime roots.

## Consequences
- A name is reusable once its session is removed.
- A stale index entry never resolves to a wrong session: the `name` file is trusted over the index.
- `--prune` gains the reconciliation rules in PLAN-0.4 §1.2.
- Tests: unit `name_collision_with_live_is_refused`, `stale_name_is_reclaimed_by_run`, `index_missing_falls_back_to_scan`, `index_repair_trusts_name_file`, `prune_removes_index_entry`; leak L51 (sandbox cannot read the index or lock).

## Dated note (2026-11-07, PLAN-0.4 §11 fold)

- The authoritative record is the session dir (`name`), and creation publishes
  atomically via `.tmp-<id>` then `rename`. The index is consulted for `ls` only,
  never for correctness; name and id uniqueness are checked authoritatively on
  creation and resolution.
- The lock is `/tmp/hisn-$UID/names.lock`, shared by every root, opened through
  `session::ensure_root` (owner, 0700, not a symlink). This removes the cross-root race.

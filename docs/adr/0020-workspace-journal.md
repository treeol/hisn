# ADR 0020 — Workspace journal: one append-only journal per workspace, a record not a replay

Title: The workspace journal (0.5.0).
Status: accepted. Date: 2026-11-14. Origin: PLAN-0.5 Step 1 (journal, protocol
spec, version gate, git-change report). Implements the session's workspace
decision (the session belongs to a workspace; state under
`$XDG_STATE_HOME/hisn/workspaces/<id>/`).

## Decision

- **One journal per workspace**, `journal.jsonl` in the workspace dir
  (`$XDG_STATE_HOME/hisn/workspaces/<id>/`, dir `0700`). The workspace is
  derived from the session's canonical cwd (stable id from the canonical
  path, readable name from its last component); `--workspace NAME` overrides.
  `session.json` gains the optional `workspace` field.
- Every record has `v` (1), `ts`, `wseq` (a workspace-wide sequence assigned
  under an exclusive `flock` — several supervisors can write to one
  workspace), `session`, `kind`, `client` (when one exists: `uid`, `label`,
  `label_source`, `req_id`) and `data`. One JSON object per line, one single
  `write` per record on an `O_APPEND`, 0600 descriptor.
- Every event written to `grants.jsonl` today is also journaled (same
  information, journal shape) — the audit log is unchanged. Plus session
  start/stop, notes and markers, and the git-change records.
- **Exec records answer "what ran and how it ended".** The journal's exec
  request record carries the argv (512 bytes total across all elements,
  whole elements only, `truncated` flag + original count/byte length when
  capped) and the cwd when the request has one. The journal can contain
  whatever a command line contains — argv is recorded verbatim, with no
  pattern-based redaction, and the docs say so. The audit log never
  carries argv. One `exec/exit` record follows each finished exec (same
  `seq`/`req_id` as its request): exit code or terminating signal,
  cancelled/lost, duration in milliseconds. Readable output collapses an
  exec's request/result/exit into one line. Readable `--last N` counts
  merged events with kind `exec`; JSON counts raw records and keeps raw
  kinds. Readable `--kind exec` selects the exec family; JSON matches exact
  raw kinds. Matching exec groups are retrieved
  from all retained files, including requests before the filter window.
  Missing requests are explicitly marked orphan; unfinished requests open.
  Queries scan each retained file once, bounded by its size at open and a
  16 MiB per-record cap (no fixed total-history limit).
- **A short git-change record.** An unchanged repo journals the cwd, an
  explicit `unchanged` marker and the hook/config-key counts — no
  snapshots. A changed repo journals the change lists plus before/after
  only for what was added, removed or modified, plus everything flagged.
  Truncated/skipped stay explicit.
- `hisn journal --session` resolves the workspace from the session's
  `session.json` (any cwd); when the session is gone it falls back to the
  cwd-derived workspace and the error names the workspace searched and
  points to `--workspace`.
- When the state home falls back to `/tmp/hisn-state-unset-<uid>`, the
  supervisor warns once at session start that the journal will not
  survive a reboot.
- **It is a record, not a replay mechanism.** Nothing re-executes it. It is
  queryable per seat and per task (`hisn journal …`), so an agent can ask
  what it did recently. `hisn journal` reads host-side, so it works for
  stopped and pruned sessions.
- **Failure handling (the failure-handling rule).** A journal write that
  fails must not fail the operation it records. The failure is logged to
  `supervisor.log`, counted, and the count is visible in `hisn journal`
  output and as an additive key in `ls --json`. The one exception: a `note`
  request returns an error to the caller, since the journal write *is* the
  operation.
- **Rotation (from day one, O6).** When `journal.jsonl` exceeds 64 MiB it is
  renamed to `journal.<n>.jsonl` under the same lock and a new file is
  started; `wseq` does not restart (it is read from the rotated file's tail).
  Queries read rotated files too.
- Notes: the new `note` op (`kind` = `note` | `marker`, `text` ≤ 8 KiB) is
  stored and returned verbatim and never parsed, interpreted or executed.
- The git-change report is report only: a start/stop snapshot of
  `.git/hooks` and `.git/config` is journaled as one `git-change` record.
  Nothing is blocked, reverted or made read-only.

## Alternatives considered

- **Keep only `grants.jsonl` (no journal).** Rejected: it is per-session, is
  removed with the session dir, and answers no cross-session or
  per-seat/per-task question. The journal is the workspace record.
- **Replay (make the journal drive re-execution).** Rejected: the journal is
  a record, not a replay mechanism — replay would be a second source of truth
  for what happened, and would need the full operation semantics in one place.
- **A single global journal under `$XDG_STATE_HOME/hisn`.** Rejected: a
  workspace is the unit of collaboration (a seat works on one repo), so the
  journal is per-workspace; a global log mixes repos and scales badly.
- **Synchronous journal that fails the op on error.** Rejected (the
  failure-handling rule): a full or read-only state dir must not take down
  the session. The counter makes the loss visible instead of silent.

## Consequences

- `hisn journal` / `hisn note` exist; `ls --json` gains `journal_failures`
  and `journal_bytes` (additive).
- The journal outlives the session dir: a start/stop trail survives `hisn
  stop` and `ls --prune`.
- A torn final line never breaks the read (unparseable lines are skipped and
  counted) and never yields a duplicate `wseq`.

## Tests

- Unit: concurrent writers keep `wseq` strictly increasing with no lost line;
  rotation under load; query filters; note size limit; a failed journal write
  does not fail a grant or exec; `wseq` survives a rotation.
- Leak: L82 (workspace state dir and journal are neither readable nor
  writable from inside a session), L83 (a note whose text looks like a
  command or JSON is stored verbatim and nothing executes), L85 (two
  sessions in one workspace produce one journal with strictly increasing
  `wseq`).

# ADR 0023 — Detached exec lifecycle

Title: An exec that outlives its client, with status, output by offset and
signal, owned by the session supervisor.

Status: Accepted (implemented 0.6.4: `src/execlog.rs`, `src/execquery.rs`,
`src/execcli.rs`, `src/supervisor.rs`, `src/authz.rs`, `src/control.rs`).
Date: 2026-11-22.

## Context

Before 0.6.4 an exec lasted as long as its client connection. A service that
wanted a long-running command had to use `setsid` and background it, which left
no status, no output capture, no seat attribution and no way to stop it, and
the idle timeout could end the session under it. The decisions below were
fixed in the plan (`docs/plans/0.6.4-detached-exec.md`, sections 2 and 7 to 10).

## Decisions

1. **One spawn path.** `exec --detach` goes through the same spawn call, spawn
   gate, Landlock domain, network policy and seat attribution as any exec. The
   supervisor, not the client, builds the descriptors: stdin is `/dev/null`,
   stdout and stderr are pipe write ends. A request with `detach: true` that
   carries descriptors, `tty` or `attach` is refused. A unit test pins the
   number of spawn call sites to one.
2. **Output lives in files, owned by the supervisor.** Per stream a pump thread
   appends to `<workspace>/exec/<incarnation>-e<N>.<stream>`; at 8 MiB the file
   becomes `.1` and a new one starts, so at most 16 MiB per stream are kept.
   Offsets are absolute byte offsets over the stream's life. A read below the
   oldest kept byte starts there and says `rotated_away`. `eof` means: the exec
   is final, this stream's pump saw EOF, and `next == total`. If rotation
   fails the pump keeps appending (the bound can be exceeded, nothing is lost).
3. **Identity is `(incarnation, exec_id)`.** The incarnation is created once per
   supervisor start. `exec-status` and `exec-output` accept an older one and
   read the state file; `exec-signal` accepts the live one only.
4. **Roles.** Owner: everything. Member: status, output of any exec, and signal
   only of an exec started by its own seat. Observer: status only. An unknown
   exec, or one started by the owner, is refused to a member without saying
   whether it exists. The legacy `signal` refuses a detached target.
5. **Protocol.** `PROTOCOL_REVISION` is 4 (supervisor, `session.json`). The
   declared `PROTOCOL_VERSION` stays 3 for every existing command, so their
   request bytes are unchanged; only `--detach` and the three new ops declare
   `DETACH_REVISION` 4. A new supervisor answers `E_UNSUPPORTED` to those from a
   client that declares less; a new CLI against an older session refuses
   locally (exit 125) and sends nothing.
6. **Session stop.** Stop sets a flag, sends TERM, then KILL after 2 s, joins
   the waiters (bounded), journals `exec/exit` with `cause: session-stop` and
   lists the execs in `session/stop.detached_execs_ended`.
7. **Idle.** A running detached exec counts as a running exec: the session is
   not idle while one runs.
8. **Retention.** Files of finished execs are removed when older than the oldest
   journal record, or beyond 256 finished execs. A `running` state file of
   another incarnation is treated as lost only when the supervisor that wrote it
   is dead (pid and start time).
9. **Limit.** 32 live detached execs per session (`E_BUSY`), reserved before
   the spawn and released on every failure path.
10. **Journal cursor index (same release).** `journal --after-wseq` seeks with a
    cache `journal.idx.<inode>`; every use is verified and any doubt falls back
    to the full scan. A corrupt line becomes one `journal/unreadable` record per
    missing `wseq` only when the count matches, so the cursor can move on;
    anything larger stays exit 4.

## Consequences

- `setsid` still works with its old limits; it is no longer the recommendation.
- Output of a finished exec cannot be read when the session has stopped (no
  supervisor); the files stay in the workspace directory.
- Disk bound: 256 finished execs x 2 streams x 16 MiB.

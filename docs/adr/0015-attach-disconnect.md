# ADR 0015 — Attach shells are cancelled on client disconnect unless detached

Title: `hisn attach` follows the exec cancellation model; `--detach` is the explicit opt-out.
Status: accepted. Date: 2026-11-07. Origin: PLAN-0.4 §2.4.

## Decision
- `hisn attach` is an interactive `exec` with `tty: true` and an `attach` flag. It is not a new control op or a new confinement path.
- When the attaching client disconnects, the attach shell gets TERM, then KILL after the exec grace period. This is the existing `exec::drive` behaviour.
- `hisn attach --detach` starts the shell as a detached exec. It is not tied to the connection; its output goes to `attach-<exec_id>.log` (0600, rotated at 1 MiB). It ends with the session, `hisn stop`, the idle lease, or an explicit signal. Re-attaching to a detached exec is out of scope for 0.4.0.
- The session itself survives client disconnect. The lease (ADR 0019) holds it.

## Why
A dropped `ssh` is the normal way a remote seat ends. A shell that outlives it
by default is a silent resource and audit gap. Matching exec keeps one
cancellation model. `--detach` makes a lingering shell an explicit, audited
choice. Users who need a shell that survives an SSH drop can run `tmux` inside
the session, which is an ordinary exec.

## Consequences
- Attach and exec share the cancellation path, so the existing exec leak tests cover the default.
- `--detach` adds a log file under the session dir: it must be 0600 and inside the runtime root (R1).
- Tests: unit `default_attach_is_cancelled_on_disconnect`, `detach_exec_is_not_cancelled_on_disconnect`; leak L55 (default attach shell killed on disconnect; `--detach` survives).

## Superseded in part (PLAN-0.4 §11, round-1 B4)

`--detach` is removed from 0.4.0: a detached attach needs a supervisor-owned
PTY master, a new subsystem. Detached attach is deferred to 0.4.x (O4). In 0.4.0
an attach is an ordinary interactive exec; closing its connection, including
the detach key, cancels it via TERM→KILL. The tmux-survives-drop idea is
unverified and must be tested against `exec::drive` before it is documented.

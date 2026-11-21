# Driving hisn from an external service (0.6.3)

This guide is for a service that hosts hisn sessions for several people and
talks to hisn only through the CLI, for example over non-interactive SSH. It
complements [Driving hisn from a program](sessions.md#driving-hisn-from-a-program)
and [CONTROL-PROTOCOL](CONTROL-PROTOCOL.md). Everything here exists in 0.6.3;
what 0.6.4 will replace is marked.

## Node setup

- **Lingering.** A service user that runs sessions over SSH needs lingering:
  `loginctl enable-linger <user>`. Without it the user's runtime directory and
  user manager go away at the last logout, and the sessions with them.
- **Fixed directories.** Export the same `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`
  in every call. Sessions live under the runtime dir, journals and seats under
  the state dir.
- **State on tmpfs does not survive a reboot.** The runtime directory is tmpfs
  on most hosts. After a reboot the sessions are gone; the workspace journal and
  seats under `XDG_STATE_HOME` remain (on a persistent disk). Reconcile after
  boot with `hisn ls --json` and start again what is wanted.
- The name registry is `/tmp/hisn-<uid>`; it is per user, not per
  `XDG_RUNTIME_DIR`.

## Start, list, stop

```sh
hisn run --detach --json --session-id seat-a --workspace seat-a --network open
# {"schema":"hisn-run/v1","id":"seat-a","name":null,"state":"ready"}
hisn ls --json
hisn stop --session seat-a --json
# {"schema":"hisn-stop/v1","session":"seat-a","outcome":"stopped",...}
```

- `run --detach --json` needs `--detach`. Failure: exit 125 and a
  `hisn-error/v1` object on stderr.
- `ls --json` (`hisn-ls/v2`) only gains keys. 0.6.3 adds `supervisor_pid` (the
  supervisor's own pid, `null` for a session started by an older release or not
  running) and `journal.first_wseq` / `journal.last_wseq`. `pid` stays `null`.
  Use `supervisor_pid` and `started` to reconcile.
- `stop --json` outcomes: `stopped`, `ended-before-stop`, `not-live` (nothing to
  stop; exit 0), and the failures `not-started`, `stopped-unrecorded`,
  `signal-failed`, `timeout` (exit 1, error object on stderr, code
  `E_STOP_<OUTCOME>`).
- `rootfs list --json`: `{"schema":"hisn-rootfs-list/v1","rootfs":[...]}`.
- `seat add|ls|set-role|revoke --json`: `hisn-seat/v1` (`add` carries the
  credential once, in `credential`) and `hisn-seat-list/v1`.
- Without `--json` every command prints exactly what 0.6.2 printed.

## Errors and exit codes

With `--json`, a failure prints one object on stderr:
`{"schema":"hisn-error/v1","code":"E_...","message":"..."}` and exits with the
status the plain command uses (125 for a hisn error). `hisn exec` has no
`--json`.

`exec` and `run`: the command's own status; `128+N` when killed by signal `N`;
125 for a hisn error; 126 when the command could not be executed; 127 when not
found. A program that itself exits 125 to 127 cannot be told apart. For the
exact status of a program use the journal `exec/exit` record (below), which
carries `exit_code` or `signal`, `exec_id`, `pid` (the pid inside the session),
`attach` and `duration_ms`.

`journal` exits 3 when `--after-wseq` is ahead of the journal and 4 when the
records are not contiguous (see "Journal cursor").

## Running commands

Each tool call is `hisn exec --no-tty --session <id> -- <argv>`. The call lasts
as long as the program; killing the `hisn exec` client ends the program (TERM,
then KILL after about 5 s).

**A long-running command until 0.6.4.** Start it detached from the call:

```sh
hisn exec --no-tty --session seat-a -- sh -c \
  'setsid sh -c "echo \$\$ >/work/dev.pid; exec dev-server >/work/dev.log 2>&1" \
     >/dev/null 2>&1 </dev/null &'
```

The process survives the end of the exec call (measured on 0.6.2, probe E11).
The shape is the one probe E11 measured: `setsid`, every descriptor redirected, backgrounded with `&`. The job writes its own pid to a file in the session and its output to a log file; find it again by that pid (`hisn exec ... -- kill -0 <pid>`). There is
no status or output capture; 0.6.4 replaces this with a detached exec that has
both. Two limits:

1. The session's idle timeout can stop the session while only such a job runs:
   idle accounting counts connected clients and live execs, not background
   processes. Do not set `idle_timeout` on a session that runs these jobs.
2. Network records of the reparented process carry no seat (`seat: null`).

## Journal cursor

A caller that shows an activity page polls; there is no follow mode.

```sh
hisn journal --workspace seat-a --info
# {"schema":"hisn-journal-info/v1","first_wseq":1,"last_wseq":4711,"files":2,"bytes":...}
hisn journal --workspace seat-a --after-wseq 4711 --json
```

- `--after-wseq N` returns the records with `wseq > N`, one JSON object per
  line, in order. Combine with `--session`, `--seat`, `--kind`, `--last`;
  the cursor is applied first, so a filter cannot hide a hole.
- Keep the highest `wseq` you received as the cursor. Records are written by
  several processes, so read `wseq` from the records, never count lines.
- Exit 3: `N` is larger than the newest record, so the journal was reset or
  replaced. Restart from `--info`.
- Exit 4: the records after `N` have a hole (expected `wseq` missing). Read once
  more; if it repeats, restart from `--info`.
- Exit 0 with a stderr warning "cursor behind retention": records between `N`
  and the oldest one on disk were deleted by retention. Take what is returned.
- With `--json` the exit 3 and 4 failures print a `hisn-error/v1` object
  (`E_CURSOR_RESET`, `E_CURSOR_GAP`) on stderr.

## Seat credential on stdin

Never put a credential in argv, in the environment of a remote shell or in a
log. Pass it on stdin:

```sh
printf '%s\n' "$TOKEN" | hisn exec --no-tty --seat-token-file - --session seat-a -- cmd
```

- One line is read, byte by byte, at most 4096 bytes; nothing after the newline
  is consumed. A terminal on stdin, an empty line and a non-UTF-8 line are
  refused.
- On `exec`, `-` requires `--no-tty`: the program's stdin is then `/dev/null`,
  so it cannot read anything that followed the credential. `attach` does not
  accept `-`.
- Setting `HISN_SEAT_TOKEN` together with `-` is the existing "both set" error.
- With a credential the journal records carry the seat; without one the
  record's seat is empty.

## Why a session ended

`session/stop` carries `cause` and the status, `session/signal` records a
TERM/INT/HUP that the supervisor itself took (sender unknown).

| `cause` | meaning |
| --- | --- |
| `idle-expired` | the idle timer stopped it |
| `supervisor-signal` | the supervisor took TERM, INT or HUP |
| `stop-request` | `hisn stop` (state `stopping` or `stopped`) |
| `command-signal` | the command was killed by a signal (`signal`, `signal_name`) |
| `command-exit` | the command exited (`exit_code`) |
| `init-lost` | no exit status could be read |

Also `duration_ms` and, when `memory.events` is readable, `oom_kill_delta` (the
OOM kills in the supervisor's cgroup since start; absent when unreadable, and
only meaningful with one cgroup per session). A supervisor killed with SIGKILL
or a host that loses power writes no record; the session then shows as
`crashed` in `ls --json`.

## Open mode

In `network = "open"`, a `bind` on a socket family other than IPv4, IPv6,
AF_UNIX and netlink is refused (0.6.3, ADR 0022 amendment). Loopback works
inside a session; there is no way to reach a port inside a session from the
host (use `hisn exec` per connection).

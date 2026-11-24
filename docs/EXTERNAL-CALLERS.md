# Driving hisn from an external service (0.6.4)

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
  `E_STOP_<OUTCOME>`). A stop that cannot even find the session (unknown name
  or id) exits 125 with the generic code `E_STOP`.
- `rootfs list --json`: `{"schema":"hisn-rootfs-list/v1","rootfs":[...]}`.
- `seat add|ls|set-role|revoke --json`: `hisn-seat/v1` (`add` carries the
  credential once, in `credential`) and `hisn-seat-list/v1`.
- Without `--json` the commands that gained it (`run --detach`, `stop`,
  `seat`, `rootfs list`) print exactly what 0.6.2 printed. The readable
  `hisn journal` output (not `--json`) is different for two record kinds: a
  `session/stop` line now names the cause, `session stopped (command-exit, exit 3)`,
  and a `session/signal` line is new. `journal --json` records only gain keys.

## Errors and exit codes

With `--json`, a failure of `run --detach`, `stop`, `seat`, `rootfs list`,
`ls` and `journal` prints one object on stderr:
`{"schema":"hisn-error/v1","code":"E_...","message":"..."}` and exits with the
status the plain command uses (125 for a hisn error). The codes are `E_RUN`,
`E_START_FAILED`, `E_STOP...`, `E_SEAT`, `E_ROOTFS`, `E_LS`, `E_JOURNAL`,
`E_CURSOR_RESET` and `E_CURSOR_GAP`. `hisn exec` has no `--json`; `inspect
--json`, `list --json` and the other control-socket commands keep printing the
raw `{"ok":false,...}` response on stdout.

`seat --json` may be given before or after the subcommand.

`exec` and `run`: the command's own status; `128+N` when killed by signal `N`;
125 for a hisn error; 126 when the command could not be executed; 127 when not
found. A program that itself exits 125 to 127 cannot be told apart. For the
exact status of a program use the journal `exec/exit` record (below), which
carries `exit_code` or `signal`, `exec_id`, `pid`, `attach` and `duration_ms`.
Only `exec/exit` has `exec_id`, `pid` and `attach`; `exec/request` is written
before the exec is numbered and does not.

`journal` exits 3 when `--after-wseq` is ahead of the journal and 4 when the
records are not contiguous (see "Journal cursor").

## Running commands

Each tool call is `hisn exec --no-tty --session <id> -- <argv>`. The call lasts
as long as the program; killing the `hisn exec` client ends the program (TERM,
then KILL after about 5 s).

**A long-running command: detached exec (0.6.4).** Start it under the
supervisor and come back to it later:

```sh
hisn exec --detach --session seat-a -- dev-server
# {"schema":"hisn-exec-start/v1","exec_id":"e-3","incarnation":"20261122T101500Z-9f3a","pid":41}
hisn exec-status --session seat-a --exec e-3 --json
hisn exec-output --session seat-a --exec e-3 --offset 0          # raw bytes; "next=<n> [rotated_away oldest=<n>] [eof]" on stderr
hisn exec-output --session seat-a --exec e-3 --stream stderr --offset 4096 --json
hisn exec-signal --session seat-a --exec e-3 --signal TERM       # TERM, INT, KILL or HUP
```

- `exec --detach` returns at once and the command survives the client. It runs
  in the same sandbox, with the same network policy and seat, as any exec. Its
  stdin is `/dev/null`; stdout and stderr are captured by the supervisor. It
  cannot be combined with `--tty` or `--no-tty` (the CLI refuses both with a
  usage error, and the supervisor refuses a detached request that carries
  descriptors or asks for a tty): a detached exec has no client stdio by design,
  so there is nothing for `--no-tty`'s pipe relay to copy. At most 32 per session
  (`E_BUSY`).
- The `exec/request` journal record of a detached exec carries `detach: true`
  (plain execs keep the v0.6.3 record shape).
- **Identity** is `(incarnation, exec_id)`. `--incarnation` selects an older
  one for status and output; signalling works on the live one only.
- **Output by offset.** Offsets are absolute byte offsets in the stream.
  Keep `next` and pass it as the next `--offset`. Each stream keeps the last
  16 MiB (two files of 8 MiB). If your offset is older than what is kept the
  read starts at `oldest` and reports `rotated_away: true`. `eof: true` means
  the exec is finished, the pipe is drained and you have read to `total`;
  an empty read with `eof: false` means poll again.
- **Roles.** Owner: everything. Member: read status and output of any exec,
  signal only execs started by its own seat. Observer: status only. A refusal
  is exit 125 with a `hisn-error/v1` object and is journaled
  (`execsignal/refused` and so on).
- **Lifecycle.** The `exec/exit` journal record carries `incarnation`,
  `exec_id`, `seat`, `pid` and `cause` (`exit`, `signal`, `exec-signal`,
  `session-stop`). Stopping the session ends detached execs (TERM, then KILL
  after 2 s) and `session/stop` lists them in `detached_execs_ended`. A running
  detached exec keeps the session from being idle.
- **Retention.** Files of a finished exec are removed when older than the
  oldest journal record or beyond 256 finished execs. After the session has
  stopped there is no supervisor to read output; the files stay in the
  workspace directory.
- The four commands need a session of protocol revision 4 (started by a 0.6.4
  supervisor): older sessions give exit 125 with code `E_UNSUPPORTED`.
  Existing commands are unaffected.
- The legacy `signal` refuses a detached exec: use `exec-signal`.

**`setsid` still works** as before (probe E11: `setsid`, every descriptor
redirected, backgrounded with `&`), with its old limits: no status or output
capture, the idle timeout can stop the session while only such a job runs, and
network records of the reparented process carry no seat (`seat: null`).

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
- Exit 4: the records after `N` have a hole (expected `wseq` missing) that no
  unreadable line explains. Read once more; if it repeats, restart from `--info`.
- Exit 0 with a stderr warning "cursor behind retention": records between `N`
  and the oldest one on disk were deleted by retention (the journal is read
  twice before this is reported, to rule out a rotation in flight). Take what
  is returned.
- Reading is cheap (0.6.4): the reader seeks with a cache
  `journal.idx.<inode>` next to the journal (verified on every use; any doubt
  falls back to a full read) and parses about the records after your cursor.
  Median 114 ms to 3 ms on 100 000 records (test machine). Still no follow
  mode: poll. `--info` scans each file once to count unreadable lines.
- **Unreadable lines.** A line that cannot be parsed no longer blocks the
  cursor. When it explains missing sequence numbers you get one
  `journal/unreadable` record per number (`data`: `file`, `offset`,
  `wseq_from`, `wseq_to`, `count`) and the cursor moves on. `journal --info`
  has an `unreadable` field (count over all files). A hole that no unreadable
  line explains is still exit 4. On this path the stderr "skipped N lines"
  count covers only what was read. Plain `hisn journal` (no cursor) does not
  emit the record.
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
| `command-signal` | the command was killed by a signal: the status is `128+N` (init folds the signal into the exit code, as `hisn run` does), reported with `signal` and `signal_name`; a program that itself exits 129..192 is indistinguishable |
| `command-exit` | the command exited (`exit_code`) |
| `init-lost` | no exit status could be read, or init itself died by a signal |

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

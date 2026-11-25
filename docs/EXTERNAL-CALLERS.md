# Driving hisn from an external service (0.6.5)

This guide is for a service that hosts hisn sessions for several people and
talks to hisn only through the CLI, for example over non-interactive SSH. It
complements [Driving hisn from a program](sessions.md#driving-hisn-from-a-program)
and [CONTROL-PROTOCOL](CONTROL-PROTOCOL.md). Everything here exists in 0.6.3;
what 0.6.4 or 0.6.5 will replace is marked.

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

Request and stdin size limits (0.6.5): a request line over 65536 bytes is
refused before it is sent — exit 125 with a `hisn-error/v1` object (`E_TOO_LARGE`,
naming the limit) on stderr, and the supervisor never sees it. A supervisor
that refuses a request answers with an error reply, not a closed connection.
With `--stdin-limit` feeding a `--no-tty` exec, a stdin over the cap ends the
exec with exit 125 and `E_TOO_LARGE` naming the stdin limit; the journal
records it. It is never silently truncated as if the input had ended.

`journal` exits 3 when `--after-wseq` is ahead of the journal and 4 when the
records are not contiguous (see "Journal cursor").

**Blocking read (0.6.7).** `hisn journal --after-wseq N --wait [SECS]`
blocks until at least one record with `wseq > N` exists, then prints it
like the non-wait path and exits 0. With `SECS` it gives up after that
many seconds and exits 6 (`E_WAIT_TIMEOUT`); without, it waits
indefinitely. If the session ends while waiting and no matching record
arrived, it exits 7 (`E_WAIT_SESSION_ENDED`); a matching record arriving
in the same batch as the stop still exits 0. Exit 4 keeps meaning a real
gap (reported immediately, never waited on); exit 5 is unused and reserved.
Works with `--json` and `--session`. Wake is inotify on the journal file
and directory with a bounded 1 s poll fallback; the wait holds no session
lock and survives journal rotation. A stop record with `wseq <= N`, a
supervisor killed outright, or a failed stop append cannot be detected
from the journal alone — in those cases the wait ends by its timeout.

## Running commands

Each tool call is `hisn exec --no-tty --session <id> -- <argv>`. The call lasts
as long as the program; killing the `hisn exec` client ends the program (TERM,
then KILL after about 5 s).

**Passing stdin (0.6.5).** By default an `--no-tty` exec's stdin is `/dev/null`
(the 0.6.4 behaviour, unchanged). Add `--stdin-limit BYTES` (1..=1073741824)
and the caller's stdin is passed through a capped relay: the command sees the
bytes, and exactly the cap is delivered when the input exceeds it. Without
`--stdin-limit`, a terminal on fd 0 is never read. With
`--seat-token-file -`, the first line is the credential and the cap counts
only the rest. Detached execs always keep stdin at `/dev/null`. Side effect:
when the cap is hit, the program sees EOF after the cap bytes and may commit
before the client replaces its exit with 125.

```sh
printf 'dx16-hello' | hisn exec --no-tty --stdin-limit 1048576 --session seat-a -- cat
```

When the cap is hit, the program sees EOF after the cap bytes and may commit
before the client replaces its exit with 125. If the program closes stdin
early, that is a normal end when the reader is already gone at write time
(the relay stops feeding stdin); if the cap trips while the pipe still
accepts the bytes, the cap hit stands.

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
  so it cannot read anything that followed the credential (without
  `--stdin-limit`; with it, the rest is passed through a capped relay).
  `attach` does not accept `-`.
- Setting `HISN_SEAT_TOKEN` together with `-` is the existing "both set" error.
- With a credential the journal records carry the seat; without one the
  record's seat is empty.

## Capabilities and profile validation (0.6.5)

```sh
hisn capabilities --json
# {"schema":"hisn-capabilities/v1","version":"0.6.5","protocol_revision":4,
#  "declared_protocol_version":3,
#  "features":[{"name":"detached-exec","available":true}, ...]}
hisn profile validate --json ./hisn.toml
# {"schema":"hisn-profile-validation/v1","ok":false,"errors":[{"path":"session.hostname",
#   "code":"E_PROFILE_VALUE","message":"session.hostname: ..."}],"warnings":[]}
```

- `capabilities` works without a running session and always exits 0 when the
  report is produced. The feature names are public API and pinned by a
  test: the 11 originals `detached-exec`, `journal-cursor`, `journal-unreadable`,
  `exec-stdin`, `seat-credential-stdin`, `network-none`, `network-host`,
  `network-open`, `rootfs`, `ssh-agent`, `services`, plus 0.6.7's
  `journal-wait` and `caller-agent-socket` (appended after, order of the
  original 11 unchanged). When `available` is false, `reason`
  carries the detail from the same check `hisn check` runs (for example open
  mode on a kernel without the needed Landlock ABI). Features derived from
  the binary itself (`detached-exec`, `journal-*`, `exec-stdin`,
  `seat-credential-stdin`, `ssh-agent`, `services`,
  `caller-agent-socket`) report `available: true`:
  the code paths exist in this binary, but an older running supervisor may
  still refuse them (for example `detached-exec` needs protocol revision 4).
  `protocol_revision` is what the supervisor speaks; `declared_protocol_version`
  is what existing commands declare (3, unchanged since 0.6.3).
- `profile validate --json` (0.6.7) reports **all** post-parse errors in
  deterministic, dedup'd order (version, policy, every surface table,
  resolve/plan); a TOML parse failure stops with exactly one error. The
  text path stays fail-fast. `path` is the dotted TOML key path
  when the validation layer knows it (`session.network`,
  `services[1].ready.socket`); omitted when unknown, never empty. `line` and
  `column` are 1-based and present when the TOML deserializer knows them.
  `code` is `E_PROFILE_PARSE` (syntax, type or unknown-key errors) or
  `E_PROFILE_VALUE` (validation failures and resolve/plan failures).
  `warnings` is reserved (`[]` today). Text output without `--json` is
  byte-identical to earlier releases.

## Caller-provided ssh-agent socket (0.6.7)

`hisn run --ssh-agent-socket PATH` (profile: `[ssh] socket = PATH`, the CLI
flag winning when both are set) hands the session's ssh-agent proxy a
caller-chosen upstream instead of the host's `SSH_AUTH_SOCK`. Default off:
with neither set the upstream is `SSH_AUTH_SOCK` exactly as before. The
flag without `[ssh] agent = true` is an error, and the path must be
absolute. The resolved upstream is read once at session start and checked
with the existing socket-is-a-socket check (whose error text now names the
path actually checked).

Every sign request journals one `ssh/sign` record through the bounded
network queue: `fingerprint` (the `SHA256:…` key fingerprint, or null for
an unparseable envelope), `seat`, `attributed` (the explicit marker — null
seat alone does not distinguish the main command from an unattributed
client), `exec_id` (`e-<n>` or null), and `result` (`ok`, `refused`, or
`error`). The record never carries the data being signed, the signature,
or the key blob. Over-rate signs fold into one `ssh/sign-summary` per
affected second, like `network/summary`.

Attribution reuses the network records' `/proc` ancestry walk from the
accepted connection's peer pid, resolved at accept: an attributed exec
signs as its seat (owner/member allowed, observer refused with
`SSH_AGENT_FAILURE` and a `refused` record), the main command signs as
owner, and an orphan, reparented-to-init, over-deep, or unreadable client
is refused with `attributed: false`. The walk is racy against pid reuse —
a client that exits and whose pid is recycled between accept and walk
could be misattributed; the role is re-checked per sign, and a pidfd
(`SO_PEERPIDFD`) hardening is deferred. Identity listing (type 11) stays
ungated; add/remove/lock keep today's tracing-only logging, and refused
non-sign message types are not journaled.

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

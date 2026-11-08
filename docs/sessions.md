# Sessions and lifecycle (0.4.1)

This page describes one hisn session from creation to removal. It collects
what DESIGN §9, §20 and §20.1 and the code say in one place. Where they
differ, the code wins; the file and line references are in `src/session.rs`,
`src/sessionmeta.rs`, `src/supervisor.rs`, `src/lifecycle.rs`,
`src/control.rs`, `src/authz.rs` and `src/main.rs`.

## Names and ids

`hisn run` gives every session an id (random, or `--session-id`). `--name`
adds a human name, unique per user (letters, digits, `.`, `_`, `-`, no leading
`.`). Every `--session` argument accepts a name or an id. The name index is
`names.json` (with `names.lock`) in the per-user root `/tmp/hisn-$UID`; it is
authoritative, and a fallback scan repairs it (ADR 0014).

## The session directory

`$XDG_RUNTIME_DIR/hisn/<id>`, falling back to `/tmp/hisn-$UID/<id>`; mode 0700.

| File | Content |
|---|---|
| `control.sock` | the control socket (0600) |
| `session.json` | session metadata, schema `hisn-session/v1` (below) |
| `supervisor.pid` | `<pid> <starttime>` followed by a newline (0600) |
| `grants.jsonl` | the append-only audit log, one JSON object per line (0600) |
| `policy.resolved.toml` | the resolved policy that `hisn inspect` prints |
| `risk.json` | the risk labels of the profile capabilities |
| `supervisor.log` | stdout and stderr of a detached supervisor (0600), `--detach` only |

`supervisor.pid` holds the supervisor's pid and its start time in clock ticks
from `/proc/<pid>/stat`, separated by one space. Stale detection compares both,
so a recycled pid is not mistaken for the supervisor.

## States

`session.json` carries `state`, one of `creating`, `running`, `stopping`,
`stopped`, `crashed`.

| State | Meaning |
|---|---|
| `creating` | the directory exists as `.tmp-<id>` before it is renamed into place |
| `running` | a live supervisor owns the session |
| `stopping` | `hisn stop` or idle expiry has signalled the session and has not yet seen it exit |
| `stopped` | the session ended through `hisn stop` or idle expiry; the directory is kept |
| `crashed` | the directory is present, the supervisor is gone, and the state is not `stopped` |

`hisn ls` derives the displayed state: `running` when the control socket
accepts a connection; otherwise `stopped` or `creating` as recorded, and
`crashed` for anything else. A session is stale when its control socket
refuses connections and its supervisor is gone (checked twice, 300 ms apart).

```mermaid
stateDiagram-v2
    [*] --> creating
    creating --> running: ready
    running --> stopping: hisn stop / idle expiry
    stopping --> stopped: exit observed
    running --> crashed: supervisor dies
    stopped --> [*]: ls --prune
    crashed --> [*]: ls --prune
```

## session.json

| Field | Content |
|---|---|
| `schema` | `hisn-session/v1` |
| `id`, `name` | the session id; the name or `null` |
| `owner` | `uid`, `label`, `client_id` of the creating client |
| `created` | `ts` (RFC 3339) and `by` |
| `cwd`, `rootfs`, `network` | working directory, rootfs name or `null`, network mode |
| `state` | see above |
| `members` | append-only list of clients seen: `uid`, `label`, `first_seen`, `last_seen`; omitted when empty |
| `lease` | `idle_timeout_s` and `last_activity`; omitted when the session has no lease |
| `env_declared` | the session env snapshot (`--env`, `--env-file`); values that look secret are stored as `<redacted>`; omitted when empty |

## Creating

`hisn run [--name N] [--detach] [-- CMD...]` resolves the policy or profile,
creates the directory, and becomes the supervisor. Without `--detach` the
process stays in the foreground and exits with the command's status. A start
failure exits 125. `hisn run --detach` is described under
[The run --detach contract](#the-run---detach-contract).

`--env K=V` and `--env-file PATH` declare the session env snapshot. Precedence
per exec or attach: the scrubbed base, then the declared values, then computed
names (`HOME`, `USER`, `LOGNAME` and cache variables). A request that names a
declared key is refused with `E_ENV_LOCKED`. Use `--env-file` for secret-shaped
values so they stay out of `/proc/<pid>/cmdline`.

## Running

- `hisn exec --session S -- CMD...` runs a command in the session's namespaces
  with the same confinement as the original command. `--tty` or `--no-tty`
  selects the stdio mode.
- `hisn attach --session S` starts the session's shell (`$SHELL` from the env
  snapshot, else `/bin/sh`) in the session cwd on a pty. Several attaches are
  peers in one pid namespace. The detach key is Ctrl-] then `d`; the shell is
  killed when the client disconnects.
- `hisn grant`, `hisn revoke`, `hisn inspect` and `hisn kill` use the same
  control socket.

Known issue: `ttyname()` fails inside an attach. See DESIGN §20.1 and the
[roadmap](ROADMAP.md).

## Clients, observers and the client record

Every control request carries a client record. The supervisor fills `uid` and
`pid` from `SO_PEERCRED`; the client cannot supply them, and a request whose
`client` object contains `uid` is refused. The client supplies a `label`
(`--client`, else `<login>@<ip>` from the SSH environment, else `local`), a
`label_source` and an optional `req_id`. The supervisor adds a sequence number.
Every audit line carries `client`, `seq` and `authz`.

One function, `authz::authorize`, gates every operation. In 0.4.1 it allows a
request when the client uid equals the session owner's uid, and refuses
otherwise.

A **client** is a control connection that has sent at least one admitted
request: an authorized exec, attach, grant, revoke, signal, kill or stop. An
**observer** is a connection that only sends `list`, `inspect` or
`sessioninfo`. Observers and bare connect-and-close probes (the readiness
check, the liveness check in `is_stale`) are never listed in `clients`, never
create a member, and never touch the lease or the idle clock, on the request or
on disconnect. A refused request does not make its connection a client. A
connection leaves `clients` when it closes.

## Leases and idle expiry

`[session] idle_timeout` in the policy is a duration string; the default is
none, meaning the session never expires. `last_activity` is updated on
admitted requests, at most every 10 s. A session is idle when all of these
hold: no connected client, no running exec, and the timeout has elapsed since
the later of the last admitted request and the last client disconnect (the
session start counts as activity). The session's main command does not count as
activity, so set `idle_timeout` only on sessions whose main command is a
keeper, such as `--detach` sessions.

On expiry the audit gets a line with `op:"lease"`, `stage:"expired"` and
`result:"idle"`, and the session stops through the same function as
`hisn stop`. A foreground `hisn run` prints
`hisn: session <name|id> stopped: idle for <d> (idle_timeout <d>)` on stderr
and exits 143. `hisn ls` shows the timeout in the LEASE column.

## Stopping

`hisn stop --session S` and idle expiry share `lifecycle::stop_and_keep`:
state `stopping`, SIGTERM to the session, wait for the exit, state `stopped`.
The wait blocks on a pidfd of the supervisor when one can be opened; only the
no-pidfd fallback polls, with bounded exponential backoff. The directory and
the name are kept.

| Case | Output | Exit |
|---|---|---|
| stopped | `session S stopped` | 0 |
| already stopped | `session S: already stopped` | 0 |
| crashed, no supervisor | `session S: crashed, no supervisor` | 0 |
| stop could not be recorded or signalled | an error line | 1 |

`hisn kill` sends a signal to the sandbox of a live session and, on a stale
session, removes the directory.

## Pruning and archival

`hisn ls --prune` removes stopped and crashed session directories.

- `--name-prefix P` restricts it to sessions whose name starts with `P`. An
  unnamed session never matches.
- `--dry-run` lists what would be pruned and removes nothing.
- Before removal, hisn archives `grants.jsonl` and the final `session.json` to
  `$XDG_STATE_HOME/hisn/audit/<id>.jsonl` (default `~/.local/state/hisn/audit/`;
  directory 0700, file 0600). Each line is `{"source":"grants","line":...}` or
  `{"source":"session","line":...}`. If archiving fails the session is not
  removed.
- `--purge` removes without archiving.
- Removal is fd-relative and confined to the one directory: a planted symlink
  is unlinked, not followed, and a planted bind mount is not entered.
- A removed session's name becomes reusable, and the name index is repaired.

## The run --detach contract

`hisn run --detach` starts a session with no command of its own and returns
when it is ready.

1. The parent forks a supervisor child that calls `setsid`, closes every
   inherited descriptor except the ready pipe, and moves stdout and stderr to
   `<session-dir>/supervisor.log` (0600). RISK lines are printed by the parent
   before the fork.
2. The parent waits until the control socket accepts connections. The wait is
   event-driven: a nonblocking connect, re-probed with exponential backoff from
   1 ms to 20 ms.
3. On success the parent prints one line on stdout and exits 0:

   ```
   <id> <name|-> ready
   ```

   `<name|->` is the `--name` value, or `-` for an unnamed session.
4. On failure the parent prints the supervisor's first error lines on stderr
   and exits 125. A start failure exits 125 with or without `--detach`.

`--ready-fd N` additionally writes `ready\n` to descriptor `N` and closes it;
it works with and without `--detach`. On a failed start nothing is written.

## Driving hisn from a program

This is the one place the programmatic contract is described; the README and
[WAKIL-INTEGRATION](WAKIL-INTEGRATION.md) link here.

- **Start.** `hisn run --name N --detach`; parse `<id> <name|-> ready` from
  stdout. Exit 0 means ready, 125 means the start failed.
- **Exit codes.** For `run` and `exec`: the command's own status; `128+N` when
  killed by signal `N`; `125` for a hisn error (policy, host, refused request,
  failed start); `126` when the command could not be executed; `127` when it
  was not found. A command that itself exits 125 to 127 cannot be told apart
  from these. `hisn run` exits 143 on idle expiry. `hisn stop` exits 0 for
  stopped, already stopped and crashed sessions.
- **List.** `hisn ls --json` prints `{"schema":"hisn-ls/v2","sessions":[...]}`.
  Fields are only added, never removed or renamed. Each session has `id`,
  `dir`, `state`, `name`, `cwd`, `hostname`, `network`, `rootfs`, `pid`,
  `started`, `execs`, `services`, `clients`, `members` and `lease`. `clients`
  entries have `uid`, `pid`, `label`, `label_source` and `connected_since`; a
  live attach appears in `execs` with `attach: true`. For a stopped or crashed
  session `clients` is `[]`.
- **sessioninfo.** The control op `{"op":"sessioninfo"}` returns
  `{"ok":true,"clients":[...],"execs":[...],"services":[...]}`, the live view
  that `session.json` cannot hold. `hisn ls --json` calls it for each running
  session. If the call fails, `ls` shows empty `clients`, `execs` and
  `services` for that session and does not fail. A request with `sessioninfo`
  is an observer: it does not count as a client and does not keep the session
  alive.
- **Control socket.** `<session-dir>/control.sock`, one JSON object per line.
  The protocol is in [POLICY-SPEC §7](POLICY-SPEC.md).
- **Stop and clean up.** `hisn stop --session N`, then
  `hisn ls --prune --name-prefix <prefix>` to archive and remove only your own
  sessions.
- **Secrets.** Pass them with `--env-file`, not `--env`.

Wakil is the reference driver; its usage is in [WAKIL-INTEGRATION](WAKIL-INTEGRATION.md).

# caj readiness: what hisn must change so an external service can drive it

Analysed commit: `06a2d1dc479f8c4fe1a401bdf7559c245122b381` (tag `v0.6.2`;
`main` points at the same commit). Everything below was read with
`git show v0.6.2:<file>` / `git grep v0.6.2`; nothing was run against a live
session. Line numbers refer to that commit. Anything that only a running
system can settle is marked **UNVERIFIED** and has a probe id in
`scripts/caj-probe.sh` (run once by the maintainer on the host).

caj in one paragraph (given, not verified here): a separate Go service that
reaches one Unix service user per node over non-interactive SSH, runs one hisn
session per person, implements agent tool calls as `hisn exec --no-tty`,
shows activity from the journal, reconciles against `hisn ls --json`, uses
network mode `open`, runs MongoDB as a `[[services]]` entry, and will wrap
`hisn run --detach` in `systemd-run --user --scope`.

## 1. Summary table

| # | Topic | Status | Gap for caj |
|---|-------|--------|-------------|
| A1 | Journal reading | verified from code | yes: no cursor, no follow |
| A2 | Exec lifetime | verified from code; kill timing UNVERIFIED (E7-E9) | yes: no detached exec, no status by exec_id |
| A3 | Loopback | code and leak tests verified; runtime UNVERIFIED (L1-L6) | no (see leftovers a-c for the notify engine) |
| A4 | Machine interface | verified from code | yes: JSON missing for most commands, errors are text |
| A5 | Services | verified from code | later/soon: no restart, no log capture |
| A6 | Inbound | verified from code (absence search not exhaustive) | later: design only |
| A7 | Seat attribution | verified from code | yes: no stdin credential path for SSH |
| A8 | systemd scope | code reading; behaviour UNVERIFIED (C1-C6) | no code conflict found |
| A9 | Lifetime | code verified; survival UNVERIFIED (D5-D8) | yes: `pid` is always null in `ls --json` |
| A10 | Many sessions | verified from code | soon: fixed `/tmp/hisn-<uid>` registry root |
| A11 | Shell death | verified from code | yes: stop record has no cause, status or signal |

## 2. Findings

### A1 Journal reading
- CLI: `hisn journal [--workspace W] [--session S] [--seat NAME] [--kind K]
  [--since TS] [--last N] [--json]` (`src/cli.rs` `JournalArgs`). Dispatch
  `src/main.rs` `journal_cmd`. There is **no** follow, tail, cursor or
  "after wseq" option.
- `--json` prints the raw records unchanged, one compact JSON object per line
  (`journal_cmd`, `serde_json::to_string` per record). Default output is
  collapsed text (`journal.rs` `query_readable`, `render_group`), not stable
  for machines.
- Filters (`journal.rs` `Query`): `session` exact; `seat` matches `data.seat`,
  else `client.seat`, else `client.label`; `kind` exact in JSON mode (readable
  mode expands `exec` to the exec family); `--since` is `>=` and accepts
  RFC 3339 with `Z` only, anything else is an error (`journal_cmd`);
  `--last N` keeps the newest N after filtering.
- Record: `{v:1, ts, wseq, session, kind, client?:{uid,label,label_source,
  req_id,seat?,role?}, data}` (`journal.rs` `JournalRecord`; ADR 0020). One
  file per workspace: `$XDG_STATE_HOME/hisn/workspaces/<id>/journal.jsonl`
  (`workspace.rs` `workspace_dir_with`, `state_home_with`).
- Writers: exclusive `flock` on `journal.lock`, `wseq` assigned from the file
  tail under the lock, one `write` on an `O_APPEND` fd. Rotation after 64 MiB
  (`ROTATE_AFTER`) renames to `journal.<n>.jsonl`; after a rotation, if more
  than 4 files and over 256 MiB, the oldest rotated files are deleted
  (`MAX_JOURNAL_FILES`, `JOURNAL_RETENTION_BYTES`) and one `journal/pruned`
  record is written. No hash chain; deleting files externally can reuse
  `wseq` (module docs).
- Reader: `journal::read_records` takes a shared lock (about 1 s best effort),
  pins file descriptors, then reads unlocked: exactly-once across rotation for
  hisn's own reader. An external tail of the raw file would have to handle
  rotation itself. UNVERIFIED under load: probe J8 (150 notes written while
  six reads run; every line must parse).
- **Gap:** caj needs "records after the last wseq I processed", repeatably,
  and a stable machine format. Today it can only re-read with `--since`
  (timestamp, `>=`, so duplicates) or `--last`.

### A2 Exec lifetime
- Control ops are the `Request` enum in `src/control.rs` (`exec`, `signal`,
  `sessioninfo`, `note`, seat ops, grant, revoke, list, inspect, kill). No
  detach or background op, no status op, no output retrieval.
- Client closes or is killed: the supervisor polls the client connection;
  on `POLLRDHUP` it sends TERM to the program's process group and KILL after
  `CANCEL_GRACE` = 5 s (`exec.rs` `drive_from_with_flag`; monitor
  `exec.rs` `monitor`: EOF on the status socket means SIGKILL to the group).
  So a normal exec's process group does not outlive its client (a program
  that left the group with `setsid` is not covered, see E11). UNVERIFIED live: E7 (kill -9 on the
  client), E9 (a process that ignores TERM; the code says KILL after 5 s).
- The client forwards SIGTERM/SIGINT/SIGHUP by `exec_id` over a second
  connection (`execcli.rs` `relay`, `supervisor.rs` `do_signal`).
- `exec_id` (`e-N`) exists only in the started reply (`supervisor.rs`
  `do_exec`), the client does not print it, and it is removed from the table
  when the exec ends. `ls --json` reports live execs as
  `execs[]={exec_id,pid,argv0,tty,attach}` (`supervisor.rs` `session_info`);
  finished execs survive only as journal records `exec/request` (argv, cwd)
  and `exec/exit` (`exit_code` or `signal`, `duration_ms`, `cancelled`,
  `lost`; `supervisor.rs` `exit_record_data`). The journal records carry
  `seq`, not `exec_id`.
- Exit status of `hisn exec`: the program's code; 128+N for signal N; Lost =
  125; unknown program = 127 (`E_EXEC` with "No such file"), other `E_EXEC` =
  126, everything else 125 (`execcli.rs` `exit_code`, `relay`).
- `--no-tty`: stdin is `/dev/null`, stdout and stderr are pipes the client
  copies (`execcli.rs` `run`, `pump_pipes`).
- In-session workaround: a program can `setsid` and background itself inside
  one exec; whether it survives the end of the exec is UNVERIFIED (probe E11).
  Even if it does, caj gets no exit status and no output.
- **Gap (blocks milestone 1):** long-running commands need a start-and-return
  mode with exit status and output retrievable later by `exec_id`.

### A3 Loopback
- `lo` is brought up for every network mode except `host`
  (`init.rs` `loopback_up`, called under `if network != Host`;
  `supervisor.rs` `start_namespaces` gives `none` and `open` their own netns).
- In-session listen and connect on 127.0.0.1 and ::1 are covered by the leak
  suite (`tests/leak/net_helper.py` `in_loopback`, `in_parity_loopback`).
  Runtime on this host is UNVERIFIED until probes L1-L4 run.
- Open mode: seccomp user-notify on connect, bind, listen
  (`notif.rs` `connect_filter`). A loopback connect is classified
  `ConnectLoopbackInet` (`classify_connect`, `is_loopback()` for v4 and v6)
  and executed by the supervisor on its own reference to the sandbox socket
  (`verdict_table`: `SupervisorExecuted`; `exec_sandbox_connect`). So
  127.0.0.0/8 and ::1 stay inside the session netns; the host loopback is
  separate (probes L5, L6 must refuse).
- AF_UNIX connect on a sandbox socket is continued to the kernel
  (`ConnectUnix`, `KernelContinued`).
- **No gap for caj.** The three leftovers found while reading this code are
  in section 5 (L-a, L-b, L-c); each was re-checked at `v0.6.2`.

### A4 Machine interface (v0.6.2)

| Command | JSON on stdout | Exit codes | Error format |
|---------|----------------|-----------|--------------|
| `run --detach` | no; prints `<id> <name\|-> ready` | 0 ready; 125 start failed (`supervisor.rs` `run_detached`) | text on stderr |
| `stop` | no | 0 stopped / already stopped / crashed / stale; 1 for NotStarted, StoppedUnrecorded, SignalFailed, Timeout (`main.rs`, `Command::Stop`) | text on stderr |
| `exec` | no | program status; 128+N; 127 / 126 / 125 as in A2 | text on stderr |
| `ls --json` | yes: `{"schema":"hisn-ls/v2","sessions":[...]}` | 0; errors 125 | text |
| `ls --session S --json` | raw control response | 0 if ok else 1 | JSON `{ok:false,...}` on stdout |
| `inspect --json` | raw control response | 0 / 1 | as above |
| `seat add/ls/set-role/revoke` | no (add prints the credential alone on stdout and a warning on stderr; ls is TSV) | 0; errors 125 | text |
| `journal --json` | yes, JSON lines | 0; bad `--since` 125 | text |
| `note` | prints the control response (JSON) | 0 / 1; revision < 2: 2 | text / JSON |
| `check --json` | yes (pretty) | 0 ok, 2 not ok | n/a |
| `rootfs list` | no (names, one per line) | 0 | text |
| `profile validate` | no (prints resolved TOML) | 0 | text |

- `main` maps every `Err` to `hisn: <error>` on stderr and exit 125
  (`src/main.rs` `main`). There is no structured error object.
- Documented exit codes: `docs/sessions.md` ("Driving hisn from a program").
  A program that itself exits 125-127 is indistinguishable from hisn errors.
- `ls --json` fields per session (`main.rs` `session_v2_json`): `id, dir,
  state, cwd, hostname, network, name, rootfs, hisn_version,
  protocol_revision, workspace{id,name}, journal{dir,files,bytes}, pid,
  started, journal_failures, seats[], execs[], services[], clients[],
  members[], lease`. `pid` is **always null** (`session_v2_json`:
  `"pid": Value::Null`); `started` is `session.json` `created.ts`;
  `last_activity` exists only inside `lease` and only when an idle timeout is
  configured (`sessionmeta.rs` `Lease`).
- State words: `running`, `stopped`, `creating`, `crashed`
  (`main.rs` `session_state_label`).
- **Gap:** no JSON for `run --detach`, `stop`, `seat *`, `rootfs list`;
  no structured error; `pid` null; `stop` failure causes share exit code 1.

### A5 Services
- `[[services]]` keys, `deny_unknown_fields` (`profile.rs` `Service`):
  `name`, `exec` (argv list), `socket`, `ready`, `stop`, `restart`.
- `ready` accepts only `socket` (a path the supervisor can `stat`, so under
  cwd or a ro/rw mount, not on private tmpfs) and `timeout` (default 15 s,
  max 86400); `ready.command` and `ready.tcp` are rejected
  (`ServiceReadinessSpec`; tests `services_ready_tcp/command_rejected`).
- `stop = {signal, grace}` (default TERM, 5 s). `restart` accepts only
  `"none"` (`validate_surface`; test `services_restart_not_none_rejected`).
  `services.rs` starts each service once and never supervises it.
- Service stdin, stdout, stderr are `/dev/null` (`services.rs`
  `start_in_sandbox_service`). Output must be directed by the service itself.
- MongoDB as a service is possible if its data directory and unix socket are
  on a persistent writable path. Persistent paths: `[home] persist`
  (mounted at `/run/hisn/home`, `mounts.rs`), the session cwd (rw bind),
  `mounts.rw`, grants. `/tmp`, `/run` and a tmpfs `$HOME` are ephemeral.
  Readiness works only if the socket is under cwd or a mount.
- Gap (needed soon): a crashed mongod is not restarted and leaves no log;
  caj must probe it through exec. Not a first-milestone blocker.

### A6 Inbound
- `none` and `open` sessions run in a private netns created with
  `CLONE_NEWNET` (`supervisor.rs` `start_namespaces`); `open` additionally
  asserts the namespace differs (`check_netns_differs`). A TCP listener in
  a session is invisible to the host. I found no port-forward or TCP listener
  code in `src`; the search was not exhaustive (UNVERIFIED, probe L7 checks
  host listeners). `network = "host"` shares the host netns and is out of
  scope.
- Options and ADR outline are in section 7.

### A7 Seat attribution
- Credential per call: `HISN_SEAT_TOKEN` or `--seat-token-file PATH`, never an
  argv value; both set is an error; empty is an error
  (`execcli.rs` `seat_token`). It travels as `client.seat_token` in the control
  request and is refused client-side for sessions below protocol revision 3
  (`seat_material`).
- Verification: `seats::verify` (SHA-256 hex compared in constant time against
  `seats.json`, 0600); revoked/expired/unknown are refusals and never fall
  back to owner (`authz.rs` `authorize`). Roles: owner all ops; member exec,
  signal, note, list, inspect, sessioninfo; observer list, inspect,
  sessioninfo only (`authz.rs` `allows`).
- Journal: with a valid credential the record has `client.seat` and
  `client.role`; without one, `client` is `{uid,label,label_source,req_id}`
  and a same-uid caller is the owner (`authz.rs` decision B;
  `supervisor.rs` `journal_client`). Where the label comes from when no
  `--client` is given is UNVERIFIED (the doc comment says SSH environment,
  else `local`; I found no `SSH_CONNECTION` read in `src`): probe T4 prints
  the record.
- The token is not copied into the client record, journal or audit log
  (`control.rs` `ClientField` docs). Probes T5 (journal files) and T6 (argv)
  check this at runtime.
- Over non-interactive SSH the two inputs are poor: an env var is only
  forwarded if the node's sshd accepts it, and a token placed in the remote
  command string is visible in the remote shell's argv; a token file must
  exist on the node. **Gap:** no way to read the credential from stdin.
  Same-uid processes can read `/proc/<pid>/environ` of the client (probe T7),
  which is inherent to the single-uid model (ADR 0021).

### A8 systemd scope
- No cgroup, systemd or DBus code; no `PR_SET_CHILD_SUBREAPER`; no `setpgid`
  (`git grep` found none). Only `check.rs` probes for cgroup v2.
- Detach: fork, `setsid`, close descriptors, redirect stdout/stderr to
  `<session-dir>/supervisor.log` (`supervisor.rs` `run_detached`,
  `redirect_stdio_to_log`). `setsid` does not change the cgroup, so the
  detached supervisor and everything below it stay in the scope's cgroup and
  die with it when the scope is stopped. That is the wanted behaviour.
- Namespaces: `unshare(NEWUSER|NEWNS)` then `clone(NEWUSER|NEWNS|NEWPID|
  NEWIPC|NEWUTS[|NEWNET])` (`start_namespaces`): needs unprivileged user
  namespaces, independent of systemd.
- pidfd use (`InitTarget`, `sys.rs`, `main.rs` stop): pid-reuse safe, no scope
  interaction. `PR_SET_PDEATHSIG` is set only for the sandbox init and exec
  helpers, not for the detached supervisor.
- No conflict found by reading. Runtime: probes C1-C6 (start inside
  `systemd-run --user --scope -p MemoryMax=512M -p TasksMax=256`, cgroup of
  the supervisor, `memory.max`, exec, stop). Skipped when no user manager.

### A9 Lifetime
- `run --detach`: the parent forks; the child calls `setsid`, closes all
  descriptors but the ready pipe, reopens 0-2 on `/dev/null`, then sends
  stdout/stderr to `supervisor.log`. The parent waits for one ready line,
  prints `<id> <name|-> ready` and returns 0 without waiting
  (`supervisor.rs` `run_detached`, `report_ready`). With no controlling
  terminal there is no SIGHUP on SSH close by construction.
  UNVERIFIED live: D5 (parent shell exits), D6 (real ssh to localhost, only if
  key auth works), D7 (session id and tty of the supervisor).
- Reconcile fields in `ls --json`: `id`, `state`, `started`, `protocol_revision`,
  `workspace.id`, `clients[]`, `execs[]`, `lease` (idle only). `pid` is null.
  The supervisor pid is in `<session-dir>/supervisor.pid` (`supervisor.rs`
  `write_supervisor_pid`); liveness is "control socket accepts"
  (`session.rs` `is_live`).
- After a host reboot: session dirs live under `$XDG_RUNTIME_DIR/hisn` or
  `/tmp/hisn-<uid>` (`session.rs` `runtime_roots`), both normally tmpfs, so
  they disappear; workspace state (journal, seats) survives in
  `$XDG_STATE_HOME`. Whether this host's `/tmp` and runtime dir are tmpfs is
  UNVERIFIED (probe P3). A stale dir (no supervisor) shows as `crashed`;
  `hisn stop` removes it, `hisn ls --prune` archives and removes
  (`main.rs`).
- Risk: without `loginctl enable-linger`, systemd removes
  `/run/user/<uid>` at the last logout and the control sockets of detached
  sessions vanish with it. caj's node setup must enable linger (probe P2).
- **Gap:** `pid` null; no machine-readable "last activity" without an idle
  timeout (caj can use the journal tail instead).

### A10 Many sessions under one user
- Runtime: `$XDG_RUNTIME_DIR/hisn/<id>/` when `XDG_RUNTIME_DIR` is absolute,
  else `/tmp/hisn-<uid>/<id>/`. `ls` scans both roots (`session.rs`
  `runtime_roots`, `list_sessions`). The name registry (`names.json`,
  `names.lock`) is fixed at `/tmp/hisn-<uid>` for every user
  (`registry.rs` `registry_root`). Isolating a test run therefore needs
  both `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`, and still shares the registry
  when `--name` is used. The probe script never uses `--name`.
- Ids: `[A-Za-z0-9._-]{1,64}`, no leading `.` (`policy.rs`
  `is_valid_session_id`); a duplicate id is `SessionError::Exists`. caj should
  choose the id itself (`--session-id`), which also makes start idempotent.
- State: `$XDG_STATE_HOME/hisn/workspaces/<id>/` holds `journal*.jsonl`,
  `journal.lock`, `seats.json`; the workspace id is derived from the canonical
  cwd or from `--workspace NAME` (`workspace.rs`). One workspace per person
  gives one journal and one seat store per person.
- Persistent home: `[home] persist` / `--home-persist PATH` (absolute), a
  distinct path per session; mounted at `/run/hisn/home` (`mounts.rs`).
- Gap (needed soon): the registry root is fixed at `/tmp/hisn-<uid>` and does
  not follow `XDG_RUNTIME_DIR`. All `hisn` invocations by caj must pass the same
  `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`; a call made with `XDG_RUNTIME_DIR`
  unset sees only `/tmp/hisn-<uid>`.

### A11 Shell death
- Detached session: PID 1 only reaps (`init.rs` `supervise_detached`); it ends
  on TERM/INT/HUP. Foreground session: `init.rs` `supervise` returns the
  command's status through `decode_status` (`128+sig` for a signal, code
  otherwise, 125 for anything else); the supervisor's `relay_and_wait` reads
  it with `waitpid` and maps it again.
- Journaled today: `session/stop` with data `{workspace}` only
  (`supervisor.rs` `journal_session`); `exec/request` and `exec/exit` with
  code or signal for each exec and attach (`exit_record_data`; the record has
  no `exec_id` and no field saying whether it was an attach); service
  start/ready/stop (audit). Not journaled: how the session ended, the exit
  status or signal of the session command, signals received by the
  supervisor (TERM from a scope or logout, HUP), service death (no
  supervision), OOM kills.
- `supervisor.log` of a detached session holds only what the supervisor
  printed to stderr.
- Diagnostics that would have explained a lost shell (proposed, section 4
  block D): `session/stop` carries `cause`, `exit_code`/`signal`,
  `duration_ms`; `session/signal` record when the supervisor receives
  TERM/INT/HUP; `exec/exit` carries `exec_id`, `attach`, `pid`;
  best-effort OOM evidence from the supervisor's cgroup `memory.events`
  (UNVERIFIED that it is readable under the scope: probe C3 shows the
  cgroup files; implementation must treat "unreadable" as "unknown").
  Probes D1-D4 show what the journal says today after a command kills itself.

## 3. Ranked gap list

Blocks caj's first milestone:
1. A2 detached exec with status and output by `exec_id`.
2. A1 journal cursor (`--after-wseq`) with a documented JSON-lines contract.
3. A4 JSON for `run --detach`, `stop`, `seat add/ls/set-role/revoke`; a
   structured error object on stderr when `--json` is given.
4. A7 credential from stdin (`--seat-token-file -`).
5. A9 `pid` (supervisor pid) in `ls --json`.

Needed soon:
- A11 end-of-session and exec-exit diagnostics (in the 0.6.3 scope by decision).
- Leftovers L-a, L-b, L-c (in the 0.6.3 scope by decision).
- A5 service log capture and restart; A10 registry root that follows
  `XDG_RUNTIME_DIR` (only matters if caj ever uses `--name`; with
  `--session-id` only, caj does not touch it); docs for linger and consistent XDG variables.

Later:
- A6 inbound; cgroup limits; seat expiry handling in caj; allowlist mode.

## 4. Design and implementation blocks (0.6.3)

All wire changes are additive. `PROTOCOL_REVISION` goes 3 to 4. A client on
revision 3 keeps working against a revision-4 supervisor (the version gate
only refuses a declared revision above the supervisor's, `control.rs`
`version_gate`), and the new CLI refuses to send revision-4-only fields to a
session below revision 4 (the pattern of `execcli.rs` `seat_material`), with
a clear message and exit 2.

Order: 1, 2, 3, 4, 5, 6, 7, 8. Each block is one commit.

### Block 1: fail-closed leftovers L-a and L-b (`src/notif.rs`)
Mashura round 1 flagged that refusing every non-INET bind would break
`AF_NETLINK` binds, which libc `getifaddrs()`, `ip` and Go's
`net.Interfaces()` use (recalled, not confirmed: probe N1 runs `ip` and a
Python netlink bind inside an open session at v0.6.2). A netlink socket in the
sandbox netns cannot leave it, so refusing it adds no isolation. Decision:
- Bind path: stop branching on the caller-written sockaddr family. Read the
  socket's own domain with `getsockopt(SOL_SOCKET, SO_DOMAIN)` on the
  `pidfd_getfd` descriptor the code already holds (`handle_implicit_call`,
  `dup`). After the existing namespace classification (Host and Unknown stay
  refused for every domain), map the domain to a `CallClass`:
  AF_UNIX -> `BindUnix`; AF_INET and AF_INET6 -> `BindInet`;
  AF_NETLINK -> new `BindNetlink`; anything else -> new `BindOtherFamily`.
- Table: `BindNetlink` is `KernelContinued` (reason: a netlink bind in the
  empty namespace creates no reachability; connect on other families is
  refused by the existing logic, leak case L109). `BindOtherFamily` is
  `Refused` (EACCES, reason `bind-other-family`). `verdict_table_continue_only_where_covered`
  asserts `t.len() == 8` and that `KernelContinued` appears only for
  `ConnectUnix` and `BindUnix`; both assertions change deliberately (10
  entries; `BindNetlink` joins the allowed set). If probe N1 shows nothing
  needs netlink bind, the implementer may refuse it instead and say so; the
  default keeps v0.6.2 behaviour.
- Catch-all (L-a): add class `ImplicitOther`, answer `Refused`. The final
  `match classify_ns(...)` of `handle_implicit_call` refuses `Sandbox` too
  (EACCES, reason `implicit-unexpected-call`, journaled by `refuse_implicit`).
  Reachability: the filter notifies connect, bind, listen and, for TFO, the
  send family is answered by errno in the filter (`connect_filter`), so the
  catch-all is reached only by a call the filter was not meant to notify;
  every hit is journaled, so a regression is visible. Unit test only (the
  `force-continue` branch at the top of the function stays unchanged).
- Route bind, listen and the catch-all through `verdict_for(class)`; the match
  on the returned `Answer` is the only place that decides. Rewrite the
  comments above `verdict_for` that say bind and listen do not use it.
- Low-port check: `low_port_bind_is_privileged(buf, family)` takes the sockaddr
  family; for `BindInet` derive the family from the socket domain and require
  `addrlen >= sizeof(sockaddr_in/in6)` before reading the port (an `AF_UNSPEC`
  address on an INET socket still binds a TCP port). Read the function first.
- Tests: update `verdict_table_continue_only_where_covered`; new unit tests
  `implicit_catch_all_refuses_sandbox_socket`,
  `bind_class_follows_socket_domain_not_sockaddr_family`,
  `bind_unspec_addr_on_inet_socket_is_port_checked`,
  `bind_other_family_is_refused`; leak case `in-bind-families`
  (`net_helper.py`, `net_cases.sh`): AF_NETLINK bind succeeds, AF_PACKET bind
  fails EACCES (skip if the socket cannot be created), AF_UNSPEC low-port bind
  fails EACCES, AF_UNIX and a high TCP port bind succeed.
  Verified at v0.6.2: leftovers (a) and (b) are present as described
  (`notif.rs` `handle_implicit_call`: "implicit-sandbox-fallthrough" and
  "af-unix-bind" continues; `verdict_table`).

### Block 2: timing probe L-c (`tests/leak/net_helper.py`, `net_cases.sh`, `scripts/host-verify-network.sh`)
- Verified at v0.6.2: `in_timing` connects 100 times to `LISTEN_IP`
  (192.0.2.1, a public-class address in the hermetic namespace) and
  `net_cases.sh` runs the same helper once in the session ("intercepted") and
  once outside ("direct"); `host-verify-network.sh` only greps that log and
  prints it as a note. It does not measure a local connect inside the session.
- Add `in_timing_local` to `net_helper.py`: a listener on 127.0.0.1 in the
  same process (thread), 100 connects, median of three runs, printing
  `TIMING-LOCAL median <x> us/connect`. In `net_cases.sh`, run it inside the
  session and print it as an `info` line next to the existing two. In
  `host-verify-network.sh`, report that line in the timing note and say what
  each number measures. Informational, never a gate.
- Test: `tests/leak/test_journal_harness.py`-style unit test for the helper's
  output format (`test_net_helper_timing_local_format`), plus `bash -n` on
  both shell scripts in the release gate they already pass through.

### Block 3: journal cursor (A1) (`src/cli.rs`, `src/main.rs`, `src/journal.rs`)
- `--after-wseq N` on `JournalArgs`: only records with `wseq > N`, applied
  before `--last`. Contract: `wseq` is monotonic within one journal history; it
  can repeat only if journal files are deleted outside hisn (module docs).
- Cursor health without a session (none is listed after a reboot): new
  `hisn journal --info` (workspace selected as for `journal`) prints
  `{"schema":"hisn-journal-info/v1","first_wseq":N|null,"last_wseq":N|null,
  "files":N,"bytes":N}`, null for an empty journal. It reads the head of the
  oldest file and the tail of the newest only.
- `journal --after-wseq N` exits 3 with one stderr line and no output when
  `N > last_wseq` (journal was reset; caj restarts from `--info`). When
  `N + 1 < first_wseq` (retention deleted unread records) it prints what
  exists and warns `cursor behind retention`, exit 0; the existing
  `journal/pruned` record (written at a higher `wseq`, so the cursor reader
  sees it) is the in-band signal. Its data is checked at implementation time
  and extended with the deleted `wseq` range if missing.
- Reader lock timeout: the reader pins descriptors under a shared lock held up
  to about 1 s and proceeds unlocked after that (A1). A rotation racing the
  pinning could hide a record from one pass; the next strict `>` poll
  recovers it. Specify and test this path.
- `ls --json` `journal` object also gets `first_wseq` and `last_wseq` from the
  same helper (additive).
- Tests: `after_wseq_filters_strictly_greater`,
  `after_wseq_across_rotation_exactly_once`, `after_wseq_with_last`,
  `after_wseq_ahead_of_head_exits_3`, `after_wseq_behind_retention_warns_and_reads`,
  `journal_info_empty_journal_is_null`, `journal_info_reports_first_and_last`,
  `ls_json_journal_reports_wseq_range`.
- No follow mode: caj polls with `--after-wseq`. Reason: a follow mode needs a
  long-lived reader across rotation and prune, new concurrency code without a
  host test.

### Block 4: machine interface (A4, A9) (`src/cli.rs`, `src/main.rs`, `src/supervisor.rs`)
- `run --detach --json`: stdout `{"schema":"hisn-run/v1","id":..,"name":..|null,
  "state":"running","workspace":{"id":..}}`; without `--json` the existing
  line is unchanged.
- `stop --json`: stdout `{"schema":"hisn-stop/v1","outcome":<word>}` with
  `outcome` one of `stopped`, `already-stopped`, `crashed`, `stale`,
  `not-started`, `stopped-unrecorded`, `signal-failed`, `timeout` (the
  `StopOutcome` variants, `lifecycle.rs`). Exit codes stay exactly as in
  0.6.2.
- `seat add --json` (`{"schema":"hisn-seat/v1","name":..,"role":..,
  "credential":..}`; the human message on stderr is kept), `seat ls --json`
  (array of the `seats::views` fields), `seat set-role/revoke --json`
  (`{"ok":true,...}`). `rootfs list --json` (array of names).
- Error object: when `--json` is present on any command that accepts it and
  the command fails with `Err`, stderr gets one line
  `{"schema":"hisn-error/v1","code":"E_...|E_INTERNAL","message":..}` and the
  exit code is unchanged (125). Without `--json` nothing changes.
- `ls --json`: `pid` is the supervisor pid as reported by the supervisor itself
  (new additive field `supervisor_pid` in the `sessioninfo` reply, which
  `live_session_view` already requests); null when the session is not live or
  the reply lacks it. The pid file is not used (it can outlive the process and
  be recycled; liveness is the control socket). caj should treat the pid as
  informational and use the scope unit for cgroup actions.
- `ls --session S --json` and `inspect --json` keep `{ok:false,...}` on stdout
  with exit 1. The new error object applies to failures that reach `main` as
  `Err` after argument parsing succeeded (clap parse errors keep clap's text
  and exit 2). The guide documents both conventions.
- Exit-code table in `docs/sessions.md` extended with `stop` 1, `check` 2,
  `note` 2.
- Tests: `run_detach_json_shape`, `stop_json_outcomes_cover_every_variant`,
  `seat_json_shapes`, `error_object_on_failure_with_json`,
  `ls_json_pid_from_sessioninfo_or_null` (beside the `session_v2_json` tests;
  the existing `assert_eq!(v["pid"], Value::Null)` keeps passing for the
  no-sessioninfo case),
  and a leak-suite case that runs `run --detach --json`, `ls --json`,
  `stop --json` end to end.

### Block 5: credential from stdin (A7) (`src/execcli.rs`)
- `seat_token` accepts the path `-` for `--seat-token-file`: read exactly one
  line, byte at a time from fd 0 (no later stdin consumer loses bytes), trim
  it, error if empty. Allowed on every command that has the flag except
  `attach`. Refused with a message naming both options: `exec --tty` and
  `note` with text `-` (both would read stdin). The future `exec --stdio` of
  section 7 is exclusive with it.
- Tests: `seat_token_dash_reads_stdin`, `seat_token_dash_empty_is_error`,
  `seat_token_dash_with_stdin_text_refused`; the existing mutual-exclusion
  test with `HISN_SEAT_TOKEN` is kept. Leak-suite case: exec with the token on
  stdin, journal shows the seat, `ps`-style check that the token is not in
  the client argv.

### Block 6: detached exec (A2) (`src/control.rs`, `src/exec.rs`, `src/supervisor.rs`, `src/execcli.rs`, `src/authz.rs`, `src/sessionmeta.rs`)
This block alone bumps `PROTOCOL_REVISION` (`sessionmeta.rs`) from 3 to 4.
- Wire: `Request::Exec` gains `detach: bool` (`#[serde(default)]`; `Request`
  has `deny_unknown_fields`). `build_request_with` (`execcli.rs`) builds the
  request with `json!`, so the CLI **omits** the key unless `--detach` is
  given: plain exec from a new CLI is byte-identical to today's request.
  `--detach`, `exec-status` and `exec-signal` are refused client-side below
  revision 4 (exit 2, nothing sent; the `seat_material` pattern).
- `hisn exec --detach [--cwd ..] [--env ..] -- CMD...` (conflicts with
  `--tty`). Lifetime: in v0.6.2 two things end an exec when its client goes:
  `drive_from_with_flag` (client connection `POLLRDHUP` -> TERM, KILL after
  5 s) and `monitor` (EOF on the status socket -> SIGKILL). The status socket's
  supervisor end is held by the supervisor (`sp.status`, dup'd into the exec
  table in `do_exec`), so only `drive_from_with_flag` depends on the client.
  For `detach` the supervisor skips the client-connection watch, keeps the
  status socket for the exec's lifetime and waits for the status line on a
  supervisor thread; the monitor rule stays (supervisor death still kills the
  group). Tests prove both paths.
- Output: stdout and stderr go to a pipe pumped by a supervisor thread into
  `<workspace-dir>/exec/<incarnation>-e<N>.log` (0600, dir 0700); `incarnation`
  is the session's `created.ts` in compact form. Reason: `exec_id` restarts at
  1 for every supervisor (`next_exec_id` starts at 1, `supervisor.rs`) and
  caj may reuse `--session-id`, so `<session-id>-<exec_id>` would collide. The
  same `incarnation` goes into `exec/request` and `exec/exit` records. Cap
  16 MiB, head kept; after the cap the pump discards and writes one marker
  line. Offset reads and retention are out of scope (documented; caj reads
  and deletes the files, same uid).
- Reply: `{"ok":true,"pid":N,"exec_id":"e-N","log":"<path>","incarnation":"..."}`;
  `hisn exec --detach` prints `{"schema":"hisn-exec/v1",...}` and exits 0.
  Start failure keeps the `E_EXEC` mapping (127 / 126 / 125), with the Block 4
  error object under `--json`.
- State: `exited` when the program's status line arrives, not at pipe EOF (a
  grandchild holding the pipe does not keep it `running`); the pump copies
  until EOF within the log cap. New op `execinfo {exec_id}` -> `{"state":
  "running"|"exited","exit_code"?,"signal"?,"started","ended"?,"log",
  "incarnation"}` from the live table plus an in-memory ring of the last 128
  finished execs (lost with the supervisor; the journal keeps the durable
  record). CLI `hisn exec-status --session S EXEC_ID` (exit 0 found, 1 unknown).
- Cancellation: `hisn exec-signal --session S [--signal SIG] EXEC_ID` over the
  existing `signal` op by `exec_id`, which signals the program's process group
  through the status socket (`exec.rs` `monitor`, `signal_group`). This
  replaces `exec -- kill`: whether the `pid` in replies and `ls --json` is a
  host or sandbox pid is UNVERIFIED (`do_exec` returns `sp.pid`; probe E7
  prints it).
- Lease: a running detached exec stays in the exec table, so `idle_due`
  (`lifecycle.rs`, requires no running exec) counts it as activity; documented.
- Authorization: `Op::ExecInfo` added to `authz::allows` for owner, member and
  observer (exhaustive match, compiler-enforced). Observers see the log path;
  accepted because the same-uid model gives file access anyway (ADR 0021).
  `exec --detach` is `Op::Exec`, `exec-signal` is `Op::Signal`.
- Journal and `ls`: `exec/request` and `exec/exit` get `exec_id`,
  `incarnation`, `detached`, `attach`, `pid` (this block owns
  `exit_record_data` and `journal_exec_request_record`; Block 7 adds no exec
  fields). `ls --json` `execs[]` gets `detached` and `log`.
- Limit: 32 concurrent detached execs per session (`E_BUSY` above), because
  each has a pump thread that counts against a scope's `TasksMax`.
- Tests: `exec_request_omits_detach_when_false`,
  `plain_exec_from_new_cli_accepted_by_revision3_request_shape`,
  `cli_refuses_detach_status_signal_below_revision_4`,
  `exec_detach_survives_client_close` (both lifetime paths),
  `exec_request_without_detach_still_cancels_on_disconnect`,
  `exec_detach_log_cap_truncates_with_marker`,
  `exec_detach_exited_when_status_arrives_even_if_pipe_open`,
  `execinfo_running_then_exited_with_code`, `execinfo_reports_signal`,
  `execinfo_ring_keeps_last_128`, `exec_signal_by_id_signals_group`,
  `exec_log_path_distinct_across_incarnations`,
  `authz_execinfo_allowed_for_all_roles`, `detach_limit_32_refused`; leak
  case: start `sleep 5` detached, close the client, `ls --json` shows it,
  `exec-status` shows `exited` code 0, the log holds the output.
- Risks: unbounded log files (per-file cap only); pump thread lives as long as
  the program; ring memory is bounded.

### Block 7: end-of-session and exec diagnostics (A11) (`src/supervisor.rs`, `src/init.rs`, `src/journal.rs`)
- `session/stop` data becomes `{workspace, cause, exit_code?, signal?,
  duration_ms}` with `cause` one of `command-exit`, `command-signal`,
  `stop-request`, `idle-expired`, `supervisor-signal`, `init-lost`.
  `stop-request` is decided by state, not signal sender: `hisn stop` records
  state `stopping` in `session.json` before it signals (`lifecycle.rs`
  `stop_and_keep`), so TERM/INT/HUP with state `stopping` is `stop-request`,
  otherwise `supervisor-signal`. If the supervisor is killed with SIGKILL or
  the host loses power no record is written (the session shows as
  `crashed`); the guide says so.
  `SessionEnd` already carries `code` and `idle_expired_after`; add the
  decoded signal. `init::decode_status` keeps its `128+sig` form for the exit
  code, and a new `decode_status_detail` returns code or signal separately.
- `session/signal` record when `relay_and_wait` takes TERM/INT/HUP from
  `sig::take_pending` (name only; the plain handler in `sig.rs` has no sender
  information, so the sender stays unknown and the record says so).
- `exec/request` and `exec/exit` fields are owned by Block 6.
- Best-effort OOM evidence: `oom_kill` in `memory.events` is cumulative and
  may cover unrelated processes, so read a baseline of the supervisor's own
  cgroup at start and report the delta. The field is absent when the file is
  unreadable and a number (possibly 0) when read; nothing is inferred from
  absence. Verified only
  by a unit test with a fake file path injected; real behaviour under a
  scope is UNVERIFIED (probe C3 shows the files).
- `journal.rs` readable renderer shows the cause in the `session/stop`
  summary line.
- Tests: `session_stop_record_carries_cause_and_status`,
  `session_signal_record_on_term`,
  `oom_events_parsing_handles_missing_file`, plus the readable-render test.

### Block 8: integration guide and docs
- New `docs/EXTERNAL-CALLERS.md`: the contract for a service driving hisn
  over SSH: node setup (linger, fixed `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`,
  `--session-id` ownership, no `--name`), start/stop/reconcile with the JSON
  shapes, exit-code table, exec and detached exec, journal cursor, seat
  credential over stdin, scope wrapping, what is not provided (limits,
  inbound).
- Update `docs/CONTROL-PROTOCOL.md` (revision 4, `detach`, `execinfo`),
  `docs/sessions.md` (exit codes, detached exec), `README.md` (one link),
  `CHANGELOG.md`, `docs/releases/` notes, `schemas/` if a schema file exists
  for ls output (check at implementation time), `docs/adr/` new ADR 0023
  (detached exec and revision 4).

## 5. Leftovers from 0.6.2 (verified at v0.6.2)

- **L-a (true):** `handle_implicit_call`, final `match classify_ns(...)`:
  `SockNs::Sandbox => continue_reply(.., "implicit-sandbox-fallthrough")`.
  The comment calls it unreachable, but nothing enforces that. Block 1.
- **L-b (true):** the bind path continues every non-INET family
  (`if family != AF_INET && family != AF_INET6 { continue_reply(.., "af-unix-bind") }`)
  while `verdict_table` has `BindUnix` as the only continued bind class.
  Bind INET and listen execute directly and do not call `verdict_for`
  (documented at the comment above `verdict_for`). Block 1.
- **L-c (true):** see Block 2.

## 6. Open risks

1. Detached exec is the largest change and touches the cancellation path that
   every existing exec relies on. The regression test
   `exec_request_without_detach_still_cancels_on_disconnect` is mandatory.
2. Revision 4 gating: a new CLI against an old session must degrade cleanly;
   covered by `cli_refuses_detach_below_revision_4`.
3. Bind classification by socket domain changes which branch runs for odd
   inputs (AF_UNSPEC); the low-port check must follow (Block 1 risk).
4. Linger and XDG consistency are node-setup facts hisn cannot enforce; the
   guide states them, the probe reports them (P2, P3).
5. Single-uid model: a seat credential is attribution, not a boundary
   (ADR 0021); any process of the service user can read another process's
   environment (T7) and `seats.json`. caj must not describe seats to people
   as isolation.
6. Journal retention can delete records a slow cursor has not read; Block 3
   exposes `first_wseq` for detection.
7. The probe script runs real sessions (small). It isolates runtime and state
   directories via `XDG_RUNTIME_DIR` / `XDG_STATE_HOME`, but hisn 0.6.2 also
   scans `/tmp/hisn-<uid>` and keeps the name registry there; the script
   avoids `--name` and checks (I1) that the registry file did not change.

## 7. A6 inbound: design sketch and ADR outline (not for 0.6.3)

Status quo: no host to session TCP path (A6).

- **Option (a): caller-side relay through `hisn exec` per connection.** caj
  accepts a TCP connection on its own side and runs
  `hisn exec --no-tty -- <relay>` where the relay connects to
  127.0.0.1:PORT inside the session. Problem: `--no-tty` gives the program
  `/dev/null` as stdin, so the relay cannot receive bytes; a stream mode
  (stdin passed through) is needed. Cost: small hisn change (an `exec --stdio`
  mode that passes the client's stdin and stdout, reusing `pump_pipes` and the
  `E_EXEC` mapping in `execcli.rs`), no new sockets. One exec per connection
  (process start cost per connection; measure with the existing latency test).
  The program inside must be present in the rootfs (`socat` or a tiny static
  helper). Journaling is automatic (`exec/request`).
- **Option (b): supervisor publishes a session port as a Unix socket on the
  host.** A `[[publish]]` profile entry (`port`, `path`) makes the supervisor
  listen on a Unix socket under the session directory and, per accepted
  connection, connect to `127.0.0.1:port` inside the session netns and copy
  bytes. Reusable: the supervisor already connects inside the sandbox netns
  (`notif.rs` `exec_sandbox_connect`, `supervisor.rs` setns to `ns_net`), the
  control-socket accept loop (`control.rs` `serve`), and the socket forward
  machinery for the opposite direction (`supervisor.rs` `do_forward`,
  `ssh_agent.rs`). Cost: new profile key, a copy loop with backpressure,
  limits (connections, idle), journal records per connection, and a
  decision about authorization (same-uid socket, seat attribution absent).
- ADR outline: context (single-uid, private netns); decision drivers
  (no new listening port on the host, attribution, no daemon); options a, b
  and the host-network non-option; decision (proposal: (a) first, (b) when
  caj needs more than a few connections per second); consequences (relay
  helper in the rootfs, connection accounting, journal volume); security
  notes (a published Unix socket is reachable by every process of the same
  uid; no credential check unless a per-socket seat is added).

## 8. Probes (scripts/caj-probe.sh)

The script isolates state with `XDG_RUNTIME_DIR` and `XDG_STATE_HOME` in a
temp directory (supported by the code: `session.rs` `runtime_roots`,
`workspace.rs` `state_home_with`). The isolation is partial (A10): the name
registry and the second runtime root live under `/tmp/hisn-<uid>`. The script
therefore never passes `--name`, `--prune` or `--purge`, starts only
sessions whose id begins with `cajprobe-`, stops exactly those in an exit
trap, and reports (I1) whether the registry file changed.

| Probe ids | Settles |
|-----------|---------|
| J1-J9 | journal formats, filters, concurrent read, absence of follow |
| E1-E11 | exec exit codes, kill of the client, TERM-ignoring programs, setsid survival |
| L1-L7 | loopback listen/connect in none and open, host loopback unreachable |
| G1 | `git ls-remote` to gitlab.com over HTTPS in open mode (`--offline` skips) |
| M1-M13 | JSON and exit codes per command, error format |
| T1-T7 | seat credential flow, journal record, token not in journal or argv |
| D1-D8 | shell death records today; detached session survival |
| C1-C6 | start inside `systemd-run --user --scope` (skipped if unavailable) |
| N1 | netlink bind and `ip` inside an open session (Block 1 decision) |
| P1-P3, R1-R2, I1 | host facts, stop semantics, registry untouched |

## 9. Mashura

Round 1 (three reviewers, no `src/` attached, so code facts were marked
unconfirmed by them). BLOCKING, all accepted and worked in: netlink bind
refusal (Block 1 rewritten, probe N1); cursor reset detection (Block 3:
`--info`, exit 3, `last_wseq`); log collision on `exec_id` restart (checked:
`next_exec_id` starts at 1; Block 6 uses an incarnation); missing cancel path
and the contradictory `hisn signal` text (Block 6 `exec-signal`);
`detach:false` serialised to revision-3 supervisors (checked: the request is
built with `json!`, so the key is omitted; test added); monitor path also
killing detached execs (Block 6 names both paths); pid-file trust (Block 4
uses the supervisor-reported pid); stop cause disambiguation and the SIGKILL
case (Block 7); catch-all reachability (Block 1).

Open points not taken into the blocks:
- A protocol revision bump in a patch release is the maintainer's call; the
  brief fixes 0.6.3.
- `ls --json` keeps schema name `hisn-ls/v2` while `pid` goes from always-null
  to a number for live sessions; check `schemas/` at implementation time.
- `exec` gets no `--json`; a program's own 125-127 stays ambiguous, the
  journal `exec/exit` record is the unambiguous source.
- The detached log keeps the head, not the tail.
- The probe overrides `XDG_RUNTIME_DIR`, which `systemd-run --user` also reads;
  the script therefore passes the isolated directories to hisn through `env` inside the scope command (probes C1-C6).

---

# 10. hisn 0.6.3 implementation plan (branch `work/0.6.3`, from tag `v0.6.2`)

Sections 1-9 above are the analysis written on `plan/caj-readiness`. This
section is the plan for the implementing session and overrides sections 4-9
where they differ. Facts below are marked **[read]** (code at `v0.6.2`) or
**[probe]** (measured on the test machine, kernel 7.3.3, with
`scripts/caj-probe.sh`, 36 PASS, 0 FAIL, 35 INFO, 1 SKIP, binary `hisn 0.6.2`).

## 10.1 Scope decision: Block 6 is out of 0.6.3

Detached exec (`exec --detach`, `exec-status`, `exec-signal`, protocol
revision 4) moves to hisn 0.6.4. 0.6.3 contains Blocks 1, 2, 3, 4, 5, 7, 8 and
**stays on protocol revision 3**: no new request field, no new op. Reason
[probe E11]: a process started with `setsid` inside an exec survives the end of
that exec call, so a caller has a working way to run long commands today (no
exit status, no output capture; the guide documents the recipe: start with
`setsid`, redirect output to a file in the session, find it again by pid).
Consequences for the other blocks:
- No revision gate is needed; nothing in 0.6.3 is sent to the supervisor that a
  revision-3 supervisor would not accept. The only supervisor-side wire change
  is an additional key in the `sessioninfo` reply (`supervisor_pid`), which old
  clients ignore.
- `exec/request` and `exec/exit` journal fields are not owned by Block 6 any
  more. Block 7 adds only `exec_id`, `attach` and `pid` (all exist today in
  the exec table, **[read]** `supervisor.rs` `do_exec`, `exit_record_data`).
  `incarnation` and `detached` move to 0.6.4.
- ADR 0023 now documents the external-caller interface contract (journal
  cursor, JSON schemas, error object); the detached-exec ADR is 0.6.4's.

## 10.2 Probe results on the test machine (all measured, `hisn 0.6.2`)

First run (maintainer's host, partly before the script aborted) and the full run
on the test machine agree where they overlap.

| Probe | Result | Effect on the plan |
|-------|--------|--------------------|
| P2, P3 | linger off; `/tmp` and the runtime dir are tmpfs | guide must state linger and that state on tmpfs does not survive a reboot (Block 8) |
| J1-J9 | `journal --json` is JSON lines with `ts`, `wseq`, `kind`; `--last`, `--since` (Z only) work; 6 reads during 150 note writes all parsed; no follow/after | confirms A1; Block 3 |
| E1-E6 | status propagates; missing program 127; SIGKILL 137; unknown session 125; program exiting 126 indistinguishable | guide documents; journal `exec/exit` is the unambiguous source |
| E7 | `ls --json` exec fields: `argv0, attach, exec_id, pid, tty` | confirms A2 |
| E8, E9 | exec'd process ended 16 ms after its client was killed -9; a TERM-ignoring process after 5019 ms | confirms the 5 s KILL grace |
| E11 | `setsid` child survives the end of its exec | Block 6 deferred |
| N1 | `AF_NETLINK` bind succeeds in `none` and `open`; `if_nameindex` shows only `lo` | Block 1 keeps netlink bind (default of the plan) |
| L1-L6 | listen on 127.0.0.1 and ::1 in one exec, connect from another: works in `none` and `open`; host loopback listener unreachable (ECONNREFUSED) | A3 confirmed, no gap |
| L7 | no host TCP listener owned by session processes | A6 confirmed |
| G1 | first run FAIL: the session has no `git` (rc 127). Second run PASS via python3 urllib HTTPS GET to gitlab.com in `open` | network path works; the test rootfs has no git; probe now falls back to HTTPS and says so |
| M1-M5 | `ls`, `inspect`, `check`, `journal`, `ls --session` print JSON | confirms A4 |
| M6-M9 | `seat ls`, `rootfs list` not JSON; `note` prints JSON; `profile validate` with no file rc 125 | Block 4 |
| M10 | `pid` is null for a running session | Block 4 |
| M12, M13 | unknown session: rc 125, stderr `hisn: no such session <id>`, empty stdout | error object, Block 4 |
| T1-T6 | seat credential on exec works; journal records the seat; token not in journal files nor client argv | confirms A7 |
| T4 | without credential: `client = {uid, label:"local", label_source:"none", req_id:null}` | label is `local` when no `--client`; the caller should pass `--client` (documented) |
| T7 | with `HISN_SEAT_TOKEN` the token is readable in `/proc/<pid>/environ` of the client | stdin path (Block 5) avoids it |
| D1-D3 | self-killed foreground command: hisn rc 137; `session/stop` data is only `{workspace}` | A11 gap confirmed, Block 7 |
| D5, D7, D8 | detached session survives the shell that started it; supervisor is its own session leader; dir contents listed | A9 |
| D6 | SKIP (no key auth to localhost) | UNVERIFIED over a real SSH session; the host-verify script of 0.6.3 repeats it on the test machine only if key auth to localhost exists |
| C1-C6 | start inside `systemd-run --user --scope -p MemoryMax=512M -p TasksMax=256` works; supervisor stays in the scope cgroup; `memory.max=536870912`, `pids.max=256`; exec and stop work | A8: no conflict. Execs inside the session are in the scope's cgroup too |
| R1, R2 | stop twice: 0 then 0; dir kept after stop | A9 |
| I1 | `/tmp/hisn-<uid>/names.json` untouched | isolation claim holds when `--name` is avoided |

No probe contradicted the analysis. One probe expectation was wrong (G1: the
session image has no `git`); the script is fixed, not the plan.
Probe script fixes (this branch, `scripts/caj-probe.sh`): the `local id=$1 ... pf="lo-$id.port"` line read `$id` in the same
`local` statement that assigns it, which aborts under `set -u` (it did abort the
maintainer's run); E8 printed raw epoch seconds as a window and now prints
milliseconds.

## 10.3 Test machine rule (amendment 2)

The test machine has no C compiler and no git. Builds use a user-local linker:
`zig cc` (sha256 checked) in `~/hisn-ci/.tools`, put first on `PATH` for the
run; nothing is installed system-wide, nothing outside `~/hisn-ci` changes.
The working tree is synced as a tarball by a sync script kept outside the
repository. Every block is run there (`cargo test --locked`, the release gate
when a block touches gated files, the leak suite, finally
`scripts/host-verify-0.6.3.sh`). A test that fails only in the session's own
sandbox is not called pre-existing until its result on the test machine is shown.

## 10.4 Blocks and tests

Commit order (one commit per block, subject `feat(0.6.3): ...`, Block 1
`fix(0.6.3): ...`): 1, 2, 3, 4, 5, 7, 8. The block text of section 4 applies
except as changed here. Line numbers refer to `v0.6.2` **[read]**.

### Block 1: fail-closed leftovers (`src/notif.rs`)
- Verified at `v0.6.2`: `handle_implicit_call` (L1361-1519): listen L1421-1436,
  bind L1442-1503 with `continue_reply(.., "af-unix-bind")` for every
  non-INET family, final `match classify_ns(..)` L1509-1518 continues a
  `Sandbox` socket (`implicit-sandbox-fallthrough`). `verdict_table` L2688
  has 8 entries; `verdict_for` L2742 is a linear find; the only consumer of
  `CallClass` besides `verdict_for` is the guard at L1905. No exhaustive match
  on `CallClass` exists, so new variants are compile-neutral; the test
  `verdict_table_continue_only_where_covered` (L4149) asserts `len() == 8`.
- Changes, as in section 4 Block 1: socket domain from `SO_DOMAIN` on the
  pidfd-dup fd; classes `BindNetlink` (KernelContinued, justified by probe N1)
  and `BindOtherFamily` (Refused, `bind-other-family`) and `ImplicitOther`
  (Refused, `implicit-unexpected-call`); bind, listen and the catch-all go
  through `verdict_for`; `low_port_bind_is_privileged` (L1525) follows the
  socket domain and checks `addrlen`.
- Tests: updated `verdict_table_continue_only_where_covered` (11 entries
  expected by design: 8 + 3 new, allowed `KernelContinued`: `ConnectUnix`,
  `BindUnix`, `BindNetlink`), `implicit_catch_all_refuses_sandbox_socket`,
  `bind_class_follows_socket_domain_not_sockaddr_family`,
  `bind_unspec_addr_on_inet_socket_is_port_checked`,
  `bind_other_family_is_refused`; leak case `in-bind-families` (net_helper.py,
  net_cases.sh, MANIFEST, run.sh NET_IDS as the leak-suite registration
  requires **[read]** `tests/leak/MANIFEST`, `run.sh`).
- The release gate's step 0c (single `FLAG_CONTINUE` site, `release-gate.sh`)
  must still pass; the catch-all no longer calls `continue_reply`.

### Block 2: local timing probe (`tests/leak/net_helper.py`, `net_cases.sh`, `scripts/host-verify-network.sh`)
- Verified: `in_timing` (`net_helper.py` L1196) connects 3x100 times to
  192.0.2.1:18080 and prints `TIMING median X us/connect`; `net_cases.sh`
  L572-575 runs it in the session and directly. Add `in_timing_local`
  (listener thread on 127.0.0.1, same format with prefix `TIMING-LOCAL`),
  register in the `main()` command table, print as an `info` line, report in
  `host-verify-network.sh`. Informational only.
- Test: `test_net_helper_timing_local_format` in `tests/leak/` (a python unit
  test runnable without a session, wired into `make test` next to
  `test_l8.py`; the Makefile edit is part of this block).

### Block 3: journal cursor (`src/cli.rs`, `src/main.rs`, `src/journal.rs`)
As section 4 Block 3: `--after-wseq N` (strict `>`, applied before `--last`),
`--info` (schema `hisn-journal-info/v1`, null for an empty journal), exit 3
when `N > last_wseq`, warning on stderr when behind retention, `first_wseq` and
`last_wseq` in the `ls --json` journal object (`session_v2_json`, L814).
`journal_cmd` (L1002) reads with `journal::read_records`; `--info` reads the
head of the oldest file and the tail of the newest only. Tests as listed in
section 4. `ls --json` keeps schema `hisn-ls/v2` (additive keys; no `schemas/`
directory exists at `v0.6.2` **[read]**, to re-check).

### Block 4: machine interface (`src/cli.rs`, `src/main.rs`, `src/supervisor.rs`)
As section 4 Block 4: `run --detach --json`, `stop --json`, `seat add/ls/set-role/revoke --json`,
`rootfs list --json`, error object on stderr under `--json`, `supervisor_pid`
in the `sessioninfo` reply surfacing as `pid` in `ls --json` (`live_session_view`
L741 gains it; `session_v2_json` L820 stops hard-coding null). `RunArgs` has no
JSON field and `detach` is handled inside `supervisor::run` **[read]**, so the
`--json` flag is added to `RunArgs`, threaded to `report_ready`. Error
object: `dispatch` result handled in `main` (L17-27), `--json` known from the
parsed `Cli`. Tests as in section 4. The protocol revision stays 3.

### Block 5: stdin credential (`src/execcli.rs`)
As section 4 Block 5. `seat_token` (L28) reads the file whole; `-` reads one
line byte by byte from fd 0. `seat_material` is called before the relay and
before any stdin forwarding (L309), so `exec --no-tty` is unaffected;
`exec --tty` and `note -` (main.rs L328) are refused with a message naming both
options. Applies to every command with `--seat-token-file` except `attach`
(`attach.rs` L50). Tests as in section 4.

### Block 7: diagnostics that do not need detached exec (`src/supervisor.rs`, `src/init.rs`, `src/lifecycle.rs`, `src/journal.rs`)
- `session/stop`: `Shared::journal_session` (L807) gets the extra data
  (`cause`, `exit_code`/`signal`, `duration_ms`). `run_session` (L3320) has the
  status from `relay_and_wait`. `cause` rules as in section 4 Block 7;
  `stop-request` is derived from `session.json` state `stopping`, which
  `lifecycle::stop_and_keep` (L117-149) writes before it signals; `idle-expired`
  from `SessionEnd`.
- `session/signal` record when the supervisor takes TERM/INT/HUP.
- `exec/request` and `exec/exit` gain `exec_id`, `attach`, `pid`. Not
  `incarnation`/`detached` (0.6.4).
- OOM evidence from the supervisor's own cgroup: baseline at start, delta at
  stop; absent when unreadable. Probe C3 shows `memory.max` is readable under a
  scope; whether `memory.events` is readable is checked by the host script.
- Tests: `session_stop_record_carries_cause_and_status`,
  `session_signal_record_on_term`, `exec_records_carry_exec_id_attach_pid`,
  `oom_events_parsing_handles_missing_file`, readable-render test; leak case
  `session-stop-cause` (foreground session whose command kills itself with
  SIGKILL: the journal shows `command-signal`, 9; probe D1-D3 shows today's
  baseline).

### Block 8: docs, version
`docs/EXTERNAL-CALLERS.md` (new): node setup with `loginctl enable-linger <user>`
(without it the user manager and runtime dir go away at the last logout
[probe P2], and session state on tmpfs does not survive a reboot [probe P3]),
fixed `XDG_RUNTIME_DIR` and `XDG_STATE_HOME` on every call, `--session-id`
ownership, no `--name`, `--client` for attribution (T4), the stdin credential,
JSON shapes, exit-code table, the exec exit-code ambiguity and the journal as
the unambiguous record, the journal cursor, the `setsid` recipe for long
commands with a statement that 0.6.4 replaces it, scope wrapping (C1-C6), what
is not provided (limits, inbound, detached exec). Plus `docs/CONTROL-PROTOCOL.md`
(`supervisor_pid` in `sessioninfo`; revision unchanged), `docs/sessions.md` (exit
codes), `README.md` (one link), `CHANGELOG.md`, `docs/releases/`, ADR 0023
(external caller interface), `Cargo.toml` and `Cargo.lock` version 0.6.3.
Also `scripts/host-verify-0.6.3.sh`.

## 10.5 Host script `scripts/host-verify-0.6.3.sh`
First line its own sha256; one line when each step starts and ends with elapsed
time; a timeout per step; counts of passed/failed/skipped for the gate and the
leak suite; PASS/FAIL/SKIP lines and a `RESULT:` line; build to `target/`;
isolated XDG directories; sessions named `host063-<random>`; no `--name`,
`--prune`, `--purge`. It exercises `journal --after-wseq/--info`, `run --detach --json`,
`ls --json` (pid), `stop --json`, stdin credential, and the session-stop
cause. It runs the caj probe as one step.

## 10.6 Open risks (0.6.3)
1. `SO_DOMAIN` on a pidfd-dup'd fd: behaviour on this kernel to be proven by
   `in-bind-families` on the test machine, not only by unit tests.
2. `supervisor_pid` makes `pid` a host-namespace number; callers on another pid
   namespace must not signal it. Documented.
3. `--after-wseq` relies on `wseq` monotonicity; deletion of journal files by hand
   can reuse numbers (module docs). Documented, `--info` gives the detector.
4. The `setsid` recipe has no status or output capture; `kill` of the group
   goes through another `exec`. Replaced in 0.6.4.
5. D6 (real SSH) remains UNVERIFIED on the test machine without key auth to
   localhost.

## 10.7 Mashura round 1 on section 10: BLOCKING items and resolutions

Three reviewers; BLOCKING only. Each item was checked against the code at
`v0.6.2` before being accepted. These resolutions override 10.4 and section 4.

1. **Block 7 stop cause (accepted, checked).** `hisn stop` sends the `kill` op,
   and the supervisor answers it by signalling the session's init
   (`supervisor.rs` `Request::Kill` -> `sys::kill(init_pid, ..)`); the supervisor
   itself takes no signal, so "TERM with state `stopping`" never fires.
   `end_of_session` (`lifecycle.rs`) accepts `Stopping | Stopped`. Idle expiry
   also writes `stopping`. New rule, evaluated in this order:
   `idle-expired` (idle flag from `SessionEnd`) > `supervisor-signal` (the
   supervisor took TERM/INT/HUP) > `stop-request` (recorded state is `stopping`
   or `stopped` at the end) > `command-signal` > `command-exit` > `init-lost`.
   Extra tests: `cause_stop_request_when_state_stopping`,
   `cause_stop_request_when_state_already_stopped`,
   `cause_idle_expired_wins_over_stopping_state`,
   `cause_supervisor_signal_without_stop_state`,
   `cause_for_detached_session_term_to_init`. For `idle-expired` the journaled
   `exit_code` is the command's decoded status, not 143.
2. **Block 3 gap recovery (accepted, checked).** `read_records` pins the file
   list once per call; a rotation between listing and opening can hide an older
   file while newer records are read, and a strict `>` cursor then never
   recovers the hidden record. In cursor mode (`--after-wseq`) the reader checks,
   before filters, that the selected `wseq` values are contiguous starting at
   `N+1` (or start at `first_wseq` when `N+1 < first_wseq`). On a gap it re-reads
   once; a second gap exits 4 with one stderr line and no stdout. Tests:
   `after_wseq_gap_is_retried_then_exit_4`, plus the existing exactly-once test.
   With `--json`, exits 3 and 4 also print the Block 4 error object
   (`E_CURSOR_RESET`, `E_CURSOR_GAP`) on stderr; without `--json` one text line.
   `--after-wseq 0` on an empty journal is exit 0 with no output; any `N > 0`
   on an empty journal is exit 3. `--info` conflicts with `--after-wseq`,
   `--last`, `--since`, `--kind`, `--session`, `--seat` (clap) and prints JSON
   always. Filtered readers (`--session`, `--kind`) may not see `journal/pruned`;
   the guide says to compare with `--info`.
3. **Block 1 bind of other families (accepted, decision recorded).** Probe N1
   (re-run on the test machine, `hisn 0.6.2`): in both `none` and `open`
   NETLINK bind OK; AF_ALG bind ENOENT (the call reaches the kernel; the algorithm
   name is unknown to it, so AF_ALG is continued today); AF_PACKET `socket()`
   EPERM (so the refusal path of `BindOtherFamily` cannot be exercised end to
   end; unit tests carry it); AF_INET low-port bind EACCES. Decision: the
   fail-closed rule of the amendment stands: the table says UNIX and, by the
   probe, NETLINK; every other domain (including AF_ALG) is `Refused`, and this
   is a recorded behaviour change in ADR 0022's update (added to Block 8).
   `SO_DOMAIN` failure refuses. A sockaddr shorter than the family needs is
   passed to the supervisor's own `bind` so the kernel returns EINVAL; the
   low-port check reads the port only when `addrlen >= 4` for INET and `>= 24`
   for INET6 (the kernel accepts the 24-byte RFC 2133 form). Raw/ICMP INET
   sockets: the port check applies to `SOCK_STREAM`/`SOCK_DGRAM` only; other
   types are `BindOtherFamily`-style refused. Tests added:
   `bind_short_addrlen_inet6_24_bytes_is_port_checked`,
   `bind_so_domain_error_refuses`, `bind_raw_inet_refused`.
4. **Namespace gate for every verdict_for use (accepted).** `classify_ns` runs
   first; `Host` and `Unknown` refuse for every call class including
   `BindNetlink` and `BindOtherFamily`; only `Sandbox` reaches `verdict_for`.
   Test: `host_netlink_bind_is_refused`, `unknown_ns_other_family_is_refused`.
   Every continue goes through `continue_reply` (release-gate step 0c); the
   gate is run on the test machine after Block 1.
5. **Section 10.1 "a working way" (accepted, checked).** The `setsid` recipe is
   weaker than stated: `idle_due` (`lifecycle.rs`) counts only connected clients
   and the exec table, so a session with `idle_timeout` is stopped under a
   `setsid` job; and `resolve_seat` (`notif.rs`, test
   `seat_walk_main_command_and_reparented_are_null`) gives `seat: null` to
   network records of a reparented process. The guide says: do not set
   `idle_timeout` on sessions that run `setsid` jobs, and expect no seat
   attribution on their network records. 0.6.4 replaces the recipe.
6. **Block 5 (accepted: Mashura's blocker plus the non-blocking ones that are
   cheap).** Default `exec` passes the caller's fds 0-2 (`execcli.rs`
   `send_with_fds(.., &[0,1,2])`), so after the credential line the program would
   inherit the rest of stdin (a seekable file could be re-read). Rule:
   `--seat-token-file -` on `exec` requires `--no-tty` (stdin becomes
   `/dev/null`); refused with `--tty` and with default mode; the refusal is
   evaluated before any read. The token is read once per process and cached;
   the line is capped at 4096 bytes. Tests:
   `seat_token_dash_requires_no_tty`, `seat_token_dash_refusal_precedes_read`,
   `seat_token_dash_line_cap`, `seat_token_dash_no_trailing_newline`,
   `seat_token_dash_crlf_trimmed`.

Open points (not worked in): the `exec`-signal relay is not seat-attributed;
`pid` namespace naming in exec records (the guide names it: sandbox pid in
`exec_id` records, host pid in `supervisor_pid`); `memory.events` delta only
means something with one scope per session; `stop --json` outcome words
`already-stopped`, `crashed`, `stale` come from the `Command::Stop` path in
`main.rs` and `StopOutcome` (`lifecycle.rs`, five variants), so the plan's
test maps both (named `stop_json_outcome_words_cover_every_path`); table size
is 11 by design (section 4's "10" is superseded); the `host-verify` first line
is the sha256 of the script file printed by the script (computed by `sha256sum`
on `$0`), not a line inside it; D6 stays UNVERIFIED without key auth.

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

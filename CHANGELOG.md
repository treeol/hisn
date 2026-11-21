# Changelog

All notable changes to hisn are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released before
0.2.0, so that section describes everything that exists.

## [Unreleased]

### Security
- Open mode, notification engine (ADR 0022 amendment): the catch-all for
  any other notified call now refuses instead of handing a sandbox socket
  back to the kernel, and `bind` is classified by the socket's own domain
  (AF_UNIX and AF_NETLINK continue, INET stream/datagram is executed by
  the supervisor, everything else is refused with EACCES). Bind, listen and
  the catch-all take their answer from the verdict table. AF_ALG and other
  exotic socket domains that 0.6.2 let through are now refused in open mode.

## [0.6.2] - 2026-11-21

### Security
- `network = "open"` no longer has a timing gap. In 0.6.1, for a call
  the supervisor left to the kernel, the check and the kernel's
  execution were two moments a program could exploit. 0.6.2 removes
  that class of decision: the supervisor performs `listen` and
  `connect`/`bind` with an AF_INET/AF_INET6 address itself on its
  own reference to the caller's socket (design A); Landlock TCP
  bind/connect rules with no allow rules refuse those calls at
  execution time for any sandboxed task (design B); fast-open sends
  are answered `EOPNOTSUPP` by the BPF filter itself (design C);
  io_uring is already denied and non-native ABIs are killed (design
  D). The "open mode is for trusted code" limitation of 0.6.1 is
  removed for these four operations. See ADR 0022, "Amendment
  0.6.2".
- **Supervisor-executed listen for every address family.** The
  supervisor performs `listen` on its own reference for every
  address family (INET and AF_UNIX), not just INET. The kernel
  never executes a continued `listen` from a sandboxed task.
- **New kernel requirement.** Open mode requires Landlock ABI >= 4
  (Linux 6.7). `hisn check` reports it; an open session on an older
  kernel fails with a clear error, never silently.
- **No longer supported.** TCP fast open (`MSG_FASTOPEN`) in open
  mode; programs fall back to a normal connect.
- **Peer-credential difference.** A client reading `SO_PEERCRED`
  on an AF_UNIX listener's accepted socket sees pid 0 instead of
  the sandbox-internal pid; uid and gid are unchanged.

### Added
- `notif::verdict_table`: every intercepted call class, its answer,
  and why it is safe; `KernelContinued` only for AF_UNIX classes.
- Test-only `force-continue` cargo feature: the engine answers
  CONTINUE for every intercepted call, to prove the kernel-side
  (Landlock) refusal independently. Never in release builds;
  release-gate checks.
- Parity cases in `tests/leak/net_cases.sh` (loopback v4/v6,
  non-blocking, AF_UNIX path/abstract, concurrency).

### Verification (this build)
- CI host (kernel 7.3.3, Landlock ABI v11):
  `HOST-RUN-062: pass=11 fail=0 timeout=0 skipped=1`.
  Unit tests 592 passed; 0 failed. Release gate (plain) green
  (fmt, clippy, cross-clippy aarch64/musl, make-check, make-test,
  leak-suite pipe 467/0, pty 468/0). Host-verify hermetic 104/0.
  Host-verify --real 111/0. Forced-continue kernel proof: Landlock
  refuses TCP connect and bind with EACCES on all three chains
  (main, exec helper, child of exec'd command). Timing comparison
  (v0.6.1 vs 0.6.2, same host): intercepted 1489.9 vs 1484.6 µs;
  direct 1485.3 vs 1478.4 µs.
- Rootfs not available on the CI host; rootfs steps skipped.
- Leak-suite counts: v0.6.1 466/0/12/4, 0.6.2 467/0/12/4 (pipe);
  pty 468/0/12/3. Net +1 (two new parity/concurrency cases).

### Known limitations
- The caller's `O_NONBLOCK` flag is briefly changed while the
  supervisor completes a blocking connect.
- Calls interrupted by a signal may be notified again by the kernel.
- TCP fast-open sends (`MSG_FASTOPEN`) are refused with `EOPNOTSUPP`
  for every socket type.


## [0.6.1] - 2026-11-19

### Security
- `network = "open"` is meant to let a program reach only targets the
  connect policy approved. In 0.6.0 a socket the supervisor had handed
  to a program before its connect, and that connect then failed, could
  still be used for a loopback connect, `bind`, `listen` or a fast-open
  send in the supervisor's network namespace. 0.6.1 refuses all of
  these on such a socket, and leaves a call to the kernel only for a
  socket that verifiably lives in the sandbox namespace. Upgrade before
  using `open` with untrusted code.
- **Remaining limitation.** For calls the supervisor leaves to the
  kernel, the check and the kernel's execution are two moments; a
  program written to exploit that timing may get a call through that
  the policy would have refused. Ordinary programs are not affected.
  Use `open` only for code you trust until 0.6.2, in which the
  supervisor performs these calls itself on its own copy of the socket,
  with a kernel-enforced backstop alongside. `network = "none"` is not
  affected. See ADR 0022, "0.6.1 hardening", "Known gap".

**Evidence (a Fedora 45 host, kernel 7.3.3, at `8f2d0a1`):**
`bash .wakil/host-run-061.sh full` ended `RESULT stage=full exit=0`
(unit tests `590 passed; 0 failed`; leak suite `473 passed, 0 failed,
9 skipped, 2 weak` and with a rootfs `486 passed, 0 failed, 5 skipped,
2 weak`; host script `RESULT: pass=110 fail=0 timeout=0 skipped=1`);
`scripts/host-verify-network.sh --real` ended
`RESULT: pass=121 fail=0 timeout=0 skipped=0`. Secondary, a second test
machine at `3d417ae`: `pass=111 fail=0 timeout=0 skipped=2`. Details:
`docs/releases/v0.6.1.md`.

### Fixed
- Journal retention now applies to every session, whatever its network
  mode (once per workspace, 64 MiB), with a `journal/pruned` record
  naming each deletion.
- `connect()` on an already-connected socket returns `EISCONN` for any
  target, private included.
- `tcp_info` fields are read by definition, not by hardcoded offset.

### Added
- `network/connect`, `network/connect-result` and `network/implicit`
  records name the seat of the exec that caused them, found by process
  ancestry of the calling task (children and threads included); the main
  command, in-sandbox services and processes detached from their exec
  stay `seat: null`. DNS records stay unattributed (a query cannot be
  tied to one caller without guessing).
- `network/connect` records carry `notif_id` and `pid`.
- New record kinds: `network/implicit` (bind, listen or fast-open send
  seen by the open-mode engine; the target names the syscall) and
  `journal/pruned` (files deleted by retention).

### Changed
- `network = "open"` needs kernel 5.14 (`SO_NETNS_COOKIE`); 0.6.0
  accepted 5.9.
- Intercepted connect: about 151 µs against 97 µs in 0.6.0 on the same
  host (the filter now also notifies `bind`, `listen` and fast-open
  sends, and each connect resolves its seat and socket namespace).
- Shipped text no longer names private hosts or addresses; the release
  gate now fails if those names or a private LAN address reappear.

## [0.6.0] - 2026-11-17

`network = "open"` (ADR 0022): outbound TCP for a session in an empty
network namespace. Each `connect()` is intercepted with seccomp user
notification; the supervisor connects from the host network namespace
and injects the socket. `open` allows every public address; there is no
allowlist in this release. `none` (the default) and `host` behave as in
0.5.1. Details, limitations and what was measured:
`docs/releases/v0.6.0.md`.

**Evidence (a Fedora 45 host, kernel 7.3.3, at `4ec88bc`):**
`scripts/host-verify-network.sh --real` ended with
`RESULT: pass=103 fail=0 timeout=0 skipped=0`; leak suite
`455 passed, 0 failed, 9 skipped, 2 weak`, with a rootfs and
`HISN_BIG_TESTS=1` `468 passed, 0 failed, 5 skipped, 2 weak`.
Also verified on a second host: `pass=100 fail=0 timeout=0 skipped=2`.

### Added
- `session.network = "open"` and `--network open`.
- Connect interception for the main command, `hisn exec`, `hisn attach`
  and all their threads: unix and loopback continue; other families,
  non-stream sockets and non-public targets get `EACCES`; public stream
  targets are connected by the supervisor. 30 s deadline
  (`ETIMEDOUT`), queue of 256 (full: `EACCES`).
- A `connect()` on a non-blocking socket returns `EINPROGRESS` at once:
  the supervisor injects its connecting socket and the program follows
  the connect itself (`POLLOUT`, `SO_ERROR`). A `connect()` on a
  blocking socket returns when the connection is established or has
  failed. 16 threads decide and start connects and never wait for one;
  up to 64 blocking connects wait at a time in a second pool, so a
  non-blocking connect is not held up by them. A second `connect()` on
  a socket whose connect is pending gets `EALREADY`, on a connected one
  `EISCONN`, on one whose connect failed that failure.
- DNS responder on the session's `127.0.0.1:53` (UDP and TCP),
  forwarding to the host's resolvers; `open` sessions get a generated
  `/etc/resolv.conf` and `/etc/nsswitch.conf`. Without a usable
  upstream the session does not start.
- Journal kinds `network/connect`, `network/dns` (real response code;
  `ok` / `failed` / `error`), `network/connect-result` (how a
  non-blocking connect ended: `connected`, `failed` or
  `pending-at-deadline`, with `latency_ms`; no errno, the supervisor
  never reads the socket's pending error) and `network/summary`
  (records beyond 50 per second are counted, not written one by one).
- Start-up checks for `open`: kernel support (5.9 or newer, by trying
  the operations), separate network namespace, Yama `ptrace_scope`
  0 or 1; `extra_deny` with `connect` or `socket` is rejected.
- `scripts/host-verify-network.sh` and the hermetic network cases
  `tests/leak/net_cases.sh` (L90, L94, L96–L100, L102–L107, L109–L117,
  L119–L124), including a Node and a Go client; the `--real` step also
  runs node `fetch` and Go `http.Get` against github.com (L118).

### Changed
- For a session in `open`, the workspace journal deletes its oldest
  rotated files once it exceeds 256 MiB in more than four files.
  Sessions in `none` and `host` keep every journal file, as before.

### Fixed
- The 512 MB import test measured the memory of the whole test process
  and could fail because of other tests running in parallel; it now
  measures in its own process.
- The release build from `4ec88bc` failed CI on non-x86_64 targets
  (`f9845fb`, `36255b3`): `AUDIT_ARCH_X86_64` was dead code on aarch64,
  and the `SECCOMP_IOCTL_NOTIF_*` request constants were declared as
  `libc::c_ulong` (u64 on glibc, but the ioctl request parameter is
  `c_int` on musl, so the musl build failed with a type mismatch).
  Each target now compiles only its own `NATIVE_ARCH` constant, with a
  `compile_error!` for unsupported architectures; the ioctl request
  constants are `u32` bit patterns passed `as libc::Ioctl` (bit
  pattern preserved on both glibc `c_ulong` and musl `c_int`). The
  release gate also now runs clippy for each non-native CI target.
  Identical behaviour on x86_64.
- Test-only: the workspace-dir tests no longer read the process
  environment (explicit `state_home_with` / `workspace_dir_with` /
  `is_tmp_state_home_with` forms), so they cannot race with the
  `/tmp`-fallback tests and fail on CI. No runtime behaviour change.

## [0.5.1] - 2026-11-15

0.5.1 gives the journal's "who" substance: named **seats** with a
credential and a role, per workspace. Under one Unix user a seat is
attribution and a guard against mistakes, not a security boundary.

**Host evidence (at `89daf77`):** `make release-gate` green — leak suite
`371 passed, 0 failed, 9 skipped, 1 weak`; with `HISN_TEST_ROOTFS` and
`HISN_BIG_TESTS` `384 passed, 0 failed, 5 skipped, 1 weak`; L89 has
21 checks. In the build sandbox, `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` were clean and
`cargo test --lib` reported 522 passed with only the two known
environmental failures.

### Added
- **`hisn seat add|ls|set-role|revoke`** with `--workspace` or `--session`.
  `add` prints the credential once; `ls` never shows one. The store is
  `seats.json` in the workspace state directory (0600, flock + atomic
  publish, fails closed for credentials on a corrupt store).
- **Roles.** `owner` (everything, including seat management), `member`
  (exec/attach/signal/note and the read-only ops), `observer` (read-only
  ops only) — one table in `src/authz.rs`, every op assigned. A client
  without a credential is the owner, exactly as before; a presented
  credential that is unknown, revoked or expired is refused, never falling
  back to owner. Role refusals name the seat, op and required role and are
  journaled.
- **Protocol revision 3.** `client.seat_token` and the ops `seat-add`,
  `seat-ls`, `seat-set-role`, `seat-revoke` exist only at revision 3; the
  CLI refuses with exit 2 and sends nothing below it when a credential is
  configured. The credential comes from `HISN_SEAT_TOKEN` or
  `--seat-token-file`, never from a command-line argument and never into a
  session's environment.
- **Journal and listings.** Credentialed records carry the server-set seat
  name and role with `label_source` `"seat"`; `journal --seat` filters on
  it (label match stays for older records). Seat management is journaled.
  `ls --json` gains an additive `seats` key; `grants.jsonl` is unchanged.

### Changed
- `session.json`: unknown fields nested inside `owner`, `lease` and
  `members` survive rewrites like the top-level ones.
- Unknown `expires` values on the wire `seat-add` are rejected instead of
  stored verbatim.

## [0.5.0] - 2026-11-15

0.5.0 adds the workspace journal: each workspace keeps an append-only
`journal.jsonl` of what its sessions did, and `hisn journal` reads it back in
one compact line per event.

**Host evidence (a Fedora 45 host, kernel 7.3.3):** `make release-gate` green — leak suite `350 passed,
0 failed, 9 skipped, 1 weak`; with `HISN_TEST_ROOTFS` and
`HISN_BIG_TESTS` the leak suite reports `363 passed, 0 failed, 5 skipped,
1 weak`. A Wakil pinned to hisn 0.4.3 drove a session started by this build:
commands, exit codes, durations, notes, session stop and the git report all
appeared in the journal, `hisn journal --session <id>` worked from another
directory for a running and for a stopped session, and `hisn note` against a
0.4.3 session was refused with exit 2. `target/debug/hisn --version` prints
`hisn 0.5.0`. No sessions, leak or integration tests were run in the build
sandbox.

### Added
- **Workspace journal.** One `journal.jsonl` per workspace (mode 0600,
  workspace-wide `wseq`, 64 MiB rotation) records the audit-shaped events,
  exec requests and exits, notes/markers, session start/stop, and git-change
  records. Exec request records carry argv capped at 512 bytes in total (the
  fitting whole-element prefix; an over-long first element records an empty
  argv with the original counts), plus the request cwd; exec exits carry the
  exit code or signal, cancelled/lost, and duration.
- **`hisn journal`.** Compact readable lines (merged `exec` events) with
  `--workspace`, `--session`, `--seat`, `--kind`, `--since` and `--last`
  filters, and exact `--json` output. `--session ID-or-NAME` resolves the
  workspace from any directory — live `session.json` first, then persistent
  session markers — including after the session has ended.
- **`hisn note`.** A verbatim note/marker (at most 8 KiB) journaled through
  the new `note` control op; never parsed, interpreted or executed.
- **Workspaces.** Every session belongs to a workspace (default from the
  canonical cwd, or `--workspace NAME`); one journal is shared by all sessions
  in a directory.
- **Git-change report.** Start/stop snapshots of `.git/hooks` and
  `.git/config` journaled as one short diff, flagged program-executing keys.
  Report only: nothing is blocked or reverted.
- **Protocol revision 2.** `client.protocol_version` / `protocol_revision`
  gates the new op; absent means revision 1. `ls --json` gains additive
  `hisn_version`, `protocol_revision`, `workspace`, `journal` and
  `journal_failures`.

### Compatibility
- A 0.4.3 client works against a 0.5.0 supervisor: grant, revoke, list, kill,
  exec and signal answer with the same bytes as before, while `sessioninfo`
  also returns `workspace` (the id text), `journal_failures` and
  `journal_bytes`, and `inspect` also returns `journal_failures` and
  `journal_bytes` (all purely additive). The 0.5.0 CLI sends nothing new to a
  0.4.3 session; `grants.jsonl` is unchanged; running 0.4.3 sessions are not
  affected by installing 0.5.0.

### Known limitations
- A 0.4.3 binary that rewrites `session.json` (for example `hisn stop`) drops
  the fields it does not know, after which that session is treated as revision
  1. The journal can contain whatever a command line contains, including
  secrets. Records are synced at session stop and rotation, not per record;
  rotated files are never deleted automatically; a dying supervisor leaves no
  git-change stop snapshot; and a client that wraps its commands in a
  launcher is journaled as the launcher.

## [0.4.3] - 2026-11-11

0.4.3 adds no features. It locks in the 0.4.2 fixes with regression tests,
adds a release gate, fixes smaller audit findings, and restructures
session startup so the coming egress proxy, cgroup v2 limits and
multi-seat work can be added safely.

**Host evidence (a Fedora host):** `make release-gate` all ok (fmt, clippy, make
check, make test), leak suite 333 passed, 0 failed, 9 skipped, 1 weak;
with `HISN_TEST_ROOTFS` and `HISN_BIG_TESTS` the leak suite reports 346
passed, 0 failed, 5 skipped, 1 weak; `make leaktest` on a terminal also
reports 333 passed, 0 failed, 9 skipped, 1 weak. The gate's
pseudo-terminal step was skipped because `script` is not installed; the
direct terminal run covers it. No unit-test count for the host is recorded;
no sessions, leak or integration tests were run in the build sandbox.

### Changed
- **Host services run in their own process group.** Each host service is
  a process-group leader with stdin `/dev/null` (stdout and stderr too).
  Stopping a session signals the whole group, then SIGKILLs it after the
  leader is reaped, so a TERM-ignoring child does not survive.
- **Startup fails at once when a host service exits before readiness
  completes**, with `host_service <name>: exited with status <n> before
  readiness completed`.
- **A service shows `starting` in `ls --json` until readiness passes**,
  then `ready`. `exit` stays `null` for in-sandbox services.
- **SSH agent proxy timeouts.** The host agent socket now has a 30 s
  read timeout alongside the existing 30 s write timeout.
- **Release gate.** `make release-gate` runs fmt, clippy, `make check`,
  `make test` and the leak suite (pipe, then pseudo-terminal when
  `script` is present), stopping at the first failure.

### Fixed
- `recv_with_fd` treats a truncated control message as an error.
- `rootfs.rs` `dup` failures now return the OS error instead of wrapping -1.
- `stdio_to_dev_null` closes the opened fd only above fd 2 on error.
- The SSH agent client counter is decremented on every exit path via a
  guard inside the worker thread.
- `sessionmeta::rewrite` removes a stale temp of the same name before
  creating a new one.
- Leak tests L77/L78 take the helper socket path from `argv[1]`; the
  release gate pipes the leak suite and reports a skipped pseudo-terminal
  run honestly; dead-service detection, the cleanup guard's group kill,
  and the ExecTable insert panic are fixed.

### Hardening
- `run_session` is split into named phases behind one cleanup guard; a new
  `src/services.rs` holds the service code; host and in-sandbox stops
  share one `stop_and_reap` path; one profile load; one exec table.
- Leak cases L76–L81: exec cancel on early disconnect, hung and slow
  readiness probes, load-time rejections, host-service group stop, and
  readiness failing for an already-dead host service.

## [0.4.2] - 2026-11-09

0.4.2 hardens the profile surface and closes audit findings from a review
of 0.4.1. Profile loading now rejects values that previously panicked or
hung at run time, readiness probes cannot outlive their timeout, and
`session.json` updates are race-free.

**Host evidence (a Fedora host):** unit tests 406 passed, 0 failed; leak suite
307 passed, 0 failed, 9 skipped, 1 weak; readiness checks pass. In the
build sandbox `cargo test --lib` is 404 passed, 2 failed (the 2 known
sandbox failures `scrub_argv_overwrites_cmdline` and
`proc_self_mem_is_not_writable_after_apply`). No sessions, leak or
integration tests were run in the build sandbox.

### Changed
- **Profile validation.** Profiles with `stop.grace` or readiness `timeout`
  above 86400 s, NUL bytes in exec strings, or `ready.tcp` are now rejected
  at load. `ready.tcp` returns `E_NOT_SUPPORTED` (not implemented).
- **Readiness probes are bounded.** A `ready.command` probe is bounded by
  `ready.timeout`; a hung probe is killed with its process group at the
  deadline and startup fails at about `timeout`.
- **Cancelled execs are killed.** An exec whose client disconnects before
  `started` is now cancelled (TERM then KILL), not left running.
- **`session.json` is written under `session.json.lock`.** Read-modify-write
  updates (`set_state`, `record_member`, `touch_lease`) are serialized across
  processes with an exclusive `flock` on `session.json.lock`.

### Fixed
- **Host-service stop race.** SIGKILL is never sent to an already-reaped
  pid; `EINTR` no longer ends the stop grace; the probe process group is
  killed as a whole.
- **Dead code removed.** `session::mode_of`, `ServiceHandle.name`,
  `init::raw_fd`, a stale `#[allow(too_many_arguments)]`, and an unused
  parameter.
- **L33 test fix.** Leak test L33 cross-exec steps now use `--no-tty`,
  matching neighbouring steps.

## [0.4.1] - 2026-11-08

0.4.1 closes four of the 0.4.0 known issues (a returning `--detach`, `ls --json`
clients/execs, CLIENTS zeroed on a stopped session, secret-safe env passing)
and removes the fixed ~100 ms latency floors on the session-ready and stop
paths. One 0.4.0 known issue — `ttyname()` inside an attach — is **not** closed
here; it needs a host to verify (see below).

**Host evidence:** the build sandbox blocks user namespaces, so `cargo test`
(unit) and the `test_l8.py` self-test run here; the leak suite (L1–L75) and the
`--detach`/attach host steps are **not run here** and must be run on the host (see
"Host verification"). Two unit tests fail only in this sandbox and pass on a
host (`scrub_argv_overwrites_cmdline`, `proc_self_mem_is_not_writable_after_apply`).

### Added
- **`hisn ls --prune --name-prefix <prefix>`**: prune only stopped/crashed
  sessions whose name starts with `<prefix>`. An unnamed session never matches a
  prefix. `--prune` without the flag keeps 0.4.0 behaviour.
- **`hisn ls --prune --dry-run`**: list the sessions that would be pruned,
  removing nothing.
- **`hisn ls --json` completes `hisn-ls/v2`** (additive): `clients` is the array
  of live control connections (uid, pid, label, label_source, connected_since);
  a live attach appears under `execs` with `attach: true`; `services` and
  `rootfs` are populated. For a stopped/crashed session `clients` is `[]` and
  CLIENTS is 0. A live session's client/exec list is read from the supervisor
  (a new `sessioninfo` control op); the schema name stays `hisn-ls/v2`.
- **`hisn run --detach` returns.** The parent forks the supervisor (`setsid`,
  stdio to `<session-dir>/supervisor.log` mode 0600), waits until the control
  socket accepts, prints `<id> <name|-> ready` on stdout and exits 0. A start
  failure prints the supervisor's first error lines and exits non-zero. Without
  `--detach` nothing changes.
- **`hisn exec --client LABEL`**: the same client-label flag as `attach`.
- **`hisn run --env-file PATH`**: read `KEY=VALUE` lines (blank lines and `#`
  comments ignored; validated exactly like `--env`). This is the documented way
  to pass secret-shaped values, so they do not appear in `/proc/<pid>/cmdline`.
- **`hisn stop` on an already-stopped session** says `already stopped` and on a
  crashed one `crashed, no supervisor`, exiting 0 without claiming to have
  stopped it.
- Leak tests **L73** (`ls --prune --name-prefix`), **L74** (`ls --json`
  clients), **L75** (`run --detach` returns).
- **Host verification for 0.4.1** (a Fedora host): `cargo test --release`;
  `HISN_TEST_ROOTFS="$(hisn rootfs path wakil-dev)" make leaktest`;
  `hisn run --name t --detach` (returns `<id> t ready`);
  `hisn attach --session t` then `tty` and `tmux new -d -s t && tmux ls`;
  `hisn ls --json` (clients); `hisn ls --prune --name-prefix wakil-`.

### Changed
- **Event-driven session wait.** `hisn run`'s readiness wait and the `hisn stop`
  wait no longer poll on a fixed ~100 ms interval. Readiness polls the control
  socket with an exponential backoff starting at 1 ms and capped at 20 ms (a
  nonblocking connect, so a stalled listener never blocks the waiter); stop
  waits on the supervisor's pidfd. Asserted in `tests/latency.rs`: a socket that
  appears after 8 ms is observed ready in under 60 ms, an already-ready socket
  in under 30 ms, and a stop in under 80 ms. The bounds are loose on purpose;
  the point is that no fixed ~100 ms floor remains.
- **Environment is read with `vars_os()`** where the host env is read, so a
  non-UTF-8 host variable no longer panics the supervisor.
- **`hisn inspect` redacts `[env.set]` values whose name matches
  `looks_secret`** (`*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASSWORD*`).
- A `[net] nameservers` override that is empty or loopback-only is refused by
  the resolver builder itself, not only at `hisn profile validate`.
  `is_loopback_ns` now also rejects `0.0.0.0` and the IPv4-mapped
  `::ffff:127.0.0.0/8` (and `::ffff:0.0.0.0`, `::`).
- A **stopped session keeps its name**; the name becomes reusable once
  `hisn ls --prune` removes the directory and repairs the index. `reserve`
  checks the index (race-free across concurrent `run`s), and `release` drops a
  name only if it still maps to the releasing session's id.
- `touch_lease` writes `session.json` only when the session has a lease
  (`idle_timeout` set); admission (a new client or exec) and the idle check
  share the lease lock, so an exec admitted during the idle check is not stopped
  under it.

### Known issues (0.4.1)
- **`ttyname()` inside an attach is still not fixed.** The client's pty slave is
  allocated on the host `devpts`, and the session has its own private `devpts`
  instance; the kernel refuses mounting a second, non-`newinstance` devpts in
  the session's user namespace, and devpts cannot carry an arbitrary node to
  bind onto. A Mashūra round (both readers) reviewed the options and both chose
  the only isolation-preserving one: allocate the attach's pty **inside** the
  session (as `init::open_pty` already does for the main command) and hand the
  **master** back to the client over the control socket. That is a protocol
  change (an fd travels sandbox→supervisor→client for the first time) and must
  be verified on a host (L76, with L10/L8 green, plus fd-count and fd-leak
  checks). Not shipped in 0.4.1; the L76 host step is listed below.
- L56 and L58 remain host-only / documented checks.

## [0.4.0] - 2026-11-07

0.4.0 adds seats: a hisn session is a named place that several clients join,
locally or over SSH (`ssh -t host hisn attach --session <name>`), sharing one
sandbox, one pid namespace, one session env snapshot and one audit log, with
idle leases, an explicit `hisn stop` that keeps the session directory, and
archival of the audit on prune.

**Host evidence:** `make leaktest` on a Fedora host: 308 passed, 0 failed, 6 skipped,
1 weak; remote attach verified on a second host (Fedora 44, kernel 7.2.13).

**Security:** equal access per uid in 0.4.0; the client record, the single
`authorize()` seam and the per-client audit ship now, so roles are a policy
change later.

### Added
- **Named sessions:** `hisn run --name <name>` (unique per user); `--session`
  accepts a name or id everywhere; `hisn ls` shows NAME, ID, STATE, CWD,
  ROOTFS, NET, AGE, CLIENTS, LEASE. A per-user index in the `/tmp/hisn-$UID`
  root is authoritative; a fallback scan repairs it (ADR 0014).
- **Attach:** `hisn attach --session <name|id>` — an interactive shell
  ($SHELL from the env snapshot, else /bin/sh) in the session cwd. Multiple
  attaches are peers. The detach key Ctrl-] d closes the client; the shell
  is killed on disconnect (no --detach in 0.4.0) (ADR 0015).
- **Client identity and the authorization seam:** every control request
  carries a `ClientRecord` (uid, pid, label, req_id, seq, principal). One
  `authorize()` function gates every op; in 0.4.0 it allows iff
  `uid == owner.uid`. The `Authorized` token cannot be forged outside the
  `authz` module. Every audit line carries `client`, `seq`, `authz`.
  Members are append-only in `session.json` (ADR 0016).
- **Session env snapshot:** `--env K=V` at run declares a session env;
  precedence: scrub < declared < computed; a request naming a declared key
  gets `E_ENV_LOCKED` (ADR 0017).
- **Leases, stop, archival:** `[session] idle_timeout` (duration string,
  default none). `hisn stop --session X` sets state stopped and keeps the
  dir. `ls --prune` archives `grants.jsonl` + `session.json` to
  `$XDG_STATE_HOME/hisn/audit/<id>.jsonl` (0600) before removing; `--purge`
  skips archival (ADR 0019). Idle expiry runs the same stop function as
  `hisn stop` (dir kept as `stopped`, audit `lease/expired`); a foreground
  `hisn run` then exits 143 with `hisn: session <name|id> stopped: idle for
  <d> (idle_timeout <d>)`. A stop racing the session end no longer removes
  the dir. `hisn ls --json` gains `dir`.
- **Lifecycle state:** `session.json` carries `state ∈ {creating, running,
  stopping, stopped, crashed}`.

### Known issues (0.4.1)
- `hisn run --detach` stays in the foreground instead of returning once the
  session is ready.
- Inside an attach, `ttyname()` fails (`tty: no such device`): the client's
  pty slave is not visible in the session's private `/dev/pts`. `isatty` is
  true (L20), so interactive programs work; programs that need the tty's
  name do not.
- `hisn ls --json` lacks the `clients` array and does not list a live
  attach under `execs`.
- CLIENTS is not zeroed on a stopped session.
- L56 and L58 remain host-only / documented checks (not automated in the
  leak suite).

### Changed
- Repository cleanup (no code change): process documents (plans, patches,
  host-run logs, the verification record) are removed from the tree; their
  decisions are in `docs/adr/`. The policy schema is regenerated from the
  struct (adds `landlock`, `shm`, `shm_size`, `tmp_size`). Example profiles use
  `/tmp/hisn-out` as `grantable_rw`, so they validate on a fresh host. CI builds
  the musl binary and validates the example profiles.

## [0.3.3] - 2026-11-06

### Fixed
- **Session DNS on systemd-resolved hosts.** The session's `/etc/resolv.conf`
  is now built from the host's non-loopback nameservers, else the
  systemd-resolved upstream file `/run/systemd/resolve/resolv.conf`, else the
  launch fails with `no usable DNS resolver …`. Loopback nameservers are never
  passed in, and an empty resolv.conf is never written. Evidence reported from a
  Fedora 45 host (hisn 0.3.2, wakil-dev rootfs): the session's resolv.conf was
  empty, `getent hosts example.com` returned rc=2, while `curl -sI https://1.1.1.1`
  returned HTTP/2 301. The host resolv.conf was the systemd stub (127.0.0.53)
  and the real upstreams were in `/run/systemd/resolve/resolv.conf`. The Fedora
  host itself was not re-run for this release. On the build host (non-loopback
  host resolv.conf) a `network = "host"` session showed the host nameserver
  with loopback dropped, and `getent hosts example.com` returned rc=0.
- **Rootfs sessions on `network = "host"` no longer fail with `no usable DNS
  resolver`** when the image's own `etc/resolv.conf` is empty (the wakil-dev
  image). The first version of this fix read only the image file for a rootfs
  session, so such a launch failed closed while the host had working
  resolvers. The precedence is now: `[net] nameservers`, then the host
  `/etc/resolv.conf`, then `/run/systemd/resolve/resolv.conf`, and the image's
  `etc/resolv.conf` only when neither host source has a usable nameserver. A
  populated image never shadows a working host resolver. The image file is read
  with `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), so a symlink in any
  component, including `etc`, is refused, and the upstream file is read
  from the real host, not from inside the image. Regression check: leak test
  L50 (runs when `HISN_TEST_ROOTFS` is set).

### Added
- **`[net] nameservers = ["ip", ...]`** (profile): replaces the derived resolver
  list. Empty, non-IP and loopback entries are rejected at `hisn profile validate`.
- **`hisn exec --no-tty`**: non-interactive exec with no pty. Stdin is
  `/dev/null`; stdout and stderr are client-owned pipes that the client copies to
  its own stdout and stderr, so the sandbox never receives the caller's terminal.
  `--tty --no-tty` is a usage error. The refusal for a terminal without either
  flag still applies and now names both options.
- **`mounts.ro` accepts `src:dst`** (ADR 0012): the host path `src` is bound
  read-only (`ro,nosuid,nodev`) at the in-session path `dst`. Same-path entries
  are unchanged. `dst` under `/run/hisn` or a runtime root, `dst` containing
  `..`, and `dst` colliding with another session mount are rejected at validate,
  naming the path. A symlinked `src` directory is resolved on the host.
- `policy validate` and `profile validate` now run the mount plan, so mount
  conflicts are refused at validate, not only at session start.
- Leak tests L47–L49 (`src:dst` mount, validate refusals, symlinked source).

## [0.3.2] - 2026-11-05

Hardening before the tag (same version):
- `rootfs import` moved to `rootfs_import`: streaming `tar` crate extraction with
  explicit hardening, unique staging, no-clobber / rename-aside `--replace`,
  `manifest.json` written without following archive links, option-like
  `--from-image` values refused.
- `[rootfs] name` that cannot be resolved is an error (it used to fall back to the
  host toolchain); a rootfs overlapping a writable mount, or with a symlinked
  `/etc`, is refused.
- `[home] persist` refuses fixed host trees, shared dirs, hisn's own state dirs and
  directories owned by someone else.
- ssh proxy rejects malformed SIGN_REQUESTs locally, caps clients, times out idle
  ones.

### Added
- **Persistent `$HOME`** (`[home] persist`, `--home-persist`): a profile may
  declare a persistent home directory that survives across sessions, bind-mounted
  rw at the same in-sandbox path. Refuse list (real `$HOME`, ancestors of
  `$HOME`, `/`, cwd, ancestors of cwd) enforced before any namespace exists. Risk
  label `home-persist` (Data). ADR 0009. Leak test L42.
- **Read-only rootfs** (`[rootfs] name|path`, `--rootfs-path`): a profile may
  declare a rootfs tree that replaces the host toolchain dirs (`/usr`, `/bin`,
  `/sbin`, `/lib`, `/lib32`, `/lib64`, `/opt`, `/nix`, `/etc`) inside the sandbox.
  All rootfs mounts are `ro, nosuid, nodev`. Host `/usr`, `/opt`, `/nix` are not
  visible when a rootfs is set. `hisn rootfs import|list|path|rm` subcommand with
  streaming extraction (via the `tar` crate — handles ustar prefix, GNU
  LongLink, and PAX extended headers) and hardening (strip setuid, reject
  traversal, reject hard links outside, reject symlink-then-write, skip
  devices, atomic staging). `hisn check` reports the rootfs store. Risk label
  `rootfs` (Trust). ADR 0010. Leak tests L43, L44, L46.
- **SSH agent T1** (`[ssh] agent = true`, `keys = [...]`): a filtering proxy that
  forwards only `REQUEST_IDENTITIES` and `SIGN_REQUEST`, rejects all mutations
  (`ADD`, `REMOVE`, `LOCK`, `UNLOCK`, `EXTENSION`), filters by fingerprint
  allowlist, and injects `SSH_AUTH_SOCK` into the scrubbed env. The host
  `SSH_AUTH_SOCK` is never mounted. Every forwarded sign request is logged
  (fingerprint, session id) — allowlist or not. The accept loop retries on
  `EMFILE`/`ENFILE`/`EAGAIN`. Risk label `ssh-agent` (Signing). ADR 0011.
  Leak test L45.

### Changed
- `Cargo.toml` version bumped to 0.3.2.
- CI: musl target (`x86_64-unknown-linux-musl`) added to the release workflow
  alongside the glibc build, with a `-musl` suffix in the asset name. Glibc
  remains the default download.

### Tests
- L42 (home-persist): persist dir created, cross-session persistence (file
  written in session A exists in B), symlink escape blocked, pre-0.3.2 home
  location fails, each refuse-list case (real `$HOME`, ancestor of `$HOME`,
  `/`, cwd, ancestor of cwd) rejected before any namespace exists, HOME env
  is the sandbox path, persist ≠ real `$HOME`.
- L43 (rootfs, with `HISN_TEST_ROOTFS`): host `/opt` marker not visible,
  host binary not executable, `/usr` mount shows `ro,nosuid,nodev` in
  mountinfo, remount cannot drop ro, username matches, `nosuid` enforced.
- L44 (rootfs import hardening, always runs): path traversal, absolute names,
  hard link escape, setuid stripping on a synthetic tar.
- L46 (rootfs symlink traps, with `HISN_TEST_ROOTFS`): symlink traps in
  `/usr/local/bin` and absolute symlinks to host `$HOME` do not reach host
  data.
- L45 (ssh-agent): two ed25519 keys; with `keys=[fp1]`: `ssh-add -l` shows
  only key1, key2 filtered, ssh-add (add) and ssh-add -D (remove all) from
  inside session fail, host agent still lists both keys, proxy socket absent
  after teardown; without `keys=`: both keys listed, add/remove still fail
  (skip if ssh-agent or ssh-add not found).

## [0.3.1] - 2026-11-03

### Fixed
- L17 signal race (7b162c7, 809da11): the control thread left `SIGCHLD`,
  `SIGTERM`, `SIGINT`, `SIGHUP` and `SIGWINCH` unblocked, so the kernel could
  deliver them to it and the main thread's `sigsuspend` was never woken (a
  detached supervisor hung after its init exited; seen on ubuntu-22.04 CI).
  The control thread now blocks them. 7b162c7 also made the L29 test and
  `profiles/docker-socket.toml` use `network = "none"` (host mode needs
  Landlock ABI >= 6, absent on ubuntu-22.04).
- Verification rows for CI and the host run: see `docs/VERIFICATION.txt` (removed from the tree after 0.3.3; the release tags carry it).
  The 0.3.0 tag points at afdccd0 and does not contain these fixes.

## [0.3.0] - 2026-11-03

### Added
- **Profiles** (`hisn-profile/v1`): an envelope around `hisn-policy/v1` that
  layers orchestration surface (services, forwards, host_services, docker tier,
  risk labels) on top of the isolation contract. `hisn run --profile <name|path>`
  resolves the profile by name (`$HISN_PROFILES/<name>.toml`, then built-in
  `profiles/<name>.toml` next to the binary) or path. `--profile` and `--policy`
  are mutually exclusive. Built-in profiles: `base` (the 0..2 sandbox),
  `wakil` (0.2 sandbox + `grantable_rw`). `hisn profile list|explain|validate`.
  A profile under the session cwd or a rw grant cannot satisfy `risk_ack`
  (`E_PROFILE_UNTRUSTED`); `./<name>.toml` is not in the search path
  (`E_PROFILE_NOTFOUND` with `$HISN_PROFILES` unset).
  A profile with no new tables yields the 0.2 mount plan (L25).
- **Risk labels**: every profile capability that widens the boundary carries a
  fixed label (`none`, `data`, `signing`, `host-exec`, `root-equivalent`,
  `kernel-surface`), computed by hisn from the capability. `hisn run` prints
  `RISK: <label> — <capability>` per widening capability at start unless
  `--quiet-risk`. `root-equivalent`, `signing`, `host-exec` require a matching
  `risk_ack` (`E_RISK_ACK_REQUIRED` / `E_RISK_ACK_MISMATCH`). An unknown
  `[[forward]]` socket without explicit `risk` is a load error. Labels are
  recorded in `risk.json` in the session dir and in `inspect --json`.
- **Socket forwarding** (`[[forward]]`): expose an existing host unix socket
  inside at `expose` via `open_tree(OPEN_TREE_CLONE)` + `move_mount`, read-only.
  `connect` works; `unlink` → `EROFS`/`EBUSY`; the host path is absent inside.
- **Host-side services** (`[[host_services]]`): hisn starts a host-side process
  as the user (no extra privilege), waits for readiness (socket/tcp/command,
  timeout default 15 s, fail closed), then forwards its socket. Stop = signal +
  grace + KILL at session end. Requires `risk_ack = "host-exec"`.
- **Docker T2** (`[docker] tier = "socket"`): raw `[[forward]]` of the Docker
  daemon socket with label `root-equivalent` and required `risk_ack =
  "root-equivalent"`. `tier = "proxy"` and `nested_userns = true` are rejected
  with `E_NOT_SUPPORTED` (0.4). Shipped: `profiles/docker-socket.toml`,
  `profiles/deploy-example.toml`. The socket dies with the session;
  containers the daemon started do not.
- **In-sandbox services** (`[[services]]`): start a long-lived process inside
  the sandbox through the exec helper chain (same confinement as the main
  command), before START. Readiness: socket stat (for paths under cwd) with
  timeout (default 15 s, fail closed). Stop: best-effort signal + grace + KILL
  (checks if the service is still alive before sleeping). `restart = "none"`
  only. `ls --json` and `inspect --json` gain a `services` array (state is
  evidence-based: `"ready"` after readiness, `"exited"` when the status socket
  closes). Shipped: `profiles/kvr-example.toml`. `hisn profile explain` prints
  a socket-hijack warning for each `[[services]]` entry with a `socket` field.

### Changed
- `sethostname` in init is now best-effort (some containers block it via seccomp
  even in a new UTS ns; the hostname is cosmetic, not a security boundary).
  A WARN line is logged when it fails.

### Removed (0.3.0 scope)
- `ready.command` and `ready.tcp` are not in the `[[services]]` schema
  (`ServiceReadinessSpec` uses `deny_unknown_fields`). `ready.command` would
  run on the host with the user's credentials while the risk label says `none`
  (P25); re-adding it through the exec helper chain is 0.3b work. `ready.tcp`
  is not available for in-sandbox services in 0.3 (use `ready.socket`).

### Tests
- L25 (profile base == 0.2 plan), L26 (profile under cwd → E_PROFILE_UNTRUSTED),
  L29 (docker-socket: RISK line, docker ps, missing risk_ack → load error),
  L31 (in-sandbox service: connectable, dies with session, no extra mounts),
  L36 (forward: connect, unlink EROFS/EBUSY, host path absent, other sockets
  invisible), L37 (host_service: socket at expose, connect works, host process
  gone after session end), L41 (service readiness timeout → fail closed).

## [0.2.2] - 2026-11-02

### Fixed
- **User name inside the sandbox.** 0.2.1 took the name for `/etc/passwd` and
  `/etc/group` from `$USER`, which a scrubbed launch environment (Wakil,
  `env -i`) does not have, so `id -un` and `echo $USER` showed `user`. The name
  now comes from `getpwuid_r(geteuid())` (fallback `user` only if the lookup
  fails or the name is unusable; `hisn run -v` logs why).

### Changed
- `USER` and `LOGNAME` are set in the sandbox environment, computed from that
  name, like `HOME`: never copied from the host environment, and `env.pass`,
  `env.set` and `exec` requests cannot override them (an `exec` request naming
  them is refused as a computed name). POLICY-SPEC and DESIGN §8 updated.
  A 0.2.1 policy yields the same mount plan. Differences: the two new
  variables; the content of the generated `/etc/passwd` / `/etc/group` (host
  login name instead of the placeholder `user` under a scrubbed launch
  environment); a policy that set `USER`/`LOGNAME` now loses to the computed
  value. Session start now queries the host user database once
  (`getpwuid_r`), which can be slow with an unreachable network backend.

### Tests
- Leak test L1c (`id -un`, `$USER`, `$LOGNAME`, `getent passwd` show the host
  user, also for a session started under `env -i`); unit tests for the lookup
  and fallback, stub generation and the computed names.

## [0.2.1] - 2026-11-02

### Added
- **`/dev/shm`** (`session.shm`, default `false`): optional tmpfs at `/dev/shm`
  with configurable size (`session.shm_size`, MiB, default 64). Default off =
  no `/dev/shm` (0.2 behavior).
- **`/tmp` size** (`session.tmp_size`, MiB, default 1024, range 16..=65536):
  replaces the hardcoded 1 GiB constant with a policy key.
- **`--ready-fd N`** on `hisn run`: after the session is live, writes `"ready\n"`
  to fd N and closes it. For programmatic readiness (Wakil).
- **Opaque exec ids**: every exec gets `exec_id = "e-<n>"` (monotonic, never
  reused). `signal` accepts `exec_id` (preferred) or `pid` (deprecated, kept
  for 0.2 clients); a recycled `pid` is rejected with `E_NOT_FOUND`.
- **Frozen `--json` schemas**: `hisn ls --json` and `hisn inspect --json` emit
  `{"schema":"hisn-ls/v1",…}` / `{"schema":"hisn-inspect/v1",…}`. `cwd`,
  `hostname`, `network` are included in `ls --json`.
- **`hisn ls --prune`**: remove stale session directories (no live
  supervisor). Stale = control socket refuses AND supervisor pid is gone or
  has a different starttime. Removal is fd-relative (`openat2` with
  `NO_SYMLINKS|NO_XDEV|BENEATH`), so a planted symlink is unlinked and never
  followed and a planted bind mount is never entered; it is owner-checked and
  confined to the one session directory.
- **Stale session cleanup on `hisn run --session-id X`**: if the dir is
  stale, remove it and proceed; if live, `E_EXISTS` stands.
- **Stale session cleanup on `hisn kill --session X`**: if stale, remove the
  dir and exit 0 with `"session X was stale; removed"`.
- **`supervisor.pid`** file in the session dir: written at start with the
  supervisor pid and starttime for stale-detection.
- **R5 ancestry retry** (OPEN-POINTS P16): `is_descendant_of` retries the
  whole `/proc/<pid>/status` walk on `ENOENT`/`ESRCH`/`EINTR` (3 attempts,
  50 ms apart). The retry targets the sandbox init (a specific pid), not
  "any pid 1".

### Changed
- **passwd/group stub** verified to use the host username (`HostFacts.username`
  from `$USER`); `id -un` inside the sandbox prints the host username.
- **init argv scrub**: after START, init overwrites its argv memory in place
  with `"hisn-init"` so the session id, policy path, and session dir do not
  appear in `/proc/1/cmdline` inside the sandbox. Best-effort.
- **musl ioctl casts** (OPEN-POINTS P22): ioctl request constants cast with
  `as _` so `x86_64`/`aarch64-unknown-linux-musl` compile. The musl target
  has not been leak-tested (stdlib not installed in the build sandbox).

### Known issues
- Pending from the external §14 review (OPEN-POINTS): align DESIGN §4.5 with §7
  on root-tmpfs renames; stop a continuous stream of spawns from starving a
  hard revoke.

## [0.2.0] - 2026-11-01

First release.

### Added
- **Sandbox sessions** (`hisn run`): user, mount, pid, ipc, uts and net
  namespaces; an empty tmpfs root entered with `pivot_root` and the old root
  detached; the working directory at the identical host path (rw), a read-only
  toolchain, private tmpfs `$HOME`, `/tmp` and `/run`. Anything else does not
  exist (ENOENT).
- **Confinement inside the sandbox:** all capabilities dropped, `no_new_privs`,
  a seccomp denylist (`mount`, `unshare`, `setns`, `open_tree`, `ptrace`, `bpf`,
  `io_uring`, `clone` with `CLONE_NEW*`, `clone3` answered with ENOSYS, ...),
  Landlock as a second write-restricting layer, a non-dumpable capless PID 1,
  rlimits, and an environment rebuilt from scratch (`env.pass` allowlist).
- **Grants** (`hisn grant`, `hisn revoke`, `hisn ls`, `hisn inspect`,
  `hisn kill`): the host-side supervisor adds and removes bind mounts in a
  running session through a control socket the sandbox cannot name or use.
  Grants end with the session. Soft revoke guarantees only that the path no
  longer resolves; `revoke --hard` kills every sandbox process.
- **`hisn exec`** (v0.2): run further commands in a running session, in the same
  namespaces, with the same confinement and the same grants, optionally on a
  pty (`--tty`, with resize). `hisn run --detach` starts a session that is only
  exec'd into. Confinement is re-applied on every exec (DESIGN §14).
- **Policy** (`hisn-policy/v1` TOML, `hisn policy validate`, JSON schema in
  `schemas/`), including `[landlock] scoped` (below).
- **`hisn check`**: host capability report (kernel, user namespaces, Landlock,
  seccomp, mount API); exit 2 when a required capability is missing.
- **Leak suite** (`make leaktest`, L1-L24): one `PASS|FAIL|SKIP|WEAK` line per
  check and a `RESULT:` line; non-zero exit on any FAIL. `make leaktest-log`
  writes a dated log with a header (commit, tree state, date, host, kernel,
  hisn version). `docs/VERIFICATION.txt` recorded what was run, where (removed from the tree after 0.3.3).
- Documentation: DESIGN, POLICY-SPEC, OPEN-POINTS, ROADMAP, WAKIL-INTEGRATION.

### Changed
- Landlock `signal` and `abstract_unix_socket` scoping is **off by default**
  (`[landlock] scoped = []`) so that one exec can signal processes started by an
  earlier exec of the same session (OPEN-POINTS P17). The filesystem ruleset,
  capabilities, `no_new_privs`, seccomp and environment scrubbing are
  unchanged. Opt in with `scoped = ["signal"]` and/or
  `scoped = ["abstract_unix_socket"]`.
- With `network = "host"` the abstract-unix-socket scope is always applied; only
  `--allow-host-abstract-sockets` removes it, and that is audited (found by the
  external §14 review; already enforced, now covered by leak test L24).

### Security
- `hisn exec` verifies fail-closed, before running anything, that the root it
  entered is the sandbox root (DESIGN D25).

[Unreleased]: https://github.com/treeol/hisn/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/treeol/hisn/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/treeol/hisn/releases/tag/v0.6.0
[0.5.1]: https://github.com/treeol/hisn/releases/tag/v0.5.1
[0.5.0]: https://github.com/treeol/hisn/releases/tag/v0.5.0
[0.4.3]: https://github.com/treeol/hisn/releases/tag/v0.4.3
[0.4.2]: https://github.com/treeol/hisn/releases/tag/v0.4.2
[0.4.1]: https://github.com/treeol/hisn/releases/tag/v0.4.1
[0.3.2]: https://github.com/treeol/hisn/releases/tag/v0.3.2
[0.2.0]: https://github.com/treeol/hisn/releases/tag/v0.2.0

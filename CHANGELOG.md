# Changelog

All notable changes to hisn are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released before
0.2.0, so that section describes everything that exists.

## [Unreleased]

## [0.2.1]

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
  has a different starttime. Removal is symlink-safe, mount-safe
  (`st_dev` check), owner-checked, and confined to the runtime root.
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

## [0.2.0]

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
  hisn version). `docs/VERIFICATION.txt` records what was run, where.
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

[Unreleased]: https://github.com/treeol/hisn/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/treeol/hisn/releases/tag/v0.2.0

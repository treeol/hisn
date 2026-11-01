# Changelog

All notable changes to hisn are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released before
0.2.0, so that section describes everything that exists.

## [Unreleased]

### Known issues
- The `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets do
  not compile (`src/init.rs` passes `u64` ioctl request constants where musl's
  `libc::ioctl` takes `c_int`). Release binaries are therefore glibc builds
  (OPEN-POINTS P22).
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

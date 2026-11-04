# Changelog

All notable changes to hisn are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released before
0.2.0, so that section describes everything that exists.

## [Unreleased]

## [0.3.2]

### Added
- **Persistent `$HOME`** (`[home] persist`, `--home-persist`): a profile may
  declare a persistent home directory that survives across sessions, bind-mounted
  rw at the same in-sandbox path. Refuse list (real `$HOME`, `/`, cwd, ancestors
  of cwd) enforced before any namespace exists. Risk label `home-persist` (Data).
  ADR 0009. Leak test L42.
- **Read-only rootfs** (`[rootfs] name|path`, `--rootfs-path`): a profile may
  declare a rootfs tree that replaces the host toolchain dirs (`/usr`, `/bin`,
  `/sbin`, `/lib`, `/lib32`, `/lib64`, `/opt`, `/nix`, `/etc`) inside the sandbox.
  All rootfs mounts are `ro, nosuid, nodev`. Host `/usr`, `/opt`, `/nix` are not
  visible when a rootfs is set. `hisn rootfs import|list|path|rm` subcommand with
  extraction hardening (strip setuid, reject traversal, reject hard links outside,
  skip devices, atomic staging). `hisn check` reports the rootfs store. Risk label
  `rootfs` (Data). ADR 0010. Leak tests L43, L44.
- **SSH agent T1** (`[ssh] agent = true`, `keys = [...]`): a filtering proxy that
  forwards only `REQUEST_IDENTITIES` and `SIGN_REQUEST`, rejects all mutations
  (`ADD`, `REMOVE`, `LOCK`, `UNLOCK`, `EXTENSION`), filters by fingerprint
  allowlist, and injects `SSH_AUTH_SOCK` into the scrubbed env. The host
  `SSH_AUTH_SOCK` is never mounted. Risk label `ssh-agent` (Signing). ADR 0011.
  Leak test L45.

### Changed
- `Cargo.toml` version bumped to 0.3.2.
- CI: musl target (`x86_64-unknown-linux-musl`) added to the release workflow
  alongside the glibc build, with a `-musl` suffix in the asset name. Glibc
  remains the default download.

### Tests
- L42 (home-persist): host `$HOME` not visible, persist dir reachable only at the
  mounted path, symlink inside persist does not escape, file written in session A
  exists in session B, invalid paths rejected.
- L43 (rootfs, with `HISN_TEST_ROOTFS`): host `/usr` not visible, host-only binary
  not executable, rootfs write fails, setuid stripped, symlink does not reach host,
  username matches.
- L44 (rootfs import hardening, always runs): path traversal, absolute names, hard
  link escape, setuid stripping on a synthetic tar.
- L45 (ssh-agent): `ADD_IDENTITY`/`REMOVE_ALL` fail, allowlist filters identities,
  sign for non-listed key fails, host `SSH_AUTH_SOCK` not visible, proxy socket
  disappears with teardown, `ssh-keygen -Y sign` succeeds (skip if no ssh-agent).

## [0.3.1]

### Fixed
- L17 signal race (7b162c7, 809da11): the control thread left `SIGCHLD`,
  `SIGTERM`, `SIGINT`, `SIGHUP` and `SIGWINCH` unblocked, so the kernel could
  deliver them to it and the main thread's `sigsuspend` was never woken (a
  detached supervisor hung after its init exited; seen on ubuntu-22.04 CI).
  The control thread now blocks them. 7b162c7 also made the L29 test and
  `profiles/docker-socket.toml` use `network = "none"` (host mode needs
  Landlock ABI >= 6, absent on ubuntu-22.04).
- Verification rows for CI and the host run: see `docs/VERIFICATION.txt`.
  The 0.3.0 tag points at afdccd0 and does not contain these fixes.

## [0.3.0]

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
  `profiles/deploy-smaragd-example.toml`. The socket dies with the session;
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

## [0.2.2]

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

[Unreleased]: https://github.com/treeol/hisn/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/treeol/hisn/releases/tag/v0.3.2
[0.2.0]: https://github.com/treeol/hisn/releases/tag/v0.2.0

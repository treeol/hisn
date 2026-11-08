> Historical: the original build brief, kept for its invariants. DESIGN.md records where the implementation deviates; current behaviour is in [DESIGN.md](DESIGN.md) and [sessions.md](sessions.md).

# hisn — build brief (authoritative)

Saved verbatim-in-substance from the user's brief so later sessions have the
binding text in-repo. Where this file and DESIGN.md disagree, DESIGN.md must
carry an explicit "deviation" note; the DO NOT ALTER block always wins.

## What hisn is

A daemonless, rootless, single-binary Linux sandbox for AI coding agents,
written in Rust. It replaces Docker as the sandbox backend of Wakil (Go agentic
coding assistant). It keeps Docker's *isolation* (namespaces, pivot_root,
seccomp, capabilities, Landlock) and drops Docker's *ecosystem* (images,
registry, daemon, OCI bundles, network stack). The sandboxed process sees
exactly:

1. its working directory, mounted at the identical host path (path parity), rw
2. a read-only toolchain (/usr, /bin, /sbin, /lib*, /etc with secrets masked)
3. a private tmpfs $HOME and /tmp
4. paths the host side explicitly **grants** during the session, ro or rw

Everything else does not exist inside the sandbox — not "permission denied",
but ENOENT. Grants live only as long as the session and vanish when it ends.
hisn is Wakil-agnostic: the CLI/contract must be usable by any agent.

## DO NOT ALTER (binding invariants)

1. **Deny by non-existence.** Root is an empty tmpfs; `pivot_root` into it;
   old root unmounted (MNT_DETACH). The host filesystem is unreachable, not
   merely unreadable. Reason: a Landlock-only design leaks path existence and
   a single policy bug exposes the host.
2. **Only the supervisor can mount.** Inside the sandbox: all caps dropped,
   `no_new_privs`, seccomp blocks mount/umount/pivot_root/unshare/setns/
   open_tree/move_mount/fsopen/fsmount/ptrace/bpf/keyctl/io_uring_*/
   perf_event_open/kexec*/reboot/swapon/init_module. Grants are performed from
   the host-side supervisor only. Reason: the agent must never be able to widen
   its own view.
3. **Grants die with the session.** Grants are bind mounts in the session's
   mount namespace and nothing else; no persistent state makes a grant survive
   PID-1 exit. Reason: "temporary" must be true by construction, not by cleanup
   code.
4. **Environment is scrubbed.** Only PATH, HOME, TERM, LANG, LC_*, TZ, plus an
   explicit `env.pass` allowlist from the policy reach the sandbox. Reason:
   host secrets commonly live in env.
5. **No images, no OCI, no Docker, no daemon in v0.** But every policy
   construct must be expressible as an OCI runtime-spec `config.json`
   (mounts[], linux.namespaces, linux.seccomp, process.capabilities). Document
   the mapping in POLICY-SPEC.md. Reason: OCI conformance is v2; don't design
   it out now.
6. **Leak test suite is the acceptance criterion** (L1–L11). If the build
   environment cannot run it (user namespaces are blocked in this Wakil
   sandbox — confirmed by recon), say so explicitly, do NOT fabricate or
   simulate results, and hand the user the exact command to run on the host.
7. **Latest stable Rust** via rustup, edition 2024. No MSRV pinned below
   current stable.

## Host assumptions (`hisn check` verifies; don't assume)

- Linux kernel ≥ 5.12 (open_tree/move_mount, Landlock ABI ≥1; ABI 3+ preferred)
- unprivileged user namespaces enabled on the *target* host (not this sandbox)
- seccomp available
- No root, no setuid helper, no CAP_SYS_ADMIN on the host.

## Architecture (decided)

**Two processes per session:**

- `hisn` **supervisor** (host side, unprivileged): parses policy, creates the
  session dir, forks the sandbox child, owns the control socket, performs
  grants/revokes, logs, reaps.
- **sandbox init** (PID 1 of the new PID ns): `unshare(CLONE_NEWUSER|NEWNS|
  NEWPID|NEWIPC|NEWUTS[|NEWNET])`, write uid_map/gid_map (single mapping of
  the caller's uid/gid → same ids; if `newuidmap` subid ranges exist, use them
  for a 65536 range so `useradd`-style tools work — detect, don't require),
  set mount propagation private, build root in tmpfs, bind-mount allowlist,
  mask secrets, mount /proc (new), /dev (null, zero, full, random, urandom,
  tty, ptmx + devpts), /tmp, $HOME, `pivot_root`, apply Landlock ruleset
  (second layer: same allowlist, ro/rw as policy), set no_new_privs, drop all
  caps (bounding + ambient + inheritable), install seccomp filter, exec the
  command. Forward SIGTERM/SIGINT to the child process group; exit with the
  child's status.

**Grant mechanism (supervisor side):** `open_tree(src, OPEN_TREE_CLONE |
(ro ? none : AT_RECURSIVE))` on the host → fork a single-threaded helper →
`setns(userns_fd)` (caller is the ns creator, so it gains full caps there) →
`setns(mntns_fd)` → `mkdir -p` the mountpoint inside the sandbox root →
`move_mount(tree_fd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH)` → for ro:
`mount_setattr(MOUNT_ATTR_RDONLY)` on the detached tree before moving. Revoke
= `umount2(target, MNT_DETACH)` via the same helper path. Supervisor keeps
`/proc/<init-pid>/ns/{user,mnt}` fds open for the session lifetime. The grant
target is always the identical host path.

**Control socket:** unix socket at `<session-dir>/control.sock`,
newline-delimited JSON: `{"op":"grant","path":"/abs","mode":"ro|rw"}`,
`{"op":"revoke","path":"/abs"}`, `{"op":"list"}`, `{"op":"inspect"}` (dumps the
sandbox's mountinfo), `{"op":"kill","signal":"TERM"}`. Socket mode 0600. v0
contract; v1 layers an E2B-shaped HTTP API and an MCP server on top.

**Session dir:** `$XDG_RUNTIME_DIR/hisn/<session-id>/` (fallback
`/tmp/hisn-$UID/<id>`), 0700, containing `control.sock`, `grants.jsonl`
(append-only audit log: ts, op, path, mode, result), `policy.resolved.toml`,
`home/` only if the policy asks for a persistent home.

**Network (v0):** `network = "none"` (default; new net ns, loopback up, no
interfaces) or `"host"` (no net ns). Egress allowlist proxy is v1.

**Toolchain mounts (default allowlist, ro):** `/usr`, `/bin`, `/sbin`, `/lib`,
`/lib32`, `/lib64`, `/etc`, `/opt` (if present), `/nix` (if present) — only
those that exist. Masked inside `/etc` with an empty tmpfs or /dev/null bind:
`/etc/ssh`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d`,
`/etc/krb5*`, `/etc/*.key`, `/etc/*.pem` outside `/etc/ssl`. Generate
`/etc/passwd` and `/etc/group` stubs for the mapped uid only. `/sys` not
mounted. `/run` is a fresh tmpfs. `/var` not mounted.

**$HOME:** tmpfs by default; `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_HOME`, `CARGO_HOME`, `GOMODCACHE`, `GOCACHE`, `npm_config_cache`,
`PIP_CACHE_DIR` all point under it. Policy `home = "tmpfs" | "/host/path"`
(persistent, rw bind) for warm caches.

## Policy file — `hisn-policy/v1` (TOML)

```toml
version = "hisn-policy/v1"

[session]
cwd = "."                 # resolved to absolute, mounted at identical path, rw
home = "tmpfs"            # or an absolute host path
network = "none"          # "none" | "host"
hostname = "hisn"

[mounts]                  # extra allowlist beyond the toolchain defaults
ro = ["/opt/toolchains"]
rw = []
mask = []                 # extra paths to mask inside allowed trees

[env]
pass = ["GOFLAGS", "RUSTFLAGS"]   # names copied from host env if set
set  = { CI = "1" }

[seccomp]
extra_deny = []           # syscall names added to the built-in denylist

[limits]                  # v0: enforced via setrlimit only
nofile = 65536
nproc  = 4096
```

Ship a JSON Schema (`schemas/hisn-policy.v1.json`, generated with `schemars`)
and validate on load. Unknown keys are errors.

## CLI

```
hisn run   [--policy hisn.toml] [--cwd DIR] [--session-id ID] [--network none|host]
           [--grant PATH[:ro|rw]]... -- CMD [ARGS...]
hisn grant   --session ID PATH [--rw]
hisn revoke  --session ID PATH
hisn ls      [--session ID]
hisn inspect --session ID
hisn kill    --session ID [--signal S]
hisn check
hisn policy  validate [FILE] | schema
```

`hisn run` passes stdin/stdout/stderr through unchanged (TTY if attached:
allocate a pty inside the sandbox via /dev/ptmx and forward resize), propagates
the exit code, and prints nothing of its own to stdout. Logs to stderr behind
`-v`.

## Crates (decided)

`rustix` (raw `syscall` for open_tree/move_mount/mount_setattr if missing),
`landlock`, `seccompiler` (pure Rust), `clap` (derive), `serde` + `toml` +
`schemars`, `nix` only if rustix lacks something, `anyhow` + `thiserror`,
`tracing`. No tokio in v0 — control socket is a blocking thread.

## Repo layout

```
Cargo.toml  (single crate `hisn`, bin + lib)
src/main.rs, cli.rs, policy.rs, session.rs, supervisor.rs, init.rs, rootfs.rs,
    mounts.rs, grant.rs, landlock.rs, seccomp.rs, env.rs, control.rs, check.rs
schemas/hisn-policy.v1.json
tests/leak/
docs/DESIGN.md, POLICY-SPEC.md, ROADMAP.md, WAKIL-INTEGRATION.md
Makefile  (build, test, leaktest, check)
README.md, LICENSE (Apache-2.0), hisn.toml (example policy)
```

## Leak test suite (`make leaktest`, tests/leak/)

Each test runs a probe inside `hisn run` and asserts from the host:

- L1 stat/open of `/home`, `/root`, `/tankz`, `/var`, `$HOST_HOME/.ssh`,
  `$HOST_HOME/.aws`, `/etc/shadow`, `/etc/ssh` → ENOENT (or empty for masks)
- L2 `/proc/1/root`, `/proc/self/root` resolve to sandbox root; host PIDs invisible
- L3 `mount`, `unshare -m`, `nsenter`, `ptrace` of own child → killed/EPERM
- L4 env: a host var not in `pass` is absent; secrets from host env absent
- L5 cwd rw, toolchain ro (`touch /usr/x` → EROFS)
- L6 grant ro → readable, write → EROFS; grant rw → writable; revoke → ENOENT;
  session end → grant mountpoint gone from host view (host mount table unchanged)
- L7 `network = "none"` → connect to 127.0.0.1 ok, any external addr → ENETUNREACH
- L8 `hisn inspect` mount table equals policy-derived expectation exactly
  (no extra mounts)
- L9 symlink escape: a symlink inside cwd pointing to `/etc/shadow` → ENOENT
- L10 `/dev` contains only the listed nodes; `/sys` absent
- L11 two concurrent sessions can't see each other's session dirs or grants

## Phases

- **Phase 0 — recon.** `hisn check` first; run here; if userns unavailable,
  state it, continue building, mark leaktest "run on host".
- **Phase 1 — docs first.** DESIGN.md (with sequence diagrams for session start
  and grant), POLICY-SPEC.md (schema, semantics, OCI mapping table), ROADMAP.md
  (v1: E2B-shaped HTTP API on unix socket, MCP server with exec/read_file/
  write_file/grant/revoke, egress proxy with allowlist, cgroup v2 limits; v2:
  OCI runtime-spec conformance), WAKIL-INTEGRATION.md (Wakil's Go side execs
  `hisn run`, maps edit-capability tiers to ro/rw grants, writes `.secrets/` as
  an rw grant).
- **Mashūra round 1** on DESIGN.md + POLICY-SPEC.md. Question: "What in this
  design lets a sandboxed process see, modify, or retain access to anything
  outside its granted set, now or after revoke?" Incorporate only BLOCKING
  findings (demonstrable escape, leak, or grant persistence); list the rest in
  docs/OPEN-POINTS.md.
- **Phase 2 — implement** in order: policy → check → rootfs/mounts → init
  (pivot_root, caps, no_new_privs) → seccomp → landlock → env → supervisor +
  control socket → grant/revoke → CLI → pty passthrough. Commit per module with
  `cargo clippy -D warnings` and `cargo fmt` clean. Unit tests for policy
  parsing, env scrubbing, mount-plan derivation, seccomp filter contents.
- **Phase 3 — leak tests.** tests/leak via `make leaktest` (here if possible,
  otherwise document the host command).
- **Mashūra round 2** on implementation + test results. Question: "Where does
  the code deviate from DESIGN.md, and which leak test is weaker than its
  claim?" Same triage. Max two rounds total — no third.
- **Phase 4 — close-out.** README (install `cargo install --path .`,
  quickstart, security model in five sentences). Final report: what works, what
  was verified here vs. on host, open points, exact host commands.

## Working rules

- Never silently drop an invariant from the DO NOT ALTER block; if one is
  impossible on this host, stop and report.
- No `sudo`, no setuid, no capabilities on the binary — if a step seems to need
  them, the design is wrong; report instead of working around.
- Prefer reading bubblewrap's source as a reference for the namespace/
  pivot_root sequence; do not vendor or wrap it.
- Keep v0 to Linux x86_64 + aarch64. No macOS.

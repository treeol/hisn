# hisn — design

Status: current as of hisn 0.3.3. §1–§14 describe the sandbox core (0.2 exec
included); §15–§19 describe the 0.3 orchestration layer. The decisions behind
each part are in [`docs/adr/`](adr/README.md). Binding input: `docs/BRIEF.md`
(the DO NOT ALTER block there always wins). §12 records where working the
design through forced a refinement from the brief.

Items marked **[HOST-VERIFY]** cannot be exercised in an unprivileged build
environment (user namespaces and the mount API are blocked there) and must be
confirmed by `make leaktest` on a real host. The leak suite is the acceptance
test for the isolation claims; see the README, "Verifying a build".

## 1. Goals and non-goals

Goal: a sandboxed process sees exactly (1) its cwd at the identical path, rw;
(2) a read-only toolchain; (3) private tmpfs `$HOME`, `/tmp`, `/run`; (4) paths
granted by the host side during the session. Everything else **does not
exist** (ENOENT), and grants end with the session.

Non-goals (v0): protecting against kernel exploits (userns + seccomp +
Landlock reduce, not remove, kernel attack surface); resource-exhaustion
protection beyond rlimits (cgroups are v1); confidentiality of data the agent
is *allowed* to read (it may copy granted data into cwd); terminal-escape
safety of the user's terminal; network isolation when `network = "host"`.

Trust model: the **host side** (the user, or Wakil) is trusted: it writes the
policy and issues grants. The **sandboxed command** is hostile.

## 2. Processes and namespaces

```
 host userns/mntns (the user's login session)
 └─ hisn run  (single-threaded at this point)
     │  unshare(NEWUSER|NEWNS)  → userns S, mntns copy of the host tree
     │  (single-id map uid→uid). Mounts made in S never reach the host.
     └─ supervisor  (this process, lives in S)
         ├─ control thread  (started AFTER all clone/unshare work)
         ├─ helper  (forked once after READY, before any thread; joins only the sandbox mntns)
         └─ sandbox init = PID 1 of new pidns
              clone(NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS[|NEWNET])  → userns U ⊂ S
              └─ command (child of init, new session, no caps, NNP, seccomp)
```

Why the supervisor lives in its own userns **S** (refinement of the brief):
`open_tree(OPEN_TREE_CLONE)` and `mount_setattr` require `CAP_SYS_ADMIN` over
the caller's mount namespace. An unprivileged process in the host userns has
none, so the brief's grant sequence cannot start there. In S the supervisor
holds caps *only over S and its own mount-ns copy*; S has no authority over
anything on the host (no root, no setuid helper, no host capability).
Consequence: anything the supervisor mounts is invisible to the host, and
"host mount table unchanged" (L6) holds by construction. **[HOST-VERIFY]**
that `open_tree(OPEN_TREE_CLONE)` works in S on the target kernels.

S and U are both single-id maps (`uid→uid`, `gid→gid`, `setgroups=deny`).
Files owned by other host users appear as `nobody`. The 65536-id range via
`newuidmap` is detected by `hisn check` but **not used** by the mapping code; every
session uses a single-id map (§12, D4).

The supervisor must be single-threaded for `unshare(CLONE_NEWUSER)`; all
namespace work therefore happens before the control thread starts, and the one
grant helper is forked at that point (never `fork()` from the threaded
supervisor afterwards).

## 3. Sandbox init (PID 1) — build order

All steps run in U with full caps *inside U only*. Any failure aborts the
session before the command runs (fail closed).

1. Write `setgroups=deny`, `uid_map`, `gid_map` (own single id); then wait for the supervisor's `GO` (it has opened `/proc/<init>/ns/*` by then).
2. `prctl(PR_SET_PDEATHSIG, SIGKILL)` — init dies if the supervisor dies, so
   no sandbox outlives its supervisor (invariant 3). (Init is marked
   `PR_SET_DUMPABLE=0` only at the end of setup, step 12; see §6.)
3. `mount(NULL, "/", MS_REC|MS_PRIVATE)` — no propagation in either direction.
4. Mount tmpfs (`size=4m`) on `<session-dir>/root` (an empty dir created by the
   supervisor, 0700). This becomes the new root `R`; create `R/.old`.
5. Build mount plan (§4) — binds are created with `open_tree(CLONE|RECURSIVE)`
   + `mount_setattr` + `move_mount` (or `mount(MS_BIND|MS_REC)` followed by
   `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)`), **never** the
   `MS_REMOUNT|MS_BIND|flags` form (fails on locked mount flags inherited
   from the host).
6. Mount new `/proc` (see §4.3 caveat), `/dev` tmpfs + device bind-mounts +
   new devpts, `/tmp`, `/run`, `$HOME` tmpfs (or the persistent home bind).
7. Generate `/etc/passwd`, `/etc/group` (mapped uid only; the user name is
   the host's `getpwuid_r(euid)` name, §8), `/etc/resolv.conf`
   (only for `network = "host"`; 0.3.3: built by `mounts::build_resolv_conf`
   from the host file's non-loopback nameservers, else
   `/run/systemd/resolve/resolv.conf`, else `[net] nameservers`; never empty,
   launch fails instead) in `R/.stage`, bind over the `/etc` entries,
   unlink the staging names (the bind keeps the inode alive).
8. `sethostname`; for `network = "none"` bring `lo` up (`SIOCSIFFLAGS`).
9. `chdir(R)`, `pivot_root(R, R/.old)`, `chdir("/")`, `umount2("/.old",
   MNT_DETACH)`, `rmdir("/.old")` (invariant 1). Close every fd > 2 that is
   not the control channel (`close_range`).
9b. Scrub argv: overwrite init's own argv memory with `hisn-init` (zero-filled
    after it) and `PR_SET_NAME`, so the session id, policy path and session
    dir are not readable from `/proc/1/cmdline` inside the sandbox. This runs
    after `GO` and **before** Landlock, `PR_SET_DUMPABLE=0` and the capability
    drop, because it writes `/proc/self/mem`, which Landlock (no write rule for
    `/proc`) and a non-dumpable process both refuse (L34).
10. Apply Landlock (§7), `setrlimit`s, `RLIMIT_CORE=0`, fresh session keyring.
11. `PR_SET_NO_NEW_PRIVS`; clear ambient, drop **bounding**, clear
    inheritable/permitted/effective (**init itself ends up capless**, §6);
    set `SECBIT_NOROOT|NO_SETUID_FIXUP|KEEP_CAPS_LOCKED`.
12. Install seccomp (§5) on init; signal "ready" to the supervisor.
13. `fork()`: child does `setsid()`, wires stdio / pty slave, `chdir(cwd)`,
    scrubs env (§8), `execve(command)`. Seccomp/NNP/Landlock are inherited.
14. Init reaps all children (it is PID 1), forwards `SIGTERM/SIGINT/SIGHUP`
    to the command's process group, and exits with the command's status
    (`128+sig` if signalled). When init exits the kernel destroys the pidns
    and kills every remaining process in it.

### Session start sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as caller (Wakil / shell)
    participant S as hisn supervisor (in userns S)
    participant I as sandbox init (PID 1, userns U)
    participant C as command

    W->>S: hisn run --policy p.toml -- cmd
    S->>S: close fds >2, parse+validate policy, resolve paths
    S->>S: refuse paths overlapping the hisn runtime dir (§9)
    S->>S: create session dir 0700, control.sock (not yet accepting)
    S->>S: unshare(NEWUSER|NEWNS), write S maps
    S->>I: clone(NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS[|NEWNET])
    S->>S: open /proc/I/ns/{user,mnt} (kept for the session)
    I->>I: write U maps, PDEATHSIG, rprivate, tmpfs root
    I->>I: mounts, /proc /dev /tmp /run $HOME, masks, stubs
    I->>I: pivot_root, umount .old, landlock, caps drop, NNP, seccomp
    I-->>S: ready (+ pty master fd via SCM_RIGHTS if pty mode)
    S->>S: write policy.resolved.toml, start control thread
    I->>C: fork; setsid; scrub env; execve
    C-->>W: stdio passthrough (or pty relay)
    C->>I: exit(status)
    I-->>S: exit(status)  (pidns dies, all procs killed)
    S->>S: close ns fds FIRST, then cleanup session dir
    S-->>W: exit(status)
```

## 4. Filesystem view

### 4.1 Mount plan (pure function of the resolved policy)

`mounts::plan(&ResolvedPolicy, &HostFacts) -> Vec<MountOp>` is deterministic
and unit-tested; `hisn inspect` output must equal it exactly (L8). Order:

| # | target | source | flags |
|---|--------|--------|-------|
| 1 | `/usr /bin /sbin /lib /lib32 /lib64 /opt /nix` (only those existing on host) | same host path | recursive bind, **recursive ro** |
| 1b | `/etc` — **not** a bind of the host `/etc`: a tmpfs holding one bind (or recreated symlink) per *top-level entry that exists at session start and is not masked* (§4.2) | `/etc/<entry>` | recursive bind, recursive ro |
| 2 | policy `mounts.ro[]` | same path | recursive bind, recursive ro |
| 3 | `/tmp` | tmpfs `size=1g,mode=1777` | nosuid,nodev |
| 4 | `/run` | tmpfs `size=64m,mode=0755` | nosuid,nodev |
| 5 | `$HOME` (`/run/hisn/home`, §4.4) | tmpfs `size=1g,mode=0700` or rw bind of `home` path | nosuid,nodev |
| 6 | cwd (identical path) | host cwd | recursive bind, rw |
| 7 | policy `mounts.rw[]`, initial `--grant`s | same path | bind (non-recursive unless stated), rw/ro as given |
| 8 | masks (§4.2) | `/dev/null` bind (files) / empty ro tmpfs (dirs) | ro |
| 9 | `/proc` (new), `/dev` + devices + devpts | — | see §4.3 |

Rules: ancestors of any mount target are created in the root tmpfs as empty
directories (mode 0555-looking, but see §4.5). A target equal to or inside
`/tmp`, `/run` is created on top of the tmpfs (so a cwd under `/tmp` works);
a cwd equal to `/tmp` replaces the private `/tmp`. Duplicates and
parent/child ro/rw conflicts are resolved by "deeper target wins, later table
row wins on equal depth"; a *shallower rw bind that would cover a mask* is a
policy error (§9, rule R3).

Ancestors of cwd are visible as empty directories (`/home`, `/home/u`, … if
cwd is `/home/u/proj`). That is an unavoidable consequence of path parity.
L1 therefore asserts "ENOENT unless the path is an ancestor of cwd or of a
grant" and the leak tests run with cwd under host `/tmp`.

### 4.2 Masks and the `/etc` view (round-1 BLOCKING fix, D12)

`/etc` is an **allowlist built at start, not a live bind**: the sandbox `/etc`
is a small tmpfs; for every *top-level* entry of the host `/etc` that exists at
session start and is not masked, the plan adds a ro bind of that entry (symlinks
are recreated as symlinks with the same target text; dangling or escaping
targets simply do not resolve in the sandbox). A secret file created in the
host `/etc` *after* start therefore does not exist in the sandbox (deny by
non-existence, invariant 1), and a masked name is omitted entirely (ENOENT,
which L1 accepts for masks).

Default masks, expanded once against the host `/etc` top level:
`ssh shadow shadow- gshadow gshadow- sudoers sudoers.d krb5* *.key *.pem`
(top-level only), plus `ssl/private` (a *nested* mask, so `ssl` is bound
recursively and `ssl/private` is covered by an empty ro tmpfs). Policy
`mounts.mask` entries inside other allowed trees (cwd, `mounts.*`) are applied
as: file → bind of the sandbox `/dev/null`; directory → empty ro tmpfs.
`/etc/passwd`, `/etc/group` are generated stubs (§3 step 7), never bound from
the host.

Residual (OPEN-POINTS P8): *nested* files created later inside a bound `/etc`
directory (e.g. `/etc/foo.d/x.key`) are visible, since only the top-level
secret globs of the brief are masked; the same applies to later files inside
any recursively bound tree (cwd, `mounts.*`) — those trees are the user's
explicit grant.

### 4.3 /proc, /dev, /sys

* `/proc`: a **new** procfs mounted in the new pidns, so host PIDs do not
  exist and `/proc/1/root`, `/proc/self/root` resolve to the sandbox root
  (L2). Afterwards `/proc/sys` is remounted ro and `/proc/kcore`,
  `/proc/keys`, `/proc/latency_stats`, `/proc/timer_list`, `/proc/sched_debug`,
  `/proc/acpi`, `/proc/scsi` are masked (file → `/dev/null`, dir → empty ro
  tmpfs) and `/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`,
  `/proc/sysrq-trigger` are bound onto themselves read-only (runc's set, with
  the latter group read-only rather than masked). Only `ENOENT` counts as
  "absent on this kernel"; any other error aborts setup. **Caveat [HOST-VERIFY]:** the kernel refuses to mount
  procfs inside a userns when the *inherited* mount tree already has
  over-mounted procfs (typical inside Docker: masked `/proc/kcore`, …). In that
  case hisn **fails closed** with a clear error; it never falls back to
  rbind-ing the host `/proc` (that would expose host PIDs). `hisn check`
  gains a "procfs-in-userns" probe in Phase 2.
* `/dev`: tmpfs with exactly `null zero full random urandom tty` (bind-mounted
  from the host nodes, since mknod is impossible), `ptmx → pts/ptmx`, a **new**
  devpts instance (`newinstance,ptmxmode=0666,mode=0620`), and the symlinks
  `fd stdin stdout stderr → /proc/self/fd[/N]`. No `/dev/shm` (OPEN-POINTS).
* `/sys`: not mounted. `/var`: not mounted.

### 4.4 $HOME and caches

`$HOME` is **not** at the host's `$HOME` path (that would materialise `/home`
for every session). It is `/run/hisn/home` (tmpfs, or a rw bind of
`session.home`). `XDG_*`, `CARGO_HOME`, `GOMODCACHE`, `GOCACHE`,
`npm_config_cache`, `PIP_CACHE_DIR` are set to subpaths of it. Toolchains that
live under the host `$HOME` (rustup, nvm, …) must be declared in
`mounts.ro`.

### 4.5 The root tmpfs stays writable (decision)

The root is owned by the single mapped uid, so ro-ness could only come from
the mount flag, and the grant helper must create mountpoints later. What an
agent can do to a writable root: create ≤4 MiB of files/dirs, rename
*non-mountpoint* ancestors. Neither widens its view. Because renames could
break path-based revoke, **revoke never resolves a path** (§6, §10).

## 5. Seccomp

Denylist on top of "no caps + NNP + userns" (defence in depth; default action
allow). Built with `seccompiler`; tests assert the compiled filter contents.

* **Invariant-2 list** (kill-process or EPERM as noted in code): `mount umount
  umount2 pivot_root chroot unshare setns open_tree move_mount fsopen fsconfig
  fsmount fspick mount_setattr ptrace bpf keyctl add_key request_key
  io_uring_setup io_uring_enter io_uring_register perf_event_open kexec_load
  kexec_file_load reboot swapon swapoff init_module finit_module delete_module`.
* **Additions found necessary** (§12 D9): `process_vm_readv process_vm_writev
  pidfd_getfd kcmp open_by_handle_at name_to_handle_at userfaultfd quotactl
  acct lookup_dcookie syslog settimeofday clock_settime clock_adjtime adjtimex
  iopl ioperm personality` (+ arch-specific legacy), and `ioctl` with
  `TIOCSTI`/`TIOCLINUX`/`TIOCSETD`.
* **clone/clone3:** `clone` is denied when any `CLONE_NEW*` bit is set in
  arg0; **`clone3` returns ENOSYS** (its flags live in user memory and cannot
  be filtered; glibc falls back to `clone`). Without this, nested user
  namespaces would bypass the `unshare` rule.
* **ABI:** the filter pins the native `AUDIT_ARCH`; on x86_64 any syscall
  number with the x32 bit (`>= 0x40000000`) is denied (denylist bypass).
* `extra_deny` from the policy is appended; unknown names are policy errors.

## 6. Capabilities, init hardening, and what the command can reach

* The command has **no capabilities** in any set (bounding dropped, so even a
  setuid-root binary cannot regain them), NNP set, securebits locked.
* **Init is also capless and non-dumpable** after step 11. This is deliberate:
  the command shares the pidns with init. If init kept `CAP_SYS_ADMIN` the
  command could write `/proc/1/mem` (same uid) and become a privileged
  process in U (umount the masks, remount rw…). Init needs no caps after
  setup because grants use the supervisor's `setns`, not init's authority.
  `PR_SET_DUMPABLE=0` additionally makes `/proc/1/{mem,environ,exe,fd,…}`
  unopenable and blocks ptrace/`process_vm_*`.
* The supervisor and helpers are outside the pidns and invisible; the control
  socket lives only in the session dir, which is never mounted (§9).
* Inherited fds: the supervisor closes every fd > 2 at process start; init
  closes everything but the control channel before `execve`; all internal fds
  are `O_CLOEXEC`.

## 7. Landlock (second layer)

Mounts are the primary boundary; Landlock narrows what a mount-plan bug could
expose. Constraint that shapes it: **a Landlock domain is fixed at
`restrict_self` and cannot be extended by the supervisor**, but grants arrive
later, at arbitrary paths that do not exist yet.

Ruleset (best-effort ABI, `hisn check` reports the ABI; ≥3 preferred):

* handled: all fs rights supported by the ABI;
* allow read/exec/readdir beneath `/` (the path walk crosses mounts, so
  later **ro grants are covered automatically**);
* allow write rights beneath: cwd, `$HOME`, `/tmp`, `/run`, `/dev`,
  policy `mounts.rw`, initial rw grants, and every `mounts.grantable_rw`
  prefix (§12 D3, new optional key). A **dynamic rw grant outside those
  prefixes is mounted rw but Landlock denies writes** — the supervisor rejects
  such grants up front with `E_NOT_GRANTABLE` instead of handing out a
  half-working mount.
* ABI ≥6: scope `AbstractUnixSocket` and `Signal`. These matter for
  `network = "host"`: abstract unix sockets are not mount- or path-visible,
  so connecting to a host D-Bus/X11 abstract socket would be an escape.
  **`network = "host"` therefore refuses to start when Landlock scope is
  unavailable** unless `--allow-host-abstract-sockets` is passed (logged in
  the audit file). With `network = "none"` the netns already isolates them.
  **Effective scopes (B1)** = `[landlock] scoped` ∪ `{abstract_unix_socket}`
  when `network = "host"`, whatever the policy lists (`scoped = []` included);
  `signal` is only ever on when the policy asks for it. Only
  `--allow-host-abstract-sockets` removes the forced abstract scope (audited
  as `session/start`). Consequence: in host mode **exec A cannot reach exec
  B's abstract sockets either** (nor the host's); inter-exec abstract sockets
  work only with `network = "none"` (leak tests L22 vs L24).
* ABI ≥4 TCP rules are not used (network is none/host in v0).

## 8. Environment

Child env is built from scratch: `PATH HOME TERM LANG LC_* TZ`, then
`env.pass` names (copied if set), then `env.set`, then the computed
`XDG_*`/cache vars. `PATH` is the host `PATH` filtered to entries that exist in
the sandbox (under a mounted prefix), falling back to
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. `HOME` is
always the sandbox home. A name in `env.pass` that looks secret (`*TOKEN*`,
`*SECRET*`, `*KEY*`, `*PASSWORD*`) is allowed but logged at warn level.
`env.set` wins over `env.pass`; neither can override `HOME`.

`USER` and `LOGNAME` are also **computed** (0.2.2): both are set to the user
name of the generated `/etc/passwd` and `/etc/group` stubs, which is the name
`getpwuid_r(geteuid())` returns on the host (NSS applies), looked up once at
session start by the supervisor — never read from the host `$USER`, so a
scrubbed launch environment (`env -i`, Wakil) gives the same result. It is
used only if it is 1–32 characters of `[A-Za-z0-9_.-]` and does not start with
`-`; if the lookup fails or the name is unusable the name is `user`, and
`hisn run -v` prints why. Unlike `HOME`, a policy that lists them in `env.pass` / `env.set` is not a
load error (0.2.1 policies keep loading); the computed value simply wins. An
`exec` request naming either is refused like one naming `HOME`. Disclosure:
under a scrubbed launch environment 0.2.1 showed the placeholder `user`; 0.2.2
shows the host login name (the same name `id -un` prints for that user), in
`/etc/passwd`, `/etc/group` and the two variables. No other field of the host
passwd entry (home, shell, GECOS) is copied. The lookup runs in the supervisor
before the sandbox is created; descriptors NSS may leave open do not reach the
sandbox (init closes every descriptor but its channel, `init.rs`), but it may
block on a slow user-database backend, which 0.2.1 never queried.

## 9. Control socket, session dir, and what must never be mounted

`<session-dir>` is `$XDG_RUNTIME_DIR/hisn/<id>` (fallback
`/tmp/hisn-$UID/<id>`), mode 0700, created with `mkdirat`+`O_NOFOLLOW`, parent
verified (owner = uid, mode 0700, not a symlink). `control.sock` is 0600.
Same-uid peers cannot be distinguished by `SO_PEERCRED`, so **the only
protection of the control socket is that the sandbox can never name it.**
Hence the hard rules enforced when the policy is resolved and again on every
grant (all on canonical, symlink-free, `openat2(RESOLVE_NO_SYMLINKS)`-resolved
paths):

* **R1** no mount/grant source or target may equal, contain, or lie inside the
  hisn runtime root (`$XDG_RUNTIME_DIR/hisn`, `/tmp/hisn-$UID`) — this also
  keeps other sessions' dirs (L11) out of reach;
* **R2** no grant of `/`, `/proc`, `/sys`, `/dev`, or any ancestor of the
  runtime root that would be rw or would include it;
* **R3** a grant may not overlap (equal / contain / lie inside) a mask or a
  non-grant mount other than as a nested child of a rw/ro static mount
  (e.g. `<cwd>/.secrets` inside cwd is fine; `/etc` over the masked `/etc` is
  not);
* **R4** grant *sources* are opened with `openat2(O_PATH, RESOLVE_NO_SYMLINKS
  | RESOLVE_NO_MAGICLINKS)`: a symlink the agent plants inside a granted rw
  directory can never redirect a later host-side grant to another host path.

* **R5 (path-independent, primary defence; round-1 BLOCKING fix, D13)** — the
  control socket **refuses any peer inside the sandbox's pid namespace**.
  On `accept` the supervisor obtains the peer pid (`SO_PEERCRED`, plus a
  `SO_PEERPIDFD` liveness check on kernel ≥ 6.5) and decides membership two
  ways: (a) if `/proc/<pid>/ns/pid` is readable and has the inode of the
  sandbox init's pid namespace ⇒ refuse; (b) walk `PPid:` upwards through the
  world-readable `/proc/<pid>/status`: a peer equal to or descending from the
  sandbox init ⇒ refuse (every process of a pid namespace descends from its
  init; orphans reparent to it). (b) is the authoritative check because the
  supervisor lives in a *child user namespace* (S): for an ordinary host
  process of the same user `/proc/<pid>/ns/pid` is `EACCES` to it
  (`ptrace_may_access`), so (a) can only ever be a positive hint — treating
  its unreadability as a refusal (the first implementation) locked out every
  legitimate client. Ancestry that cannot be established (unreadable status,
  vanished parent chain, peer gone) ⇒ refuse (fail closed). The check is
  repeated for every request line. This holds even if a bind alias, an
  inherited fd, or any other mount-topology accident makes `control.sock`
  *nameable* from inside, because a sandbox process always descends from
  the sandbox init. (A sandbox process cannot escape the tree: seccomp denies
  `unshare`/`setns`/`clone(CLONE_NEWPID)`, it has no caps, and init is its
  reaper.) The same ancestry walk enumerates the sandbox's processes for
  soft-revoke scans and hard revoke.
* **R1b (defence in depth)** — at start, for every recursively bound tree,
  the supervisor scans the host `/proc/self/mountinfo` and rejects the session
  if any mount inside that tree has the same `major:minor` and a root that is
  the runtime root or lies within it, or if the tree is itself on the runtime
  filesystem object (`st_dev`+`st_ino` ancestry check). A non-recursive bind
  cannot import such a submount. Unreadable mountinfo ⇒ reject.

Requests are newline-delimited JSON (see POLICY-SPEC §7). Unknown ops, bad
JSON, or lines > 64 KiB close the connection. Every request is appended to
`grants.jsonl` *before* it is executed and the result after.

## 10. Grant and revoke

Supervisor-side sequence (the sandbox cannot initiate any of it):

```mermaid
sequenceDiagram
    autonumber
    participant W as caller
    participant S as supervisor (userns S)
    participant H as helper (forked once at start, single-threaded, in userns S)
    participant M as sandbox mntns (userns U)

    W->>S: {"op":"grant","path":"/abs/x","mode":"ro"} on control.sock
    S->>S: rules R1–R4, grantable check, audit "request"
    S->>S: src = openat2(path, O_PATH, NO_SYMLINKS)
    S->>S: tree = open_tree(src, "", EMPTY_PATH|CLONE|CLOEXEC [|RECURSIVE])  (anon mntns owned by S)
    S->>S: ro? mount_setattr(tree, RDONLY, AT_RECURSIVE) on the detached tree
    S->>H: send `grant /abs/x` + tree fd over the helper socketpair (helper forked once, before any thread)
    H->>M: setns(mntns M)  (stays in userns S: S is U's owner-ancestor ⇒ caps over M and over the tree)
    H->>M: walk components of /abs/x with openat2(NO_SYMLINKS), mkdirat as needed
    H->>M: move_mount(tree, "", dirfd, "", F_EMPTY_PATH|T_EMPTY_PATH)
    H->>M: id = statx(tree fd).mnt_id  (the open_tree fd *is* the handle: no pathname is re-resolved after attaching)
    H-->>S: ok + tree fd back (SCM_RIGHTS) + mount_id; any failure after move_mount detaches again
    S->>S: remember grant{path, mode, mnt fd, mount_id}; audit "ok"
    S-->>W: {"ok":true,"mount_id":N}
```

Properties:

* **[HOST-VERIFY]** moving a detached tree owned by anon-ns-of-S into M (owned
  by U) after `setns` into U/M is what the brief specifies and what
  `systemd-nspawn` does as root; whether the kernel accepts it for an
  *unprivileged* owner on the target kernels is the single biggest
  unverified mechanism. **Fallback (designed, not built):** a shared-subtree
  channel — R is created as a *shared* mount in S; the copy in U becomes a
  slave (`CL_SHARED_TO_SLAVE` across userns); grants are then plain
  `mount --bind` in S at `R/<abs path>`, and the kernel propagates them. It
  needs no `setns`/`move_mount`, gives identical-path targets, and propagated
  mounts are flag-locked in U. See OPEN-POINTS P1.
* Non-recursive by default (a grant exposes exactly one mount; submounts such
  as another filesystem under a directory are not exposed). `"recursive":true`
  opts in. `ro` is applied to the whole detached tree before it is attached,
  so a ro grant is never visible rw, not even for an instant.
* **Revoke is fd-based, never path-based.** `{"op":"revoke","path":P}` looks up
  the stored grant and sends the stored mount handle (the original
  `open_tree` fd) to the helper, which does `setns(M); fchdir(fd);
  umount2(".", MNT_DETACH)`. The supervisor keeps the handle and the table
  entry until the detach succeeded, so a failed detach is retryable.
  Renamed ancestors, planted symlinks, or a shadowing mount cannot make
  revoke miss. After detach, new lookups of that path yield ENOENT (or the
  underlying empty mountpoint dir).
* **Revoke guarantees are explicit (round-1 BLOCKING fix, D14).** Detaching
  the mount removes the path for *new lookups* only; it cannot invalidate fds,
  cwd, mmaps — or **descriptors queued in a unix socket via `SCM_RIGHTS`**,
  which no scan can see. So there are two revoke strengths and the response
  states which one was achieved:
  * **soft** (default): detach, then scan the sandbox processes'
    `/proc/<pid>/{cwd,root,fd/*,maps}` (mount id from `fdinfo`) and report
    `holders`. Response is `guarantee:"lookup"` — *never* more, whatever the
    scan found; unreadable/unidentifiable entries are listed as holders of kind
    `"unknown"`. `kill_holders:true` kills the listed holders but keeps the
    `"lookup"` guarantee (it cannot reach queued descriptors).
  * **hard** (`"hard":true`): detach, then `SIGKILL` **every process in the
    sandbox pid namespace except init** (enumerated from the pidns's
    `/proc`, repeated until empty, bounded by a timeout), and only then report
    `guarantee:"hard"`. Killing all processes closes every socket that could
    hold a queued descriptor, so no usable reference to the revoked object
    remains inside the sandbox (init is capless, holds no grant fds, and never
    `recvmsg`s on sandbox-reachable sockets). Sockets whose other end is
    *outside* the sandbox are not a sandbox-side reference. Timeout ⇒
    `E_INTERNAL` and the session is killed. Callers that need "no access after
    revoke" use hard; callers that only need "the path is gone" use soft.
* **Session end.** On init's exit the supervisor first closes its
  `/proc/<init>/ns/*` fds and stored mount fds, then removes the session dir.
  Mounts live only in M (and the anon trees, which die with the fds);
  there is no state in which a grant outlives PID 1 + supervisor (invariant
  3). If the supervisor is SIGKILLed, the kernel closes the fds and init's
  `PDEATHSIG` kills the sandbox.

## 11. Terminal and stdio

* No std fd is a tty → pass fds 0/1/2 through unchanged (pipes/files). The
  command still gets `setsid()`, so `TIOCSTI` against an inherited host tty is
  impossible (not its controlling tty; also seccomp-denied).
* stdin is a tty → **never hand the host tty to the sandbox.** Init opens
  `/dev/ptmx` on the sandbox's own devpts, sets the slave as the command's
  controlling tty (stdin/out/err merged onto it), and passes the master to the
  supervisor over an `SCM_RIGHTS` channel created before the clone. The
  supervisor puts the real tty in raw mode (restored on every exit path,
  including signals), relays both directions, and forwards `SIGWINCH` as
  `TIOCSWINSZ` on the master. `^C` etc. travel as bytes through the pty line
  discipline.
* `hisn run` prints nothing of its own on stdout; diagnostics go to stderr
  behind `-v`. Exit code = command's (`128+sig`); `125` hisn internal error,
  `126` could not start the command, `127` not found.
* Terminal escape sequences emitted by the command reach the user's terminal
  in both modes (output is data); this is not a sandbox boundary (OPEN-POINTS).

## 12. Deviations from the brief (all additive or refining; none touches the DO NOT ALTER block)

| id | brief says | design does | why |
|----|-----------|-------------|-----|
| D1 | supervisor "host side, unprivileged" | supervisor runs in its own userns S | `open_tree(CLONE)`/`mount_setattr` need `CAP_SYS_ADMIN` over the caller's mntns; S gives that without any host authority |
| D2 | `open_tree(... ro ? none : AT_RECURSIVE)` | non-recursive by default for dynamic grants; ro applied recursively to the detached tree; `recursive` opt-in | recursion only for rw would drag submounts in rw; default exposes exactly one mount |
| D3 | Landlock "same allowlist" | read-everywhere + write on a static set + new optional `mounts.grantable_rw` | a Landlock domain cannot grow after start; dynamic rw grants need a pre-declared prefix |
| D4 | use subid range if present | detect only; single-id map in v0 | newuidmap must run from the *parent* of the new userns; with S in between it needs a launcher stage — deferred (ROADMAP) |
| D5 | revoke = `umount2(target)` | revoke by held mount-root fd + holder scan | path-based revoke can be dodged by renaming ancestors; open handles must be reported/killed |
| D6 | init "exec the command" | init stays PID 1 (reaper/signal forwarder), forks the command; init is capless + non-dumpable | PID 1 needs reaping; a privileged init would be a local privilege-escalation target for the command |
| D7 | `$HOME` tmpfs (path unspecified) | `/run/hisn/home` | keeps `/home` from existing (L1) |
| D8 | `network="host"` | requires Landlock scope (ABI ≥6) or explicit flag | abstract unix sockets are otherwise an escape (D-Bus/X11) |
| D9 | seccomp list in invariant 2 | list + `process_vm_*`, `pidfd_getfd`, `open_by_handle_at`, clone/clone3 handling, x32 deny, `TIOCSTI` | each is a known bypass of the listed set |
| D10 | pty "inside the sandbox via /dev/ptmx" | same; master passed to supervisor via SCM_RIGHTS | master must be held outside the command's reach |
| D12 | `/etc` ro bind with masks | `/etc` = tmpfs of per-entry binds (allowlist at start) | round-1 BLOCKING: live bind exposes later-created secrets |
| D13 | (not specified) | R5 peer-pidns check on the control socket + R1b mount-alias scan | round-1 BLOCKING: path rules alone miss bind aliases |
| D14 | revoke = umount | soft/hard revoke with explicit `guarantee` | round-1 BLOCKING: queued `SCM_RIGHTS` fds survive lazy detach |
| D15 | helper does `setns(userns)` then `setns(mntns)` | helper stays in S and joins **only the mount ns** | joining U would drop the helper's authority over the detached tree (owned by S); S is U's owner-ancestor and already has full caps over M |
| D16 | supervisor writes init's uid/gid maps | init writes its own single-id maps (`setgroups=deny` first) | an unprivileged process may map its own euid in a userns it created; avoids a supervisor↔init race and needs no helper |
| D17 | helper "single-threaded fresh re-exec" per operation | one persistent helper, `fork`ed after READY and before the control thread; talks over a socketpair | an `execve` drops the capabilities S grants, so a re-exec'd helper could not mount; a fork keeps them |
| D18 | (unspecified) | revoke removes the directories the grant created; `ro` initial grants get no pre-created dir | so a revoked path is ENOENT again, not an empty directory (L6); rw prefixes stay as empty dirs (Landlock needs an inode) |
| D19 | revoke handle = reopened mount root | revoke handle = the `open_tree` fd itself | round-2 finding: reopening the target by pathname after `move_mount` can be redirected by a sandbox that renames an ancestor, so revoke would hit the wrong mount |
| D20 | (unspecified) | `landlock::apply` counts scoping as applied only if the kernel's *effective ABI* >= 6 | round-2 finding: best-effort mode drops unsupported scopes silently; "requested" is not "applied" |
| D11 | mkdir -p mountpoint by path | component walk with `openat2(NO_SYMLINKS)` + `move_mount` to a dirfd | no path TOCTOU in the helper |
| D21 | v0.2 exec: "exec'd processes are children of sandbox PID 1 (fork from a helper that has setns'd into the pid ns)" | the helper's child forks a second time inside the pid ns; the program is a **grandchild** of PID 1 (init → monitor `W` → program `P`) | a single fork from outside the pid ns yields a process whose parent is *outside* the namespace (PPid 0 inside, never adopted by init): it would not descend from init in the supervisor's `/proc` view, so R5 (§9) would fail open and hard revoke (§10) would miss it. Intent of the invariant (descendant of PID 1, reaped inside, dies with the session) is kept; the literal "direct child" is not achievable. See §14.3 |
| D22 | (unspecified) | grants/revokes and exec spawns are ordered by a spawn gate (`RwLock`): spawns share it, a hard revoke takes it exclusively | a hard revoke must not sweep while an exec is half-started (§14.6) |
| D23 | (unspecified) | exec uses a **second** persistent helper `E` (userns S, joins nothing itself); the grant helper is unchanged | the grant helper must stay in S + sandbox mntns only (D15); exec needs a per-exec child that joins userns U |
| D24 | (unspecified) | the `/proc/<init>/ns/*` fds the exec helper needs are opened by the supervisor before `GO`, like the mount-ns fd already is; the sandbox **root** fd is the exception and comes from init (D25) | the ns fds need no later `/proc/<init>` access; whether the supervisor *could* open them after init became non-dumpable (§6) is not relied on and not verified |
| D25 | (unspecified) | `C` fchdirs onto the sandbox root fd after `setns(mnt)` | `setns(CLONE_NEWNS)` swaps the mount tree and sets root and cwd to the new namespace's root, but the fchdir is kept as belt and braces (round-2 review finding A; external review 2026-11-01 corrected the claim that it does not). `C` and `D` additionally fail closed unless `statx("/")` and `statx(".")` both equal the dev/ino of that root fd. The fd is opened by **init itself** (`open("/", O_PATH\|O_DIRECTORY)` right after `pivot_root`) and passed to the supervisor with `READY`. Two host runs ruled out the alternatives: `/proc/<init>/root` opened before `GO` is still the host root (every exec refused by the check), and the `/proc/<init>/ns/user` open attempted after `READY` failed with EACCES (init is non-dumpable, D6; the root open goes through the same `/proc/<init>` access check, not separately tested) |
| D26 | (unspecified) | helper protocol carries a request id; an ambiguous handover (timeout/EOF/garbage) **poisons** the channel: later execs fail with `E_INTERNAL` | a late reply would otherwise be consumed as the answer to the *next* request (round-2 review finding C) |
| D27 | (unspecified) | `W` treats a partial/failed errno-pipe read as an exec failure (`EIO`), never as success | clean EOF (`CLOEXEC`) is the only evidence of a successful `execve` (round-2 review finding E) |
| D28 | (unspecified) | a client that disconnects before the `{"ok":true,…}` line could be written enters `drive` **pre-cancelled**: `TERM` immediately, `KILL` after the grace — same sequence as a mid-run disconnect | the old path passed a dead fd and waited for a poll event that could never arrive (round-2 review finding D) |

## 13. Module map

`alias` (R1b, §9) is a **reject-only gate**, not part of path resolution or of
the mount plan. It parses a `/proc/self/mountinfo` text (pure, unit-tested) and
answers one question: is a tree that is about to be exposed (recursively or not)
the same filesystem object as, an ancestor of, or a descendant of the hisn
runtime directory, reached through a bind alias that the lexical rules R1-R4
cannot see? It has two callers, both in `supervisor`: `mountinfo_check` at
session start (cwd, `mounts.*`, toolchain trees) and `do_grant` (the grant
source). It never changes what `mounts::plan` derives and never influences how
`grant::open_source` resolves a path; a positive result only makes the session
start or the grant fail (`E_PATH_FORBIDDEN`). Because it does gate grants, both
uses have a leak test: L14 (start) and L14b (grant).

`policy` (schema, load, validate, resolve) → `check` → `mounts` (pure plan) →
`rootfs` (executes plan) → `init` (§3) → `seccomp` → `landlock` → `env` →
`session`/`supervisor`/`control` → `grant` (supervisor + helper) → `cli` →
pty relay (in `supervisor`). Pure functions (policy, env scrub, mount plan,
seccomp rule set, rule R1–R4 checks) carry the unit tests; everything
namespace-dependent is covered by `tests/leak` on a host.

## 14. `exec` into a running session (v0.2)

Wakil issues many tool calls per session. Each must run in the **same
namespaces, with the same confinement, seeing the same grants** as the
original command. This section is the design for that; deviations from the v0.2
brief are D21-D24 in §12. Everything here is **[HOST-VERIFY]**: it needs user
namespaces, which the build sandbox blocks. §14.11 lists what is unit-tested
here and what only a host can show.

### 14.1 Contract

Control-socket op (POLICY-SPEC §7 has the table):

```
{"op":"exec","argv":["sh","-c","…"],"cwd":"/abs"|null,"env":{"K":"V"},"tty":false}
```

The request line carries `SCM_RIGHTS` fds in the **same `sendmsg`**: three
(stdin, stdout, stderr) when `tty=false`, exactly one (the slave side of a pty
the *client* allocated) when `tty=true`. Responses, one JSON line each:

1. `{"ok":true,"pid":N}` once the program has been `execve`d (`N` is its pid
   **inside the sandbox pid namespace**; it is only a handle for `signal`), or
   `{"ok":false,"error":E,"message":…}` (`E_BAD_REQUEST` for validation incl.
   rejected env keys, `E_EXEC` if confinement or `execve` failed, `E_INTERNAL`);
2. on exit: `{"exit":{"code":N}}` or `{"exit":{"signal":"TERM"}}`, or
   `{"exit":{"lost":true}}` (extension, §14.9: the monitor died, so the status
   is unknown; the program is still inside the session).

`{"op":"signal","pid":N,"signal":"TERM"}` (second connection) forwards a signal
to the program's process group, only for a pid that is a live exec of this
session (`E_NOT_FOUND` otherwise). Closing the exec connection counts as
cancellation: `TERM`, then `KILL` after 5 s.

CLI: `hisn exec --session ID [--cwd DIR] [--env K=V]... [--tty] -- CMD…`
passes stdio through, exits with the program's code (`128+sig` if signalled;
`125` hisn error, `126`/`127` as for `run`) and prints nothing of its own.
`hisn run --detach` starts a session with **no command**: init finishes setup,
then only sleeps and reaps until `SIGTERM/SIGINT/SIGHUP`, then exits 0.

### 14.2 Processes

```
 supervisor (userns S)            ──forks once, before any thread──▶  E  exec helper (userns S)
 E ── per exec ──▶ C  (still outside the sandbox; setns user,mnt,ipc,uts,[net],pid)
                   └─ fork ─▶ D  (inside the pid ns, confines itself)
                              └─ fork ─▶ W  monitor ──▶ P  the program
 D exits; W is reparented to sandbox init.
```

* `E` is forked next to the grant helper, while the supervisor is
  single-threaded. It holds the namespace fds (`/proc/<init>/ns/{user,mnt,ipc,
  uts,pid[,net]}`, opened before `GO`, D24), the resolved policy, the Landlock
  plan, the compiled seccomp programs and the session's base environment (all
  copied by `fork`). It never joins a namespace itself (D23): it stays in S like
  the grant helper, so the grant helper's invariants (D15) are untouched. It
  has `PDEATHSIG=SIGKILL`, `SIGCHLD=SIG_IGN` and talks to the supervisor over a
  `SOCK_SEQPACKET` socketpair, so one message is one request (JSON spec + fds).
* `C` is forked by `E` per exec. It sets `PDEATHSIG=SIGKILL`, then
  `setns(user)` **first**: S is the owner-ancestor of the sandbox userns U, so
  `C` has all capabilities in U on joining — and only there. Then
  `setns(mnt)`, `ipc`, `uts`, `[net]`, and `pid` last (the pid-ns switch affects
  only children). `C` sets `PR_SET_DUMPABLE=0` **before and after** `setns(user)`
  (joining a userns replaces the credentials, which may reset dumpability) and
  closes every fd except the passed stdio fds and the status socket **before**
  the fork, so `D` never inherits the namespace fds or `E`'s channel.
  `chdir("/")`, `fork` → `D`, `waitpid(D)`, exit. `C` never uses
  `/proc/self` (after `setns(mnt)` `/proc` is the sandbox's, in which `C`, being
  outside the pid ns, has no `self`).
* `D` is inside the pid ns but its parent (`C`) is outside: ns-pid parent `0`.
  It sets `PDEATHSIG=SIGKILL` (relative to `C`), so killing `C` kills a stuck `D`.
  It is the only process that ever holds capabilities inside the sandbox, and
  only until §14.4 step 5. It does the confinement, then forks `W` and exits.
* `W` (monitor) waits until `getppid()==1` — i.e. until the kernel has
  reparented it to the sandbox init, so the chain `init → W` exists — and only
  then forks `P`. The wait is **bounded (5 s)**; on timeout, or if `getppid()` is
  ever neither `D`'s pid nor `1`, `W` reports `E …` and exits without forking `P`
  (fail closed). Why `1` is the right adopter: `D`'s only ancestors are outside
  the namespace, so within it there is no subreaper between `D` and init, and
  orphans of `D` go to the namespace's init. `PDEATHSIG` is cleared across
  `fork`, so `W` does not inherit `D`'s and survives `D`'s exit. `W` relays status and signals (§14.8) and is reaped by init.
* `P` is the program: `setsid` (+ controlling tty if `tty`), `dup2` of the
  passed stdio, `PDEATHSIG=SIGKILL` (so it dies with `W`), `execve`.

```mermaid
sequenceDiagram
    autonumber
    participant K as client (hisn exec / Wakil)
    participant S as supervisor (control thread)
    participant E as exec helper E (userns S)
    participant C as C (setns → U)
    participant D as D (inside pid ns)
    participant I as sandbox init (PID 1)
    participant W as W monitor
    participant P as P program

    K->>S: exec request line + stdio fds (one sendmsg)
    S->>S: authorize (R5), validate argv/cwd/env, audit "request"
    S->>S: take spawn gate (shared); socketpair "status"
    S->>E: spec + stdio fds + status end (SEQPACKET)
    E->>C: fork
    C->>C: setns user, mnt, ipc, uts, [net], pid; chdir /
    C->>D: fork (D lands in the sandbox pid ns, ns-ppid 0)
    D->>D: dumpable=0, rlimits, Landlock, NNP, drop all caps, seccomp, verify (fail closed)
    D->>W: fork; D exits
    I-->>W: W reparented to init (getppid()==1)
    W->>P: fork; P: setsid, stdio, execve
    W-->>S: status: "P <ns pid>"
    S->>S: register pid, release spawn gate, audit "ok"
    S-->>K: {"ok":true,"pid":N}
    P-->>W: exit
    W-->>S: status: "X exit 0"
    S-->>K: {"exit":{"code":0}}
    W-->>I: W exits; init reaps it
```

### 14.3 Why two forks (D21)

The brief wants exec'd processes to be children of sandbox PID 1, "fork from a
helper that has setns'd into the pid ns". A process forked that way is created
inside the namespace but its **parent is outside it**: its in-namespace `PPid`
is 0, and when the parent exits the kernel picks a new reaper from the *dying
parent's* pid namespace (a subreaper or the host init), **not** the sandbox
init. Consequences, none acceptable:

* in the supervisor's `/proc` the process would not descend from init, so the
  R5 ancestry test (§9) would conclude "not in the sandbox" — **R5 would fail
  open** for it — and hard revoke's sweep (§10, `descendants_of(init)`) would
  miss it;
* nothing inside the sandbox would reap it (zombie, or an orphan that outlives
  init's reaping duty; it still dies with the pid ns).

The second fork fixes all three: `D` exits, `W` is reparented *within* the pid
ns to init (it is `D`'s child inside the ns), so `init → W → P` is a real tree
in both views. `W` is also the only way to obtain `P`'s exit status: the
supervisor is not `P`'s parent, `waitid(P_PIDFD)` needs a child, and
`PIDFD_GET_INFO` exit info needs kernel ≥ 6.15. `P` is therefore a
*grandchild* of PID 1 (and a child if `W` dies), not the literal child the
brief names. The intent — descendant of PID 1, reaped inside, never outliving
the session — holds; the literal wording cannot. **Reported to the user.**

### 14.4 Confinement re-applied on every exec (DO NOT ALTER #1)

`setns` does not carry the sandbox's seccomp filter, Landlock domain,
`no_new_privs` or dropped capabilities. `D` re-applies, in this order, **reusing
the exact functions and inputs `init` uses** (so there is no second
implementation to drift):

1. `prctl(PR_SET_DUMPABLE, 0)` — the very first action. While `D` holds
   capabilities a same-uid sandbox process could otherwise `ptrace`/read
   `/proc/<D>/mem`; non-dumpable plus "target has caps the tracer lacks" closes
   it (seccomp already denies `ptrace`/`process_vm_*`). `W` inherits it and stays
   non-dumpable; `P` becomes dumpable on `execve` as any process does.
2. `close_all_except` {the three passed stdio fds *kept at their high numbers*,
   status socket}; `D`'s own fds 0-2 are pointed at the sandbox's `/dev/null`
   (so nothing it prints or reads touches the client). The passed fds stay
   untouched until `P` `dup2`s them onto 0-2 (§14.8); `W` keeps them only to
   hand to `P`. Descriptor inventory by stage — `E`: ns fds, supervisor channel;
   `C`: passed fds + status socket (ns fds closed before the fork); `D`/`W`:
   passed fds + status socket; `P`: 0-2 + nothing else (status socket and the
   high copies are closed before `execve`).
3. `setsid`; `set_rlimits(policy)` (`nofile`, `nproc`, `core=0`).
4. `chdir("/")`, then `landlock::apply(plan, require_scope)` — the **same
   plan** as init (`landlock::plan(policy, initial_rw)`, copied into `E`).
5. `PR_SET_NO_NEW_PRIVS`; `drop_all_caps()` (securebits, ambient, bounding,
   inheritable/permitted/effective); `seccomp::install(progs)` — the same
   compiled programs; `verify_hardening()` re-reads `/proc/self/status` and
   requires all five cap sets zero, `NoNewPrivs 1`, `Seccomp 2`.
6. only now `chdir(cwd)` and the environment is built (§14.5).

Any failure writes `E <message>` on the status socket and `_exit(125)`: the
request fails closed with `E_EXEC` and nothing is started. `fork` of `W` happens
only after step 5, so no process in the sandbox ever has capabilities or lacks
seccomp, and `W`/`P` inherit all four layers.

### 14.5 Request validation and environment (DO NOT ALTER #1, env)

Validated by the supervisor before anything is sent (pure, unit-tested):
`argv` 1-4096 entries, none containing NUL, total request ≤ 48 KiB; `cwd` null
(→ the policy `cwd`) or absolute without NUL or `..` segments; `tty` matches
the number of fds; unknown JSON keys are errors (as for every op).

Final environment = the session's base environment (what init gave the main
command: allowlist + `env.pass` + `env.set` + computed `HOME`/cache vars) with
the request's `env` applied on top. A request key is **accepted only if it is
in `env.pass`** and is not a computed name (`HOME`, `USER`, `LOGNAME`, `XDG_*`, `CARGO_HOME`,
`GOMODCACHE`, `GOCACHE`, `npm_config_cache`, `PIP_CACHE_DIR`). Any other key
rejects the **whole request** (`E_BAD_REQUEST`, message lists the keys, never
the values); nothing is dropped silently. Names must be non-empty, without `=`
or NUL; values without NUL; ≤ 256 variables. *Decision:* `TERM`/`LANG`/`TZ`/`LC_*`
are not exempt — they are already in the base environment from session start;
a policy that wants per-exec values adds them to `env.pass`. The base
environment never changes after start (host env is read once, as for `run`).

### 14.6 Ordering, hard revoke, session end

* **Spawn gate (D22).** A `RwLock`: each exec holds it *shared* from "send to
  `E`" until `P <pid>` is received — `W` sends it only after it observed
  `getppid()==1`, so by then `W` is in init's tree. On **failure, timeout or
  client disconnect** before that point the gate is *not* released until `E` has
  reported that `C` was reaped (on timeout `E` first sends `SIGKILL` to `C`,
  which kills `D` through its `PDEATHSIG`; a `W` that already exists dies when
  the supervisor closes the status socket). Only then can hard revoke sweep, so
  a half-started exec is either in init's tree and killable, or gone.
  Hard revoke (§10) takes it *exclusive* before its kill sweep, so the sweep can
  never run while an exec is half-started (a `D` not yet under init would be
  missed). Grants/soft revokes use `op_lock` as before; they do not wait for
  spawns, which is what "grant during a running exec is visible to it" needs:
  the grant mount lives in the shared mount namespace.
* **Grants (DO NOT ALTER #3).** `P` is in the sandbox mount namespace, so a
  grant made before or after it started is visible, and a revoke detaches the
  mount for it too (`ENOENT` for new lookups; soft-revoke guarantees unchanged).
* **R5 (§9).** `W`, `P` descend from init, so the control socket still refuses
  them. `D` is briefly outside the tree (parent `C`), but `D` holds no path to
  the socket (never mounted) and runs no sandbox-controlled code.
* **Session end (DO NOT ALTER #2).** Init exiting destroys the pid ns and kills
  every process in it: `D`, `W`, `P`. A `D` forked while init is already dying is
  killed by the teardown; a *new* `fork` into a dead pid ns fails (`ENOMEM`),
  so no exec can start after the session ended. `C`/`E` die with the supervisor
  (`PDEATHSIG`); `C` also exits when `D` is gone.

### 14.7 Control-socket changes

The server reads request lines with `recvmsg` (`MSG_CMSG_CLOEXEC`, room for ≤ 4
fds; `MSG_CTRUNC` ⇒ bad request, fds closed). Rules: fds are accepted **only**
on the first request line of a connection and **only** for `exec`; anywhere
else they are closed and the request is `E_BAD_REQUEST`; the count must be
exactly 3 / 1. Clients send the request line and its fds in one `sendmsg` and
nothing after the newline until the response. R5 still runs per request line.
The exec handler may write several lines (response, then exit), so the
connection thread is occupied for the exec's duration; `signal` therefore uses
a second connection. The accept loop now starts **after** `START` is sent (the
socket is bound earlier, so early clients wait in the listen backlog): no exec
can reach a session that is not fully set up.

### 14.8 Stdio, signals, tty

* Pipes/files (`tty=false`): the client's three fds are `dup2`ed onto `P`'s
  0-2. The supervisor closes its copies once handed to `E`.
* `tty=true`: **the user's terminal is never passed to the sandbox.** The
  client allocates a *fresh host pty*, passes the slave, and relays master ↔
  its own stdin/stdout (raw mode on a real tty, restored on every exit path);
  `SIGWINCH` → `TIOCSWINSZ` on the master, which the kernel propagates to the
  foreground group of the slave. `P` makes the slave its controlling tty
  (`TIOCSCTTY`) after `setsid`. The CLI refuses (exit 125 with a hint) when any
  of fd 0-2 is a terminal and neither `--tty` nor `--no-tty` was given, instead
  of handing the host tty over (`TIOCSTI`-class attacks stay impossible, §11).
  `--no-tty` (0.3.3): no pty; the request carries `/dev/null` as stdin and the
  client-owned pipes for stdout and stderr, which the client copies to its own
  fd 1 and 2 (drained concurrently with the exit wait, so output larger than a
  pipe buffer does not deadlock). The sandbox never receives a descriptor for the
  caller's terminal. `--tty --no-tty` is a usage error.
* Status/signals use the per-exec **status socketpair** (`W` ↔ supervisor):
  `W → S: P <pid>`, `X exit <code>` | `X sig <n>`; `S → W: K <n>` (1 ≤ n ≤ 64,
  delivered with `kill(-P, n)`). EOF from the supervisor side means "cancel":
  `W` kills `P`'s group with `SIGKILL`.

### 14.9 Failure modes

* `W` killed by `P` (same uid, same Landlock domain): `P` dies with it through
  `PDEATHSIG` unless the program cleared it; either way the status socket closes
  and the client gets `{"exit":{"lost":true}}`. The program cannot leave the
  session: it is in init's tree and dies with the session or a hard revoke.
* `E` dies: the supervisor sees EOF on its socket; further execs fail with
  `E_INTERNAL`; the main command and grants are unaffected.
* Spawn handshake exceeds 10 s: the supervisor closes the status socket (`W`
  kills `P`), replies `E_INTERNAL`, audits it.
* Each exec is audited (`exec` request/result, argv[0] only, never env values).

### 14.10 Rejected alternatives

* **Ask init to fork the program.** Gives literal "child of PID 1" and
  trivial status, but needs a sandbox-reachable command channel into a process
  that must stay minimal, capless and non-dumpable (§6), and the brief
  mandates helper + `setns` + re-application. Rejected.
* **Single fork from the helper.** §14.3: R5 fails open, revoke misses it.
* **Exec a `nsenter`-style binary.** `execve` drops the capabilities `setns`
  needs (D17) and adds a binary on the trust path.
* **Re-parent with `PR_SET_CHILD_SUBREAPER`.** Would make the *supervisor* the
  reaper, i.e. outside the sandbox tree.

### 14.11 What is tested where

Unit tests (here): request parsing/validation, env rejection, status-line
format/parse, fd-receiving control server with a fake handler, the monitor
loop with a real child process over a socketpair (signal forwarding, exit code
vs signal reporting), multi-fd `SCM_RIGHTS`, CLI parsing. **Host only
(`make leaktest`, L15-L20):** the `setns` chain, `D`'s confinement, the
`init → W → P` ancestry, grants seen by exec'd processes, fd/zombie hygiene,
pty behaviour. Results from a given host run are recorded in the log that run
produced (`make leaktest-log`), not in this document.

### 14.12 Known limits of this design

* **Landlock write roots are resolved by pathname in `D`** (the plan holds
  paths; `PathFd::new` runs after `setns(mnt)`). A sandbox process that
  renames a non-mountpoint ancestor under a writable tmpfs (`/tmp`, `/run`)
  and recreates a directory at the old path could make `D` anchor a write rule
  on the *new* directory. That can only weaken what the exec'd process may write
  (it can write under `/tmp`/`/run` anyway); it cannot add rights outside the
  write set. Closing it needs inode-anchored rules captured at session start
  (open the roots once in the supervisor before the pivot and pass the fds) —
  open point P18.

* **Sibling Landlock domains (P17 — resolved).** Each exec gets its *own*
  Landlock domain (`landlock::apply` in `D`), a sibling of init's domain and
  of every other exec's. With ABI >= 6 the ruleset can scope `Signal` and
  `AbstractUnixSocket` (§7): a scoped process cannot signal, or connect an
  abstract unix socket to, a process in a *different* (non-descendant)
  domain. The default is now **no scoping** (`[landlock] scoped = []`):
  execs of the same session may signal each other and reach each other's
  abstract sockets — isolation is against the host, not between execs.
  `network = "host"` still requires `AbstractUnixSocket` scope (§7), so in
  host mode inter-exec abstract sockets are blocked by design (B1; L24
  checks the host-side listener is unreachable from an exec, default and
  explicit `scoped = []`). A policy that wants inter-exec signal isolation sets `scoped =
  ["signal"]`; the leak tests L21 (cross-exec kill succeeds by default),
  L22 (cross-exec abstract socket connect succeeds by default, `network =
  "none"` only), and L23
  (with `scoped = ["signal"]` the kill fails with `EPERM`, skipped if
  ABI < 6) cover both defaults.
* `P` shares the pid namespace, mount namespace and (for `network="host"`) the
  network with the main command; exec does not add isolation between tool calls.
* The ns-pid returned in `{"ok":true,"pid":N}` is only meaningful for the
  `signal` op of this session.

## 15. Profiles (v0.3, ADR 0001)

A **profile** is an envelope around `hisn-policy/v1`, not a v2. A profile file
is a TOML document with `version = "hisn-profile/v1"` and one required table
`[policy]`, whose value is a complete `hisn-policy/v1` document (inline
table). The inner `[policy]` is resolved by the exact existing
`policy::load` + `policy::resolve` code path; v1 policy stays valid unchanged.

```
# profiles/wakil.toml
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "."
session.network = "none"
mounts.grantable_rw = ["/srv/out"]
```

### Search path and precedence

`hisn run --profile <name|path>` resolves the profile in this order:

1. `--profile` with a `/` → that file (must exist, must be a profile not a
   bare policy). A file that parses as `hisn-policy/v1` (no `version` key or
   `version = "hisn-policy/v1"`) is rejected with `E_PROFILE_NOT_PROFILE`.
2. `--profile <name>` → `$HISN_PROFILES/<name>.toml`, then the built-in
   `profiles/<name>.toml` shipped next to the binary. **`./<name>.toml` is
   deliberately not in the search path** — a profile resolved from under the
   session cwd (or any rw grant / persistent home) can be written by the
   sandbox and self-ack its own risk. Such a profile is rejected with
   `E_PROFILE_UNTRUSTED` if the resolved path lies under the session cwd, a
   rw grant, or the persistent home.
3. `--policy <file>` (existing 0.2 path) → a bare `hisn-policy/v1` document,
   treated as a profile with no 0.3 surface. Stays for scripts and the leak
   suite.

`--profile` and `--policy` are mutually exclusive (`E_PROFILE_POLICY`).

### Built-in profiles

`base` (= the 0.2 sandbox: no 0.3 surface, defaults to `Policy::default()`)
and `wakil` (a default session with `grantable_rw`). A profile that declares
none of the new tables (`[[services]]`, `[[host_services]]`, `[[forward]]`,
`[docker]`, `[ssh]`, `[[risk]]`) yields byte-for-byte the 0.2 mount plan —
the same `mounts::plan` output as a bare policy at the same `[policy]`
values (L25 asserts this).

### CLI

`hisn profile list` — prints the resolved search path (`$HISN_PROFILES`,
the built-in directory) and the built-in profile names.

`hisn profile explain [<name>]` — prints each capability of the profile and
its computed risk label (§16) with one sentence of explanation. With no
argument, explains the default profile (`base`).

`hisn profile validate [<file>]` — validates a profile file: parses the
envelope, resolves the inner `[policy]`, and checks the 0.3 surface (risk_ack
matching, unsupported tiers). Prints the resolved inner policy on success.

### Resolution

`profile::load(path) -> Result<Profile>`: parse the TOML, verify
`version == "hisn-profile/v1"`, extract the `[policy]` inline table, parse
it as a `Policy` (same `Policy::parse`), validate the 0.3 surface (§16–§19).
`profile::resolve(profile, base_dir, overrides, runtime_roots) ->
Result<ResolvedProfile>`: resolve the inner `[policy]` via the existing
`Policy::resolve`, then carry the 0.3 surface fields into the resolved
result. The resolved profile is what `supervisor::run` consumes; the mount
plan is derived from it exactly as today (no change to `mounts::plan`).

### What the profile layer does not change

- The mount plan (`mounts::plan`): the inner `[policy]` drives it unchanged.
- The seccomp filter, Landlock ruleset, capability drop, env scrub: all
  derived from the inner `[policy]` as today.
- The control socket, grant/revoke, exec: unchanged (the 0.3 surface is
  orchestration, not isolation).

**Invariant touched:** 5 (the envelope tables have no OCI runtime-spec
representation; they are annotation only). 1, 2, 3, 4 untouched (same
resolution, same mount plan, same grants, same env scrub).

## 16. Risk labels (v0.3, ADR 0006)

Every profile capability that widens the boundary carries a **fixed risk label**
from a closed set. The label is **computed by hisn from the capability**, not
chosen by the profile author: the author declares the *capability*; hisn emits
the *label*. A missing or mismatched `risk_ack` for a `root-equivalent`,
`signing`, or `host-exec` capability is a load error.

### Label set

| label | meaning |
|---|---|
| `none` | no widening; the 0.2 sandbox |
| `data` | the sandbox can read or write host data beyond cwd (a bind, a forwarded data socket) |
| `signing` | the sandbox can produce a cryptographic signature valid on the host (ssh agent, git signing) |
| `host-exec` | the sandbox can run arbitrary commands on the host as the user (a forwarded D-Bus/systemd socket, a shell server, another hisn control socket) — user-equivalent |
| `root-equivalent` | the sandbox can become root on the host (raw docker socket) |
| `kernel-surface` | the sandbox can provoke kernel code paths out of scope of the 0.2 threat model (nested userns) |

### How a label is assigned (by the feature, not the author)

- `[docker] tier = "socket"` → `root-equivalent` (always; the 0.3 tier).
- `[docker] tier = "proxy"` → `E_NOT_SUPPORTED` (0.4; T1 is not available).
- `nested_userns = true` → `kernel-surface` (always; **rejected in 0.3**).
- `[[forward]]` of an ssh agent → `signing` (always).
- `[[forward]]` of the Docker socket (or a recognized rootless-podman socket)
  → `root-equivalent` (always).
- `[[forward]]` of the D-Bus system or session bus → `host-exec` (always).
- `[[forward]]` / `[[host_services]]` of **an unrecognised socket** → **load
  error** (`E_RISK_ACK_REQUIRED`) unless the profile sets `risk` explicitly
  (minimum `host-exec`, documenting that the author asserts the server is not
  root). The profile may **downgrade** the label only for a recognised socket
  path pattern; an unrecognised socket cannot be labelled `none` or `data` without
  an explicit `[[forward]] risk = "data"` that hisn accepts.
- `[[host_services]]` → `host-exec` for the execution itself (a profile's
  arbitrary host-side `exec` is user-equivalent execution), plus the socket's
  label (`data`/`signing`/`root-equivalent` as above). The `risk_ack` covers
  both.

### Behaviour

- `hisn run` prints the effective risk labels on start, one line each:
  `RISK: <label> — <capability>`, unless `--quiet-risk` is passed. A profile
  with no widening capabilities prints `RISK: none` (with `--verbose` only).
- `hisn profile explain <name>` prints each capability and its label with
  one sentence of explanation.
- A profile with a `root-equivalent`, `signing`, or `host-exec` capability
  **must** contain the matching `risk_ack`:
  ```toml
  [docker]
  tier = "socket"
  risk_ack = "root-equivalent"   # must match the computed label
  ```
  Missing → `E_RISK_ACK_REQUIRED`; mismatched → `E_RISK_ACK_MISMATCH`.
- The risk list is recorded in the session dir (`risk.json`) and in `inspect
  --json` (the `risk` field).

### Secure by default

A profile with no `[[services]]`, `[[host_services]]`, `[[forward]]`, `[docker]`,
`[ssh]`, `nested_userns`, and the inner `[policy]` at its defaults yields
exactly the 0.2 sandbox — same mount plan, same seccomp, same Landlock, same
env. The profile layer is a strict superset of capabilities, never a relaxation.
(DO NOT ALTER #3.)

### What the risk labels do not change

- The labels add no capability; they disclose the ones the profile already
  declares. A missing `risk_ack` is a load error, so a profile cannot silently
  enable a root-equivalent or signing capability.
- The labels cover **0.3 surface capabilities** (`[[forward]]`, `[docker]`,
  `[[host_services]]`, `[[services]]`, `nested_userns`). Inner-policy widenings
  (`mounts.rw`, `network = "host"`, `--allow-host-abstract-sockets`) are not
  labelled by the 0.3 risk system — they are the existing 0.2 surface, already
  subject to their own enforcement (Landlock write set, abstract-socket
  scope). `RISK: none` means "no 0.3 surface widening", not "no widening at
  all"; a profile with `mounts.rw = ["/home/u"]` still widens the 0.2 boundary
  (a `data` exposure) but does so through the existing inner-policy mechanism.
- `risk.json` and `inspect --json` are start-time snapshots — they reflect the
  profile as loaded. Dynamic grants made after start are not reflected in
  `risk.json` (they are in `grants.jsonl`).
- The mount plan, seccomp, Landlock, caps, env scrub are unchanged — the
  labels are display + load-time enforcement, not a runtime boundary.

**Invariant touched:** 5 (the labels are annotation only). 6 (the leak suite
tests the isolation; the labels are display + load-time enforcement). 1, 2, 3, 4
untouched.

## 17. Socket forwarding (v0.3, ADR 0003)

Two profile tables expose a **host-side unix socket** inside the sandbox at a
declared path, as a **read-only mount of one socket inode**:

- `[[forward]]` — expose an **existing** host socket (ssh agent, Docker
  daemon). The supervisor prepares a detached tree with `open_tree(OPEN_TREE_CLONE)`
  and sends it to the **grant helper** (§10), which attaches it at `expose`
  inside the sandbox mount namespace via `move_mount`, with
  `MOUNT_ATTR_RDONLY`. The helper is the same single-threaded fork from §10/D17:
  it is forked before any thread, stays in userns S, joins only the sandbox
  mntns, and uses fd-anchored, symlink-free path walks (R4). The forward is
  tracked in the **grant table** so `inspect`, `list`, and revoke see it.
- `[[host_services]]` — start a host-side process **in the supervisor's
  userns S** (not the sandbox userns U), wait for its socket, then forward it
  as above. Stop = signal + grace then KILL at session end.

```toml
[[forward]]
name      = "ssh-agent"
socket    = "/run/user/1000/ssh-agent.sock"   # existing host socket
expose    = "/run/ssh/agent.sock"             # in-sandbox path
risk      = "signing"
risk_ack  = "signing"

[[host_services]]
name      = "kvr-host"
exec      = ["kvr-server", "--addr", "/run/user/1000/kvr/abc.sock"]
socket    = "/run/user/1000/kvr/abc.sock"     # host path the process binds
expose    = "/run/kvr/kvr.sock"               # in-sandbox path
ready     = { socket = "/run/user/1000/kvr/abc.sock" }
stop      = { signal = "TERM", grace = 5 }
risk_ack  = "host-exec"
```

### What the sandbox can and cannot do with a forwarded socket

- **Can:** `connect(2)` to `expose`; speak the service's protocol over the
  stream. A read-only mount does **not** make socket requests read-only: the
  service may read/write host files, launch processes, or return descriptors
  via `SCM_RIGHTS` — the risk is bounded by the **protocol**, disclosed by
  the risk label, not by the mount flag.
- **Cannot unlink it:** the mount is ro (`MOUNT_ATTR_RDONLY`); the parent
  directory is the sandbox root tmpfs (owned by the mapped uid), but the
  socket inode is not writable. `unlink` → `EBUSY` (a mounted inode).
- **Cannot re-bind it:** the sandbox has no `CAP_SYS_ADMIN` and seccomp denies
  `mount`/`umount`, so it cannot create a new mount at that path. `bind(2)`
  the socket syscall is not denied; the sandbox can create its own unix
  sockets, but it cannot move the forwarded inode.
- **Cannot see the host path as a mount name:** `expose` is the only mount
  name; `socket` does not exist in the sandbox's mount namespace. However,
  `getpeername(2)` on a connected `AF_UNIX` socket returns the peer's bound
  `sun_path` (the host path); this is a **known information leak** — the
  host path is visible through the socket API, not through the filesystem.
  The risk label covers the **authority** the socket grants, not the
  confidentiality of the host path name. Leak test L36 records this.
- **Cannot see other host sockets as mount names:** only the one inode is
  mounted, not the host's `/run`. Other sockets in the same host directory
  are not mounted and do not exist as path names. (A service can relay access
  to other sockets through its protocol — that is protocol-level, not
  mount-level, and is covered by the risk label.)

### Source path rules (R1–R4 + R1b + R3)

The `socket` path (the host-side source) satisfies the same path rules as a
grant source: R1 (not the runtime dir), R2 (not `/`, `/proc`, `/sys`, `/dev`),
R4 (opened with `openat2(O_PATH, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`),
and R1b (mountinfo alias scan). The `expose` path is an absolute in-sandbox
path; it must not be `/`, `/proc`, `/sys`, `/dev`, or inside the runtime dir.
R3 applies: `expose` may not overlap a mask or a static mount (same check as a
grant target). The source must be a **socket** (`statx` → `S_IFSOCK`); a
non-socket inode is a load error (`E_NOT_SOCKET`).

### Mechanism (grant helper, not threaded supervisor)

The forward is performed **through the grant helper** (§10), not by the
threaded supervisor directly. The supervisor:
1. `open_tree(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)` the socket inode (no
   `AT_RECURSIVE` — a socket is a single inode);
2. `mount_setattr(tree, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID, AT_EMPTY_PATH)`
   on the detached tree;
3. sends `grant <expose>` + the tree fd to the helper over the socketpair;
4. the helper `setns(mntns)`, walks to the target dirfd with
   `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`, `move_mount`s the tree;
5. the helper returns the mount-root fd + mount id; the supervisor stores
   the forward in the **grant table** (as a `Grant` with `mode = Ro`,
   `recursive = false`) so `inspect`, `list`, and revoke see it.

This reuses the exact same mechanism as a ro grant, ensuring:
- the threaded supervisor never forks (D17);
- the helper's fd-anchored path walk has no TOCTOU (R4);
- the mount is tracked and revokable like any grant.

### `[[host_services]]` lifecycle

1. The supervisor forks the host process **before any thread** (like the
   grant helper, D17), in the supervisor's userns S. The process runs with
   the user's host credentials (not in the sandbox userns U), the host `PATH`
   (not the sandbox's), and optional `cwd`. Never setuid, never extra caps.
2. **Readiness:** the supervisor polls `ready` (socket stat, tcp connect, or
   command exit 0) with a timeout (default 15 s; `ready.timeout` per service).
   On timeout the session fails to start (fail closed) — the service is
   killed and the session exits `125`. Readiness must complete **before**
   `START` is sent to init.
3. **Forward:** once ready, the socket is forwarded as `[[forward]]` above.
4. **Stop:** on session end (init exit, `hisn kill`), the supervisor sends
   `stop.signal` to the host process's process group, waits `stop.grace`,
   then `SIGKILL`. The host process is a direct child of the supervisor
   (not in the sandbox pidns); `kill(-pgid)` targets its group. If the
   supervisor is `SIGKILL`ed, the host process is orphaned — it runs with
   `PR_SET_PDEATHSIG=SIGKILL` so it dies with the supervisor.
5. **`risk_ack = "host-exec"`** is required for the execution itself (a
   profile's arbitrary host-side `exec` is user-equivalent execution),
   independently of the socket's label. If the socket also has a
   `signing` or `root-equivalent` label, the `risk_ack` must match the
   **highest** label (§16).

### Audit

Every `[[forward]]` and every `[[host_services]]` start/stop is appended to
`grants.jsonl` (op = `"forward"` or `"host_service"`, path = `socket` (the
host source, not `expose` — the audit records what host object was exposed),
expose = `expose` (the in-sandbox path), stage =
`"start"`/`"stop"`/`"result"`).

### `inspect --json` and L8

Forwards appear as **additional mounts** in `inspect --json` (the mount
table includes the forwarded socket at `expose`). They are **not in
`mounts::plan`** (the plan is the inner policy's mount list); L8 compares
`inspect` against `plan + initial grants`, so forwards are treated like
initial grants — the L8 comparator must account for them.

### What this feature does not change

- The mount plan for the inner `[policy]` is unchanged; the forwarded socket
  is an additional mount made by the supervisor after the initial plan.
- The seccomp filter, Landlock ruleset, capability drop, and env scrub are
  unchanged.
- The control socket, grant/revoke, and exec mechanics are unchanged (the
  forward reuses the grant helper and the grant table).

**Invariant touched:** 1 (the exposed socket is a single ro mount inside the
empty-tmpfs root; the host path is absent as a mount name). 2 (seccomp still
denies mount/unlink from inside; the mount is made by the supervisor via the
grant helper). 3 (the forward lives as long as the session; on session end
the host-side process is stopped and the mount dies with the mnt ns). 5
(annotation only; the mount is a bind of one inode if emitted in v2).

### Known information leak (round-1 review)

`getpeername(2)` on a connected `AF_UNIX` socket returns the peer's bound
`sun_path` — the host path of the forwarded socket. This is visible to the
sandbox through the socket API, not through the filesystem. The risk label
covers the **authority** the socket grants (signing, root-equivalent,
host-exec), not the confidentiality of the host path name. Leak test L36
records this as a WEAK check (the host path is visible through `getpeername`
but the sandbox cannot reach the host path as a file).

## 18. Docker T2 — raw socket forward (v0.3, ADR 0004)

**0.3 ships T2 only.** T1 (`tier = "proxy"`) and T3 (`nested_userns = true`)
are designed in ADR 0004 but rejected in 0.3 with `E_NOT_SUPPORTED` (round-1/2
BLOCKING: T1's bind-source TOCTOU, container-lifetime-by-construction, and
shared-bridge isolation are not achievable by a host-side proxy alone in
0.3; T3 needs subuid handling and a seccomp profile change).

### Decision

`[docker] tier = "socket"` is a `[[forward]]` of the Docker daemon socket
(`/var/run/docker.sock` or the host's docker socket). The sandbox can do
anything the Docker daemon can: create a privileged container, mount host
paths, start a container that mounts `docker.sock` again. This is
**root-equivalent**.

T2 is:
- never the default (DO NOT ALTER #4);
- never silent — `hisn run` prints `RISK: root-equivalent — docker:socket`
  on start, every start, to **stderr** (like all hisn diagnostics, §11),
  unless `--quiet-risk`;
- only loadable from a profile that contains `risk_ack = "root-equivalent"`
  in its `[docker]` block; a profile with `tier = "socket"` and no
  matching `risk_ack` is a **load error** (`E_RISK_ACK_REQUIRED`).

### What the sandbox can and cannot do

- **Can:** `docker ps`, `docker run`, `docker compose` — anything the daemon
  accepts. The daemon runs as root; a container it starts is not a child of
  the sandbox's PID namespace and does not inherit the sandbox's seccomp,
  Landlock, or rlimits.
- **Cannot** outlive the session: the **socket** dies with the session (it
  is a mount in the sandbox mntns); the **containers** the daemon started
  do **not** die with the session — they are daemon-owned, not sandbox-owned.
  This is why T2 is `root-equivalent` and `risk_ack` is required: the
  sandbox can start containers that outlive the session.

### What T2 makes advisory (round-1 BLOCKING)

A container started via the forwarded docker socket can mount host paths
(e.g. `docker run -v /run/user/$UID:/x`), and its processes descend from
`dockerd`, not from sandbox init. This means:

- **R5** (§9) accepts the container's processes by design (they do not
  descend from sandbox init), so a container can name and drive
  `control.sock` — self-granting `/` rw, revoking other sessions' grants.
- **Masks** (§4.2) and **revoke guarantees** (§10) are void for paths the
  container can reach via bind mounts.
- **L11** (session isolation) is void if a container mounts the runtime
  root.

This is the fundamental reason T2 is `root-equivalent` and `risk_ack` is
required: the sandbox can start a container that defeats every isolation
guarantee of the session. The profile author who sets `risk_ack =
"root-equivalent"` acknowledges this. T1 (0.4) closes these gaps by
filtering container creation; T2 does not.

### Rejected tiers

- `[docker] tier = "proxy"` → `E_NOT_SUPPORTED` (0.4). T1 is a host-side
  filtering proxy; the proxy is a separate untrusted-code boundary. It is
  designed in ADR 0004 but the review found gaps a proxy cannot close in
  0.3 (bind-source TOCTOU, container lifetime, shared-bridge isolation, build
  authority).
- `nested_userns = true` → `E_NOT_SUPPORTED` (0.4). T3 allows
  `unshare(CLONE_NEWUSER)` inside the sandbox for rootless podman/buildah;
  it needs a seccomp profile change (removing `CLONE_NEWUSER` from the deny
  mask) and subuid handling. Risk label: `kernel-surface`.

### Profile table and interaction with `[[forward]]`

```toml
[docker]
tier = "socket"
risk_ack = "root-equivalent"
```

In 0.3, `[docker] tier = "socket"` adds the **risk label** and
`risk_ack` enforcement but does **not** auto-create the forward. The
profile author must also write a `[[forward]]` entry for the docker socket:

```toml
[[forward]]
name = "docker"
socket = "/var/run/docker.sock"
expose = "/run/docker.sock"
risk = "root-equivalent"
risk_ack = "root-equivalent"
```

A `[docker]` block without a matching `[[forward]]` is valid (the risk
label is computed and the `risk_ack` is checked) but has no effect — no
socket is forwarded. A `[[forward]]` of the docker socket without a
`[docker]` block is also valid (the `[[forward]]` risk_ack covers the
forward); the `[docker]` block is for the `tier` declaration and future
0.4 features. A future 0.4 may add `[docker] socket = "/path"` to
auto-create the forward.

### Networking

A unix socket forward (§17) works cross-network-namespace: the socket is
reached by inode via a mount, not by network. `network = "none"` is
sufficient for `docker ps` and `docker run`. The shipped
`profiles/docker-socket.toml` uses `network = "host"` because the deploy
use case (smaragd) needs host networking for compose services, not for
reaching the daemon socket. A profile that only needs `docker run` (no
container networking) may use `network = "none"`.

### Shipped profiles

- `profiles/docker-socket.toml` — T2 with `risk_ack = "root-equivalent"`,
  `network = "host"` (for compose services), and a `[[forward]]` of
  `/var/run/docker.sock`.
- `profiles/deploy-smaragd-example.toml` — a deploy example: `network =
  "host"`, `cwd` rw, `mounts.grantable_rw` for deploy outputs, docker
  socket T2 with `risk_ack`.

### Leak test

L29 (host-only): requires a running Docker daemon. Asserts: (1) the RISK
line `RISK: root-equivalent — docker:socket` is printed on start; (2)
`docker ps` works inside the sandbox; (3) a profile with `docker =
"socket"` and no `risk_ack` is a load error (`E_RISK_ACK_REQUIRED`).

### OCI mapping

Annotation only (`org.hisn.docker.tier = "socket"`). The forwarded socket is
a `[[forward]]` mount (§17); if emitted in v2, it is a `mounts[]` bind of one
inode with `options: ["ro","nosuid"]` (matching §17's `MOUNT_ATTR_RDONLY |
MOUNT_ATTR_NOSUID`).

**Invariant touched:** 1 (T2 adds the docker socket, a single ro mount of one
inode). 2 (seccomp unchanged; the socket is host-side). 3 (the **socket**
dies with the session; the containers the daemon started do not — this is
why T2 is root-equivalent and acked; T2 also makes R5/mask/revoke advisory
for the session, as documented above). 5 (annotation only).

## 19. In-sandbox services `[[services]]` (v0.3, ADR 0002)

A `[[services]]` entry starts a long-lived process **inside the sandbox** after
the init sequence reports `READY` and before the supervisor sends `START`. The
service runs under the **same confinement as the main command**: same
namespaces, same seccomp, same Landlock (re-applied via the exec chain,
`§14.4`/`§14.12`), same caps (none), same env. It is a sibling of the main
command in the sandbox pid namespace, reaped by init.

### Schema

```toml
[[services]]
name      = "kvr"                             # required, unique among services
exec      = ["kvr-server", "--addr", "/run/kvr/kvr.sock"]
socket    = "/run/kvr/kvr.sock"               # optional: the path it listens on
ready     = { socket = "/run/kvr/kvr.sock" }  # one of: socket | command (not tcp in 0.3)
stop      = { signal = "TERM", grace = 5 }    # signal name + seconds; default TERM/5
restart   = "none"                            # only "none" in 0.3; other values → load error
```

`name` is unique among `[[services]]` entries (duplicate names are a load
error). `socket` is for display and `ls --json`; it is not validated against
the actual `bind(2)` address (the service may listen anywhere).

### Lifecycle

1. Init finishes the setup sequence (`DESIGN §3`), reports `READY`.
2. The supervisor starts each service through the **exec helper chain**
   (`DESIGN §14.2`, process `C→D→W→P`), exactly as a `hisn exec` would. The
   service is confined via `§14.4`: same `setns` + re-applied seccomp,
   Landlock, caps, NNP. The service gets its **own sibling Landlock domain**
   (`§14.12`); with the default `scoped = []`, the service and the main
   command may signal each other and reach each other's abstract sockets.
3. **Readiness**: the supervisor polls `ready` with a timeout (default 15 s;
   `ready.timeout` per service). On timeout the session fails to start (fail
   closed) — the service is killed and the session exits `125`.
   - `ready.socket = "<path>"`: the supervisor stats the path **from the
     supervisor's mount namespace** (userns S). This works for paths under cwd
     (a rw bind visible from S) and under `mounts.ro`/`mounts.rw` (also visible
     from S). It does **not** work for paths on the sandbox's private tmpfs
     (`/tmp`, `/run`, `$HOME`); for those, use `ready.command` instead.
   - `ready.command = ["sh", "-c", "test -S /run/kvr/kvr.sock"]`: the supervisor
     runs the command **through the exec helper chain** (inside the sandbox).
     This is the readiness check for sockets on private tmpfs.
   - `ready.tcp` is **not available in 0.3** for in-sandbox services (the
     supervisor cannot reach the sandbox's netns; `network = "none"` has only
     loopback). A `ready.tcp` entry is a load error for `[[services]]`.
4. **Stop** (best-effort): before the supervisor closes the ns fds and
   removes the session dir (`§10`), it sends `stop.signal` to each service's
   process group, waits `stop.grace`, then `SIGKILL`. If init exits first
   (command exit, `hisn kill`), the kernel destroys the pid ns and SIGKILLs
   everything in it — the graceful stop is moot but harmless. The supervisor
   does not delay init's exit for the grace period; the stop is best-effort.
   For `--detach`: the supervisor sends `stop.signal` + grace + `SIGKILL`
   before closing the ns fds.
5. `restart = "none"`: if a service exits before the session ends, it stays
   down. The supervisor logs the exit and does **not** restart. (0.4 may add
   `restart = "on-failure"`.)

### Service stdio

A service has no client connection; its stdio is directed to `/dev/null` (the
sandbox's own `/dev/null`, via the exec helper's `child_d` which points fds 0-2
at `/dev/null`). The service may write to its own stdout/stderr but the output
is discarded. The status socket for a service is owned by the supervisor
(the same as an exec), not by a client connection; the supervisor reads the
`P` and `X` lines to track the service's state for `ls --json`.

### What the service can and cannot do

The service is confined via `§14.4` (re-applied in `D`), like any exec. It can:

- bind a unix socket at `socket` inside the sandbox (via `bind(2)`, which is
  not `mount --bind`; seccomp denies `mount`, not `bind(2)`). Other sandbox
  processes can `connect(2)` to it.
- read/write within the sandbox's writable set (cwd, `$HOME`, `/tmp`, `/run`,
  `mounts.rw`, `mounts.grantable_rw`).

It cannot:

- escape the sandbox (same seccomp/Landlock/caps as init; no `mount`/`unshare`/
  `setns`/`open_tree`/`move_mount`).
- outlive the session (it is in the pid ns; when init exits the kernel kills
  every process in the namespace).

A hostile main command (same uid, same pid ns) can `kill` the service, `unlink`
its socket, and `bind(2)` a replacement at the same path — this is inherent to
the sandbox model (all processes share the same uid and pid ns). The service's
protocol must be robust against this; the profile author is told by `risk =
none` that the service adds no host-side capability, not that it is protected
from the main command.

### `ls --json`

`hisn ls --json` gains a `services` array:
`[{name, pid, socket, state: "starting|ready|exited", exit}]`. The `pid` is
the in-sandbox pid (same namespace as `exec` pids). `state` is `starting`
until readiness is confirmed, `ready` after, `exited` if the service exits
before the session ends. The schema is additive (`hisn-ls/v2`; `v1` fields are kept).

### Risk label

A `[[services]]` entry that starts a process inside the sandbox does not widen
the boundary beyond the sandbox itself — the service is confined like the main
command. The risk label is `none` (the service adds no host-side capability;
it is a sibling process, not a host-side process). `risk_ack` is not required.

### Shipped profile

- `profiles/kvr-example.toml` — a `[[services]]` entry for a kvr-server
  listening on `{cwd}/.wakil/kvr.sock`, with `ready = { command =
  ["test", "-S", "{cwd}/.wakil/kvr.sock"] }` (readiness via exec chain, since
  the socket is on a rw bind under cwd, visible from the supervisor) and
  `stop = { signal = "TERM", grace = 5 }`.

### Wakil integration

Wakil declares a `[[services]]` entry in its profile. The service's socket
is at `{cwd}/.wakil/kvr.sock` inside the sandbox. Because cwd is a rw bind of
the host directory at the identical path (path parity, `§4.1` row 6), the
socket file is visible on the host at the same path. Wakil's host-side client
connects to that path. A stale socket file at that path after session end is
cleaned up by Wakil (not by hisn); the session dir cleanup does not remove
files created inside cwd by the sandbox. See `docs/WAKIL-INTEGRATION.md`.

### Leak tests

- **L31** (kvr-example): the service socket is connectable from a second exec;
  the service dies with the session; `inspect` shows the same mount table as
  the 0.2 plan (the service adds no mounts; the socket is `bind(2)`, not a
  mount).
- **L41** (readiness timeout): a service with a readiness check that never
  succeeds → the session fails closed (exit 125); nothing is left running.

### OCI mapping

Annotation only (`org.hisn.services=[{name,socket,exec}]`). The service runs
in the same namespaces; there is no `mounts[]` entry (the socket is bound by
the service, not mounted by the supervisor).

**Invariant touched:** 1 (the root is still an empty tmpfs + pivot_root — the
service sees the same root). 2 (same seccomp — the service is exec'd through
the same chain). 3 (the service is in the pid ns and dies with it — `restart =
"none"` means no out-of-band restart). 5 (annotation only).

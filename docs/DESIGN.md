# hisn — design

Status: v0 design, pre-implementation. Binding input: `docs/BRIEF.md`
(the DO NOT ALTER block there always wins). This document expands the brief's
architecture and records every place where working it through forced a
refinement (§12 "Deviations from the brief"). Items marked **[HOST-VERIFY]**
cannot be exercised in the Wakil build sandbox (user namespaces and the mount
API are blocked there, see `hisn check` output in the README/close-out) and
must be confirmed by `make leaktest` on a real host.

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
`newuidmap` is detected by `hisn check` but **not used in v0** (§12, D4).

The supervisor must be single-threaded for `unshare(CLONE_NEWUSER)`; all
namespace work therefore happens before the control thread starts, and the one
grant helper is forked at that point (never `fork()` from the threaded
supervisor afterwards).

## 3. Sandbox init (PID 1) — build order

All steps run in U with full caps *inside U only*. Any failure aborts the
session before the command runs (fail closed).

1. Write `setgroups=deny`, `uid_map`, `gid_map` (own single id); then wait for the supervisor's `GO` (it has opened `/proc/<init>/ns/*` by then).
2. `prctl(PR_SET_PDEATHSIG, SIGKILL)` — init dies if the supervisor dies, so
   no sandbox outlives its supervisor (invariant 3). Mark init
   `PR_SET_DUMPABLE=0` (see §6).
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
7. Generate `/etc/passwd`, `/etc/group` (mapped uid only), `/etc/resolv.conf`
   (only for `network = "host"`) in `R/.stage`, bind over the `/etc` entries,
   unlink the staging names (the bind keeps the inode alive).
8. `sethostname`; for `network = "none"` bring `lo` up (`SIOCSIFFLAGS`).
9. `chdir(R)`, `pivot_root(R, R/.old)`, `chdir("/")`, `umount2("/.old",
   MNT_DETACH)`, `rmdir("/.old")` (invariant 1). Close every fd > 2 that is
   not the control channel (`close_range`).
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
  On `accept` the supervisor obtains the peer identity with `SO_PEERPIDFD`
  (kernel ≥ 6.5) or `SO_PEERCRED` pid, opens `/proc/<pid>/ns/pid`, and compares
  its inode with that of `/proc/<init>/ns/pid` (held open since start). Equal,
  unreadable, or process-already-gone ⇒ close the connection (fail closed). The
  check is repeated for every request line. This holds even if a bind alias,
  an inherited fd, or any other mount-topology accident makes `control.sock`
  *nameable* from inside, because a sandbox process always carries the
  sandbox pidns. (A sandbox process cannot hide in another pidns: seccomp
  denies `unshare`/`setns`/`clone(CLONE_NEWPID)` and it has no caps.)
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

## 13. Module map

`policy` (schema, load, validate, resolve) → `check` → `mounts` (pure plan) →
`rootfs` (executes plan) → `init` (§3) → `seccomp` → `landlock` → `env` →
`session`/`supervisor`/`control` → `grant` (supervisor + helper) → `cli` →
pty relay (in `supervisor`). Pure functions (policy, env scrub, mount plan,
seccomp rule set, rule R1–R4 checks) carry the unit tests; everything
namespace-dependent is covered by `tests/leak` on a host.

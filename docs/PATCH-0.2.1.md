# hisn 0.2.1 — patch release spec

0.2.1 is a patch release on top of 0.2.0: fixes and small additions with **no
new boundary**. A 0.2.0 policy yields the identical sandbox under 0.2.1 except
for the fixes below. No feature is on by default if it widens the 0.2 sandbox
(DO NOT ALTER #3). Baseline: `ab58f95` (plan docs only; code is 0.2.0).

This build sandbox blocks user namespaces: build, fmt, clippy `-D warnings`
(x86_64 + aarch64), unit tests run here; leak tests are "run on host" with
exact commands in `docs/VERIFICATION.txt`. Never fabricate leak results.

## Patches

### 1. `/dev/shm`

**Behaviour.** New policy keys `session.shm` (bool, default `false`) and
`session.shm_size` (u64, MiB, optional; default 64). When `shm = true`,
`mounts.rs` adds a tmpfs at `/dev/shm` (`size=<shm_size>m`, `mode=1777`,
`nosuid,nodev,noexec` — matching `/dev`'s flags, not `/tmp`'s) to the mount
plan, after `/dev` and before `/tmp`. When `shm = false` (default) `/dev`
stays the 0.2 fixed set (no `/dev/shm`).

**Errors.** `shm_size` outside `1..=65536` → `E_POLICY_INVALID` at load.

**Tests.** L33: `/dev/shm` is present when `shm = true`, absent by default; a
file created in `/dev/shm` by exec A is visible to exec B; absent from the host
`/proc/self/mountinfo`. L8 expectation updated to include or omit `/dev/shm`.

**OCI.** `mounts[]` `{destination:"/dev/shm", type:"tmpfs",
options:["nosuid","nodev","noexec","mode=1777","size=…m"]}`.

**Invariant.** 1 (root is still empty tmpfs + pivot_root — `/dev/shm` is one
more mount inside `/dev`); 2 (seccomp unchanged — `shm` is a mount, not a
syscall). Default off = 0.2 sandbox.

### 2. `/tmp` size configurable

**Behaviour.** New policy key `session.tmp_size` (u64, MiB, default 1024,
range `16..=65536`). `mounts.rs` `TMP_SIZE` (currently `1 << 30`) becomes
`tmp_size << 20` from the resolved policy. Everything else unchanged.

**Errors.** `tmp_size` outside `16..=65536` → `E_POLICY_INVALID`.

**Tests.** L8 (mount-plan comparator) covers the value; no new leak test.

**OCI.** `mounts[]` tmpfs `size=…m` (same row, new value source).

**Invariant.** none (a size change on an existing tmpfs).

### 3. passwd/group stub with host username

**Behaviour.** `mounts.rs::passwd_stub` already uses `HostFacts.username`
(populated from `$USER` in `supervisor.rs::getids`, fallback `"user"`). The
stub writes `name:x:uid:gid:name:<sandbox-home>:/bin/sh`. `/etc/group` writes
`name:x:gid:`. No code change expected — verify `id -un` inside the sandbox
prints the host username; if it does not, fix the stub.

**Errors.** none new.

**Tests.** L1 expectation: `id -un` inside the sandbox equals the host
`$USER`. Already covered if L1 is updated to check.

**OCI.** no change (generated files; same as today).

**Invariant.** 4 (env unchanged — the username comes from `$USER` at session
start, not from host env inside the sandbox).

### 4. init argv scrub

**Behaviour.** After `GO`/`READY` and before the `fork()` that starts the
command, init overwrites its own `argv` memory in place: `argv[0]` →
`"hisn-init"`, remaining argv bytes zero-filled. Then
`prctl(PR_SET_NAME, "hisn-init")`. `PR_SET_NAME` alone does **not** change
`/proc/1/cmdline` (it sets the comm name only) — the argv memory itself must be
overwritten. The session id, policy path, and session dir must not appear in
`/proc/1/cmdline` inside the sandbox. Init's argv comes from `args.command`
(the user's command), so the scrub replaces it with the opaque string. In
`--detach` mode (no command), init's argv is already `["hisn-init"]` or
similar; the scrub is a no-op there.

Zero-filling the argv region in place does not change the length the kernel
reports for `/proc/1/cmdline` — the arg region's byte count is fixed at
`execve` time. `/proc/1/cmdline` will contain `hisn-init\0` followed by NUL
padding to the original argv length. L34 must assert the **content** starts
with `hisn-init` and contains no non-NUL bytes after it — not that the file is
exactly `hisn-init\0` (which zero-fill alone cannot achieve without
`PR_SET_MM_ARG_START/END`, and that needs `CAP_SYS_RESOURCE` which the init
userns does not grant). The goal is that the session id, policy path, and
session dir do not appear; `hisn-init` followed by NUL padding satisfies that.

**Errors.** none (best-effort; failure to overwrite is not fatal — the
confinement is already in place).

**Tests.** L34: from an exec'd shell, read `/proc/1/cmdline` and assert the
content starts with `hisn-init\0` and contains no non-NUL bytes after it —
no session id, no policy path, no session dir. (Zero-fill leaves NUL
padding to the original argv length; the assertion checks content, not file
size.)

**OCI.** no OCI equivalent (process title); annotation
`org.hisn.init.scrub=true`.

**Invariant.** 1 (the scrub does not change the mount plan); 2 (seccomp
unchanged). The scrub prevents information leak through `/proc/1/cmdline`.

### 5. stale session cleanup

**Behaviour.** At session start the supervisor writes
`<session-dir>/supervisor.pid` containing its pid and the starttime field
from `/proc/<pid>/stat` (field 22 after the `)` — parse with `rsplit(')')`,
then split whitespace and take field 20, 0-indexed). A session dir is
**stale** if both:

1. `control.sock` refuses connection with `ECONNREFUSED` or `ENOENT` (the
   socket file does not exist or nothing listens). A timeout, `EAGAIN` on a
   full backlog, or any other transient error means **not stale** — a busy
   live supervisor must never be classified stale.
2. `supervisor.pid` is present, readable, and the pid is either not alive
   (`kill(pid, 0)` fails with `ESRCH`) **or** the starttime from
   `/proc/<pid>/stat` does not match the recorded value.

A **missing** `supervisor.pid` means **not stale** (a 0.2.0 dir without the
file, or a 0.2.1 session between `mkdir` and writing the file — both are
live or starting, never stale). A **malformed** `supervisor.pid` (non-numeric
pid, missing starttime, symlinked) means **not stale** — do not delete a dir
whose metadata cannot be parsed; log it at `-v` and skip.

The check is performed twice 300 ms apart (to avoid racing a live session
mid-shutdown). Both checks must agree: stale on both. If the second check
finds the socket connects, the dir is live — abort removal.

- `hisn kill --session X` on a stale dir: remove the dir, print
  `session X was stale; removed` to stderr, exit 0. (A live session is
  killed as today; a hung-but-alive session where the socket refuses but the
  pid is alive with matching starttime is **not stale** — `kill` sends
  SIGTERM as today.)
- `hisn run --session-id X` with a stale dir: remove it, log one line at
  `-v`, proceed. A **live** dir with the same id is still an error
  (`E_EXISTS`).
- `hisn ls --prune`: remove all stale dirs, print each removed id to stderr.
  A non-stale dir is a no-op (printed as `skipped` at `-v`).

**Removal safety.** Removal is **only** inside the hisn runtime root
(`$XDG_RUNTIME_DIR/hisn` / `/tmp/hisn-$UID`). The runtime root itself is
verified at startup by `session::ensure_root` (owner = uid, mode 0700, not a
symlink — already enforced). Each session dir is removed by opening it
relative to the runtime root fd with `openat2(RESOLVE_NO_SYMLINKS |
RESOLVE_BENEATH | RESOLVE_NO_XDEV)` + `unlinkat(fd, name, AT_REMOVEDIR)`.
`RESOLVE_NO_XDEV` prevents crossing a mount boundary — a same-uid attacker
who `mount --bind $HOME <stale-dir>/x` cannot redirect the recursive
removal to `$HOME` (the bind is a mount, not a symlink; `RESOLVE_NO_SYMLINKS`
alone does not stop it). Refuse if any entry inside the dir is not owned by
the uid. A symlink entry is **unlinked, not followed and not refused**
(`unlinkat` never dereferences its final component, so a link to `$HOME` is
removed and `$HOME` is untouched; refusing would leave the stale dir behind,
which host run L17b caught). `unlinkat` (not `remove_dir_all`) is used so the
traversal is fd-relative and flag-bounded, not path-based.

The `supervisor.pid` file is treated as a **hint**, never the sole liveness
signal — the socket refusal + pid check is the staleness test, and a missing
or malformed hint means "not stale" (fail safe).

**Errors.** `E_EXISTS` for a live dir on `run --session-id`. Stale removal
on `kill` prints `session X was stale; removed` to stderr (one line). Stale
removal on `run` logs one line at `-v`. `--prune` on a non-stale dir is a
no-op (printed as `skipped` at `-v`). No output on stdout (stderr only).

**Tests.** L17b: SIGKILL a supervisor, assert `ls` shows the session as
stale; `run` with the same id succeeds and the old dir is gone; `--prune` on
another stale dir removes it; a **bind mount** planted inside a stale dir
pointing at a host directory is not traversed (`RESOLVE_NO_XDEV`); a
symlink planted inside a stale dir pointing at `$HOME` is not followed;
`--prune` on a dir with a missing `supervisor.pid` does not remove it;
`--prune` on a live session does not remove it (socket connects on second
check). A sentinel file outside the stale dir under the runtime root is
unaffected.

**OCI.** no OCI equivalent (session lifecycle).

**Invariant.** 3 (cleanup removes only stale state; a live session is
untouched). The removal path is symlink-safe, mount-safe (`RESOLVE_NO_XDEV`),
owner-checked, mode-checked, and confined to the runtime root (DO NOT
ALTER: a cleanup path pointed elsewhere is a host-delete primitive).

### 6. R5 ancestry retry (P16)

**Behaviour.** `supervisor::authorize_peer` (R5, DESIGN §9) retries the
whole `/proc/<pid>/status` ancestry walk on `ENOENT`/`ESRCH` from any
ancestor read — the observed failure is an ancestor vanishing mid-walk. 3
attempts, 50 ms apart. `EINTR` is also retried (a signal during the read).
Refuse (fail closed) only if the **peer itself** is gone or the chain still
cannot be established after retries.

**Peer identity across retries.** The peer pid is captured once from
`SO_PEERCRED` at the start of `authorize`. On kernel ≥ 6.5,
`SO_PEERPIDFD` is preferred (it pins the peer process, immune to pid reuse).
On retry, the peer is re-checked: if using `SO_PEERPIDFD`, the pidfd must
still be alive; if using `SO_PEERCRED` only, the peer's starttime is
captured on the first attempt and compared on each retry — a reused pid
with a different starttime means the original peer is gone (refuse).

**Reparenting.** When an ancestor dies mid-walk, children reparent to the
namespace init. The retry does **not** accept "reaches pid 1" as success —
the retry must reach the **sandbox init** (the specific pid stored in
`self.sh.init_pid`), not a reparented substitute. A reparented chain that
reaches a different init (e.g. the host's pid 1) is a refuse. The walk's
target is the sandbox init pid, not "any pid 1".

**Errors.** refusal is `Refuse::Unknown` (same as today). The retry
suppresses transient `ENOENT`/`ESRCH`/`EINTR` on ancestor reads only; the
peer-identity check (starttime or pidfd) is never retried past a mismatch.
Parse errors (`InvalidData` — no `PPid` line), permission errors (`EACCES`),
and depth-limit exhaustion are **not** retried — they are immediate refuses.

**Tests.** L14c: 200 rapid `hisn ls` invocations from a shell loop that
forks short-lived parents → 0 refusals (availability; host-only). Unit test
with a fake `/proc` tree where an ancestor disappears between attempts (the
test that can run here). A negative unit test: a peer whose pid is reused
between attempts (starttime mismatch) is refused, not accepted.

**OCI.** no OCI equivalent (control-socket defence).

**Invariant.** 2 (R5 is the control socket's defence; retries never turn an
unestablished chain into an accept — the retry targets the sandbox init, not
"reaches pid 1"; a reused peer pid is detected via starttime/pidfd — DO NOT
ALTER #4).

### 7. `--ready-fd N`

**Behaviour.** New `hisn run --ready-fd <N>` flag. After the control socket
accepts and the session would be reported `live` (after `START` is sent,
initial grants applied), write `"ready\n"` to fd N and close it. On start
failure write nothing (the exit status carries it). Works with and without
`--detach`. The fd is the caller's; hisn does not create it. The fd is
closed (or never passed to init) before the sandbox command forks — the
sandboxed process must not inherit it. `close_range` in init already closes
every fd > 2 that is not the control channel; `--ready-fd` is closed by the
supervisor after writing, before `START` is sent.

**Errors.** fd N not writable → `E_BAD_REQUEST` (reported on stderr, exit
125). Session start failure → nothing written, exit status carries it.

**Tests.** unit test: pass a pipe fd, assert `"ready\n"` is read after
`hisn run --detach` returns. No new leak test (readiness is a protocol
addition, not a boundary change).

**OCI.** no OCI equivalent.

**Invariant.** none (a readiness signal; does not change confinement).

### 8. opaque exec ids

**Behaviour.** Every exec gets `exec_id = "e-<n>"` (monotonic per session,
never reused). Response: `{"ok":true,"pid":N,"exec_id":"e-n"}`. `signal`
accepts `exec_id` (preferred) or `pid` (kept for 0.2 clients, marked
deprecated in POLICY-SPEC §7). `exec_id` of a finished exec → `E_NOT_FOUND`.
A bare `pid` request cannot distinguish a stale client's reference from a
fresh one to the same numeric pid; the rule is: once a pid has been reused by
a different exec within the session, `signal` by that pid →
`E_NOT_FOUND` (the pid is no longer unambiguously the original exec). The
supervisor tracks `pid → exec_id` at spawn time and marks a pid as
"recycled" when a new exec reuses it; a recycled pid is rejected even if the
new exec is still live (the client must use `exec_id`). `hisn ls --session X
--json` lists live execs with their `exec_id`s.

**Errors.** `E_NOT_FOUND` for a stale `exec_id` or a recycled `pid`.

**Tests.** L35: signal via `exec_id` works; signal via a stale `exec_id` →
`E_NOT_FOUND`; signal via a recycled `pid` (start an exec, let it exit,
start another exec that reuses the pid) → `E_NOT_FOUND`.

**OCI.** no OCI equivalent (control-protocol only); annotation
`org.hisn.exec.id=…`.

**Invariant.** 2 (control protocol addition; R5 unchanged). The exec_id
prevents a stale client from signalling the wrong exec after pid reuse.

### 9. frozen `--json` schemas

**Behaviour.** `hisn ls --json` → `{"schema":"hisn-ls/v1","sessions":[…]}`;
each session: `{id, state, cwd, hostname, network, pid, started,
execs:[…]}`. `hisn inspect --json` → `{"schema":"hisn-inspect/v1", …}`.
`cwd` is added now (discovery in 0.3 needs it). `hisn ls --json` with no
sessions returns `{"schema":"hisn-ls/v1","sessions":[]}` (empty array, not
nothing). New doc `docs/JSON-SCHEMAS.md`: fields, types, "additive only"
rule (future versions add fields, never remove or rename).

**Errors.** none new.

**Tests.** unit tests for the JSON shape (schema field present, empty
array, execs array). No new leak test.

**OCI.** no OCI equivalent (CLI output format).

**Invariant.** none (output format; does not change confinement).

### 10. musl ioctl casts (optional, P22)

**Behaviour.** Fix the `u64`→`c_int` ioctl request-type casts in
`src/init.rs` (`TIOCSCTTY`, `SIOCSIFFLAGS`, `TIOCSPTLCK`, `TIOCGPTN`) so
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` compile. Add a
CI job that builds musl (no release artifact) and, on ubuntu-24.04, runs
`make leaktest` with the musl binary. Release stays glibc until the user
decides; README note updated to say musl builds and where the leak result is.

**Errors.** if the fix needs more than `as _` casts (e.g. conditional code
per target), stop and report — do not restructure `init.rs`.

**Tests.** CI musl build + leak run on ubuntu-24.04.

**OCI.** none (build target).

**Invariant.** none (build fix only).

## Implementation order

9 → 7 → 8 → 5 → 6 → 3 → 4 → 1 → 2 → 10. Commit per patch; `cargo fmt` +
`clippy -D warnings` (x86_64 + aarch64) + `cargo test` green after each.

## Docs to update

POLICY-SPEC (`shm`, `shm_size`, `tmp_size`, `exec_id`, deprecated `pid`,
`--ready-fd`, `--prune`), DESIGN (§3 argv scrub, §9 R5 retry, §14 exec_id),
OPEN-POINTS (P16 resolved, P22 status), CHANGELOG 0.2.1, README (`--prune`,
`--ready-fd`), `tests/leak/run.sh` (L14c, L17b, L33, L34, L35),
`docs/VERIFICATION.txt` (rows as "not run" until the host log exists),
`docs/JSON-SCHEMAS.md` (new).

## Host commands (verbatim)

```
cargo install --path . --locked
make lint && make test
make leaktest-log
```

Plus the two Wakil-side follow-ups this enables: switch to `--ready-fd`;
signal by `exec_id`.
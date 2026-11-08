# hisn 0.4.1

## What's new

0.4.1 closes four of the 0.4.0 known issues and removes the fixed ~100 ms
latency floors on the session-ready and stop paths.

### `hisn run --detach` returns
The parent forks the supervisor (`setsid`, stdio to
`<session-dir>/supervisor.log` 0600), waits until the control socket accepts,
prints `<id> <name|-> ready` on stdout and exits 0. A start failure prints the
supervisor's first error lines and exits non-zero. Without `--detach` nothing
changes.

### `ls --json` completes `hisn-ls/v2`
- `clients`: the live control connections (uid, pid, label, label_source,
  connected_since).
- a live attach appears under `execs` with `attach: true`.
- `services` and `rootfs` are populated.
- For a stopped/crashed session `clients` is `[]` and CLIENTS is 0.
- Additive; the schema name stays `hisn-ls/v2`.

### Prune scope
- `hisn ls --prune --name-prefix <prefix>` prunes only stopped/crashed sessions
  named `<prefix>*`; an unnamed session never matches.
- `hisn ls --prune --dry-run` lists what would go, removing nothing.
- A name is reusable once its session directory is gone.

### CLI
- `hisn exec --client LABEL` (same as attach).
- `hisn run --env-file PATH` (`KEY=VALUE` lines; the way to pass secret-shaped
  values without them appearing in `/proc/<pid>/cmdline`).
- `hisn stop` on an already-stopped session says `already stopped`; on a crashed
  one `crashed, no supervisor`; both exit 0.

### Latency
- Readiness and stop waits are event-driven. Readiness polls the control socket
  with a 1 ms → 20 ms exponential backoff (nonblocking connect); stop waits on
  the supervisor's pidfd. Measured in `tests/latency.rs`: a socket that appears
  after 8 ms is observed ready in ~15 µs (one probe), a stop in ~82 µs. No fixed
  100 ms poll remains on either path.

### Hardening
- Host env read with `vars_os()` (non-UTF-8 must not panic).
- `hisn inspect` redacts secret-shaped `[env.set]` values.
- A `[net] nameservers` override that is empty or loopback-only is refused by
  the builder; `is_loopback_ns` also rejects `0.0.0.0`, `::`, and
  `::ffff:127.0.0.0/8`.
- Admission and the idle check share the lease lock.
- `touch_lease` writes `session.json` only when the session has a lease.

## Known issues (0.4.1)
- **`ttyname()` inside an attach still fails.** The attach's pty is on the host
  `devpts`; the session has a private `devpts`, and the kernel refuses a second
  non-`newinstance` devpts in the session's user namespace. The
  isolation-preserving fix (allocate the pty inside the session and hand the
  master back over the control socket) is a protocol change that needs a host to
  verify. Not shipped in 0.4.1; the L76 host step is listed below.
- L56 and L58 remain host-only / documented checks.

## Host verification (rubin)
1. `cargo test --release`
2. `HISN_TEST_ROOTFS="$(hisn rootfs path wakil-dev)" make leaktest`
   (expects L1–L75; L73/L74/L75 are the new HOST ids)
3. `hisn run --name t --detach` — returns `<id> t ready`
4. `hisn attach --session t` then, inside the attach, `tty` (expects
   `/dev/pts/N`) and `tmux new -d -s t && tmux ls`
5. `hisn ls --json` — `clients` reflects the live connections
6. `hisn ls --prune --name-prefix wakil-`

The build sandbox blocks user namespaces, so the leak suite and the host steps
above were **not run here**; unit tests and `tests/leak/test_l8.py` were. Two
unit tests fail only in this sandbox and pass on a host
(`scrub_argv_overwrites_cmdline`, `proc_self_mem_is_not_writable_after_apply`).

## Gate
- `cargo fmt --check` ✓
- `cargo clippy --all-targets -- -D warnings` ✓
- `cargo test --lib` ✓ (386 pass; the two sandbox-only failures above are in
  the ignored set)
- `python3 tests/leak/test_l8.py` ✓
- `make leaktest` — HOST only (needs user namespaces)

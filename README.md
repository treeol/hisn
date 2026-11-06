# hisn

**A rootless, daemonless, single-binary sandbox for AI coding agents on Linux.**

[![CI](https://github.com/treeol/hisn/actions/workflows/ci.yml/badge.svg)](https://github.com/treeol/hisn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/treeol/hisn)](https://github.com/treeol/hisn/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/logo.png" alt="hisn logo" width="256">
</p>

**hisn** runs a command in a private view of your machine. The command sees its
working directory at the *same path* as on the host, a read-only toolchain, and
private `$HOME`, `/tmp` and `/run`. Anything else exists only if you grant it,
and every grant ends with the session. Paths outside the view are not denied,
they are absent: `ENOENT`.

- **Rootless and daemonless.** One binary, no root, no setuid helper, no file
  capabilities, no background service.
- **Absent, not blocked.** The root is an empty tmpfs entered with `pivot_root`;
  the host filesystem is not reachable, so there is nothing to probe.
- **Path parity.** Your project lives at the identical path inside, so tools,
  error messages and editors keep working.
- **Steerable while it runs.** Add and remove access, run more commands, and
  signal them from outside, over a control socket the sandbox cannot reach.
- **Agent-agnostic.** A plain CLI with exit codes and versioned JSON; see
  [programmatic use](#programmatic-use).

## Contents

[Quick start](#quick-start) · [What the sandbox contains](#what-the-sandbox-contains) ·
[Install](#install) · [Usage](#usage) · [Policy](#policy) ·
[Programmatic use](#programmatic-use) · [Security model](#security-model) ·
[Verifying a build](#verifying-a-build) · [Status](#status) ·
[Documentation](#documentation)

## Quick start

```sh
hisn check                                              # does this host qualify?
hisn run -- make test                                   # cwd rw, toolchain ro, nothing else
hisn run --policy hisn.toml --grant ~/data:ro -- ./job  # with a policy and a read-only grant
hisn run --profile base -- make test                    # with a profile (built-in: base, wakil)
```

`hisn run` passes stdio through unchanged and allocates a pty inside the sandbox
when stdin is a terminal. It exits with the command's status.

| Exit code | Meaning |
|---|---|
| `0`-`124` | the command's own status (a command that itself exits 125-127 is indistinguishable from the cases below) |
| `128+N` | the command was killed by signal `N` |
| `125` | hisn error (policy, host, refused request) |
| `126` / `127` | the command could not be executed / was not found |

Add `-v` (repeatable) for logs on stderr.

## What the sandbox contains

| Path | Inside the sandbox |
|---|---|
| working directory | read-write, at the identical host path |
| system toolchain (`/usr` and friends) | read-only |
| `$HOME`, `/tmp`, `/run` | private tmpfs, discarded with the session (`/tmp` size is configurable) |
| `/dev/shm` | absent unless `session.shm = true` |
| `/etc` | the entries present at start, minus secrets |
| `/proc`, `/dev` | the sandbox's own; `/sys` is absent |
| granted paths | present until revoked or the session ends |
| everything else | does not exist |

The environment is rebuilt from scratch: `PATH`, `HOME`, `TERM`, `LANG`, `LC_*`,
`TZ`, plus the keys you list in `env.pass`. Host secrets in the environment never
enter. Inside, `/etc/passwd` and `/etc/group` hold a stub for your uid (user name
taken from `$USER`), and `/proc/1/cmdline` reads only `hisn-init`, so the
session id and host paths are not exposed.

## Install

**Release binary** (Linux x86_64 or aarch64), from the
[latest release](https://github.com/treeol/hisn/releases/latest):

```sh
# x86_64; use hisn-aarch64-linux-gnu on aarch64
curl -fsSLO https://github.com/treeol/hisn/releases/latest/download/hisn-x86_64-linux-gnu
curl -fsSLO https://github.com/treeol/hisn/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
install -m 0755 hisn-x86_64-linux-gnu ~/.local/bin/hisn
hisn check
```

**From source** (Rust stable, edition 2024):

```sh
cargo install --path . --locked
hisn check
```

`hisn check` reports whether the host qualifies (exit 2 if not; `--json` for a
machine-readable report). hisn needs no root, no setuid binary and no file
capabilities. It requires kernel 5.12 or newer with unprivileged user
namespaces, Landlock and seccomp. On Ubuntu 24.04 AppArmor restricts
unprivileged user namespaces by default
(`kernel.apparmor_restrict_unprivileged_userns`); `hisn check` shows the value.

The release binaries are dynamically linked glibc builds (glibc 2.35 or newer).
The ioctl casts that blocked musl were fixed in 0.2.1 (OPEN-POINTS P22), but a
musl build has not been verified to compile or been leak-tested, so no static
binary is published.

## Usage

### One-shot commands

```sh
hisn run -- make test
hisn run --cwd ~/src/app --network none -- cargo test
hisn policy validate hisn.toml          # print the resolved policy
hisn policy schema                      # JSON Schema of hisn-policy/v1
```

### Long-lived sessions

A session can be steered from outside while it runs. This is how an agent
runtime hands a sandboxed process more access, or runs further commands in it.

```sh
hisn run --session-id agent1 --detach &      # a session with no command of its own

hisn exec   --session agent1 -- ls -la                  # another command, same confinement
hisn exec   --session agent1 --tty -- bash              # interactive, on its own pty
hisn exec   --session agent1 --no-tty -- make test      # non-interactive: no pty, stdin /dev/null (0.3.3)
hisn grant  --session agent1 /srv/reference             # read-only, gone with the session
hisn grant  --session agent1 --rw /srv/out              # needs a mounts.grantable_rw prefix
hisn revoke --session agent1 /srv/reference             # the path becomes ENOENT
hisn revoke --session agent1 --hard /srv/out            # also kills every sandbox process
hisn ls --session agent1                                # grants of one session
hisn inspect --session agent1                           # mount table and resolved policy
hisn kill --session agent1
```

Every `exec` runs in the same namespaces, with the same seccomp filter,
Landlock domain and dropped capabilities as the original command, and sees the
same grants.

### Housekeeping

```sh
hisn ls                  # all your sessions
hisn ls --json           # same, as versioned JSON
hisn ls --prune          # remove session directories whose supervisor has died
hisn kill --session X    # on a stale session: removes the directory, exits 0
```

A session is *stale* when its control socket refuses connections and its
supervisor process is gone (checked twice, 300 ms apart). Removal is
fd-relative and confined to that one directory: a planted symlink is unlinked,
never followed, and a planted bind mount is never entered.
`hisn run --session-id X` over a stale directory removes it and proceeds; over a
live one it fails.

### Profiles (0.3)

A profile (`hisn-profile/v1`) is an envelope around a policy that adds
orchestration surface: persistent home, rootfs, SSH agent, in-sandbox services,
socket forwarding, host-side services, and Docker access. Each capability
that widens the boundary carries a risk label (`none`, `trust`, `data`,
`signing`, `host-exec`, `root-equivalent`, `kernel-surface`).

```sh
hisn profile list                           # search path and built-in profiles
hisn profile explain [name]                  # capabilities and risk labels
hisn profile validate [file]                 # resolve and print the inner policy
hisn run --profile base -- make test         # built-in: base (0.2 sandbox)
hisn run --profile wakil -- make test        # built-in: wakil (grantable_rw)
hisn run --home-persist ~/.cache/wakil/home/proj -- make test  # persistent $HOME
hisn run --rootfs-path /path/to/rootfs -- make test            # rootfs toolchain
```

Profile tables (all optional; absent = 0.3.1 behaviour):

```toml
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
# … inner policy …

[home]
persist = "/home/user/.cache/wakil/home/proj"   # persistent $HOME (survives sessions)

[rootfs]
name = "go-dev"            # from the rootfs store ($XDG_DATA_HOME/hisn/rootfs/<name>/)
# or
path = "/path/to/rootfs"   # a directory directly

[ssh]
agent = true               # filtering proxy (T1: sign but never add/remove/extract)
keys = ["SHA256:…"]       # fingerprint allowlist (absent = all keys)

[net]
nameservers = ["192.168.1.111"]   # optional (0.3.3): DNS resolvers for network = "host"
```

**DNS with `network = "host"` (0.3.3).** The session's `/etc/resolv.conf` is
built from the host's `/etc/resolv.conf` (non-loopback `nameserver` lines plus
its `search`/`options`). When the host file lists only a loopback stub
(systemd-resolved's `127.0.0.53`), the upstreams are taken from
`/run/systemd/resolve/resolv.conf`. Loopback addresses are never passed into
the session. If no usable resolver remains, the launch fails with
`no usable DNS resolver …`; hisn never writes an empty resolv.conf. `[net]
nameservers` replaces this derivation entirely and is rejected at
`hisn profile validate` if it is empty, not an IP, or loopback.

### Rootfs store (0.3.2)

```sh
hisn rootfs import go-dev --from-tar rootfs.tar       # import from a tar archive
hisn rootfs import go-dev --from-image golang:1.24    # import from a Docker image
hisn rootfs list                                      # list imported rootfs images
hisn rootfs path go-dev                               # print the store path
hisn rootfs rm go-dev                                 # remove a rootfs
```

The import tool streams the tar via the `tar` crate (handles ustar prefix,
GNU LongLink, and PAX extended headers), strips setuid/setgid bits, rejects
path traversal and hard links pointing outside the target, rejects
symlink-then-write escapes, skips device nodes, and atomically publishes the
result. `hisn check` reports the rootfs store path and names.

## Policy

A policy is a small TOML file (`hisn-policy/v1`). A file that declares nothing
gives the default sandbox described above.

```toml
version = "hisn-policy/v1"

[session]
cwd = "."            # mounted rw at the identical path
home = "tmpfs"       # or an absolute host path for warm caches
network = "none"     # "none" | "host"
shm = false          # true: tmpfs at /dev/shm
shm_size = 64        # MiB, only with shm = true
tmp_size = 1024      # MiB, 16..=65536

[mounts]
ro = ["/opt/toolchains", "/home/me/.gitconfig:/etc/gitconfig.d/user"]
# ro entries: "path" (same path, recursive ro) or "src:dst" (0.3.3: host src at
# in-session dst, ro,nosuid,nodev; src may not be a symlink, dst may not sit
# under a hisn runtime dir or another session mount; see ADR 0012)
grantable_rw = ["/srv/out"]     # prefixes where `hisn grant --rw` is allowed
mask = ["/work/app/.secrets"]   # hidden inside allowed trees

[env]
pass = ["GOFLAGS", "RUSTFLAGS"]
set  = { CI = "1" }
```

Everything that widens the sandbox is opt-in. `network = "host"` additionally
requires Landlock abstract-socket scoping (ABI 6) or an explicit
`--allow-host-abstract-sockets`. The full format is in
[docs/POLICY-SPEC.md](docs/POLICY-SPEC.md); a complete example is
[`hisn.toml`](hisn.toml) and the JSON schema is
[`schemas/hisn-policy.v1.json`](schemas/hisn-policy.v1.json). Unknown keys are
errors.

## Programmatic use

hisn is designed to be driven by an agent runtime. [Wakil](docs/WAKIL-INTEGRATION.md)
is one consumer; nothing in the contract is specific to it.

- **Readiness.** `hisn run --ready-fd N` writes `"ready\n"` to fd `N` once the
  session is live (after the control socket accepts), then closes it. On a
  failed start nothing is written; the exit status carries the error. Works
  with and without `--detach`.
- **Stable exec handles.** Every exec gets an opaque `exec_id` (`"e-<n>"`,
  monotonic per session, never reused). `signal` takes the `exec_id`; the bare
  `pid` form is deprecated, and a pid recycled by a different exec is rejected
  with `E_NOT_FOUND`.
- **Frozen JSON.** `hisn ls --json` and `hisn inspect --json` carry a
  `schema` field (`hisn-ls/v1`, `hisn-inspect/v1`). Fields are only ever added.
  `hisn ls --json` with no sessions returns an empty list.
- **Control socket.** `<session>/control.sock`, one JSON object per line
  (`grant`, `revoke`, `list`, `inspect`, `exec`, `signal`, `kill`). The
  protocol is in [POLICY-SPEC §7](docs/POLICY-SPEC.md). A `{"exit":{"lost":true}}`
  reply means the monitor died and the status is unknown, not that the program
  finished.

## Security model

The host side (you, or the agent runtime) is trusted: it writes the policy and
issues grants. The sandboxed command is treated as hostile.

1. **Absent, not blocked.** The sandbox root is an empty tmpfs entered with
   `pivot_root`, and the old root is detached. Only an allowlist of bind mounts
   exists inside.
2. **Layered confinement.** Every capability is dropped, `no_new_privs` is set,
   and seccomp denies `mount`, `unshare`, `setns`, `open_tree`, `ptrace`, `bpf`,
   `io_uring` and related calls. Landlock restricts writes to the same allowlist
   as a second layer. PID 1 of the sandbox is itself capability-free and
   non-dumpable.
3. **Only the supervisor mounts.** Grants and revokes are performed by the
   host-side supervisor over a control socket that the sandbox can neither name
   nor use; the socket also refuses any peer that descends from the sandbox's
   init. A grant is a bind mount in the session's mount namespace and nothing
   else, so it cannot outlive the session.
4. **Defined revoke semantics.** A soft revoke guarantees that the path no
   longer resolves; file descriptors that were already open or queued can
   survive. `--hard` kills every sandbox process and is the only revoke that
   guarantees no reference remains.
5. **Scope.** The model covers filesystem and environment exposure and privilege
   inside the sandbox. Kernel vulnerabilities, resource exhaustion beyond
   rlimits, and network isolation under `network = "host"` are outside it (for
   `network = "none"` the sandbox has only loopback).

**What hisn does not do:** it has no images, no registry and no OCI runtime, it
does not filter network traffic, and it does not use cgroups. See the
[roadmap](docs/ROADMAP.md).

The reasoning behind each decision is in [docs/DESIGN.md](docs/DESIGN.md);
known limits are tracked in [docs/OPEN-POINTS.md](docs/OPEN-POINTS.md). To
report a vulnerability, see [SECURITY.md](SECURITY.md).

## Verifying a build

The isolation claims are backed by a leak suite, `tests/leak/run.sh`, that runs
real probes from inside the sandbox: it tries to stat host paths, read secrets,
escape through `/proc`, use denied syscalls, reach sibling sessions, use revoked
grants, follow planted symlinks, and read what init exposes about the host. It
prints one line per check and a final `RESULT:` line, and exits non-zero on any
`FAIL`. A manifest (`tests/leak/MANIFEST`) lists every expected test id, and the
run fails if a listed test printed no line, so a test cannot be silently
dropped.

```sh
make lint && make test     # rustfmt, clippy -D warnings, unit tests (runs anywhere)
make leaktest              # builds release + the probe, runs the leak suite
make leaktest-log          # same, saved to docs/leaktest-host-YYYY-MM-DD.log with a header
```

The leak suite needs a host that allows unprivileged user namespaces; without
one it refuses to run (exit 77) and reports nothing. `SKIP` and `WEAK` lines are
never counted as passes. `WEAK` means a check passed without the fixture that
would make it meaningful. On kernels with Landlock ABI below 6, L23 and L24
skip.

To check a downloaded binary, run `sha256sum -c SHA256SUMS`, then
`hisn --version` and `hisn check`.

## Status

hisn 0.3.1 is maintained by one person. The leak suite was last recorded on a
Fedora x86_64 host at commit `809da11`: **216 passed, 0 failed, 1 skipped
(L12, needs write access to `/etc`), 1 weak (L14 R5)**
([log](docs/leaktest-host-2026-11-03.log)).
CI runs the suite on Ubuntu 22.04 and 24.04 (x86_64) and builds a release only
after it passes. aarch64 is cross-checked by clippy and has not been
leak-tested. [docs/VERIFICATION.txt](docs/VERIFICATION.txt) lists what was run,
where, and with which log; anything without a log is recorded as "not run".

**Next:** 0.3b (ssh T1, recipes, threat-model leak tests) and 0.4 (Docker T1/T3,
leases, egress proxy) are planned in
[docs/PLAN-0.3.md](docs/PLAN-0.3.md).

## Documentation

| | |
|---|---|
| [DESIGN](docs/DESIGN.md) | how it works and why |
| [POLICY-SPEC](docs/POLICY-SPEC.md) | policy format, control protocol, OCI mapping |
| [ROADMAP](docs/ROADMAP.md), [PLAN-0.3](docs/PLAN-0.3.md) | where it is going |
| [WAKIL-INTEGRATION](docs/WAKIL-INTEGRATION.md) | driving hisn from an agent runtime |
| [OPEN-POINTS](docs/OPEN-POINTS.md), [VERIFICATION](docs/VERIFICATION.txt) | known limits; what was run and where |
| [CHANGELOG](CHANGELOG.md), [SECURITY](SECURITY.md), [CONTRIBUTING](CONTRIBUTING.md) | project |

## License

[Apache-2.0](LICENSE)

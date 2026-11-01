# hisn

[![CI](https://github.com/treeol/hisn/actions/workflows/ci.yml/badge.svg)](https://github.com/treeol/hisn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/treeol/hisn)](https://github.com/treeol/hisn/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A rootless, daemonless, single-binary sandbox for AI coding agents on Linux.**

hisn runs a command in a private view of your machine. The command sees its
working directory at the *same path* as on the host, a read-only toolchain, and
private `$HOME`, `/tmp` and `/run`. Anything else exists only if you grant it,
and every grant ends with the session. Paths outside the view are not denied,
they are absent: `ENOENT`.

## What the sandbox contains

| Path | Inside the sandbox |
|---|---|
| working directory | read-write, at the identical host path |
| system toolchain (`/usr` and friends) | read-only |
| `$HOME`, `/tmp`, `/run` | private tmpfs, discarded with the session |
| `/etc` | the entries present at start, minus secrets |
| `/proc`, `/dev` | the sandbox's own; `/sys` is absent |
| granted paths | present until revoked or the session ends |
| everything else | does not exist |

The environment is rebuilt from scratch: `PATH`, `HOME`, `TERM`, `LANG`, `LC_*`,
`TZ`, plus the keys you list in `env.pass`. Host secrets in the environment never
enter.

## Install

**Release binary** (Linux x86_64 or aarch64):

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

`hisn check` reports whether the host qualifies (exit 2 if not). hisn needs no
root, no setuid binary and no file capabilities. It requires kernel 5.12 or
newer with unprivileged user namespaces, Landlock and seccomp. On Ubuntu 24.04
AppArmor restricts unprivileged user namespaces by default
(`kernel.apparmor_restrict_unprivileged_userns`); `hisn check` shows the value.

The release binaries are dynamically linked glibc builds (glibc 2.35 or newer).
Static musl builds do not compile yet; see [OPEN-POINTS P22](docs/OPEN-POINTS.md).

## Usage

```sh
hisn run -- make test                                  # cwd rw, toolchain ro, nothing else
hisn run --policy hisn.toml --grant ~/data:ro -- ./job # with a policy and a read-only grant
hisn policy validate hisn.toml                         # print the resolved policy
```

`hisn run` passes stdio through unchanged and allocates a pty inside the sandbox
when stdin is a terminal. It exits with the command's status (`128+sig` if
signalled). Exit `125` is a hisn error; `126` and `127` mean the command could
not be executed or was not found. Add `-v` for logs on stderr.

### Long-lived sessions

A session can be steered from outside while it runs. This is how an agent
runtime hands a sandboxed process more access, or runs further commands in it.

```sh
hisn run --session-id agent1 -- sleep 3600 &

hisn exec   --session agent1 -- ls -la                  # another command, same confinement
hisn exec   --session agent1 --tty -- bash              # interactive, on its own pty
hisn grant  --session agent1 /srv/reference             # read-only, gone with the session
hisn grant  --session agent1 --rw /srv/out              # needs a mounts.grantable_rw prefix
hisn revoke --session agent1 /srv/reference             # the path becomes ENOENT
hisn revoke --session agent1 --hard /srv/out            # also kills every sandbox process
hisn ls --session agent1
hisn inspect --session agent1                           # mount table and resolved policy
hisn kill --session agent1
```

### Policy

A policy is a small TOML file (`hisn-policy/v1`):

```toml
version = "hisn-policy/v1"

[session]
cwd = "."            # mounted rw at the identical path
home = "tmpfs"
network = "none"     # "none" | "host"

[mounts]
ro = ["/opt/toolchains"]
grantable_rw = ["/srv/out"]

[env]
pass = ["GOFLAGS", "RUSTFLAGS"]
set  = { CI = "1" }
```

The full format is in [docs/POLICY-SPEC.md](docs/POLICY-SPEC.md); a complete
example is [`hisn.toml`](hisn.toml) and the JSON schema is
[`schemas/hisn-policy.v1.json`](schemas/hisn-policy.v1.json).

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
   nor use. A grant is a bind mount in the session's mount namespace and nothing
   else, so it cannot outlive the session.
4. **Defined revoke semantics.** A soft revoke guarantees that the path no
   longer resolves; file descriptors that were already open or queued can
   survive. `--hard` kills every sandbox process and is the only revoke that
   guarantees no reference remains.
5. **Scope.** The model covers filesystem and environment exposure and privilege
   inside the sandbox. Kernel vulnerabilities, resource exhaustion beyond
   rlimits, and network isolation under `network = "host"` are outside it (for
   `network = "none"` the sandbox has only loopback).

The reasoning behind each decision is in [docs/DESIGN.md](docs/DESIGN.md);
known limits are tracked in [docs/OPEN-POINTS.md](docs/OPEN-POINTS.md). To
report a vulnerability, see [SECURITY.md](SECURITY.md).

## Verifying a build

The isolation claims are backed by a leak suite, `tests/leak/run.sh`, that runs
real probes from inside the sandbox (L1 to L24): it tries to stat host paths,
read secrets, escape through `/proc`, use denied syscalls, reach sibling
sessions, and use revoked grants. It prints one line per check and a final
`RESULT:` line, and exits non-zero on any `FAIL`.

```sh
make lint && make test     # rustfmt, clippy -D warnings, unit tests (runs anywhere)
make leaktest              # builds release + the probe, runs the leak suite
make leaktest-log          # same, saved to docs/leaktest-host-YYYY-MM-DD.log with a header
```

The leak suite needs a host that allows unprivileged user namespaces; without
one it refuses to run (exit 77) and reports nothing. `SKIP` and `WEAK` lines are
never counted as passes. `WEAK` means a check passed without the fixture that
would make it meaningful, for example a host with no `~/.ssh` to hide. On kernels
with Landlock ABI below 6, L23 and L24 skip.

To check a downloaded binary, run `sha256sum -c SHA256SUMS`, then
`hisn --version` and `hisn check`.

## Status

hisn 0.2 is maintained by one person. The leak suite was last recorded green on
a Fedora x86_64 host: 175 passed, 0 failed, 1 skipped, 1 weak
([log](docs/leaktest-host-2026-11-01.log)). CI runs it on Ubuntu 22.04 and 24.04
(x86_64) and builds a release only after it passes. aarch64 is cross-checked by
clippy and has not been leak-tested. [docs/VERIFICATION.txt](docs/VERIFICATION.txt)
lists what was run, where, and with which log; anything without a log is
recorded as "not run".

## Documentation

[DESIGN](docs/DESIGN.md) · [POLICY-SPEC](docs/POLICY-SPEC.md) ·
[ROADMAP](docs/ROADMAP.md) · [WAKIL-INTEGRATION](docs/WAKIL-INTEGRATION.md) ·
[OPEN-POINTS](docs/OPEN-POINTS.md) · [VERIFICATION](docs/VERIFICATION.txt) ·
[CHANGELOG](CHANGELOG.md) · [SECURITY](SECURITY.md) ·
[CONTRIBUTING](CONTRIBUTING.md)

## License

[Apache-2.0](LICENSE)

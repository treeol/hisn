# hisn

[![CI](https://github.com/treeol/hisn/actions/workflows/ci.yml/badge.svg)](https://github.com/treeol/hisn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/treeol/hisn)](https://github.com/treeol/hisn/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

hisn is a daemonless, rootless, single-binary Linux sandbox for AI coding
agents. It keeps Docker's *isolation* (user/mount/pid/ipc/uts/net namespaces,
`pivot_root`, seccomp, dropped capabilities, Landlock) and drops its
*ecosystem* (images, registry, daemon, OCI bundles). A sandboxed process sees
exactly: its working directory at the **identical host path** (rw), a read-only
toolchain, private tmpfs `$HOME`/`/tmp`/`/run`, and paths the host side
explicitly **grants** for the life of the session. Everything else does not
exist (ENOENT), not "permission denied".

hisn is not a container runtime (no images, no registry, no daemon), not a
defence against kernel exploits, not a network firewall (`network = "none"` or
the host network, nothing in between), and not a resource limiter beyond
rlimits. See [DESIGN §1](docs/DESIGN.md) and [OPEN-POINTS](docs/OPEN-POINTS.md).

> **Status: v0.2, single-maintainer.** The leak suite (L1-L24) was last
> recorded green on one Fedora x86_64 host (175 passed, 0 failed, 1 skipped,
> 1 weak; [log](docs/leaktest-host-2026-11-01.log)). CI runs it on Ubuntu 22.04
> and 24.04 (x86_64), and a release is only built after that passes. The first
> green CI run (commit c4acf20) gave 174 passed on 24.04 and 171 passed on
> 22.04, both with 0 failed; on 22.04 the Landlock-scoping tests (L23, L24) skip
> because the runner kernel's Landlock ABI is below 6. aarch64 is
> cross-checked by clippy only: it has never been leak-tested, and CI starts
> the aarch64 binary only for `--version` at release time. Details:
> [docs/VERIFICATION.txt](docs/VERIFICATION.txt).

## Install

From a release binary (glibc, Linux x86_64 or aarch64; see the note below):

```sh
# x86_64; use hisn-aarch64-linux-gnu on aarch64
curl -fsSLO https://github.com/treeol/hisn/releases/latest/download/hisn-x86_64-linux-gnu
curl -fsSLO https://github.com/treeol/hisn/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
install -m 0755 hisn-x86_64-linux-gnu ~/.local/bin/hisn
hisn check                      # does this host qualify? (exit 2 if not)
```

From source (Rust stable, edition 2024):

```sh
cargo install --path . --locked
hisn check
```

No root, no setuid, no file capabilities. Needs kernel >= 5.12, unprivileged
user namespaces, Landlock and seccomp (`hisn check` probes each). On Ubuntu
24.04 unprivileged user namespaces are restricted by AppArmor by default
(`kernel.apparmor_restrict_unprivileged_userns`); `hisn check` shows its value.

**Why glibc, not static musl:** the musl targets do not compile at 0.2.0 (the
ioctl request constants in `src/init.rs` have the wrong type for musl; see
[OPEN-POINTS P22](docs/OPEN-POINTS.md)). The release must not move the
host-verified code, so the binaries are dynamically linked glibc builds made
natively on Ubuntu 22.04 (glibc 2.35 or newer). A static build is planned
once musl has passed the leak suite.

## Quickstart

```sh
hisn policy validate hisn.toml                     # check a policy (prints the resolved form)
hisn run -- ls -la                                 # cwd rw, toolchain ro, nothing else
hisn run --policy hisn.toml --grant ~/data:ro -- make test

# a long-lived session another process can steer
hisn run --session-id agent1 -- sleep 3600 &
hisn grant   --session agent1 /srv/reference            # ro, vanishes with the session
hisn grant   --session agent1 --rw /srv/out             # needs a mounts.grantable_rw prefix
hisn revoke  --session agent1 /srv/reference            # path -> ENOENT
hisn revoke  --session agent1 --hard /srv/out           # + kill every sandbox process
hisn ls --session agent1 ; hisn inspect --session agent1 ; hisn kill --session agent1
```

`hisn run` passes stdio through unchanged (a pty is allocated inside the
sandbox when stdin is a tty), exits with the command's status (`128+sig` if
signalled), and prints nothing of its own on stdout. `125` = hisn error,
`126`/`127` = command could not be executed / not found. Add `-v` for logs on
stderr.

Policy format: [docs/POLICY-SPEC.md](docs/POLICY-SPEC.md) (example: `hisn.toml`,
schema: `schemas/hisn-policy.v1.json`).

## Security model

1. The sandbox root is an empty tmpfs entered with `pivot_root` and the old
   root is detached, so the host filesystem is unreachable, not merely
   unreadable; only an allowlist of bind mounts exists inside, and `/etc` is
   an allowlist of its start-time entries minus secrets.
2. Inside, every capability is dropped, `no_new_privs` is set, seccomp denies
   `mount`/`unshare`/`setns`/`open_tree`/`ptrace`/`bpf`/`io_uring`/... and Landlock
   restricts writes to the same allowlist as a second layer; PID 1 of the
   sandbox is itself capless and non-dumpable.
3. Only the host-side supervisor can mount: grants and revokes are performed
   by it through a control socket the sandbox can neither name nor use (peer
   ancestry check), and grants are bind mounts in the session's mount
   namespace and nothing else, so they die with the session by construction.
4. The environment is rebuilt from scratch (`PATH HOME TERM LANG LC_* TZ` plus
   an explicit `env.pass` allowlist), so host secrets in env never enter.
5. A soft revoke guarantees only that the path no longer resolves (open or
   queued file descriptors can survive); `--hard` kills every sandbox process
   and is the only revoke that guarantees no remaining reference. Kernel
   exploits and `network = "host"` are outside the model; see
   [docs/OPEN-POINTS.md](docs/OPEN-POINTS.md).

## Verifying a build

Pure checks run anywhere:

```sh
make lint && make test          # fmt + clippy -D warnings + unit tests
```

`make lint` needs the `rustfmt` and `clippy` components; `rust-toolchain.toml`
requests them, so rustup installs them on the first `cargo` run.

The leak suite needs a host that allows unprivileged user namespaces; without
one it refuses to run (exit 77) and reports nothing:

```sh
git clone https://github.com/treeol/hisn && cd hisn
make leaktest                   # builds release + examples/leakprobe, runs tests/leak/run.sh
make leaktest-log               # same, tee'd to docs/leaktest-host-YYYY-MM-DD.log, with a header
```

`make leaktest` prints one line per check (`L<n>[<sub>] PASS|FAIL|SKIP|WEAK —
<reason for SKIP/WEAK>`) and a final `RESULT:` line; it exits non-zero on any
`FAIL`. `SKIP` and `WEAK` are never counted as passes: `WEAK` means the check
passed without the fixture that would make it meaningful (e.g. no `~/.ssh` on
the host to hide). On kernels with Landlock ABI < 6, L23 and L24 skip. The
`make leaktest-log` header records commit, tree state, date, hostname, kernel
and `hisn --version`. `docs/VERIFICATION.txt` lists what was run, where, with
which log; anything not backed by a log is "not run".

To check a downloaded binary, `sha256sum -c SHA256SUMS`, then run
`hisn --version` and `hisn check`.

## Docs

[DESIGN](docs/DESIGN.md) · [POLICY-SPEC](docs/POLICY-SPEC.md) ·
[ROADMAP](docs/ROADMAP.md) · [WAKIL-INTEGRATION](docs/WAKIL-INTEGRATION.md) ·
[OPEN-POINTS](docs/OPEN-POINTS.md) · [BRIEF](docs/BRIEF.md) ·
[VERIFICATION](docs/VERIFICATION.txt) · [CHANGELOG](CHANGELOG.md) ·
[SECURITY](SECURITY.md) · [CONTRIBUTING](CONTRIBUTING.md)

License: [Apache-2.0](LICENSE).

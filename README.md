# hisn

A daemonless, rootless, single-binary Linux sandbox for AI coding agents.
It keeps Docker's *isolation* (user/mount/pid/ipc/uts/net namespaces,
`pivot_root`, seccomp, dropped capabilities, Landlock) and drops its
*ecosystem* (images, registry, daemon, OCI bundles).

A sandboxed process sees exactly: its working directory at the **identical
host path** (rw), a read-only toolchain, private tmpfs `$HOME`/`/tmp`/`/run`,
and paths the host side explicitly **grants** for the life of the session.
Everything else does not exist (ENOENT), not "permission denied".

> **Status: v0, not yet verified on a real host.** Unit tests, clippy and the
> seccomp/Landlock kernel checks pass in the build sandbox, but user
> namespaces are blocked there, so the namespace/mount/grant machinery and the
> leak suite (L1-L14) have **not been run**. See [Verifying](#verifying).

## Install

```sh
cargo install --path .          # Rust stable, edition 2024; Linux x86_64 or aarch64
hisn check                      # does this host qualify? (exit 2 if not)
```

No root, no setuid, no file capabilities. Needs kernel >= 5.12, unprivileged
user namespaces, Landlock and seccomp (`hisn check` probes each).

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
   pid-namespace check), and grants are bind mounts in the session's mount
   namespace and nothing else, so they die with the session by construction.
4. The environment is rebuilt from scratch (`PATH HOME TERM LANG LC_* TZ` plus
   an explicit `env.pass` allowlist), so host secrets in env never enter.
5. A soft revoke guarantees only that the path no longer resolves (open or
   queued file descriptors can survive); `--hard` kills every sandbox process
   and is the only revoke that guarantees no remaining reference. Kernel
   exploits and `network = "host"` are outside the model; see
   [docs/OPEN-POINTS.md](docs/OPEN-POINTS.md).

## Verifying

Everything pure is tested anywhere:

```sh
make lint && make test          # fmt + clippy -D warnings + unit tests
```

The leak suite needs a host that allows unprivileged user namespaces (it will
refuse to run, exit 77, and report nothing otherwise):

```sh
git clone <repo> && cd hisn
make leaktest                   # builds release + examples/leakprobe, runs tests/leak/run.sh
```

Output is one `PASS`/`FAIL`/`SKIP`/`WEAK` line per check. `WEAK` means a check
passed without the fixture that would make it meaningful (e.g. no `~/.ssh` on
the host to hide).

## Docs

[DESIGN](docs/DESIGN.md) · [POLICY-SPEC](docs/POLICY-SPEC.md) ·
[ROADMAP](docs/ROADMAP.md) · [WAKIL-INTEGRATION](docs/WAKIL-INTEGRATION.md) ·
[OPEN-POINTS](docs/OPEN-POINTS.md) · [BRIEF](docs/BRIEF.md)

License: Apache-2.0.

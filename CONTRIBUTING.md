# Contributing

hisn is a security tool; the leak suite is the acceptance criterion, not an
extra. A change is done when it passes the suite on a real host.

## Before opening a pull request

```sh
make lint && make test          # fmt, clippy -D warnings, unit tests
make leaktest                   # L1-L24; needs unprivileged user namespaces
```

CI runs the same on Ubuntu 22.04 and 24.04, but see the next section.

## Changes that need a host leak log

A PR that touches **init, rootfs/mounts, grant, exec, landlock, or seccomp**
(`src/init.rs`, `src/rootfs.rs`, `src/mounts.rs`, `src/grant.rs`,
`src/exec.rs`, `src/landlock.rs`, `src/seccomp.rs`) must attach the log of a
host run on the PR head:

```sh
make leaktest-log               # writes docs/leaktest-host-YYYY-MM-DD.log
```

The log header records the commit, tree state, host, kernel and `hisn
--version`. A log from another commit, or with a dirty tree, does not count.
A `FAIL` blocks the PR; a `SKIP` or `WEAK` needs its reason stated.

## Rules

* The invariants in [docs/BRIEF.md](docs/BRIEF.md) (1-7) and the exec
  invariants in [DESIGN §14](docs/DESIGN.md) stand. Changing one needs a design
  discussion first, in an issue.
* New isolation behaviour comes with a leak test. A test that cannot fail is
  not a test; do not add `SKIP`s to make a run green.
* Update the docs your change makes wrong (`docs/`, `README.md`, the policy
  schema in `schemas/`, `CHANGELOG.md` under *Unreleased*).
* Do not report results you did not run. Say what was run, where, and what was
  not (see [docs/VERIFICATION.txt](docs/VERIFICATION.txt)).
* Vulnerabilities: do not file them as issues or PRs; see
  [SECURITY.md](SECURITY.md).
* Contributions are accepted under the Apache-2.0 license.

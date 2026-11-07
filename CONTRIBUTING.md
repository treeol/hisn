# Contributing

hisn is a security tool. The leak suite is the acceptance criterion: a change is
done when it passes the suite on a real host, not when it compiles.

## Gate

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                       # unit tests
python3 tests/leak/test_l8.py    # leak-comparator self-tests
for f in profiles/*.toml; do target/debug/hisn profile validate "$f" || exit 1; done   # needs /tmp/hisn-out
make leaktest                    # the leak suite; needs unprivileged user namespaces
```

`make lint` and `make test` run the first four. CI runs the same, plus clippy
for aarch64 and musl, a musl build, the example-profile check, and
`cargo publish --dry-run`.

## Changes that need a host leak log

A change to init, rootfs/mounts, grant, exec, landlock, or seccomp
(`src/init.rs`, `src/rootfs.rs`, `src/mounts.rs`, `src/grant.rs`,
`src/exec.rs`, `src/landlock.rs`, `src/seccomp.rs`) needs a host run on the PR
head. Attach the log from `make leaktest-log` (it writes
`docs/leaktest-host-YYYY-MM-DD.log`, which is git-ignored) to the pull request.
The log header records the commit, tree state, host, kernel and version. A log
from another commit, or from a dirty tree, does not count. A `FAIL` blocks the
change; a `SKIP` or `WEAK` needs its reason stated.

Logs are not committed to the repository. They are evidence attached to a
change, not part of the tree.

## Decisions: ADRs

A decision that changes how hisn works, or that a future reader would otherwise
have to rediscover, gets an ADR in `docs/adr/`:

- Number it with the next free `NNNN` and a short slug, for example
  `docs/adr/0014-my-decision.md`.
- Use the format of the existing records: a title, `Status`, `Date`, and an
  `Origin` line if the decision came from a plan, then Decision, Why and
  Consequences.
- Add a row to the index in [docs/adr/README.md](docs/adr/README.md).
- Do not rewrite an accepted ADR. Add a dated note to it instead.

## Rules

* The invariants in [docs/BRIEF.md](docs/BRIEF.md) (1-7) and the exec
  invariants in [DESIGN §14](docs/DESIGN.md) stand. Changing one needs a design
  discussion first, in an issue.
* New isolation behaviour comes with a leak test. A test that cannot fail is not
  a test. Do not add `SKIP`s to make a run green.
* Update the docs your change makes wrong (`docs/`, `README.md`, the policy
  schema in `schemas/`, `CHANGELOG.md` under *Unreleased*).
* Do not report results you did not run. Say what was run, where, and what was
  not.
* Vulnerabilities: do not file them as issues or PRs; see
  [SECURITY.md](SECURITY.md).
* Contributions are accepted under the Apache-2.0 license.

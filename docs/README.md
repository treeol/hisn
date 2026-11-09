# hisn documentation

## Getting started

- [README](../README.md): what hisn is, install, quickstart.
- [CONTRIBUTING](../CONTRIBUTING.md): build, test, and what a change must show.

## CLI reference

- `hisn --help` and `hisn <command> --help` are the reference for commands and
  flags; the clap definitions are in `src/cli.rs`.
- [POLICY-SPEC](POLICY-SPEC.md): the `hisn-policy/v1` format, the CLI-to-policy
  mapping and the control protocol.
- [DESIGN §15](DESIGN.md): profiles and the profile tables.
- [hisn.toml](../hisn.toml) and [schemas/hisn-policy.v1.json](../schemas/hisn-policy.v1.json): an example policy and its JSON Schema.

## Sessions and lifecycle

- [sessions.md](sessions.md): names, states, `session.json`, clients and
  observers, leases, stop, prune and archival, the `run --detach` contract, and
  driving hisn from a program.
- [WAKIL-INTEGRATION](WAKIL-INTEGRATION.md): how Wakil, the reference driver,
  uses hisn.

## Security model

- [SECURITY](../SECURITY.md): reporting a vulnerability.
- [DESIGN](DESIGN.md): §5 seccomp, §6 capabilities, §7 Landlock, §9 control
  socket and what must never be mounted, §16 risk labels.
- [OPEN-POINTS](OPEN-POINTS.md): known limits (historical review log).

## Design

- [DESIGN](DESIGN.md): how it works and why.
- [ADR index](adr/README.md): one record per decision.
- [BRIEF](BRIEF.md): the original build brief and its invariants (historical).

## Releases

- [CHANGELOG](../CHANGELOG.md)
- [v0.4.2](releases/v0.4.2.md)
- [v0.4.1](releases/v0.4.1.md)
- [v0.4.0](releases/v0.4.0.md)

## Roadmap

- [ROADMAP](ROADMAP.md): done, planned, and ideas.

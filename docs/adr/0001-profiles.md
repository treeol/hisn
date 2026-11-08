# ADR 0001 — Profiles as an envelope around `hisn-policy/v1`

Status: proposed. Date: 2026-11-02. Origin: the 0.3 planning document (§1), removed from the tree; this record stands alone.

Gap: shipped in 0.3.0 (`src/profile.rs`) as an envelope around `hisn-policy/v1`, but the built-in profiles named in this record (`go`, `rust`, `node`, `python`, `zig`) were not shipped; only `base` and `wakil` are.

## Decision

A **profile** is an envelope around `hisn-policy/v1`, not a v2. A profile
file is a TOML document with `version = "hisn-profile/v1"` and one required
table `[policy]`, whose value is a complete `hisn-policy/v1` document
(inline table). All other tables (`[[services]]`, `[[host_services]]`,
`[[forward]]`, `[docker]`, `[ssh]`, `[[risk]]`) are 0.3 surface. The inner
policy is resolved by the exact existing `policy::load` + `policy::resolve`
code path; v1 policy stays valid unchanged.

## Resolution and precedence

`hisn run --profile <name|path>`:

1. `--profile` with a `/` → that file.
2. `--profile <name>` → `$HISN_PROFILES/<name>.toml`, then the built-in
   `profiles/<name>.toml` shipped next to the binary (`go`, `rust`, `node`,
   `python`, `zig`, `wakil`). **`./<name>.toml` is deliberately not in the
   search path** (round-1 BLOCKING: a profile resolved from under the
   session cwd could be written by the sandbox and self-ack its own risk).
3. `--policy <file>` (0.2) → a bare `hisn-policy/v1` document, treated as a
   profile with no 0.3 surface. Stays for scripts and the leak suite.

`--profile` and `--policy` are mutually exclusive (`E_PROFILE_POLICY`). CLI
flags (`--cwd`, `--network`, `--grant`) override the profile's `[policy]`,
which overrides built-in defaults — the existing `POLICY-SPEC §2` order. The
envelope adds nothing above it.

## Sharing

A profile is one file committed to a repo. Built-ins live in the hisn repo
under `profiles/` and are installed next to the binary. `hisn profile list`
prints the resolved search path and the built-ins. A profile never carries
secrets (secrets stay in `env.pass` of the inner policy or in an agent
`[[forward]]`).

## Why envelope, not v2

v2 would fork the schema and force every 0.2 user to migrate. An envelope
keeps `hisn-policy/v1` as the isolation contract (the thing the leak suite
tests) and layers the orchestration surface on top. The inner policy is
resolved by the existing code, so the 0.2 invariants are the same code path.

## Invariants

- 1, 2, 3, 4: untouched (same resolution, same mount plan, same grants, same
  env scrub).
- 5: the envelope tables have no OCI runtime-spec representation; they are
  carried as annotations (`org.hisn.profile.version`, `org.hisn.services`,
  `org.hisn.forward`, …). The inner policy maps per `POLICY-SPEC §8`.
- 6: the leak suite (L1–L24) still tests the inner policy; L32 tests that the
  Wakil profile yields the 0.2 plan.
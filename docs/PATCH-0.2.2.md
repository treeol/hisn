# hisn 0.2.2 — user name inside the sandbox

0.2.2 fixes one defect from 0.2.1 with **no new boundary**: a 0.2.1 policy
yields the identical mount plan (L8). The env allowlist is unchanged apart from
two computed names (`USER`, `LOGNAME`). Invariants 1-7 are untouched.

## Symptom

Observed on the host with hisn 0.2.1 started by Wakil: inside the sandbox
`id -un` and `echo $USER` print `user`, although the host user has another
name. PATCH-0.2.1 patch 3 said the stubs already used the host user name and
that no code change was expected.

## Diagnosis (read from the 0.2.1 source, commit f2e47d7)

| question | answer | where |
|---|---|---|
| Does `HostFacts.username` come from `getpwuid(host uid)`? | **No.** It comes from the host environment variable `$USER`, read by `supervisor.rs::getids()`; `HostFacts::probe` only stores the string it is given. | `src/supervisor.rs` (`getids`), `src/mounts.rs` (`HostFacts::probe`) |
| Does the stub fall back to `"user"`? | **Yes**, whenever `$USER` is unset, empty, or contains a character outside `[A-Za-z0-9_.-]`. A launcher with a scrubbed environment (Wakil, `env -i`, some service managers) has no `$USER`, so it always lands on the fallback. Nothing was logged. | same |
| Is `USER` set in the sandbox env? | **No.** DESIGN §8 / POLICY-SPEC §3 allow `PATH HOME TERM LANG LC_* TZ` plus `env.pass`; `USER` is not in the allowlist, and `env::scrub` never adds it. So `echo $USER` is empty unless the policy passes it, and a shell that falls back to `id -un` shows the stub name. | `src/env.rs` (`scrub`, `BASE_PASS`) |
| Anything else with the same flaw? | `hisn policy plan` hard-codes `"user"` (`src/main.rs`); it prints mount targets only, so the name cannot show up there. `hisn check` reads `$USER` to match `/etc/subuid` lines by name (it also matches by numeric uid); that is a diagnostic, not sandbox content, and is left alone in this patch. | `src/main.rs`, `src/check.rs` |

Root cause: the 0.2.1 spec text said "from `$USER` at session start", the code
did exactly that, and the leak suite never compared the name inside against the
host's. Unit tests used a fake `HostFacts { username: "u" }`, which cannot
catch a wrong *source* for the name.

## Behaviour (0.2.2)

* `sys::passwd_name(uid)` wraps `getpwuid_r` (NSS applies, buffer grown on
  `ERANGE` up to 1 MiB). `supervisor::getids(verbose)` calls it with the
  **effective** uid (`geteuid`) once, in the supervisor, before the sandbox
  exists.
* The name is used only if it is 1-32 characters of `[A-Za-z0-9_.-]` and does
  not start with `-`. This keeps a hostile or odd NSS entry from adding a
  field or a line (`:`, newline, whitespace, `/`) to the generated
  `/etc/passwd` and `/etc/group`.
* Otherwise the name is `user`, and `hisn run -v` prints the reason
  (`no passwd entry`, `getpwuid_r failed: ...`, `not usable`). Without `-v`
  nothing is printed (as before).
* The stubs are unchanged in shape: `name:x:uid:gid:name:/run/hisn/home:/bin/sh`
  and `name:x:gid:`.
* `env::scrub` gains a `username` argument and always sets `USER` and `LOGNAME`
  to it, after `env.pass` / `env.set`, so those cannot override them. The
  value never comes from the host environment. `env::is_computed` now covers
  `HOME`, `USER`, `LOGNAME` and the cache variables, so an `exec` request that
  names `USER` or `LOGNAME` is refused whole (`E_BAD_REQUEST`, names only),
  exactly as for `HOME`.
* Disclosure: under a scrubbed launch environment 0.2.1 showed `user`; 0.2.2
  shows the host login name (also in `/etc/passwd`, `/etc/group`). No other
  field of the host entry is copied. NSS may open descriptors or load modules
  during the lookup; init closes all descriptors but its channel
  (`init.rs`, `close_all_except`), so none reach the sandbox. The lookup can
  block on a slow backend.
* `getids` uses the real uid/gid for the mapping and the effective uid for the
  name; 
* Policy loading is **not** changed: a 0.2.1 policy that lists `USER` in
  `env.pass` or sets it in `env.set` still loads; the computed value wins
  (documented in POLICY-SPEC).

## Compatibility

* Mount plan: identical (the only input that changes is the *content* of two
  generated files).
* Environment: two extra variables. A program that tested `USER` for emptiness
  now sees it set.
* Session dirs, control protocol, `--json` schemas: unchanged.

## Tests

* Unit: `supervisor::tests::username_*` (lookup result vs. fallback and its
  reason, rejection of `:` / newline / space / `/` / leading `-` / over-long
  names, `passwd_name` against `id -un`, an absent uid gives `Ok(None)`);
  `mounts::tests::stubs_use_the_host_username_not_a_constant` (fake
  `HostFacts`, passwd and group content); `env::tests::user_and_logname_*`
  (set from the argument even when the host env says otherwise or has no
  `USER`, not overridable via `env.pass`/`env.set`); `exec::tests`
  (request env naming `USER`/`LOGNAME` is rejected).
* Leak test **L1c** (needs user namespaces; "run on host"): `id -un`,
  `$USER`, `$LOGNAME` inside the sandbox equal the host's `id -un`, and
  `getent passwd <uid>` returns exactly the generated record
  `name:x:uid:gid:name:/run/hisn/home:/bin/sh`, in three sessions: the suite's
  exec session, one under `env -i`, and one under `env -i USER=notme
  LOGNAME=notme` (a false launch value must not be believed).

## Host commands (verbatim)

```
cargo install --path . --locked
make lint && make test
make leaktest-log
```

Expected leak total: 186 + 12 L1c lines = **198 passed**, 0 failed, 1 skipped
(L12), 1 weak (L14 R5). (L1c: 4 checks x 3 sessions; fewer if `getent` is
missing or the host user name is outside the portable set, in which case the
affected lines are SKIP.)

## Not covered

No leak result exists for 0.2.2 until the host log is committed; see
`docs/VERIFICATION.txt`.

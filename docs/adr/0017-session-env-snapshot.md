# ADR 0017 — The session environment is a snapshot declared at creation; requests may only add

Title: Session env precedence and the secret-value rule.
Status: accepted. Date: 2026-11-07. Origin: PLAN-0.4 §4.

## Decision
Precedence for every exec and attach, lowest to highest:
1. scrub base (`PATH HOME TERM LANG LC_* TZ` from the host, filtered as today);
2. session declared (`env.declared` in `session.json`, from the creating client's `env_pass`/`env_set`/`--env`), which replaces the base for the keys it names;
3. computed (`USER`, `LOGNAME`, `XDG_*`, cache vars, `HOME` forced to the sandbox home), which always wins and is never overridable;
4. per request (`exec.env`), which may add names in `env_pass` that are not session-declared. A request naming a session-declared key is refused with `E_ENV_LOCKED`.

A request cannot remove a declared key, because removal is not expressible in the request schema.

Secret-shaped names (`looks_secret`) keep their value in supervisor memory only. `session.json` stores `"<redacted>"`. Non-secret names, including `GIT_SSH_COMMAND` and `SSH_AUTH_SOCK`, are stored in full. Planner guidance: never put key material in `GIT_SSH_COMMAND`, only a key path.

## Why
The creating client decides the session's environment once, so every attached
client sees the same tools and identity. A later client cannot silently
change `GIT_CONFIG_GLOBAL` or `HOME` for the others. A host variable from an
attaching client's shell can never reach the session, because the base is
always the scrub plus the snapshot.

## Consequences
- The snapshot is stored in the session dir (0600). A declared secret-named value does not survive a supervisor restart. There is no daemon in 0.4, so this has no effect in practice; it is stated here, not hidden.
- Tests: unit `session_declared_wins_over_scrub_base`, `request_cannot_override_declared`, `computed_still_wins`; leak L59 (host `HISN_LEAK_SECRET` absent in exec and attach from a snapshot session), L60 (planner `GIT_CONFIG_GLOBAL` present, host value absent).
- Note: the requested `TestIntegrationEnvIsAllowlisted` does not exist in the tree. Its intent is covered by L4 and L59, and by the unit tests named here.

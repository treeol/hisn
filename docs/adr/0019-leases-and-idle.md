# ADR 0019 — Leases: owner, last activity, and idle means no clients, no exec, and timeout passed

Title: Session lease semantics for 0.4.0.
Status: accepted. Date: 2026-11-07. Origin: PLAN-0.4 §5; completes ADR 0008's deferred "leases in 0.4".

## Decision
- `session.json` records `owner`, `created`, `last_activity` (written at most once per 10 s), and `lease.idle_timeout` from the profile key `[session] idle_timeout` (duration `\d+[smhd]`, default none = never idle).
- A session is **idle** iff it has zero connected clients **and** no exec is running **and** `now − last_activity > idle_timeout`. An attached shell at a prompt with a connected client is never idle.
- An idle session stops itself through the normal stop path and writes `op:"lease", stage:"expired", reason:"idle"` to its audit.
- `hisn stop --session X` is an explicit stop, audited as `op:"stop"`. In 0.4 any authorized client may stop.
- Nothing stops a session with a connected client, except an explicit stop by an authorized client.

## Why
ADR 0008 deferred leases because they need per-client identity. ADR 0016 supplies it. A connected client is the only reliable liveness signal, because a timer alone would kill a session someone is using at a prompt.

## Consequences
- `hisn ls` shows the remaining lease. `hisn-ls/v2` gains `lease` and `clients`.
- Tests: unit `idle_never_fires_with_a_connected_client`, `idle_fires_after_timeout_with_zero_clients`, `last_activity_rate_limited`, `stop_is_audited`; leak L61 (attached session survives past timeout; the same session after the client is gone is stopped and audited).
- Behaviour when the supervisor is killed is unchanged: the session dies with it, as today.

## Clarified (PLAN-0.4 §11, round-1)

`stop` and idle expiry do not delete the session dir. They set state `stopped`
in `session.json` and keep `grants.jsonl`. Only `ls --prune` removes a dir, and
it refuses a stopped dir whose audit has not been archived (format open, O3).

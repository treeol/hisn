# hisn 0.4.0 — seats

## What's new

0.4.0 adds "seats": a hisn session is a place several clients join, locally
or over SSH (`ssh -t host hisn attach --session <name>`), with equal access
(uid == owner). The client record, the authorization seam, the members list
and the audit fields exist from 0.4.0 so a later role model changes one
function and a policy source — nothing else.

### Named sessions
- `hisn run --name <name>` (unique per user)
- `--session` accepts a name or id everywhere
- `hisn ls` shows NAME, ID, STATE, CWD, ROOTFS, NET, AGE, CLIENTS, LEASE
- A per-user index in the `/tmp/hisn-$UID` root is authoritative; `ls --prune` repairs it

### Lifecycle
- `session.json` carries `state ∈ {creating, running, stopping, stopped, crashed}`
- `.tmp-<id>` publication with fsync+rename (atomic)

### Attach
- `hisn attach --session <name|id>` — interactive shell ($SHELL from the env snapshot, else /bin/sh)
- Multiple attaches are peers (same pid namespace)
- Detach key: Ctrl-] then d (closes the client; the shell is killed on disconnect)
- No `--detach` in 0.4.0

### Client identity and the authorization seam
- Every control request carries a `ClientRecord` (uid, pid, label, req_id, seq, principal)
- One `authorize()` function gates every op; in 0.4.0 it allows iff `uid == owner.uid`
- The `Authorized` token cannot be forged outside the `authz` module
- Every audit line carries `client`, `seq`, `authz`
- Members are append-only in `session.json`

### Session env snapshot
- `--env K=V` at run declares a session env
- Precedence: scrub base < declared < computed
- A request naming a declared key gets `E_ENV_LOCKED`
- Secret-looking values are stored on disk as `<redacted>`

### Leases, stop, archival
- `[session] idle_timeout` (duration string, default none = never)
- `hisn stop --session X` — sets state stopped, keeps the dir
- `ls --prune` archives `grants.jsonl` + `session.json` to `$XDG_STATE_HOME/hisn/audit/<id>.jsonl` (0600)
- `--purge` skips archival

## Fix round (Mashūra review)
- **F1**: `Request` gains an optional `client` field (`ClientField { label, label_source, req_id }`). The supervisor builds `ClientRecord` from SO_PEERCRED + the client-supplied fields. A `client` object containing `uid` is refused (`deny_unknown_fields`).
- **F2**: idle timer thread (wakes every `min(timeout/4, 30 s)`, guards against backward clock, no timer when `idle_timeout` is unset).
- **F3**: `XDG_STATE_HOME/hisn` added to the persist-home refuse set; archive writes compact JSON (not pretty), uses `create_new(true)` + rename, checks dir ownership and mode.
- **F4**: stop sets `stopping` → sends TERM → waits for exit → sets `stopped`. Timeout returns failure without writing `stopped`.
- **F5**: `touch_lease` is a no-op when `idle_timeout` is unset; `session_json_lock` serialises all rewrites.
- **F6**: `parse_duration` rejects non-ASCII and empty input without panicking; uses `checked_mul`.
- **F7**: detach shuts down the write side (triggers TERM→KILL), reads the exit line with a 5 s timeout; SIGWINCH forwarded.
- **F8**: members keyed by `(uid, label)`, not uid alone.

## What's NOT in 0.4.0
- No daemon, no network listener, no public service. SSH is the only remote transport.
- No `--detach` for attach.
- Egress proxy (0.4.1) and cgroups (0.4.2) are deferred.
- Equal access only — roles come later.

## Host verification (rubin + smaragd)
1. `hisn run --name test0 --profile base -- make test` on smaragd
2. `hisn ls` shows the session with its name and state
3. `ssh -t rubin hisn attach --session test0` — attach from rubin over SSH
4. Both clients run execs; the audit shows both client records
5. `hisn stop --session test0` — the dir stays as stopped
6. `make leaktest` with `HISN_TEST_ROOTFS` set — L51–L61, L72
7. Probe (a): uid mapping and peer creds (see .wakil/plans/PROBES-0.4.0.md)
8. Probe (b): PTY over ssh (see .wakil/plans/PROBES-0.4.0.md)

## Gate
- `cargo fmt --check` ✓
- `cargo clippy --all-targets -- -D warnings` ✓
- `cargo test --lib` ✓ (361 pass, 2 fail = known sandbox-only)
- `python3 tests/leak/test_l8.py` ✓
- `make leaktest` — HOST only (needs user namespaces)
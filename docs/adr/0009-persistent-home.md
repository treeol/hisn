# ADR 0009 — Persistent `$HOME` (0.3.2)

Status: accepted. Date: 2026-11-04. Context: `docs/PLAN-0.3.2.md §1`.

## Decision

A profile may declare a **persistent home directory** that survives across
sessions:

```toml
[home]
persist = "/home/user/.cache/wakil/home/proj"
```

When set, the directory is bind-mounted rw as the session's `$HOME` at the
same in-sandbox path (`/run/hisn/home`) that hisn uses for the tmpfs home.
Absent → today's tmpfs home, byte-for-byte identical behaviour.

CLI override: `hisn run --home-persist <path>` (same validation; overrides
the profile key).

## Resolution

`[home] persist` is resolved **after** the inner policy's `session.home`,
as a post-resolution override (`Policy::resolve`):

1. Expand `~` to the invoking user's home directory.
2. Canonicalise the **parent** (which must exist); join the final component.
3. **Refuse list** (checked before any namespace is created):
   - the real host `$HOME`
   - any ancestor of the real host `$HOME`
   - `/`
   - the resolved session cwd
   - any ancestor of the session cwd
   - a path that is not a directory after creation
4. Create the directory if missing (`fs::create_dir`, mode 0700).
5. Override `ResolvedPolicy.home` to `Home::Path(canonicalised)`.

## Sharing

Several sessions may share one persist dir (caches tolerate that). No locking.
A session can poison caches read by later sessions in the same dir — that is
the risk.

## Risk label

`home-persist` (medium, `RiskLabel::Data`): state carries across sessions;
a session can poison caches read by later sessions in the same dir. Shown by
`profile explain` and in the JSON output used by Wakil's banner.

## Invariants

- The host `$HOME` is never visible inside the sandbox (the refuse list
  rejects it before any namespace exists).
- The tmpfs rules for `/tmp` and `/dev/shm` are unchanged.
- Profiles without `[home]` behave identically to 0.3.1.
- The persist directory is the only host path that becomes `$HOME`; nothing
  else from the host home is visible.

## Leak tests

L42: host `$HOME` not visible; persist dir reachable only at the mounted path;
a symlink inside the persist dir pointing to a host path outside it does not
grant access; a file written in session A exists in session B; writes anywhere
else under the former home location fail; each refuse-list case (real
`$HOME`, ancestor of `$HOME`, `/`, cwd, ancestor of cwd, non-directory) is
rejected before any namespace is created — no session dir or socket is
created.
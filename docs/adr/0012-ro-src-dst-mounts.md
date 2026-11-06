# ADR 0012 — Read-only `src:dst` mounts (0.3.3)

Status: accepted. Date: 2026-11-06. Context: 0.3.3 brief, item C3.

## Context

`mounts.ro` accepted only same-path entries: a host path was bound read-only
at the identical path inside the session. A host file that a session should see
at a different path (for example a config file at the location a tool expects)
had no way to be expressed without a symlink, and a symlink in the session
would point at a host path that does not exist inside it.

## Decision

`mounts.ro` entries may be `path` (unchanged) or `src:dst`:

```toml
[mounts]
ro = ["/opt/toolchains", "/home/me/.gitconfig:/etc/gitconfig.d/user"]
```

- The grammar splits at the single `:`. Both sides must be absolute and NUL-free.
  A `:` in the same-path form is not valid.
- `src` is a host path. It is resolved as every other mount source: a symlinked
  final component is refused, intermediate symlinks are canonicalised on the host
  before mounting. The session never sees the link, and never sees the host
  path `src` itself (the leak test checks this).
- `dst` is an in-session path. It must be absolute, must not contain `..`, and is
  lexically normalised. It is refused when:
  - it lies under `/run/hisn` or any hisn runtime root (named in the error);
  - it equals, lies inside, or contains any other session mount: the profile's
    own mounts (cwd, rw, home, `/tmp`, `/run`, `/dev`, `/proc`, `/dev/shm`), the
    toolchain binds (`/usr`, `/bin`, `/lib`, …, `/nix`, `/opt`), `/etc` and the
    generated `/etc` files, and other `ro` destinations. The planner reports the
    conflicting path.
- A `src:dst` bind is mounted `ro, nosuid, nodev` (MOUNT_ATTR_RDONLY |
  MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV). There is no write path into the session
  from this entry. Writes are refused with `EROFS` (leak test L47).
- Same-path entries keep their 0.2 flags (`ro, nosuid`, recursive). Changing them
  would alter existing plans; the brief asked that they keep working unchanged.
- The R1b alias check (`supervisor::mountinfo_check`) runs against `src`, the
  host tree that is actually mounted.

## Consequences

- `ResolvedPolicy` gains `ro_binds: [{src, dst}]` next to `ro` (the in-session
  targets, unchanged for existing consumers). A policy built with only `ro` is
  treated as same-path entries.
- Landlock's static read-only set and the mount table (`hisn inspect`, L8) see the
  `dst`, which is the path the session can use.
- Revocation and grants are unaffected: `src:dst` mounts are static, created at
  session start, like `ro` entries today.

## Alternatives considered

- **Symlink inside the session**: rejected. A link to a host path resolves
  nowhere inside the session and would require the executor to follow symlinks
  (the planner forbids that by design).
- **Allow dst under `/run/hisn`**: rejected. That tree is hisn's own runtime and
  control area.
- **Allow dst to shadow a session mount** (e.g. overlay a file over `/usr/share`):
  rejected for 0.3.3. Shadowing an owned tree makes the mount table depend on
  mount order and hides owned content. Can be revisited with a use case.

## Tests

- Unit (policy): grammar (`split_ro_entry`), `src` canonicalised, symlinked final
  `src` refused, `dst` under `/run/hisn` refused with the path named, `dst` with
  `..` refused.
- Unit (mounts): `src:dst` mounts the source at `dst` only (nodev, ro); same-path
  unchanged; collision with `/tmp` and with the toolchain `/usr` refused with
  `RoConflict` naming the path.
- Leak (L47–L49, `tests/leak/run.sh`): same-path still works; `src:dst` shows the
  file at `dst`, not at `src`, read-only and nodev; a dst under `/run/hisn` and a
  dst colliding with another mount are rejected at validate; a symlinked `src`
  directory is resolved on the host before mounting.

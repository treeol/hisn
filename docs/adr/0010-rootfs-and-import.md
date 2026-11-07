# ADR 0010 — Read-only rootfs and import tool (0.3.2)

Status: accepted. Date: 2026-11-04. Origin: the 0.3.2 planning document (§2), removed from the tree; this record stands alone.

## Decision

A profile may declare a **rootfs** — a directory tree that replaces the
host toolchain dirs (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`,
`/opt`, `/nix`, `/etc`) inside the sandbox:

```toml
[rootfs]
name = "go-dev"            # resolve from the rootfs store
# or
path = "/path/to/rootfs"  # use a directory directly
```

When set, the read-only system dirs come from the rootfs tree instead of the
host. Host `/usr`, `/opt` and `/nix` must not be visible anywhere in the
mount tree. All rootfs mounts are `ro, nosuid, nodev`.

Absent → today's behaviour (host `/usr`, `/opt`, `/nix` read-only).

## Store

`$XDG_DATA_HOME/hisn/rootfs/<name>/` (default `~/.local/share/hisn/rootfs/
<name>/`), each with a `manifest.json`:

```json
{
  "name": "go-dev",
  "source": "docker://golang:1.24",
  "source_digest": null,
  "import_timestamp": "2026-11-04T12:00:00Z",
  "hisn_version": "0.3.2",
  "sha256": "<sha256 of the imported tar>",
  "files": 1234,
  "skipped": 0,
  "size_bytes": 456789
}
```

## Import tool

```
hisn rootfs import <name> --from-tar <file|->
hisn rootfs import <name> --from-image <image>
hisn rootfs list | path <name> | rm <name>
```

`--from-image` execs `docker create` + `docker export` + `docker rm` on the
host and feeds the tar to the core extraction path. Docker CLI missing →
clear error.

## Extraction hardening

- Extract as the invoking user with `--no-same-owner` semantics.
- Strip setuid/setgid bits from all entries.
- Reject entries with `..` components; absolute member names are normalised
  to relative (stripped of the leading `/`) and then checked.
- Hard links whose target points outside the target dir are rejected; links
  to siblings inside the archive are allowed.
- Symlinks are stored as-is (they resolve inside the mounted tree).
- Device nodes and fifos are skipped and counted in the manifest.
- Refuse to overwrite an existing name without `--replace`.
- With `--replace` the old tree is moved aside (`.old-<name>-…`), the new tree
  is renamed in, and the old tree is removed only afterwards. If the rename of
  the new tree fails, the old tree is restored; if that also fails, the error
  names the `.old-*` path. A replace never deletes the old tree before the new
  one is in place.
- Atomic publication: extract to a staging dir, then `rename` to the final
  name. A failed import leaves no partial store entry.

## `hisn check`

Reports the rootfs store path and the names present. `profile validate`
resolves `name`/`path` and fails on a missing rootfs.

## Risk label

`rootfs` (low, `RiskLabel::Trust`): the toolchain comes from the imported
image instead of the host; host `/usr`, `/opt` and `/nix` are not visible —
you trust the image, not the host install.

## Invariants

- Rootfs mounts are `ro + nosuid + nodev`.
- Host `/usr`, `/opt`, `/nix` are not visible when a rootfs is set.
- hisn never writes into the user's rootfs tree at session start.
- hisn's `/etc` stubs (passwd/group with the real username) are layered on
  top of the rootfs `/etc` exactly as today.
- cwd path parity, `/proc`, `/dev`, `/tmp`, `/dev/shm`, `$HOME`, control
  socket and `[[services]]` are unchanged.

## Leak tests

L43 (with `HISN_TEST_ROOTFS`): host `/usr`, `/opt`, `/nix` not visible (host-
only marker absent in session); a host-only binary cannot be executed;
rootfs write fails (ro); `/usr` mount shows `ro,nosuid,nodev` in
`/proc/self/mountinfo`; a remount cannot drop the flags; the username equals
the host username; `nosuid` is enforced.

L46 (with `HISN_TEST_ROOTFS`): symlink traps in the rootfs (`/usr/local/bin/trap
→ ../../../../home`, absolute symlink to host `$HOME`) do not reach host data.

L44 (always runs): import-time rejection tests (path traversal, absolute
names, hard links, setuid stripping) on a synthetic tar.
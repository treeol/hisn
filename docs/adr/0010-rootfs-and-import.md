# ADR 0010 — Read-only rootfs and import tool (0.3.2)

Status: proposed. Date: 2026-11-04. Context: `docs/PLAN-0.3.2.md §2`.

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
- Atomic publication: extract to a staging dir, then `rename` to the final
  name. A failed import leaves no partial store entry.

## `hisn check`

Reports the rootfs store path and the names present. `profile validate`
resolves `name`/`path` and fails on a missing rootfs.

## Risk label

`rootfs` (low, `RiskLabel::Data`): the sandbox runs whatever the image
contains — trust in the image replaces trust in the host toolchain; it
reduces host exposure.

## Invariants

- Rootfs mounts are `ro + nosuid + nodev`.
- Host `/usr`, `/opt`, `/nix` are not visible when a rootfs is set.
- hisn never writes into the user's rootfs tree at session start.
- hisn's `/etc` stubs (passwd/group with the real username) are layered on
  top of the rootfs `/etc` exactly as today.
- cwd path parity, `/proc`, `/dev`, `/tmp`, `/dev/shm`, `$HOME`, control
  socket and `[[services]]` are unchanged.

## Leak tests

L43 (with `HISN_TEST_ROOTFS`): host `/usr` not visible; a host-only binary
cannot be executed; rootfs write fails (ro); a setuid binary runs without
privilege; a crafted symlink does not reach the host; the username equals
the host username.

L44 (always runs): import-time rejection tests (path traversal, absolute
names, hard links, setuid stripping) on a synthetic tar.
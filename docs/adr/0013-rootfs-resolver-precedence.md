# ADR 0013 — Session `resolv.conf` precedence for `network = "host"` (0.3.3)

Status: accepted. Date: 2026-11-06. Origin: the 0.3.3 review (commits
`4ee66fc`, `0afadf3`); code in `src/mounts.rs` (`build_resolv_conf_ordered`,
`read_image_resolv_conf`).

## Decision

On `network = "host"` the session's `/etc/resolv.conf` is built from the first
usable source, in this order (`build_resolv_conf_ordered`, `src/mounts.rs`):

1. `[net] nameservers` from the profile, if set. It overrides everything.
2. The host `/etc/resolv.conf`, if it lists a non-loopback `nameserver`. Its
   nameservers and search/options lines are used.
3. The systemd-resolved upstream file `/run/systemd/resolve/resolv.conf`, if the
   host file has no usable nameserver and this file does. Its search lines are
   used when the host file gave none.
4. The rootfs's own `etc/resolv.conf`, **only** when rootfs is in use and both
   host sources are unusable. Its nameservers and search lines are used.
5. Otherwise the launch **fails closed**. An empty resolv.conf is never written.

Loopback stubs (`127.0.0.0/8`, `::1`) are never used: they are unreachable from
the session's network namespace.

The rootfs file is last so that a populated image file never shadows a working
host resolver.

The image file is read through `openat2` with `RESOLVE_BENEATH |
RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, so a symlink in any component
(including `etc` itself) is refused rather than followed.

## Why

- A populated image `resolv.conf` must not shadow a host resolver that works.
  The first 0.3.3 draft (`4ee66fc`) put the image file before the host file, so
  a rootfs session whose image shipped an empty or useless file could launch
  without DNS even though the host resolved. The 0.3.3 Mashūra round (`0afadf3`)
  made the image file the last resort, after both host sources.
- On `network = "host"` the host's resolvers are the ones the session is meant to
  reach, so they are preferred over the image's.
- Reading the image file without following symlinks keeps the rootfs from
  pointing the resolver read at host files.

## Consequences

- Leak test L50 (`HISN_TEST_ROOTFS` set) covers the image-file case, the
  loopback-only case and the fail-closed case.
- Precedence changes are behaviour changes: they need a CHANGELOG entry and a
  leak-test update.
- `network = "none"` is unaffected: there is no resolver in that mode.

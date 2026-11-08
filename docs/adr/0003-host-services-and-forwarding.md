# ADR 0003 — Host-side services and socket forwarding

Status: accepted. Date: 2026-11-02. Origin: the 0.3 planning document (§3), removed from the tree; this record stands alone.

Implemented in 0.3.0 (`src/profile.rs`, `src/supervisor.rs`; CHANGELOG 0.3.0, "Socket forwarding" and "Host-side services").

## Decision

Two entry kinds, both about exposing a **host-side unix socket** inside the
sandbox at a declared path, as a **read-only mount of one socket inode**:

- `[[host_services]]` — hisn **starts** a process outside the sandbox as the
  user (never with extra privilege) and exposes its socket inside.
- `[[forward]]` — hisn exposes an **existing** host socket (ssh agent,
  Docker daemon) without starting anything.

```toml
[[host_services]]
name   = "kvr-host"
exec   = ["kvr-server", "--addr", "%t/kvr/%p.sock"]
socket = "/run/user/1000/kvr/abc123.sock"     # host path
expose = "/run/kvr/kvr.sock"                  # in-sandbox path
ready  = { socket = "/run/user/1000/kvr/abc123.sock" }
stop   = { signal = "TERM", grace = 5 }

[[forward]]
name   = "ssh-agent"
socket = "/run/user/1000/ssh-agent.sock"      # existing host socket
expose = "/run/ssh/agent.sock"
risk   = "signing"
risk_ack = "signing"
```

## How the socket gets inside

The supervisor `open_tree`s the host socket inode (`OPEN_TREE_CLONE`, the
same mechanism as a ro grant) and `move_mount`s it at `expose` inside the
sandbox root, with `MOUNT_ATTR_RDONLY`. From inside the sandbox the socket is
a unix socket file at `expose`; the sandbox can `connect(2)` to it.

### What the sandbox can and cannot do with a forwarded socket

- **Can:** `connect(2)` to `expose`; speak the service's protocol over the
  stream. The risk is whatever the protocol allows (§5): an ssh agent is
  `signing`; a Docker socket is `root-equivalent` unless T1 proxies it (§4).
- **Cannot unlink it:** the mount is ro (`MOUNT_ATTR_RDONLY`); unlink targets
  the inode, which is the ro mount. The parent directory is the sandbox root
  tmpfs (owned by the mapped uid) but the socket inode is not writable.
- **Cannot re-bind it:** the sandbox has no `CAP_SYS_ADMIN` and seccomp denies
  `mount`/`umount` (the mount syscall), so it cannot create a new mount at
  that path. (`bind(2)` the socket syscall is not denied; the sandbox can
  create its own unix sockets, but it cannot move the forwarded inode.)
- **Cannot see the host path:** `expose` is the only name; `socket` (the host
  path) does not exist in the sandbox's mount namespace. `connect(2)` to
  `expose` lands on the forwarded inode; there is no `readlink`-able path to
  the host.
- **Cannot see other host sockets:** only the one inode is exposed, not the
  host's `/run`.

The host-side process (`[[host_services]]`) runs **as the user** with the
user's normal credentials, never setuid, never with extra caps. It is reaped
by the supervisor and stopped with `stop.signal`/`grace`. Its host-side
socket path satisfies the same path rules (R1–R4) as a grant source, **except**
it is not under `grantable_rw` (it is a host path, not a grant). **A profile's
arbitrary host-side `exec` is user-equivalent execution** (round-2 BLOCKING):
a trusted profile that launches a cwd-controlled executable, interpreter
script, or configuration can turn sandbox-writable content into host code.
`[[host_services]]` therefore requires `risk_ack = "host-exec"` for the
execution itself, independently of the socket's label (§5). The `exec` binary
must be resolved from a host-side `PATH` (not the sandbox's); the profile may
constrain `PATH` and `cwd` for the host process.

## `[[forward]]` vs `[[host_services]]`

`[[forward]]` is the primitive (expose an existing socket).
`[[host_services]]` is `[[forward]]` plus "start the thing that owns the
socket" plus host execution. Both share the expose mechanism and the
ro-mount invariant. A `[[forward]]` of the raw Docker socket with no
`risk_ack` is a **load error** (T2 requires `risk_ack = "root-equivalent"`,
§4); the same for an ssh agent without `risk_ack = "signing"` (§4b);
`[[host_services]]` requires `risk_ack = "host-exec"` for the execution
itself (round-2 BLOCKING), plus the socket's label.

## Why not grant the socket's parent dir

Granting the parent dir would expose the *host directory* — all the other
sockets, the agent's state, etc. `open_tree` of the socket inode exposes
exactly the socket file and nothing else. This is the same deny-by-
non-existence principle as the rest of the sandbox: the sandbox sees *one*
socket, not the host's `/run`.

## Invariants

- 1: the exposed socket is a single ro mount inside the empty-tmpfs root;
  the host path is absent.
- 2: seccomp still denies mount/unlink/unbind from inside; the mount is made
  by the supervisor.
- 3: the forward lives as long as the session; on session end the host-side
  process is stopped and the mount dies with the mnt ns.
- 5: annotation only (`org.hisn.forward=[{name,expose,risk}]`); if emitted
  in v2, the mount is `mounts[]` `{destination=expose, type:"bind",
  options:["ro","nosuid","nodev"]}`.

## Threat model

The sandbox gains: a stream socket it can `connect` to. It does not gain:
the host path, the ability to unlink/rebind, other host sockets, or (for
`[[forward]]`) the ability to start anything on the host. The risk is
bounded by the service's protocol — which is why docker T2 and ssh T2 need
`risk_ack` (§4, §4b), and why an **unknown** socket defaults to `host-exec`
(§5, round-1 BLOCKING): hisn cannot know its protocol, so it defaults to the
strongest non-root label. Leak tests: L36 (forward), L37 (host_service).
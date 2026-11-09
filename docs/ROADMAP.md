# hisn roadmap

## Done

- **0.2.x**: `exec` into a running session and `run --detach`. The control ops
  `exec` and `signal`, the helper chain with confinement re-applied on every
  exec (DESIGN §14), leak tests L15 to L20. See [CHANGELOG](../CHANGELOG.md).
- **0.3.0**: profiles (`hisn-profile/v1`), risk labels, socket forwarding,
  host-side and in-sandbox services, Docker T2, named sessions. See the
  [CHANGELOG](../CHANGELOG.md) entry for 0.3.0.
- **0.3.1 to 0.3.3**: persistent `$HOME`, read-only rootfs and `hisn rootfs
  import`, SSH agent T1, `src:dst` read-only mounts, resolver derivation for
  `network = "host"`, `exec --no-tty`. See the [CHANGELOG](../CHANGELOG.md).
- **0.4.0**: seats. Named sessions, `attach`, client identity and the
  authorization seam, session env snapshot, leases, `stop`, archival on prune.
  See [releases/v0.4.0.md](releases/v0.4.0.md).
- **0.4.1**: `run --detach` returns, event-driven start and stop, live `clients`
  and `execs` in `ls --json`, `ls --prune --name-prefix` and `--dry-run`,
  `run --env-file`, `exec --client`. See [releases/v0.4.1.md](releases/v0.4.1.md).
- **0.4.2**: profile validation for `grace`/readiness `timeout`, NUL bytes and
  `ready.tcp`; cancelled execs are killed; `ready.command` probes are bounded by
  `ready.timeout`; `session.json` writes are locked. See
  [releases/v0.4.2.md](releases/v0.4.2.md).

## Planned, not yet scheduled

- **Egress proxy.** A `network = "proxy"` mode: the sandbox gets a network
  namespace whose only route is a forwarder to a host-side proxy that enforces
  a hostname allowlist (CONNECT and DNS by name) and audits every request.
  Not implemented; today hisn offers only `network = "none"` and `"host"`.
- **cgroup v2 limits.** Memory, pids and cpu through a delegated cgroup subtree,
  falling back to rlimits with a warning. `hisn check` already reports whether
  cgroup v2 is mounted. Not implemented; today only `setrlimit` limits apply.
- **Attach pty allocated inside the session.** `ttyname()` fails inside an
  attach because the pty is allocated on the host `devpts` while the session
  has a private one. The chosen approach is to allocate the attach's pty inside
  the session and hand the master back to the client over the control socket,
  as `init::open_pty` already does for the main command. It changes the
  protocol in `exec.rs` (a descriptor travels sandbox to supervisor to client
  for the first time) and has to be verified on a host with L76, L10 and L8
  and with fd-leak checks. See DESIGN §20.1.

Other candidates: a 65536-id mapping through `newuidmap` with a launcher stage
(DESIGN D4); `/dev/pts` options; a shared-subtree grant fallback (DESIGN §10)
if `move_mount` into the user namespace is not permitted on some kernels.
Known limits of the current design are in [OPEN-POINTS](OPEN-POINTS.md).

## Ideas

None of these is implemented.

- **`hisn serve`**: an HTTP API over a unix socket with sandboxes as sessions
  and a `commands.run` that wraps the `exec` control op without reimplementing
  it.
- **`hisn mcp`**: an MCP server over stdio with `exec`, `read_file`,
  `write_file`, `grant`, `revoke` and `list_grants`. File access would go
  through the sandbox's own view so a client could not use it to bypass grants.
- **OCI runtime conformance**: hisn consumable as an OCI runtime for bundles
  that fit the model, and able to export a policy as `config.json` using the
  mapping in POLICY-SPEC §8. Images and registries stay out of scope.

## Explicitly never

A daemon, a setuid helper, a root requirement, macOS support, and image
distribution.

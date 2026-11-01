# hisn roadmap

## v0 (this repo)

Policy → rootfs/mounts → init (pivot_root, caps, NNP) → seccomp → Landlock →
env scrub → supervisor + unix control socket → grant/revoke → CLI → pty
passthrough. Linux x86_64 + aarch64. Acceptance: leak tests L1–L11 on a real
host (`make leaktest`).

Known v0 limits are tracked in `docs/OPEN-POINTS.md` (e.g. `/etc` is a live
bind, single-id uid map, no egress filtering, no cgroups).

## v0.x candidates

* allowlist-style `/etc` (only named files) instead of live bind + masks;
* 65536-id mapping via `newuidmap` using a launcher stage (DESIGN D4);
* `/dev/shm`, `/dev/pts` options;
* shared-subtree grant fallback (DESIGN §10) if `move_mount` into U is not
  permitted on some kernels.

## v1

1. **E2B-shaped HTTP API** over a unix socket (`hisn serve --socket PATH`):
   sandboxes = sessions; create/kill/list; `commands.run` (exec with streamed
   stdout/stderr/exit), `files.read|write|list`, `filesystem` watch is out of
   scope. The v0 JSON control socket stays the internal transport.
2. **MCP server** (`hisn mcp`, stdio): tools `exec`, `read_file`, `write_file`,
   `grant`, `revoke` (+ `list_grants`). `read_file`/`write_file` operate
   through the sandbox's view only (path must be visible in the session), so
   an MCP client cannot use them to bypass grants.
3. **Egress proxy with allowlist:** `network = "proxy"`; the sandbox gets a net
   ns whose only route is a unix-socket/loopback forwarder to a host-side
   proxy enforcing a hostname allowlist (CONNECT + DNS by name), audit-logged.
4. **cgroup v2 limits:** memory, pids, cpu via a delegated cgroup subtree
   (systemd user slice or pre-delegated); falls back to rlimits with a
   warning. `hisn check` already reports cgroup v2.

## v2

**OCI runtime-spec conformance:** `hisn` consumable as an OCI runtime
(`create/start/kill/delete/state`) for bundles that fit the model, and able to
export a policy as `config.json` using the mapping table in POLICY-SPEC §8,
with Landlock/dynamic grants as annotated extensions. Images/registries remain
out of scope (bundle rootfs only).

## Explicitly never

Daemon, setuid helper, root requirement, macOS support (v0), image
distribution.

# ADR 0004 — Docker access: T1 proxy / T2 socket / T3 nested userns

Status: proposed. Date: 2026-11-02. Context: `docs/PLAN-0.3.md §4`.

## 0.3 ships T2 only; T1 and T3 are 0.4

Round 2 of the Mashūra review found that T1's security boundary has gaps a
host-side proxy alone cannot close in 0.3: bind-source TOCTOU (the proxy
validates a path but the daemon resolves the string), container lifetime
(stop/remove RPC is cleanup, not construction — invariant 3), shared-bridge
lateral movement (inventory stops direct API requests but not
cross-container reachability through a shared `bridge`), and build authority
(`POST /build` is enabled by a gate with no build-threat-model). **0.3
rejects a profile with `docker = "proxy"` or `nested_userns = true`** with
`E_NOT_SUPPORTED`. T2 (`docker = "socket"`) is the only docker tier in 0.3.
T1 and T3 ship in 0.4, with the designs below as targets.

## T1 `docker = "proxy"` — designed for 0.4, rejected in 0.3

A host-side filtering proxy, `hisn-docker-proxy` (new crate in this repo,
separate binary, started by `[[host_services]]` and exposed via `[[forward]]`
internally). It presents a Docker-API unix socket inside the sandbox and
enforces a policy on every request.

### What the proxy does

**Endpoint + method allowlist (fixed in 0.3; no profile knob to widen it).**
Default allow: `/_ping`, `/version`, `/containers/json` (scoped to the
session's containers), `/containers/create`, `/containers/{id}/start`,
`/containers/{id}/json`, `/containers/{id}/stop`, `/containers/{id}/logs`,
`/containers/{id}/wait`, `/containers/{id}/inspect`, `/networks/*` (read),
`/volumes/*` (read). `POST /containers/create` and `/containers/{id}/start`
are the only mutating paths allowed; `/containers/{id}/stop` is allowed only
for containers in the session inventory. Everything else (images, build,
exec, attach, `system/df`, prune, events) is denied.

**Per-session container inventory (round-1 BLOCKING).** The proxy tracks
every container it created (by daemon container ID) and rejects all requests
referencing containers, volumes, networks, or exec IDs not in the session's
inventory (`403`). `/containers/json` is scoped to the session's containers;
`/containers/{id}/start|stop|logs|inspect` for a foreign container is denied.
Client-supplied labels are not proof of ownership. This closes the "start an
existing privileged container" bypass.

**`HostConfig` constraints** (enforced on `/containers/create`, rejected
with `403`):

- `Privileged` must be false.
- `CapAdd` must be empty.
- `NetworkMode` not `host`, `container:`, or host-port-mapped `bridge`;
  only `none`, `bridge` (default), or a named user network the profile lists.
- `PidMode`/`IpcMode` not `host` or `container:`.
- `Binds`/`Mounts`: every source under the session cwd or under a path in
  `[docker] allow_binds`, resolved with `openat2(RESOLVE_NO_SYMLINKS |
  RESOLVE_NO_MAGICLINKS)` in the daemon's view; a masked path inside cwd
  (e.g. `<cwd>/.secrets`) is rejected even if the mask is invisible to the
  daemon (round-1 BLOCKING). `VolumesFrom` must be empty; named volumes
  denied (they expose host-managed data). No `docker.sock` mount (any socket
  inode, not just the literal name).
- `Devices` empty.
- `SecurityOpt`: seccomp/apparmor not `unconfined` (the container keeps a
  seccomp profile; Docker's default stays).
- `User` must be set, must not be `0` or `root`, and must be a non-root name
  or a non-zero numeric uid (profile may set a default non-root user)
  (round-1 BLOCKING).

**Image policy.** `[docker] image_pull` (default `deny`) gates
`POST /images/create` (pull); `[docker] image_build` (default `deny`) is an
**independent** gate for `POST /build` (round-1 BLOCKING: the earlier text
conflated the two). `deny` for both means only images present on the host.
Build authorization beyond the on/off gate (buildx backends, entitlements,
exporters, `--output` transports) is **not modelled in 0.3** —
`image_build = "allow"` enables `POST /build` but the build's own authority
is a 0.4 threat model.

**Request log.** Every request appended to
`<session>/docker-proxy.jsonl`: method, **route template** (not raw URL),
status, duration, container id. Never the request body (may contain secrets
in env); never the response body; **never the query string** (it can carry
build args). The proxy parses and reconstructs a canonical request and
rejects ambiguous encodings/framing (round-1 BLOCKING: parser disagreement
between proxy and daemon can smuggle a request past the filter).

### Compose/buildx compatibility

`docker compose` works through T1 for the subset above (create + start +
logs + wait). What breaks:

- `docker compose up --build` (needs `POST /build`) unless
  `image_build = "allow"`.
- `docker compose run --service-ports` with host port maps (denied by the
  NetworkMode rule).
- `docker exec` (`POST /containers/{id}/exec` + the websocket) **denied in
  0.3** (round-1 BLOCKING: the earlier text offered `allow_exec = true`;
  that is removed). It is a shell into a container, which bypasses the
  proxy's creation filter; a 0.4 `allow_exec` would bind exec IDs to approved
  containers and validate privileges.
- `docker events` (streaming) denied; `docker system df`/`prune` denied;
  `docker push` denied; BuildKit `--output` to a host path outside cwd
  denied.

### What T1 breaks and why

| Docker feature | T1 | reason |
|---|---|---|
| `--privileged` | denied | a privileged container is root on the host |
| `--cap-add` | denied | same |
| `--net=host` | denied | container reaches host network directly |
| `--pid=host` / `--ipc=host` | denied | container sees host processes/IPC |
| `--device` | denied | direct device access |
| mounting `docker.sock` | denied | recursive root-equivalent |
| `docker exec` | denied by default | shell into a container bypasses the proxy |
| `docker build` | denied by default | build runs arbitrary RUN as root |
| `docker push` | denied | writes to a registry from inside |
| `docker events` | denied | streaming side channel |
| bind to host path outside cwd | denied | the whole point of the sandbox |

### Why a proxy and not a library

The sandbox talks to the proxy over a socket; it never links Docker client
code. The proxy is reusable for other host-side filtering (ssh agent, §4b
ADR 0005) and is a separate binary so its bugs are not in the sandbox binary.

## T2 `docker = "socket"` — raw forward, root-equivalent (the 0.3 tier)

`[[forward]]` of the host Docker socket. The sandbox can do anything the
Docker daemon can: privileged containers, host path mounts, re-mounting
`docker.sock`. **Root-equivalent.**

- Never the default (DO NOT ALTER #4).
- Never silent: `hisn run` prints
  `RISK: docker=socket is root-equivalent` on every start unless
  `--quiet-risk`.
- Only loadable from a profile with `risk_ack = "root-equivalent"` in
  `[docker]` (or top level); missing/mismatched → load error
  (`E_RISK_ACK_REQUIRED` / `E_RISK_ACK_MISMATCH`).

## T3 `nested_userns = true` — rootless podman/buildah inside (0.4, rejected in 0.3)

Allow `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)` inside the sandbox
so rootless `podman`/`buildah` runs **without any host daemon**.

### What changes

- **Seccomp:** `CLONE_NEWUSER` (0x10000000) removed from the `clone` deny
  mask (`seccomp.rs` `CLONE_NEW_BITS`); `clone3` allowed (or `ENOSYS` only
  when a `CLONE_NEW*` bit *other than* `NEWUSER` is set). `unshare` allowed
  **only for `CLONE_NEWUSER | CLONE_NEWNS` together** (rootless podman does
  both at once); `unshare` of `CLONE_NEWPID`/`NEWNET`/`NEWIPC`/`NEWUTS`
  stays denied.
- **Kernel attack surface:** `CLONE_NEWUSER` is the most-repeatedly-
  vulnerable Linux syscall. Allowing it inside means a hostile sandboxed
  process can provoke the kernel's userns code paths (id mapping, cap
  inheritance, the `proc` trick). The sandbox's seccomp denylist is defence
  in depth, not a proof (OPEN-POINTS P10). **Risk label: `kernel-surface`.**
- **Landlock/caps:** the nested userns is a *child* of the sandbox userns
  U; caps inside it apply only there; the nested root has no authority over
  U or the host. Landlock's domain is inherited (a nested process cannot
  escape the parent's ruleset), so the filesystem boundary holds. The
  concern is the kernel, not caps/Landlock.
- **subuid (D4):** rootless podman needs a `/etc/subuid` range. hisn's
  sandbox has no `/etc/subuid` (not in the `/etc` allowlist). T3 requires
  `[rootless] subuid = "<range>"` (e.g. `100000:65536`), which hisn
  synthesizes into the sandbox `/etc/subuid`/`/etc/subgid` as a ro stub
  (same mechanism as the `passwd` stub, §8). Without it `podman` cannot
  create a userns for its containers; with it nested rootless works.
- **Most secure for building images?** T3 is the most secure way to *build*
  if you accept the kernel-surface risk: no host daemon, no socket, the
  build happens in a nested userns that the sandbox's Landlock and caps
  still bound. T1 is safer for *running* containers against the host daemon
  (no userns inside). For *building* without a daemon, T3 wins; for
  *running* against the host daemon, T1 wins.

### Ship in 0.4, not 0.3

T3 needs subuid handling, a nested leak run (L38), and a seccomp profile
change that deserves its own review round. **0.3 rejects a profile with
`nested_userns = true`** with `E_NOT_SUPPORTED` (round-1 BLOCKING: BRIEF
invariant 2 expressly prohibits `unshare`, and an ADR cannot override that
binding requirement; silently accepting a T3 profile would let a profile
author believe a nested-userns sandbox is available when the seccomp filter
still blocks it). The `kernel-surface` risk label is defined now so profiles
can reference it; the "most secure for building" and "nested rootless works"
claims are removed pending 0.4 evidence.

## Valon's concrete case (smaragd deploy)

**In 0.3: Tier T2** (`docker = "socket"`, `risk_ack = "root-equivalent"`):
run `docker compose` against the host daemon. T1 is deferred to 0.4 (round-2
BLOCKING); the sandbox can run compose, the risk is root-equivalent and is
disclosed and acked. In 0.4, when T1 ships, the recommendation moves to T1.

```toml
[policy]
session.cwd = "."                       # the deploy repo
session.network = "host"                # compose services need host networking
mounts.grantable_rw = ["/srv/out"]

[docker]
tier = "socket"
risk_ack = "root-equivalent"
```

`session.network = "host"` is so the compose *services* can reach the host
network; it is not needed to reach the daemon socket (a unix socket under
`/run` is reachable with `session.network = "none"` — round-2 finding). The
current smaragd case uses `host` because the compose services themselves need
host networking; that is a 0.2 capability with risk label `data`.

## Invariants

- 1: T1/T3 add no host filesystem inside; T2 adds the docker socket, a ro
  mount of one inode.
- 2: T1/T2 the proxy/socket are host-side; T3 relaxes seccomp for
  `CLONE_NEWUSER` only — **but 0.3 rejects T3** (invariant 2 stays
  unchanged; `E_NOT_SUPPORTED`).
- 3: containers the proxy created are stopped on session end **by
  construction** (the supervisor's stop sequence), not by best-effort cleanup
  (round-1 BLOCKING). A daemon-unreachable container is a residual (§11)
  covered by the docker tier's `risk_ack`.
- 4: env unchanged.
- 5: T1/T2 annotation only (`org.hisn.docker.tier=…`); T3 (0.4) the seccomp
  `clone`/`clone3` rules change and map to `linux.seccomp` with
  `CLONE_NEWUSER` removed from the masked-arg rule.

## Threat model

- T1: gains unprivileged containers under cwd; **cannot** create
  privileged/cap-adding/host-net/pid-host containers, mount `docker.sock`
  (any socket inode), `docker exec`, build (default), push, or reach host
  paths outside `allow_binds`; **cannot** start/inspect/logs/stop a foreign
  container (per-session inventory). Leak test L28 (incl. adversarial
  foreign-container, symlink, masked-canary, and session-end cases).
- T2: gains root on the host (the docker daemon); by design
  root-equivalent. Leak test L29 (ack check + risk line).
- T3 (0.4, rejected in 0.3): gains the ability to provoke the kernel's
  userns code paths; cannot escape the sandbox's Landlock/caps (nested
  userns is a child) or reach host paths not granted. Leak test L38.
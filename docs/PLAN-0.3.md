# hisn 0.3 — plan

Status: planning. Output of the 0.3 planning task (no source changes; docs and
`docs/adr/` only). Baseline: `aa9e5c4` (0.2.0, host-verified). Binding input:
`docs/BRIEF.md` (the DO NOT ALTER block there always wins). Every feature below
states which invariant it touches and how it stays true.

The goal of 0.3: let a profile author describe a *wider* sandbox (controlled
access to a Docker daemon, a git identity, an ssh agent, an in-sandbox service,
host-side socket) **without** making it possible to create an insecure sandbox
by accident, and without widening the 0.2 sandbox unless the profile asks. A
profile that declares nothing yields exactly the 0.2 sandbox (DO NOT ALTER #3).

## How to read this plan

- "0.2.1" = the patch subset that ships first, on top of 0.2.0, no new surface.
- "0.3" = the features in §1–§7.
- "0.4" = explicitly deferred (§11).
- Each numbered feature has a matching ADR in `docs/adr/NNNN-*.md`.
- Leak tests continue from L24; new ones are L25+ and are the acceptance
  criterion for the threat-model delta in §9.
- "Invariant N" refers to `docs/BRIEF.md` §"DO NOT ALTER".

## 1. Profiles (ADR 0001)

### Decision

A **profile** is an envelope around `hisn-policy/v1`, **not** a v2. A profile
file is a TOML document with a `version = "hisn-profile/v1"` header and one
required table, `[policy]`, whose value is a complete `hisn-policy/v1` document
(inline table). Everything else in the profile (`[[services]]`,
`[[host_services]]`, `[[forward]]`, `[[risk]]`, `[docker]`, `[ssh]`, …) is new
0.3 surface; the `[policy]` block is resolved by the exact existing
`policy::load` + `policy::resolve` code path and is valid unchanged. v1 policy
stays valid unchanged.

```
# profiles/wakil.toml — a profile
version = "hisn-profile/v1"

[policy]                       # a full hisn-policy/v1 document
version = "hisn-policy/v1"
session.cwd = "."
session.home = "tmpfs"
session.network = "none"
mounts.grantable_rw = ["/srv/out"]

[[services]]                  # 0.3 §2
name = "kvr"
exec = ["kvr-server"]
socket = "/run/kvr/kvr.sock"
ready = { socket = "/run/kvr/kvr.sock" }
stop = { signal = "TERM", grace = 5 }

[[forward]]                   # 0.3 §3
name = "ssh-agent"
socket = "/run/user/1000/ssh-agent.sock"
expose = "/run/ssh/agent.sock"
risk = "signing"
risk_ack = "signing"
```

### Search path and precedence

`hisn run --profile <name|path>` resolves the profile in this order:

1. `--profile` with a `/` → that file (must exist, must be a profile not a bare
   policy).
2. `--profile <name>` → `$HISN_PROFILES/<name>.toml`, then the built-in
   `profiles/<name>.toml` shipped in the hisn repo (`go`, `rust`, `node`,
   `python`, `zig`, `wakil`). Built-ins are read from the install directory
   next to the binary (`hisn --version` reports it). **A profile resolved from
   under the session cwd (or any rw grant / persistent home) does not satisfy
   `risk_ack`** — a sandbox can write a profile that shadows a built-in name
   and self-ack the risk (round-1 BLOCKING: profile shadowing). `./<name>.toml`
   is deliberately **not** in the search path for this reason.
3. `--policy <file>` (existing) → a bare `hisn-policy/v1` document, treated as
   a profile with an empty `[policy]`-equivalent and **no** 0.3 surface. This
   is the 0.2 path; it stays for scripts and for the leak suite.

Precedence (highest wins): CLI flags (`--cwd`, `--network`, `--grant`) override
the profile's `[policy]` block, which overrides built-in policy defaults. This
is the existing resolution order (`POLICY-SPEC §2`); the profile layer adds
nothing above it. `--profile` and `--policy` are mutually exclusive (error:
`E_PROFILE_POLICY`).

### Sharing a profile

A profile is a single file you commit to a repo (a team's `profiles/` dir, a
Wakil project's `.hisn/profile.toml`). Built-ins live in the hisn repo under
`profiles/` and are installed next to the binary; `hisn profile list` prints
the resolved search path and the built-ins. A profile never carries secrets
(secrets stay in `env.pass` of the inner policy or in `[[forward]]` of an
agent socket — never in the profile file).

### Why envelope, not v2

v2 would fork the policy schema and force every 0.2 user to migrate. An
envelope keeps `hisn-policy/v1` as the isolation contract (the thing the leak
suite tests) and layers the *orchestration* surface (services, forwarding,
docker tier, risk) on top. The inner policy is resolved by the existing code,
so the 0.2 invariants are literally the same code path. OCI mapping for the
envelope is "annotation only" (the inner policy maps per `POLICY-SPEC §8`);
the new tables have no OCI runtime-spec representation.

**Invariant touched:** 5 (OCI mapping) — envelope tables are annotation-only;
the inner policy maps as today. **1, 2, 3, 4** untouched (same resolution,
same mount plan, same grants, same env scrub).

## 2. In-sandbox services `[[services]]` (ADR 0002)

### Decision

A `[[services]]` entry starts a long-lived process **inside the sandbox**
after the init sequence reports `READY` and before `hisn run` returns (or, for
`--detach`, before the session is listed as ready). The service runs under the
**same confinement as the main command**: same namespaces, same seccomp, same
Landlock, same caps (none), same env. It is a sibling of the main command in
the sandbox pid namespace, reaped by init.

```toml
[[services]]
name      = "kvr"                         # required, unique within the profile
exec      = ["kvr-server", "--addr", "/run/kvr/kvr.sock"]
socket    = "/run/kvr/kvr.sock"           # optional: the path it listens on
ready     = { socket = "/run/kvr/kvr.sock" }   # one of: socket | tcp | command
# ready = { tcp = "127.0.0.1:8080" }
# ready = { command = ["sh", "-c", "test -S /run/kvr/kvr.sock"] }
stop      = { signal = "TERM", grace = 5 }     # signal name + seconds; default TERM/5
restart   = "none"                        # only "none" in 0.3
```

### Lifecycle

1. Init finishes the setup sequence (`DESIGN §3`), reports `READY`.
2. The supervisor, on the host side but through the exec helper chain
   (`DESIGN §14.2`, process `C→D→W→P`), starts each service in order. The
   service is an exec like any other: it re-enters through the same `setns` +
   re-applied confinement (`§14.4`). It is therefore indistinguishable from
   the main command to the kernel.
3. Readiness: the supervisor polls `ready` (socket stat, tcp connect, or
   command exit 0) with a timeout (default 15 s; `ready.timeout` per service).
   On timeout the session fails to start (fail closed) — the service is
   killed and the session exits `125`.
4. Stop: on session end (init exit, `hisn kill`, or a `revoke --hard` that
   kills the pid ns), the supervisor sends `stop.signal` to the service's
   process group, waits `stop.grace`, then `SIGKILL`. This is the same
   TERM-then-KILL the exec monitor uses (`§14.8`).
5. `restart = "none"`: if a service exits before the session ends, it stays
   down. The supervisor logs the exit and does **not** restart. (0.4 may add
   `restart = "on-failure"`.)

### `ls --json`

`hisn ls --json` gains a `services` array:
`[{name, pid, socket, state: "starting|ready|exited", exit}]`. The `pid` is
the in-sandbox pid (same namespace as `exec` pids). The schema is frozen in
0.2.1 (§8) and extended here; it stays additive.

### Why inside, not host-side

kvr is a scratch store for Wakil's staging tools; it must be confined (it
holds transient agent data) and it must die with the session. Starting it
inside the sandbox means it gets the same seccomp/Landlock/caps as the
command for free, and its socket is only reachable from inside. A host-side
service (§3) is for things that must outlive or stand outside the sandbox
(Docker, an agent that signs with host keys); kvr is neither.

(Note: the service binds its socket with `bind(2)` on an `AF_UNIX` address
inside the sandbox — `bind(2)` the syscall is not `mount --bind`; the
seccomp filter denies `mount`/`umount`, not `bind(2)`. The sandbox can create
unix sockets on its own filesystem.)

**Invariant touched:** 1 (root is still an empty tmpfs + pivot_root — the
service sees the same root), 2 (same seccomp — the service is exec'd through
the same chain), 3 (grants die with the session — the service is in the pid
ns and dies with it). The service can widen the boundary **only** by what its
socket allows; that is bounded by the service's own protocol (kvr is a
key-value store over a unix socket, not a shell). **OCI:** annotation only
(`org.hisn.services=[{name,socket,…}]`).

## 3. Host-side services and socket forwarding `[[host_services]]` / `[[forward]]` (ADR 0003)

### Decision

Two kinds of entry, both about exposing a **host-side unix socket** inside the
sandbox at a declared path:

- `[[host_services]]` — hisn **starts** a process outside the sandbox, as the
  user, never with extra privilege, and exposes its socket inside.
- `[[forward]]` — hisn exposes an **existing** host socket (ssh agent, Docker
  daemon) inside without starting anything.

```toml
[[host_services]]
name    = "kvr-host"
exec    = ["kvr-server", "--addr", "%t/kvr/%p.sock"]   # %t = XDG_RUNTIME_DIR, %p = session id
socket   = "/run/user/1000/kvr/abc123.sock"            # the host path the process binds
expose   = "/run/kvr/kvr.sock"                         # the in-sandbox path
ready    = { socket = "/run/user/1000/kvr/abc123.sock" }
stop     = { signal = "TERM", grace = 5 }

[[forward]]
name     = "ssh-agent"
socket   = "/run/user/1000/ssh-agent.sock"   # existing host socket
expose   = "/run/ssh/agent.sock"              # in-sandbox path
risk     = "signing"
risk_ack = "signing"
```

### How the socket gets inside

The supervisor `open_tree`s the host socket inode (`OPEN_TREE_CLONE`, the
same mechanism as a ro grant) and `move_mount`s it at `expose` inside the
sandbox root, **read-only as a mount**. From inside the sandbox the socket is
just a unix socket file at `expose`; the sandbox can `connect(2)` to it. What
it **cannot** do:

- **unlink** it — the mount is ro (`MOUNT_ATTR_RDONLY`), so `unlink` of
  `expose` fails with `EROFS` (or `EBUSY` if the socket inode is momentarily
  busy). `connect(2)` on the forwarded socket **must succeed** — read-only
  mounts do not block socket inodes; the ro mount prevents `unlink`/`rename`,
  not `connect`.
- **re-bind** it — the sandbox has no `CAP_SYS_ADMIN` and seccomp denies
  `mount`/`umount` (the mount syscall), so it cannot create a new mount at
  that path. (`bind(2)` the socket syscall is not denied; the sandbox can
  create its own unix sockets, but it cannot move the forwarded inode.)
- **see the host path** — `expose` is the only name; the host path
  (`socket`) does not exist in the sandbox's mount namespace. `connect(2)` to
  `expose` lands on the forwarded inode; there is no `readlink`-able path to
  the host.
- **escalate through the socket** — the socket is a stream; the sandbox speaks
  the service's protocol over it. The risk is whatever the protocol allows
  (§5). For `[[forward]]` of an ssh agent that protocol is *signing*; for a
  Docker socket it is *root-equivalent* unless T1 proxies it (§4).

The host-side process (`[[host_services]]`) runs **as the user**, with the
user's normal credentials, never setuid, never with extra caps. It is reaped
by the supervisor and stopped with `stop.signal`/`grace`. Its host-side socket
path must satisfy the same path rules (R1–R4) as a grant source, **except** it
is not under `grantable_rw` (it is a host path, not a grant). **A profile's
arbitrary host-side `exec` is user-equivalent execution** (round-2 BLOCKING):
a trusted profile that launches a cwd-controlled executable, interpreter
script, or configuration can turn sandbox-writable content into host code.
`[[host_services]]` therefore requires `risk_ack = "host-exec"` for the
execution itself, independently of the socket's label (§5). The `exec` binary
is resolved from a host-side `PATH` (not the sandbox's); the profile may
constrain `PATH` and `cwd` for the host process.

### `[[forward]]` vs `[[host_services]]`

`[[forward]]` is the primitive: expose an existing socket. `[[host_services]]`
is `[[forward]]` plus "start the thing that owns the socket" plus host
execution. Both share the expose mechanism and the ro-mount invariant. A
profile that forwards the raw Docker socket (`[[forward]]` with
`socket = "/var/run/docker.sock"`, no `risk_ack`) is a **policy error** at
load time (§4 T2 requires `risk_ack = "root-equivalent"`); the same is true
for an ssh agent without `risk_ack = "signing"` (§4b); `[[host_services]]`
requires `risk_ack = "host-exec"` for the execution itself (round-2
BLOCKING), plus the socket's label.

### Why not just grant the socket path

Granting the socket's parent dir would expose the *host directory* (all the
other sockets, the agent's state, etc.), not just the one socket. `open_tree`
of the socket inode exposes exactly the socket file and nothing else. This is
the same deny-by-non-existence principle as the rest of the sandbox: the
sandbox sees *one* socket, not the host's `/run`.

**Invariant touched:** 1 (the exposed socket is a single ro mount inside the
empty-tmpfs root; the host path is absent), 2 (seccomp still denies
mount/unlink from inside; the mount is made by the supervisor), 3 (the
forward lives as long as the session; on session end the host-side process is
stopped and the mount dies with the mnt ns). **OCI:** annotation only
(`org.hisn.forward=[{name,expose,risk}]`).

## 4. Docker access — T1 / T2 / T3 (ADR 0004)

**0.3 ships T2 only.** T1 (proxy) and T3 (nested userns) are designed here
and in ADR 0004 but are **rejected in 0.3** and ship in 0.4 (round-2
BLOCKING: T1's bind-source TOCTOU — the proxy validates a path but the daemon
resolves the string it receives; container lifetime — a stop/remove RPC is
cleanup, not construction (invariant 3); shared-bridge lateral movement —
the inventory stops direct API requests but not cross-container reachability
through a shared `bridge`; build authority — `POST /build` is enabled by a
gate with no build-threat-model). T2 is the only docker tier that can ship
in 0.3 without a gap between claim and enforcement. The T1 and T3 designs
below are the 0.4 targets.

### T1 `docker = "proxy"` — designed for 0.4, rejected in 0.3

A host-side filtering proxy, `hisn-docker-proxy` (new crate in this repo,
separate binary, started by `[[host_services]]` and exposed via `[[forward]]`
internally). It presents a Docker-API unix socket inside the sandbox and
enforces a policy on every request.

**What the proxy does:**

- **The proxy is a separate, untrusted-code boundary, not a thin filter.** The
  Docker daemon runs host-side as root; a container it starts is not a child
  of the sandbox's PID namespace and does not inherit the sandbox's seccomp,
  Landlock, or rlimits (round-1 BLOCKING). T1 treats Docker workloads as a
  separate execution boundary with its own filesystem, network, resource,
  and lifetime policy:
  - **Per-session container inventory.** The proxy tracks every container it
    created (by daemon container ID, not client label) and **rejects** all
    requests referencing containers, volumes, networks, or exec IDs not in
    the session's inventory (`403`). `/containers/json` results are scoped to
    the session's containers only; `/containers/{id}/start|stop|logs|inspect`
    for a foreign container is denied. This closes the "start an existing
    privileged container" bypass.
  - **Bind-source containment is symlink- and mask-aware.** Bind sources are
    resolved in the **daemon's** filesystem view, not the sandbox's masked
    view, so a symlink inside cwd pointing at `/` would expose the host
    (round-1 BLOCKING). The proxy resolves every bind source with
    `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` and rejects if the
    resolved path is not under cwd or `allow_binds` *as the daemon sees it*;
    a masked path inside cwd (e.g. `<cwd>/.secrets`) is rejected even if the
    mask is invisible to the daemon. `VolumesFrom`, named volumes, and any
    mount mechanism other than an explicit `Binds`/`Mounts` source under an
    allowed path are denied.
  - **Creation filter is a closed schema.** `User` must be set and must not be
    `0` or `root`; `VolumesFrom` must be empty; named volumes denied; the
    full `HostConfig` is validated against a closed allowlist and any
    unknown/authority-bearing field is rejected (round-1 BLOCKING). The
    boundary is **container authority** (no Privileged, no CapAdd, no host
    namespace, no device), not "no shell" — `create`+`start` can already run
    a shell via command/entrypoint; the proxy prevents *privileged*
    containers, not shell access.
  - **Container lifetime ties to the session.** The proxy stops (and removes
    on `image_pull = "allow"`) every container it created when the session
    ends, **by construction** (the supervisor's stop sequence), not by best-
    effort cleanup (round-1 BLOCKING; BRIEF invariant 3). A container whose
    start the proxy approved is tracked from `create`; on session end
    (`init` exit, `hisn kill`, hard revoke) the proxy sends `stop` then
    `remove`. If the daemon is unreachable at session end, the container
    survives the proxy — this is a residual documented in §11, and the
    profile's `risk_ack` for the docker tier covers it.
  - **Container networking is separate from sandbox networking.** A
    container's `NetworkMode` is gated by the proxy (only `none`, `bridge`,
    or a named user network from the profile); it is **not** derived from
    `session.network`. A profile with `session.network = "none"` still allows
    `docker run` containers on `bridge` — the proxy's `[docker] network`
    governs that, and the risk label for `bridge` is `data` (round-1
    BLOCKING). The deploy example below uses `session.network = "host"` so
    compose can reach the daemon socket; the containers themselves run on
    `bridge` (T1 denies `NetworkMode = "host"`).
  - **No arbitrary endpoint opt-ins in 0.3.** The 0.3 allowlist is fixed
    (the list above); there is no profile knob to enable extra endpoints
    (round-1 BLOCKING). `allow_exec` is removed from 0.3 — `docker exec` is
    denied; a 0.4 `allow_exec` would bind exec IDs to approved containers
    and validate privileges. `image_pull` and `image_build` are **independent
    gates** (pull gates `POST /images/create`; build gates `POST /build`);
    the earlier conflation is corrected.
  - **Canonical request parsing and audit.** The proxy parses and
    reconstructs a canonical request (API version prefix, URL decoding, query
    authorization) and rejects ambiguous encodings/framing (round-1
    BLOCKING: parser disagreement between proxy and daemon can smuggle a
    request past the filter). The audit log logs **route templates**, not
    raw URLs; query strings are not logged (they can carry build args).
- **What the proxy does not do in 0.3:** build authorization beyond the
  on/off gate (buildx backends, entitlements, exporters, `--output` transports
  are not modelled — `image_build = "allow"` enables `POST /build` but the
  build's own authority is a 0.4 threat model); `docker exec`; streaming
  endpoints (`events`, `attach`).
- **Endpoint + method allowlist (fixed in 0.3; no profile knob to widen it).**
  Default allow: `/_ping`, `/version`, `/containers/json` (scoped to the
  session's containers), `/containers/create`, `/containers/{id}/start`,
  `/containers/{id}/json`, `/containers/{id}/stop`, `/containers/{id}/logs`,
  `/containers/{id}/wait`, `/containers/{id}/inspect`, `/networks/*` (read),
  `/volumes/*` (read). `POST /containers/create` and `/containers/{id}/start`
  are the only mutating paths allowed; `/containers/{id}/stop` is allowed
  only for containers in the session inventory. Everything else (images,
  build, exec, attach, `system/df`, prune, events) is denied.
  - `Privileged` must be `false` (absent or false).
  - `CapAdd` must be empty.
  - `NetworkMode` must not be `host`, `container:`, or `bridge`-with-host-ports;
    only `none`, `bridge` (the default bridge), or a named user network the
    profile lists.
  - `PidMode` and `IpcMode` must not be `host` or `container:`.
  - `Binds`/`Mounts`: every source must be under the session cwd or under a
    path the profile declares in `[docker] allow_binds`, resolved with
    `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` in the daemon's
    view; a masked path inside cwd is rejected even if the mask is invisible
    to the daemon (round-1 BLOCKING). `VolumesFrom` must be empty; named
    volumes denied (they expose host-managed data). No `docker.sock` mount
    (any socket inode, not just the literal name `docker.sock`).
  - `Devices`: must be empty.
  - `SecurityOpt`: seccomp/apparmor must not be set to `unconfined` or absent
    (i.e. the container must keep a seccomp profile); the default Docker
    seccomp stays.
  - `User` must be set, must not be `0` or `root`, and must be a non-root
    name or a non-zero numeric uid (profile may set a default non-root user).
- **Image policy.** `[docker] image_pull = "allow" | "deny"` (default `deny`):
  `POST /images/create` (`pull`) is allowed only if `image_pull = "allow"`.
  `[docker] image_build = "allow" | "deny"` (default `deny`) is an
  **independent** gate for `POST /build` (round-1 BLOCKING: the earlier text
  conflated the two). `deny` for both means the sandbox can only run images
  already present on the host (no network pull, no build). Build authorization
  beyond the on/off gate (buildx backends, entitlements, exporters, `--output`
  transports) is **not modelled in 0.3** — `image_build = "allow"` enables
  `POST /build` but the build's own authority is a 0.4 threat model.
- **Compose/buildx compatibility.** `docker compose` works through T1 for the
  subset above: it does `containers/create` + `start` + `logs` + `wait`, which
  are all allowed. **What breaks:**
  - `docker compose up --build` (needs `POST /build`) unless
    `image_build = "allow"`.
  - `docker compose run` with `--service-ports` that maps host ports (host
    port binds are denied by the NetworkMode rule).
  - `docker exec` (`POST /containers/{id}/exec` + the `exec/{id}/start`
    websocket) is **denied** in 0.3 (round-1 BLOCKING: the earlier text offered
    `allow_exec = true`; that is removed). It is a shell into a container,
    which bypasses the proxy's creation filter; a 0.4 `allow_exec` would bind
    exec IDs to approved containers and validate privileges.
  - `docker events` (streaming) denied; `docker system df`/`prune` denied.
  - `docker push` is denied (no registry write from inside the sandbox).
  - **BuildKit / buildx `--output` to a host path outside cwd** is denied by
    the bind rule.
- **Request log.** Every request is appended to
  `<session>/docker-proxy.jsonl` (method, **route template** (not raw URL),
  status, duration, container id if any). Never the request body (may
  contain secrets in env); never the response body; **never the query string**
  (it can carry build args). The proxy parses and reconstructs a canonical
  request and rejects ambiguous encodings/framing so a smuggled request
  cannot bypass the filter (round-1 BLOCKING).

**What T1 breaks and why** (precise list for the threat model, §9):

| Docker feature | T1 | reason |
|---|---|---|
| `--privileged` | denied | a privileged container is root on the host |
| `--cap-add` | denied | same |
| `--net=host` | denied | container reaches host network directly |
| `--pid=host` / `--ipc=host` | denied | container sees host processes/IPC |
| `--device` | denied | direct device access |
| mounting `docker.sock` | denied | recursive root-equivalent |
| `docker exec` | denied by default | shell into a container bypasses the proxy |
| `docker build` | denied by default | build can run arbitrary RUN as root in a container |
| `docker push` | denied | writes to a registry from inside the sandbox |
| `docker events` | denied | streaming side channel |
| bind to host path outside cwd | denied | the whole point of the sandbox |

**Why a proxy and not a library:** the proxy is a separate process the
sandbox talks to over a socket. The sandbox never links against Docker
client code; it just opens the socket. The proxy is reusable for other
host-side filtering (ssh agent, §4b).

### T2 `docker = "socket"` — raw forward, root-equivalent (the 0.3 tier)

`[[forward]]` of `/var/run/docker.sock` (or the host's docker socket). The
sandbox can do anything the Docker daemon can: create a privileged container,
mount host paths, start a container that mounts `docker.sock` again. This is
**root-equivalent**. T2 is:

- never the default (DO NOT ALTER #4);
- never silent — `hisn run` prints `RISK: docker=socket is root-equivalent`
  on start, every start, unless `--quiet-risk`;
- only loadable from a profile that contains
  `risk_ack = "root-equivalent"` in its `[docker]` block (or at the top
  level); a profile with `docker = "socket"` and no matching `risk_ack` is a
  **load error** (`E_RISK_ACK_REQUIRED`).

### T3 `nested_userns = true` — rootless podman/buildah inside (0.4, rejected in 0.3)

Allow `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)` inside the sandbox
so rootless `podman`/`buildah` can run **without any host daemon**.

**What changes to make T3 work:**

- **Seccomp:** the `clone` rule currently denies any `CLONE_NEW*` bit
  (`seccomp.rs` `CLONE_NEW_BITS`), and `clone3` returns `ENOSYS`. For T3 the
  `CLONE_NEWUSER` bit (0x10000000) is **removed from the deny mask** and
  `clone3` is **allowed** (or returns `ENOSYS` only when no `CLONE_NEW*` bit
  *other than* `NEWUSER` is set). `unshare(CLONE_NEWUSER)` and
  `unshare(CLONE_NEWNS)` (already denied) — `NEWNS` inside a userns the
  process owns is fine; the rule that blocks it today is the invariant-2
  denylist. For T3, `unshare` is allowed **only for `CLONE_NEWUSER` and
  `CLONE_NEWNS` together** (rootless podman does both at once); `unshare` of
  `CLONE_NEWPID`/`NEWNET`/`NEWIPC`/`NEWUTS` inside the sandbox stays denied
  (a nested container does not need them and they widen the surface).
- **Kernel attack surface:** `CLONE_NEWUSER` is the most-repeatedly-vulnerable
  Linux syscall. Allowing it inside the sandbox means a hostile sandboxed
  process can provoke the kernel's userns code paths (id mapping, capability
  inheritance, the `proc` trick). The sandbox's seccomp denylist is defence in
  depth, not a proof (OPEN-POINTS P10); T3 deliberately re-enables the
  highest-risk path. **Risk label: `kernel-surface`.**
- **Landlock/caps:** the nested userns is a *child* of the sandbox userns U.
  Caps inside it apply only there; the nested root has no authority over U or
  the host. Landlock's domain is inherited (a nested process cannot escape the
  parent's Landlock ruleset), so the filesystem boundary holds. The concern is
  not caps/Landlock — it is the kernel.
- **subuid (D4):** rootless podman needs a `/etc/subuid` range. hisn's sandbox
  has no `/etc/subuid` (it is not in the `/etc` allowlist). T3 would require
  the profile to declare `[rootless] subuid = "<range>"` (e.g.
  `100000:65536`), which hisn synthesizes into the sandbox
  `/etc/subuid`/`/etc/subgid` as a ro stub (same mechanism as the `passwd`
  stub, §8). Whether `podman` can then create a userns for its containers
  inside the nested userns is **not verified in 0.3** (round-1 BLOCKING).
- **Most secure for building images?** T3 *would* be the most secure way to
  *build* images *if* it works: no host daemon, no socket, the build happens
  in a nested userns that the sandbox's Landlock and caps still bound. T1 is
  safer for *running* containers against the host daemon (no userns inside).
  This claim is **conditional on 0.4 evidence** (round-1 BLOCKING: "most
  secure" and "nested rootless works" are not asserted in 0.3).
  **Recommendation: 0.3 ships T2 only; T1 and T3 are designed (ADR 0004) but
  ship in 0.4.** T1 needs a trusted-source mount mechanism and a
  by-construction container lifetime that round 2 showed are not achievable
  by a host-side proxy alone in 0.3 (see "Round 2 BLOCKING" below); T3 needs
  subuid handling, a nested leak run, and a seccomp profile change. The risk
  labels `kernel-surface` (T3) and `root-equivalent` (T2) are defined now so
  profiles can reference them. **0.3 rejects a profile with `nested_userns =
  true` or `docker = "proxy"`** with `E_NOT_SUPPORTED` (round-1/round-2
  BLOCKING: BRIEF invariant 2 expressly prohibits `unshare`, and invariant 3
  requires grants die with the session by construction; a host-side proxy
  cannot make daemon-owned containers die by construction).

### Valon's concrete case

Deploy sessions on `smaragd` that run `docker compose` against the host
daemon. **In 0.3: Tier T2 (`docker = "socket"`)**, with
`risk_ack = "root-equivalent"`, because T1 is deferred to 0.4 (round-2
BLOCKING: T1's bind-source TOCTOU, container-lifetime-by-construction, and
shared-bridge isolation are not achievable by a host-side proxy alone in
0.3). The sandbox can run `docker compose` against the host daemon; the risk
is root-equivalent and is disclosed and acked. In 0.4, when T1 ships, the
recommendation moves to T1.

```toml
[policy]
session.cwd = "."                       # the deploy repo
session.network = "host"                # compose needs to reach the daemon socket
mounts.grantable_rw = ["/srv/out"]      # deploy outputs

[docker]
tier = "socket"
risk_ack = "root-equivalent"
```

`session.network = "host"` is so the sandbox can reach the Docker daemon socket
(compose talks to it over a unix socket). Unix-socket access does not itself
require host networking (round-2 finding: the earlier text justified host
networking for a pathname unix socket, which is incorrect); `session.network =
"none"` would be enough to reach a socket under `/run`, and a 0.4 deploy
profile may use `none`. The current smaragd case uses `host` because the
compose services also need host networking; that is a separate 0.2 capability
with its own risk label (`data`).

**Invariant touched:** 1 (T2 adds the docker socket which is a mount, ro,
of one inode; T1/T3 in 0.4 add no host filesystem inside), 2 (T2 the socket
is host-side; T3 would relax seccomp for `CLONE_NEWUSER` only), 3 (T2: the
**socket** dies with the session; the containers the daemon started do not,
which is why T2 is `root-equivalent` and acked — the sandbox can start
containers that outlive the session; T1 in 0.4 would stop them by
construction), 4 (env unchanged). **OCI:** T2 annotation only; T1 (0.4)
annotation only; T3 (0.4) the seccomp `clone`/`clone3` rules change.

## 4b. SSH / git signing — T0 / T1 / T2 (ADR 0005)

Three tiers, mirroring Docker because the risk shape is the same: "a socket
that can do a powerful thing on the host."

- **T0 `ssh = "host-git"`** (default): no agent inside the sandbox. The
  sandbox has a git identity (`env.set` for `GIT_AUTHOR_*`/`GIT_COMMITTER_*`,
  or a ro `~/.gitconfig` bind) but **no** ssh agent and **no** private keys.
  Commits are made inside; push happens on the host (Wakil runs `git push` on
  the host side, not inside the sandbox). Risk label: `none`.
- **T1 `ssh = "proxy"`** — `hisn-agent-proxy`: a host-side process that speaks
  the ssh-agent protocol and exposes a socket inside. It:
  - allowlists **key fingerprints** (the profile lists
    `[ssh] allow_keys = ["SHA256:…"]`); other keys in the host agent are
    invisible.
  - **is sign-only with filtered identity listing** (round-2 BLOCKING):
    `SSH_AGENTC.SSH_AGENTC_SIGN_REQUEST` is allowed;
    `SSH_AGENTC.SSH_AGENTC_REQUEST_IDENTITIES` (`LIST_IDS`) is **also**
    allowed — but the proxy **filters the reply** to only `allow_keys`
    fingerprints, so non-allowlisted keys are **invisible** (that is how
    invisibility is enforced, not by denying the op outright — a denied
    `LIST_IDS` proves nothing about what keys the agent holds);
    `SSH_AGENTC_ADD_IDENTITY`, `REMOVE_*`, `LOCK`/`UNLOCK` are denied;
    `SSH_AGENTC_EXTENSION` is allowed only for
    `session-bind@openssh.com` and `query` (required for `ssh-add -h`
    constrained keys to sign via the per-session agent). The sandbox cannot
    add or remove keys or lock the agent.
  - **restricts the auth target — but not by parsing the signed blob.** The
    signed blob in the ssh-agent protocol is the SSH protocol's session data,
    not a directly authenticated destination hostname; and git SSH signing
    uses SSHSIG framing, so a sign-only proxy cannot simply inspect an
    underlying commit object (round-1 BLOCKING: the earlier text claimed
    "parse the signed blob to restrict the auth target" and
    "commit_signing_only … detects a git commit/tag object by format" —
    neither is reliably enforceable from the agent protocol). Instead, the
    proxy **restricts which keys** are visible (`allow_keys`) and **logs
    every sign request** (fingerprint, timestamp; never the blob). Host
    restriction, where needed, is enforced by using a **per-session agent
    with destination-constrained keys** (`ssh-add -h`, below) — the
    constraint is enforced by the agent, not the proxy's parser.
    **Constrained keys cannot do `ssh-keygen -Y sign`** (round-2 BLOCKING):
    `ssh-keygen -Y sign -f <key.pub>` **does** use the agent — it resolves the
    public key to a private key in the agent and asks the agent to sign. The
    failure is not "the agent is not called"; it is that a
    destination-constrained key (loaded with `ssh-add -h`) is constrained to
    sign only within a session-bound SSH connection to the declared
    destination, so the agent **refuses to sign** a `git commit -S` SSHSIG
    blob (it is not an SSH connection to the constrained destination). Git
    commit signing via SSHSIG therefore needs a separate **unconstrained**
    key in `allow_keys` for the `SIGN_REQUEST` path, or an unconstrained key
    loaded into the per-session agent without `-h`. A constrained key is for
    ssh login / `git push` over ssh, not for `git commit -S` with an SSH
    signing key.
  - **per-signature audit**: every sign request logs (fingerprint, timestamp)
    to `<session>/ssh-proxy.jsonl`. Never the blob.
  Risk label: `signing`. `risk_ack = "signing"` required.
- **T2 `ssh = "socket"`** — raw `[[forward]]` of the host ssh-agent socket.
  The sandbox can use any key in the agent for anything (ssh login, git push,
    add/remove keys). Risk label: `signing`, `risk_ack = "signing"` required,
    printed at every start. Not the default.

**Per-session agent with destination-constrained keys (`ssh-add -h`):**
OpenSSH **8.9+** `ssh-add -h` loads a key that is constrained to specific
destinations (round-2 BLOCKING: destination constraints exist since OpenSSH
8.9, not 9.6; the ssh client inside the sandbox must be >= 8.9 for the
constraint to be enforced). The profile can ask hisn to `ssh-add -h` a
dedicated key into a fresh per-session agent that the proxy then forwards.
This is the **enforceable** host-restriction mechanism (round-1 BLOCKING: the
constraint is enforced by the agent, not by the proxy parsing the signed
blob). T1 supports it (`[ssh] per_session_agent = true`); the proxy forwards
to the per-session agent, not the host one.

**FIDO `sk-` keys:** a FIDO key (`sk-ssh-ed25519@…`) may require a physical
touch for each signature. The proxy can require `[ssh] require_fido = true`,
which refuses a non-FIDO key. Whether every `sk-` key configuration requires
touch is **not assumed** (round-1 BLOCKING: verify the touch policy per key,
do not assume it). Risk label stays `signing`.

**Recommendation for Wakil:** `ssh = "host-git"` as the default profile
(T0 — commits carry the identity inside, push on the host on review, no
signing inside); `ssh = "proxy"` with `per_session_agent = true` and
`require_fido = true` when an agent is actually needed inside (e.g. an agent
that pulls). Never T2 unless the user explicitly asks.

**Invariant touched:** 1 (T0/T1/T2 add at most a socket inode, ro), 3 (agent
dies with session), 4 (env: the `SSH_AUTH_SOCK` the sandbox sees points at
`expose`, not the host path; set by hisn, not passed from host env). **OCI:**
annotation only.

## 5. Risk disclosure (ADR 0006)

### Decision

Every profile capability that widens the boundary carries a **fixed risk
label** from a closed set:

| label | meaning |
|---|---|
| `none` | no widening; the 0.2 sandbox |
| `data` | the sandbox can read or write host data beyond cwd (a bind, a forwarded data socket) |
| `signing` | the sandbox can produce a cryptographic signature that is valid on the host (ssh agent, git signing) |
| `root-equivalent` | the sandbox can become root on the host (raw docker socket) |
| `host-exec` | the sandbox can run arbitrary commands on the host as the user (a forwarded D-Bus/systemd socket, a shell server, another hisn control socket) — user-equivalent |
| `kernel-surface` | the sandbox can provoke kernel code paths that are out of scope of the 0.2 threat model (nested userns) |

A capability's label is **fixed by the feature**, not chosen by the profile
author: `docker = "socket"` is always `root-equivalent`; `nested_userns = true`
is always `kernel-surface`; a `[[forward]]` of an ssh agent is always
`signing`; a `[[forward]]` of the Docker socket (or a recognised rootless-
podman socket) is always `root-equivalent`; a `[[forward]]` of the D-Bus
system or session bus is always `host-exec`; **a `[[forward]]` of an
unrecognised socket is a load error** (round-2 BLOCKING: hisn cannot know what
protocol an arbitrary inode speaks; a forwarded socket is as powerful as its
server, so an unknown socket is rejected unless the profile sets `risk`
explicitly — minimum `host-exec`, documenting that the author asserts the
server is not root — or matches a known path pattern that hisn recognises).
The author declares the *capability*; hisn computes the *label*; an unknown
socket cannot be labelled `none` or `data` without an explicit
`[forward] risk = "data"` that hisn accepts against a known path pattern.

### Behaviour

- `hisn run` prints the effective risk labels on start, one line each, unless
  `--quiet-risk` is passed. A profile with no widening capabilities prints
  nothing (or `RISK: none` with `--verbose`).
- `hisn profile explain <name>` prints each capability and its label with one
  sentence of explanation.
- A profile with a `root-equivalent`, `signing`, or `host-exec` capability
  **must** contain the matching `risk_ack`:

  ```toml
  [docker]
  tier = "socket"
  risk_ack = "root-equivalent"      # must match the computed label

  [[forward]]
  name = "ssh-agent"
  ...
  risk_ack = "signing"
  ```

  A missing or mismatched `risk_ack` is a **load error**
  (`E_RISK_ACK_REQUIRED` or `E_RISK_ACK_MISMATCH`). This is the "never silent"
  rule for T2/ssh-T2 and the "secure by default" rule for everything else.

- "Secure by default" (DO NOT ALTER #3): a profile with no `[[services]]`,
  no `[[host_services]]`, no `[[forward]]`, no `[docker]`, no `[ssh]`, no
  `nested_userns`, and the inner `[policy]` at its defaults yields **exactly
  the 0.2 sandbox** — same mount plan, same seccomp, same Landlock, same env.
  The profile layer is a strict superset of capabilities, never a relaxation.

**Invariant touched:** 5 (the labels are carried as annotations
`org.hisn.risk=[…]`); the isolation invariants are unchanged by the labels
themselves. **OCI:** annotation only.

## 6. Recipes (ADR 0007)

Each recipe is a profile shipped in `profiles/` with a matching leak test
(continuing from L24) that proves the recipe exposes only what it says.

| recipe | file | risk label | leak test | ships |
|---|---|---|---|---|
| git identity (env.set) | `profiles/git-identity.toml` | `none` | L25 | 0.3 |
| git identity (~/.gitconfig ro) | `profiles/git-config.toml` | `none` | L26 | 0.3 |
| ssh agent forward (T1) | `profiles/ssh-proxy.toml` | `signing` | L27 | 0.3 |
| docker T2 | `profiles/docker-socket.toml` | `root-equivalent` | L29 | 0.3 |
| docker T1 | `profiles/docker-proxy.toml` | `data`/`none` | L28 | 0.4 |
| toolchains under $HOME (rustup/nvm/mise in persistent home) | `profiles/toolchains.toml` | `none` | L30 | 0.3 |
| kvr service | `profiles/kvr.toml` | `none` | L31 | 0.3 |
| Wakil | `profiles/wakil.toml` | `none` (T0) | L32 | 0.3 |

Each leak test asserts: (a) the recipe's declared exposure works (the agent
can talk to the socket / the service is up / the toolchain is on `PATH`),
and (b) the recipe does **not** expose anything else (no host paths beyond
the declared binds, no other sockets, no extra mounts in `inspect`).

- **L25** (git-identity): `git config user.name` inside the sandbox equals
  the `env.set` value; `git push` to a real remote fails (no agent); the
  host's `~/.gitconfig` is absent.
- **L26** (git-config): `~/.gitconfig` is readable; `touch ~/.gitconfig`
  → `EROFS`; `~/.ssh` is absent.
- **L27** (ssh-proxy): a sign request with an allowlisted key succeeds; a
  sign request with a non-allowlisted key is denied;
  `SSH_AGENTC.LIST_IDS` is allowed but the reply is **filtered** to
  `allow_keys` (a non-allowlisted key is invisible, not just "op denied");
  `ADD_IDENTITY`/`REMOVE_*`/`LOCK`/`UNLOCK` are denied;
  `EXTENSION` is allowed only for `session-bind@openssh.com` and `query`,
  denied for others (round-2 BLOCKING). The test **must drive a real ssh
  client against a real sshd** (not only raw agent messages): `ssh
  user@localhost true` with an allowlisted key succeeds; the same with a
  non-allowlisted key fails with `Permission denied (publickey)`;
  `ssh-add -l` inside the sandbox shows only `allow_keys` (round-2
  BLOCKING: raw agent messages do not prove the ssh client path works).
- **L28** (docker-proxy): `docker run --privileged hello-world` is denied by
  the proxy (403); `docker run hello-world` (unprivileged, image present)
  succeeds; `docker exec` is denied; `docker pull` is denied (default
  `image_pull = "deny"`); the session `inspect` shows only the proxy socket.
  **Adversarial cases (round-1 BLOCKING):** a foreign container seeded with a
  secret canary (including a stopped container with prohibited mounts) —
  `/containers/json` must not list it, `/containers/{id}/start|inspect|logs`
  must be denied; a `docker run -v $PWD/x:/host` where `$PWD/x` is a symlink
  to `/` must be denied (bind-source symlink check); a masked path inside
  cwd (`<cwd>/.secrets`) used as a bind source must be denied even though
  the mask is invisible to the daemon; after session end, the container the
  proxy created is stopped (not just the proxy process).
- **L29** (docker-socket): `docker run --privileged` succeeds *and* `hisn run`
  printed `RISK: docker=socket is root-equivalent`; the profile has the
  matching `risk_ack`; the test then cleans up the container.
- **L30** (toolchains): `rustc --version` inside the sandbox is the rustup
  one; `which cargo` is under the persistent home; the home is a ro bind
  (attempted write to the home root → `EROFS`).
- **L31** (kvr): the service socket is connectable from a second exec; the
  service dies with the session; `inspect` shows the service socket and
  nothing else.
- **L32** (wakil): the Wakil profile (T0 ssh, no docker, no forward,
  `session.shm = true` for `tests/leak`) yields `RISK: none`; `hisn profile
  explain wakil` lists no widening capabilities; `inspect` equals the 0.2
  plan plus `/dev/shm`.

**Invariant touched:** the recipes are the proof that "secure by accident"
holds — each one either widens the boundary in a declared, labelled way or
not at all. **OCI:** the profiles are annotation-only; the inner policies map.

## 7. Multi-agent (ADR 0008)

### Decision

0.3 ships the **discovery** half of multi-agent; the **lease** half moves to
0.4.

**In 0.3:**

- `hisn attach --session <id|name>` — a second client (a second Wakil, a
  shell) attaches to a running session. Attaching means: the new client can
  `exec`, `grant`, `revoke`, `inspect`, `kill` through the same control
  socket, **with the same uid check as today**. There is no per-client
  identity in 0.3 — any same-uid process can attach (R5 still refuses the
  sandbox's own processes). This is the 0.2 behaviour, just named and
  documented.
- **Session discovery by name/cwd:** `hisn ls --json` gains `cwd` (the
  resolved session cwd) and `name` (a new `--name` flag on `run`, stored in
  the session dir). `hisn attach --name foo` and `hisn attach --cwd
  /path/to/repo` resolve to a session by name or by cwd match. If `--name`
  matches multiple sessions, `attach` errors (`E_AMBIGUOUS`) rather than
  picking one. This lets a second agent find "the session already running in
  this repo" without guessing the session id.

**In 0.4 (deferred):**

- **Leases:** a client takes a lease on a session (exclusive or shared) so
  that `hisn kill` by one client does not tear down a session another client
  is using. Leases need per-client identity, which needs a client token
  (passed by Wakil) and a control-socket auth step that is not just uid.
- **Per-client grant/signal policy:** client A can grant but not kill; client
  B can exec but not grant. Needs the same per-client identity.
- **`hisn request <path>` from inside the sandbox** (surfaced to the host for
  approval) — interacts with per-client identity and the risk labels; deferred
  to 0.4 with the lease work (§11).

### Why split

Discovery is cheap (name/cwd in the session dir; `attach` is a documented
alias for the existing socket path resolution). Leases need identity and auth,
which is a control-protocol change and its own review. 0.3 can ship discovery
without touching the control protocol; 0.4 does the protocol.

**Invariant touched:** 3 (grants still die with the session — attach does not
extend them), 2 (the control socket is unchanged; R5 still refuses the
sandbox). **OCI:** annotation only (`org.hisn.session.name=…`).

## 8. 0.2.1 patch list (prerequisites)

These ship first, on top of 0.2.0, with no new 0.3 surface. Each is small and
independently useful. They are folded into 0.3 as prerequisites because the
profiles and services in 0.3 rely on them.

| # | patch | what | leak test |
|---|---|---|---|
| 1 | `/dev/shm` tmpfs | mount `/dev/shm` (tmpfs, `size=…`, `mode=1777`) inside `/dev`; `session.shm = true` to enable, default off (some programs need it; default off keeps the 0.2 `/dev`) | L33 |
| 2 | `/tmp` size configurable | `session.tmp_size = <MiB>` (default 1024); `mounts.rs` `TMP_SIZE` becomes a policy value | — (L8 covers it) |
| 3 | passwd stub with host username | `mounts.rs::passwd_stub` already uses `HostFacts.username`; ensure `/etc/passwd` and `/etc/group` in the sandbox have the real username (`getids()` already reads `USER`) | — (L1 covers it) |
| 4 | init argv scrub | init's `argv[0]` is overwritten in memory to something opaque (not the session id leak); `PR_SET_NAME` alone does **not** change `/proc/1/cmdline` (it sets the process title only), so the `argv` memory itself must be overwritten. The session id is not in argv | L34 |
| 5 | stale-dir cleanup on kill/run | `session::ensure_root` and `supervisor` cleanup: on `run`/`kill`, remove session dirs that are not live (`is_live` already exists); bounded | — |
| 6 | R5 ancestry retry | `supervisor::authorize_peer` retries the `/proc/<pid>/status` read on `ENOENT`/`ESRCH`/`EINTR`/`ETXTBSY` on any ancestor during the walk (the observed failure is `ENOENT`/`ESRCH` when an ancestor vanishes mid-walk); bounded (3×, 50 ms); refuse only if the peer itself is gone or the chain cannot be established after retries | — (P16 covers it) |
| 7 | `--ready-fd` | `hisn run --ready-fd <fd>`: after the sandbox is ready, write one byte to the fd before returning; for programmatic readiness (Wakil) | — |
| 8 | opaque exec ids for `signal` | the `pid` returned by `exec` and accepted by `signal` is already the in-sandbox pid; 0.2.1 adds an opaque `exec_id` (monotonic per session) and `signal` accepts it too, so a recycled pid cannot be signalled by a stale client | L35 |
| 9 | `hisn ls/inspect --json` schema frozen | the `--json` output gets a `schema` version field (`"hisn-ls/v1"`, `"hisn-inspect/v1"`); fields are documented and additive; 0.3 services add to it | — |

## 9. Threat model delta

For each feature: what a hostile sandboxed process **gains**, what it **still
cannot** do, which invariant it touches, and the leak tests (L25+) that are
the acceptance criterion.

| feature | gains | still cannot | invariant | leak test |
|---|---|---|---|---|
| profiles (§1) | nothing (envelope) | — (same inner policy) | 5 | L32 (wakil profile == 0.2 plan) |
| in-sandbox service (§2) | a sibling process; whatever its socket protocol allows | escape the sandbox (same seccomp/Landlock/caps); outlive the session | 1, 2, 3 | L31 |
| host_service / forward (§3) | talk to one host socket at `expose` | unlink/re-bind the socket; see the host path; see other host sockets; start anything on the host (forward) / start only the declared process (host_service) | 1, 2, 3 | L36 (forward), L37 (host_service) |
| docker T1 (§4, 0.4) | create unprivileged containers under cwd; run images present on host | create privileged/cap-adding/host-net/pid-host containers; mount docker.sock; exec into containers; build; push; reach host paths outside `allow_binds` | 1, 2, 3 | L28 (0.4) |
| docker T2 (§4) | root on the host (the docker daemon) | — (it is root-equivalent by design) | 1, 3 | L29 |
| docker T3 (§4, 0.4) | provoke the kernel's userns code paths | escape the sandbox's Landlock/caps (nested userns is a child); reach host paths not granted | 2 (seccomp change) | L38 (0.4) |
| ssh T0 (§4b) | a git identity (name/email) | sign anything; push from inside | 4 | L25/L26 |
| ssh T1 (§4b) | produce signatures with allowlisted keys | use non-allowlisted keys (invisible in filtered `LIST_IDS`); add/remove keys; lock the agent | 1, 3, 4 | L27 |
| ssh T2 (§4b) | use any host agent key for anything | — (root-equivalent for the agent) | 1, 3 | — (covered by L29's ack check) |
| risk labels (§5) | nothing (display) | — | 5 | — (no leak test; load error is unit-tested) |
| recipes (§6) | per recipe | per recipe | per recipe | L25–L32 |
| multi-agent discovery (§7) | a second same-uid client can attach | a sandbox process attach (R5); per-client grant/signal policy (0.4) | 2, 3 | L39 |

### New leak tests (continuing from L24)

- **L25–L32**: the recipe leak tests (§6).
- **L33**: `/dev/shm` present when `session.shm = true`, absent by default.
- **L34**: init's `argv` does not contain the session id (read `/proc/1/cmdline`).
- **L35**: `signal` with a stale/recycled `exec_id` → `E_NOT_FOUND`; a live
  `exec_id` works.
- **L36** (forward): the sandbox can `connect` to `expose` (must succeed —
  ro mounts do not block socket inodes); `unlink expose` → `EROFS` or
  `EBUSY` (the mount is ro); `ls /run/user` → absent; the host path is not
  resolvable.
- **L37** (host_service): the service starts, its socket is at `expose`; on
  session end the host process is gone (`kill -0` fails) and the socket is
  gone.
- **L38** (T3, 0.4): `unshare -U` inside succeeds; `unshare -Urn` (NEWPID+NET)
  fails; a nested rootless `podman` container is bounded by the sandbox
  Landlock (cannot write outside the granted paths).
- **L39** (attach): a second client attaches by name/cwd; a sandbox process
  is still refused (R5); the attached client's `grant` is visible to the
  first; `kill` by one does not leave the other's fds live in the sandbox
  (hard revoke semantics).

### OCI mapping for new constructs (invariant 5)

| construct | OCI `config.json` |
|---|---|
| profile envelope (`version = "hisn-profile/v1"`) | annotation `org.hisn.profile.version=…` |
| `[[services]]` | annotation `org.hisn.services=[{name,socket,exec}]` (no mount; the service runs in the same namespaces) |
| `[[forward]]` / `[[host_services]]` | annotation `org.hisn.forward=[{name,expose,risk}]` (the mount is a bind of one inode → `mounts[]` `{destination=expose, type:"bind", options:["ro","nosuid","nodev"]}` if emitted in v2; in 0.3 annotation only) |
| `[docker] tier` | annotation `org.hisn.docker.tier=…` (T2 socket forward → `mounts[]` bind; T3 → `linux.seccomp` clone rule change) |
| `[ssh] tier` | annotation `org.hisn.ssh.tier=…` |
| `[risk]` / `risk_ack` | annotation `org.hisn.risk=[…]` |
| `nested_userns = true` | `linux.seccomp` `clone3` rule: `CLONE_NEWUSER` (0x10000000) removed from the `SCMP_CMP_MASKED_EQ` mask; `clone` same; `unshare` arg0 masked for `CLONE_NEWUSER|CLONE_NEWNS` |
| `session.shm = true` | `mounts[]` tmpfs at `/dev/shm` |
| `session.tmp_size` | `mounts[]` tmpfs `size=…` |
| `--name` / attach | annotation `org.hisn.session.name=…` |
| `exec_id` | annotation `org.hisn.exec.id=…` (no OCI equivalent; control-protocol only) |

## 10. Sequencing and estimates

Dependency graph (edges = "needs first"):

```
0.2.1 patches (§8)
 ├─ shm, tmp_size, passwd, argv scrub, stale-dir, R5 retry, ready-fd, exec_id, --json schema
 └─> 0.3a:
      ├─ profiles (§1)        [needs --json schema frozen, needs ready-fd for services]
      ├─ risk labels (§5)     [needs profiles]
      ├─ forward / host_services (§3) [needs profiles]
      │    └─> docker T2 (§4)          [needs forward + risk labels]
      ├─ in-sandbox services (§2)   [needs profiles + ready-fd]
      ├─ multi-agent discovery (§7) [needs profiles + --name; cheap, ships in 0.3a]
      └─> 0.3b:
           ├─ ssh T1 (§4b)            [needs host_services; new crate; own review cycle after B1]
           ├─ recipes (§6)            [needs everything above, incl. ssh T1]
           │    └─> threat model / leak tests (§9) [needs recipes]
docker T1 (§4)  ──> 0.4 (new crate, trusted-source mount, by-construction lifetime)
docker T3 (§4)  ──> 0.4 (seccomp change, subuid, nested leak run)
leases / per-client (§7) ──> 0.4
```

### Order and estimates (single maintainer, Wakil-built; in sessions)

**0.3a** (ships first — the core boundary, the deploy case, and cheap
discovery):

| step | what | est. | ships |
|---|---|---|---|
| 1 | 0.2.1 patches (§8, all nine) | 2 sessions | 0.2.1 |
| 2 | profiles (§1): envelope, `--profile`, search path, `profile explain`, `profile list` | 1.5 | 0.3a |
| 3 | risk labels (§5): label table, `--quiet-risk`, `risk_ack` enforcement, `host-exec` | 1 | 0.3a |
| 4 | forward / host_services (§3): `open_tree` socket forward, lifecycle, `host-exec` risk_ack, L36/L37 | 2 | 0.3a |
| 5 | in-sandbox services (§2): exec-chain start, readiness, stop, `ls --json`, L31 | 2 | 0.3a |
| 6 | docker T2 (§4): raw forward + risk_ack check, L29 | 0.5 | 0.3a |
| 8 | multi-agent discovery (§7): `--name`, `attach`, cwd lookup, L39 | 1.5 | 0.3a |
| | **0.3a total** | **~10.5 sessions** | |

**0.3b** (ships second — ~~ssh T1 gets its own review cycle after B1, then
recipes and the threat-model proof layer~~ — **moved to 0.3.2**: ssh T1
shipped in 0.3.2 as the filtering agent proxy, ADR 0011, leak test L45):

| step | what | est. | ships |
|---|---|---|---|
| 7 | ~~ssh T1 (§4b)~~ — **shipped in 0.3.2** (ADR 0011, `src/ssh_agent.rs`, leak L45) | — | 0.3.2 |
| 9 | recipes (§6): profiles + L25/L26/L30/L32 | 2 | 0.3b |
| 10 | threat model leak tests (§9): L33–L37 | 2 | 0.3b |
| | **0.3b total** | **~4 sessions** | |
| | **0.3 total** | **~17.5 sessions** | |

| step | what | est. | ships |
|---|---|---|---|
| 11 | docker T1 (§4): `hisn-docker-proxy` crate, per-session inventory, bind-source mechanism, container lifetime, L28 | 6 | 0.4 |
| 12 | docker T3 (§4) + subuid + nested leak L38 | 4 | 0.4 |
| 13 | leases + per-client identity (§7) + `hisn request` (§11) | 5 | 0.4 |
| 14 | `network = "proxy"` egress (§11) | 3 | 0.4 |

**T1 is the largest 0.4 item** (6 sessions) because round 2 showed it needs a
trusted-source mount mechanism (to close the TOCTOU between proxy validation
and daemon resolution), a by-construction container lifetime (not a
stop/remove RPC), shared-bridge isolation, and a build authority model — none
of which a host-side proxy alone closes in 0.3. T3 (4 sessions) needs subuid
handling and a nested leak run. The two are ordered T1-first because the
deploy case (smaragd) wants T1.

### 0.2.1 subset (ships immediately)

Patches 1–9 from §8: `/dev/shm`, `/tmp` size, passwd username, argv scrub,
stale-dir cleanup, R5 retry, `--ready-fd`, opaque exec ids, `--json` schema.
These are the prerequisites that do not depend on any 0.3 feature and can
land on 0.2.0 first. Estimated 2 sessions; no new surface, no leak-test
additions beyond L33/L34/L35 (which can ship with 0.2.1 or 0.3).

## 11. Open points

Non-blocking findings from the Mashūra rounds and items explicitly scoped to
0.4 or deferred. Blocking findings are folded into §1–§9; they are not
repeated here.

### External review — COMPLETED (2026-11-02)

An external review of the full `docs/PLAN-0.3.md` was completed outside Wakil
on 2026-11-02. Three BLOCKING findings (B1–B3) were folded into §4b/§5/§8
and the ADRs above:

- **B1** (§4b/ADR 0005): SSH T1 must allow `REQUEST_IDENTITIES` and filter the
  reply to `allow_keys`; deny `ADD`/`REMOVE`/`LOCK`/`UNLOCK`; allow `EXTENSION`
  only for `session-bind@openssh.com` and `query`; constrained keys cannot do
  `ssh-keygen -Y sign`; destination constraints since OpenSSH 8.9 (not 9.6);
  L27 must drive a real ssh client against a real sshd. → folded into §4b and
  ADR 0005.
- **B2** (§5/ADR 0006): an unrecognised `[[forward]]` socket is a **load
  error**, not a default `host-exec`; the profile must set `risk` explicitly
  (minimum `host-exec`, documenting that the author asserts the server is not
  root). → folded into §5 and ADR 0006.
- **B3** (§8 patch 6): R5 retry must cover `ENOENT`/`ESRCH` on any ancestor
  during the walk (the observed failure), bounded 3×/50 ms; refuse only if the
  peer itself is gone or the chain cannot be established after retries. →
  folded into §8 patch 6.

Non-blocking findings from the external review (recorded here, applied to
the relevant sections):

- Patch 4 (`init argv scrub`): must overwrite argv memory;
  `PR_SET_NAME` does not change `/proc/1/cmdline` (L34 reads `cmdline`).
  Folded into §8 patch 4.
- L36: `EBUSY`/`EROFS` applies to `unlink <expose>` (the ro mount blocks
  unlink/rename, not `connect`); `connect` on the forwarded socket must
  succeed. Folded into L36 and §3.
- L30: drop the `$CARGO_HOME/..` assertion (`/run` is writable, so the
  parent-of-home EROFS test is not a valid assertion). Folded into L30.
- `attach --name` ambiguous match → `E_AMBIGUOUS` error. Folded into §7.
- Wakil profile sets `session.shm = true`. Folded into L32.
- §10: split into 0.3a (steps 1–6 and 8 — core boundary, deploy case, cheap
  discovery; ~10.5 sessions) and 0.3b (steps 7, 9, 10 — ssh T1 gets its own
  review cycle after B1, then recipes and the threat-model proof layer; ~7
  sessions); 0.3a ships first. Folded into §10.

### Scoped to 0.4 (with reason)

- **Docker T1 (`docker = "proxy"`)** — designed in ADR 0004, ships in 0.4.
  Round 2 of the Mashūra review found that T1's security boundary has gaps a
  host-side proxy alone cannot close in 0.3: bind-source TOCTOU (the proxy
  validates a path but the daemon resolves the string it receives), container
  lifetime (a stop/remove RPC is cleanup, not construction — invariant 3),
  shared-bridge lateral movement (the inventory stops direct API requests
  but not cross-container reachability through a shared `bridge`), and build
  authority (`POST /build` is enabled by a gate with no build-threat-model).
  T1 needs a trusted-source mount mechanism, a by-construction container
  lifetime, shared-network isolation, and a build authority model — all 0.4.
  The deploy case (smaragd) uses T2 in 0.3; the recommendation moves to T1
  in 0.4.
- **Docker T3 (`nested_userns`)** — designed in ADR 0004, ships in 0.4. Needs
  a seccomp profile change (re-enable `CLONE_NEWUSER`), subuid handling, and a
  nested leak run; the kernel-surface risk deserves its own review round.
- **Leases and per-client identity (§7)** — 0.4. Needs a control-protocol
  change (client token, auth step) and per-client grant/signal policy. 0.3
  ships discovery only.
- **`network = "proxy"`** — egress allowlist proxy with per-session log. 0.4.
  Reason: it is a second proxy (like the docker one) and the 0.3 scope is
  already large; `network = "host"` covers the deploy case today. Designing
  it now so the docker-proxy crate is reusable.
- **`hisn request <path>`** — agent-initiated grant surfaced to the host for
  approval. 0.4, with leases (it needs per-client identity to attribute the
  request).
- **`hisn diff --session`** — what the session wrote under cwd (snapshot or
  fanotify). 0.4. Reason: it is a review/audit feature, not a boundary one;
  0.3 establishes the audit stream it would feed.
- **`[rootfs]` overlay on the toolchain** — lower = host or a dir, upper =
  per-project; root-in-sandbox via subuid. First need: zig 0.15.2 on a 0.16
  host. 0.4. **Recommendation:** prefer the "mise/rustup in the persistent
  home" recipe (§6, L30) for the zig case in 0.3 — it is cheaper (one bind of
  a directory hisn already supports) and does not need subuid. The overlay is
  the right answer when a whole toolchain must be overlaid (e.g. glibc
  version); defer to 0.4 with the subuid work.

### Deferred (with reason)

- **cgroup v2 per session** — `pids.max`, `memory.max`, `cpu.weight`. 0.4.
  Reason: rlimit `nproc` is held at 4096 today and the pressure is
  memory-driven, not fork-driven; cgroups are a resource feature, not a
  boundary one. Designing it so the session dir lives under a delegated
  cgroup subtree (systemd user slice); falls back to rlimits with a warning
  (same shape as the roadmap v1 item).
- **seccomp allowlist profile** — audit mode that logs syscalls per session,
  then a generated allowlist; keep the denylist as fallback. 0.4. Reason: it
  is a hardening layer on top of the denylist; the denylist stays the 0.3
  default. Needs a log format and a generation step.
- **P18: Landlock write roots inode-anchored** — fds captured before pivot.
  0.4. Reason: it fixes the pathname-resolved root weakness in exec
  (`DESIGN §14.12`); it is a correctness fix, not a 0.3 feature, and it needs
  the supervisor to hold root fds across the pivot.
- **spawn-gate starvation** — "no new spawns" flag before hard revoke takes
  the exclusive lock. 0.4 (OPEN-POINTS item 3). Reason: it is a fairness fix
  for the spawn gate; 0.3 does not change the gate.
- **audit event stream** — freeze `grants.jsonl` + exec + service events as a
  documented, versioned format so ilm-stack can ingest it. 0.4. Reason: the
  events already exist; the work is format-freezing and a consumer, not a
  boundary change. The docker/ssh proxies already write per-session jsonl.
- **MCP server and E2B-shaped HTTP API (roadmap v1)** — confirm they wrap the
  exec/grant/attach ops and do not reimplement them. 0.4, as the v1 work.
  Reason: 0.3 establishes `attach` and the services that the MCP tools would
  expose; the HTTP/MCP layer is a separate transport and its own review. The
  rule is set now: `exec`/`grant`/`revoke`/`attach` are the control-socket
  ops; the MCP server and HTTP API are thin wrappers over them, not
  re-implementations. Version: the v1 HTTP API wraps the v0 control socket;
  the MCP server wraps the v0.2 `exec` op. Both target 0.3's control socket
  (which adds `attach` and `services`).
- **static musl build (P22), aarch64 leak run, L12 skip, R5 weak** — status:
  P22 (musl ioctl `c_int` cast) is a 0.2.1 candidate; the aarch64 leak run and
  L12 (the `/etc/hisn-test.key` after-start test, currently skipped on CI
  because the host fixture is missing) are host-verification gaps, not 0.3
  features. R5 (P16) has unit coverage only and is accepted for 0.3; a
  full end-to-end R5 test needs a fixture that does not exist (OPEN-POINTS
  P16). 0.3 does not change any of these; they stay as OPEN-POINTS.
- **browser inside a hisn session** — Wakil rejects `browser_enabled` today.
  A GUI-capable profile would need: a Wayland (or X11) socket forward
  (`[[forward]]` of `$XDG_RUNTIME_DIR/wayland-0`, or the X11 socket), `/dev/shm`
  (§8 patch 1), and dri (a `--device` grant, which the sandbox does not
  support today). **Recommendation: defer to 0.4 and keep browsers on Docker
  for now.** Reason: a GUI socket forward is a `[[forward]]` with risk `data`
  (the compositor sees the sandbox's windows), but dri device access is a
  new capability (`[devices]`) that the 0.2 sandbox explicitly does not
  have (`/dev` is a fixed tmpfs). Designing `[devices]` is its own ADR and
  not in 0.3. The `[[forward]]` mechanism (§3) is ready for Wayland; the
  device access is not.

### From Mashūra round 1 (folded)

Round 1 ran with the plan truncated at §7 (both reviewers' copies ended at
the context-window boundary, as in every prior round on this project). The
reviewers could not quote §9; the findings below are from §1–§5 and the ADRs
that were visible. Blocking findings (1–11) are folded into §1–§5 above; the
non-blocking corrections are:

- **L25** should not conflate author env vars (`GIT_AUTHOR_*`) with `git
  config` values; "missing an agent" does not prove all push transports
  fail (a credential helper in `~/.gitconfig` could still push). L25 asserts
  the env values and the absence of `~/.gitconfig`; push-transport
  completeness is a 0.4 concern.
- **L28 success case** needs an explicit non-root `User` consistent with
  the policy (folded into the creation filter: `User` must be set and not
  `0`/`root`).
- **§2 vs §3 bind(2):** clarified — `bind(2)` the socket syscall is not
  denied; `mount`/`umount` is. The sandbox can create its own unix sockets;
  it cannot move the forwarded inode (folded into §2 and §3).
- **Invariant references:** BRIEF #3 is grant lifetime, #4 is env scrubbing;
  the plan's invariant attributions are corrected (folded into the
  per-feature invariant lines).
- **T3 "most secure" claim** removed; T3 is rejected in 0.3 and the claim is
  deferred to 0.4 with evidence (folded into §4).
- **Parser/audit** — the proxy must parse and reconstruct a canonical
  request and reject ambiguous encodings (folded into §4 as a blocking
  finding; the audit log logs route templates, not raw URLs, and never query
  strings).
- **Profile provenance** — a profile resolved from under the session cwd
  cannot satisfy `risk_ack`; `./<name>.toml` is removed from the search
  path (folded into §1).
- **`[[forward]]` label not computable** — `host-exec` label added; unknown
  sockets default to it with `risk_ack` (folded into §5).

### Round 1 BLOCKING findings (summary, all folded into §1–§5)

1. T1 must track a per-session container inventory; reject foreign
   containers/volumes/networks/exec IDs; scope `/containers/json`. (§4)
2. Bind-source containment must be symlink- and mask-aware (`openat2`,
   daemon's view); `VolumesFrom`/named volumes denied. (§4)
3. Creation filter must be a closed schema; `User` not `0`/`root`;
   `VolumesFrom` denied; boundary is container authority not "no shell". (§4)
4. Daemon containers must be stopped on session end by construction
   (invariant 3); not by best-effort cleanup. (§4)
5. No arbitrary endpoint opt-ins in 0.3; `allow_exec` removed; build not
   modelled beyond on/off; `image_pull`/`image_build` are independent gates. (§4)
6. Proxy must parse canonical requests; reject ambiguous encodings; audit
   logs route templates not raw URLs; query strings not logged. (§4)
7. `[[forward]]` of unknown sockets defaults to `host-exec` with
   `risk_ack`; labels for known paths (docker, ssh, D-Bus) are fixed. (§5)
8. Profile search path: `./<name>.toml` removed; cwd-resident profile cannot
   satisfy `risk_ack`. (§1)
9. SSH T1: blob-parsing and `commit_signing_only` format-detection claims
   removed; host restriction is `ssh-add -h` (per-session agent); FIDO touch
   not assumed. (§4b)
10. T3 rejected in 0.3 (`E_NOT_SUPPORTED`); invariant 2 prohibits `unshare`;
    "most secure"/"nested rootless works" claims removed. (§4)
11. Deploy example: `session.network = "host"` is for the daemon socket,
    not for container NetworkMode; container networking ≠ sandbox networking. (§4)

### From Mashūra round 2 (folded)

Round 2 ran with the plan truncated at §4b (both reviewers' copies ended at
the context-window boundary). The reviewers could not quote §9. The
answering reviewer found **8 remaining blockers** that showed T1's security
boundary has gaps a host-side proxy alone cannot close in 0.3:

### Round 2 BLOCKING findings (all folded into §4)

1. **Bind-source TOCTOU** — `openat2` validation does not bind the daemon's
   later mount: the proxy resolves a path, but the daemon resolves the string
   it receives; a writable path component can be replaced between validation
   and daemon mount. A host-side proxy cannot close this without a
   daemon-consumable immutable source reference (which Docker does not
   provide). → T1 deferred to 0.4.
2. **Directory bind bypasses masks and socket prohibition** — binding cwd
   exposes `cwd/.secrets` even if directly binding the child is forbidden;
   binding an allowed directory containing a daemon socket exposes the socket
   without submitting a socket inode as source; a socket can appear after
   validation in a live writable directory. The per-inode check is
   insufficient for directory binds. → T1 deferred to 0.4.
3. **Container lifetime is cleanup, not construction** — a stop/remove RPC
   sequence is not a structural lifetime bound (invariant 3); the plan
   acknowledged "if the daemon is unreachable, the container survives" which
   contradicts "by construction". A host-side proxy cannot make
   daemon-owned containers die by construction. → T1 deferred to 0.4.
4. **Inventory stops API selection, not lateral movement** — two sessions
   sharing a daemon (and a `bridge`) can reach each other's containers
   through shared networking; the inventory stops direct API requests but not
   cross-container reachability. Shared networks need explicit isolation
   design. → T1 deferred to 0.4.
5. **Non-root not established by `User` check** — an image-defined username
   other than `root` can resolve to UID 0; `CapAdd` empty ≠ no default caps;
   `HostConfig` alone does not cover top-level creation fields,
   `NetworkingConfig`, or image config. The closed schema was not enumerated.
   → T1 deferred to 0.4.
6. **Build enabled before its authority is modelled** — `image_build =
   "allow"` enables `POST /build` but the build's own authority (backends,
   sessions, outputs, cache) is a 0.4 threat model; the bind-rule claim for
   `--output` has no enforcement mechanism behind a container-create filter.
   → build denied in 0.3 (T1 deferred).
7. **`host-exec` is not conservative for unknown sockets** — a pathname
   pattern does not authenticate a protocol; a renamed Docker socket under an
   arbitrary filename is still root. Unknown direct forwards need
   root-equivalent disclosure or rejection. → folded into §5: unknown sockets
   default to `host-exec` with `risk_ack`; ADR 0006 notes that a pathname
   pattern is not authentication and lower labels require trusted provenance.
8. **`[[host_services]]` is host execution before socket access** — a
   profile's arbitrary host-side `exec` is user-equivalent execution; a
   trusted profile that launches a cwd-controlled executable or interpreter
   script can turn sandbox-writable content into host code. `risk_ack` for
   host execution is required independently of the socket protocol. → folded
   into §3/§5: `[[host_services]]` requires `risk_ack = "host-exec"` for the
   execution itself, independently of the socket label.

**Consequence for the plan:** T1 and T3 are both **rejected in 0.3**
(`E_NOT_SUPPORTED`) and ship in 0.4. **0.3 ships T2 only** for docker access.
The deploy case (smaragd) uses T2 with `risk_ack = "root-equivalent"` in
0.3; the recommendation moves to T1 in 0.4. The `[[host_services]]` risk
ack requirement and the `host-exec` label for unknown sockets are folded
into §3 and §5.

**Risk-label consistency fix:** ADR 0006 labelled T1 `none` (the proxy is
the boundary) which is only true if the proxy actually closes the boundary;
round 2 showed it does not in 0.3. ADR 0006 is corrected: T1 is `none` only
in 0.4 (when the proxy is the boundary); in 0.3 T1 is not available. The
docker tier's `risk_ack` in 0.3 covers the T2 root-equivalent case only.
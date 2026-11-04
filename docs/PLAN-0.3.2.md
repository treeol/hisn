# hisn 0.3.2 — Docker-workflow parity: persistent home, read-only rootfs, SSH agent T1

Status: planning. Baseline: `009a5bd` (v0.3.1). No source changes in this document;
it is the plan for the implementation phase. Binding input: the user's 0.3.2
brief (context block in the session). Every feature ships with a risk label and
at least one leak test registered in the host leak run. Existing leak tests are
not weakened or renumbered. No git tag, no release.

## What 0.3.2 adds

Three features that give hisn what the user had in his Docker-based Wakil
workflow, without inventing second mechanisms:

1. **Persistent $HOME** — caches survive sessions (Phase 1)
2. **Read-only rootfs per session** — toolchain no longer depends on the host (Phase 2)
3. **SSH agent T1** — git over ssh, ssh commit signing, via a filtering agent proxy (Phase 3)

Plus: musl release build in CI, version bump to 0.3.2.

## Backward compatibility

Profiles without the new keys behave identically to 0.3.1 — tmpfs home, host
system dirs, no SSH. The `Profile` struct gains three new optional fields
(`home`, `rootfs`, `ssh`), each `#[serde(default)]`; `deny_unknown_fields` on
the `Profile` struct requires them to be declared. The inner `Policy` is
unchanged; the new keys are resolved at the profile level and feed into the
existing resolution path.

## Phase 1 — Persistent $HOME

### Config key

```toml
[home]
persist = "/home/user/.cache/wakil/home/proj"   # absolute path; ~ allowed
# absent → today's tmpfs $HOME (byte-for-byte identical behaviour)
```

CLI override: `hisn run --home-persist <path>` (same validation; overrides the
profile key).

### Resolution

The profile-level `[home] persist` is resolved AFTER the inner policy's
`session.home`, as a post-resolution override. The flow:

1. Resolve the inner policy as today (`Policy::resolve`), producing a
   `ResolvedPolicy` with `home = Home::Tmpfs` (or `Home::Path` if
   `session.home` is an absolute path — unchanged).
2. If `home.persist` is set (from profile or `--home-persist`):
   a. Expand `~` to the invoking user's home directory (`env::home_dir` /
      `$HOME`).
   b. **Canonicalise the parent** (which must exist) with
      `fs::canonicalize`; join the final component. `fs::canonicalize` on
      the full path fails if the directory does not exist yet — so
      canonicalise the parent, then create the final component(s) with
      `fs::create_dir` (not `create_dir_all` — the parent is already
      canonicalised). This avoids the TOCTOU between canonicalise and create.
   c. **Refuse list** (checked before any namespace is created):
      - the real host `$HOME` (resolved from `env::home_dir`)
      - `/`
      - the resolved session cwd
      - any ancestor of the session cwd
      - a path that is not a directory after creation
   d. Create the directory if missing (`fs::create_dir`, mode 0700, owned
      by the invoking user — `chown` to the real uid/gid). If the directory
      already exists, verify it is a directory and is owned by the invoking
      user; refuse if it is foreign-owned or group/world-writable.
   e. Override `ResolvedPolicy.home` to `Home::Path(canonicalised)`.
   f. **Risk reporting covers CLI overrides**: `compute_risks` checks the
      resolved `home.persist` (from profile OR `--home-persist`), not the
      profile text alone.

The inner policy's `session.home` is unchanged and still works as before. The
profile-level `[home] persist` is a separate mechanism that creates and
validates the directory; it does not modify the inner policy's text.

### Landlock/mount scope

Write access is limited to the persist directory; the tmpfs rules for `/tmp`
and `/dev/shm` stay as they are. The mount is `BindRw { recursive: false }` at
`SANDBOX_HOME` — the same mount op as today's `Home::Path`.

### Sharing

Several sessions may share one persist dir (caches tolerate that). Documented,
no locking. A session can poison caches read by later sessions in the same dir
— that is the risk.

### Risk label

`home-persist` (medium): state carries across sessions; a session can poison
caches read by later sessions in the same dir. Shown by `profile explain` and
in the JSON output used by Wakil's banner.

### Where it lives in the code

- `src/profile.rs`: add `HomeConfig` struct (`persist: Option<String>`), add
  `home: Option<HomeConfig>` to `Profile` with `#[serde(default, rename =
  "home")]`.
- `src/policy.rs`: add `home_persist: Option<PathBuf>` to `Overrides`; in
  `Policy::resolve`, after resolving `session.home`, if `home_persist` is set,
  expand `~`, canonicalise, check the refuse list, create the dir, and override
  `home`.
- `src/cli.rs`: add `--home-persist <path>` to `RunArgs`; map it into
  `Overrides` in `supervisor::prepare`.
- `src/supervisor.rs`: in `prepare`, pass `home_persist` from `RunArgs` into
  `Overrides`.
- `src/profile.rs::compute_risks`: add a `FeatureRisk` entry when
  `home.persist` is set.

### Leak tests

- L42: host `$HOME` not visible (reuse L1 probes); persist dir reachable only
  at the mounted path; a symlink created inside the persist dir pointing to a
  host path outside it does not grant access; a file written in session A
  exists in session B; writes anywhere else under the former home location fail;
  invalid paths (the refuse list) are rejected before any namespace is created.

## Phase 2 — Read-only rootfs + import tool

### Config key

```toml
[rootfs]
name = "go-dev"            # resolve from the rootfs store
# or
path = "/path/to/rootfs"  # use a directory directly
# exactly one of name/path; absent → today's behaviour (host /usr, /opt, …)
```

### Store

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

### Mount plan

When a rootfs is set, the read-only system dirs come from the rootfs tree
instead of the host. The existing `mounts::plan()` and `HostFacts::probe()` are
extended:

- `HostFacts::probe()` gains an optional `rootfs: Option<&Path>` parameter.
  When set, toolchain entries (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`,
  `/lib64`, `/opt`, `/nix`) are probed from `<rootfs>/usr`, `<rootfs>/bin`,
  etc. instead of the host paths. `/etc` entries are probed from
  `<rootfs>/etc` instead of `/etc`.
- `mounts::plan()` binds from the rootfs source paths (e.g.
  `<rootfs>/usr` → `/usr` in the sandbox) instead of from the host paths
  (`/usr` → `/usr`). The `bind()` function is extended to accept a separate
  source path when the target differs from the source.
- Host `/usr`, `/opt` and `/nix` must not be visible anywhere in the mount
  tree when a rootfs is set.
- All rootfs mounts are `ro, nosuid, nodev` — the existing `bind()` already
  sets `MOUNT_ATTR_NOSUID`; `nodev` is added via `MOUNT_ATTR_NODEV`.
- hisn's `/etc` stubs (passwd/group with the real username, resolv.conf,
  hosts) are layered on top exactly as today. The generated stubs use the
  host username (`HostFacts.username`), not the rootfs's.
- If a required mountpoint dir is missing in the rootfs, fail with a message
  naming it; do not create dirs inside the user's rootfs tree at session
  start.
- cwd path parity, `/proc`, `/dev`, `/tmp`, `/dev/shm`, `$HOME` (phase 1),
  control socket and `[[services]]` are unchanged.

### Import tool

### Store name validation

Store names for `import`/`path`/`rm` are validated: `^[a-zA-Z0-9._-]{1,64}$`
(same charset as session ids). A name with `/` or `..` is rejected.

### Extraction hardening (explicit design)

- Extract as the invoking user with `--no-same-owner` semantics (chown to
  the invoking uid/gid).
- Strip setuid/setgid bits from all entries.
- **Path traversal**: reject entries with `..` components. Absolute member
  names (leading `/`) are normalised to relative (stripped of the leading
  `/`) and then checked. This is NOT a contradiction: the check rejects
  `../foo` but accepts `/usr/bin/foo` (stripped to `usr/bin/foo`). The L44
  test covers both cases.
- **Hard links**: reject hard links whose target (by link name) points
  outside the target dir. A hard link to a sibling entry inside the archive
  is allowed (it resolves inside the extracted tree).
- **Symlinks**: stored as-is (they resolve inside the mounted tree, that is
  fine). A symlink that points outside the rootfs is stored — it is only
  resolved inside the sandbox's mount namespace, where the target does not
  exist. The L43 test with a crafted symlink (`/usr/local/bin/trap ->
  ../../../../home`) verifies this.
- **Device nodes and fifos**: skipped and counted in the manifest.
- **Pre-existing targets**: refuse to overwrite an existing name without
  `--replace`. `--replace` removes the existing store entry first, then
  extracts.
- **Duplicate entries**: last entry wins (tar semantics); the tar crate
  handles this.
- **Byte/entry limits**: the import tool imposes a maximum (1 GiB total
  size, 100k entries) and fails closed if exceeded. Cleanup on failure:
  the staging directory is removed if extraction fails partway.
- **Atomic publication**: extract to a staging dir
  (`$XDG_DATA_HOME/hisn/rootfs/<name>.staging`), then `rename` to the final
  name. A failed import leaves no partial store entry.
- **Docker container cleanup**: `--from-image` always runs `docker rm`
  after `docker export`, even on failure (best effort; the container is
  created with `--rm` semantics).

### Extraction hardening

- Extract as the invoking user with `--no-same-owner` semantics (chown to
  the invoking uid/gid).
- Strip setuid/setgid bits from all entries.
- Reject entries whose resolved path escapes the target dir: `..` components,
  absolute member names normalised to relative, hard links pointing outside.
- Symlinks are stored as-is (they resolve inside the mounted tree, that is
  fine).
- Device nodes and fifos are skipped and counted in the manifest.
- Refuse to overwrite an existing name without `--replace`.
- Print a one-line summary (files, skipped entries, size).

### `hisn check`

Reports the rootfs store path and the names present.

### `profile validate`

Resolves `name`/`path` and fails on a missing rootfs.

### Risk label

`rootfs` (low): the sandbox runs whatever the image contains — trust in the
image replaces trust in the host toolchain; it reduces host exposure.

### Recipes

- `contrib/rootfs/Dockerfile.go-dev` (debian stable, latest stable Go from
  go.dev, plus git, openssh-client, ca-certificates, build-essential, make,
  curl).
- `profiles/go-dev.toml` referencing rootfs name "go-dev", with a README
  explaining `docker build` → `hisn rootfs import go-dev --from-image ...`.

### Leak tests

With `HISN_TEST_ROOTFS` set to a real rootfs path (skip, counted as skip, when
unset):

- L43: host `/usr` not visible; a host-only binary cannot be executed; rootfs
  write fails (ro); a setuid binary copied into a test copy of the rootfs runs
  without privilege; a crafted symlink in a test copy does not reach the host;
  the username in the session equals the host username.

Without a real rootfs (always runs):

- L44: import-time rejection tests (path traversal, absolute names, hard links,
  setuid stripping) run on a synthetic tar built by the test.

## Phase 3 — SSH agent T1

### Config key

```toml
[ssh]
agent = true                     # default false
keys = ["SHA256:..."]           # optional fingerprint allowlist; empty/absent = all keys
```

### Semantics

- hisn starts a proxy (same supervisor/lifecycle as `[[host_services]]`)
  listening on a unix socket inside the session; the session gets
  `SSH_AUTH_SOCK` pointing at it.
- The host `SSH_AUTH_SOCK` path is never mounted into the session. The proxy
  socket lives under the hisn runtime dir, not in cwd or `$HOME`.
- The proxy speaks the ssh-agent protocol and forwards ONLY
  `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST`.
  Everything else (`ADD_IDENTITY`, `REMOVE_*`, `LOCK`, `UNLOCK`,
  `EXTENSION`, constrained adds) is answered with `SSH_AGENT_FAILURE` and
  logged.
- With `keys` set, `REQUEST_IDENTITIES` responses are filtered to the
  allowlisted fingerprints; `SIGN_REQUEST` for a non-listed key fails.
- Every forwarded sign request is logged once (fingerprint, session id,
  timestamp) on hisn's log channel — no payloads.
- Host agent missing or `SSH_AUTH_SOCK` unset → session start fails with a
  clear message when `agent = true`.
- The raw-socket route stays what it is: `[[forward]]` with its existing
  `risk_ack`. `[ssh]` is NOT implementable as sugar over `[[forward]]`; it is
  its own label and review.

### Risk label

`ssh-agent` (T1, medium): the session can sign with the listed keys for its
lifetime — it can push, authenticate and sign commits as the user; it cannot
add, remove or extract keys. Risk text names the allowlist state (all keys vs.
filtered).

### Where it lives in the code

- `src/profile.rs`: add `SshConfig` struct (`agent: bool`, `keys:
  Vec<String>`), add `ssh: Option<SshConfig>` to `Profile`.
- `src/ssh_agent.rs` (new module): the proxy process — connects to the host
  `SSH_AUTH_SOCK`, listens on a socket, forwards filtered requests.
- `src/supervisor.rs`: in `run_session`, **before** the sandbox is started
  (before the GO/READY handshake), if `ssh.agent` is true, start the proxy
  on the host side, wait for its socket to be ready, and set `SSH_AUTH_SOCK`
  in the session env. The proxy must be ready before the sandbox's init
  starts, so the workload never sees a missing `SSH_AUTH_SOCK`.
- `src/env.rs`: `SSH_AUTH_SOCK` is already scrubbed (L4). The session env
  gets a new `SSH_AUTH_SOCK` pointing at the proxy socket (set by the
  supervisor, not passed from host env).
- **Conflicting exposure**: if `[ssh] agent = true` is set, refuse any
  `[[forward]]` entry whose socket is the host `SSH_AUTH_SOCK` — the proxy
  is the only route to the host agent in T1 mode. This prevents the raw
  socket from being exposed alongside the proxy.
- **Socket isolation**: the proxy socket lives under the hisn runtime dir
  (`$XDG_RUNTIME_DIR/hisn/<session>/ssh-agent.sock`), with mode 0600, owned
  by the invoking user. It is not in cwd or `$HOME`. The sandbox sees it as
  `SSH_AUTH_SOCK` only — the path is not mounted, just the env var set in
  the scrubbed env.

### Leak tests

- L45: `ADD_IDENTITY` and `REMOVE_ALL` from inside the session fail; the host
  agent's key list is unchanged. With an allowlist of one key, `ssh-add -l`
  in the session lists exactly that key; a sign request for another key
  fails. The host `SSH_AUTH_SOCK` path is not visible in the session. The
  proxy socket disappears with session teardown. An actual `ssh-keygen -Y
  sign` with the allowed key succeeds inside the session (skip if `ssh-agent`
  binary is missing, counted as skip).

## Phase 4 — Tests, docs, verification

### Tests

- Unit tests for all three features (path validation, refuse list, rootfs
  extraction hardening, ssh-agent protocol filtering).
- Integration tests in the leak suite, numbered consecutively after the
  highest existing L-number (L41). New tests: L42 (home-persist), L43 (rootfs
  with real rootfs), L44 (rootfs import hardening, always runs), L45 (ssh
  agent T1).
- Register them in `tests/leak/MANIFEST` and `tests/leak/run.sh`.

### CI

- Add the musl target (`x86_64-unknown-linux-musl`) to the release workflow,
  with a `-musl` suffix in the asset name. Keep glibc as the default download.
- The musl build may need a fix for the `ioctl` `c_int` vs `u64` cast in
  `src/init.rs` (OPEN-POINTS P22); if it does, fix it as part of this phase.
- The CI `check` job adds the musl target to the clippy cross-check.
- Update the release notes template and the checksum count (3 artifacts
  instead of 2).

### Docs

- Three ADRs:
  - `docs/adr/0009-persistent-home.md`
  - `docs/adr/0010-rootfs-and-import.md`
  - `docs/adr/0011-ssh-agent-t1.md`
- `README.md`: update the profile reference with the new `[home]`, `[rootfs]`,
  and `[ssh]` tables; add `hisn rootfs` subcommand to the usage section.
- `schemas/hisn-policy.v1.json`: regenerate (the inner `Policy` is unchanged,
  but the `Profile` schema needs the new tables — this may need a separate
  `schemas/hisn-profile.v1.json` or an extension of the existing schema).
- `CHANGELOG.md`: entry for 0.3.2.
- `docs/PLAN-0.3.md`: mark where 0.3b items moved (ssh T1 was in 0.3b; it
  ships here as part of 0.3.2).

### Version

`0.3.2` in `Cargo.toml`/`Cargo.lock` and wherever else the version is stamped.

### Verification

1. Run the full in-sandbox test suite (`cargo test`).
2. Run `cargo clippy --all-targets` and `cargo fmt --check`.
3. Mashūra round 2 on the diff + test results (verification: leaks, lifecycle,
   docs/code consistency).

## Open points — not done

- The `nodev` flag on rootfs mounts: the existing `bind()` in `mounts.rs` sets
  `MOUNT_ATTR_NOSUID` but not `MOUNT_ATTR_NODEV`. Adding `nodev` to all
  toolchain binds (not just rootfs) is a small behaviour change for existing
  profiles. Decision: add `MOUNT_ATTR_NODEV` to rootfs binds only; leave host
  binds as-is (nosuid only) for backward compat. If the user wants `nodev` on
  host binds too, that's a separate change.
- The `[ssh]` proxy is a new host-side process. It uses the same lifecycle as
  `[[host_services]]` (start, wait readiness, stop on session end) but it is
  NOT a `[[host_services]]` entry — it has its own start/stop code in the
  supervisor. This is because the proxy needs to know the host `SSH_AUTH_SOCK`
  and the allowlist, which are profile-level config, not a generic exec.
- The ssh-agent protocol constants (`SSH_AGENTC_*`) are not in any crate
  dependency; they are defined in the OpenSSH source as simple byte values.
  We define them as constants in `src/ssh_agent.rs` (they are a stable
  protocol, not an API that changes).
- The rootfs import uses the `tar` crate (new dependency) for extraction, or
  shells out to `tar(1)`. Decision: use the `tar` crate for extraction
  hardening (path traversal, setuid stripping, hard link checks) — the logic
  is easier to audit in Rust than in a shell pipeline. Add `tar = "0.4"` to
  `Cargo.toml`.
- The musl build: the release workflow adds a third matrix entry
  (`x86_64-unknown-linux-musl` on `ubuntu-22.04`). The musl target may need
  `musl-gcc` or `zig` as a cross linker. If the build does not compile on
  musl (the `ioctl` cast issue), fix it; if the fix is large, drop musl from
  this release and note it as a follow-up.
# Wakil ↔ hisn integration

hisn is Wakil-agnostic; this document describes one consumer. Wakil's Go side
only needs: `exec.Command("hisn", …)`, the exit code, and (optionally) the
control socket.

## 1. Launching

Wakil replaces its Docker executor's `docker run …` with:

```go
args := []string{"run", "--policy", policyPath, "--session-id", sessionID,
    "--cwd", workdir, "--"}
args = append(args, userCmd...)
cmd := exec.CommandContext(ctx, "hisn", args...)
cmd.Env = minimalEnv            // hisn scrubs again; do not rely on only one side
cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
err := cmd.Run()                // *exec.ExitError.ExitCode() == command's code
```

* `hisn run` does not print on stdout; stdout is the command's.
  Exit codes: command's code, `128+sig`; `125` hisn error (policy/host),
  `126` cannot exec, `127` not found.
* **v0.2: one session, many tool calls.** Wakil starts ONE long-lived session
  at agent start — `hisn run --session-id <agent> --detach` — and runs every
  tool call with `hisn exec --session <agent> [--cwd DIR] [--env K=V]... -- CMD…`
  in it: the same namespaces, the same confinement, the same grants. `exec`
  passes stdio through, propagates the exit code (`128+sig` if signalled,
  `125` hisn error, `126`/`127` as for `run`) and prints nothing of its own.
  Grants made mid-session (`hisn grant`) are visible to later and running
  execs. `hisn exec --tty` runs a tool on a fresh pty (Wakil passes pipes
  instead). Terminate a running tool with `hisn exec`'s own
  `{"op":"signal","pid":N}` on a second connection, or end the whole session
  with `hisn kill`. Pre-v0.2 (one `hisn run` per tool call, warm `home`)
  still works and remains the fallback when `hisn --version` < 0.2.
  **0.4.1:** `hisn run --detach` returns once the session is ready
  (`<id> <name|-> ready` on stdout, exit 0), so Wakil need not poll `hisn ls`;
  a start failure prints the supervisor's error lines and exits non-zero.
  Pass secret-shaped values with `--env-file PATH` (KEY=VALUE lines) so they do
  not appear in `/proc/<pid>/cmdline`.
  A failed start exits 125 with or without `--detach`. Label Wakil's
  connections with `--client LABEL` on `exec` and `attach`; the label appears in
  the audit log and in `hisn ls --json` `clients[]`. The `hisn-ls/v2` schema,
  the `sessioninfo` op, exit codes and observer rules are described once in
  [sessions.md](sessions.md#driving-hisn-from-a-program).
* Cancellation: `ctx` cancel → SIGTERM to `hisn`, which forwards to the
  command's process group; after a grace period `hisn kill --session ID
  --signal KILL`.
* `hisn check` (exit 0/2, `--json`) is the preflight; Wakil falls back to its
  Docker executor when it reports a missing required capability.

## 2. Mapping Wakil's capability tiers to grants

| Wakil tier | policy | grants |
|-----------|--------|--------|
| discovery (read-only) | `cwd` rw is **not** wanted | start with `--cwd` of a *ro* view: run with `mounts.ro=[workdir]`, `session.cwd=<scratch dir>`; no `rw` mounts |
| edit | `session.cwd = workdir` (rw) | none required |
| edit, isolated worktree child | `cwd = <child worktree>` (rw) | `grant <parent repo>` **ro** if it needs history |
| tools (MCP/web) | as edit | any MCP data dir as **ro** grant; outputs dir as **rw** grant under `mounts.grantable_rw` |
| `/auto` consent off | same as discovery | a write attempt gets `EROFS`, which Wakil reports as "needs consent" |

Escalation (user approves a write mid-session) is a dynamic grant:
`hisn grant --session ID PATH --rw` (requires `PATH` under a configured
`mounts.grantable_rw`). Wakil must treat `E_NOT_GRANTABLE` as "restart the
session with a wider policy", never as a reason to retry differently.
Revocation on consent withdrawal: `hisn revoke --session ID PATH --hard` —
kills every sandbox process except init and returns `guarantee:"hard"`. A plain
(soft) revoke only guarantees the path no longer resolves; already-open or
queued file descriptors may survive it. Wakil must use `--hard` whenever the
revocation is a security decision.

## 3. `.secrets/` as an rw grant

Wakil writes per-run secrets (API tokens for MCP servers, etc.) to
`<workdir>/.secrets/`. With hisn this directory must **not** be inside the
agent-visible cwd by default. Recommended layout:

1. Create `<workdir>/.secrets` on the host as today (0700, `.gitignore`d).
2. Add it to `mounts.mask` of the policy so the agent's view of cwd shows an
   empty directory there (secrets are not readable).
3. When a *trusted tool process* inside the sandbox needs it, Wakil issues
   `grant <workdir>/.secrets --rw` (identical path; the grant mount sits over
   the mask) and `revoke`s it afterwards. Because grants are rule-checked
   (R3), overlapping a mask is allowed **only** for this exact "unmask by
   grant" pattern: the grant target must equal a mask entry, and the audit
   log records it. The mask comes back automatically on revoke, because the
   mask mount is still underneath.
4. For secrets the agent itself must never see, do not grant; pass them in
   `env.pass` of a *separate* policy for the tool process, or keep the tool
   outside the sandbox. `env.pass` names that look secret are logged.

(Open point: "grant over mask" is the one place R3 is relaxed; see
OPEN-POINTS.)

## 4. Contract tests Wakil should add

* start a session, `hisn grant` a temp dir ro, assert write → `EROFS`;
* revoke, assert path → `ENOENT`;
* session end → no `hisn` process, no session dir, no residual mounts in the
  host `/proc/self/mountinfo` diff.

## 5. In-sandbox services (`[[services]]`, 0.3)

Wakil may declare a `[[services]]` entry in its profile to start a long-lived
process inside the sandbox (e.g. `kvr-server` for staging). The service:

- is started by hisn through the exec helper chain, with the **same confinement**
  as the main command (same seccomp, Landlock, caps, env);
- runs as a sibling of the main command in the sandbox pid namespace;
- binds its socket at a path inside the sandbox (e.g. `{cwd}/.wakil/kvr.sock`);
- dies with the session (it is in the pid ns; when init exits the kernel kills
  everything in it);
- has no client connection; its stdio is `/dev/null`.

Wakil's host-side client connects to the socket at the **identical path** (path
parity: cwd is a rw bind of the host directory at the same path). A stale
socket file at that path after session end is cleaned up by Wakil (not by hisn);
the session dir cleanup does not remove files created inside cwd by the
sandbox.

The `kvr-example` profile (`profiles/kvr-example.toml`) ships as a reference.
`hisn ls --json` gains a `services` array: `[{name, pid, socket, state, exit}]`.

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
* A long-lived "sandbox" (Wakil's per-session container today) is one
  `hisn run … -- sleep infinity`-style session started at agent start; each
  tool call is then a further process in it. v0 has no `exec-in-session` verb;
  the v1 HTTP/MCP `commands.run` provides it. Until then Wakil starts one
  `hisn run` per tool call with the same persistent `home` path (warm caches)
  and `--session-id <agent>-<n>`.
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
Revocation on consent withdrawal: `hisn revoke --session ID PATH
[kill_holders]` and read `holders` — if non-empty and the guarantee matters,
end the session.

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

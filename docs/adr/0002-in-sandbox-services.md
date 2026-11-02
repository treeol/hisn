# ADR 0002 — In-sandbox services `[[services]]`

Status: proposed. Date: 2026-11-02. Context: `docs/PLAN-0.3.md §2`.

## Decision

A `[[services]]` entry starts a long-lived process **inside the sandbox**
after `READY` and before `hisn run` returns (or before a `--detach` session is
listed as ready). The service runs under the **same confinement as the main
command**: same namespaces, same seccomp, same Landlock, same caps (none),
same env. It is a sibling of the main command in the sandbox pid namespace,
reaped by init.

```toml
[[services]]
name    = "kvr"                         # required, unique
exec    = ["kvr-server", "--addr", "/run/kvr/kvr.sock"]
socket  = "/run/kvr/kvr.sock"            # optional
ready   = { socket = "/run/kvr/kvr.sock" }   # socket | tcp | command
stop    = { signal = "TERM", grace = 5 }
restart = "none"                        # only "none" in 0.3
```

## Lifecycle

1. Init reports `READY` (`DESIGN §3`).
2. The supervisor starts each service **through the exec helper chain**
   (`DESIGN §14.2`, process `C→D→W→P`), in order. The service re-enters via
   the same `setns` + re-applied confinement (`§14.4`); it is
   indistinguishable from the main command to the kernel.
3. Readiness: the supervisor polls `ready` (socket stat, tcp connect, or
   command exit 0) with a timeout (default 15 s; `ready.timeout` per
   service). On timeout the session fails to start (fail closed): the service
   is killed and the session exits `125`.
4. Stop: on session end (init exit, `hisn kill`, or a `revoke --hard` that
   kills the pid ns), the supervisor sends `stop.signal` to the service's
   process group, waits `stop.grace`, then `SIGKILL` — the same
   TERM-then-KILL the exec monitor uses (`§14.8`).
5. `restart = "none"`: if a service exits before the session ends, it stays
   down; the supervisor logs the exit and does not restart. (0.4 may add
   `restart = "on-failure"`.)

## `ls --json`

Gains a `services` array: `[{name, pid, socket, state, exit}]`. `pid` is the
in-sandbox pid (same namespace as `exec` pids). The schema is additive on
the 0.2.1 frozen schema (§8).

## Why inside, not host-side

kvr is a scratch store for Wakil's staging tools; it must be confined (it
holds transient agent data) and must die with the session. Starting it
inside the sandbox means it gets the same seccomp/Landlock/caps as the
command for free, and its socket is only reachable from inside. A host-side
service (§3) is for things that must outlive or stand outside the sandbox
(Docker, an agent that signs with host keys); kvr is neither.

## Invariants

- 1: the service sees the same empty-tmpfs root + pivot_root.
- 2: same seccomp — the service is exec'd through the same chain as the main
  command.
- 3: the service is in the pid ns and dies with it.
- 5: annotation only (`org.hisn.services=[{name,socket,exec}]`); no
  `mounts[]` entry (the service runs in the existing namespaces).

## Threat model

A sibling process that can talk to the main command over whatever protocol
its socket allows. It cannot escape the sandbox (same seccomp/Landlock/caps)
or outlive the session. The risk is bounded by the service's own protocol
(kvr is a KV store over a unix socket, not a shell). Leak test: L31.
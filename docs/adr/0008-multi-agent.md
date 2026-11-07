# ADR 0008 — Multi-agent: discovery in 0.3, leases in 0.4

Status: proposed. Date: 2026-11-02. Origin: the 0.3 planning document (§7), removed from the tree; this record stands alone.

## Decision

0.3 ships the **discovery** half of multi-agent; the **lease** half moves to
0.4. 0.3 does not change the control protocol; 0.4 does.

## In 0.3

- `hisn attach --session <id|name>` — a second client (a second Wakil, a
  shell) attaches to a running session. Attaching means: the new client can
  `exec`, `grant`, `revoke`, `inspect`, `kill` through the same control
  socket, **with the same uid check as today**. There is no per-client
  identity in 0.3 — any same-uid process can attach. R5 still refuses the
  sandbox's own processes. This is the 0.2 behaviour, named and documented.
- **Session discovery by name/cwd:** `hisn ls --json` gains `cwd` (the
  resolved session cwd) and `name` (a new `--name` flag on `run`, stored in
  the session dir). `hisn attach --name foo` and `hisn attach --cwd
  /path/to/repo` resolve to a session by name or by cwd match. This lets a
  second agent find "the session already running in this repo" without
  guessing the session id.

## In 0.4 (deferred)

- **Leases:** a client takes a lease on a session (exclusive or shared) so
  `hisn kill` by one client does not tear down a session another client is
  using. Leases need per-client identity, which needs a client token (passed
  by Wakil) and a control-socket auth step that is not just uid.
- **Per-client grant/signal policy:** client A can grant but not kill;
  client B can exec but not grant. Needs the same per-client identity.
- **`hisn request <path>` from inside the sandbox** (surfaced to the host
  for approval) — interacts with per-client identity and the risk labels
  (§11); deferred with the lease work.

## Why split

Discovery is cheap: name/cwd in the session dir; `attach` is a documented
alias for the existing socket path resolution. Leases need identity and auth,
which is a control-protocol change and its own review. 0.3 can ship discovery
without touching the control protocol; 0.4 does the protocol.

## Invariants

- 3: grants still die with the session — attach does not extend them.
- 2: the control socket is unchanged; R5 still refuses the sandbox.
- 5: annotation only (`org.hisn.session.name=…`).

## Threat model

0.3: a second same-uid client can attach. It gains the same control surface
the first client has. It does not gain: the ability to attach as a sandbox
process (R5), per-client grant/signal policy (0.4), or a lease that survives
a `kill` by another client (0.4). Leak test L39: a second client attaches by
name/cwd; a sandbox process is still refused; the attached client's `grant`
is visible to the first; `kill` by one does not leave the other's fds live
in the sandbox (hard revoke semantics).
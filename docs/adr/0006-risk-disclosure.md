# ADR 0006 — Risk disclosure

Status: proposed. Date: 2026-11-02. Origin: the 0.3 planning document (§5), removed from the tree; this record stands alone.

## Decision

Every profile capability that widens the boundary carries a **fixed risk
label** from a closed set. The label is **computed by hisn from the
capability**, not chosen by the author: the author declares the capability;
hisn emits the label.

## Labels

| label | meaning |
|---|---|
| `none` | no widening; the 0.2 sandbox |
| `data` | the sandbox can read or write host data beyond cwd (a bind, a forwarded data socket) |
| `signing` | the sandbox can produce a cryptographic signature valid on the host (ssh agent, git signing) |
| `host-exec` | the sandbox can run arbitrary commands on the host as the user (a forwarded D-Bus/systemd socket, a shell server, another hisn control socket) — user-equivalent |
| `root-equivalent` | the sandbox can become root on the host (raw docker socket) |
| `kernel-surface` | the sandbox can provoke kernel code paths out of scope of the 0.2 threat model (nested userns) |

## How a label is assigned

By the feature, not the author:

- `docker = "socket"` → `root-equivalent` (always).
- `nested_userns = true` → `kernel-surface` (always; **rejected in 0.3**).
- `[[forward]]` of an ssh agent → `signing` (always).
- `[[forward]]` of the Docker socket (or a recognized rootless-podman
  socket) → `root-equivalent` (always; the Docker daemon is root).
- `[[forward]]` of the D-Bus system or session bus → `host-exec` (always).
- `[[forward]]` / `[[host_services]]` of **an unrecognised socket** → **load
  error** (round-2 BLOCKING: hisn cannot know what protocol an arbitrary
  inode speaks; a forwarded socket is as powerful as its server, so an
  unknown socket is rejected unless the profile sets `risk` explicitly —
  minimum `host-exec`, documenting that the author asserts the server is
  not root). The profile may **downgrade** the label only for a recognised
  socket path pattern; an unrecognised socket cannot be labelled `none` or
  `data` without an explicit `[forward] risk = "data"` that hisn accepts
  against a known pattern.
- `[[host_services]]` → `data` (it starts a host process; the exposure is
  the socket) unless the service is itself a signer (then `signing`) or a
  known root-equivalent (then `root-equivalent`).
- `[ssh] tier = "host-git"` → `none`; `tier = "proxy"` → `signing`;
  `tier = "socket"` → `signing`.
- `[docker] tier = "proxy"` → `none` (the proxy is the boundary) **in 0.4
  only, when the proxy actually closes the boundary**; in 0.3 T1 is not
  available (`E_NOT_SUPPORTED`). `[docker] network = "host"` (0.4) adds
  `data`.
- `[docker] tier = "socket"` → `root-equivalent` (always, the 0.3 tier).
- `[[host_services]]` → `host-exec` for the execution itself (round-2
  BLOCKING: a profile's arbitrary host-side `exec` is user-equivalent
  execution, independently of the socket protocol), plus the socket's label
  (`data`/`signing`/`root-equivalent` as above). The `risk_ack` covers both.

## Behaviour

- `hisn run` prints the effective risk labels on start, one line each,
  unless `--quiet-risk`. A profile with no widening capabilities prints
  nothing (or `RISK: none` with `--verbose`).
- `hisn profile explain <name>` prints each capability and its label with
  one sentence of explanation.
- A profile with a `root-equivalent`, `signing`, or `host-exec` capability
  **must** contain the matching `risk_ack`:

  ```toml
  [docker]
  tier = "socket"
  risk_ack = "root-equivalent"   # must match the computed label

  [[forward]]
  name = "ssh-agent"
  risk_ack = "signing"
  ```

  Missing/mismatched → load error (`E_RISK_ACK_REQUIRED` /
  `E_RISK_ACK_MISMATCH`). This is the "never silent" rule for T2/ssh-T2 and
  the "secure by default" rule for everything else.

## Secure by default

A profile with no `[[services]]`, `[[host_services]]`, `[[forward]]`,
`[docker]`, `[ssh]`, `nested_userns`, and the inner `[policy]` at its defaults
yields **exactly the 0.2 sandbox** — same mount plan, same seccomp, same
Landlock, same env. The profile layer is a strict superset of capabilities,
never a relaxation. (DO NOT ALTER #3.)

## Invariants

- 5: the labels are carried as annotations `org.hisn.risk=[…]`; the
  isolation invariants are unchanged by the labels themselves.
- 6: the leak suite (L1–L24, L25–L39) tests the isolation; the labels are
  display + load-time enforcement, not a runtime boundary.

## Threat model

The labels add no capability; they disclose the ones the profile already
declares. A missing `risk_ack` is a load error, so a profile cannot silently
enable a root-equivalent or signing capability. The leak tests for the
underlying capabilities (L27–L29) are the acceptance criterion.
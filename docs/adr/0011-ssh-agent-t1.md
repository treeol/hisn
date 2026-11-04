# ADR 0011 — SSH agent T1 filtering proxy (0.3.2)

Status: accepted. Date: 2026-11-04. Context: `docs/PLAN-0.3.2.md §3`.

## Decision

A profile may declare an **SSH agent T1 proxy** that lets the session sign
with the host's SSH keys without exposing the raw agent socket:

```toml
[ssh]
agent = true                     # default false
keys = ["SHA256:..."]            # optional fingerprint allowlist; absent = all
```

When `agent = true`, hisn starts a filtering proxy that:
- connects to the host `SSH_AUTH_SOCK`,
- listens on a unix socket inside the hisn runtime dir (not cwd, not `$HOME`),
- forwards ONLY `SSH_AGENTC_REQUEST_IDENTITIES` (11) and
  `SSH_AGENTC_SIGN_REQUEST` (13),
- answers everything else (`ADD_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `LOCK`,
  `UNLOCK`, `EXTENSION`, constrained adds) with `SSH_AGENT_FAILURE` (5) and
  logs it,
- with `keys` set, filters `REQUEST_IDENTITIES` responses to the allowlisted
  fingerprints and rejects `SIGN_REQUEST` for non-listed keys,
- logs every forwarded sign request (fingerprint, session id, timestamp)
  on hisn's log channel — no payloads.

The session gets `SSH_AUTH_SOCK` pointing at the proxy's forwarded socket.
The host `SSH_AUTH_SOCK` path is never mounted into the session.

## T1 vs T2

T1 (this feature) means "sign but never add/remove/extract": the session can
produce signatures with the listed keys, but cannot mutate the host agent's
key set or extract key material. T2 (the raw-socket route, `[[forward]]` with
`risk_ack = "signing"`) exposes the full agent socket — the session can add
keys, remove keys, lock, unlock, and extract key material.

`[ssh]` is NOT implementable as sugar over `[[forward]]`; it is its own label
and its own review. The raw-socket route stays as it is.

## Risk label

`ssh-agent` (T1, medium, `RiskLabel::Signing`): the session can sign with
the listed keys for its lifetime — it can push, authenticate and sign commits
as the user; it cannot add, remove or extract keys. Risk text names the
allowlist state (all keys vs filtered).

## Lifecycle

The proxy runs as a thread in the supervisor process. It starts before the
sandbox init (so `SSH_AUTH_SOCK` is available from the first exec), and the
proxy socket is forwarded into the sandbox using the same `do_forward`
mechanism as `[[forward]]`. The host `SSH_AUTH_SOCK` is never mounted; only
the proxy socket is forwarded, and only the env var is set.

Host agent missing or `SSH_AUTH_SOCK` unset → session start fails with a
clear message when `agent = true`.

## Invariants

- The host `SSH_AUTH_SOCK` path is never mounted into the session.
- The proxy socket lives under the hisn runtime dir, not in cwd or `$HOME`.
- Only message types 11 and 13 are forwarded; everything else is FAILURE.
- With `keys` set, only allowlisted keys appear in `REQUEST_IDENTITIES` and
  `SIGN_REQUEST` for non-listed keys fails.
- Git identity, `gpg.format=ssh`, `allowed_signers` and `known_hosts` are
  Wakil's job (cwd-side config); hisn does nothing there.

## Leak tests

L45: `ADD_IDENTITY` and `REMOVE_ALL_IDENTITIES` from inside the session
fail; the host agent's key list is unchanged. With an allowlist of one key,
`ssh-add -l` in the session lists exactly that key; a sign request for
another key fails. The host `SSH_AUTH_SOCK` path is not visible in the
session. The proxy socket disappears with session teardown. An actual
`ssh-keygen -Y sign` with the allowed key succeeds (skip if `ssh-agent`
binary is missing).
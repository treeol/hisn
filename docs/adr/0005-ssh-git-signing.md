# ADR 0005 — SSH / git signing: T0 host-git / T1 proxy / T2 socket

Status: proposed. Date: 2026-11-02. Context: `docs/PLAN-0.3.md §4b`.

## Decision

Three tiers for ssh / git signing from inside a hisn sandbox, mirroring Docker
because the risk shape is the same: "a socket that can do a powerful thing on
the host." A fourth option (per-session agent with destination-constrained
keys) and a fifth (FIDO `sk-` keys) strengthen T1 without changing the tier.

## T0 `ssh = "host-git"` — default, no agent inside

The sandbox has a git identity (`env.set` for `GIT_AUTHOR_*` /
`GIT_COMMITTER_*`, or a ro `~/.gitconfig` bind) but **no** ssh agent and **no**
private keys. Commits are made inside; push happens on the host (Wakil runs
`git push` on the host side, not inside the sandbox). Risk label: `none`.

## T1 `ssh = "proxy"` — `hisn-agent-proxy`

A host-side process that speaks the ssh-agent protocol and exposes a socket
inside. It:

- **allowlists key fingerprints** (`[ssh] allow_keys = ["SHA256:…"]`); other
  keys in the host agent are invisible.
- **is sign-only**: `SSH_AGENTC.SSH_AGENTC_SIGN_REQUEST` is allowed; all other
  agent ops (`ADD_IDENTITY`, `REMOVE_*`, `LOCK`/`UNLOCK`, `LIST_IDS`) are
  denied. The sandbox cannot add or remove keys or lock the agent.
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
- **per-signature audit**: every sign request logs (fingerprint, timestamp)
  to `<session>/ssh-proxy.jsonl`. Never the blob.
- **commit-signing restriction (0.4, not claimed in 0.3):** a future
  `commit_signing_only` flag would restrict sign requests to git
  commit/tag objects; the mechanism is SSHSIG framing detection, which is
  not trivially parseable from the agent protocol and is **not claimed in
  0.3**. In 0.3 the restriction is `allow_keys` + per-session agent +
  audit.

Risk label: `signing`. `risk_ack = "signing"` required.

### Per-session agent with destination-constrained keys (`ssh-add -h`)

OpenSSH 9.6+ `ssh-add -h` loads a key constrained to specific destinations.
The profile can ask hisn to `ssh-add -h` a dedicated key into a fresh
per-session agent that the proxy then forwards to (`[ssh]
per_session_agent = true`). The proxy forwards to the per-session agent, not
the host agent. This is the **enforceable** host-restriction mechanism
(round-1 BLOCKING: the constraint is enforced by the agent, not by the
proxy parsing the signed blob).

### FIDO `sk-` keys

A FIDO key (`sk-ssh-ed25519@…`) may require a physical touch for each
signature. `[ssh] require_fido = true` refuses a non-FIDO key. Whether every
`sk-` key configuration requires touch is **not assumed** (round-1 BLOCKING:
verify the touch policy per key). Risk label stays `signing`.

## T2 `ssh = "socket"` — raw `[[forward]]` of the host ssh-agent

The sandbox can use any key in the agent for anything (ssh login, git push,
add/remove keys). Risk label: `signing`, `risk_ack = "signing"` required,
printed at every start. Not the default.

## Recommendation for Wakil

`ssh = "host-git"` as the default profile (T0: commits carry the identity
inside, push on the host on review, no signing inside). `ssh = "proxy"`
with `per_session_agent = true` and `require_fido = true` when an agent is
actually needed inside (e.g. an agent that pulls). Never T2 unless the user
explicitly asks.

## Invariants

- 1: T0/T1/T2 add at most a socket inode, ro, inside the empty-tmpfs root.
- 3: the agent/proxy dies with the session; the per-session agent is a
  host-side process stopped on session end.
- 4: `SSH_AUTH_SOCK` the sandbox sees points at `expose`, not the host path;
  set by hisn, not passed from host env.
- 5: annotation only (`org.hisn.ssh.tier=…`).

## Threat model

- T0: gains a git identity (name/email); cannot sign anything or push from
  inside. Leak tests L25/L26.
- T1: gains signatures with allowlisted keys; cannot use non-allowlisted
  keys, add/remove keys, or lock the agent. Leak test L27.
- T2: gains use of any host agent key for anything; root-equivalent for the
  agent. Covered by the L29 ack check (the risk line must print).
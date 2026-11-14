# hisn control protocol

The control socket is the wire between a `hisn` client and a session's
supervisor. It is a **documented contract**: WAKIL (and any other client) is
pinned to hisn 0.4.3 and must keep working against a 0.5.0 supervisor, and a
0.5.0 CLI must keep working against a still-running 0.4.3 supervisor. This
document is the single source for the wire shape; the shapes below were
generated from the code (`src/control.rs`, `src/supervisor.rs`,
`src/sessionmeta.rs`) and cross-checked against `docs/POLICY-SPEC.md` §7.

<p><strong>Regenerated from code on 2026-11-14.</strong> If this file and the
code disagree, the code wins and this file is wrong.</p>

## Framing

- Unix datagram… stream socket: `<session-dir>/control.sock`, mode `0600`,
  inside the session runtime dir (which is `0700`).
- One request per line, one response per request, in order, over one
  connection (a client may pipeline several lines, except `exec` — see
  below). The server is transport only; the peer is authorized before every
  request (DESIGN §9 R5) and the operations are supplied by the supervisor.
- A request line is at most 64 KiB (`MAX_LINE`). A response may be up to
  16 MiB (`MAX_RESPONSE_LINE`) because `inspect` carries mountinfo + the
  resolved policy.
- Every line is one JSON object, newline terminated. A request that is not
  valid JSON, or that does not parse as a `Request`, is answered with a
  single `{"ok":false,"error":"E_BAD_REQUEST",…}` line and the connection is
  then **closed** (POLICY-SPEC §7). The request is never dispatched.
- Descriptors travel as `SCM_RIGHTS` in the same `sendmsg` as the request
  line. Descriptors are accepted **only** with the first line of a connection
  and **only** for `exec`, and an `exec` with descriptors must be unpipelined
  (nothing else in the same segment). Any other use is `E_BAD_REQUEST` +
  close; every received descriptor is owned (and closed) by the server once
  `recvmsg` returns, so a rejected request cannot leak one. At most 5
  descriptors are accepted (the `recv_with_fds` cap); more is a framing error
  and the connection is closed with no response.

## `client` field rules

Every request may carry a `client` object with three optional fields:

```json
{"label": "wakil@rubin", "label_source": "ssh", "req_id": "7f3a"}
```

- `label` — a human label from `--client LABEL` (or derived from the SSH
  environment by the client). The supervisor falls back to `local` (the
  owner's uid) or `uid:<n>` (another uid) when absent.
- `label_source` — where `label` came from: `flag`, `ssh`, `local`, `none`,
  or `internal`.
- `req_id` — an opaque request id chosen by the client.

`client` is **strict**: an unknown field in the object (including `uid`, which
is never a request field — uid comes only from `SO_PEERCRED`) makes the whole
request unparseable → `E_BAD_REQUEST` + close. The same goes for unknown
fields on a request variant (the `Request` enum is `deny_unknown_fields`):
extra keys are errors, never silently ignored. This is how a 0.4.3 client that
sends a field this supervisor does not know is refused rather than misread.

The supervisor never trusts `client` for identity: `uid` and `pid` come from
`SO_PEERCRED`, the only tamper-proof peer credential. The audit `client`
object and the journal `client` object are built from those facts plus the
labels above.

## Error codes

Error response: `{"ok":false,"error":"<CODE>","message":"…"}`.

| code | meaning |
| --- | --- |
| `E_BAD_REQUEST` | unparseable request, or a validation failure (a refused `env` key names the key). The connection is closed only for unparseable requests; a parseable request that fails validation is answered with this code and the connection stays open. |
| `E_PATH_FORBIDDEN` | the path is not grantable (not absolute, not canonical, under a runtime root, under a mask, under a static read-only mount). |
| `E_NOT_FOUND` | the path does not exist, or no live exec has that `exec_id`/`pid`. |
| `E_NOT_GRANTABLE` | the path is inside a subtree that cannot be granted (e.g. a mount point). |
| `E_EXISTS` | the path is already granted (modes are never silently changed). |
| `E_NOT_GRANTED` | `revoke` of a path that is not granted. |
| `E_HELD` | reserved: a revoke holder was found that cannot be killed under a soft revoke (not currently emitted; kept for the v0 contract). |
| `E_INTERNAL` | the sandbox failed (setup, a hard revoke that could not complete — the session is then killed, a supervisor error). |
| `E_UNAUTHORIZED` | the authorization seam refused the request (the peer was not the session owner in 0.4; see DESIGN §9). |
| `E_EXEC` | the program could not be started (confinement failed, not found, not executable). |
| `E_VERSION` | **0.5.0**: the request declares a protocol revision newer than the supervisor supports. The message names the supported revision. See "Version rule". An unknown op string is never `E_VERSION`: it fails parsing first and is answered `E_BAD_REQUEST` + close, exactly as in 0.4.3. |

There are no CLI exit codes for these wire errors: a client maps a failed
response through its own exit-code policy (the `hisn` CLI prints the response
and exits 1). `E_VERSION` is never a process exit code.

## Operations

All ops are lower-case `op` strings. Every op below accepts an optional
`client` object (§`client` field rules).

### `grant`

```json
{"op":"grant","path":"/a","mode":"ro","recursive":false}
```

`path` (absolute), `mode` (`"ro"`|`"rw"`, default `"ro"`), `recursive`
(bool, default false).
Success: `{"ok":true,"mount_id":N,"path":P,"mode":M}`.

### `revoke`

```json
{"op":"revoke","path":"/a","hard":false,"kill_holders":false}
```

`path`, `hard` (bool, default false), `kill_holders` (bool, default false;
soft only).
Success: `{"ok":true,"guarantee":"lookup"|"hard","holders":[…]}`.
`guarantee:"lookup"` = the path no longer resolves, but already-open or
queued (`SCM_RIGHTS`) descriptors cannot be ruled out — `holders` lists what
the scan found (kinds `cwd`, `fd`, `map`, `unknown`). `guarantee:"hard"` =
all sandbox processes except init were killed after the detach, so no usable
reference remains inside the sandbox. `E_INTERNAL` if a hard revoke could not
complete (the session is then killed).

### `list`

```json
{"op":"list"}
```

Success: `{"ok":true,"grants":[{"path","mode","recursive","mount_id","ts"}]}`.

### `inspect`

```json
{"op":"inspect"}
```

Success: `{"ok":true,"schema":"hisn-inspect/v1","mountinfo":"…","policy":"<resolved toml>","risk":[…],"services":[…],"supervisor_fds":N}`.
`supervisor_fds` is the supervisor's own open-descriptor count (the leak
suite's L19 cannot read `/proc/<supervisor>/fd` itself); `null` if it could
not be counted. `risk` lists the session's risk labels (capability +
kebab-case label).

### `sessioninfo`

```json
{"op":"sessioninfo"}
```

Success: `{"ok":true,"clients":[…],"execs":[…],"services":[…], …}`.
**Observer**: it never counts as a client (see "Observers"). Each client is
`{"uid","pid","label","label_source","connected_since"}`; each exec is
`{"exec_id","pid","argv0","tty","attach"}`. 0.5.0 adds two additive keys,
`journal_failures` and `journal_bytes` (and `workspace`), which older clients
ignore.

### `kill`

```json
{"op":"kill","signal":"TERM"}
```

`signal` is a name (with or without `SIG`, any case) or a number; default
`TERM`. Success: `{"ok":true}`.

### `exec`

```json
{"op":"exec","argv":["x"],"cwd":"/w","env":{"K":"V"},"tty":false,"attach":false}
```

`argv` (1–4096 entries), `cwd` (absolute or `null`; default the session
cwd), `env` (`K`→`V`; every key must be in `env.pass` and not be computed —
`HOME`, `USER`, `LOGNAME`, `XDG_*`, `CARGO_HOME`, `GOMODCACHE`, `GOCACHE`,
`npm_config_cache`, `PIP_CACHE_DIR` — otherwise the whole request is
refused), `tty` (bool; default false), `attach` (bool; default false — 0.4.0:
an attach is an exec with `attach:true`, starting the session's shell).

The request line travels with `SCM_RIGHTS` fds in the same message: 3
(stdin/stdout/stderr) or, with `tty`, exactly 1 (the slave of a pty the client
allocated — never the caller's terminal). First response:
`{"ok":true,"pid":N,"exec_id":"e-n"}` (`N` is the pid **inside the sandbox
pid ns**, a handle for `signal`; `exec_id` is the preferred handle), then on
exit `{"exit":{"code":N}}` / `{"exit":{"signal":"TERM"}}` /
`{"exit":{"lost":true}}` (monitor gone: status unknown). Closing the
connection cancels: `TERM`, then `KILL` after 5 s. Confinement is re-applied
identically to `execve` (DESIGN §14.4).

### `signal`

```json
{"op":"signal","exec_id":"e-1","signal":"TERM"}
```

`exec_id` (preferred) or `pid` (deprecated, kept for 0.2 clients); `signal`
(name or number; default `TERM`). Success: `{"ok":true}` — delivered to the
program's process group. `E_NOT_FOUND` for a stale `exec_id`, a recycled
`pid`, or a pid that is not a live exec of this session.

### `note` (0.5.0)

```json
{"op":"note","kind":"note","text":"…","client":{"protocol_version":2}}
```

`kind` is `"note"` or `"marker"`; `text` is at most 8 KiB (8192 bytes).
The text is stored in the workspace journal **verbatim** and returned
verbatim; it is never parsed, interpreted or executed anywhere. Success:
`{"ok":true,"kind":K,"text":T}`. A journal write failure is returned as
`E_INTERNAL` (the note op is the one place a journal failure is the
response, because the journal write *is* the operation). A `kind` other than
`note`/`marker` or text over 8 KiB is `E_BAD_REQUEST`.

## Version rule (0.5.0)

`client.protocol_version` is an optional integer: the **protocol revision**.
One concept, one number (declared once, as `PROTOCOL_REVISION` in
`src/sessionmeta.rs`; the wire field keeps the historical name
`protocol_version`). It is **additive and backwards compatible in both
directions**:

- The supervisor records its own version in `session.json` as the optional
  `hisn_version` field (e.g. `"0.5.0-dev"`) and its protocol revision as
  `protocol_revision` (this build: `2`), both written at session creation.
  A pre-0.5.0 `session.json` has neither field (or a `null`).
- `hisn_version` is **information only and is never compared** — not by the
  CLI, not by the supervisor. The gate is the integer revision: that is what
  lets a `-dev` build use its own feature (a version-string comparison would
  refuse `note` on every session a pre-bump build creates).
- The CLI reads `protocol_revision` **before** talking to a session. When it
  is absent (= revision 1, i.e. 0.4.3) or below the revision that
  introduced a field or op, the CLI does not send the field/op and prints
  that the session predates the feature. So a 0.5.0 CLI against a
  still-running 0.4.3 supervisor behaves exactly as 0.4.3 for the old ops,
  and for a new op (`note`) it refuses locally rather than sending an op the
  old supervisor would close.
- The supervisor speaks protocol revision `2`. A request that declares a
  revision **newer** than the supervisor's is answered
  `{"ok":false,"error":"E_VERSION", …}` naming the supported revision,
  before any effect and before the connection counts as a client. Requests
  without the field are treated as revision 1 (0.4.3) and behave exactly as
  before. There is no "`E_VERSION` for an unknown op" case: an unknown op
  string fails parsing before the gate and is answered `E_BAD_REQUEST` +
  close, unchanged from 0.4.3.
- `session.json` itself is forward-compatible on the read side: it has no
  `deny_unknown_fields`, so a 0.4.3 reader ignores the new `hisn_version`,
  `protocol_revision` and `workspace` fields, and a 0.5.0 reader loads a
  0.4.3 file with `None`.

## `ls --json` (the on-disk schema)

`hisn ls --json` prints `{"schema":"hisn-ls/v2","sessions":[…]}`.
The v1 fields are kept unchanged; v2 adds `clients`, live `execs` (with
`attach`), `services`, `rootfs`, `members`, `lease`. 0.5.0 adds three additive
fields per session: `hisn_version` (the recorded version, information only,
or `null`), `protocol_revision` (the recorded revision, or `null`) and
`workspace` (`{"id","name"}`) plus a `journal` summary (`{dir,files,bytes}`).
No field is renamed, retyped or removed, so a 0.4.3 client reading a 0.5.0
`ls --json` sees the same keys and values for the ones it knows.

## Compatibility

| direction | behaviour |
| --- | --- |
| 0.4.3 client → 0.5.0 supervisor | Same request and response bytes for the 8 existing ops. `E_VERSION` is only ever answered to a request that declares a version, which a 0.4.3 client never sends. |
| 0.5.0 CLI → 0.4.3 supervisor | The CLI reads `protocol_revision` (absent = 1) and so does not send `protocol_version` nor the `note` op. The 8 old ops are byte-identical. |
| `grants.jsonl` | Unchanged in format and path. The journal is written *in addition*, never instead. |
| `session.json` | Additive optional fields only; old files load unchanged. |
| `ls --json` | Additive keys only; no field changed or removed. |
| exit codes | Unchanged. |

## Observers

An observer request (`sessioninfo`, `inspect`, `list`) never makes its
connection a counted client: it is not listed in `clients[]`, creates no
member, and touches neither the lease nor the idle clock — on request or on
disconnect. A connection becomes a client only on its first *admitted*
(non-observer, authorized) request. A bare connect-and-close (a liveness
probe) is never a client at all.

## What is NOT in this document

The 0.5.0 workspace journal (`hisn journal`, the `note` op, `wseq`, rotation)
is specified in the journal ADR (`docs/adr/0020-workspace-journal.md`) and in
`docs/sessions.md`; this document covers the wire. Network modes, seat
credentials, roles, approvals, tasks, messages, invites and secrets are later
0.5.x steps and are not on this wire yet.

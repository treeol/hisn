# ADR 0021 — Seats with credentials and roles (0.5.1)

Title: Named seats with a credential and a role, same Unix user.
Status: draft. Date: 2026-11-15. Origin: PLAN-0.5 Step 2 (seat credentials and
roles), as fixed by the 0.5.1 design decisions A–J. Builds on ADR 0020
(workspace journal) and ADR 0016 (client identity and the `authorize` seam).

## The boundary, stated plainly (decision A)

Under one Unix user a seat is **attribution and a guard against mistakes, not
a security boundary**. Any process of that user can omit the credential (and
be the owner, decision B) or read the user's files, including this store.
Real separation comes later, with separate Unix users (invites/admission).
Nothing in this design may be relied on to stop a same-uid process that
wants to act. What it does give: two agents of the same user are
distinguishable in the journal, and a seat that is handed a *member* or
*observer* credential cannot, by its own requests, widen paths, kill the
session, or manage seats — it can only stumble into refusals, which are
recorded.

## Decision

- **Seats belong to the workspace, not to a session** (decision C). A seat
  created once is valid in every session of that workspace. The store lives
  in the workspace state directory,
  `$XDG_STATE_HOME/hisn/workspaces/<id>/seats.json`, private to the user
  (dir 0700 via `workspace::ensure_workspace`, file 0600), never inside a
  session's view. A per-session store was rejected: it would force
  re-creation per session and would die with the session, contradicting the
  "set up a project once" goal.
- **A seat has** name, role, creation time, optional expiry, an optional
  revocation flag, and a credential (decision D). The credential is a random
  token of 256 bits, generated from `/dev/urandom`, shown **exactly once**
  at creation, stored **only as a hash** (SHA-256 of the token, hex), compared
  in constant time, and never written to the journal, `grants.jsonl`,
  `session.json`, `ls` output, logs or error messages. A lost credential
  means the seat is revoked and re-created; there is no recovery and no
  second display. SHA-256 rather than a memory-hard KDF (argon2/bcrypt):
  there is no new dependency allowed, `sha2` is already in the tree
  (`Cargo.toml:29`), and the threat model above says the file is readable
  by the same uid anyway — a slow KDF would buy nothing here. When seats
  later belong to other Unix users, the hash column can be re-chosen; the
  wire format does not change.
- **Roles, smallest useful set** (decision E): `owner` (everything, including
  seat management), `member` (run and observe: exec, attach, signal, note,
  and the read-only ops), `observer` (read-only ops only). Every op the
  protocol has is assigned in **one table** in the authorization module;
  no op is unassigned, and adding a `Request` variant fails to compile
  until the table names it. The owner may give a seat the role `owner`
  (delegation), which is how a second administrative seat is made.
- **Owner without a credential** (decision B): a same-uid client that
  presents no credential is the owner, exactly as in 0.5.0. The uid check
  stays the first check in `authz::authorize`. A presented credential that
  is unknown, revoked or expired is **refused and never falls back to
  owner** (decision F) — otherwise a typo would silently grant everything.
- **Refusals** (decision G): a refusal for lack of role uses the existing
  refusal path — `E_UNAUTHORIZED` with a machine-readable message naming
  the seat, the op and the required role — and is journaled with the seat
  name and the op, via the same `log_client` call that journals every
  refusal today. The machine-readable reason is the `message` string plus
  the fact that the error code is `E_UNAUTHORIZED`; no new error code is
  introduced, so an old client that matches on codes keeps working.
  (Structured keys in the error object were considered and dropped: the
  refusal value is also the audit/journal `result`, and a message that
  names seat/op/role is what a program can act on.)
- **Wire: protocol revision 3** (decision I). `client` gains an optional
  `seat_token` field (the credential) — additive under `deny_unknown_fields`,
  so it must be named in `ClientField`. New ops `seat-add`, `seat-ls`,
  `seat-set-role`, `seat-revoke` exist only at revision 3; the 0.5.1 CLI
  refuses with exit 2 and sends nothing to a session below revision 3, as
  `note` does today for revision 1. Tokens are in the request line only —
  never in an exec's `env`, which is the one place a value would be passed
  to the sandbox.
- **Running sessions pick up changes** (decision J): `Shared` holds an
  in-memory seat set with the store's `(mtime, len)` stamp; before each
  authorization decision it stats `seats.json` (one `stat(2)`) and reloads
  only when the stamp changed. One stat per request is the cheapest reliable
  freshness check available — there is no watcher in the tree (Phase 0:
  no inotify/notify; the idle loop reads only in-memory state). A change
  made with `seat set-role` or `seat revoke` therefore takes effect in an
  already running session without a restart. The stamp is `(mtime, len)`
  only; two writes in one timestamp tick that net to the same length could
  leave a supervisor stale — accepted and stated, because the store is
  replaced atomically and a second write in the same tick is the only way
  to miss it, and the next write (any change) or restart recovers. Expiry
  is compared against the clock at every decision, so an expired seat is
  refused even when the file has not changed. A stat failure or a missing
  file clears the in-memory set (fails closed for credentials, never for
  the owner without a credential). Revocation blocks **new requests only**,
  plainly: an already-running exec or attached shell is not killed by a
  revocation; authorization is per request and there is no process
  ownership to cancel through.
- **Credential transport** (decision H): the CLI takes it from
  `HISN_SEAT_TOKEN` or `--seat-token-file PATH`, never from a command-line
  argument (argv is visible in `ps`), and never passes it into a session's
  environment. The session environment is built from scratch
  (`env::scrub` copies only `TERM`, `LANG`, `TZ`, `LC_*`, `PATH`, plus
  `env.pass`/`env.set` and computed names), so a host variable cannot reach
  it unless declared — and the CLI declares nothing. If a token is
  configured and the session is below revision 3, the CLI refuses with
  exit 2 for **every** op, not only the seat ops: dropping the token to
  preserve compatibility would silently run a member/observer request as
  the owner, which decision F forbids. An empty, unreadable or conflicting
  (env and file both) token source is an error, never a silent
  "credential absent".
- **Store robustness**: a `v` version field and a `hash_algo` tag are in the
  file from day one; the only value is `"sha256"`. Writes go through a
  `seats.lock` flock with read-modify-write inside the lock (the
  `sessionmeta` pattern), so concurrent writers do not lose updates; the
  file is replaced atomically (tmp + rename). Directory fsync after rename
  is not promised: no crash-durability claim is made. A truncated or corrupt
  store **fails closed for credentials** (no seat verifies; an unknown token
  is refused) and **never for the owner without a credential** (rule:
  nothing new blocks an existing operation for a client without a seat
  credential). A name is reused only by an explicit new `seat add` after
  revocation, which is a new seat with a new token; the journal records
  both, distinguishable by creation time. Names use the session-name
  charset (letters, digits, `.`, `_`, `-`, no leading `.`) and may not be
  `local`, `hisn-internal`, or match the `<login>@<ip>` label shape.
- **Journal and listings** (Part 5): when a credential was used, journal
  records carry the seat name and role as **server-set** fields
  (`JournalClient.seat`, `JournalClient.role`), and `label_source` says so
  (`"seat"`). The seat name is never the client's label: a credentialed
  client may still send `--client`, and must not be able to impersonate
  another seat in the journal by choosing a label. `hisn journal --seat
  NAME` filters on the server-set seat field; the old label match stays as
  the legacy behaviour for records without a seat field. Seat management
  itself is journaled (who created/changed/revoked which seat, never the
  credential). `ls --json` gains an additive `seats` key per session
  (names and roles, never credentials), emitted only in the on-disk
  `ls --json` output, **never** by the observer-readable `sessioninfo` op —
  seat names are not observer information. `grants.jsonl` gets no new field
  (rule 4): the audit `client` object is byte-identical for a client
  without a credential, and for one with a credential the label is the seat
  name, which needs no new field.
- **Seat management without a session**: `hisn seat add|ls|set-role|revoke`
  with `--workspace` or `--session` writes the store directly (the
  workspace dir is the unit), and the CLI journals the management event
  with the same `Journal` writer the supervisor uses. There is one code
  path (the store module); the supervisor only reads it.
- **Scope fence**: no approvals, tasks, invites, admission of other Unix
  users, messages, network or secrets work. Cross-uid admission stays in
  the invites step with its own ADR; the credential here overrides nothing
  about the R5 peer check, which is untouched.
- **Compatibility** (rule 4): a client that sends no seat credential behaves
  exactly as in 0.5.0 — same requests, same responses, same `grants.jsonl`
  lines. Wakil pinned to 0.4.3 sends nothing new, and the 0.5.1 CLI sends
  nothing new to a session below revision 3.

## Role table

| op | owner | member | observer |
|---|---|---|---|
| grant | yes | no | no |
| revoke | yes | no | no |
| kill | yes | no | no |
| seat-add | yes | no | no |
| seat-ls | yes | no | no |
| seat-set-role | yes | no | no |
| seat-revoke | yes | no | no |
| exec (incl. attach) | yes | yes | no |
| signal | yes | yes | no |
| note | yes | yes | no |
| list | yes | yes | yes |
| inspect | yes | yes | yes |
| sessioninfo | yes | yes | yes |

`kill` is owner-only: it signals the sandbox init (session-wide), which is
not something a "run and observe" seat should do. `seat-ls` is owner-only
for the same reason seat management is: listing seats reveals the workspace's
seat names. (Whether `seat-ls` should be member-readable is a judgement
call; the table above keeps it owner-only and the leak cases assert the
refusal is journaled.) `signal` is member: it reaches only a live exec of
*this* session through a status handle keyed by `exec_id` or by a
non-recycled pid (`supervisor.rs:1357`, `exec_table.by_id`/`by_pid`), never
the sandbox init, so it cannot stand in for `kill`.

Two implementation facts the review asked to have checked, and what the
code actually does:

- **Admission vs authorization.** `serve_conn` calls `Handler::admit`,
  which runs the same `authz::authorize` on the same `SO_PEERCRED` identity
  (`supervisor.rs:1648`), and only registration as a client follows an
  admitted non-observer request (`handle` calls `record_member` /
  `update_client` after `authorize`). A refused request therefore never
  registers and never touches the idle clock. `authorize` stays pure: the
  store stat/reload happens in the supervisor before the call and the seat
  set is passed in through `SessionAuth`.
- **Token secrecy at the boundary.** `parse_request` returns serde's error
  text, which carries line/column but never field *values*, so a malformed
  `seat_token` value is not echoed. `Request` and `ClientField` still
  derive `Debug`, so the supervisor clones the token out of the request at
  dispatch and the field is never formatted after that; the token is never
  copied into `ClientRecord` (which derives `Serialize`) — only the
  server-set seat name and role are. `env::scrub` copies only `TERM`,
  `LANG`, `TZ`, `LC_*`, `PATH` plus declared `env.pass`/`env.set` and
  computed names (`src/env.rs`), and the CLI declares nothing, so
  `HISN_SEAT_TOKEN` cannot reach a session unless a profile explicitly
  passes it — in which case the user chose to declare it. The one exception
  to "statically impossible" is a request's own `env`, which is already
  gated by `env.pass` and `E_ENV_LOCKED` on the server.
- **`seat-add` and the one-time token.** The supervisor generates the token
  and returns it in the response; the response is never logged (the audit
  and journal entries for seat management carry only name, role and the
  acting seat, never the token). If the response is lost, the token is
  unrecoverable by design: revoke and re-create. `hisn seat add` is a
  local store operation, so the token is shown once on stdout with a
  one-line note and is never written anywhere else.
- **`--seat-token-file`.** The file is read as UTF-8, trimmed, and must be
  non-empty; its owner/mode are not checked (a same-uid file is readable
  under decision A anyway), but a missing or unreadable file is an error,
  never a silent "credential absent".

## Alternatives considered

- **Per-session store in `session.json` (`seats[]`).** Rejected: PLAN-0.5
  Step 2 proposed it, but a session dir is pruned with the session and is
  inside the runtime root; a project set up once must outlive sessions.
  Decision C fixes workspace storage.
- **Keypair / SSH certificates instead of a bearer token.** Rejected for
  now: heavier, needs a client-side key agent, and the same-uid boundary
  says the extra machinery buys nothing. A bearer token over the local
  socket matches the existing transport. Certificates remain a later
  provider behind the same wire field.
- **A new error code for role refusals (`E_FORBIDDEN`).** Rejected: the
  existing refusal path is `E_UNAUTHORIZED`; adding a code would change what
  an old client sees only if it sends a credential, which it never does — but
  the machine-readable reason in the message is enough for a program to act
  on, and one code keeps the contract small.
- **Slow KDF for the stored hash.** Rejected: no new dependency, and under
  decision A the file is same-uid readable anyway.

## Consequences

- `hisn seat add|ls|set-role|revoke` exist; `add` prints the credential once.
- `client.seat_token` on the wire at revision 3; four new ops at revision 3.
- The journal answers "who, as which seat, did what"; `grants.jsonl` is
  unchanged in shape for a client without a credential.
- A same-uid process can still omit the credential and be owner: seats are
  attribution and a guard against mistakes, not a boundary. The docs say so
  in plain words everywhere seats are described.

## Tests

- Unit: seat store create/list/set-role/revoke/expiry, modes, symlink and
  owner refusals, concurrent writers, truncated/corrupt store fails closed
  for credentials and never for the owner; every op against every role;
  unknown/revoked/expired credentials; a client without a credential
  unchanged; the documented protocol examples parse through the real types;
  unknown nested `session.json` fields survive rewrites.
- Leak (HOST, unexecuted here, `bash -n` only): L89–L94 seat round trip,
  role refusals journaled with the seat name, revoked/expired refused,
  no-credential unchanged including `grants.jsonl` shape, credential in none
  of journal/`grants.jsonl`/`session.json`/`ls --json`/supervisor log,
  store unreachable from inside a session and `HISN_SEAT_TOKEN` absent from
  the session env, and a live revocation taking effect in a running session.

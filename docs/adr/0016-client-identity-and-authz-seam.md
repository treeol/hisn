# ADR 0016 — Client identity and the single authorization seam

Title: Every control request carries a client record and passes one authorization function.
Status: accepted. Date: 2026-11-07. Origin: PLAN-0.4 §3.

## Decision
- Each request carries a client record: `uid` and `pid` from `SO_PEERCRED` (set by the supervisor, never the client), `label` (`--client`, else `<login>@<ssh-client-ip>` from `SSH_CONNECTION`/`SSH_CLIENT`, else `local`), `label_source`, and a client-generated `req_id`. The supervisor adds its own per-session `seq`.
- Remote identity is the SSH account, which is the uid the sshd already authenticated. The label is audit text and is never used for authorization.
- `authz::authorize(client, session_meta, op) -> Result<Authorized, Refusal>` is the only authorization path. In 0.4 it allows iff `client.uid == meta.owner.uid`. `Op::of(&Request)` has no wildcard arm.
- `Handler::dispatch(client, req, fds, conn)` is the only method that matches on `Request`. It calls `authorize` before the match. Op functions take `Authorized`, whose constructor is private to `authz`.
- The pre-accept R5 ancestry check (`authorize_peer`) stays unchanged and separate. It is about the peer process tree, not the request.
- Session metadata gets `owner` and an append-only `members` list (first seen, last seen) in `session.json`.

## Why
Roles are a later change to the function body and a policy source, not a
protocol, audit, or layout change. Putting the check in one function with a
token that only it can construct makes "every request is authorized" a
property the compiler and a unit test check, not a convention. The label is
self-asserted, so it must not carry authority. The account is the identity.

## Consequences
- The `Handler` trait changes: `authorize(&UnixStream)` is replaced by `dispatch`. This is a 0.4.0 internal change, not a wire change; the wire gains `client` and `req_id` fields (versioned, §3.5).
- Audit lines gain `client`, `seq`, `authz`. Old readers ignore unknown keys.
- Limit: the 0.4 leak test for "another uid is refused" uses a second user-namespace mapping, not a second real account. The real two-account check is a host step.
- The compile-time guarantee covers the token, not the `op` passed to `authorize`. A review rule and a unit test cover that.
- Tests: unit `every_request_variant_maps_to_an_op`, `owner_uid_allowed`, `other_uid_refused_and_audited`, `refusal_is_audited_with_client_record`, `members_append_only_first_seen_preserved`; leak L56, L57, L58.

## Narrowed (PLAN-0.4 §11, round-1 B5/B6)

The `Authorized` token enforces only that op functions run after `authorize`
returned `Ok` in the same module tree. It does not bind a decision to a client,
session, op or peer, and privacy is not "only one function". Internal callers
(startup grants, services) pass an `internal` client record through `authorize`.
R5 peer-ancestry is checked per line as today, separately from request authorization.

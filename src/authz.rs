//! The single authorization seam (0.4.0 step 3, PLAN §3; seats 0.5.1, ADR
//! 0021).
//!
//! Every control request is authorized here, exactly once, before any effect.
//! `authorize(client, meta, req)` is the only function that can produce an
//! [`Authorized`] token, and `Authorized` has a private field, so code outside
//! this module cannot forge one: the dispatch in `supervisor` must call
//! `authorize` to obtain the token that each operation requires.
//!
//! The decision order (decision B first, then the role table):
//!
//! 1. a same-uid client that presents **no** credential is the owner, on
//!    every op, exactly as in 0.5.0;
//! 2. a presented credential is checked against the workspace seat store
//!    (passed in through [`SessionAuth`]; the store is loaded by the
//!    supervisor, never here, and this function stays pure): unknown,
//!    revoked or expired is refused, and never falls back to owner
//!    (decision F);
//! 3. otherwise the seat's role is checked against the one role table
//!    ([`allows`]): every op is assigned, and no op is unassigned.
//!
//! The R5 peer check (`Ctl::authorize`, `authorize_peer`) is a separate,
//! earlier, per-line gate. It stays in place; this seam does not replace it.

use serde::{Deserialize, Serialize};

use crate::control::Request;
use crate::seats::{Role, SeatIdentity};

/// Who is asking. Filled in by the dispatch from SO_PEERCRED and the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// Peer uid from SO_PEERCRED.
    pub uid: u32,
    /// Peer pid from SO_PEERCRED (the client process; may be None for an
    /// internal call).
    pub pid: Option<i32>,
    /// Human label: `--client LABEL`, else `<login>@<ip>` from the SSH
    /// environment, else `local`.
    pub label: String,
    /// Where `label` came from: `flag`, `ssh`, `local`, or `internal`.
    pub label_source: String,
    /// Request id supplied by the client (opaque), if any.
    pub req_id: Option<String>,
    /// Supervisor-assigned sequence number, per request.
    pub seq: u64,
    /// Reserved for a later role model. Always `None` in 0.4.
    pub principal: Option<String>,
    /// 0.5.1 (ADR 0021): the seat the presented credential authenticated,
    /// and its role — server-set from the credential, never from the
    /// client's label. `None` for a client without a credential.
    pub seat: Option<String>,
    pub seat_role: Option<crate::seats::Role>,
}

impl ClientRecord {
    /// The record used by the supervisor's own internal calls (startup
    /// grants, service setup). It acts as the session owner.
    pub fn internal(owner_uid: u32, seq: u64) -> Self {
        Self {
            uid: owner_uid,
            pid: None,
            label: "hisn-internal".into(),
            label_source: "internal".into(),
            req_id: None,
            seq,
            principal: None,
            seat: None,
            seat_role: None,
        }
    }
}

/// The session facts authorization looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionAuth {
    pub owner_uid: u32,
    /// The workspace seat set the supervisor last read (empty for a client
    /// without a credential, which never needs it).
    pub seats: Vec<SeatIdentity>,
}

/// Why a presented credential did not authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    Unknown,
    Revoked,
    Expired,
}

impl CredentialFailure {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialFailure::Unknown => "unknown seat credential",
            CredentialFailure::Revoked => "seat credential revoked",
            CredentialFailure::Expired => "seat credential expired",
        }
    }
}

/// The result of checking a presented credential (which the supervisor
/// reads from the request and hashes against the store before calling
/// `authorize`).
pub enum Credential {
    /// No credential was presented.
    Absent,
    /// The credential matched `name` acting with `role`.
    Authenticated { name: String, role: Role },
    /// A credential was presented and did not authenticate.
    Rejected(CredentialFailure),
}

/// The one role table (decision E): every op, assigned to a role. Adding a
/// `Request` variant without an entry here fails to compile.
pub fn allows(role: Role, op: Op) -> bool {
    match role {
        Role::Owner => true,
        Role::Member => matches!(
            op,
            Op::Exec | Op::Signal | Op::Note | Op::List | Op::Inspect | Op::SessionInfo
        ),
        Role::Observer => matches!(op, Op::List | Op::Inspect | Op::SessionInfo),
    }
}

/// The operation a request performs. Exhaustive over `Request`: adding a
/// request variant fails to compile until it is given an `Op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Grant,
    Revoke,
    List,
    Inspect,
    Kill,
    Exec,
    Signal,
    SessionInfo,
    Note,
    SeatAdd,
    SeatLs,
    SeatSetRole,
    SeatRevoke,
}

impl Op {
    pub fn of(req: &Request) -> Op {
        match req {
            Request::Grant { .. } => Op::Grant,
            Request::Revoke { .. } => Op::Revoke,
            Request::List { .. } => Op::List,
            Request::Inspect { .. } => Op::Inspect,
            Request::Kill { .. } => Op::Kill,
            Request::Exec { .. } => Op::Exec,
            Request::Signal { .. } => Op::Signal,
            Request::SessionInfo { .. } => Op::SessionInfo,
            Request::Note { .. } => Op::Note,
            Request::SeatAdd { .. } => Op::SeatAdd,
            Request::SeatLs { .. } => Op::SeatLs,
            Request::SeatSetRole { .. } => Op::SeatSetRole,
            Request::SeatRevoke { .. } => Op::SeatRevoke,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Op::Grant => "grant",
            Op::Revoke => "revoke",
            Op::List => "list",
            Op::Inspect => "inspect",
            Op::Kill => "kill",
            Op::Exec => "exec",
            Op::Signal => "signal",
            Op::SessionInfo => "sessioninfo",
            Op::Note => "note",
            Op::SeatAdd => "seat-add",
            Op::SeatLs => "seat-ls",
            Op::SeatSetRole => "seat-set-role",
            Op::SeatRevoke => "seat-revoke",
        }
    }

    /// The role this op requires. A seat whose role does not allow the op
    /// is refused with this name in the reason.
    pub fn required_role(self) -> Role {
        if allows(Role::Member, self) {
            Role::Member
        } else if allows(Role::Observer, self) {
            Role::Observer
        } else {
            Role::Owner
        }
    }
}

/// Proof that `authorize` allowed this request. Constructible only here.
///
/// Forging one outside this module does not compile (the private field has no
/// public constructor):
///
/// ```compile_fail
/// let _ = hisn::authz::Authorized { op: hisn::authz::Op::List, role: "x", _private: () };
/// ```
#[derive(Debug)]
pub struct Authorized {
    op: Op,
    role: &'static str,
    _private: (),
}

impl Authorized {
    pub fn op(&self) -> Op {
        self.op
    }

    pub fn role(&self) -> &'static str {
        self.role
    }
}

/// Why a request was refused. No side effects; the caller audits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub op: Op,
    pub reason: String,
}

/// The one authorization decision. The uid check stays the first check
/// (decision B): a same-uid client without a credential is the owner. A
/// presented credential is checked next; a refusal for a lack of role names
/// the seat, the op and the required role (decision G). Every request path
/// reaches the operations only through this.
pub fn authorize(
    client: &ClientRecord,
    session: &SessionAuth,
    credential: &Credential,
    req: &Request,
) -> Result<Authorized, Refusal> {
    let op = Op::of(req);
    // Decision B: no credential + owner uid = owner, on every op.
    // This is also the 0.5.0 behaviour, byte for byte.
    if matches!(credential, Credential::Absent) && client.uid == session.owner_uid {
        return Ok(Authorized {
            op,
            role: "owner",
            _private: (),
        });
    }
    // A presented credential: verified by the supervisor against the store
    // and carried here as `Authenticated`/`Rejected`. It never falls back
    // to owner (decision F) — not even for the owner's own uid.
    match credential {
        Credential::Absent => Err(Refusal {
            op,
            reason: format!(
                "uid {} is not the session owner (uid {})",
                client.uid, session.owner_uid
            ),
        }),
        Credential::Rejected(why) => Err(Refusal {
            op,
            reason: format!("{}: the request is refused", why.as_str()),
        }),
        Credential::Authenticated { name, role } => {
            let role = *role;
            if allows(role, op) {
                Ok(Authorized {
                    op,
                    role: role.as_str(),
                    _private: (),
                })
            } else {
                Err(Refusal {
                    op,
                    reason: format!(
                        "seat {name} (role {}) may not {}: requires {}",
                        role.as_str(),
                        op.name(),
                        op.required_role().as_str()
                    ),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sess() -> SessionAuth {
        SessionAuth {
            owner_uid: 1000,
            seats: Vec::new(),
        }
    }

    fn client(uid: u32) -> ClientRecord {
        ClientRecord {
            uid,
            pid: Some(42),
            label: "local".into(),
            label_source: "local".into(),
            req_id: None,
            seq: 1,
            principal: None,
            seat: None,
            seat_role: None,
        }
    }

    fn cred(name: &str, role: Role) -> Credential {
        Credential::Authenticated {
            name: name.to_string(),
            role,
        }
    }

    fn absent() -> Credential {
        Credential::Absent
    }

    /// Every Request variant maps to an Op, and each Op has a stable name.
    #[test]
    fn every_request_variant_maps_to_an_op() {
        let cases: Vec<(Request, Op)> = vec![
            (
                Request::Grant {
                    path: "/p".into(),
                    mode: Default::default(),
                    recursive: false,
                    client: None,
                },
                Op::Grant,
            ),
            (
                Request::Revoke {
                    path: "/p".into(),
                    hard: false,
                    kill_holders: false,
                    client: None,
                },
                Op::Revoke,
            ),
            (Request::List { client: None }, Op::List),
            (Request::Inspect { client: None }, Op::Inspect),
            (
                Request::Kill {
                    signal: "TERM".into(),
                    client: None,
                },
                Op::Kill,
            ),
            (
                Request::Exec {
                    argv: vec!["true".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    tty: false,
                    attach: false,
                    client: None,
                },
                Op::Exec,
            ),
            (
                Request::Signal {
                    exec_id: None,
                    pid: None,
                    signal: "TERM".into(),
                    client: None,
                },
                Op::Signal,
            ),
        ];
        for (req, want) in cases {
            assert_eq!(Op::of(&req), want);
            assert!(!want.name().is_empty());
        }
    }

    #[test]
    fn owner_uid_is_allowed() {
        let a = authorize(
            &client(1000),
            &sess(),
            &absent(),
            &Request::List { client: None },
        )
        .unwrap();
        assert_eq!(a.op(), Op::List);
        assert_eq!(a.role(), "owner");
    }

    #[test]
    fn foreign_uid_is_refused_with_op_and_reason() {
        let r = authorize(
            &client(1001),
            &sess(),
            &absent(),
            &Request::Inspect { client: None },
        )
        .unwrap_err();
        assert_eq!(r.op, Op::Inspect);
        assert!(r.reason.contains("not the session owner"));
    }

    #[test]
    fn internal_record_acts_as_owner() {
        let c = ClientRecord::internal(1000, 7);
        assert_eq!(c.label_source, "internal");
        assert!(authorize(&c, &sess(), &absent(), &Request::List { client: None }).is_ok());
    }

    /// The seam must reach every request path. Each variant of Request is
    /// authorized through `authorize`; a refused foreign uid gets a refusal
    /// for every variant (so none can bypass the decision). `note` is
    /// included (item 5): an unauthorized peer's note is refused at the
    /// seam — the supervisor audits the refusal in `handle` before any
    /// journal write.
    #[test]
    fn every_variant_goes_through_authorize() {
        let reqs = [
            Request::Grant {
                path: "/p".into(),
                mode: Default::default(),
                recursive: false,
                client: None,
            },
            Request::Revoke {
                path: "/p".into(),
                hard: false,
                kill_holders: false,
                client: None,
            },
            Request::List { client: None },
            Request::Inspect { client: None },
            Request::Kill {
                signal: "TERM".into(),
                client: None,
            },
            Request::Exec {
                argv: vec!["true".into()],
                cwd: None,
                env: BTreeMap::new(),
                tty: false,
                attach: false,
                client: None,
            },
            Request::Signal {
                exec_id: None,
                pid: None,
                signal: "TERM".into(),
                client: None,
            },
            Request::SessionInfo { client: None },
            Request::Note {
                kind: "note".into(),
                text: "hi".into(),
                client: None,
            },
        ];
        for r in &reqs {
            assert!(authorize(&client(999), &sess(), &absent(), r).is_err());
        }
        // The refusal names the op, so the supervisor's audit line does too.
        let refusal = authorize(
            &client(999),
            &sess(),
            &absent(),
            &Request::Note {
                kind: "note".into(),
                text: "hi".into(),
                client: None,
            },
        )
        .unwrap_err();
        assert_eq!(refusal.op, Op::Note);
        assert!(refusal.reason.contains("not the session owner"));
    }

    fn every_op() -> Vec<(Op, Request)> {
        vec![
            (
                Op::SeatAdd,
                Request::SeatAdd {
                    name: "bob".into(),
                    role: None,
                    expires: None,
                    client: None,
                },
            ),
            (Op::SeatLs, Request::SeatLs { client: None }),
            (
                Op::SeatSetRole,
                Request::SeatSetRole {
                    name: "bob".into(),
                    role: "member".into(),
                    client: None,
                },
            ),
            (
                Op::SeatRevoke,
                Request::SeatRevoke {
                    name: "bob".into(),
                    client: None,
                },
            ),
            (
                Op::Grant,
                Request::Grant {
                    path: "/p".into(),
                    mode: Default::default(),
                    recursive: false,
                    client: None,
                },
            ),
            (
                Op::Revoke,
                Request::Revoke {
                    path: "/p".into(),
                    hard: false,
                    kill_holders: false,
                    client: None,
                },
            ),
            (Op::List, Request::List { client: None }),
            (Op::Inspect, Request::Inspect { client: None }),
            (
                Op::Kill,
                Request::Kill {
                    signal: "TERM".into(),
                    client: None,
                },
            ),
            (
                Op::Exec,
                Request::Exec {
                    argv: vec!["true".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    tty: false,
                    attach: false,
                    client: None,
                },
            ),
            (
                Op::Signal,
                Request::Signal {
                    exec_id: None,
                    pid: None,
                    signal: "TERM".into(),
                    client: None,
                },
            ),
            (Op::SessionInfo, Request::SessionInfo { client: None }),
            (
                Op::Note,
                Request::Note {
                    kind: "note".into(),
                    text: "hi".into(),
                    client: None,
                },
            ),
        ]
    }

    /// Every op against every role (the table, both directions).
    #[test]
    fn every_op_against_every_role() {
        for (op, req) in every_op() {
            assert!(allows(Role::Owner, op), "{op:?}");
            assert!(
                authorize(&client(1000), &sess(), &cred("o", Role::Owner), &req).is_ok(),
                "{op:?}"
            );
            assert_eq!(
                allows(Role::Member, op),
                matches!(
                    op,
                    Op::Exec | Op::Signal | Op::Note | Op::List | Op::Inspect | Op::SessionInfo
                ),
                "{op:?}"
            );
            assert_eq!(
                allows(Role::Observer, op),
                matches!(op, Op::List | Op::Inspect | Op::SessionInfo),
                "{op:?}"
            );
        }
    }

    /// A member is refused for grant/revoke/kill with the seat, the op and
    /// the required role in the reason; an observer for exec too.
    #[test]
    fn role_refusals_name_the_seat_and_the_required_role() {
        let member = cred("bob", Role::Member);
        for (op, req) in every_op() {
            if !allows(Role::Member, op) {
                let r = authorize(&client(1000), &sess(), &member, &req).unwrap_err();
                assert_eq!(r.op, op);
                assert!(r.reason.contains("bob"), "{}", r.reason);
                assert!(r.reason.contains("owner"), "{}", r.reason);
            }
        }
        let observer = cred("carol", Role::Observer);
        let r = authorize(
            &client(1000),
            &sess(),
            &observer,
            &Request::Exec {
                argv: vec!["true".into()],
                cwd: None,
                env: BTreeMap::new(),
                tty: false,
                attach: false,
                client: None,
            },
        )
        .unwrap_err();
        assert!(
            r.reason.contains("carol") && r.reason.contains("member"),
            "{}",
            r.reason
        );
    }

    /// Unknown, revoked and expired credentials are refused — including for
    /// the owner's own uid (never a fallback to owner, decision F).
    #[test]
    fn bad_credentials_are_refused_even_for_the_owner_uid() {
        for why in [
            CredentialFailure::Unknown,
            CredentialFailure::Revoked,
            CredentialFailure::Expired,
        ] {
            let c = Credential::Rejected(why);
            for uid in [1000, 1001] {
                let r = authorize(&client(uid), &sess(), &c, &Request::List { client: None })
                    .unwrap_err();
                assert_eq!(r.op, Op::List);
                assert!(r.reason.contains(why.as_str()), "{}", r.reason);
            }
        }
    }

    /// A client without a credential is unchanged (0.5.0, rule 4): every op
    /// allowed for the owner's uid, refused for a foreign uid.
    #[test]
    fn a_client_without_a_credential_is_unchanged() {
        for (op, req) in every_op() {
            assert!(
                authorize(&client(1000), &sess(), &absent(), &req).is_ok(),
                "{op:?}"
            );
            assert!(
                authorize(&client(1001), &sess(), &absent(), &req).is_err(),
                "{op:?}"
            );
        }
    }

    /// The seat ops are owner-only in the table.
    #[test]
    fn seat_ops_are_owner_only() {
        for op in [Op::SeatAdd, Op::SeatLs, Op::SeatSetRole, Op::SeatRevoke] {
            assert_eq!(op.required_role(), Role::Owner);
            assert!(!allows(Role::Member, op));
            assert!(!allows(Role::Observer, op));
            assert!(allows(Role::Owner, op));
        }
    }
}

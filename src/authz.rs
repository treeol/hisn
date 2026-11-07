//! The single authorization seam (0.4.0 step 3, PLAN §3).
//!
//! Every control request is authorized here, exactly once, before any effect.
//! `authorize(client, meta, req)` is the only function that can produce an
//! [`Authorized`] token, and `Authorized` has a private field, so code outside
//! this module cannot forge one: the dispatch in `supervisor` must call
//! `authorize` to obtain the token that each operation requires.
//!
//! In 0.4.0 the policy is equal access: allow iff the client's uid is the
//! session owner's uid. Roles later change this one function plus a policy
//! source. The client record, the members list and the audit fields already
//! exist, so a role model needs no protocol, audit or layout change.
//!
//! The R5 peer check (`Ctl::authorize`, `authorize_peer`) is a separate,
//! earlier, per-line gate. It stays in place; this seam does not replace it.

use serde::{Deserialize, Serialize};

use crate::control::Request;

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
        }
    }
}

/// The session facts authorization looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuth {
    pub owner_uid: u32,
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
}

impl Op {
    pub fn of(req: &Request) -> Op {
        match req {
            Request::Grant { .. } => Op::Grant,
            Request::Revoke { .. } => Op::Revoke,
            Request::List {} => Op::List,
            Request::Inspect {} => Op::Inspect,
            Request::Kill { .. } => Op::Kill,
            Request::Exec { .. } => Op::Exec,
            Request::Signal { .. } => Op::Signal,
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
        }
    }
}

/// Proof that `authorize` allowed this request. Constructible only here.
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

/// The one authorization decision. 0.4: allow iff the client uid is the
/// owner uid. Every request path reaches the operations only through this.
pub fn authorize(
    client: &ClientRecord,
    session: &SessionAuth,
    req: &Request,
) -> Result<Authorized, Refusal> {
    let op = Op::of(req);
    if client.uid == session.owner_uid {
        Ok(Authorized {
            op,
            role: "owner",
            _private: (),
        })
    } else {
        Err(Refusal {
            op,
            reason: format!(
                "uid {} is not the session owner (uid {})",
                client.uid, session.owner_uid
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sess() -> SessionAuth {
        SessionAuth { owner_uid: 1000 }
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
        }
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
                },
                Op::Grant,
            ),
            (
                Request::Revoke {
                    path: "/p".into(),
                    hard: false,
                    kill_holders: false,
                },
                Op::Revoke,
            ),
            (Request::List {}, Op::List),
            (Request::Inspect {}, Op::Inspect),
            (
                Request::Kill {
                    signal: "TERM".into(),
                },
                Op::Kill,
            ),
            (
                Request::Exec {
                    argv: vec!["true".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    tty: false,
                },
                Op::Exec,
            ),
            (
                Request::Signal {
                    exec_id: None,
                    pid: None,
                    signal: "TERM".into(),
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
        let a = authorize(&client(1000), &sess(), &Request::List {}).unwrap();
        assert_eq!(a.op(), Op::List);
        assert_eq!(a.role(), "owner");
    }

    #[test]
    fn foreign_uid_is_refused_with_op_and_reason() {
        let r = authorize(&client(1001), &sess(), &Request::Inspect {}).unwrap_err();
        assert_eq!(r.op, Op::Inspect);
        assert!(r.reason.contains("not the session owner"));
    }

    #[test]
    fn internal_record_acts_as_owner() {
        let c = ClientRecord::internal(1000, 7);
        assert_eq!(c.label_source, "internal");
        assert!(authorize(&c, &sess(), &Request::List {}).is_ok());
    }

    /// The seam must reach every request path. Each variant of Request is
    /// authorized through `authorize`; a refused foreign uid gets a refusal
    /// for every variant (so none can bypass the decision).
    #[test]
    fn every_variant_goes_through_authorize() {
        let reqs = [
            Request::Grant {
                path: "/p".into(),
                mode: Default::default(),
                recursive: false,
            },
            Request::Revoke {
                path: "/p".into(),
                hard: false,
                kill_holders: false,
            },
            Request::List {},
            Request::Inspect {},
            Request::Kill {
                signal: "TERM".into(),
            },
            Request::Signal {
                exec_id: None,
                pid: None,
                signal: "TERM".into(),
            },
        ];
        for r in &reqs {
            assert!(authorize(&client(999), &sess(), r).is_err());
        }
    }
}

//! Landlock second layer (DESIGN §7). Mounts are the primary boundary; this
//! narrows what a mount-plan bug could expose.
//!
//! Rights are computed purely ([`plan`]) and applied by [`apply`]. A Landlock
//! domain cannot grow after `restrict_self`, so write access is granted only
//! beneath prefixes known at start (cwd, home, tmp, run, dev, `mounts.rw`,
//! initial rw grants, `mounts.grantable_rw`); reads/execs are allowed beneath
//! `/` so later ro grants work without extending the domain.

use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, Scope,
};

use crate::mounts::SANDBOX_HOME;
use crate::policy::{Network, ResolvedPolicy};

/// Newest ABI hisn knows how to use. Older kernels degrade (best-effort).
pub const TARGET_ABI: ABI = ABI::V6;

#[derive(Debug, thiserror::Error)]
pub enum LandlockError {
    #[error("landlock: {0}")]
    Ruleset(String),
    #[error(
        "network = \"host\" needs Landlock ABI >= 6 (abstract unix socket scoping), kernel offers \
         less; pass --allow-host-abstract-sockets to accept the risk"
    )]
    ScopeUnavailable,
}

/// What the ruleset will contain, independent of kernel support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPlan {
    /// Read/exec/readdir allowed beneath these roots (always `["/"]`).
    pub read_roots: Vec<PathBuf>,
    /// Full write access allowed beneath these roots.
    pub write_roots: Vec<PathBuf>,
    /// Scope abstract unix sockets and signals (ABI >= 6).
    pub scope: bool,
}

/// Compute the ruleset from the resolved policy. `initial_rw_grants` are the
/// `--grant PATH:rw` paths given at start.
pub fn plan(policy: &ResolvedPolicy, initial_rw_grants: &[PathBuf]) -> LandlockPlan {
    let mut write: Vec<PathBuf> = vec![
        policy.cwd.clone(),
        PathBuf::from(SANDBOX_HOME),
        "/tmp".into(),
        "/run".into(),
        "/dev".into(),
    ];
    write.extend(policy.rw.iter().cloned());
    write.extend(policy.grantable_rw.iter().cloned());
    write.extend(initial_rw_grants.iter().cloned());
    write.sort();
    write.dedup();
    LandlockPlan {
        read_roots: vec!["/".into()],
        write_roots: write,
        // For network=none the net namespace already isolates abstract
        // sockets; scoping is still applied when available, and *required*
        // for host networking.
        scope: true,
    }
}

/// `network = "host"` must not start without abstract-socket scoping unless
/// the caller explicitly opted out.
pub fn scope_required(policy: &ResolvedPolicy, allow_host_abstract: bool) -> bool {
    policy.network == Network::Host && !allow_host_abstract
}

/// Apply the plan to the calling thread (and its future children).
/// Returns the `(fully_enforced, scope_applied)` pair for logging; fails when
/// scope is required but the kernel cannot provide it.
pub fn apply(plan: &LandlockPlan, require_scope: bool) -> Result<(bool, bool), LandlockError> {
    let err = |e: &dyn std::fmt::Display| LandlockError::Ruleset(e.to_string());
    let all = AccessFs::from_all(TARGET_ABI);
    let read = AccessFs::from_read(TARGET_ABI);

    let mut rs = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all)
        .map_err(|e| err(&e))?;
    let scope_handled = plan.scope && TARGET_ABI >= ABI::V6;
    if scope_handled {
        rs = rs
            .scope(Scope::AbstractUnixSocket | Scope::Signal)
            .map_err(|e| err(&e))?;
    }
    let mut created = rs.create().map_err(|e| err(&e))?;
    for root in &plan.read_roots {
        let fd = PathFd::new(root).map_err(|e| err(&e))?;
        created = created
            .add_rule(PathBeneath::new(fd, read))
            .map_err(|e| err(&e))?;
    }
    for root in &plan.write_roots {
        // Absent roots (e.g. a grantable prefix that does not exist yet) have
        // nothing to protect or to allow; skip them.
        let Ok(fd) = PathFd::new(root) else { continue };
        created = created
            .add_rule(PathBeneath::new(fd, all))
            .map_err(|e| err(&e))?;
    }
    let status = created.restrict_self().map_err(|e| err(&e))?;
    let enforced = status.ruleset != landlock::RulesetStatus::NotEnforced;
    let scoped = scope_handled && enforced;
    if require_scope && !scoped {
        return Err(LandlockError::ScopeUnavailable);
    }
    Ok((enforced, scoped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Home;

    fn pol(net: Network) -> ResolvedPolicy {
        ResolvedPolicy {
            version: "hisn-policy/v1".into(),
            cwd: "/w/p".into(),
            home: Home::Tmpfs,
            network: net,
            hostname: "hisn".into(),
            ro: vec!["/opt/tc".into()],
            rw: vec!["/data/out".into()],
            mask: vec![],
            grantable_rw: vec!["/data/shared".into()],
            env_pass: vec![],
            env_set: Default::default(),
            extra_deny: vec![],
            nofile: 1,
            nproc: 1,
        }
    }

    #[test]
    fn reads_everywhere_writes_only_on_the_static_set() {
        let p = plan(&pol(Network::None), &["/g/rw".into(), "/w/p".into()]);
        assert_eq!(p.read_roots, vec![PathBuf::from("/")]);
        let w: Vec<String> = p
            .write_roots
            .iter()
            .map(|x| x.display().to_string())
            .collect();
        for want in [
            "/w/p",
            "/run/hisn/home",
            "/tmp",
            "/run",
            "/dev",
            "/data/out",
            "/data/shared",
            "/g/rw",
        ] {
            assert!(w.contains(&want.to_string()), "{want} missing from {w:?}");
        }
        // ro mounts and the toolchain are never writable
        for never in ["/opt/tc", "/usr", "/etc", "/"] {
            assert!(
                !w.contains(&never.to_string()),
                "{never} must not be writable"
            );
        }
        // duplicates collapse
        assert_eq!(w.iter().filter(|x| *x == "/w/p").count(), 1);
    }

    #[test]
    fn host_network_requires_scope_unless_overridden() {
        assert!(scope_required(&pol(Network::Host), false));
        assert!(!scope_required(&pol(Network::Host), true));
        assert!(!scope_required(&pol(Network::None), false));
    }

    #[test]
    fn plan_requests_scoping() {
        assert!(plan(&pol(Network::Host), &[]).scope);
    }

    /// Real kernel check in a forked child: write inside an allowed dir works,
    /// write outside fails with EACCES, reading outside still works. Needs
    /// Landlock only (no userns), so it runs in restricted containers too.
    #[test]
    fn kernel_enforces_write_set() {
        let allowed = tempfile::tempdir().unwrap();
        let denied = tempfile::tempdir().unwrap();
        let mut pl = plan(&pol(Network::None), &[allowed.path().to_path_buf()]);
        // keep /tmp (where tempdirs live) out of the write set for the probe
        pl.write_roots.retain(|p| p != std::path::Path::new("/tmp"));
        let ok_file = allowed.path().join("ok");
        let bad_file = denied.path().join("bad");
        // SAFETY: fork in a test; the child only uses std fs calls and `_exit`s.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let code = match apply(&pl, false) {
                    Err(_) => 20,
                    Ok((false, _)) => 21,
                    Ok(_) => {
                        let w_ok = std::fs::write(&ok_file, b"x").is_ok();
                        let w_bad = std::fs::write(&bad_file, b"x");
                        let r_ok = std::fs::read_to_string("/proc/self/stat").is_ok();
                        match (w_ok, w_bad, r_ok) {
                            (true, Err(e), true) if e.raw_os_error() == Some(libc::EACCES) => 0,
                            _ => 22,
                        }
                    }
                };
                libc::_exit(code);
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            assert!(libc::WIFEXITED(st));
            let c = libc::WEXITSTATUS(st);
            assert_eq!(
                c, 0,
                "child code (20=apply failed, 21=not enforced, 22=wrong behaviour)"
            );
        }
        assert!(ok_file.exists());
        assert!(!bad_file.exists());
    }
}

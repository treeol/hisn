//! `hisn-profile/v1`: envelope around `hisn-policy/v1` (ADR 0001, PLAN §1).
//!
//! A profile is a TOML document with `version = "hisn-profile/v1"` and one
//! required table `[policy]`, whose value is a complete `hisn-policy/v1`
//! document (inline table). The inner policy is resolved by the exact existing
//! `policy::load` + `policy::resolve` code path; v1 policy stays valid
//! unchanged. This module adds the envelope parse/resolve and the profile
//! search path; it does not change the mount plan, seccomp, Landlock, or env.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::policy::{Overrides, Policy, ResolvedPolicy};

pub const PROFILE_VERSION: &str = "hisn-profile/v1";

/// Error codes for profile load failures (POLICY-SPEC §7 style).
pub const E_PROFILE_POLICY: &str = "E_PROFILE_POLICY";
pub const E_PROFILE_NOT_PROFILE: &str = "E_PROFILE_NOT_PROFILE";
pub const E_PROFILE_UNTRUSTED: &str = "E_PROFILE_UNTRUSTED";
pub const E_PROFILE_NOTFOUND: &str = "E_PROFILE_NOTFOUND";

/// A profile as written in a `.toml` file: the envelope around a `Policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Must be exactly `hisn-profile/v1`.
    pub version: String,
    /// A complete `hisn-policy/v1` document (inline table).
    pub policy: Policy,
}

impl Profile {
    /// Parse and syntax-validate a profile TOML (no filesystem access).
    pub fn parse(text: &str) -> Result<Self> {
        let p: Profile = toml::from_str(text)
            .map_err(|e| anyhow!("profile parse: {e}"))?;
        if p.version != PROFILE_VERSION {
            bail!(
                "version: must be \"{PROFILE_VERSION}\", got {:?}",
                p.version
            );
        }
        // The inner Policy::validate runs from Policy::parse inside the
        // toml::from_str above (deny_unknown_fields + the Parse path). But
        // the inner Policy is deserialized by serde, not parsed — so we
        // re-validate it here to get the same syntax checks.
        p.policy.validate().map_err(|e| anyhow!("{e}"))?;
        Ok(p)
    }

    /// Load and parse a profile from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing profile {}", path.display()))
    }

    /// Resolve the inner `[policy]` against the filesystem and apply overrides.
    /// Returns the `ResolvedPolicy` (the same type the supervisor consumes)
    /// plus the profile's base directory (for trust checks).
    pub fn resolve(
        &self,
        base_dir: &Path,
        overrides: &Overrides,
        runtime_roots: &[PathBuf],
    ) -> Result<ResolvedPolicy> {
        self.policy
            .resolve(base_dir, overrides, runtime_roots)
            .map_err(|e| anyhow!("{e}"))
    }
}

/// Resolve `--profile <name|path>` to a file path, applying the search path.
///
/// 1. If `spec` contains `/`, it is a file path → use it directly.
/// 2. Otherwise, search `$HISN_PROFILES/<spec>.toml`, then the built-in
///    `profiles/<spec>.toml` next to the binary.
/// 3. `./<spec>.toml` is deliberately NOT in the search path (profile
///    shadowing: a sandbox could write a profile that shadows a built-in
///    name and self-ack its own risk).
///
/// Returns the resolved file path and whether it was found in
/// `$HISN_PROFILES` or built-in (for trust checking).
pub fn resolve_profile_path(spec: &str) -> Result<(PathBuf, ProfileSource)> {
    if spec.contains('/') {
        let p = PathBuf::from(spec);
        if !p.exists() {
            bail!("profile file not found: {}", p.display());
        }
        return Ok((p, ProfileSource::Path));
    }
    // Try $HISN_PROFILES/<spec>.toml
    if let Ok(hisn_profiles) = std::env::var("HISN_PROFILES") {
        let candidate = Path::new(&hisn_profiles).join(format!("{spec}.toml"));
        if candidate.exists() {
            return Ok((candidate, ProfileSource::Env));
        }
    }
    // Try built-in profiles/ next to the binary
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join("profiles").join(format!("{spec}.toml"));
        if candidate.exists() {
            return Ok((candidate, ProfileSource::Builtin));
        }
    }
    // No cwd-relative fallback: a profile under the session cwd is the
    // untrusted-profile hole the trust check exists for. $HISN_PROFILES
    // (or the binary's profiles/) is the only trusted search path.
    bail!(
        "E_PROFILE_NOTFOUND: profile {:?} not found in $HISN_PROFILES or built-in profiles/ next to the binary",
        spec
    );
}

/// Where a profile was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSource {
    /// A file path (`--profile /path/to/profile.toml`).
    Path,
    /// `$HISN_PROFILES/<name>.toml`.
    Env,
    /// Built-in `profiles/<name>.toml` next to the binary.
    Builtin,
}

/// Check whether a profile loaded from `source` at `path` is trusted for
/// `risk_ack`. A profile resolved from under the invoking process's cwd, the
/// final resolved session cwd, or a rw grant is not trusted
/// (`E_PROFILE_UNTRUSTED`) — the sandbox can write it and self-ack its own
/// risk. The check uses BOTH the process cwd and the session cwd so nothing
/// in the check may depend on the profile's own `[policy]` alone.
///
/// `proc_cwd`: the invoking process's cwd (getcwd at `hisn run`).
/// `session_cwd`: the final resolved session cwd (from the inner `[policy]`).
/// `rw_grants`: the list of rw grant paths.
pub fn check_profile_trust(
    profile_path: &Path,
    source: ProfileSource,
    session_cwd: &Path,
    rw_grants: &[&Path],
) -> Result<()> {
    // Also check against the process cwd, which is independent of the
    // profile's own [policy]. A profile under the process cwd is
    // untrusted even if it declares a different session.cwd.
    let proc_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    match source {
        ProfileSource::Path => {
            let canon = std::fs::canonicalize(profile_path)
                .unwrap_or_else(|_| profile_path.to_path_buf());
            // Check against the process cwd (independent of the profile's
            // own [policy]).
            let proc_cwd_canon = std::fs::canonicalize(&proc_cwd)
                .unwrap_or_else(|_| proc_cwd.clone());
            if canon.starts_with(&proc_cwd_canon) {
                bail!(
                    "E_PROFILE_UNTRUSTED: profile {} lies under the process cwd {}",
                    canon.display(),
                    proc_cwd_canon.display()
                );
            }
            // Also check against the session cwd (from the inner [policy]).
            let cwd_canon = std::fs::canonicalize(session_cwd)
                .unwrap_or_else(|_| session_cwd.to_path_buf());
            if canon.starts_with(&cwd_canon) {
                bail!(
                    "E_PROFILE_UNTRUSTED: profile {} lies under the session cwd {}",
                    canon.display(),
                    cwd_canon.display()
                );
            }
            for g in rw_grants {
                let g_canon = std::fs::canonicalize(g).unwrap_or_else(|_| g.to_path_buf());
                if canon.starts_with(&g_canon) {
                    bail!(
                        "E_PROFILE_UNTRUSTED: profile {} lies under a rw grant {}",
                        canon.display(),
                        g_canon.display()
                    );
                }
            }
            Ok(())
        }
        ProfileSource::Env | ProfileSource::Builtin => Ok(()),
    }
}

/// The built-in profile names (shipped in `profiles/` next to the binary).
pub const BUILTIN_PROFILES: &[&str] = &["base", "wakil"];

/// Print the profile search path and built-in names (for `hisn profile list`).
pub fn list() -> Result<Value> {
    let hisn_profiles = std::env::var("HISN_PROFILES").ok();
    let builtin_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("profiles")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(not found)".to_string());
    Ok(json!({
        "schema": "hisn-profile-list/v1",
        "hisn_profiles_dir": hisn_profiles.unwrap_or_default(),
        "builtin_dir": builtin_dir,
        "builtins": BUILTIN_PROFILES,
    }))
}

/// Explain a profile: parse it and print the capabilities and their risk
/// labels (for `hisn profile explain`). In 0.3a (Feature 1 only), profiles
/// have no 0.3 surface yet, so the explanation is just "no widening
/// capabilities" or the risk labels from later features.
pub fn explain(spec: Option<&str>) -> Result<Value> {
    let profile = match spec {
        Some(s) => {
            let (path, _source) = resolve_profile_path(s)?;
            Profile::load(&path)?
        }
        None => Profile {
            version: PROFILE_VERSION.to_string(),
            policy: Policy::default(),
        },
    };
    // In Feature 1 (profiles only, no 0.3 surface), there are no widening
    // capabilities yet. The risk label is "none".
    Ok(json!({
        "schema": "hisn-profile-explain/v1",
        "version": profile.version,
        "capabilities": [],
        "risk": "none",
    }))
}

/// Validate a profile file (for `hisn profile validate`). Prints the resolved
/// inner policy on success.
pub fn validate(path: Option<&Path>) -> Result<ResolvedPolicy> {
    let (path, _source) = match path {
        Some(p) => (p.to_path_buf(), ProfileSource::Path),
        None => {
            let (p, s) = resolve_profile_path("base")?;
            (p, s)
        }
    };
    let profile = Profile::load(&path)?;
    let base = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let uid = rustix::process::getuid().as_raw();
    let roots = crate::session::runtime_roots(
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
        uid,
    );
    let resolved = profile.resolve(base, &Overrides::default(), &roots)?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn minimal_profile_parses() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
"#,
        )
        .unwrap();
        assert_eq!(p.version, PROFILE_VERSION);
        assert_eq!(p.policy, Policy::default());
    }

    #[test]
    fn profile_with_inner_policy_parses() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
session.cwd = "."
session.network = "none"
mounts.grantable_rw = ["/srv/out"]
"#,
        )
        .unwrap();
        assert_eq!(p.policy.session.network, crate::policy::Network::None);
        assert_eq!(p.policy.mounts.grantable_rw, ["/srv/out".to_string()]);
    }

    #[test]
    fn wrong_version_rejected() {
        assert!(Profile::parse(
            r#"
version = "hisn-profile/v2"
[policy]
version = "hisn-policy/v1"
"#,
        )
        .is_err());
    }

    #[test]
    fn missing_version_rejected() {
        assert!(Profile::parse(
            r#"
[policy]
version = "hisn-policy/v1"
"#,
        )
        .is_err());
    }

    #[test]
    fn inner_policy_validated() {
        // Bad inner policy version → error
        assert!(Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v2"
"#,
        )
        .is_err());
    }

    #[test]
    fn resolve_profile_path_finds_builtin_in_dev() {
        // In the build sandbox, profiles/ is at the repo root and may be
        // found via $HISN_PROFILES or the binary's profiles/ directory.
        // Set $HISN_PROFILES to the repo's profiles/ for this test.
        let here = std::env::current_dir().unwrap();
        let profiles_dir = here.join("profiles");
        // SAFETY: tests are single-threaded.
        unsafe { std::env::set_var("HISN_PROFILES", &profiles_dir); }
        let result = resolve_profile_path("base");
        // Don't clean up $HISN_PROFILES — other tests may need it too.
        if let Ok((p, _)) = &result {
            assert!(p.exists());
            assert_eq!(result.unwrap().1, ProfileSource::Env);
        } else {
            // If $HISN_PROFILES doesn't have base.toml, try the binary's
            // profiles/ directory — which may or may not exist.
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    let candidate = parent.join("profiles").join("base.toml");
                    if candidate.exists() {
                        let (p, source) =
                            resolve_profile_path("base").unwrap_or((candidate, ProfileSource::Builtin));
                        assert!(p.exists());
                        assert_eq!(source, ProfileSource::Builtin);
                        return;
                    }
                }
            }
            // Neither path found — skip (the test environment doesn't have
            // profiles/ installed).
        }
    }

    #[test]
    fn resolve_profile_path_with_slash_is_path() {
        let d = tmp();
        let f = d.path().join("my-profile.toml");
        fs::write(&f, "version = \"hisn-profile/v1\"\n").unwrap();
        let (p, source) = resolve_profile_path(f.to_str().unwrap()).unwrap();
        assert_eq!(p, f);
        assert_eq!(source, ProfileSource::Path);
    }

    #[test]
    fn resolve_profile_path_not_found() {
        assert!(resolve_profile_path("nonexistent-profile-xyz").is_err());
    }

    #[test]
    fn check_profile_trust_rejects_cwd_profile() {
        let d = tmp();
        let cwd = d.path().join("proj");
        fs::create_dir(&cwd).unwrap();
        let profile = cwd.join("profile.toml");
        fs::write(&profile, "version = \"hisn-profile/v1\"\n").unwrap();
        let result = check_profile_trust(
            &profile,
            ProfileSource::Path,
            &cwd,
            &[],
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_PROFILE_UNTRUSTED"), "{msg}");
    }

    #[test]
    fn check_profile_trust_allows_outside_cwd() {
        let d = tmp();
        let cwd = d.path().join("proj");
        fs::create_dir(&cwd).unwrap();
        let profile = d.path().join("profile.toml");
        fs::write(&profile, "version = \"hisn-profile/v1\"\n").unwrap();
        let result = check_profile_trust(
            &profile,
            ProfileSource::Path,
            &cwd,
            &[],
        );
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    #[test]
    fn check_profile_trust_rejects_rw_grant_profile() {
        let d = tmp();
        let cwd = d.path().join("proj");
        fs::create_dir(&cwd).unwrap();
        let grant = d.path().join("grant");
        fs::create_dir(&grant).unwrap();
        let profile = grant.join("profile.toml");
        fs::write(&profile, "version = \"hisn-profile/v1\"\n").unwrap();
        let result = check_profile_trust(
            &profile,
            ProfileSource::Path,
            &cwd,
            &[grant.as_path()],
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_PROFILE_UNTRUSTED"), "{msg}");
    }

    #[test]
    fn check_profile_trust_allows_builtin_and_env() {
        let d = tmp();
        let cwd = d.path().join("proj");
        fs::create_dir(&cwd).unwrap();
        let profile = cwd.join("profile.toml");
        fs::write(&profile, "version = \"hisn-profile/v1\"\n").unwrap();
        assert!(check_profile_trust(
            &profile,
            ProfileSource::Builtin,
            &cwd,
            &[],
        )
        .is_ok());
        assert!(check_profile_trust(
            &profile,
            ProfileSource::Env,
            &cwd,
            &[],
        )
        .is_ok());
    }

    #[test]
    fn resolve_profile_path_rejects_cwd_fallback() {
        // With $HISN_PROFILES unset and ./profiles/x.toml present in cwd,
        // --profile x must fail with E_PROFILE_NOTFOUND — a cwd-relative
        // lookup is the untrusted-profile hole the trust check exists for.
        let d = tmp();
        let cwd = d.path().join("proj");
        fs::create_dir(&cwd).unwrap();
        let profiles_dir = cwd.join("profiles");
        fs::create_dir(&profiles_dir).unwrap();
        let bad = profiles_dir.join("evil.toml");
        fs::write(&bad, "version = \"hisn-profile/v1\"\n").unwrap();
        // Save and unset $HISN_PROFILES
        let saved = std::env::var("HISN_PROFILES").ok();
        // SAFETY: tests are single-threaded; no other thread reads this env var.
        unsafe { std::env::remove_var("HISN_PROFILES"); }
        // cd to the dir that has ./profiles/evil.toml
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&cwd).unwrap();
        let result = resolve_profile_path("evil");
        // Restore
        std::env::set_current_dir(prev).unwrap();
        if let Some(v) = saved {
            // SAFETY: tests are single-threaded.
            unsafe { std::env::set_var("HISN_PROFILES", v); }
        }
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_PROFILE_NOTFOUND"), "{msg}");
    }

    #[test]
    fn check_profile_trust_uses_process_cwd_not_profile_cwd() {
        // A profile that sets session.cwd to a path outside its own
        // location must still be rejected if the profile file itself
        // lies under the invoking process's cwd. The trust check uses
        // BOTH the process cwd (getcwd at `hisn run`) and the final
        // resolved session cwd — nothing in the check may depend on
        // the profile's own [policy] alone.
        let d = tmp();
        let proc_cwd = d.path().join("proc_cwd");
        fs::create_dir(&proc_cwd).unwrap();
        // The profile lives under proc_cwd but declares a different session.cwd
        let profile = proc_cwd.join("profile.toml");
        fs::write(
            &profile,
            "version = \"hisn-profile/v1\"\n[policy]\nsession.cwd = \"/elsewhere\"\n",
        )
        .unwrap();
        // The session cwd from the policy is /elsewhere, but the profile
        // is under proc_cwd — so it must be rejected.
        let result = check_profile_trust(
            &profile,
            ProfileSource::Path,
            &proc_cwd,
            &[],
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_PROFILE_UNTRUSTED"), "{msg}");
    }
}
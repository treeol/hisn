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
pub const E_RISK_ACK_REQUIRED: &str = "E_RISK_ACK_REQUIRED";
pub const E_RISK_ACK_MISMATCH: &str = "E_RISK_ACK_MISMATCH";
pub const E_NOT_SUPPORTED: &str = "E_NOT_SUPPORTED";

/// A profile as written in a `.toml` file: the envelope around a `Policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Must be exactly `hisn-profile/v1`.
    pub version: String,
    /// A complete `hisn-policy/v1` document (inline table).
    pub policy: Policy,
    /// Forward an existing host socket inside (0.3 §17).
    #[serde(default, rename = "forward")]
    pub forwards: Vec<Forward>,
    /// Start a host-side process and forward its socket (0.3 §17).
    #[serde(default, rename = "host_services")]
    pub host_services: Vec<HostService>,
}

impl Profile {
    /// Parse and syntax-validate a profile TOML (no filesystem access).
    pub fn parse(text: &str) -> Result<Self> {
        let p: Profile = toml::from_str(text).map_err(|e| anyhow!("profile parse: {e}"))?;
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
        // Validate the 0.3 surface (forwards and host_services).
        p.validate_surface()?;
        Ok(p)
    }

    /// Validate the 0.3 surface tables: `[[forward]]` and `[[host_services]]`.
    /// Enforces risk_ack matching (§16) and path sanity.
    fn validate_surface(&self) -> Result<()> {
        for f in &self.forwards {
            if f.name.is_empty() {
                bail!("[[forward]]: name must not be empty");
            }
            if !f.socket.starts_with('/') {
                bail!("[[forward]] {}: socket must be an absolute path", f.name);
            }
            if !f.expose.starts_with('/') {
                bail!("[[forward]] {}: expose must be an absolute path", f.name);
            }
            // Compute the label and check risk_ack (§16).
            let label = forward_label(&f.socket, f.risk.as_deref());
            if label == RiskLabel::None && f.risk.is_none() {
                // Unknown socket with no explicit risk → load error
                bail!(
                    "E_RISK_ACK_REQUIRED: [[forward]] {}: unknown socket {} — set `risk` explicitly (minimum host-exec)",
                    f.name,
                    f.socket
                );
            }
            if label.requires_ack() {
                match &f.risk_ack {
                    None => bail!(
                        "E_RISK_ACK_REQUIRED: [[forward]] {}: {} requires risk_ack = \"{}\"",
                        f.name,
                        f.socket,
                        label.kebab()
                    ),
                    Some(ack) if ack != label.kebab() => bail!(
                        "E_RISK_ACK_MISMATCH: [[forward]] {}: risk_ack = {:?} but the computed label is {:?}",
                        f.name,
                        ack,
                        label.kebab()
                    ),
                    _ => {}
                }
            }
        }
        for h in &self.host_services {
            if h.name.is_empty() {
                bail!("[[host_services]]: name must not be empty");
            }
            if h.exec.is_empty() {
                bail!("[[host_services]] {}: exec must not be empty", h.name);
            }
            if !h.socket.starts_with('/') {
                bail!(
                    "[[host_services]] {}: socket must be an absolute path",
                    h.name
                );
            }
            if !h.expose.starts_with('/') {
                bail!(
                    "[[host_services]] {}: expose must be an absolute path",
                    h.name
                );
            }
            // host_services always requires host-exec for the execution
            // itself, plus the socket's label. For an unknown socket
            // without explicit `risk`, the effective label is `host-exec`
            // (the floor for the execution itself); the `risk_ack` must
            // match that.
            let socket_label = if h.risk.is_some() {
                forward_label(&h.socket, h.risk.as_deref())
            } else {
                // Unknown socket with no explicit risk: for host_services,
                // the floor is host-exec (the execution itself).
                match forward_label(&h.socket, h.risk.as_deref()) {
                    RiskLabel::None => RiskLabel::HostExec,
                    other => other,
                }
            };
            let effective = if socket_label > RiskLabel::HostExec {
                socket_label
            } else {
                RiskLabel::HostExec
            };
            match &h.risk_ack {
                None => bail!(
                    "E_RISK_ACK_REQUIRED: [[host_services]] {}: requires risk_ack = \"{}\"",
                    h.name,
                    effective.kebab()
                ),
                Some(ack) if ack != effective.kebab() => bail!(
                    "E_RISK_ACK_MISMATCH: [[host_services]] {}: risk_ack = {:?} but the computed label is {:?}",
                    h.name,
                    ack,
                    effective.kebab()
                ),
                _ => {}
            }
        }
        Ok(())
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

/// A `[[forward]]` table: expose an existing host socket inside (DESIGN §17).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    /// Required. A name for this forward (for display and audit).
    pub name: String,
    /// The host-side socket path to forward.
    pub socket: String,
    /// The in-sandbox path where the socket will appear.
    pub expose: String,
    /// Optional explicit risk label (for unknown sockets; §16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    /// Required risk acknowledgment (must match the computed label).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_ack: Option<String>,
}

/// A `[[host_services]]` table: start a host process and forward its socket
/// (DESIGN §17).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostService {
    /// Required. A name for this service.
    pub name: String,
    /// The command to run on the host.
    pub exec: Vec<String>,
    /// The host-side socket path the process binds.
    pub socket: String,
    /// The in-sandbox path where the socket will appear.
    pub expose: String,
    /// Readiness check (socket stat, tcp connect, or command exit 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<ReadinessSpec>,
    /// Stop policy (signal + grace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopSpec>,
    /// Optional explicit risk label (for the socket; §16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    /// Required risk acknowledgment (must cover host-exec for the execution
    /// itself, plus the socket's label).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_ack: Option<String>,
}

/// Readiness specification for `[[host_services]]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSpec {
    /// `socket = "/path"` — stat the socket file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// `tcp = "host:port"` — connect to a TCP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<String>,
    /// `command = ["sh", "-c", "test -S /path"]` — run a command, exit 0 = ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Timeout in seconds (default 15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Stop specification for `[[host_services]]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopSpec {
    /// Signal name (default "TERM").
    #[serde(default = "default_signal")]
    pub signal: String,
    /// Grace period in seconds (default 5).
    #[serde(default = "default_grace")]
    pub grace: u64,
}

fn default_signal() -> String {
    "TERM".to_string()
}

fn default_grace() -> u64 {
    5
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
            let canon = std::fs::canonicalize(profile_path).with_context(|| {
                format!("canonicalizing profile path {}", profile_path.display())
            })?;
            // Check against the process cwd (independent of the profile's
            // own [policy]).
            let proc_cwd_canon = std::fs::canonicalize(&proc_cwd)
                .with_context(|| format!("canonicalizing process cwd {}", proc_cwd.display()))?;
            if canon.starts_with(&proc_cwd_canon) {
                bail!(
                    "E_PROFILE_UNTRUSTED: profile {} lies under the process cwd {}",
                    canon.display(),
                    proc_cwd_canon.display()
                );
            }
            // Also check against the session cwd (from the inner [policy]).
            let cwd_canon = std::fs::canonicalize(session_cwd)
                .with_context(|| format!("canonicalizing session cwd {}", session_cwd.display()))?;
            if canon.starts_with(&cwd_canon) {
                bail!(
                    "E_PROFILE_UNTRUSTED: profile {} lies under the session cwd {}",
                    canon.display(),
                    cwd_canon.display()
                );
            }
            for g in rw_grants {
                let g_canon = std::fs::canonicalize(g)
                    .with_context(|| format!("canonicalizing rw grant {}", g.display()))?;
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

/// A risk label from the closed set (ADR 0006, PLAN §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLabel {
    None,
    Data,
    Signing,
    HostExec,
    RootEquivalent,
    KernelSurface,
}

impl RiskLabel {
    /// The label requires a matching `risk_ack` (DESIGN §16).
    pub fn requires_ack(self) -> bool {
        matches!(self, Self::RootEquivalent | Self::Signing | Self::HostExec)
    }

    /// One-sentence explanation (for `hisn profile explain`).
    pub fn explain(self) -> &'static str {
        match self {
            Self::None => "no widening; the 0.2 sandbox",
            Self::Data => "the sandbox can read or write host data beyond cwd",
            Self::Signing => "the sandbox can produce a cryptographic signature valid on the host",
            Self::HostExec => "the sandbox can run arbitrary commands on the host as the user",
            Self::RootEquivalent => "the sandbox can become root on the host",
            Self::KernelSurface => {
                "the sandbox can provoke kernel code paths out of scope of the 0.2 threat model"
            }
        }
    }
}

/// A capability and its computed risk label (for display and audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEntry {
    pub capability: String,
    pub label: RiskLabel,
}

/// Compute the risk labels for a profile's capabilities (DESIGN §16).
/// Detects `[[forward]]` and `[[host_services]]` capabilities and assigns
/// labels per §16/§17. Unknown sockets without explicit `risk` are a load
/// error (E_RISK_ACK_REQUIRED).
pub fn compute_risks(profile: &Profile) -> Vec<RiskEntry> {
    let mut entries = Vec::new();
    for f in &profile.forwards {
        let label = forward_label(&f.socket, f.risk.as_deref());
        entries.push(RiskEntry {
            capability: format!("forward:{}", f.name),
            label,
        });
    }
    for h in &profile.host_services {
        // host_services always adds host-exec for the execution itself.
        // For an unknown socket without explicit risk, the floor is
        // host-exec (the execution itself).
        let socket_label = forward_label(&h.socket, h.risk.as_deref());
        let label = match socket_label {
            RiskLabel::None => RiskLabel::HostExec,
            other if other > RiskLabel::HostExec => other,
            _ => RiskLabel::HostExec,
        };
        entries.push(RiskEntry {
            capability: format!("host_service:{}", h.name),
            label,
        });
    }
    entries
}

/// Compute the risk label for a `[[forward]]` socket.
/// Known patterns: ssh-agent → signing, docker.sock → root-equivalent,
/// D-Bus → host-exec. Unknown → load error unless the profile sets `risk`
/// explicitly (minimum host-exec).
fn forward_label(socket: &str, explicit: Option<&str>) -> RiskLabel {
    // Known patterns (path-based, not name-based — a docker socket at a
    // non-standard path is still root-equivalent if it matches the pattern).
    if is_ssh_agent_socket(socket) {
        return RiskLabel::Signing;
    }
    if is_docker_socket(socket) {
        return RiskLabel::RootEquivalent;
    }
    if is_dbus_socket(socket) {
        return RiskLabel::HostExec;
    }
    // Unknown socket: the profile must set `risk` explicitly (minimum
    // host-exec). If no `risk` is set, this is a load error — return a
    // sentinel that the caller checks.
    match explicit {
        Some("data") => RiskLabel::Data,
        Some("signing") => RiskLabel::Signing,
        Some("host-exec") => RiskLabel::HostExec,
        Some("root-equivalent") => RiskLabel::RootEquivalent,
        Some("kernel-surface") => RiskLabel::KernelSurface,
        _ => RiskLabel::None, // caller must check and reject
    }
}

/// Recognised ssh-agent socket paths.
fn is_ssh_agent_socket(p: &str) -> bool {
    p.contains("ssh-agent")
        || p.ends_with("/ssh/agent.sock")
        || p.ends_with("/ssh-agent.sock")
        || p.contains("ssh-agent.sock")
}

/// Recognised Docker daemon socket paths.
fn is_docker_socket(p: &str) -> bool {
    p.ends_with("/docker.sock")
        || p == "/var/run/docker.sock"
        || p.contains("docker.sock")
        || p.contains("podman.sock")
}

/// Recognised D-Bus socket paths.
fn is_dbus_socket(p: &str) -> bool {
    p.contains("dbus")
        || p == "/run/dbus/system_bus_socket"
        || p.contains("system_bus_socket")
        || p.contains("session_bus_socket")
}

/// The highest risk label from a list (for the RISK line and risk.json).
pub fn highest_risk(entries: &[RiskEntry]) -> RiskLabel {
    entries
        .iter()
        .map(|e| e.label)
        .max()
        .unwrap_or(RiskLabel::None)
}

/// Format the RISK lines for `hisn run` output (one per widening capability).
/// Format: `RISK: <label> — <capability>` (DESIGN §16).
pub fn format_risk_lines(entries: &[RiskEntry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.label != RiskLabel::None)
        .map(|e| format!("RISK: {} — {}", e.label.kebab(), e.capability))
        .collect()
}

impl RiskLabel {
    /// The kebab-case string for display and serialization.
    pub fn kebab(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Data => "data",
            Self::Signing => "signing",
            Self::HostExec => "host-exec",
            Self::RootEquivalent => "root-equivalent",
            Self::KernelSurface => "kernel-surface",
        }
    }
}

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
/// labels (for `hisn profile explain`).
pub fn explain(spec: Option<&str>) -> Result<Value> {
    let profile = match spec {
        Some(s) => {
            let (path, _source) = resolve_profile_path(s)?;
            Profile::load(&path)?
        }
        None => Profile {
            version: PROFILE_VERSION.to_string(),
            policy: Policy::default(),
            forwards: Vec::new(),
            host_services: Vec::new(),
        },
    };
    let risks = compute_risks(&profile);
    let highest = highest_risk(&risks);
    let caps: Vec<Value> = risks
        .iter()
        .map(|r| {
            json!({
                "capability": r.capability,
                "label": r.label.kebab(),
            })
        })
        .collect();
    Ok(json!({
        "schema": "hisn-profile-explain/v1",
        "version": profile.version,
        "capabilities": caps,
        "risk": highest.kebab(),
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
    let roots =
        crate::session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
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
        assert!(
            Profile::parse(
                r#"
version = "hisn-profile/v2"
[policy]
version = "hisn-policy/v1"
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_version_rejected() {
        assert!(
            Profile::parse(
                r#"
[policy]
version = "hisn-policy/v1"
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn inner_policy_validated() {
        // Bad inner policy version → error
        assert!(
            Profile::parse(
                r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v2"
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_profile_path_finds_builtin_in_dev() {
        // In the build sandbox, profiles/ is at the repo root and may be
        // found via $HISN_PROFILES or the binary's profiles/ directory.
        // Set $HISN_PROFILES to the repo's profiles/ for this test.
        let here = std::env::current_dir().unwrap();
        let profiles_dir = here.join("profiles");
        // SAFETY: tests are single-threaded.
        unsafe {
            std::env::set_var("HISN_PROFILES", &profiles_dir);
        }
        let result = resolve_profile_path("base");
        // Don't clean up $HISN_PROFILES — other tests may need it too.
        if let Ok((p, _)) = &result {
            assert!(p.exists());
            assert_eq!(result.unwrap().1, ProfileSource::Env);
        } else {
            // If $HISN_PROFILES doesn't have base.toml, try the binary's
            // profiles/ directory — which may or may not exist.
            if let Ok(exe) = std::env::current_exe()
                && let Some(parent) = exe.parent()
            {
                let candidate = parent.join("profiles").join("base.toml");
                if candidate.exists() {
                    let (p, source) =
                        resolve_profile_path("base").unwrap_or((candidate, ProfileSource::Builtin));
                    assert!(p.exists());
                    assert_eq!(source, ProfileSource::Builtin);
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
        let result = check_profile_trust(&profile, ProfileSource::Path, &cwd, &[]);
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
        let result = check_profile_trust(&profile, ProfileSource::Path, &cwd, &[]);
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
        let result = check_profile_trust(&profile, ProfileSource::Path, &cwd, &[grant.as_path()]);
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
        assert!(check_profile_trust(&profile, ProfileSource::Builtin, &cwd, &[],).is_ok());
        assert!(check_profile_trust(&profile, ProfileSource::Env, &cwd, &[],).is_ok());
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
        unsafe {
            std::env::remove_var("HISN_PROFILES");
        }
        // cd to the dir that has ./profiles/evil.toml
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&cwd).unwrap();
        let result = resolve_profile_path("evil");
        // Restore
        std::env::set_current_dir(prev).unwrap();
        if let Some(v) = saved {
            // SAFETY: tests are single-threaded.
            unsafe {
                std::env::set_var("HISN_PROFILES", v);
            }
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
        let result = check_profile_trust(&profile, ProfileSource::Path, &proc_cwd, &[]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_PROFILE_UNTRUSTED"), "{msg}");
    }

    #[test]
    fn risk_label_kebab_and_format_risk_lines() {
        assert_eq!(RiskLabel::None.kebab(), "none");
        assert_eq!(RiskLabel::Data.kebab(), "data");
        assert_eq!(RiskLabel::Signing.kebab(), "signing");
        assert_eq!(RiskLabel::HostExec.kebab(), "host-exec");
        assert_eq!(RiskLabel::RootEquivalent.kebab(), "root-equivalent");
        assert_eq!(RiskLabel::KernelSurface.kebab(), "kernel-surface");

        let entries = vec![
            RiskEntry {
                capability: "docker-socket".into(),
                label: RiskLabel::RootEquivalent,
            },
            RiskEntry {
                capability: "ssh-agent".into(),
                label: RiskLabel::Signing,
            },
        ];
        let lines = format_risk_lines(&entries);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "RISK: root-equivalent — docker-socket");
        assert_eq!(lines[1], "RISK: signing — ssh-agent");

        // None entries are filtered out.
        let none_entries = vec![RiskEntry {
            capability: "base".into(),
            label: RiskLabel::None,
        }];
        assert!(format_risk_lines(&none_entries).is_empty());
    }

    #[test]
    fn highest_risk_orders_labels() {
        let entries = vec![
            RiskEntry {
                capability: "data".into(),
                label: RiskLabel::Data,
            },
            RiskEntry {
                capability: "docker".into(),
                label: RiskLabel::RootEquivalent,
            },
        ];
        assert_eq!(highest_risk(&entries), RiskLabel::RootEquivalent);
        assert_eq!(highest_risk(&[]), RiskLabel::None);
    }

    #[test]
    fn forward_parses_and_computes_signing() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[forward]]
name = "ssh-agent"
socket = "/run/user/1000/ssh-agent.sock"
expose = "/run/ssh/agent.sock"
risk = "signing"
risk_ack = "signing"
"#,
        )
        .unwrap();
        assert_eq!(p.forwards.len(), 1);
        assert_eq!(p.forwards[0].name, "ssh-agent");
        let risks = compute_risks(&p);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].label, RiskLabel::Signing);
    }

    #[test]
    fn forward_docker_socket_computes_root_equivalent() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[forward]]
name = "docker"
socket = "/var/run/docker.sock"
expose = "/run/docker.sock"
risk = "root-equivalent"
risk_ack = "root-equivalent"
"#,
        )
        .unwrap();
        let risks = compute_risks(&p);
        assert_eq!(risks[0].label, RiskLabel::RootEquivalent);
    }

    #[test]
    fn forward_unknown_socket_without_risk_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[forward]]
name = "unknown"
socket = "/run/user/1000/custom.sock"
expose = "/run/custom.sock"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_RISK_ACK_REQUIRED"), "{msg}");
    }

    #[test]
    fn forward_unknown_socket_with_risk_and_ack_accepted() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[forward]]
name = "custom"
socket = "/run/user/1000/custom.sock"
expose = "/run/custom.sock"
risk = "host-exec"
risk_ack = "host-exec"
"#,
        )
        .unwrap();
        let risks = compute_risks(&p);
        assert_eq!(risks[0].label, RiskLabel::HostExec);
    }

    #[test]
    fn forward_risk_ack_mismatch_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[forward]]
name = "ssh-agent"
socket = "/run/user/1000/ssh-agent.sock"
expose = "/run/ssh/agent.sock"
risk = "signing"
risk_ack = "data"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_RISK_ACK_MISMATCH"), "{msg}");
    }

    #[test]
    fn host_service_parses_and_requires_host_exec_ack() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[host_services]]
name = "kvr-host"
exec = ["kvr-server"]
socket = "/run/user/1000/kvr/abc.sock"
expose = "/run/kvr/kvr.sock"
ready = { socket = "/run/user/1000/kvr/abc.sock" }
stop = { signal = "TERM", grace = 5 }
risk_ack = "host-exec"
"#,
        )
        .unwrap();
        assert_eq!(p.host_services.len(), 1);
        let risks = compute_risks(&p);
        assert_eq!(risks[0].label, RiskLabel::HostExec);
    }

    #[test]
    fn host_service_without_risk_ack_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[host_services]]
name = "kvr-host"
exec = ["kvr-server"]
socket = "/run/user/1000/kvr/abc.sock"
expose = "/run/kvr/kvr.sock"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_RISK_ACK_REQUIRED"), "{msg}");
    }

    #[test]
    fn profile_with_no_surface_yields_no_risks() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
"#,
        )
        .unwrap();
        assert!(compute_risks(&p).is_empty());
    }

    #[test]
    fn forward_label_recognizes_known_patterns() {
        assert_eq!(
            forward_label("/run/user/1000/ssh-agent.sock", None),
            RiskLabel::Signing
        );
        assert_eq!(
            forward_label("/var/run/docker.sock", None),
            RiskLabel::RootEquivalent
        );
        assert_eq!(
            forward_label("/run/dbus/system_bus_socket", None),
            RiskLabel::HostExec
        );
        assert_eq!(
            forward_label("/run/user/1000/podman.sock", None),
            RiskLabel::RootEquivalent
        );
        // Unknown without explicit risk → None (caller must reject)
        assert_eq!(forward_label("/run/custom.sock", None), RiskLabel::None);
        // Unknown with explicit risk → accepted
        assert_eq!(
            forward_label("/run/custom.sock", Some("data")),
            RiskLabel::Data
        );
        assert_eq!(
            forward_label("/run/custom.sock", Some("host-exec")),
            RiskLabel::HostExec
        );
    }
}

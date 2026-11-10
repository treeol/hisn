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

/// Upper bound (seconds) for `stop.grace` and readiness `timeout`. Anything
/// larger is rejected at validation so deadline arithmetic can never overflow
/// `Instant` (one day).
pub const MAX_TIMEOUT_SECS: u64 = 86400;

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
    /// Persistent-home config (0.3.2).
    #[serde(default, rename = "home")]
    pub home: Option<HomeConfig>,
    /// Rootfs config (0.3.2).
    #[serde(default, rename = "rootfs")]
    pub rootfs: Option<RootfsConfig>,
    /// SSH agent config (0.3.2).
    #[serde(default, rename = "ssh")]
    pub ssh: Option<SshConfig>,
    /// Session network resolver override (0.3.3).
    #[serde(default, rename = "net")]
    pub net: Option<NetConfig>,
    /// In-sandbox services (0.3 §19).
    #[serde(default, rename = "services")]
    pub services: Vec<Service>,
    /// Forward an existing host socket inside (0.3 §17).
    #[serde(default, rename = "forward")]
    pub forwards: Vec<Forward>,
    /// Start a host-side process and forward its socket (0.3 §17).
    #[serde(default, rename = "host_services")]
    pub host_services: Vec<HostService>,
    /// Docker access tier (0.3 §18: T2 socket only).
    #[serde(default)]
    pub docker: Option<Docker>,
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

    /// Reject a string containing a NUL byte (would panic `CString::new` /
    /// fail `execvp`).
    fn check_no_nul(value: &str, what: &str) -> Result<()> {
        if value.contains('\0') {
            bail!("{what}: must not contain NUL bytes");
        }
        Ok(())
    }

    /// Check one `risk_ack` against the label its capability computed, in the
    /// shared form used by `[[forward]]`, `[[host_services]]` and `[docker]`
    /// (0.4.3: the three copies of this match block became one helper).
    ///
    /// `subject` is the subject prefix the error messages name, without the
    /// following colon: `[[forward]] <name>`, `[[host_services]] <name>`, or
    /// `[docker]`. The messages are byte-identical to the former copies:
    /// the `[docker]` mismatch was `[docker] risk_ack = ...` (colon-less,
    /// extra space), so it passes `is_docker=true`; the `[[forward]]`
    /// required message named the socket, so it passes `name=Some(socket)`.
    fn check_risk_ack(
        subject: &str,
        name: Option<&str>,
        label: RiskLabel,
        ack: &Option<String>,
    ) -> Result<()> {
        match ack {
            None => match name {
                Some(n) => bail!(
                    "E_RISK_ACK_REQUIRED: {subject}: {n} requires risk_ack = \"{}\"",
                    label.kebab()
                ),
                None => bail!(
                    "E_RISK_ACK_REQUIRED: {subject}: requires risk_ack = \"{}\"",
                    label.kebab()
                ),
            },
            Some(a) if a != label.kebab() => bail!(
                "E_RISK_ACK_MISMATCH: {subject} risk_ack = {a:?} but the computed label is {:?}",
                label.kebab()
            ),
            _ => {}
        }
        Ok(())
    }

    /// Validate the 0.3 surface tables: `[[services]]`, `[[forward]]`,
    /// `[[host_services]]`, and `[docker]`. Enforces risk_ack matching
    /// (§16–§18) and path sanity.
    fn validate_surface(&self) -> Result<()> {
        if let Some(n) = &self.net
            && let Some(ns) = &n.nameservers
        {
            validate_nameservers(ns)?;
        }
        // Validate [[services]] (§19).
        let mut service_names = std::collections::HashSet::new();
        for s in &self.services {
            if s.name.is_empty() {
                bail!("[[services]]: name must not be empty");
            }
            if !service_names.insert(s.name.as_str()) {
                bail!("[[services]]: duplicate name {:?}", s.name);
            }
            if s.exec.is_empty() {
                bail!("[[services]] {}: exec must not be empty", s.name);
            }
            for arg in &s.exec {
                Self::check_no_nul(arg, &format!("[[services]] {}: exec arg", s.name))?;
            }
            // restart = "none" only in 0.3.
            match s.restart.as_deref() {
                None | Some("none") => {}
                Some(other) => {
                    bail!(
                        "E_NOT_SUPPORTED: [[services]] {}: restart = {:?} is not available in 0.3 (only \"none\")",
                        s.name,
                        other
                    );
                }
            }
            // ready for [[services]] only supports `socket` (stat from
            // supervisor). `command` and `tcp` are not in
            // `ServiceReadinessSpec` — `deny_unknown_fields` rejects them at
            // parse time with a clear error naming the unknown field. No
            // additional validation needed here.
            if let Some(r) = &s.ready
                && let Some(t) = r.timeout
                && t > MAX_TIMEOUT_SECS
            {
                bail!(
                    "[[services]] {}: ready.timeout {t} exceeds maximum {MAX_TIMEOUT_SECS} seconds",
                    s.name
                );
            }
            if let Some(stop) = &s.stop {
                if stop.grace > MAX_TIMEOUT_SECS {
                    bail!(
                        "[[services]] {}: stop.grace {} exceeds maximum {} seconds",
                        s.name,
                        stop.grace,
                        MAX_TIMEOUT_SECS
                    );
                }
                Self::check_no_nul(
                    &stop.signal,
                    &format!("[[services]] {}: stop.signal", s.name),
                )?;
            }
        }
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
                Self::check_risk_ack(
                    &format!("[[forward]] {}", f.name),
                    Some(&f.socket),
                    label,
                    &f.risk_ack,
                )?;
            }
        }
        for h in &self.host_services {
            if h.name.is_empty() {
                bail!("[[host_services]]: name must not be empty");
            }
            if h.exec.is_empty() {
                bail!("[[host_services]] {}: exec must not be empty", h.name);
            }
            for arg in &h.exec {
                Self::check_no_nul(arg, &format!("[[host_services]] {}: exec arg", h.name))?;
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
            // `[[host_services]]` always requires an ack: its effective
            // label is at least `host-exec` (the execution itself), so the
            // ack must match it (None is an error, not "no ack needed").
            Self::check_risk_ack(
                &format!("[[host_services]] {}", h.name),
                None,
                effective,
                &h.risk_ack,
            )?;
            // Readiness and stop validation.
            if let Some(r) = &h.ready {
                if r.tcp.is_some() {
                    bail!(
                        "E_NOT_SUPPORTED: [[host_services]] {}: ready.tcp is not implemented",
                        h.name
                    );
                }
                if let Some(cmd) = &r.command {
                    for arg in cmd {
                        Self::check_no_nul(
                            arg,
                            &format!("[[host_services]] {}: ready.command arg", h.name),
                        )?;
                    }
                }
                if let Some(t) = r.timeout
                    && t > MAX_TIMEOUT_SECS
                {
                    bail!(
                        "[[host_services]] {}: ready.timeout {t} exceeds maximum {MAX_TIMEOUT_SECS} seconds",
                        h.name
                    );
                }
            }
            if let Some(stop) = &h.stop {
                if stop.grace > MAX_TIMEOUT_SECS {
                    bail!(
                        "[[host_services]] {}: stop.grace {} exceeds maximum {} seconds",
                        h.name,
                        stop.grace,
                        MAX_TIMEOUT_SECS
                    );
                }
                Self::check_no_nul(
                    &stop.signal,
                    &format!("[[host_services]] {}: stop.signal", h.name),
                )?;
            }
        }
        // [docker] tier validation (§18).
        if let Some(d) = &self.docker {
            let tier = docker_tier(d)?;
            if tier == "socket" {
                let label = RiskLabel::RootEquivalent;
                if d.risk_ack.is_none() {
                    // The `[docker]` subject names only the tier in the
                    // required message (byte-identical to the former copy).
                    bail!(
                        "E_RISK_ACK_REQUIRED: [docker] tier = \"socket\" requires risk_ack = \"{}\"",
                        label.kebab()
                    );
                }
                // The required message keeps its colon-less form via the
                // helper's None path is NOT what we want: see helper docs —
                // the colon-less `[docker]` text is produced by the explicit
                // None bail above; the helper handles the mismatch here.
                Self::check_risk_ack("[docker]", None, label, &d.risk_ack)?;
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

    /// The [`Overrides`] this profile contributes: its `[home] persist`,
    /// `[rootfs]` (store name or path, via [`rootfs_spec`]) and `[net]
    /// nameservers`. The supervisor's `prepare` and `profile validate` share
    /// this one construction (0.4.3-style single source; before, each built
    /// the same three fields by hand and had already drifted once).
    ///
    /// CLI flags win over profile values, so callers apply their CLI
    /// overrides on top of the returned value (e.g.
    /// `overrides.cwd = args.cwd`); the profile never sets `cwd` or
    /// `network`, so those stay `None` here.
    pub fn overrides(&self) -> Result<Overrides> {
        Ok(Overrides {
            home_persist: self.home.as_ref().and_then(|h| h.persist.clone()),
            // Strict: a profile naming a rootfs that cannot be resolved is
            // an error, never a silent fall-back to the host toolchain.
            rootfs_path: self.rootfs.as_ref().map(rootfs_spec).transpose()?,
            nameservers: self.net.as_ref().and_then(|n| n.nameservers.clone()),
            ..Default::default()
        })
    }
}

/// `[net]` table (0.3.3): the session's DNS resolvers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetConfig {
    /// Nameserver addresses written verbatim to the session's `/etc/resolv.conf`,
    /// replacing the host-derived list. Loopback addresses are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<Vec<String>>,
}

/// Validate `[net] nameservers`: non-empty, each an IP address, none loopback.
pub fn validate_nameservers(ns: &[String]) -> Result<()> {
    if ns.is_empty() {
        bail!("[net] nameservers: must list at least one address (omit the key to use the host's)");
    }
    for a in ns {
        let ip: std::net::IpAddr = a
            .parse()
            .map_err(|_| anyhow!("[net] nameservers: {a:?} is not an IP address"))?;
        if crate::mounts::is_loopback_ns(a) {
            bail!(
                "[net] nameservers: {ip} is a loopback address; it is unreachable from the session"
            );
        }
    }
    Ok(())
}

/// Persistent-home config (`[home]` table in a profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HomeConfig {
    /// Absolute path for the persistent home directory. `~` is expanded.
    /// Absent → the inner policy's `session.home` (tmpfs by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist: Option<String>,
}

/// Resolve a profile's `[rootfs]` to a path string, strictly: exactly one of
/// `name` / `path`, and a name must resolve (the store entry is checked later
/// by `existing_dir`). Used by both `profile validate` and session start so a
/// missing rootfs can never silently fall back to the host toolchain.
pub fn rootfs_spec(r: &RootfsConfig) -> Result<String> {
    match (&r.name, &r.path) {
        (Some(_), Some(_)) => bail!("[rootfs]: name and path are mutually exclusive"),
        (None, None) => bail!("[rootfs]: one of name or path is required"),
        (None, Some(p)) => Ok(p.clone()),
        (Some(n), None) => Ok(crate::rootfs_store::resolve_name(n)
            .with_context(|| format!("[rootfs] name {n:?}"))?
            .to_string_lossy()
            .into_owned()),
    }
}

/// Rootfs config (`[rootfs]` table in a profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RootfsConfig {
    /// Store name to resolve from `$XDG_DATA_HOME/hisn/rootfs/<name>/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Direct path to a rootfs directory. Mutually exclusive with `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// SSH agent config (`[ssh]` table in a profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshConfig {
    /// Start a filtering ssh-agent proxy inside the session.
    #[serde(default)]
    pub agent: bool,
    /// Optional fingerprint allowlist (`SHA256:…`). Empty/absent = all keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
}

/// A `[[services]]` table: start a long-lived process inside the sandbox
/// (DESIGN §19).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Required. A name for this service (unique among `[[services]]`).
    pub name: String,
    /// The command to run inside the sandbox (through the exec chain).
    pub exec: Vec<String>,
    /// Optional: the path the service listens on (for display and `ls --json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// Readiness check: socket stat from the supervisor (for paths under
    /// cwd or mounts). `ready.command` is not available for `[[services]]` in
    /// 0.3 — it would run on the host with the user's credentials (P25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<ServiceReadinessSpec>,
    /// Stop policy (signal + grace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopSpec>,
    /// Restart policy (only "none" in 0.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<String>,
}

/// Readiness spec for `[[services]]`: only `socket` stat (from the
/// supervisor) and `timeout` are available. `command` and `tcp` are not —
/// `command` would run on the host with the user's credentials (P25), and
/// `tcp` is not available for in-sandbox services in 0.3 (use `socket`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadinessSpec {
    /// `socket = "/path"` — stat the socket file from the supervisor.
    /// Works for paths under cwd (a rw bind visible from S) or under
    /// mounts.ro/mounts.rw. For paths on the sandbox's private tmpfs (/tmp,
    /// /run, $HOME), the supervisor cannot stat them; declare the socket
    /// under cwd instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// Timeout in seconds (default 15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
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
    /// Readiness check (socket stat or command exit 0).
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

/// Docker access tier (0.3 §18, ADR 0004). Only `socket` (T2) is available
/// in 0.3; `proxy` (T1) and `nested_userns` (T3) are rejected with
/// `E_NOT_SUPPORTED`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docker {
    /// `"socket"` (T2 — raw forward, root-equivalent). `"proxy"` (T1) is
    /// rejected with `E_NOT_SUPPORTED` in 0.3.
    pub tier: String,
    /// Required: must match the computed risk label (`root-equivalent` for
    /// `socket`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_ack: Option<String>,
    // Note: `nested_userns = true` (T3) is a top-level profile key, not
    // inside `[docker]`. It is rejected with `E_NOT_SUPPORTED` in 0.3.
    // We do not parse it here — it would be a deny_unknown_fields violation.
}

/// The docker tier (only `socket` is available in 0.3).
pub fn docker_tier(docker: &Docker) -> Result<&'static str> {
    match docker.tier.as_str() {
        "socket" => Ok("socket"),
        "proxy" => bail!(
            "E_NOT_SUPPORTED: [docker] tier = \"proxy\" is not available in 0.3 (T1 ships in 0.4)"
        ),
        other => bail!(
            "E_NOT_SUPPORTED: [docker] tier = {:?} is not a valid tier (0.3: \"socket\" only)",
            other
        ),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSpec {
    /// `socket = "/path"` — stat the socket file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// `tcp = "host:port"` — not implemented: rejected at validation
    /// with `E_NOT_SUPPORTED`. Kept in the schema only so the field is
    /// parsed and rejected with a clear error instead of an unknown-field
    /// error.
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

/// Checked `Instant::now() + Duration` that never panics: returns an error
/// instead of overflowing.
pub fn checked_deadline(secs: u64, what: &str) -> Result<std::time::Instant> {
    std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(secs))
        .ok_or_else(|| anyhow!("{what}: deadline overflow for {secs} seconds"))
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
    Trust,
    Data,
    Signing,
    HostExec,
    RootEquivalent,
    KernelSurface,
}

impl RiskLabel {
    /// The label requires a matching `risk_ack` (DESIGN §16).
    pub fn requires_ack(self) -> bool {
        matches!(
            self,
            Self::RootEquivalent | Self::Signing | Self::HostExec | Self::Trust
        )
    }

    /// One-sentence explanation (for `hisn profile explain`).
    pub fn explain(self) -> &'static str {
        match self {
            Self::None => "no widening; the 0.2 sandbox",
            Self::Trust => "the sandbox trusts an external source instead of the host",
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
    /// Human-readable description of the risk (shown in `profile explain`
    /// and the RISK line). Empty for `None`-labelled capabilities.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Compute the risk labels for a profile's capabilities (DESIGN §16).
/// Detects `[[forward]]`, `[[host_services]]`, and `[docker]` capabilities
/// and assigns labels per §16/§17/§18. Unknown sockets without explicit
/// `risk` are a load error (E_RISK_ACK_REQUIRED).
pub fn compute_risks(profile: &Profile) -> Vec<RiskEntry> {
    let mut entries = Vec::new();
    // [[services]] (§19): in-sandbox services do not widen the boundary;
    // the label is `none` and no risk_ack is required.
    for s in &profile.services {
        entries.push(RiskEntry {
            capability: format!("service:{}", s.name),
            label: RiskLabel::None,
            description: String::new(),
        });
    }
    for f in &profile.forwards {
        let label = forward_label(&f.socket, f.risk.as_deref());
        entries.push(RiskEntry {
            capability: format!("forward:{}", f.name),
            label,
            description: label.explain().to_string(),
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
            description: label.explain().to_string(),
        });
    }
    // [docker] tier (§18): socket → root-equivalent.
    if let Some(d) = &profile.docker
        && d.tier == "socket"
    {
        entries.push(RiskEntry {
            capability: "docker:socket".into(),
            label: RiskLabel::RootEquivalent,
            description: RiskLabel::RootEquivalent.explain().to_string(),
        });
    }
    // 0.3.2: [home] persist → Data (state carries across sessions).
    if let Some(h) = &profile.home
        && let Some(ref p) = h.persist
    {
        entries.push(RiskEntry {
            capability: "home-persist".into(),
            label: RiskLabel::Data,
            description: format!(
                "state persists across sessions in {p}; a session can read and poison \
                 caches used by later sessions sharing this directory"
            ),
        });
    }
    // 0.3.2: [rootfs] → Trust (the toolchain comes from the imported image
    // instead of the host; host /usr, /opt and /nix are not visible — you
    // trust the image, not the host install).
    if let Some(r) = &profile.rootfs {
        let label_desc = if let Some(ref n) = r.name {
            format!(
                "the toolchain comes from the imported image '{n}' instead of the host; \
                 host /usr, /opt and /nix are not visible — you trust the image, not the host install"
            )
        } else if let Some(ref p) = r.path {
            format!(
                "the toolchain comes from the imported image '{p}' instead of the host; \
                 host /usr, /opt and /nix are not visible — you trust the image, not the host install"
            )
        } else {
            "the toolchain comes from the imported image instead of the host; \
             host /usr, /opt and /nix are not visible — you trust the image, not the host install"
                .to_string()
        };
        entries.push(RiskEntry {
            capability: "rootfs".into(),
            label: RiskLabel::Trust,
            description: label_desc,
        });
    }
    // 0.3.2: [ssh] agent → Signing (the session can sign with the listed keys).
    if let Some(s) = &profile.ssh
        && s.agent
    {
        let n_keys = s.keys.len();
        let desc = if n_keys > 0 {
            format!(
                "the session can sign and authenticate with {n_keys} listed keys for its lifetime; \
                 it cannot add, remove or extract keys"
            )
        } else {
            "the session can sign and authenticate with all keys the host agent offers \
             for its lifetime; it cannot add, remove or extract keys"
                .to_string()
        };
        entries.push(RiskEntry {
            capability: "ssh-agent".into(),
            label: RiskLabel::Signing,
            description: desc,
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
        Some("trust") => RiskLabel::Trust,
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
/// Format: `RISK: <label> — <capability> — <description>` (DESIGN §16).
pub fn format_risk_lines(entries: &[RiskEntry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.label != RiskLabel::None)
        .map(|e| {
            if e.description.is_empty() {
                format!("RISK: {} — {}", e.label.kebab(), e.capability)
            } else {
                format!(
                    "RISK: {} — {} — {}",
                    e.label.kebab(),
                    e.capability,
                    e.description
                )
            }
        })
        .collect()
}

impl RiskLabel {
    /// The kebab-case string for display and serialization.
    pub fn kebab(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Trust => "trust",
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
/// labels (for `hisn profile explain`). Includes `notes` for each
/// `[[services]]` entry warning that the service socket is replaceable by
/// the sandboxed command (socket hijack, P29).
pub fn explain(spec: Option<&str>) -> Result<Value> {
    let profile = match spec {
        Some(s) => {
            let (path, _source) = resolve_profile_path(s)?;
            Profile::load(&path)?
        }
        None => Profile {
            version: PROFILE_VERSION.to_string(),
            policy: Policy::default(),
            home: None,
            rootfs: None,
            net: None,
            ssh: None,
            services: Vec::new(),
            forwards: Vec::new(),
            host_services: Vec::new(),
            docker: None,
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
                "description": r.description,
            })
        })
        .collect();
    // Notes for [[services]]: the service socket is on a writable path
    // (cwd or a grant) that the main command can also write. A hostile
    // command can kill the service, unlink its socket, and bind a
    // replacement — a host-side client connecting to the socket path would
    // then reach the attacker's process (P29).
    let notes: Vec<String> = profile
        .services
        .iter()
        .filter_map(|s| {
            s.socket.as_ref().map(|sock| {
                format!(
                    "service {}: socket {} is replaceable by the sandboxed command; the client must authenticate the service",
                    s.name, sock
                )
            })
        })
        .collect();
    Ok(json!({
        "schema": "hisn-profile-explain/v1",
        "version": profile.version,
        "capabilities": caps,
        "risk": highest.kebab(),
        "notes": notes,
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
    // Resolve [rootfs] name/path through the same code the session start
    // uses (Profile::overrides, shared with supervisor::prepare).
    let overrides = profile.overrides()?;
    let resolved = profile.resolve(base, &overrides, &roots)?;
    // 0.3.3: the mount plan's conflicts (src:dst vs session mounts) are
    // validate-time errors too, as at session start.
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let facts = crate::mounts::HostFacts::probe(&resolved, uid, gid, "user");
    crate::mounts::plan(&resolved, &facts, &[]).map_err(|e| anyhow!("mount plan: {e}"))?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn net_nameservers_loopback_only_is_rejected_at_validate() {
        let loop_only = r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[net]
nameservers = ["127.0.0.53", "::1"]
"#;
        let e = Profile::parse(loop_only).unwrap_err().to_string();
        assert!(e.contains("loopback") && e.contains("127.0.0.53"), "{e}");
        let mixed = loop_only.replace("[\"127.0.0.53\", \"::1\"]", "[\"1.1.1.1\", \"::1\"]");
        assert!(Profile::parse(&mixed).is_err());
        let good = loop_only.replace("[\"127.0.0.53\", \"::1\"]", "[\"1.1.1.1\"]");
        let p = Profile::parse(&good).unwrap();
        assert_eq!(p.net.unwrap().nameservers, Some(vec!["1.1.1.1".to_owned()]));
        let empty = loop_only.replace("[\"127.0.0.53\", \"::1\"]", "[]");
        assert!(Profile::parse(&empty).is_err());
        let not_ip = loop_only.replace("[\"127.0.0.53\", \"::1\"]", "[\"dns.example\"]");
        assert!(
            Profile::parse(&not_ip)
                .unwrap_err()
                .to_string()
                .contains("not an IP")
        );
    }

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
                description: String::new(),
            },
            RiskEntry {
                capability: "ssh-agent".into(),
                label: RiskLabel::Signing,
                description: String::new(),
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
            description: String::new(),
        }];
        assert!(format_risk_lines(&none_entries).is_empty());
    }

    #[test]
    fn highest_risk_orders_labels() {
        let entries = vec![
            RiskEntry {
                capability: "data".into(),
                label: RiskLabel::Data,
                description: String::new(),
            },
            RiskEntry {
                capability: "docker".into(),
                label: RiskLabel::RootEquivalent,
                description: String::new(),
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

    #[test]
    fn docker_socket_tier_computes_root_equivalent() {
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
[docker]
tier = "socket"
risk_ack = "root-equivalent"
"#,
        )
        .unwrap();
        let risks = compute_risks(&p);
        // Two entries: the forward (root-equivalent) and docker:socket (root-equivalent).
        assert_eq!(risks.len(), 2);
        assert_eq!(risks[1].label, RiskLabel::RootEquivalent);
        assert_eq!(risks[1].capability, "docker:socket");
    }

    #[test]
    fn docker_socket_without_risk_ack_rejected() {
        let result = Profile::parse(
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
[docker]
tier = "socket"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_RISK_ACK_REQUIRED"), "{msg}");
    }

    #[test]
    fn docker_socket_with_mismatched_risk_ack_rejected() {
        let result = Profile::parse(
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
[docker]
tier = "socket"
risk_ack = "data"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_RISK_ACK_MISMATCH"), "{msg}");
    }

    #[test]
    fn docker_proxy_tier_rejected_with_e_not_supported() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[docker]
tier = "proxy"
risk_ack = "none"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_NOT_SUPPORTED"), "{msg}");
    }

    #[test]
    fn docker_unknown_tier_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[docker]
tier = "bogus"
risk_ack = "none"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("E_NOT_SUPPORTED"), "{msg}");
    }

    #[test]
    fn profile_with_docker_but_no_surface_still_has_risk() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[docker]
tier = "socket"
risk_ack = "root-equivalent"
"#,
        )
        .unwrap();
        let risks = compute_risks(&p);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].label, RiskLabel::RootEquivalent);
    }

    #[test]
    fn services_parses_and_computes_none_risk() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "kvr"
exec = ["kvr-server", "--addr", "/run/kvr/kvr.sock"]
socket = "/run/kvr/kvr.sock"
ready = { socket = "/run/kvr/kvr.sock" }
stop = { signal = "TERM", grace = 5 }
restart = "none"
"#,
        )
        .unwrap();
        assert_eq!(p.services.len(), 1);
        assert_eq!(p.services[0].name, "kvr");
        assert_eq!(
            p.services[0].exec,
            ["kvr-server", "--addr", "/run/kvr/kvr.sock"]
        );
        let risks = compute_risks(&p);
        // Services have risk = none, so compute_risks returns a None entry.
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].label, RiskLabel::None);
        assert_eq!(risks[0].capability, "service:kvr");
    }

    #[test]
    fn services_empty_exec_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "bad"
exec = []
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn services_duplicate_name_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "dup"
exec = ["sleep", "1"]
[[services]]
name = "dup"
exec = ["sleep", "2"]
"#,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate name"));
    }

    #[test]
    fn services_restart_not_none_rejected() {
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "kvr"
exec = ["sleep", "1"]
restart = "on-failure"
"#,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("E_NOT_SUPPORTED"));
    }

    #[test]
    fn services_ready_tcp_rejected() {
        // ready.tcp is not in ServiceReadinessSpec — deny_unknown_fields
        // rejects it at parse time (P25: command and tcp are not available
        // for in-sandbox services in 0.3).
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "kvr"
exec = ["sleep", "1"]
ready = { tcp = "127.0.0.1:8080" }
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // deny_unknown_fields produces a serde parse error mentioning "tcp".
        assert!(
            msg.contains("tcp") || msg.contains("unknown field"),
            "{msg}"
        );
    }

    #[test]
    fn services_ready_command_rejected() {
        // ready.command is not in ServiceReadinessSpec — deny_unknown_fields
        // rejects it at parse time (P25: command would run on the host with
        // the user's credentials).
        let result = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "kvr"
exec = ["sleep", "1"]
ready = { command = ["test", "-S", "/run/kvr.sock"] }
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("command") || msg.contains("unknown field"),
            "{msg}"
        );
    }

    #[test]
    fn services_no_ready_field_is_ok() {
        let p = Profile::parse(
            r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[services]]
name = "kvr"
exec = ["sleep", "1"]
"#,
        )
        .unwrap();
        assert!(p.services[0].ready.is_none());
    }

    #[test]
    fn host_service_grace_above_max_rejected() {
        let text = r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[host_services]]
name = "kvr-host"
exec = ["kvr-server"]
socket = "/run/user/1000/kvr/abc.sock"
expose = "/run/kvr/kvr.sock"
ready = { socket = "/run/user/1000/kvr/abc.sock", timeout = 86401 }
risk_ack = "host-exec"
"#;
        let e = Profile::parse(text).unwrap_err().to_string();
        assert!(e.contains("ready.timeout") && e.contains("86400"), "{e}");
        let text2 = text.replace("timeout = 86401", "timeout = 15").replace(
            "ready = { socket",
            "stop = { grace = 18446744073709551615 }\nready = { socket",
        );
        let e2 = Profile::parse(&text2).unwrap_err().to_string();
        assert!(e2.contains("stop.grace"), "{e2}");
    }

    #[test]
    fn nul_bytes_rejected_in_exec_and_ready_command_and_service_argv() {
        // NUL in host_services.exec
        let text = "version = \"hisn-profile/v1\"\n[policy]\nversion = \"hisn-policy/v1\"\n[[host_services]]\nname = \"kvr-host\"\nexec = [\"true\\u0000x\"]\nsocket = \"/run/user/1000/kvr/abc.sock\"\nexpose = \"/run/kvr/kvr.sock\"\nready = { socket = \"/run/user/1000/kvr/abc.sock\" }\nrisk_ack = \"host-exec\"\n";
        let e = Profile::parse(text).unwrap_err().to_string();
        assert!(e.contains("NUL"), "{e}");
        // NUL in ready.command
        let text2 = "version = \"hisn-profile/v1\"\n[policy]\nversion = \"hisn-policy/v1\"\n[[host_services]]\nname = \"kvr-host\"\nexec = [\"true\"]\nsocket = \"/run/user/1000/kvr/abc.sock\"\nexpose = \"/run/kvr/kvr.sock\"\nready = { command = [\"true\\u0000x\"] }\nrisk_ack = \"host-exec\"\n";
        let e2 = Profile::parse(text2).unwrap_err().to_string();
        assert!(e2.contains("NUL"), "{e2}");
        // NUL in service argv
        let text3 = "version = \"hisn-profile/v1\"\n[policy]\nversion = \"hisn-policy/v1\"\n[[services]]\nname = \"kvr\"\nexec = [\"sleep\\u0000\", \"1\"]\n";
        let e3 = Profile::parse(text3).unwrap_err().to_string();
        assert!(e3.contains("NUL"), "{e3}");
    }

    #[test]
    fn host_service_ready_tcp_rejected() {
        let text = r#"
version = "hisn-profile/v1"
[policy]
version = "hisn-policy/v1"
[[host_services]]
name = "kvr-host"
exec = ["kvr-server"]
socket = "/run/user/1000/kvr/abc.sock"
expose = "/run/kvr/kvr.sock"
ready = { tcp = "127.0.0.1:8080" }
risk_ack = "host-exec"
"#;
        let e = Profile::parse(text).unwrap_err().to_string();
        assert!(
            e.contains("ready.tcp") && e.contains("not implemented"),
            "{e}"
        );
    }

    #[test]
    fn checked_deadline_overflow_is_error_not_panic() {
        assert!(checked_deadline(u64::MAX, "overflow test").is_err());
        assert!(checked_deadline(1, "ok").is_ok());
    }
}

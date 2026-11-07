//! `hisn-policy/v1`: schema, loading, validation and resolution.
//!
//! Parsing and syntax validation are pure ([`Policy::parse`]); resolution
//! ([`Policy::resolve`]) touches the filesystem to canonicalise paths and
//! enforces the path rules R1/R2 of POLICY-SPEC §4. R3 (mask overlap) is
//! enforced by the mount planner, which sees the whole plan.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const POLICY_VERSION: &str = "hisn-policy/v1";

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Parse(String),
    /// `key: reason`, matching the spec's error format.
    #[error("{key}: {reason}")]
    Invalid { key: String, reason: String },
}

fn invalid(key: &str, reason: impl Into<String>) -> PolicyError {
    PolicyError::Invalid {
        key: key.into(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    None,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Session {
    /// Working directory, mounted rw at the identical path. Relative paths
    /// resolve against the policy file's directory.
    pub cwd: String,
    /// `"tmpfs"` or an absolute host path (persistent, rw).
    pub home: String,
    pub network: Network,
    /// RFC 1123 label, at most 63 characters.
    pub hostname: String,
    /// Mount /dev/shm (tmpfs) inside the sandbox. Default false.
    pub shm: bool,
    /// /dev/shm size in MiB (default 64; range 1..=65536).
    pub shm_size: u64,
    /// /tmp size in MiB (default 1024; range 16..=65536).
    pub tmp_size: u64,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            cwd: ".".into(),
            home: "tmpfs".into(),
            network: Network::None,
            hostname: "hisn".into(),
            shm: false,
            shm_size: 64,
            tmp_size: 1024,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Mounts {
    /// Extra read-only binds (absolute paths, recursive).
    pub ro: Vec<String>,
    /// Extra read-write binds (absolute paths).
    pub rw: Vec<String>,
    /// Extra paths masked inside allowed trees.
    pub mask: Vec<String>,
    /// Prefixes under which dynamic rw grants are allowed (Landlock write set).
    pub grantable_rw: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EnvPolicy {
    /// Variable names copied from the host environment if set.
    pub pass: Vec<String>,
    /// Literal variables; wins over `pass`.
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SeccompPolicy {
    /// Syscall names added to the built-in denylist.
    pub extra_deny: Vec<String>,
}

/// Which Landlock IPC scopes to apply (ABI >= 6). Default empty: execs of the
/// same session may signal each other and reach each other's abstract unix
/// sockets. Isolation is against the host, not between execs (P17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LandlockScope {
    /// `LANDLOCK_SCOPE_SIGNAL` — execs cannot signal processes in other
    /// Landlock domains of the same session.
    Signal,
    /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — execs cannot connect to
    /// abstract unix sockets bound by processes in other domains.
    AbstractUnixSocket,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LandlockPolicy {
    /// IPC scopes to apply (ABI >= 6). Default empty.
    pub scoped: Vec<LandlockScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// RLIMIT_NOFILE (>= 1).
    pub nofile: u64,
    /// RLIMIT_NPROC (>= 1).
    pub nproc: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            nofile: 65536,
            nproc: 4096,
        }
    }
}

/// The policy as written in `hisn.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "hisn-policy/v1")]
pub struct Policy {
    /// Must be exactly `hisn-policy/v1`.
    pub version: String,
    #[serde(default)]
    pub session: Session,
    #[serde(default)]
    pub mounts: Mounts,
    #[serde(default)]
    pub env: EnvPolicy,
    #[serde(default)]
    pub seccomp: SeccompPolicy,
    #[serde(default)]
    pub landlock: LandlockPolicy,
    #[serde(default)]
    pub limits: Limits,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION.into(),
            session: Session::default(),
            mounts: Mounts::default(),
            env: EnvPolicy::default(),
            seccomp: SeccompPolicy::default(),
            landlock: LandlockPolicy::default(),
            limits: Limits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "path", rename_all = "lowercase")]
pub enum Home {
    Tmpfs,
    Path(PathBuf),
}

/// One read-only bind (0.3.3). `src` is the canonical host path; `dst` the
/// in-session path. Same-path entries have `src == dst`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoBind {
    pub src: PathBuf,
    pub dst: PathBuf,
}

/// Split a `mounts.ro` entry into `(src, dst)` (0.3.3). `"/p"` is `("/p",
/// "/p")`; `"src:dst"` splits at the first `:`. Both sides must be absolute and
/// NUL-free. The raw strings are returned; canonicalisation happens in `resolve`.
pub fn split_ro_entry(raw: &str) -> Result<(String, String), String> {
    if raw.contains('\0') {
        return Err("NUL byte in path".into());
    }
    match raw.split_once(':') {
        None => {
            if !raw.starts_with('/') {
                return Err(format!("{raw:?} is not an absolute path"));
            }
            Ok((raw.to_owned(), raw.to_owned()))
        }
        Some((src, dst)) => {
            if !src.starts_with('/') || !dst.starts_with('/') {
                return Err(format!(
                    "{raw:?}: src:dst needs two absolute paths (src is a host path, dst an in-session path)"
                ));
            }
            if dst.contains(':') || src.contains(':') {
                return Err(format!("{raw:?}: only one ':' separates src and dst"));
            }
            Ok((src.to_owned(), dst.to_owned()))
        }
    }
}

/// Fully resolved policy: absolute, canonical paths; CLI overrides applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    pub version: String,
    pub cwd: PathBuf,
    pub home: Home,
    pub network: Network,
    pub hostname: String,
    /// In-session target paths of the read-only binds (`ro_binds[i].dst`).
    pub ro: Vec<PathBuf>,
    /// Read-only binds with their host source (0.3.3, `src:dst`). A same-path
    /// entry has `src == dst`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ro_binds: Vec<RoBind>,
    pub rw: Vec<PathBuf>,
    pub mask: Vec<PathBuf>,
    pub grantable_rw: Vec<PathBuf>,
    pub env_pass: Vec<String>,
    pub env_set: BTreeMap<String, String>,
    pub extra_deny: Vec<String>,
    pub landlock_scoped: Vec<LandlockScope>,
    pub nofile: u64,
    pub nproc: u64,
    pub shm: bool,
    pub shm_size: u64,
    pub tmp_size: u64,
    /// 0.3.2: the rootfs path if set (from `[rootfs]` or `--rootfs-path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<PathBuf>,
    /// 0.3.3: `[net] nameservers` from the profile; replaces the host-derived
    /// resolver list when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<Vec<String>>,
}

/// CLI flags that take precedence over the policy file.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub cwd: Option<PathBuf>,
    pub network: Option<Network>,
    /// `--home-persist`: overrides the profile's `[home] persist`.
    pub home_persist: Option<String>,
    /// `--rootfs-path`: overrides the profile's `[rootfs] path`.
    pub rootfs_path: Option<String>,
    /// `[net] nameservers` from the profile (0.3.3).
    pub nameservers: Option<Vec<String>>,
}

pub fn is_valid_env_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// RFC 1123 label: 1..=63 of `[A-Za-z0-9-]`, not starting/ending with `-`.
pub fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Session ids become directory names: `[A-Za-z0-9._-]{1,64}`, not `.`/`..`.
pub fn is_valid_session_id(s: &str) -> bool {
    // A leading '.' is reserved for in-progress `.tmp-<id>` publication
    // directories (0.4.0), so no session id may begin with one.
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_valid_syscall_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// R1/R2 (POLICY-SPEC §4): reject `path` if it is, contains, or lies inside a
/// runtime root, or is `/` or inside/equal to `/proc`, `/sys`, `/dev`.
pub fn check_forbidden(path: &Path, runtime_roots: &[PathBuf]) -> Result<(), String> {
    if path == Path::new("/") {
        return Err("`/` may not be mounted".into());
    }
    for special in ["/proc", "/sys", "/dev"] {
        if path.starts_with(special) {
            return Err(format!("{} is not mountable from policy", path.display()));
        }
    }
    for root in runtime_roots {
        if path.starts_with(root) || root.starts_with(path) {
            return Err(format!(
                "{} overlaps the hisn runtime directory {}",
                path.display(),
                root.display()
            ));
        }
    }
    Ok(())
}

/// Lexically normalise an absolute path (no filesystem access): drops `.`,
/// resolves `..`. Used for paths that must not exist yet or must not be
/// symlink-resolved.
pub fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

impl Policy {
    /// Parse and syntax-validate (no filesystem access).
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let p: Policy = toml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.into(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(invalid(
                "version",
                format!("must be \"{POLICY_VERSION}\", got {:?}", self.version),
            ));
        }
        if !is_valid_hostname(&self.session.hostname) {
            return Err(invalid(
                "session.hostname",
                "not an RFC 1123 label (max 63)",
            ));
        }
        if self.session.cwd.is_empty() {
            return Err(invalid("session.cwd", "must not be empty"));
        }
        if self.session.home != "tmpfs" && !self.session.home.starts_with('/') {
            return Err(invalid(
                "session.home",
                "must be \"tmpfs\" or an absolute path",
            ));
        }
        for e in &self.mounts.ro {
            split_ro_entry(e).map_err(|r| invalid("mounts.ro", r))?;
        }
        for (key, list) in [
            ("mounts.rw", &self.mounts.rw),
            ("mounts.mask", &self.mounts.mask),
            ("mounts.grantable_rw", &self.mounts.grantable_rw),
        ] {
            for p in list {
                if !p.starts_with('/') {
                    return Err(invalid(key, format!("{p:?} is not an absolute path")));
                }
                if p.contains('\0') {
                    return Err(invalid(key, "NUL byte in path"));
                }
            }
        }
        for n in &self.env.pass {
            if !is_valid_env_name(n) {
                return Err(invalid(
                    "env.pass",
                    format!("{n:?} is not a valid variable name"),
                ));
            }
            if n == "HOME" {
                return Err(invalid("env.pass", "HOME cannot be passed"));
            }
        }
        for (k, v) in &self.env.set {
            if !is_valid_env_name(k) {
                return Err(invalid(
                    "env.set",
                    format!("{k:?} is not a valid variable name"),
                ));
            }
            if k == "HOME" {
                return Err(invalid("env.set", "HOME cannot be set"));
            }
            if v.contains('\0') {
                return Err(invalid("env.set", format!("NUL byte in value of {k}")));
            }
        }
        for s in &self.seccomp.extra_deny {
            if !is_valid_syscall_name(s) {
                return Err(invalid(
                    "seccomp.extra_deny",
                    format!("{s:?} is not a syscall name"),
                ));
            }
        }
        if self.limits.nofile < 1 {
            return Err(invalid("limits.nofile", "must be >= 1"));
        }
        if self.limits.nproc < 1 {
            return Err(invalid("limits.nproc", "must be >= 1"));
        }
        if self.session.shm_size < 1 || self.session.shm_size > 65536 {
            return Err(invalid("session.shm_size", "must be in 1..=65536"));
        }
        if self.session.tmp_size < 16 || self.session.tmp_size > 65536 {
            return Err(invalid("session.tmp_size", "must be in 16..=65536"));
        }
        Ok(())
    }

    /// Resolve against the filesystem.
    ///
    /// `base_dir`: directory of the policy file (or the process cwd) for the
    /// policy's relative `cwd`. `runtime_roots`: hisn runtime directories
    /// (R1). `overrides.cwd` is resolved against the process cwd.
    pub fn resolve(
        &self,
        base_dir: &Path,
        overrides: &Overrides,
        runtime_roots: &[PathBuf],
    ) -> Result<ResolvedPolicy, PolicyError> {
        self.validate()?;

        let cwd_raw = match &overrides.cwd {
            Some(p) => p.clone(),
            None => base_dir.join(&self.session.cwd),
        };
        let cwd = fs::canonicalize(&cwd_raw)
            .map_err(|e| invalid("session.cwd", format!("{}: {e}", cwd_raw.display())))?;
        if !cwd.is_dir() {
            return Err(invalid(
                "session.cwd",
                format!("{} is not a directory", cwd.display()),
            ));
        }
        check_forbidden(&cwd, runtime_roots).map_err(|r| invalid("session.cwd", r))?;

        let home = if self.session.home == "tmpfs" {
            Home::Tmpfs
        } else {
            let p = existing_dir("session.home", &self.session.home, runtime_roots)?;
            Home::Path(p)
        };

        // 0.3.2: `[home] persist` override (from profile or --home-persist).
        // Expands ~, canonicalises the parent, checks the refuse list, creates
        // the directory if missing, and overrides `home`.
        let home = match &overrides.home_persist {
            Some(raw) => resolve_home_persist(raw, &cwd, runtime_roots)?,
            None => home,
        };

        // 0.3.2: `[rootfs]` or `--rootfs-path`. The path must be an existing
        // directory; the rootfs store resolves names to paths in
        // `$XDG_DATA_HOME/hisn/rootfs/<name>/`.
        let rootfs = match &overrides.rootfs_path {
            Some(raw) => {
                let p = existing_dir("rootfs.path", raw, runtime_roots)?;
                crate::rootfs_store::check_layout(&p).map_err(|e| invalid("rootfs.path", e))?;
                Some(p)
            }
            None => None,
        };

        // 0.3.3: `mounts.ro` entries are `path` or `src:dst`. `src` is a host
        // path, resolved here exactly like any other mount source (symlinked
        // final component refused, intermediate links canonicalised on the host).
        // `dst` is an in-session path: lexically normalised, never under a
        // hisn runtime root.
        let mut ro = Vec::new();
        let mut ro_binds = Vec::new();
        for raw in &self.mounts.ro {
            let (src_raw, dst_raw) = split_ro_entry(raw).map_err(|r| invalid("mounts.ro", r))?;
            let src = existing_dir_or_file("mounts.ro", &src_raw, runtime_roots)?;
            // 0.3.3 (review): a host source under /etc would re-expose the
            // host's /etc, or a masked entry of it, at dst, bypassing the
            // generated /etc view and its masks (R3 is checked on dst only).
            if src.starts_with("/etc") {
                return Err(invalid(
                    "mounts.ro",
                    format!(
                        "{raw}: src {} is under /etc; the generated /etc view must not be re-exposed",
                        src.display()
                    ),
                ));
            }
            let dst = if src_raw == dst_raw {
                src.clone()
            } else {
                if Path::new(&dst_raw)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(invalid(
                        "mounts.ro",
                        format!("{raw}: dst must not contain '..'"),
                    ));
                }
                let d = lexical_normalize(Path::new(&dst_raw));
                check_forbidden(&d, runtime_roots).map_err(|r| invalid("mounts.ro", r))?;
                if d == Path::new("/run/hisn") || d.starts_with("/run/hisn") {
                    return Err(invalid(
                        "mounts.ro",
                        format!("{raw}: dst {} is under /run/hisn", d.display()),
                    ));
                }
                d
            };
            ro.push(dst.clone());
            ro_binds.push(RoBind { src, dst });
        }
        let rw = self.resolve_list("mounts.rw", &self.mounts.rw, runtime_roots)?;
        let grantable_rw = self.resolve_list(
            "mounts.grantable_rw",
            &self.mounts.grantable_rw,
            runtime_roots,
        )?;
        // A rootfs is the session's toolchain: it must not be reachable
        // read-write through any other mount (cwd, rw, grantable_rw, home),
        // or the session could rewrite the image later sessions run from.
        if let Some(r) = &rootfs {
            let home_dir = match &home {
                Home::Path(h) => Some(h),
                Home::Tmpfs => None,
            };
            for (what, w) in std::iter::once(("session.cwd", &cwd))
                .chain(rw.iter().map(|x| ("mounts.rw", x)))
                .chain(grantable_rw.iter().map(|x| ("mounts.grantable_rw", x)))
                .chain(home_dir.map(|h| ("home", h)))
            {
                if r.starts_with(w) || w.starts_with(r) {
                    return Err(invalid(
                        "rootfs.path",
                        format!(
                            "{} overlaps the writable {what} {}; the session could modify its own toolchain",
                            r.display(),
                            w.display()
                        ),
                    ));
                }
            }
        }
        // Masks may name paths that do not exist yet (then there is nothing to
        // hide): normalise lexically, apply R1/R2, never follow symlinks.
        let mut mask = Vec::new();
        for m in &self.mounts.mask {
            let p = lexical_normalize(Path::new(m));
            check_forbidden(&p, runtime_roots).map_err(|r| invalid("mounts.mask", r))?;
            mask.push(p);
        }

        Ok(ResolvedPolicy {
            version: self.version.clone(),
            cwd,
            home,
            network: overrides.network.unwrap_or(self.session.network),
            hostname: self.session.hostname.clone(),
            ro,
            ro_binds,
            rw,
            mask,
            grantable_rw,
            env_pass: self.env.pass.clone(),
            env_set: self.env.set.clone(),
            extra_deny: self.seccomp.extra_deny.clone(),
            landlock_scoped: self.landlock.scoped.clone(),
            nofile: self.limits.nofile,
            nproc: self.limits.nproc,
            shm: self.session.shm,
            shm_size: self.session.shm_size,
            tmp_size: self.session.tmp_size,
            rootfs,
            nameservers: overrides.nameservers.clone(),
        })
    }

    fn resolve_list(
        &self,
        key: &str,
        list: &[String],
        runtime_roots: &[PathBuf],
    ) -> Result<Vec<PathBuf>, PolicyError> {
        list.iter()
            .map(|p| existing_dir_or_file(key, p, runtime_roots))
            .collect()
    }
}

/// Existing path whose *final component is not a symlink*, canonicalised.
fn existing_dir_or_file(
    key: &str,
    raw: &str,
    runtime_roots: &[PathBuf],
) -> Result<PathBuf, PolicyError> {
    let meta = fs::symlink_metadata(raw).map_err(|e| invalid(key, format!("{raw}: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(invalid(
            key,
            format!("{raw} is a symlink; name the target instead"),
        ));
    }
    let p = fs::canonicalize(raw).map_err(|e| invalid(key, format!("{raw}: {e}")))?;
    check_forbidden(&p, runtime_roots).map_err(|r| invalid(key, r))?;
    Ok(p)
}

fn existing_dir(key: &str, raw: &str, runtime_roots: &[PathBuf]) -> Result<PathBuf, PolicyError> {
    let p = existing_dir_or_file(key, raw, runtime_roots)?;
    if !p.is_dir() {
        return Err(invalid(key, format!("{raw} is not a directory")));
    }
    Ok(p)
}

/// Expand `~` at the start of a path to the invoking user's home directory.
fn expand_tilde(raw: &str) -> String {
    if raw == "~" {
        return std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    }
    if let Some(rest) = raw.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    raw.to_string()
}

/// Host trees no persist dir may live in.
const HOME_REFUSE_TREES: [&str; 12] = [
    "/etc", "/dev", "/proc", "/sys", "/usr", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/opt",
    "/nix",
];
/// Shared directories refused as the persist dir itself.
const HOME_REFUSE_EXACT: [&str; 6] = ["/tmp", "/var", "/var/tmp", "/run", "/root", "/home"];

/// hisn's per-user config and data directories (`$XDG_CONFIG_HOME/hisn`,
/// `$XDG_DATA_HOME/hisn`, with the usual `$HOME` fallbacks).
fn hisn_state_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg = |var: &str, fallback: &str| {
        std::env::var_os(var)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(fallback)))
            .map(|d| d.join("hisn"))
    };
    [
        xdg("XDG_CONFIG_HOME", ".config"),
        xdg("XDG_DATA_HOME", ".local/share"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Resolve a `[home] persist` path (0.3.2).
///
/// Expands `~`, canonicalises the parent (which must exist), creates the
/// final directory if missing (mode 0700, owned by the invoking user), and
/// checks the refuse list before any namespace is created.
///
/// **Refuse list**: the real host `$HOME` or any ancestor of it, `/`, the
/// resolved session cwd, any ancestor of the session cwd, a runtime root,
/// or a path that is not a directory after creation.
fn resolve_home_persist(
    raw: &str,
    cwd: &Path,
    runtime_roots: &[PathBuf],
) -> Result<Home, PolicyError> {
    let host_home = std::env::var("HOME").ok().map(PathBuf::from);
    resolve_home_persist_with(raw, cwd, runtime_roots, host_home.as_deref())
}

/// [`resolve_home_persist`] with the real host `$HOME` passed in (so tests
/// do not mutate the process environment).
fn resolve_home_persist_with(
    raw: &str,
    cwd: &Path,
    runtime_roots: &[PathBuf],
    host_home: Option<&Path>,
) -> Result<Home, PolicyError> {
    let expanded = expand_tilde(raw);
    let raw_path = PathBuf::from(&expanded);
    if !raw_path.is_absolute() {
        return Err(invalid(
            "home.persist",
            format!("{raw:?} is not an absolute path"),
        ));
    }
    // Canonicalise the parent (which must exist), then join the final component.
    let parent = raw_path
        .parent()
        .ok_or_else(|| invalid("home.persist", "path has no parent"))?;
    let parent_canon = fs::canonicalize(parent)
        .map_err(|e| invalid("home.persist", format!("{}: {e}", parent.display())))?;
    let final_name = raw_path
        .file_name()
        .ok_or_else(|| invalid("home.persist", "path has no final component"))?;
    let path = parent_canon.join(final_name);
    // Check the refuse list before any filesystem mutation.
    // Refuse: the real host $HOME or any ancestor of it.
    if let Some(hh) = host_home {
        let hh_canon = fs::canonicalize(hh).ok();
        if let Some(hhc) = hh_canon {
            if path == hhc {
                return Err(invalid("home.persist", "must not be the real host $HOME"));
            }
            // Refuse if the persist path is an ancestor of the real host
            // $HOME (e.g. persist="/home" when $HOME="/home/valon"). The
            // persist dir would contain the real home, handing the session
            // read/write access to the parent of $HOME.
            if hhc.starts_with(&path) {
                return Err(invalid(
                    "home.persist",
                    format!(
                        "{} is an ancestor of the real host $HOME ({})",
                        path.display(),
                        hhc.display()
                    ),
                ));
            }
        }
    }
    // Refuse: `/`.
    if path == Path::new("/") {
        return Err(invalid("home.persist", "/ is not a valid persist dir"));
    }
    // Refuse: the session cwd or any ancestor of it.
    if path == *cwd {
        return Err(invalid("home.persist", "must not be the session cwd"));
    }
    // Refuse: any ancestor of the session cwd (the persist dir must not
    // contain the cwd).
    if cwd.starts_with(&path) && path != *cwd {
        return Err(invalid(
            "home.persist",
            format!("{} is an ancestor of the session cwd", path.display()),
        ));
    }
    // Refuse: fixed host trees. Subtrees of these are never a home; the
    // shared roots below are refused only as the exact directory (a private
    // child of /tmp is a normal place for a persist dir).
    for tree in HOME_REFUSE_TREES {
        if path.starts_with(tree) {
            return Err(invalid(
                "home.persist",
                format!("{} is inside the host tree {tree}", path.display()),
            ));
        }
    }
    for dir in HOME_REFUSE_EXACT {
        if path == Path::new(dir) {
            return Err(invalid(
                "home.persist",
                format!("{dir} is a shared host directory, not a persist dir"),
            ));
        }
    }
    // Refuse: hisn's own config and data (profiles, rootfs store): a session
    // that could write them would poison every later session.
    for state in hisn_state_dirs() {
        let state = fs::canonicalize(&state).unwrap_or(state);
        if path.starts_with(&state) || state.starts_with(&path) {
            return Err(invalid(
                "home.persist",
                format!(
                    "{} overlaps hisn's own state directory {}",
                    path.display(),
                    state.display()
                ),
            ));
        }
    }
    // Refuse: overlaps a runtime root.
    check_forbidden(&path, runtime_roots).map_err(|r| invalid("home.persist", r))?;
    // Create the directory if missing (mode 0700, owned by the invoking user).
    if !path.exists() {
        fs::create_dir(&path)
            .map_err(|e| invalid("home.persist", format!("create {}: {e}", path.display())))?;
        // Set permissions to 0700.
        let meta = fs::metadata(&path)
            .map_err(|e| invalid("home.persist", format!("stat {}: {e}", path.display())))?;
        let mut perms = meta.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        fs::set_permissions(&path, perms)
            .map_err(|e| invalid("home.persist", format!("chmod {}: {e}", path.display())))?;
    }
    // Verify it is a directory.
    let meta = fs::symlink_metadata(&path)
        .map_err(|e| invalid("home.persist", format!("stat {}: {e}", path.display())))?;
    if !meta.is_dir() {
        return Err(invalid(
            "home.persist",
            format!("{} is not a directory", path.display()),
        ));
    }
    // Verify it is not a symlink (the final component).
    if meta.file_type().is_symlink() {
        return Err(invalid(
            "home.persist",
            format!("{} is a symlink; name the target instead", path.display()),
        ));
    }
    // The directory must belong to the invoking user (a pre-existing dir of
    // someone else, e.g. in a sticky /tmp, is not ours to hand out).
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != rustix::process::getuid().as_raw() {
            return Err(invalid(
                "home.persist",
                format!("{} is not owned by the invoking user", path.display()),
            ));
        }
    }
    // Canonicalise the full path (now it exists).
    let canon = fs::canonicalize(&path)
        .map_err(|e| invalid("home.persist", format!("{}: {e}", path.display())))?;
    Ok(Home::Path(canon))
}

impl ResolvedPolicy {
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("resolved policy serializes to TOML")
    }
}

/// JSON Schema for `hisn-policy/v1` (what `hisn policy schema` prints and
/// `schemas/hisn-policy.v1.json` contains).
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(Policy);
    serde_json::to_string_pretty(&schema).expect("schema serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn minimal_policy_gets_defaults() {
        let p = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        assert_eq!(p, Policy::default());
        assert_eq!(p.limits.nofile, 65536);
        assert_eq!(p.session.network, Network::None);
        assert!(!p.session.shm);
        assert_eq!(p.session.shm_size, 64);
        assert_eq!(p.session.tmp_size, 1024);
    }

    #[test]
    fn shm_and_tmp_size_parse_and_resolve() {
        let p = Policy::parse(
            r#"
version = "hisn-policy/v1"
[session]
shm = true
shm_size = 128
tmp_size = 512
"#,
        )
        .unwrap();
        assert!(p.session.shm);
        assert_eq!(p.session.shm_size, 128);
        assert_eq!(p.session.tmp_size, 512);
        let d = tempfile::tempdir().unwrap();
        let r = p.resolve(d.path(), &Overrides::default(), &[]).unwrap();
        assert!(r.shm);
        assert_eq!(r.shm_size, 128);
        assert_eq!(r.tmp_size, 512);
    }

    #[test]
    fn brief_example_parses() {
        let p = Policy::parse(
            r#"
version = "hisn-policy/v1"
[session]
cwd = "."
home = "tmpfs"
network = "none"
hostname = "hisn"
[mounts]
ro = ["/opt/toolchains"]
rw = []
mask = []
[env]
pass = ["GOFLAGS", "RUSTFLAGS"]
set  = { CI = "1" }
[seccomp]
extra_deny = []
[limits]
nofile = 65536
nproc  = 4096
"#,
        )
        .unwrap();
        assert_eq!(p.env.pass, ["GOFLAGS", "RUSTFLAGS"]);
        assert_eq!(p.env.set["CI"], "1");
    }

    #[test]
    fn unknown_keys_are_errors_at_every_level() {
        for bad in [
            "version = \"hisn-policy/v1\"\nbogus = 1",
            "version = \"hisn-policy/v1\"\n[session]\nbogus = 1",
            "version = \"hisn-policy/v1\"\n[mounts]\nbogus = []",
            "version = \"hisn-policy/v1\"\n[env]\nbogus = []",
            "version = \"hisn-policy/v1\"\n[seccomp]\nbogus = []",
            "version = \"hisn-policy/v1\"\n[landlock]\nbogus = []",
            "version = \"hisn-policy/v1\"\n[limits]\nbogus = 1",
            "version = \"hisn-policy/v1\"\n[bogus]\nx = 1",
        ] {
            assert!(
                matches!(Policy::parse(bad), Err(PolicyError::Parse(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn landlock_scoped_parses_and_rejects_unknown_values() {
        let p = Policy::parse(
            r#"
version = "hisn-policy/v1"
[landlock]
scoped = ["signal", "abstract_unix_socket"]
"#,
        )
        .unwrap();
        assert_eq!(
            p.landlock.scoped,
            [LandlockScope::Signal, LandlockScope::AbstractUnixSocket]
        );
        // default is empty
        let d = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        assert!(d.landlock.scoped.is_empty());
        // unknown value is a parse error
        assert!(
            Policy::parse(
                r#"
version = "hisn-policy/v1"
[landlock]
scoped = ["bogus"]
"#
            )
            .is_err()
        );
        // the resolved policy carries the scopes
        let d = tempfile::tempdir().unwrap();
        let r = p.resolve(d.path(), &Overrides::default(), &[]).unwrap();
        assert_eq!(
            r.landlock_scoped,
            [LandlockScope::Signal, LandlockScope::AbstractUnixSocket]
        );
    }

    #[test]
    fn version_is_required_and_exact() {
        assert!(matches!(Policy::parse(""), Err(PolicyError::Parse(_))));
        let e = Policy::parse("version = \"hisn-policy/v2\"").unwrap_err();
        assert!(e.to_string().starts_with("version:"), "{e}");
    }

    #[test]
    fn syntax_validation() {
        let base = "version = \"hisn-policy/v1\"\n";
        for (extra, key) in [
            ("[session]\nhostname = \"-bad\"", "session.hostname"),
            ("[session]\nhostname = \"a_b\"", "session.hostname"),
            ("[session]\nhome = \"rel/path\"", "session.home"),
            ("[session]\nnetwork = \"bridge\"", ""),
            ("[mounts]\nro = [\"rel\"]", "mounts.ro"),
            ("[env]\npass = [\"1BAD\"]", "env.pass"),
            ("[env]\npass = [\"HOME\"]", "env.pass"),
            ("[env]\nset = { HOME = \"/x\" }", "env.set"),
            (
                "[seccomp]\nextra_deny = [\"Not A Name\"]",
                "seccomp.extra_deny",
            ),
            ("[limits]\nnofile = 0", "limits.nofile"),
            ("[limits]\nnproc = -1", ""),
            ("[session]\nshm_size = 0", "session.shm_size"),
            ("[session]\ntmp_size = 1", "session.tmp_size"),
        ] {
            let e = Policy::parse(&format!("{base}{extra}"))
                .unwrap_err()
                .to_string();
            assert!(e.contains(key), "{extra} -> {e}");
        }
    }

    #[test]
    fn hostname_and_session_id_rules() {
        assert!(is_valid_hostname("hisn"));
        assert!(is_valid_hostname("a-b-1"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname(&"a".repeat(64)));
        assert!(is_valid_session_id("agent-1.run_2"));
        assert!(!is_valid_session_id(".."));
        assert!(!is_valid_session_id("a/b"));
        assert!(!is_valid_session_id(&"a".repeat(65)));
    }

    #[test]
    fn forbidden_paths() {
        let roots = vec![PathBuf::from("/run/user/1000/hisn")];
        assert!(check_forbidden(Path::new("/"), &roots).is_err());
        assert!(check_forbidden(Path::new("/proc"), &roots).is_err());
        assert!(check_forbidden(Path::new("/sys/fs"), &roots).is_err());
        assert!(check_forbidden(Path::new("/dev"), &roots).is_err());
        // equal, inside, and ancestor of the runtime root
        assert!(check_forbidden(Path::new("/run/user/1000/hisn"), &roots).is_err());
        assert!(check_forbidden(Path::new("/run/user/1000/hisn/s1"), &roots).is_err());
        assert!(check_forbidden(Path::new("/run/user"), &roots).is_err());
        // unrelated, including a sibling with a shared name prefix
        assert!(check_forbidden(Path::new("/run/user/1000/hisnx"), &roots).is_ok());
        assert!(check_forbidden(Path::new("/home/u/proj"), &roots).is_ok());
    }

    #[test]
    fn lexical_normalization() {
        assert_eq!(
            lexical_normalize(Path::new("/a/./b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(lexical_normalize(Path::new("/../..")), PathBuf::from("/"));
    }

    #[test]
    fn ro_entry_grammar() {
        assert_eq!(
            split_ro_entry("/a/b").unwrap(),
            ("/a/b".into(), "/a/b".into())
        );
        assert_eq!(
            split_ro_entry("/host/x:/in/x").unwrap(),
            ("/host/x".into(), "/in/x".into())
        );
        assert!(split_ro_entry("rel").is_err());
        assert!(split_ro_entry("/host:rel").is_err());
        assert!(split_ro_entry("rel:/in").is_err());
        assert!(split_ro_entry("/a:/b:/c").is_err());
        assert!(split_ro_entry("/a\0:/b").is_err());
    }

    #[test]
    fn ro_src_dst_resolves_the_host_source_and_keeps_dst() {
        let d = tmp();
        let host = d.path().join("host.conf");
        fs::write(&host, "x").unwrap();
        let spec = format!("{}:/etc-like/app.conf", host.to_str().unwrap());
        let pol = Policy::parse(&format!(
            "version = \"hisn-policy/v1\"\n[mounts]\nro = [{spec:?}]\n"
        ))
        .unwrap();
        let r = pol.resolve(d.path(), &Overrides::default(), &[]).unwrap();
        assert_eq!(r.ro, vec![PathBuf::from("/etc-like/app.conf")]);
        assert_eq!(
            r.ro_binds,
            vec![RoBind {
                src: fs::canonicalize(&host).unwrap(),
                dst: PathBuf::from("/etc-like/app.conf"),
            }]
        );
    }

    #[test]
    fn ro_src_is_resolved_on_the_host_symlinks_refused_at_the_final_component() {
        let d = tmp();
        let real = d.path().join("real.txt");
        fs::write(&real, "x").unwrap();
        let link = d.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // a symlinked final src component is refused, as for every mount source
        let pol = Policy::parse(&format!(
            "version = \"hisn-policy/v1\"\n[mounts]\nro = [{:?}]\n",
            format!("{}:/in/x", link.to_str().unwrap())
        ))
        .unwrap();
        let e = pol
            .resolve(d.path(), &Overrides::default(), &[])
            .unwrap_err();
        assert!(e.to_string().contains("is a symlink"), "{e}");
    }

    #[test]
    fn ro_src_under_etc_is_rejected() {
        // The reviewer's case: a relocated host /etc or masked /etc entry must
        // not re-expose what the generated /etc view hides.
        for src in ["/etc", "/etc/hosts"] {
            let pol = Policy::parse(&format!(
                "version = \"hisn-policy/v1\"\n[mounts]\nro = [{:?}]\n",
                format!("{src}:/exposed")
            ))
            .unwrap();
            let d = tmp();
            let e = pol
                .resolve(d.path(), &Overrides::default(), &[])
                .unwrap_err()
                .to_string();
            assert!(e.contains("under /etc"), "{src}: {e}");
        }
    }

    #[test]
    fn ro_dst_under_hisn_runtime_is_rejected_and_names_the_path() {
        let d = tmp();
        let host = d.path().join("h");
        fs::write(&host, "x").unwrap();
        let spec = format!("{}:/run/hisn/evil", host.to_str().unwrap());
        let pol = Policy::parse(&format!(
            "version = \"hisn-policy/v1\"\n[mounts]\nro = [{spec:?}]\n"
        ))
        .unwrap();
        let e = pol
            .resolve(d.path(), &Overrides::default(), &[])
            .unwrap_err();
        let s = e.to_string();
        assert!(s.contains("/run/hisn/evil"), "{s}");
    }

    #[test]
    fn ro_dst_with_dotdot_is_rejected() {
        let d = tmp();
        let host = d.path().join("h");
        fs::write(&host, "x").unwrap();
        let spec = format!("{}:/a/../b", host.to_str().unwrap());
        let pol = Policy::parse(&format!(
            "version = \"hisn-policy/v1\"\n[mounts]\nro = [{spec:?}]\n"
        ))
        .unwrap();
        assert!(pol.resolve(d.path(), &Overrides::default(), &[]).is_err());
    }

    #[test]
    fn resolve_applies_overrides_and_canonicalises() {
        let d = tmp();
        let proj = d.path().join("proj");
        fs::create_dir(&proj).unwrap();
        let toolchain = d.path().join("tc");
        fs::create_dir(&toolchain).unwrap();
        let pol = Policy::parse(&format!(
            "version = \"hisn-policy/v1\"\n[session]\ncwd = \"proj\"\nnetwork = \"host\"\n[mounts]\nro = [{:?}]\nmask = [\"/x/./y/../z\"]\n",
            toolchain.to_str().unwrap()
        ))
        .unwrap();
        let r = pol.resolve(d.path(), &Overrides::default(), &[]).unwrap();
        assert_eq!(r.cwd, fs::canonicalize(&proj).unwrap());
        assert_eq!(r.network, Network::Host);
        assert_eq!(r.ro, vec![fs::canonicalize(&toolchain).unwrap()]);
        assert_eq!(r.mask, vec![PathBuf::from("/x/z")]);
        assert_eq!(r.home, Home::Tmpfs);

        let o = Overrides {
            cwd: Some(toolchain.clone()),
            network: Some(Network::None),
            home_persist: None,
            rootfs_path: None,
            nameservers: None,
        };
        let r = pol.resolve(d.path(), &o, &[]).unwrap();
        assert_eq!(r.cwd, fs::canonicalize(&toolchain).unwrap());
        assert_eq!(r.network, Network::None);
        // round-trips through the resolved TOML
        let back: ResolvedPolicy = toml::from_str(&r.to_toml()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn resolve_rejects_bad_paths() {
        let d = tmp();
        let sub = d.path().join("s");
        fs::create_dir(&sub).unwrap();
        let link = d.path().join("l");
        std::os::unix::fs::symlink(&sub, &link).unwrap();
        let file = d.path().join("f");
        fs::write(&file, b"x").unwrap();

        let mk = |extra: String| {
            Policy::parse(&format!("version = \"hisn-policy/v1\"\n{extra}")).unwrap()
        };
        let none = Overrides::default();

        let e = mk(format!("[mounts]\nro = [{:?}]", link.to_str().unwrap()))
            .resolve(d.path(), &none, &[])
            .unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        let e = mk(format!(
            "[mounts]\nrw = [{:?}]",
            d.path().join("nope").to_str().unwrap()
        ))
        .resolve(d.path(), &none, &[])
        .unwrap_err();
        assert!(e.to_string().starts_with("mounts.rw:"), "{e}");
        let e = mk(format!("[session]\ncwd = {:?}", file.to_str().unwrap()))
            .resolve(d.path(), &none, &[])
            .unwrap_err();
        assert!(e.to_string().contains("not a directory"), "{e}");
        let e = mk(format!("[session]\ncwd = {:?}", sub.to_str().unwrap()))
            .resolve(d.path(), &none, &[fs::canonicalize(&sub).unwrap()])
            .unwrap_err();
        assert!(e.to_string().contains("runtime"), "{e}");
        let e = mk("[mounts]\nro = [\"/proc\"]".into())
            .resolve(d.path(), &none, &[])
            .unwrap_err();
        assert!(e.to_string().starts_with("mounts.ro:"), "{e}");
    }

    #[test]
    fn schema_forbids_additional_properties_and_requires_version() {
        let v: serde_json::Value = serde_json::from_str(&schema_json()).unwrap();
        assert_eq!(v["additionalProperties"], false);
        assert_eq!(v["required"], serde_json::json!(["version"]));
        assert_eq!(v["title"], "hisn-policy/v1");
    }

    #[test]
    fn home_persist_refuses_real_host_home() {
        let d = tmp();
        let home_dir = d.path().join("home");
        fs::create_dir(&home_dir).unwrap();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let err = resolve_home_persist_with(home_dir.to_str().unwrap(), &cwd, &[], Some(&home_dir))
            .unwrap_err()
            .to_string();
        assert!(err.contains("real host $HOME"), "{err}");
    }

    #[test]
    fn home_persist_refuses_ancestor_of_real_host_home() {
        let d = tmp();
        let parent = d.path().join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let err = resolve_home_persist_with(parent.to_str().unwrap(), &cwd, &[], Some(&child))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ancestor of the real host $HOME"), "{err}");
    }

    #[test]
    fn home_persist_refuses_root() {
        // "/" as persist → refused (no valid parent, or caught by the /
        // check). Either way it must be an error.
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let ov = Overrides {
            home_persist: Some("/".to_string()),
            ..Default::default()
        };
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        assert!(pol.resolve(&cwd, &ov, &[]).is_err());
    }

    #[test]
    fn home_persist_refuses_session_cwd() {
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let ov = Overrides {
            home_persist: Some(cwd.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        let err = pol.resolve(&cwd, &ov, &[]).unwrap_err().to_string();
        assert!(err.contains("session cwd"), "{err}");
    }

    #[test]
    fn home_persist_refuses_ancestor_of_cwd() {
        // persist = parent of cwd → refused.
        let d = tmp();
        let parent = d.path().join("parent");
        let cwd = parent.join("cwd");
        fs::create_dir_all(&cwd).unwrap();
        let ov = Overrides {
            home_persist: Some(parent.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        let err = pol.resolve(&cwd, &ov, &[]).unwrap_err().to_string();
        assert!(err.contains("ancestor of the session cwd"), "{err}");
    }

    #[test]
    fn home_persist_accepts_valid_path() {
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let persist = d.path().join("persist");
        let ov = Overrides {
            home_persist: Some(persist.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        let r = pol.resolve(&cwd, &ov, &[]).unwrap();
        assert!(matches!(r.home, Home::Path(_)));
        assert!(persist.exists(), "persist dir was created");
    }

    #[test]
    fn home_persist_refuses_non_directory() {
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        // Create a file and try to persist at its path — the parent exists
        // but the final component is a file, not a directory.
        let file = d.path().join("notadir");
        fs::write(&file, b"x").unwrap();
        let ov = Overrides {
            home_persist: Some(file.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        let err = pol.resolve(&cwd, &ov, &[]).unwrap_err().to_string();
        assert!(err.contains("not a directory"), "{err}");
    }

    #[test]
    fn home_persist_refuses_fixed_host_trees_and_shared_dirs() {
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        for bad in [
            "/etc", "/etc/ssh", "/dev", "/usr", "/opt", "/tmp", "/var", "/run",
        ] {
            if !Path::new(bad).exists() {
                continue;
            }
            let r = resolve_home_persist_with(bad, &cwd, &[], None);
            assert!(r.is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn home_persist_accepts_a_private_child_of_tmp_and_creates_it_0700() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        let cwd = d.path().join("cwd");
        fs::create_dir(&cwd).unwrap();
        let p = d.path().join("persist");
        let h = resolve_home_persist_with(p.to_str().unwrap(), &cwd, &[], None).unwrap();
        assert!(matches!(h, Home::Path(_)));
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn rootfs_overlapping_a_writable_path_is_refused() {
        let d = tmp();
        let cwd = d.path().join("cwd");
        let img = cwd.join("image");
        fs::create_dir_all(img.join("etc")).unwrap();
        let pol = Policy::parse("version = \"hisn-policy/v1\"").unwrap();
        let ov = Overrides {
            rootfs_path: Some(img.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let e = pol.resolve(&cwd, &ov, &[]).unwrap_err().to_string();
        assert!(e.contains("overlaps the writable session.cwd"), "{e}");
        // Outside the cwd it is accepted.
        let img2 = d.path().join("image2");
        fs::create_dir_all(img2.join("etc")).unwrap();
        let ov2 = Overrides {
            rootfs_path: Some(img2.to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert!(pol.resolve(&cwd, &ov2, &[]).is_ok());
    }
}

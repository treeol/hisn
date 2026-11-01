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
}

impl Default for Session {
    fn default() -> Self {
        Self {
            cwd: ".".into(),
            home: "tmpfs".into(),
            network: Network::None,
            hostname: "hisn".into(),
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

/// Fully resolved policy: absolute, canonical paths; CLI overrides applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    pub version: String,
    pub cwd: PathBuf,
    pub home: Home,
    pub network: Network,
    pub hostname: String,
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub mask: Vec<PathBuf>,
    pub grantable_rw: Vec<PathBuf>,
    pub env_pass: Vec<String>,
    pub env_set: BTreeMap<String, String>,
    pub extra_deny: Vec<String>,
    pub nofile: u64,
    pub nproc: u64,
}

/// CLI flags that take precedence over the policy file.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub cwd: Option<PathBuf>,
    pub network: Option<Network>,
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
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
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
        for (key, list) in [
            ("mounts.ro", &self.mounts.ro),
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

        let ro = self.resolve_list("mounts.ro", &self.mounts.ro, runtime_roots)?;
        let rw = self.resolve_list("mounts.rw", &self.mounts.rw, runtime_roots)?;
        let grantable_rw = self.resolve_list(
            "mounts.grantable_rw",
            &self.mounts.grantable_rw,
            runtime_roots,
        )?;
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
            rw,
            mask,
            grantable_rw,
            env_pass: self.env.pass.clone(),
            env_set: self.env.set.clone(),
            extra_deny: self.seccomp.extra_deny.clone(),
            nofile: self.limits.nofile,
            nproc: self.limits.nproc,
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
}

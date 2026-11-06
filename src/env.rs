//! Environment scrubbing (DESIGN §8, invariant 4): the sandbox environment is
//! built from scratch, never filtered from the host's.

use std::collections::BTreeMap;
use std::path::Path;

use crate::mounts::SANDBOX_HOME;
use crate::policy::ResolvedPolicy;

pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Names copied from the host when set (invariant 4), besides `LC_*`.
const BASE_PASS: [&str; 3] = ["TERM", "LANG", "TZ"];

/// Case-insensitive substrings that make an `env.pass` name look secret.
const SECRETISH: [&str; 5] = ["TOKEN", "SECRET", "KEY", "PASSWORD", "PASSWD"];

/// Cache variables pointed under `$HOME` (brief), as `(name, subpath)`.
const CACHE_VARS: [(&str, &str); 8] = [
    ("XDG_CACHE_HOME", ".cache"),
    ("XDG_CONFIG_HOME", ".config"),
    ("XDG_DATA_HOME", ".local/share"),
    ("CARGO_HOME", ".cargo"),
    ("GOMODCACHE", "go/pkg/mod"),
    ("GOCACHE", ".cache/go-build"),
    ("npm_config_cache", ".npm"),
    ("PIP_CACHE_DIR", ".cache/pip"),
];

/// Result of scrubbing: the child environment plus `env.pass` names that look
/// like secrets (callers log those at warn level; values are never returned
/// separately).
#[derive(Debug, PartialEq, Eq)]
pub struct ScrubbedEnv {
    pub vars: BTreeMap<String, String>,
    pub secretish_passed: Vec<String>,
}

/// Names the session computes itself (`HOME`, `USER`, `LOGNAME` and the cache
/// variables): they can neither be passed through nor overridden, by
/// `env.pass`, `env.set` or an `exec` request (DESIGN §14.5).
pub fn is_computed(name: &str) -> bool {
    matches!(name, "HOME" | "USER" | "LOGNAME") || CACHE_VARS.iter().any(|(n, _)| *n == name)
}

pub fn looks_secret(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    SECRETISH.iter().any(|s| up.contains(s))
}

/// Keep `PATH` entries that point into a tree mounted in the sandbox
/// (`visible(path)`); fall back to [`DEFAULT_PATH`] if none survive.
pub fn filter_path(host_path: Option<&str>, visible: impl Fn(&Path) -> bool) -> String {
    let kept: Vec<&str> = host_path
        .unwrap_or("")
        .split(':')
        .filter(|e| e.starts_with('/') && visible(Path::new(e)))
        .collect();
    if kept.is_empty() {
        DEFAULT_PATH.to_owned()
    } else {
        kept.join(":")
    }
}

/// Build the child environment.
///
/// `host` is the host environment (iterated only for the allowlist);
/// `username` is the sandbox user name (the one in the generated
/// `/etc/passwd`; never read from `host`); `path_visible` decides which host `PATH` entries exist inside the sandbox.
pub fn scrub<'a>(
    policy: &ResolvedPolicy,
    host: impl IntoIterator<Item = (&'a str, &'a str)>,
    username: &str,
    path_visible: impl Fn(&Path) -> bool,
) -> ScrubbedEnv {
    let host: BTreeMap<&str, &str> = host.into_iter().collect();
    let mut vars = BTreeMap::new();

    // 1. Base allowlist from the host.
    for n in BASE_PASS {
        if let Some(v) = host.get(n) {
            vars.insert(n.to_owned(), (*v).to_owned());
        }
    }
    for (n, v) in &host {
        if n.starts_with("LC_") {
            vars.insert((*n).to_owned(), (*v).to_owned());
        }
    }
    vars.insert(
        "PATH".into(),
        filter_path(host.get("PATH").copied(), path_visible),
    );

    // 2. Explicit allowlist from the policy.
    let mut secretish_passed = Vec::new();
    for n in &policy.env_pass {
        if let Some(v) = host.get(n.as_str()) {
            if looks_secret(n) {
                secretish_passed.push(n.clone());
            }
            vars.insert(n.clone(), (*v).to_owned());
        }
    }

    // 3. Literal values win over pass-through.
    for (k, v) in &policy.env_set {
        vars.insert(k.clone(), v.clone());
    }

    // 4. Computed variables; HOME, USER, LOGNAME and the cache dirs cannot be
    //    overridden (they replace anything `env.pass`/`env.set` produced).
    vars.insert("HOME".into(), SANDBOX_HOME.into());
    vars.insert("USER".into(), username.to_owned());
    vars.insert("LOGNAME".into(), username.to_owned());
    for (name, sub) in CACHE_VARS {
        vars.insert(name.into(), format!("{SANDBOX_HOME}/{sub}"));
    }
    ScrubbedEnv {
        vars,
        secretish_passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Home, Network};

    fn pol(pass: &[&str], set: &[(&str, &str)]) -> ResolvedPolicy {
        ResolvedPolicy {
            version: "hisn-policy/v1".into(),
            cwd: "/w".into(),
            home: Home::Tmpfs,
            network: Network::None,
            hostname: "hisn".into(),
            ro: vec![],
            rw: vec![],
            mask: vec![],
            grantable_rw: vec![],
            env_pass: pass.iter().map(|s| s.to_string()).collect(),
            env_set: set
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            extra_deny: vec![],
            landlock_scoped: vec![],
            nofile: 1,
            nproc: 1,
            shm: false,
            shm_size: 64,
            tmp_size: 1024,
            rootfs: None,
            nameservers: None,
        }
    }

    const HOST: [(&str, &str); 14] = [
        ("PATH", "/home/u/.cargo/bin:/usr/local/bin:/usr/bin:/bin"),
        ("HOME", "/home/u"),
        ("TERM", "xterm-256color"),
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("AWS_SECRET_ACCESS_KEY", "hunter2"),
        ("GITHUB_TOKEN", "ghp_x"),
        ("SSH_AUTH_SOCK", "/run/user/1000/agent"),
        ("GOFLAGS", "-mod=mod"),
        ("RUSTFLAGS", "-Dwarnings"),
        ("API_KEY", "k"),
        ("LCX", "not-lc-prefix-with-underscore"),
        ("USER", "u"),
    ];

    fn visible(p: &Path) -> bool {
        p.starts_with("/usr") || p.starts_with("/bin")
    }

    #[test]
    fn host_secrets_not_in_pass_are_absent() {
        let e = scrub(&pol(&["GOFLAGS"], &[]), HOST, "alice", visible);
        for gone in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "SSH_AUTH_SOCK",
            "API_KEY",
            "RUSTFLAGS",
            "LCX",
        ] {
            assert!(!e.vars.contains_key(gone), "{gone} leaked");
        }
        assert_eq!(e.vars["GOFLAGS"], "-mod=mod");
    }

    #[test]
    fn only_documented_names_reach_the_child() {
        let e = scrub(&pol(&[], &[]), HOST, "alice", visible);
        let mut keys: Vec<&str> = e.vars.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "CARGO_HOME",
            "GOCACHE",
            "GOMODCACHE",
            "HOME",
            "LANG",
            "LC_ALL",
            "LOGNAME",
            "PATH",
            "PIP_CACHE_DIR",
            "TERM",
            "TZ",
            "USER",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "npm_config_cache",
        ];
        want.sort_unstable();
        assert_eq!(keys, want);
    }

    #[test]
    fn home_is_forced_and_caches_live_under_it() {
        let e = scrub(&pol(&[], &[]), HOST, "alice", visible);
        assert_eq!(e.vars["HOME"], SANDBOX_HOME);
        for (n, _) in CACHE_VARS {
            assert!(
                e.vars[n].starts_with(&format!("{SANDBOX_HOME}/")),
                "{n}={}",
                e.vars[n]
            );
        }
    }

    #[test]
    fn user_and_logname_are_computed_not_taken_from_the_host_or_policy() {
        // The host env says USER=u; the sandbox name is the argument.
        let e = scrub(&pol(&[], &[]), HOST, "alice", visible);
        assert_eq!(e.vars["USER"], "alice");
        assert_eq!(e.vars["LOGNAME"], "alice");
        // Neither env.pass nor env.set can override them (a 0.2.1 policy that
        // lists USER keeps loading; the computed value wins).
        let e = scrub(
            &pol(&["USER", "LOGNAME"], &[("LOGNAME", "root")]),
            HOST,
            "alice",
            visible,
        );
        assert_eq!(e.vars["USER"], "alice");
        assert_eq!(e.vars["LOGNAME"], "alice");
        // A scrubbed host environment (no USER at all) still yields both.
        let e = scrub(&pol(&[], &[]), [("PATH", "/usr/bin")], "alice", visible);
        assert_eq!(e.vars["USER"], "alice");
        assert_eq!(e.vars["LOGNAME"], "alice");
    }

    #[test]
    fn set_beats_pass_but_cannot_override_computed_vars() {
        let e = scrub(
            &pol(
                &["GOFLAGS"],
                &[("GOFLAGS", "-x"), ("CARGO_HOME", "/evil"), ("CI", "1")],
            ),
            HOST,
            "alice",
            visible,
        );
        assert_eq!(e.vars["GOFLAGS"], "-x");
        assert_eq!(e.vars["CI"], "1");
        assert_eq!(e.vars["CARGO_HOME"], format!("{SANDBOX_HOME}/.cargo"));
    }

    #[test]
    fn computed_names_are_exactly_home_user_logname_and_the_cache_vars() {
        assert!(is_computed("USER") && is_computed("LOGNAME"));
        assert!(!is_computed("user") && !is_computed("LOGIN"));
        assert!(
            is_computed("HOME") && is_computed("CARGO_HOME") && is_computed("npm_config_cache")
        );
        assert!(!is_computed("PATH") && !is_computed("GOFLAGS") && !is_computed("home"));
        for (n, _) in CACHE_VARS {
            assert!(is_computed(n), "{n}");
        }
    }

    #[test]
    fn pass_of_unset_name_is_noop() {
        let e = scrub(&pol(&["NOT_SET_ANYWHERE"], &[]), HOST, "alice", visible);
        assert!(!e.vars.contains_key("NOT_SET_ANYWHERE"));
    }

    #[test]
    fn secretish_passthrough_is_reported_not_blocked() {
        let e = scrub(
            &pol(&["GITHUB_TOKEN", "GOFLAGS", "UNSET_TOKEN"], &[]),
            HOST,
            "alice",
            visible,
        );
        assert_eq!(e.secretish_passed, vec!["GITHUB_TOKEN".to_owned()]);
        assert_eq!(e.vars["GITHUB_TOKEN"], "ghp_x");
        assert!(
            looks_secret("my_Password")
                && looks_secret("SSH_PRIVATE_KEY")
                && !looks_secret("GOFLAGS")
        );
    }

    #[test]
    fn path_is_filtered_to_visible_entries() {
        let e = scrub(&pol(&[], &[]), HOST, "alice", visible);
        assert_eq!(e.vars["PATH"], "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(
            filter_path(Some("/home/u/bin:relative:/nope"), visible),
            DEFAULT_PATH
        );
        assert_eq!(filter_path(None, visible), DEFAULT_PATH);
    }

    #[test]
    fn missing_host_vars_do_not_appear() {
        let e = scrub(&pol(&[], &[]), [("PATH", "/usr/bin")], "alice", visible);
        assert!(!e.vars.contains_key("TERM") && !e.vars.contains_key("LANG"));
        assert_eq!(e.vars["PATH"], "/usr/bin");
    }
}

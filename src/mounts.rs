//! Mount-plan derivation (DESIGN §4): a pure function of the resolved policy
//! and a snapshot of host facts. `rootfs` executes the plan; `hisn inspect`
//! output is compared against [`expected_targets`] (leak test L8).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::{Home, ResolvedPolicy};

/// Toolchain directories bound read-only when they exist on the host.
pub const TOOLCHAIN_DIRS: [&str; 7] = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/opt"];
/// `/nix` is handled alongside; kept separate so the list in the brief reads 1:1.
pub const NIX_DIR: &str = "/nix";
/// Sandbox home directory (DESIGN §4.4).
pub const SANDBOX_HOME: &str = "/run/hisn/home";
/// Device nodes bind-mounted into `/dev` (DESIGN §4.3).
pub const DEV_NODES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

pub const TMP_SIZE: u64 = 1 << 30;
pub const RUN_SIZE: u64 = 64 << 20;
pub const HOME_SIZE: u64 = 1 << 30;
pub const ETC_SIZE: u64 = 4 << 20;
pub const DEV_SIZE: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
    Symlink(String),
}

impl EntryKind {
    fn of(path: &Path) -> Option<Self> {
        let md = fs::symlink_metadata(path).ok()?;
        let ft = md.file_type();
        if ft.is_symlink() {
            let t = fs::read_link(path).ok()?;
            Some(Self::Symlink(t.to_string_lossy().into_owned()))
        } else if ft.is_dir() {
            Some(Self::Dir)
        } else {
            Some(Self::File)
        }
    }
}

/// Everything the planner needs to know about the host, snapshotted once.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// Existing toolchain top-level entries (`/usr`, `/bin`, …).
    pub toolchain: BTreeMap<PathBuf, EntryKind>,
    /// Top-level entries of the host `/etc` at session start.
    pub etc: BTreeMap<String, EntryKind>,
    /// Whether `/etc/ssl/private` exists (nested default mask).
    pub ssl_private: bool,
    /// Existing policy mask targets.
    pub masks: BTreeMap<PathBuf, EntryKind>,
    pub uid: u32,
    pub gid: u32,
    pub username: String,
    /// Host resolver config content, copied only for `network = "host"`.
    pub resolv_conf: Option<String>,
}

impl HostFacts {
    /// Snapshot the real host, or the rootfs if set. Impure; everything else
    /// in this module is pure. When `rootfs` is set, toolchain dirs and /etc
    /// entries are probed from `<rootfs>/usr`, `<rootfs>/etc`, etc.
    pub fn probe(policy: &ResolvedPolicy, uid: u32, gid: u32, username: &str) -> Self {
        let rootfs = policy.rootfs.as_deref();
        let mut toolchain = BTreeMap::new();
        for d in TOOLCHAIN_DIRS.iter().chain(std::iter::once(&NIX_DIR)) {
            let host_path = Path::new(d);
            let probe_path = match rootfs {
                Some(r) => {
                    let rel = d.strip_prefix('/').unwrap_or(d);
                    r.join(rel)
                }
                None => host_path.to_path_buf(),
            };
            if let Some(k) = EntryKind::of(&probe_path) {
                // For rootfs: store the source path (rootfs/<dir>) and the
                // sandbox target path (/usr). The bind op uses the source path.
                let source = if rootfs.is_some() {
                    probe_path
                } else {
                    host_path.to_path_buf()
                };
                toolchain.insert(PathBuf::from(d), k);
                // Stash the source path in the toolchain map value? No — the
                // toolchain map is keyed by the sandbox target path. The bind
                // op in plan() uses `bind(path, ...)` which uses `path` as
                // both source and target. For rootfs, we need a separate source.
                // We'll handle this in plan() by checking policy.rootfs.
                let _ = source; // used in plan()
            }
        }
        let mut etc = BTreeMap::new();
        let etc_path = match rootfs {
            Some(r) => r.join("etc"),
            None => PathBuf::from("/etc"),
        };
        if let Ok(rd) = fs::read_dir(&etc_path) {
            for e in rd.flatten() {
                if let (Some(name), Some(k)) = (
                    e.file_name().to_str().map(str::to_owned),
                    EntryKind::of(&e.path()),
                ) {
                    etc.insert(name, k);
                }
            }
        }
        let masks = policy
            .mask
            .iter()
            .filter_map(|m| EntryKind::of(m).map(|k| (m.clone(), k)))
            .collect();
        let resolv_conf = (policy.network == crate::policy::Network::Host)
            .then(|| {
                let rc_path = match rootfs {
                    Some(r) => r.join("etc").join("resolv.conf"),
                    None => PathBuf::from("/etc/resolv.conf"),
                };
                // With a rootfs, never follow a symlinked resolv.conf: the
                // host would resolve it outside the tree and copy host file
                // contents into the session.
                let is_symlink = rootfs.is_some()
                    && fs::symlink_metadata(&rc_path).is_ok_and(|m| m.file_type().is_symlink());
                if is_symlink {
                    None
                } else {
                    fs::read_to_string(&rc_path).ok()
                }
            })
            .flatten();
        Self {
            toolchain,
            etc,
            ssl_private: {
                let ssl_path = match rootfs {
                    Some(r) => r.join("etc").join("ssl").join("private"),
                    None => PathBuf::from("/etc/ssl/private"),
                };
                ssl_path.is_dir()
            },
            masks,
            uid,
            gid,
            username: username.to_owned(),
            resolv_conf,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountKind {
    /// Bind of `source` (same path as target unless stated), read-only.
    BindRo {
        recursive: bool,
    },
    BindRw {
        recursive: bool,
    },
    Tmpfs {
        size: u64,
        mode: u32,
        readonly: bool,
    },
    /// A symlink created inside a tmpfs (not a mount).
    Symlink {
        link_target: String,
    },
    /// File bound over with the sandbox's `/dev/null`.
    MaskFile,
    /// Directory covered by an empty read-only tmpfs.
    MaskDir,
    /// Regular file with generated content, written into the (later sealed)
    /// parent tmpfs. Not a mount.
    Generated {
        content: String,
    },
    /// Plain directory created in the root tmpfs; not a mount. Gives Landlock
    /// and the grant helper an existing path for grant targets and
    /// `grantable_rw` prefixes.
    EmptyDir,
    /// New procfs for the sandbox pid namespace.
    Proc,
    /// New devpts instance.
    Devpts,
    /// Bind of a host device node (source is the host `/dev/<name>`).
    BindDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountOp {
    pub target: PathBuf,
    pub source: Option<PathBuf>,
    pub kind: MountKind,
    /// 0.3.2: mount with MOUNT_ATTR_NODEV in addition to MOUNT_ATTR_NOSUID.
    /// Used for rootfs binds.
    pub nodev: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("{path}: would expose /etc outside the generated allowlist view (R3)")]
    EtcOverlap { path: PathBuf },
    #[error("{path}: lies inside the masked /etc entry {entry} (R3)")]
    MaskedEtcOverlap { path: PathBuf, entry: String },
    #[error("mask {path}: not inside any allowed tree")]
    MaskOutsideTree { path: PathBuf },
    #[error("{path}: lies below the symlink {link}; the executor never traverses symlinks")]
    UnderSymlink { path: PathBuf, link: PathBuf },
}

/// True if a top-level `/etc` entry name is masked by default (brief:
/// `/etc/ssh /etc/shadow /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/krb5*
/// /etc/*.key /etc/*.pem`, plus the `-` backup files of shadow/gshadow).
pub fn etc_masked(name: &str) -> bool {
    matches!(
        name,
        "ssh" | "shadow" | "shadow-" | "gshadow" | "gshadow-" | "sudoers" | "sudoers.d"
    ) || name.starts_with("krb5")
        || name.ends_with(".key")
        || name.ends_with(".pem")
}

/// Entries of `/etc` that are generated, never bound from the host.
/// (`resolv.conf` is generated only for `network = "host"`; otherwise absent.)
fn etc_generated(name: &str) -> bool {
    matches!(name, "passwd" | "group" | "resolv.conf")
}

fn depth(p: &Path) -> usize {
    p.components().count()
}

fn op(target: impl Into<PathBuf>, source: Option<PathBuf>, kind: MountKind) -> MountOp {
    MountOp {
        target: target.into(),
        source,
        kind,
        nodev: false,
    }
}

fn op_nodev(target: impl Into<PathBuf>, source: Option<PathBuf>, kind: MountKind) -> MountOp {
    MountOp {
        target: target.into(),
        source,
        kind,
        nodev: true,
    }
}

fn bind(p: &Path, kind_is_rw: bool, recursive: bool) -> MountOp {
    let kind = if kind_is_rw {
        MountKind::BindRw { recursive }
    } else {
        MountKind::BindRo { recursive }
    };
    op(p, Some(p.to_path_buf()), kind)
}

/// Bind `src` to `target` (ro, recursive) with nodev. Used for rootfs
/// toolchain binds where the source path differs from the sandbox target
/// path.
fn bind_src(src: &Path, target: &Path, kind_is_rw: bool, recursive: bool) -> MountOp {
    let kind = if kind_is_rw {
        MountKind::BindRw { recursive }
    } else {
        MountKind::BindRo { recursive }
    };
    op_nodev(target, Some(src.to_path_buf()), kind)
}

fn passwd_stub(f: &HostFacts, home: &str) -> String {
    format!(
        "{0}:x:{1}:{2}:{0}:{3}:/bin/sh\n",
        f.username, f.uid, f.gid, home
    )
}

fn group_stub(f: &HostFacts) -> String {
    format!("{0}:x:{1}:\n", f.username, f.gid)
}

/// Does `p` equal or lie inside `/etc` (lexically)?
fn under_etc(p: &Path) -> Option<&Path> {
    p.strip_prefix("/etc").ok()
}

/// Derive the ordered, de-duplicated list of mount operations.
///
/// Ordering: parents before children (by path depth, stable), later
/// declaration wins on an equal target. This keeps `/tmp` tmpfs before a cwd
/// below it, and masks after the trees they cover.
pub fn plan(
    policy: &ResolvedPolicy,
    facts: &HostFacts,
    grant_dirs: &[PathBuf],
) -> Result<Vec<MountOp>, PlanError> {
    let host_net = policy.network == crate::policy::Network::Host;
    let mut ops: Vec<MountOp> = Vec::new();

    // 0. Mountpoint directories for grants (declared first so any real mount
    //    on the same target wins in `order_and_dedupe`).
    for d in grant_dirs.iter().chain(&policy.grantable_rw) {
        ops.push(op(d, None, MountKind::EmptyDir));
    }

    // 1. Toolchain: ro, recursive; symlinked entries (e.g. /bin -> usr/bin)
    //    are recreated as symlinks, never followed. When a rootfs is set,
    //    the source is `<rootfs>/<dir>` and the target is `/<dir>`.
    let rootfs = policy.rootfs.as_deref();
    for (path, kind) in &facts.toolchain {
        let src = match rootfs {
            Some(r) => {
                let rel = path.strip_prefix("/").unwrap_or(path);
                r.join(rel)
            }
            None => path.clone(),
        };
        match kind {
            EntryKind::Symlink(t) => ops.push(op(
                path,
                None,
                MountKind::Symlink {
                    link_target: t.clone(),
                },
            )),
            _ => {
                if rootfs.is_some() {
                    ops.push(bind_src(&src, path, false, true));
                } else {
                    ops.push(bind(path, false, true));
                }
            }
        }
    }

    // 1b. /etc: tmpfs holding one entry per non-masked top-level host entry.
    ops.push(op(
        "/etc",
        None,
        MountKind::Tmpfs {
            size: ETC_SIZE,
            mode: 0o755,
            readonly: true,
        },
    ));
    for (name, kind) in &facts.etc {
        if etc_masked(name) || etc_generated(name) {
            continue;
        }
        let p = Path::new("/etc").join(name);
        let src = match rootfs {
            Some(r) => r.join("etc").join(name),
            None => p.clone(),
        };
        match kind {
            EntryKind::Symlink(t) => ops.push(op(
                p,
                None,
                MountKind::Symlink {
                    link_target: t.clone(),
                },
            )),
            _ => {
                if rootfs.is_some() {
                    ops.push(bind_src(&src, &p, false, true));
                } else {
                    ops.push(bind(&p, false, true));
                }
            }
        }
    }
    let home_str = match &policy.home {
        Home::Tmpfs | Home::Path(_) => SANDBOX_HOME,
    };
    ops.push(op(
        "/etc/passwd",
        None,
        MountKind::Generated {
            content: passwd_stub(facts, home_str),
        },
    ));
    ops.push(op(
        "/etc/group",
        None,
        MountKind::Generated {
            content: group_stub(facts),
        },
    ));
    if let (true, Some(c)) = (host_net, &facts.resolv_conf) {
        ops.push(op(
            "/etc/resolv.conf",
            None,
            MountKind::Generated { content: c.clone() },
        ));
    }
    if facts.ssl_private && matches!(facts.etc.get("ssl"), Some(EntryKind::Dir)) {
        ops.push(op("/etc/ssl/private", None, MountKind::MaskDir));
    }

    // 2. User binds. A bind may never re-expose /etc or a masked /etc entry.
    let user_paths = policy
        .ro
        .iter()
        .chain(&policy.rw)
        .chain(std::iter::once(&policy.cwd));
    for p in user_paths {
        if let Some(rest) = under_etc(p) {
            match rest.components().next() {
                None => return Err(PlanError::EtcOverlap { path: p.clone() }),
                Some(c) => {
                    let name = c.as_os_str().to_string_lossy().into_owned();
                    if etc_masked(&name) || etc_generated(&name) {
                        return Err(PlanError::MaskedEtcOverlap {
                            path: p.clone(),
                            entry: name,
                        });
                    }
                }
            }
        }
    }
    for p in &policy.ro {
        ops.push(bind(p, false, true));
    }

    // 3. Private tmpfs areas.
    ops.push(op(
        "/tmp",
        None,
        MountKind::Tmpfs {
            size: policy.tmp_size << 20,
            mode: 0o1777,
            readonly: false,
        },
    ));
    ops.push(op(
        "/run",
        None,
        MountKind::Tmpfs {
            size: RUN_SIZE,
            mode: 0o755,
            readonly: false,
        },
    ));
    match &policy.home {
        Home::Tmpfs => ops.push(op(
            SANDBOX_HOME,
            None,
            MountKind::Tmpfs {
                size: HOME_SIZE,
                mode: 0o700,
                readonly: false,
            },
        )),
        Home::Path(p) => ops.push(op(
            SANDBOX_HOME,
            Some(p.clone()),
            MountKind::BindRw { recursive: false },
        )),
    }

    // 3b. /dev/shm (optional, opt-in via session.shm).
    if policy.shm {
        ops.push(op(
            "/dev/shm",
            None,
            MountKind::Tmpfs {
                size: policy.shm_size << 20,
                mode: 0o1777,
                readonly: false,
            },
        ));
    }

    // 4. cwd (rw, recursive) and extra rw binds (non-recursive).
    ops.push(bind(&policy.cwd, true, true));
    for p in &policy.rw {
        ops.push(bind(p, true, false));
    }

    // 5. Policy masks, only where something exists to hide. Must lie inside a
    //    tree bound above (otherwise the path does not exist in the sandbox
    //    anyway, and a mask would just invent a mount point).
    let tree_roots: Vec<PathBuf> = ops
        .iter()
        .filter(|o| is_mount(&o.kind))
        .map(|o| o.target.clone())
        .collect();
    for m in &policy.mask {
        let Some(kind) = facts.masks.get(m) else {
            continue;
        };
        if !tree_roots.iter().any(|r| m != r && m.starts_with(r)) && !tree_roots.contains(m) {
            return Err(PlanError::MaskOutsideTree { path: m.clone() });
        }
        match kind {
            EntryKind::Dir => ops.push(op(m, None, MountKind::MaskDir)),
            EntryKind::File => ops.push(op(m, None, MountKind::MaskFile)),
            EntryKind::Symlink(_) => ops.push(op(m, None, MountKind::MaskFile)),
        }
    }

    // 6. /proc and /dev (the only mounts not under policy control).
    ops.push(op("/proc", None, MountKind::Proc));
    ops.push(op(
        "/dev",
        None,
        MountKind::Tmpfs {
            size: DEV_SIZE,
            mode: 0o755,
            readonly: true,
        },
    ));
    for n in DEV_NODES {
        let t = Path::new("/dev").join(n);
        ops.push(op(&t, Some(t.clone()), MountKind::BindDevice));
    }
    ops.push(op("/dev/pts", None, MountKind::Devpts));
    for (name, target) in [
        ("ptmx", "pts/ptmx"),
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        ops.push(op(
            Path::new("/dev").join(name),
            None,
            MountKind::Symlink {
                link_target: target.into(),
            },
        ));
    }

    let ops = order_and_dedupe(ops);
    // The executor builds paths lexically under the new root and must never
    // walk a symlink it created (an absolute link would resolve on the host).
    for o in &ops {
        for a in ancestors(&o.target) {
            if let Some(l) = ops
                .iter()
                .find(|x| x.target == a && matches!(x.kind, MountKind::Symlink { .. }))
            {
                return Err(PlanError::UnderSymlink {
                    path: o.target.clone(),
                    link: l.target.clone(),
                });
            }
        }
    }
    Ok(ops)
}

/// Stable sort by depth (parents first), then drop earlier ops whose target
/// is repeated by a later one (later declaration wins).
fn order_and_dedupe(ops: Vec<MountOp>) -> Vec<MountOp> {
    let mut indexed: Vec<(usize, MountOp)> = ops.into_iter().enumerate().collect();
    // Later declaration wins: keep only the last op per target.
    let mut last: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for (i, o) in &indexed {
        last.insert(o.target.clone(), *i);
    }
    indexed.retain(|(i, o)| last[&o.target] == *i);
    // Parents before children. Declaration order breaks ties, which also keeps
    // `/etc` (tmpfs) before `/etc/<entry>` since depth already orders them.
    indexed.sort_by_key(|(i, o)| (depth(&o.target), *i));
    indexed.into_iter().map(|(_, o)| o).collect()
}

/// Mount targets the sandbox must show in its mount table (symlinks, generated
/// files and plain directories excluded). Used by L8 / `hisn inspect`.
pub fn expected_targets(plan: &[MountOp]) -> BTreeSet<PathBuf> {
    plan.iter()
        .filter(|o| is_mount(&o.kind))
        .map(|o| o.target.clone())
        .collect()
}

/// `(recursive, read_only)` of a mount op, for the leak tests' typed comparison
/// (`hisn policy plan`). `read_only` is `None` when the mount has no fixed mode.
pub fn mount_traits(k: &MountKind) -> (bool, Option<bool>) {
    match k {
        MountKind::BindRo { recursive } => (*recursive, Some(true)),
        MountKind::BindRw { recursive } => (*recursive, Some(false)),
        MountKind::Tmpfs { readonly, .. } => (false, Some(*readonly)),
        MountKind::MaskFile | MountKind::MaskDir => (false, Some(true)),
        _ => (false, None),
    }
}

/// Does executing this op create a mount (as opposed to a symlink, a plain
/// file, or a directory)?
pub fn is_mount(k: &MountKind) -> bool {
    !matches!(
        k,
        MountKind::Symlink { .. } | MountKind::Generated { .. } | MountKind::EmptyDir
    )
}

/// Directories that must exist (as plain tmpfs directories) before `op` can be
/// mounted: every proper ancestor of its target.
pub fn ancestors(target: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = target
        .ancestors()
        .skip(1)
        .filter(|a| *a != Path::new("/") && !a.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect();
    v.reverse();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Network, ResolvedPolicy};

    fn pol(cwd: &str) -> ResolvedPolicy {
        ResolvedPolicy {
            version: "hisn-policy/v1".into(),
            cwd: cwd.into(),
            home: Home::Tmpfs,
            network: Network::None,
            hostname: "hisn".into(),
            ro: vec![],
            rw: vec![],
            mask: vec![],
            grantable_rw: vec![],
            env_pass: vec![],
            env_set: Default::default(),
            extra_deny: vec![],
            landlock_scoped: vec![],
            nofile: 1,
            nproc: 1,
            shm: false,
            shm_size: 64,
            tmp_size: 1024,
            rootfs: None,
        }
    }

    fn facts() -> HostFacts {
        let mut f = HostFacts {
            uid: 1000,
            gid: 1000,
            username: "u".into(),
            ..Default::default()
        };
        for d in ["/usr", "/lib64", "/opt"] {
            f.toolchain.insert(d.into(), EntryKind::Dir);
        }
        f.toolchain
            .insert("/bin".into(), EntryKind::Symlink("usr/bin".into()));
        for (n, k) in [
            ("passwd", EntryKind::File),
            ("group", EntryKind::File),
            ("shadow", EntryKind::File),
            ("ssh", EntryKind::Dir),
            ("a.key", EntryKind::File),
            ("b.pem", EntryKind::File),
            ("krb5.conf", EntryKind::File),
            ("sudoers.d", EntryKind::Dir),
            ("ssl", EntryKind::Dir),
            ("hosts", EntryKind::File),
            (
                "os-release",
                EntryKind::Symlink("../usr/lib/os-release".into()),
            ),
            ("resolv.conf", EntryKind::File),
        ] {
            f.etc.insert(n.into(), k);
        }
        f.ssl_private = true;
        f
    }

    fn targets(ops: &[MountOp]) -> Vec<String> {
        ops.iter().map(|o| o.target.display().to_string()).collect()
    }

    fn find<'a>(ops: &'a [MountOp], t: &str) -> Option<&'a MountOp> {
        ops.iter().find(|o| o.target == Path::new(t))
    }

    #[test]
    fn stubs_use_the_host_username_not_a_constant() {
        let mut f = facts();
        f.username = "alice".into();
        f.uid = 1234;
        f.gid = 5678;
        assert_eq!(
            passwd_stub(&f, SANDBOX_HOME),
            "alice:x:1234:5678:alice:/run/hisn/home:/bin/sh\n"
        );
        assert_eq!(group_stub(&f), "alice:x:5678:\n");
        let ops = plan(&pol("/w"), &f, &[]).unwrap();
        for (t, want) in [
            (
                "/etc/passwd",
                "alice:x:1234:5678:alice:/run/hisn/home:/bin/sh\n",
            ),
            ("/etc/group", "alice:x:5678:\n"),
        ] {
            let o = ops.iter().find(|o| o.target == Path::new(t)).unwrap();
            assert_eq!(
                o.kind,
                MountKind::Generated {
                    content: want.into()
                }
            );
        }
    }

    #[test]
    fn default_masks_match_the_brief() {
        for n in [
            "ssh",
            "shadow",
            "gshadow",
            "sudoers",
            "sudoers.d",
            "krb5.conf",
            "krb5.keytab",
            "x.key",
            "x.pem",
        ] {
            assert!(etc_masked(n), "{n}");
        }
        for n in [
            "ssl",
            "hosts",
            "passwd",
            "ld.so.cache",
            "keyboard",
            "pemfile",
        ] {
            assert!(!etc_masked(n), "{n}");
        }
    }

    #[test]
    fn etc_is_an_allowlist_without_secrets() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        let t = targets(&ops);
        for secret in [
            "/etc/shadow",
            "/etc/ssh",
            "/etc/a.key",
            "/etc/b.pem",
            "/etc/krb5.conf",
            "/etc/sudoers.d",
        ] {
            assert!(
                !t.contains(&secret.to_string()),
                "{secret} must not be mounted"
            );
        }
        assert!(find(&ops, "/etc").is_some_and(|o| matches!(o.kind, MountKind::Tmpfs { .. })));
        assert!(
            find(&ops, "/etc/hosts")
                .is_some_and(|o| o.kind == MountKind::BindRo { recursive: true })
        );
        assert!(
            find(&ops, "/etc/os-release")
                .is_some_and(|o| matches!(o.kind, MountKind::Symlink { .. }))
        );
        assert!(find(&ops, "/etc/ssl/private").is_some_and(|o| o.kind == MountKind::MaskDir));
        // generated stubs, not host files
        let passwd = find(&ops, "/etc/passwd").unwrap();
        assert_eq!(
            passwd.kind,
            MountKind::Generated {
                content: "u:x:1000:1000:u:/run/hisn/home:/bin/sh\n".into()
            }
        );
        assert!(passwd.source.is_none());
        assert_eq!(
            find(&ops, "/etc/group").unwrap().kind,
            MountKind::Generated {
                content: "u:x:1000:\n".into()
            }
        );
        // network none: no resolv.conf at all
        assert!(find(&ops, "/etc/resolv.conf").is_none());
    }

    #[test]
    fn shm_mount_present_when_enabled() {
        let mut p = pol("/work/p");
        p.shm = true;
        p.shm_size = 32;
        let ops = plan(&p, &facts(), &[]).unwrap();
        let shm = find(&ops, "/dev/shm").expect("/dev/shm must be in plan");
        let expected = 32u64 << 20;
        assert!(matches!(
            shm.kind,
            MountKind::Tmpfs {
                size,
                mode: 0o1777,
                ..
            } if size == expected
        ));
    }

    #[test]
    fn shm_absent_by_default() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        assert!(
            find(&ops, "/dev/shm").is_none(),
            "/dev/shm must not be in plan by default"
        );
    }

    #[test]
    fn tmp_size_controls_tmpfs() {
        let mut p = pol("/work/p");
        p.tmp_size = 512;
        let ops = plan(&p, &facts(), &[]).unwrap();
        let tmp = find(&ops, "/tmp").unwrap();
        let expected = 512u64 << 20;
        assert!(matches!(tmp.kind, MountKind::Tmpfs { size, .. } if size == expected));
    }

    #[test]
    fn resolv_conf_only_for_host_network() {
        let mut p = pol("/work/p");
        p.network = Network::Host;
        let mut f = facts();
        f.resolv_conf = Some("nameserver 1.1.1.1\n".into());
        let ops = plan(&p, &f, &[]).unwrap();
        assert_eq!(
            find(&ops, "/etc/resolv.conf").unwrap().kind,
            MountKind::Generated {
                content: "nameserver 1.1.1.1\n".into()
            }
        );
    }

    #[test]
    fn toolchain_is_ro_and_symlinks_are_recreated() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        assert_eq!(
            find(&ops, "/usr").unwrap().kind,
            MountKind::BindRo { recursive: true }
        );
        assert_eq!(
            find(&ops, "/usr").unwrap().source.as_deref(),
            Some(Path::new("/usr"))
        );
        assert_eq!(
            find(&ops, "/bin").unwrap().kind,
            MountKind::Symlink {
                link_target: "usr/bin".into()
            }
        );
        // absent toolchain dirs produce nothing
        assert!(find(&ops, "/nix").is_none());
        assert!(find(&ops, "/lib32").is_none());
        // never mounted: /var /sys /home /root
        for n in ["/var", "/sys", "/home", "/root"] {
            assert!(find(&ops, n).is_none(), "{n}");
        }
    }

    #[test]
    fn cwd_is_rw_recursive_at_identical_path_and_parents_come_first() {
        let ops = plan(&pol("/tmp/proj"), &facts(), &[]).unwrap();
        let cwd = find(&ops, "/tmp/proj").unwrap();
        assert_eq!(cwd.kind, MountKind::BindRw { recursive: true });
        assert_eq!(cwd.source.as_deref(), Some(Path::new("/tmp/proj")));
        let pos = |t: &str| ops.iter().position(|o| o.target == Path::new(t)).unwrap();
        assert!(
            pos("/tmp") < pos("/tmp/proj"),
            "tmpfs /tmp must precede cwd below it"
        );
        assert!(pos("/run") < pos(SANDBOX_HOME));
        assert!(pos("/etc") < pos("/etc/hosts"));
        assert!(pos("/dev") < pos("/dev/null") && pos("/dev") < pos("/dev/pts"));
    }

    #[test]
    fn cwd_equal_to_tmp_replaces_the_private_tmp() {
        let ops = plan(&pol("/tmp"), &facts(), &[]).unwrap();
        let tmp: Vec<_> = ops
            .iter()
            .filter(|o| o.target == Path::new("/tmp"))
            .collect();
        assert_eq!(tmp.len(), 1);
        assert_eq!(tmp[0].kind, MountKind::BindRw { recursive: true });
    }

    #[test]
    fn home_modes() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        assert!(matches!(
            find(&ops, SANDBOX_HOME).unwrap().kind,
            MountKind::Tmpfs { mode: 0o700, .. }
        ));
        let mut p = pol("/work/p");
        p.home = Home::Path("/cache/home".into());
        let ops = plan(&p, &facts(), &[]).unwrap();
        let h = find(&ops, SANDBOX_HOME).unwrap();
        assert_eq!(h.kind, MountKind::BindRw { recursive: false });
        assert_eq!(h.source.as_deref(), Some(Path::new("/cache/home")));
    }

    #[test]
    fn extra_ro_rw_binds() {
        let mut p = pol("/work/p");
        p.ro = vec!["/opt/toolchains".into()];
        p.rw = vec!["/data/out".into()];
        let ops = plan(&p, &facts(), &[]).unwrap();
        assert_eq!(
            find(&ops, "/opt/toolchains").unwrap().kind,
            MountKind::BindRo { recursive: true }
        );
        assert_eq!(
            find(&ops, "/data/out").unwrap().kind,
            MountKind::BindRw { recursive: false }
        );
    }

    #[test]
    fn masks_apply_after_their_tree_and_by_kind() {
        let mut p = pol("/work/p");
        p.mask = vec![
            "/work/p/.secrets".into(),
            "/work/p/.env".into(),
            "/work/p/absent".into(),
        ];
        let mut f = facts();
        f.masks.insert("/work/p/.secrets".into(), EntryKind::Dir);
        f.masks.insert("/work/p/.env".into(), EntryKind::File);
        let ops = plan(&p, &f, &[]).unwrap();
        assert_eq!(
            find(&ops, "/work/p/.secrets").unwrap().kind,
            MountKind::MaskDir
        );
        assert_eq!(
            find(&ops, "/work/p/.env").unwrap().kind,
            MountKind::MaskFile
        );
        assert!(
            find(&ops, "/work/p/absent").is_none(),
            "absent paths are skipped"
        );
        let pos = |t: &str| ops.iter().position(|o| o.target == Path::new(t)).unwrap();
        assert!(pos("/work/p") < pos("/work/p/.secrets"));
    }

    #[test]
    fn mask_outside_any_tree_is_an_error() {
        let mut p = pol("/work/p");
        p.mask = vec!["/srv/thing".into()];
        let mut f = facts();
        f.masks.insert("/srv/thing".into(), EntryKind::File);
        assert_eq!(
            plan(&p, &f, &[]).unwrap_err(),
            PlanError::MaskOutsideTree {
                path: "/srv/thing".into()
            }
        );
    }

    #[test]
    fn user_binds_cannot_reexpose_etc_or_masked_entries() {
        for (path, is_masked) in [
            ("/etc", false),
            ("/etc/ssh", true),
            ("/etc/ssh/keys", true),
            ("/etc/a.key", true),
            ("/etc/passwd", true),
        ] {
            let mut p = pol("/work/p");
            p.ro = vec![path.into()];
            let e = plan(&p, &facts(), &[]).unwrap_err();
            if is_masked {
                assert!(
                    matches!(e, PlanError::MaskedEtcOverlap { .. }),
                    "{path}: {e}"
                );
            } else {
                assert!(matches!(e, PlanError::EtcOverlap { .. }), "{path}: {e}");
            }
        }
        // cwd and rw too
        let p = pol("/etc/ssh");
        assert!(plan(&p, &facts(), &[]).is_err());
        let mut p = pol("/work/p");
        p.rw = vec!["/etc".into()];
        assert!(plan(&p, &facts(), &[]).is_err());
        // an unmasked etc subpath is fine
        let mut p = pol("/work/p");
        p.ro = vec!["/etc/ssl/certs".into()];
        assert!(plan(&p, &facts(), &[]).is_ok());
    }

    #[test]
    fn proc_dev_are_fixed_and_complete() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        assert_eq!(find(&ops, "/proc").unwrap().kind, MountKind::Proc);
        let dev: Vec<_> = ops
            .iter()
            .filter(|o| o.target.starts_with("/dev") && o.target != Path::new("/dev"))
            .map(|o| o.target.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        let mut got = dev.clone();
        got.sort();
        let mut want: Vec<String> = [
            "null", "zero", "full", "random", "urandom", "tty", "pts", "ptmx", "fd", "stdin",
            "stdout", "stderr",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        want.sort();
        assert_eq!(got, want);
        assert!(find(&ops, "/sys").is_none());
    }

    #[test]
    fn expected_targets_excludes_symlinks_and_is_exact() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        let exp = expected_targets(&ops);
        assert!(exp.contains(Path::new("/usr")));
        assert!(exp.contains(Path::new("/etc/hosts")));
        assert!(exp.contains(Path::new("/work/p")));
        assert!(!exp.contains(Path::new("/bin")), "symlink");
        assert!(!exp.contains(Path::new("/etc/os-release")), "symlink");
        assert!(!exp.contains(Path::new("/dev/stdin")), "symlink");
        assert!(!exp.contains(Path::new("/etc/passwd")), "generated file");
        assert_eq!(exp.len(), ops.iter().filter(|o| is_mount(&o.kind)).count());
    }

    #[test]
    fn grant_dirs_are_plain_directories_and_lose_to_real_mounts() {
        let mut p = pol("/work/p");
        p.grantable_rw = vec!["/data/shared".into(), "/work/p".into()];
        let ops = plan(&p, &facts(), &["/g/in".into()]).unwrap();
        for d in ["/data/shared", "/g/in"] {
            assert_eq!(find(&ops, d).unwrap().kind, MountKind::EmptyDir, "{d}");
            assert!(!expected_targets(&ops).contains(Path::new(d)));
        }
        // a prefix equal to the cwd stays the real bind
        assert_eq!(
            find(&ops, "/work/p").unwrap().kind,
            MountKind::BindRw { recursive: true }
        );
    }

    #[test]
    fn etc_and_dev_tmpfs_are_sealed_read_only() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        for t in ["/etc", "/dev"] {
            assert!(
                matches!(
                    find(&ops, t).unwrap().kind,
                    MountKind::Tmpfs { readonly: true, .. }
                ),
                "{t}"
            );
        }
        assert!(matches!(
            find(&ops, "/tmp").unwrap().kind,
            MountKind::Tmpfs {
                readonly: false,
                ..
            }
        ));
    }

    #[test]
    fn targets_below_a_symlink_are_rejected() {
        // /bin is a symlink in the test facts; a cwd below it must not plan.
        let e = plan(&pol("/bin/proj"), &facts(), &[]).unwrap_err();
        assert!(matches!(e, PlanError::UnderSymlink { .. }), "{e}");
        assert!(plan(&pol("/work/p"), &facts(), &[]).is_ok());
    }

    #[test]
    fn mount_traits_describe_recursion_and_mode() {
        let ops = plan(&pol("/work/p"), &facts(), &[]).unwrap();
        let t = |p: &str| mount_traits(&find(&ops, p).unwrap().kind);
        assert_eq!(t("/usr"), (true, Some(true)));
        assert_eq!(t("/work/p"), (true, Some(false)));
        assert_eq!(t("/tmp"), (false, Some(false)));
        assert_eq!(t("/etc"), (false, Some(true)));
        assert_eq!(t("/proc"), (false, None));
    }

    #[test]
    fn plan_is_deterministic() {
        assert_eq!(
            plan(&pol("/work/p"), &facts(), &[]),
            plan(&pol("/work/p"), &facts(), &[])
        );
    }

    #[test]
    fn ancestors_exclude_root_and_self() {
        assert_eq!(
            ancestors(Path::new("/a/b/c")),
            vec![PathBuf::from("/a"), PathBuf::from("/a/b")]
        );
        assert!(ancestors(Path::new("/a")).is_empty());
    }
}

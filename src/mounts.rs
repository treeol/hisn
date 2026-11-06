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
    /// Session resolver config, built only for `network = "host"`. `Err` when
    /// no usable resolver exists (the launch fails; see `build_resolv_conf`).
    pub resolv_conf: Option<Result<String, String>>,
}

/// Systemd-resolved's real upstream list (the host `/etc/resolv.conf` is only a
/// loopback stub on such hosts).
pub const RESOLVED_UPSTREAM_FILE: &str = "/run/systemd/resolve/resolv.conf";

/// Is this nameserver address a loopback address (127.0.0.0/8 or ::1)? A
/// loopback resolver is unreachable from the session's network namespace, so it
/// is never passed into the session.
pub fn is_loopback_ns(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        // Unparsable: keep out of the session (never pass what we cannot vouch for).
        Err(_) => true,
    }
}

/// Non-loopback `nameserver` addresses, in file order.
fn usable_nameservers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        if it.next() != Some("nameserver") {
            continue;
        }
        if let Some(a) = it.next()
            && !is_loopback_ns(a)
        {
            out.push(a.to_owned());
        }
    }
    out
}

/// Lines that carry search/domain/options (kept from the host file).
fn search_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| {
            matches!(
                l.split_whitespace().next(),
                Some("search" | "domain" | "options")
            )
        })
        .map(str::to_owned)
        .collect()
}

/// Build the session's `/etc/resolv.conf` (pure; see `docs/configuration.md`
/// `[net]`). `override_ns` (from the profile) replaces everything. Otherwise:
/// the host file's non-loopback nameservers, else the systemd-resolved upstream
/// file's. Returns `Err` when no usable resolver exists: an empty resolv.conf is
/// never written.
pub fn build_resolv_conf(
    host: Option<&str>,
    upstream: Option<&str>,
    override_ns: Option<&[String]>,
) -> Result<String, String> {
    build_resolv_conf_ordered(None, host, upstream, override_ns)
}

/// Build the session's resolv.conf (0.3.3). Candidates, in order:
/// `image` (a rootfs's own resolv.conf, rootfs sessions only), `host`, and
/// `upstream` (systemd-resolved's real list).
///
/// The profile override wins over everything. Otherwise the image file is used
/// only if it has a usable (non-loopback) nameserver, since on `network = "host"`
/// the host's resolvers are authoritative and an image's placeholder must not
/// shadow a working host resolver. The host file then supplies both its
/// nameservers and its search/options lines, falling back to the upstream file
/// for nameservers (and for search/options when the host had none), exactly as
/// before 0.3.3 for a host session. Loopback is never passed in, and when
/// nothing usable remains the result is `Err`, never an empty file.
pub fn build_resolv_conf_ordered(
    image: Option<&str>,
    host: Option<&str>,
    upstream: Option<&str>,
    override_ns: Option<&[String]>,
) -> Result<String, String> {
    if let Some(ns) = override_ns {
        let mut out = String::new();
        for a in ns {
            out.push_str(&format!("nameserver {a}\n"));
        }
        return Ok(out);
    }
    if let Some(img) = image {
        let servers = usable_nameservers(img);
        if !servers.is_empty() {
            let mut out = String::new();
            for l in search_lines(img) {
                out.push_str(&l);
                out.push('\n');
            }
            for a in &servers {
                out.push_str(&format!("nameserver {a}\n"));
            }
            return Ok(out);
        }
    }
    let host = host.unwrap_or("");
    let mut servers = usable_nameservers(host);
    let mut extra = search_lines(host);
    if servers.is_empty() {
        let up = upstream.unwrap_or("");
        servers = usable_nameservers(up);
        if extra.is_empty() {
            extra = search_lines(up);
        }
    }
    if servers.is_empty() {
        return Err(
            "no usable DNS resolver: host resolv.conf lists only loopback stubs and \
             /run/systemd/resolve/resolv.conf has none; set [net] nameservers in the profile"
                .to_owned(),
        );
    }
    let mut out = String::new();
    for l in &extra {
        out.push_str(l);
        out.push('\n');
    }
    for a in &servers {
        out.push_str(&format!("nameserver {a}\n"));
    }
    Ok(out)
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
        // Host networking: the session's resolver is built from the host file,
        // then systemd-resolved's upstream list, then the profile override
        // (`build_resolv_conf`). A failure is kept and reported at launch; it
        // never yields an empty file.
        //
        // With a rootfs, the resolver is still the rootfs's own
        // `etc/resolv.conf` (copied verbatim, never through a symlink), as
        // before 0.3.3.
        let resolv_conf: Option<Result<String, String>> =
            if policy.network != crate::policy::Network::Host {
                None
            } else if let Some(r) = rootfs {
                // A rootfs session on network = "host" shares the host netns, so
                // the host's resolvers are the authoritative ones. The image's
                // own resolv.conf is tried first only when it has a usable
                // nameserver; otherwise the host file, then the host's
                // systemd-resolved upstream file (read from the real host, never
                // from inside the image). A symlinked image file is never followed.
                let rc_path = r.join("etc").join("resolv.conf");
                let is_symlink =
                    fs::symlink_metadata(&rc_path).is_ok_and(|m| m.file_type().is_symlink());
                let image = if is_symlink {
                    None
                } else {
                    fs::read_to_string(&rc_path).ok()
                };
                let host = fs::read_to_string("/etc/resolv.conf").ok();
                let up = fs::read_to_string(RESOLVED_UPSTREAM_FILE).ok();
                Some(build_resolv_conf_ordered(
                    image.as_deref(),
                    host.as_deref(),
                    up.as_deref(),
                    policy.nameservers.as_deref(),
                ))
            } else {
                let host = fs::read_to_string("/etc/resolv.conf").ok();
                let up = fs::read_to_string(RESOLVED_UPSTREAM_FILE).ok();
                Some(build_resolv_conf(
                    host.as_deref(),
                    up.as_deref(),
                    policy.nameservers.as_deref(),
                ))
            };
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
    /// No usable DNS resolver for `network = "host"` (C1). Never an empty file.
    #[error("{0}")]
    NoResolver(String),
    /// A `mounts.ro` `src:dst` (or same-path) entry conflicts with an owned or
    /// existing session path (C3).
    #[error("mounts.ro {src}:{dst}: {reason}")]
    RoConflict {
        src: PathBuf,
        dst: PathBuf,
        reason: String,
    },
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
        let content = c.clone().map_err(PlanError::NoResolver)?;
        ops.push(op(
            "/etc/resolv.conf",
            None,
            MountKind::Generated { content },
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
    // Same-path entries: unchanged (`bind`, recursive ro). `src:dst` entries
    // (0.3.3) bind `src` at `dst` with ro,nosuid,nodev; their collisions are
    // checked once the whole plan exists (see `check_ro_dst` below).
    // A policy built with only `ro` (no `ro_binds`) is all same-path entries.
    let ro_binds: Vec<crate::policy::RoBind> = if policy.ro_binds.is_empty() {
        policy
            .ro
            .iter()
            .map(|p| crate::policy::RoBind {
                src: p.clone(),
                dst: p.clone(),
            })
            .collect()
    } else {
        policy.ro_binds.clone()
    };
    for b in &ro_binds {
        if b.src == b.dst {
            ops.push(bind(&b.dst, false, true));
        } else {
            ops.push(op_nodev(
                &b.dst,
                Some(b.src.clone()),
                MountKind::BindRo { recursive: true },
            ));
        }
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

    // 0.3.3: a `src:dst` dst must not shadow or sit inside another session
    // mount (owned by the profile or the toolchain), nor equal another entry.
    // Checked before dedupe, which would otherwise hide the collision.
    //
    // "Another mount" means any real mount op (bind, tmpfs, mask, proc, dev)
    // whose target is the dst, sits above it, or sits below it. The dst's own
    // src:dst op is excluded by identity (same dst AND same src).
    for b in policy.ro_binds.iter().filter(|b| b.src != b.dst) {
        for o in &ops {
            // Symlinks count too: a dst at an owned symlink (e.g. merged-usr
            // /bin -> usr/bin) would otherwise replace it by later-wins dedupe.
            if !(is_mount(&o.kind) || matches!(o.kind, MountKind::Symlink { .. })) {
                continue;
            }
            if o.target == b.dst && o.source.as_deref() == Some(b.src.as_path()) {
                continue; // this bind itself
            }
            let covers = o.target.starts_with(&b.dst) || b.dst.starts_with(&o.target);
            if covers {
                return Err(PlanError::RoConflict {
                    src: b.src.clone(),
                    dst: b.dst.clone(),
                    reason: format!("collides with the session mount at {}", o.target.display()),
                });
            }
        }
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
            ro_binds: vec![],
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
            nameservers: None,
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
        f.resolv_conf = Some(Ok("nameserver 1.1.1.1\n".into()));
        let ops = plan(&p, &f, &[]).unwrap();
        assert_eq!(
            find(&ops, "/etc/resolv.conf").unwrap().kind,
            MountKind::Generated {
                content: "nameserver 1.1.1.1\n".into()
            }
        );
    }

    const STUB_HOST: &str = "# systemd stub\nnameserver 127.0.0.53\nsearch home\n";
    const UPSTREAMS: &str = "# real\nnameserver 192.168.1.111\nnameserver 2001:db8::1\nsearch corp.example\noptions edns0\n";

    #[test]
    fn stub_only_host_uses_the_resolver_file_upstreams() {
        let out = build_resolv_conf(Some(STUB_HOST), Some(UPSTREAMS), None).unwrap();
        assert!(out.contains("nameserver 192.168.1.111\n"), "{out}");
        assert!(out.contains("nameserver 2001:db8::1\n"), "{out}");
        assert!(!out.contains("127.0.0.53"), "loopback passed: {out}");
        // the host had a search line, so it wins over the upstream file's
        assert!(
            out.contains("search home\n") && !out.contains("corp.example"),
            "{out}"
        );
    }

    #[test]
    fn stub_only_host_without_resolver_file_fails() {
        let e = build_resolv_conf(Some(STUB_HOST), None, None).unwrap_err();
        assert!(e.starts_with("no usable DNS resolver"), "{e}");
        assert!(e.contains("[net] nameservers"), "{e}");
        // an upstream file with only loopback stubs is the same failure
        assert!(build_resolv_conf(Some(STUB_HOST), Some("nameserver ::1\n"), None).is_err());
    }

    #[test]
    fn host_with_real_nameservers_is_copied_minus_loopback() {
        let host = "nameserver 127.0.0.1\nnameserver 10.0.0.2\nsearch lan\noptions ndots:2\n";
        let out = build_resolv_conf(Some(host), Some(UPSTREAMS), None).unwrap();
        assert_eq!(out, "search lan\noptions ndots:2\nnameserver 10.0.0.2\n");
    }

    #[test]
    fn profile_override_is_used_verbatim() {
        let ns = vec!["1.1.1.1".to_owned(), "9.9.9.9".to_owned()];
        let out = build_resolv_conf(Some(STUB_HOST), Some(UPSTREAMS), Some(&ns)).unwrap();
        assert_eq!(out, "nameserver 1.1.1.1\nnameserver 9.9.9.9\n");
    }

    const IMAGE_EMPTY: &str = "";
    const IMAGE_REAL: &str = "nameserver 9.9.9.9\nsearch img.example\n";

    #[test]
    fn rootfs_empty_resolver_uses_the_host_upstream() {
        // The wakil-dev case: the image's resolv.conf is empty, the host file is
        // a stub, and the systemd upstream file has real servers.
        let out =
            build_resolv_conf_ordered(Some(IMAGE_EMPTY), Some(STUB_HOST), Some(UPSTREAMS), None)
                .unwrap();
        assert!(out.contains("nameserver 192.168.1.111\n"), "{out}");
        assert!(
            !out.contains("9.9.9.9") && !out.contains("127.0.0.53"),
            "{out}"
        );
    }

    #[test]
    fn rootfs_real_resolver_wins_over_the_host() {
        let out = build_resolv_conf_ordered(
            Some(IMAGE_REAL),
            Some("nameserver 10.0.0.2\n"),
            Some(UPSTREAMS),
            None,
        )
        .unwrap();
        assert_eq!(out, "search img.example\nnameserver 9.9.9.9\n");
    }

    #[test]
    fn rootfs_empty_image_uses_the_host_file_when_it_has_servers() {
        let out = build_resolv_conf_ordered(
            Some(IMAGE_EMPTY),
            Some("search lan\nnameserver 10.0.0.2\n"),
            Some(UPSTREAMS),
            None,
        )
        .unwrap();
        assert_eq!(out, "search lan\nnameserver 10.0.0.2\n");
    }

    #[test]
    fn rootfs_loopback_only_everywhere_fails_closed() {
        let r = build_resolv_conf_ordered(
            Some("nameserver 127.0.0.11\n"),
            Some(STUB_HOST),
            Some("nameserver ::1\n"),
            None,
        );
        assert!(r.is_err(), "{r:?}");
        assert!(build_resolv_conf_ordered(Some(IMAGE_EMPTY), None, None, None).is_err());
    }

    #[test]
    fn profile_override_wins_over_every_rootfs_candidate() {
        let ns = vec!["1.1.1.1".to_owned()];
        let out = build_resolv_conf_ordered(
            Some(IMAGE_REAL),
            Some("nameserver 10.0.0.2\n"),
            Some(UPSTREAMS),
            Some(&ns),
        )
        .unwrap();
        assert_eq!(out, "nameserver 1.1.1.1\n");
    }

    #[test]
    fn rootfs_style_empty_or_stub_resolver_fails_closed() {
        // A rootfs's resolv.conf goes through the same builder (B3): an empty
        // file or a loopback-only stub is a launch failure, never an empty
        // resolv.conf or a stub passed into the session.
        assert!(build_resolv_conf(Some(""), None, None).is_err());
        assert!(build_resolv_conf(Some("nameserver 127.0.0.11\n"), None, None).is_err());
        assert!(build_resolv_conf(None, None, None).is_err());
        let ns = vec!["1.1.1.1".to_owned()];
        assert_eq!(
            build_resolv_conf(Some(""), None, Some(&ns)).unwrap(),
            "nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn loopback_addresses_are_recognised() {
        for a in ["127.0.0.1", "127.8.9.10", "::1"] {
            assert!(is_loopback_ns(a), "{a}");
        }
        for a in ["10.0.0.1", "2001:db8::1", "1.1.1.1"] {
            assert!(!is_loopback_ns(a), "{a}");
        }
        assert!(is_loopback_ns("not-an-ip"), "unparsable is kept out");
    }

    fn bind_pol(ro: Vec<crate::policy::RoBind>) -> ResolvedPolicy {
        let mut p = pol("/work/p");
        p.ro = ro.iter().map(|b| b.dst.clone()).collect();
        p.ro_binds = ro;
        p
    }

    #[test]
    fn src_dst_mounts_the_source_at_dst_only() {
        let p = bind_pol(vec![crate::policy::RoBind {
            src: PathBuf::from("/host/secret-ish/app.conf"),
            dst: PathBuf::from("/etc-app/app.conf"),
        }]);
        let ops = plan(&p, &facts(), &[]).unwrap();
        let o = find(&ops, "/etc-app/app.conf").expect("mounted at dst");
        assert_eq!(
            o.source.as_deref(),
            Some(Path::new("/host/secret-ish/app.conf"))
        );
        assert_eq!(o.kind, MountKind::BindRo { recursive: true });
        assert!(o.nodev, "src:dst keeps nodev as well as nosuid and ro");
        // nothing is mounted at the host source path itself
        assert!(
            ops.iter()
                .all(|x| x.target != Path::new("/host/secret-ish/app.conf"))
        );
    }

    #[test]
    fn same_path_ro_is_unchanged() {
        let p = bind_pol(vec![crate::policy::RoBind {
            src: PathBuf::from("/opt/tc"),
            dst: PathBuf::from("/opt/tc"),
        }]);
        let ops = plan(&p, &facts(), &[]).unwrap();
        let o = find(&ops, "/opt/tc").unwrap();
        assert_eq!(o.kind, MountKind::BindRo { recursive: true });
        assert_eq!(o.source.as_deref(), Some(Path::new("/opt/tc")));
        assert!(!o.nodev, "same-path entries keep their 0.2 flags");
    }

    #[test]
    fn src_dst_colliding_with_a_session_mount_is_rejected_and_named() {
        // /tmp is a private tmpfs mount: a dst inside it must be refused.
        let p = bind_pol(vec![crate::policy::RoBind {
            src: PathBuf::from("/host/x"),
            dst: PathBuf::from("/tmp/x"),
        }]);
        match plan(&p, &facts(), &[]) {
            Err(PlanError::RoConflict { dst, reason, .. }) => {
                assert_eq!(dst, PathBuf::from("/tmp/x"));
                assert!(reason.contains("/tmp"), "{reason}");
            }
            other => panic!("expected RoConflict, got {other:?}"),
        }
    }

    #[test]
    fn src_dst_onto_an_owned_toolchain_symlink_is_rejected() {
        // /bin is a symlink (usr/bin) in the test facts: a dst equal to it
        // must be refused, not allowed to replace it.
        let p = bind_pol(vec![crate::policy::RoBind {
            src: PathBuf::from("/host/x"),
            dst: PathBuf::from("/bin"),
        }]);
        match plan(&p, &facts(), &[]) {
            Err(PlanError::RoConflict { reason, .. }) => {
                assert!(reason.contains("/bin"), "{reason}");
            }
            other => panic!("expected RoConflict on the /bin symlink, got {other:?}"),
        }
    }

    #[test]
    fn src_dst_shadowing_the_toolchain_is_rejected() {
        // /usr is a toolchain bind (in facts): dst beneath it is refused.
        let p = bind_pol(vec![crate::policy::RoBind {
            src: PathBuf::from("/host/x"),
            dst: PathBuf::from("/usr/lib/x"),
        }]);
        assert!(matches!(
            plan(&p, &facts(), &[]),
            Err(PlanError::RoConflict { .. })
        ));
    }

    #[test]
    fn planner_fails_closed_without_a_resolver() {
        let mut p = pol("/work/p");
        p.network = Network::Host;
        let mut f = facts();
        f.resolv_conf = Some(Err("no usable DNS resolver".into()));
        match plan(&p, &f, &[]) {
            Err(PlanError::NoResolver(m)) => assert!(m.contains("no usable DNS resolver")),
            other => panic!("expected NoResolver, got {other:?}"),
        }
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

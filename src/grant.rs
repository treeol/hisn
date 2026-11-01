//! Grants and revocation (DESIGN §10).
//!
//! Split in two halves:
//!
//! * **pure policy** ([`Rules`], [`GrantTable`], [`check_grant`]): path rules
//!   R1–R4 + grantability + bookkeeping. Fully unit-tested here.
//! * **kernel mechanics** ([`prepare_tree`], [`helper_main`]): `open_tree`,
//!   `setns`, `move_mount`, fd-based `umount2`. Needs user namespaces; covered
//!   by the host leak tests only.
//!
//! The sandbox can never initiate any of this: the supervisor holds the
//! namespace fds and the control socket is unreachable from inside (R5).

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::control::{E_EXISTS, E_NOT_GRANTABLE, E_NOT_GRANTED, E_PATH_FORBIDDEN, Mode};
use crate::policy::lexical_normalize;
use crate::sys;

/// A refused grant: wire error code + message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

/// Static facts the rules need; all paths canonical.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub runtime_roots: Vec<PathBuf>,
    pub grantable_rw: Vec<PathBuf>,
    /// Targets of static (non-grant) mounts, e.g. `/usr`, cwd, `/tmp`.
    pub static_mounts: Vec<PathBuf>,
    /// Static mounts that are read-only trees (a grant must not shadow them).
    pub static_ro: Vec<PathBuf>,
    /// Effective masks (default `/etc` masks + policy masks).
    pub masks: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub path: PathBuf,
    pub mode: Mode,
    pub recursive: bool,
    pub mount_id: u64,
    pub ts: String,
}

#[derive(Debug, Default)]
pub struct GrantTable {
    grants: BTreeMap<PathBuf, Grant>,
}

impl GrantTable {
    pub fn get(&self, p: &Path) -> Option<&Grant> {
        self.grants.get(p)
    }
    pub fn insert(&mut self, g: Grant) {
        self.grants.insert(g.path.clone(), g);
    }
    pub fn remove(&mut self, p: &Path) -> Option<Grant> {
        self.grants.remove(p)
    }
    pub fn list(&self) -> Vec<&Grant> {
        self.grants.values().collect()
    }
    pub fn paths(&self) -> Vec<PathBuf> {
        self.grants.keys().cloned().collect()
    }
}

/// True if any `/`-separated segment of the raw string is `.` or `..`.
/// (`Path::components()` silently drops interior `.`, so inspect the string.)
pub fn has_dot_segments(raw: &str) -> bool {
    raw.split('/').any(|seg| seg == "." || seg == "..")
}

/// Reject non-absolute paths, `..`/`.` segments and NUL; return the
/// normalised absolute path.
pub fn parse_abs(path: &str) -> Result<PathBuf, Refusal> {
    if path.contains('\0') {
        return Err(refuse(E_PATH_FORBIDDEN, "NUL byte in path"));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(refuse(E_PATH_FORBIDDEN, "path must be absolute"));
    }
    if has_dot_segments(path) {
        return Err(refuse(
            E_PATH_FORBIDDEN,
            "path must not contain . or .. components",
        ));
    }
    Ok(lexical_normalize(p))
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Decide whether `path` may be granted with `mode`. `path` must already be
/// canonical (resolved symlink-free by the caller via `openat2`).
///
/// Implements R1, R2, R3 and the `grantable_rw` bound; also refuses duplicates
/// (`E_EXISTS`) and grants nested in an existing grant of the same tree.
pub fn check_grant(
    rules: &Rules,
    table: &GrantTable,
    path: &Path,
    mode: Mode,
    recursive: bool,
) -> Result<(), Refusal> {
    // R2
    if path == Path::new("/") {
        return Err(refuse(E_PATH_FORBIDDEN, "`/` cannot be granted"));
    }
    for special in ["/proc", "/sys", "/dev"] {
        if path.starts_with(special) {
            return Err(refuse(
                E_PATH_FORBIDDEN,
                format!("{} cannot be granted", path.display()),
            ));
        }
    }
    // R1
    for root in &rules.runtime_roots {
        if overlaps(path, root) {
            return Err(refuse(
                E_PATH_FORBIDDEN,
                format!("{} overlaps the hisn runtime directory", path.display()),
            ));
        }
    }
    // R3: masks. A grant may *equal* a mask entry exactly (Wakil's `.secrets`
    // unmask-by-grant pattern, WAKIL-INTEGRATION §3); any other overlap is out.
    for m in &rules.masks {
        if path == m.as_path() {
            continue;
        }
        if overlaps(path, m) {
            return Err(refuse(
                E_PATH_FORBIDDEN,
                format!(
                    "{} overlaps the masked path {}",
                    path.display(),
                    m.display()
                ),
            ));
        }
    }
    // R3: a recursive grant must not swallow a mask below it (its content
    // would be re-exposed beneath the mask, which the mount order cannot fix).
    if recursive {
        for m in &rules.masks {
            if m.starts_with(path) && m != path {
                return Err(refuse(
                    E_PATH_FORBIDDEN,
                    format!(
                        "recursive grant of {} would cover the masked path {}",
                        path.display(),
                        m.display()
                    ),
                ));
            }
        }
    }
    // R3: may not shadow a static mount (equal or ancestor), nor sit inside a
    // read-only static tree (the grant would punch rw through a ro mount).
    for s in &rules.static_mounts {
        if path == s.as_path() || s.starts_with(path) {
            return Err(refuse(
                E_PATH_FORBIDDEN,
                format!(
                    "{} would shadow the static mount {}",
                    path.display(),
                    s.display()
                ),
            ));
        }
    }
    for s in &rules.static_ro {
        if path.starts_with(s) && mode == Mode::Rw {
            return Err(refuse(
                E_PATH_FORBIDDEN,
                format!(
                    "{} lies inside the read-only mount {}",
                    path.display(),
                    s.display()
                ),
            ));
        }
    }
    // Landlock cannot be widened later: rw grants must sit under a prefix that
    // was in the write set at start.
    if mode == Mode::Rw && !rules.grantable_rw.iter().any(|g| path.starts_with(g)) {
        return Err(refuse(
            E_NOT_GRANTABLE,
            format!(
                "{} is not under any mounts.grantable_rw prefix",
                path.display()
            ),
        ));
    }
    // Bookkeeping: never silently change a mode, never nest grants.
    if table.get(path).is_some() {
        return Err(refuse(
            E_EXISTS,
            format!("{} is already granted", path.display()),
        ));
    }
    for g in table.list() {
        if path.starts_with(&g.path) || g.path.starts_with(path) {
            return Err(refuse(
                E_EXISTS,
                format!(
                    "{} overlaps the existing grant {}",
                    path.display(),
                    g.path.display()
                ),
            ));
        }
    }
    Ok(())
}

pub fn require_granted<'a>(table: &'a GrantTable, path: &Path) -> Result<&'a Grant, Refusal> {
    table
        .get(path)
        .ok_or_else(|| refuse(E_NOT_GRANTED, format!("{} is not granted", path.display())))
}

// ------------------------------------------------------------------ mechanics

/// Resolve a grant source symlink-free (R4) and return an `O_PATH` fd plus the
/// canonical path read back from the kernel.
pub fn open_source(path: &Path) -> io::Result<(OwnedFd, PathBuf)> {
    let rel = sys::rel_to_root(path);
    let root = sys::openat2(
        libc::AT_FDCWD,
        c"/",
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        0,
    )?;
    let fd = sys::openat2(
        root.as_raw_fd(),
        &sys::cstr(rel)?,
        (libc::O_PATH | libc::O_CLOEXEC) as u64,
        0,
        sys::RESOLVE_BENEATH | sys::RESOLVE_NO_SYMLINKS | sys::RESOLVE_NO_MAGICLINKS,
    )?;
    let canon = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    Ok((fd, canon))
}

/// Clone the source into a detached mount; for `ro` apply the flag to the
/// detached tree *before* it can be attached anywhere (DESIGN D2).
pub fn prepare_tree(src: &OwnedFd, mode: Mode, recursive: bool) -> io::Result<OwnedFd> {
    let mut flags = sys::OPEN_TREE_CLONE | sys::OPEN_TREE_CLOEXEC | sys::AT_EMPTY_PATH;
    if recursive {
        flags |= sys::AT_RECURSIVE;
    }
    let tree = sys::open_tree(src.as_raw_fd(), c"", flags)?;
    let mut set = sys::MOUNT_ATTR_NOSUID;
    if mode == Mode::Ro {
        set |= sys::MOUNT_ATTR_RDONLY;
    }
    let attr = sys::MountAttr {
        attr_set: set,
        ..Default::default()
    };
    let mut f = sys::AT_EMPTY_PATH;
    if recursive {
        f |= sys::AT_RECURSIVE;
    }
    sys::mount_setattr(tree.as_raw_fd(), c"", f, &attr)?;
    Ok(tree)
}

/// Commands the helper process understands. Wire format (one line on the
/// helper's stdin): `grant <target-path>` or `revoke`.
#[derive(Debug, PartialEq, Eq)]
pub enum HelperCmd {
    Grant(PathBuf),
    /// Detach the passed mount-root fd; then remove the directories the
    /// grant of this path created.
    Revoke(PathBuf),
}

pub fn parse_helper_cmd(line: &str) -> Option<HelperCmd> {
    let line = line.trim_end_matches('\n');
    let (verb, p) = line.split_once(' ')?;
    if !(p.starts_with('/') && !p.contains('\0') && !has_dot_segments(p)) {
        return None;
    }
    match verb {
        "grant" => Some(HelperCmd::Grant(PathBuf::from(p))),
        "revoke" => Some(HelperCmd::Revoke(PathBuf::from(p))),
        _ => None,
    }
}

/// Persistent helper (DESIGN §10, D17). Forked by the supervisor once, after
/// the sandbox reported ready and **before any thread exists**, so it may use
/// the full Rust runtime. It stays in the supervisor's user namespace S and
/// joins only the sandbox mount namespace: S is the owner-ancestor of the
/// sandbox userns, so the helper has `CAP_SYS_ADMIN` over that mntns *and*
/// over the anonymous trees the supervisor creates with `open_tree`. (A
/// re-exec'd helper would lose its capabilities on `execve`, and joining the
/// sandbox userns would drop its authority over the detached tree.)
///
/// Wire protocol over the socketpair: request = `grant <abs path>` or
/// `revoke` plus exactly one fd (the detached tree, or the mount-root fd);
/// reply = `ok <mount id>` (+ the attached mount-root fd for grants) or
/// `err <errno> <message>`. EOF on the socket ends the helper.
///
/// After `setns` the helper's `/proc` is the sandbox's procfs, where
/// `/proc/self` does not resolve (it lives outside that pid namespace), so no
/// `/proc/self/...` path may be used here.
pub fn helper_serve(sock: OwnedFd, mntns: OwnedFd) -> ! {
    let code = match helper_loop(&sock, &mntns) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("hisn helper: {e}");
            1
        }
    };
    // SAFETY: terminate without running the parent's atexit machinery.
    unsafe { libc::_exit(code) }
}

fn helper_loop(sock: &OwnedFd, mntns: &OwnedFd) -> io::Result<()> {
    sys::prctl(1 /* PR_SET_PDEATHSIG */, libc::SIGKILL as u64, 0, 0, 0)?;
    sys::setns(mntns.as_raw_fd(), libc::CLONE_NEWNS)?;
    // Work only through an explicit root dirfd of the sandbox mntns.
    std::env::set_current_dir("/")?;
    let root = sys::openat2(
        libc::AT_FDCWD,
        c"/",
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        0,
    )?;
    let mut buf = vec![0u8; 8192];
    // Directories each live grant created, for removal on revoke.
    let mut created: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> = Default::default();
    loop {
        let (n, fd) = sys::recv_with_fd(sock.as_raw_fd(), &mut buf)?;
        if n == 0 {
            return Ok(()); // supervisor closed its end
        }
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        let result = match (parse_helper_cmd(&line), fd) {
            (Some(HelperCmd::Grant(target)), Some(tree)) => {
                do_grant(&root, &target, &tree).map(|(id, attached, made)| {
                    created.insert(target, made);
                    (id, attached)
                })
            }
            (Some(HelperCmd::Revoke(target)), Some(mnt)) => do_revoke(&mnt).map(|()| {
                if let Some(made) = created.remove(&target) {
                    crate::rootfs::remove_created(root.as_raw_fd(), &made);
                }
                (0, None)
            }),
            _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };
        match result {
            Ok((id, attached)) => sys::send_with_fd(
                sock.as_raw_fd(),
                format!("ok {id}").as_bytes(),
                attached.as_ref().map(AsRawFd::as_raw_fd),
            )?,
            Err(e) => {
                let msg = format!("err {} {e}", e.raw_os_error().unwrap_or(0));
                sys::send_with_fd(sock.as_raw_fd(), msg.as_bytes(), None)?;
            }
        }
    }
}

type Granted = (u64, Option<OwnedFd>, Vec<PathBuf>);

fn do_grant(root: &OwnedFd, target: &Path, tree: &OwnedFd) -> io::Result<Granted> {
    let rel = sys::rel_to_root(target);
    let (dir, made) = crate::rootfs::ensure_dir_tracked(root.as_raw_fd(), rel)?;
    let attach = sys::move_mount(
        tree.as_raw_fd(),
        c"",
        dir.as_raw_fd(),
        c"",
        sys::MOVE_MOUNT_F_EMPTY_PATH | sys::MOVE_MOUNT_T_EMPTY_PATH,
    );
    if let Err(e) = attach {
        crate::rootfs::remove_created(root.as_raw_fd(), &made); // leave no trace on failure
        return Err(e);
    }
    // Reopen the *attached* mount root (not the covered mountpoint fd).
    let attached = sys::openat2(
        root.as_raw_fd(),
        &sys::cstr(rel)?,
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        sys::RESOLVE_BENEATH | sys::RESOLVE_NO_SYMLINKS | sys::RESOLVE_NO_MAGICLINKS,
    )?;
    let id = sys::mnt_id(attached.as_raw_fd(), c"", libc::AT_EMPTY_PATH)?;
    Ok((id, Some(attached), made))
}

/// Detach by fd, never by path: renames, planted symlinks or a shadowing mount
/// cannot make revoke miss (DESIGN D5). `fchdir` onto the mount root, then
/// `umount2(".")`.
fn do_revoke(mount_root: &OwnedFd) -> io::Result<()> {
    // SAFETY: plain fchdir on a descriptor we own.
    if unsafe { libc::fchdir(mount_root.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let r = sys::umount2(Path::new("."), libc::MNT_DETACH);
    std::env::set_current_dir("/")?; // leave the (now detached) mount
    r
}

/// Supervisor-side client of the helper socket.
pub struct HelperClient {
    sock: OwnedFd,
    pub pid: libc::pid_t,
}

impl HelperClient {
    pub fn new(sock: OwnedFd, pid: libc::pid_t) -> Self {
        Self { sock, pid }
    }

    fn call(&self, line: &str, fd: RawFd) -> io::Result<(String, Option<OwnedFd>)> {
        sys::send_with_fd(self.sock.as_raw_fd(), line.as_bytes(), Some(fd))?;
        let mut buf = vec![0u8; 4096];
        let (n, got) = sys::recv_with_fd(self.sock.as_raw_fd(), &mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "helper exited"));
        }
        Ok((String::from_utf8_lossy(&buf[..n]).into_owned(), got))
    }

    /// Attach `tree` at `target` inside the sandbox; returns the attached
    /// mount-root fd and its mount id.
    pub fn grant(&self, target: &Path, tree: &OwnedFd) -> io::Result<(OwnedFd, u64)> {
        let (reply, fd) = self.call(&format!("grant {}", target.display()), tree.as_raw_fd())?;
        let id = parse_helper_reply(&reply)?;
        Ok((
            fd.ok_or_else(|| io::Error::other("helper returned no mount fd"))?,
            id,
        ))
    }

    pub fn revoke(&self, target: &Path, mount_root: &OwnedFd) -> io::Result<()> {
        let (reply, _) = self.call(
            &format!("revoke {}", target.display()),
            mount_root.as_raw_fd(),
        )?;
        parse_helper_reply(&reply).map(drop)
    }
}

/// `ok <id>` → id; `err <errno> <msg>` → `io::Error`.
pub fn parse_helper_reply(reply: &str) -> io::Result<u64> {
    if let Some(id) = reply.strip_prefix("ok ") {
        return id
            .trim()
            .parse()
            .map_err(|_| io::Error::other(format!("bad helper reply {reply:?}")));
    }
    if let Some(rest) = reply.strip_prefix("err ") {
        let (errno, msg) = rest.split_once(' ').unwrap_or((rest, ""));
        return Err(match errno.parse::<i32>() {
            Ok(e) if e != 0 => io::Error::from_raw_os_error(e),
            _ => io::Error::other(msg.to_owned()),
        });
    }
    Err(io::Error::other(format!("bad helper reply {reply:?}")))
}

/// Holder kinds reported by revoke scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HolderKind {
    Cwd,
    Fd,
    Map,
    /// An entry that could not be read or identified: never counted as "clean".
    Unknown,
}

impl HolderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HolderKind::Cwd => "cwd",
            HolderKind::Fd => "fd",
            HolderKind::Map => "map",
            HolderKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Holder {
    pub pid: i32,
    pub kind: HolderKind,
}

/// Does a `/proc/<pid>/fdinfo/<n>` body say the fd lives on mount `mnt_id`?
pub fn fdinfo_mount_id(body: &str) -> Option<u64> {
    body.lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Mount id of the mapping at `maps` line (`/proc/<pid>/maps` carries only
/// dev:inode, so callers compare `st_dev` instead); returns the device string.
pub fn maps_device(line: &str) -> Option<&str> {
    line.split_whitespace().nth(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules {
            runtime_roots: vec!["/run/user/1000/hisn".into(), "/tmp/hisn-1000".into()],
            grantable_rw: vec!["/data/shared".into()],
            static_mounts: vec![
                "/usr".into(),
                "/work/p".into(),
                "/tmp".into(),
                "/etc".into(),
            ],
            static_ro: vec!["/usr".into(), "/etc".into()],
            masks: vec!["/work/p/.secrets".into(), "/etc/ssh".into()],
        }
    }

    fn check(path: &str, mode: Mode, rec: bool) -> Result<(), Refusal> {
        check_grant(&rules(), &GrantTable::default(), Path::new(path), mode, rec)
    }

    fn code(r: Result<(), Refusal>) -> &'static str {
        r.unwrap_err().code
    }

    #[test]
    fn parse_abs_rejects_relative_dotdot_and_nul() {
        assert_eq!(parse_abs("/a/b/").unwrap(), PathBuf::from("/a/b"));
        assert_eq!(parse_abs("/a//b").unwrap(), PathBuf::from("/a/b"));
        assert!(!has_dot_segments("/a/.hidden/..x/b."));
        for bad in ["a/b", "/a/../b", "/a/./b", "/a/.", "/..", "", "/a\0b"] {
            assert_eq!(
                parse_abs(bad).unwrap_err().code,
                E_PATH_FORBIDDEN,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn plain_ro_and_rw_grants_pass() {
        assert!(check("/srv/data", Mode::Ro, false).is_ok());
        assert!(check("/data/shared/out", Mode::Rw, false).is_ok());
        assert!(check("/data/shared", Mode::Rw, true).is_ok());
    }

    #[test]
    fn r2_special_trees_and_root() {
        for p in ["/", "/proc", "/proc/1", "/sys", "/dev", "/dev/pts"] {
            assert_eq!(code(check(p, Mode::Ro, false)), E_PATH_FORBIDDEN, "{p}");
        }
    }

    #[test]
    fn r1_runtime_dir_equal_inside_and_ancestor() {
        for p in [
            "/run/user/1000/hisn",
            "/run/user/1000/hisn/other-session",
            "/run/user/1000/hisn/other-session/control.sock",
            "/run/user/1000",
            "/run/user",
            "/tmp/hisn-1000/x",
        ] {
            assert_eq!(code(check(p, Mode::Ro, true)), E_PATH_FORBIDDEN, "{p}");
        }
        // lookalike siblings are fine
        assert!(check("/run/user/1000/hisnx", Mode::Ro, false).is_ok());
        assert!(check("/tmp/hisn-10000", Mode::Ro, false).is_ok());
    }

    #[test]
    fn r3_masks_only_exact_unmask_by_grant() {
        // exact == the documented unmask-by-grant pattern, but needs a grantable prefix for rw
        assert!(check("/work/p/.secrets", Mode::Ro, false).is_ok());
        // inside a mask, or a different name that merely contains it
        assert_eq!(
            code(check("/work/p/.secrets/key", Mode::Ro, false)),
            E_PATH_FORBIDDEN
        );
        assert_eq!(
            code(check("/etc/ssh/keys", Mode::Ro, false)),
            E_PATH_FORBIDDEN
        );
        // a recursive grant that covers a mask is refused
        assert_eq!(code(check("/work", Mode::Ro, true)), E_PATH_FORBIDDEN);
        // non-recursive ancestor grants are refused too: /work is an ancestor of static /work/p
        assert_eq!(code(check("/work", Mode::Ro, false)), E_PATH_FORBIDDEN);
    }

    #[test]
    fn r3_static_mounts_cannot_be_shadowed_or_made_writable() {
        assert_eq!(
            code(check("/usr", Mode::Ro, false)),
            E_PATH_FORBIDDEN,
            "equal"
        );
        assert_eq!(code(check("/", Mode::Ro, false)), E_PATH_FORBIDDEN);
        assert_eq!(code(check("/work/p", Mode::Ro, false)), E_PATH_FORBIDDEN);
        // rw inside a read-only tree
        assert_eq!(
            code(check("/usr/local/x", Mode::Rw, false)),
            E_PATH_FORBIDDEN
        );
        // ro inside a ro tree is harmless (no new access)
        assert!(check("/usr/share/doc", Mode::Ro, false).is_ok());
    }

    #[test]
    fn rw_requires_a_grantable_prefix() {
        assert_eq!(code(check("/srv/data", Mode::Rw, false)), E_NOT_GRANTABLE);
        assert_eq!(
            code(check("/data/sharedx", Mode::Rw, false)),
            E_NOT_GRANTABLE,
            "prefix is path-wise, not string-wise"
        );
        assert!(check("/data/shared/a/b", Mode::Rw, false).is_ok());
    }

    #[test]
    fn duplicates_and_nesting_are_never_silently_changed() {
        let mut t = GrantTable::default();
        t.insert(Grant {
            path: "/srv/a".into(),
            mode: Mode::Ro,
            recursive: false,
            mount_id: 9,
            ts: "t".into(),
        });
        let r = rules();
        for p in ["/srv/a", "/srv/a/b", "/srv"] {
            let e = check_grant(&r, &t, Path::new(p), Mode::Ro, false).unwrap_err();
            assert_eq!(e.code, E_EXISTS, "{p}");
        }
        assert!(check_grant(&r, &t, Path::new("/srv/b"), Mode::Ro, false).is_ok());
        // same path, different mode: still E_EXISTS (not an upgrade)
        assert_eq!(
            check_grant(&r, &t, Path::new("/srv/a"), Mode::Rw, false)
                .unwrap_err()
                .code,
            E_NOT_GRANTABLE
        );
    }

    #[test]
    fn table_bookkeeping() {
        let mut t = GrantTable::default();
        assert!(require_granted(&t, Path::new("/x")).is_err());
        t.insert(Grant {
            path: "/x".into(),
            mode: Mode::Rw,
            recursive: true,
            mount_id: 3,
            ts: "t".into(),
        });
        assert_eq!(require_granted(&t, Path::new("/x")).unwrap().mount_id, 3);
        assert_eq!(t.paths(), vec![PathBuf::from("/x")]);
        assert!(t.remove(Path::new("/x")).is_some());
        assert_eq!(
            require_granted(&t, Path::new("/x")).unwrap_err().code,
            E_NOT_GRANTED
        );
    }

    #[test]
    fn helper_command_parsing() {
        assert_eq!(
            parse_helper_cmd("revoke /a\n"),
            Some(HelperCmd::Revoke("/a".into()))
        );
        assert_eq!(parse_helper_cmd("revoke"), None);
        assert_eq!(parse_helper_cmd("revoke /a/../b"), None);
        assert_eq!(
            parse_helper_cmd("grant /a/b\n"),
            Some(HelperCmd::Grant("/a/b".into()))
        );
        for bad in [
            "grant a/b",
            "grant /a/../b",
            "grant /a/./b",
            "grant /a/.",
            "grant",
            "mount /x",
            "",
        ] {
            assert_eq!(parse_helper_cmd(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn helper_reply_parsing() {
        assert_eq!(parse_helper_reply("ok 42").unwrap(), 42);
        let e = parse_helper_reply("err 30 Read-only file system").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(30));
        let e = parse_helper_reply("err 0 something odd").unwrap_err();
        assert!(e.to_string().contains("something odd"));
        assert!(parse_helper_reply("garbage").is_err());
        assert!(parse_helper_reply("ok notanumber").is_err());
    }

    #[test]
    fn holder_parsing() {
        assert_eq!(
            fdinfo_mount_id("pos:\t0\nflags:\t02\nmnt_id:\t42\nino:\t1\n"),
            Some(42)
        );
        assert_eq!(fdinfo_mount_id("pos: 0\n"), None);
        assert_eq!(
            maps_device("7f00-7f10 r--p 00000000 08:01 1234 /x/y"),
            Some("08:01")
        );
        assert!(HolderKind::Unknown > HolderKind::Fd);
        assert_eq!(HolderKind::Map.as_str(), "map");
    }

    #[test]
    fn open_source_refuses_symlinks_and_returns_canonical_path() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = real.parent().unwrap().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (_fd, canon) = open_source(&real).unwrap();
        assert_eq!(canon, real);
        let e = open_source(&link).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        assert!(open_source(&real.join("missing")).is_err());
    }
}

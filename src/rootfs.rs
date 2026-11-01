//! Executes a mount plan (DESIGN §3 steps 3–9). Runs inside the sandbox's
//! user+mount namespaces, as sandbox init, before `pivot_root`.
//!
//! **Needs user namespaces and the new mount API; it cannot run in the Wakil
//! build sandbox.** Everything pure lives in `mounts`; this module is
//! exercised by the host leak tests.
//!
//! Path discipline: every target is reached by walking components from a root
//! dirfd with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS)`, so no mount ever lands on a host path through a
//! symlink living inside a bound tree. Binds use `open_tree` + `move_mount`
//! onto the target fd; fresh filesystems use `mount(2)` on `/proc/self/fd/N`.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::mounts::{MountKind, MountOp};
use crate::sys::{self, MountAttr};

const O_PATH_DIR: u64 = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
const O_PATH_ANY: u64 = (libc::O_PATH | libc::O_CLOEXEC) as u64;
const RESOLVE_SAFE: u64 =
    sys::RESOLVE_BENEATH | sys::RESOLVE_NO_SYMLINKS | sys::RESOLVE_NO_MAGICLINKS;

/// Proc entries masked/made read-only after mounting `/proc` (same set as runc).
const PROC_MASKED: [&str; 7] = [
    "kcore",
    "keys",
    "latency_stats",
    "timer_list",
    "timer_stats",
    "sched_debug",
    "acpi",
];
const PROC_MASKED_ALSO: [&str; 1] = ["scsi"];
const PROC_READONLY: [&str; 5] = ["bus", "fs", "irq", "sys", "sysrq-trigger"];

/// Make `new_root` a private mount point backed by a small tmpfs.
pub fn mount_root(new_root: &Path) -> Result<()> {
    sys::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )
    .context("making / mount propagation private")?;
    sys::mount(
        Some("tmpfs"),
        new_root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=4m,mode=0755"),
    )
    .with_context(|| format!("mounting root tmpfs on {}", new_root.display()))
}

fn open_dir_path(p: &Path) -> io::Result<OwnedFd> {
    sys::openat2(libc::AT_FDCWD, &sys::cstr(p)?, O_PATH_DIR, 0, 0)
}

/// Walk `rel` (no `..`, no leading slash) from `root`, creating directories
/// as needed. Returns an `O_PATH` fd of the final directory.
pub fn ensure_dir(root: RawFd, rel: &Path) -> io::Result<OwnedFd> {
    ensure_dir_tracked(root, rel).map(|(fd, _)| fd)
}

/// Like [`ensure_dir`], also returning the directories this call *created*
/// (relative to `root`, shallowest first) so a revoke can remove exactly
/// those and leave the path as ENOENT again.
pub fn ensure_dir_tracked(root: RawFd, rel: &Path) -> io::Result<(OwnedFd, Vec<PathBuf>)> {
    // SAFETY: dup of a valid fd to get an owned handle we can replace.
    let mut cur = unsafe { OwnedFd::from_raw_fd(libc::dup(root)) };
    let mut created = Vec::new();
    let mut walked = PathBuf::new();
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            if matches!(comp, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        let c = sys::cstr(Path::new(name))?;
        walked.push(name);
        let next = match sys::openat2(cur.as_raw_fd(), &c, O_PATH_DIR, 0, RESOLVE_SAFE) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // SAFETY: valid dirfd + C string.
                if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                created.push(walked.clone());
                sys::openat2(cur.as_raw_fd(), &c, O_PATH_DIR, 0, RESOLVE_SAFE)?
            }
            Err(e) => return Err(e),
        };
        cur = next;
    }
    Ok((cur, created))
}

/// Remove `rels` (as returned by [`ensure_dir_tracked`]) deepest first.
/// Best effort: a directory that is no longer empty or is a mountpoint stays.
pub fn remove_created(root: RawFd, rels: &[PathBuf]) {
    for rel in rels.iter().rev() {
        let Some(name) = rel.file_name() else {
            continue;
        };
        let Ok(parent) = ensure_existing_dir(root, rel.parent().unwrap_or(Path::new(""))) else {
            continue;
        };
        if let Ok(c) = sys::cstr(Path::new(name)) {
            // SAFETY: valid dirfd + C string; AT_REMOVEDIR removes an empty dir only.
            unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
        }
    }
}

/// Open an existing directory beneath `root` (never creating anything).
fn ensure_existing_dir(root: RawFd, rel: &Path) -> io::Result<OwnedFd> {
    // SAFETY: dup of a valid fd.
    let mut cur = unsafe { OwnedFd::from_raw_fd(libc::dup(root)) };
    for comp in rel.components() {
        if let Component::Normal(name) = comp {
            cur = sys::openat2(
                cur.as_raw_fd(),
                &sys::cstr(Path::new(name))?,
                O_PATH_DIR,
                0,
                RESOLVE_SAFE,
            )?;
        }
    }
    Ok(cur)
}

/// Open (creating an empty regular file if absent) the file at `rel`.
fn ensure_file(root: RawFd, rel: &Path) -> io::Result<OwnedFd> {
    let name = rel
        .file_name()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let parent = ensure_dir(root, rel.parent().unwrap_or(Path::new("")))?;
    let c = sys::cstr(Path::new(name))?;
    match sys::openat2(parent.as_raw_fd(), &c, O_PATH_ANY, 0, RESOLVE_SAFE) {
        Ok(fd) => Ok(fd),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            // SAFETY: valid dirfd + C string; O_EXCL|O_NOFOLLOW make creation atomic and symlink-safe.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_WRONLY,
                    0o644,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fresh fd.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
            sys::openat2(parent.as_raw_fd(), &c, O_PATH_ANY, 0, RESOLVE_SAFE)
        }
        Err(e) => Err(e),
    }
}

fn proc_fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Clone `src` (a host path) into a detached mount and attach it at `target`.
fn bind_onto(
    src: &Path,
    target: &OwnedFd,
    recursive: bool,
    readonly: bool,
    extra: u64,
) -> io::Result<()> {
    let mut flags =
        sys::OPEN_TREE_CLONE | sys::OPEN_TREE_CLOEXEC | libc::AT_SYMLINK_NOFOLLOW as u32;
    if recursive {
        flags |= sys::AT_RECURSIVE;
    }
    let tree = sys::open_tree(libc::AT_FDCWD, &sys::cstr(src)?, flags)?;
    let set = if readonly { sys::MOUNT_ATTR_RDONLY } else { 0 } | extra;
    if set != 0 {
        let attr = MountAttr {
            attr_set: set,
            ..Default::default()
        };
        let mut f = sys::AT_EMPTY_PATH;
        if recursive {
            f |= sys::AT_RECURSIVE;
        }
        sys::mount_setattr(tree.as_raw_fd(), c"", f, &attr)?;
    }
    sys::move_mount(
        tree.as_raw_fd(),
        c"",
        target.as_raw_fd(),
        c"",
        sys::MOVE_MOUNT_F_EMPTY_PATH | sys::MOVE_MOUNT_T_EMPTY_PATH,
    )
}

fn set_ro(fd: &OwnedFd, recursive: bool) -> io::Result<()> {
    let attr = MountAttr {
        attr_set: sys::MOUNT_ATTR_RDONLY,
        ..Default::default()
    };
    let mut f = sys::AT_EMPTY_PATH;
    if recursive {
        f |= sys::AT_RECURSIVE;
    }
    sys::mount_setattr(fd.as_raw_fd(), c"", f, &attr)
}

fn tmpfs_data(size: u64, mode: u32) -> String {
    format!("size={size},mode={mode:o}")
}

fn mask_file(target: &OwnedFd) -> io::Result<()> {
    bind_onto(Path::new("/dev/null"), target, false, true, 0)
}

fn mask_dir(target: &OwnedFd) -> io::Result<()> {
    sys::mount(
        Some("tmpfs"),
        &proc_fd_path(target),
        Some("tmpfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=4k,mode=0555"),
    )
}

/// After mounting a fresh procfs at `proc_fd`'s path, hide dangerous entries.
fn harden_proc(root: RawFd) -> Result<()> {
    for name in PROC_MASKED.iter().chain(&PROC_MASKED_ALSO) {
        let rel = Path::new("proc").join(name);
        let parent = ensure_dir(root, rel.parent().expect("has parent"))?;
        let c = sys::cstr(Path::new(name))?;
        let t = match sys::openat2(parent.as_raw_fd(), &c, O_PATH_ANY, 0, RESOLVE_SAFE) {
            Ok(t) => t,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue, // absent on this kernel
            Err(e) => return Err(e).with_context(|| format!("opening /proc/{name} to mask it")),
        };
        // SAFETY: valid fd; fstat into a zeroed buffer.
        let is_dir = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            libc::fstat(t.as_raw_fd(), &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
        };
        if is_dir { mask_dir(&t) } else { mask_file(&t) }
            .with_context(|| format!("masking /proc/{name}"))?;
    }
    for name in PROC_READONLY {
        let rel = Path::new("proc").join(name);
        let parent = ensure_dir(root, rel.parent().expect("has parent"))?;
        let c = sys::cstr(Path::new(name))?;
        let t = match sys::openat2(parent.as_raw_fd(), &c, O_PATH_ANY, 0, RESOLVE_SAFE) {
            Ok(t) => t,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("opening /proc/{name} to remount it read-only"));
            }
        };
        // Bind the entry onto itself read-only. The *source* is addressed via
        // the (safe) fd, so no path is re-resolved.
        let src = proc_fd_path(&t);
        bind_onto(&src, &t, true, true, 0)
            .with_context(|| format!("remounting /proc/{name} read-only"))?;
    }
    Ok(())
}

/// Execute `plan` against the tmpfs mounted on `new_root`.
pub fn execute(plan: &[MountOp], new_root: &Path) -> Result<()> {
    let root = open_dir_path(new_root).context("opening new root")?;
    let rfd = root.as_raw_fd();
    let mut sealed: Vec<PathBuf> = Vec::new();

    for op in plan {
        let rel = sys::rel_to_root(&op.target);
        let ctx = || format!("{:?} at {}", op.kind, op.target.display());
        match &op.kind {
            MountKind::EmptyDir => {
                ensure_dir(rfd, rel).with_context(ctx)?;
            }
            MountKind::Symlink { link_target } => {
                let parent =
                    ensure_dir(rfd, rel.parent().unwrap_or(Path::new(""))).with_context(ctx)?;
                let name = sys::cstr(Path::new(
                    rel.file_name().ok_or_else(|| anyhow!("no name"))?,
                ))?;
                let tgt = sys::cstr_str(link_target)?;
                // SAFETY: valid C strings and dirfd.
                if unsafe { libc::symlinkat(tgt.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0
                {
                    return Err(io::Error::last_os_error()).with_context(ctx);
                }
            }
            MountKind::Generated { content } => {
                let f = ensure_file(rfd, rel).with_context(ctx)?;
                // O_PATH fds cannot be written; reopen through /proc/self/fd.
                fs::write(proc_fd_path(&f), content).with_context(ctx)?;
            }
            MountKind::Tmpfs {
                size,
                mode,
                readonly,
            } => {
                let t = ensure_dir(rfd, rel).with_context(ctx)?;
                let dev = if op.target == Path::new("/dev") {
                    0
                } else {
                    libc::MS_NODEV
                };
                sys::mount(
                    Some("tmpfs"),
                    &proc_fd_path(&t),
                    Some("tmpfs"),
                    libc::MS_NOSUID | dev,
                    Some(&tmpfs_data(*size, *mode)),
                )
                .with_context(ctx)?;
                if *readonly {
                    sealed.push(rel.to_path_buf());
                }
            }
            MountKind::BindRo { recursive } | MountKind::BindRw { recursive } => {
                let src = op
                    .source
                    .as_deref()
                    .ok_or_else(|| anyhow!("bind without source"))?;
                let is_dir = fs::metadata(src).with_context(ctx)?.is_dir();
                let t = if is_dir {
                    ensure_dir(rfd, rel)
                } else {
                    ensure_file(rfd, rel)
                }
                .with_context(ctx)?;
                let ro = matches!(op.kind, MountKind::BindRo { .. });
                bind_onto(src, &t, *recursive, ro, sys::MOUNT_ATTR_NOSUID).with_context(ctx)?;
            }
            MountKind::BindDevice => {
                let src = op
                    .source
                    .as_deref()
                    .ok_or_else(|| anyhow!("device without source"))?;
                let t = ensure_file(rfd, rel).with_context(ctx)?;
                bind_onto(src, &t, false, false, sys::MOUNT_ATTR_NOSUID).with_context(ctx)?;
            }
            MountKind::MaskFile => {
                let t = ensure_file(rfd, rel).with_context(ctx)?;
                mask_file(&t).with_context(ctx)?;
            }
            MountKind::MaskDir => {
                let t = ensure_dir(rfd, rel).with_context(ctx)?;
                mask_dir(&t).with_context(ctx)?;
            }
            MountKind::Proc => {
                let t = ensure_dir(rfd, rel).with_context(ctx)?;
                // Fails closed if the kernel considers the inherited proc
                // over-mounted (e.g. inside Docker); never falls back to a
                // bind of the host /proc.
                sys::mount(
                    Some("proc"),
                    &proc_fd_path(&t),
                    Some("proc"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    None,
                )
                .with_context(|| {
                    "mounting a new procfs failed; hisn will not fall back to the host /proc"
                        .to_owned()
                })?;
                harden_proc(rfd)?;
            }
            MountKind::Devpts => {
                let t = ensure_dir(rfd, rel).with_context(ctx)?;
                sys::mount(
                    Some("devpts"),
                    &proc_fd_path(&t),
                    Some("devpts"),
                    libc::MS_NOSUID | libc::MS_NOEXEC,
                    Some("newinstance,ptmxmode=0666,mode=0620"),
                )
                .with_context(ctx)?;
            }
        }
    }

    // Seal tmpfs trees whose children are now in place.
    for rel in sealed {
        let t = ensure_dir(rfd, &rel)?;
        set_ro(&t, false).with_context(|| format!("sealing /{} read-only", rel.display()))?;
    }
    Ok(())
}

/// `pivot_root` into `new_root` and detach the old root (DESIGN §3 step 9).
/// After this call the host filesystem is unreachable (invariant 1).
pub fn enter(new_root: &Path) -> Result<()> {
    std::env::set_current_dir(new_root).context("chdir to new root")?;
    sys::pivot_root(Path::new("."), Path::new(".")).context("pivot_root")?;
    sys::umount2(Path::new("."), libc::MNT_DETACH).context("detaching the old root")?;
    std::env::set_current_dir("/").context("chdir /")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn ensure_dir_creates_nested_dirs_and_refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::File::open(d.path()).unwrap();
        let rfd = root.as_fd().as_raw_fd();
        ensure_dir(rfd, Path::new("a/b/c")).unwrap();
        assert!(d.path().join("a/b/c").is_dir());
        // idempotent
        ensure_dir(rfd, Path::new("a/b/c")).unwrap();
        // a symlink planted in the tree is never followed
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("a/evil")).unwrap();
        let e = ensure_dir(rfd, Path::new("a/evil/x")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        assert!(
            !outside.path().join("x").exists(),
            "nothing created through the symlink"
        );
        // `..` is rejected outright
        assert!(ensure_dir(rfd, Path::new("a/../../x")).is_err());
    }

    #[test]
    fn tracked_creation_and_removal_restores_enoent() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::File::open(d.path()).unwrap();
        let rfd = root.as_fd().as_raw_fd();
        ensure_dir(rfd, Path::new("pre")).unwrap();
        let (_fd, created) = ensure_dir_tracked(rfd, Path::new("pre/a/b")).unwrap();
        assert_eq!(
            created,
            vec![PathBuf::from("pre/a"), PathBuf::from("pre/a/b")]
        );
        // second call creates nothing
        let (_fd, again) = ensure_dir_tracked(rfd, Path::new("pre/a/b")).unwrap();
        assert!(again.is_empty());
        remove_created(rfd, &created);
        assert!(!d.path().join("pre/a").exists(), "created dirs are gone");
        assert!(d.path().join("pre").is_dir(), "pre-existing dirs stay");
        // a created dir that gained content is left alone
        let (_fd, created) = ensure_dir_tracked(rfd, Path::new("x/y")).unwrap();
        fs::write(d.path().join("x/y/keep"), b"1").unwrap();
        remove_created(rfd, &created);
        assert!(d.path().join("x/y/keep").exists());
    }

    #[test]
    fn ensure_file_creates_once_and_stays_beneath() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::File::open(d.path()).unwrap();
        let rfd = root.as_fd().as_raw_fd();
        ensure_file(rfd, Path::new("etc/passwd")).unwrap();
        assert!(d.path().join("etc/passwd").is_file());
        ensure_file(rfd, Path::new("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/etc/shadow", d.path().join("etc/link")).unwrap();
        assert!(ensure_file(rfd, Path::new("etc/link")).is_err());
    }

    #[test]
    fn tmpfs_option_string() {
        assert_eq!(tmpfs_data(4096, 0o1777), "size=4096,mode=1777");
        assert_eq!(tmpfs_data(1, 0o700), "size=1,mode=700");
    }
}

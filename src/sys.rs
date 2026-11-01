//! Thin, audited wrappers over raw Linux syscalls that neither `std` nor
//! `rustix` expose conveniently (new mount API, `openat2`, `close_range`,
//! fd passing). Everything else in hisn calls these instead of using `unsafe`
//! directly. Each wrapper maps errno to `io::Error`.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use libc::{c_int, c_long, c_uint, c_ulong};

pub const OPEN_TREE_CLONE: c_uint = 1;
pub const OPEN_TREE_CLOEXEC: c_uint = libc::O_CLOEXEC as c_uint;
pub const AT_RECURSIVE: c_uint = 0x8000;
pub const AT_EMPTY_PATH: c_uint = libc::AT_EMPTY_PATH as c_uint;
pub const MOVE_MOUNT_F_EMPTY_PATH: c_uint = 0x4;
pub const MOVE_MOUNT_T_EMPTY_PATH: c_uint = 0x40;
pub const MOUNT_ATTR_RDONLY: u64 = 0x1;
pub const MOUNT_ATTR_NOSUID: u64 = 0x2;
pub const MOUNT_ATTR_NODEV: u64 = 0x4;
pub const MOUNT_ATTR_NOEXEC: u64 = 0x8;
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
#[derive(Default)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn cvt(r: c_long) -> io::Result<c_long> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_int(r: c_int) -> io::Result<c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub fn cstr_str(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn owned(fd: c_long) -> OwnedFd {
    // SAFETY: `fd` was just returned by a successful syscall that creates a
    // new descriptor, so we are its sole owner.
    unsafe { OwnedFd::from_raw_fd(fd as RawFd) }
}

/// `mount(2)`. `None` strings are passed as NULL.
pub fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let src = source.map(cstr_str).transpose()?;
    let tgt = cstr(target)?;
    let fst = fstype.map(cstr_str).transpose()?;
    let dat = data.map(cstr_str).transpose()?;
    let p = |c: &Option<CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: all pointers are valid NUL-terminated strings or NULL for the
    // duration of the call.
    cvt_int(unsafe { libc::mount(p(&src), tgt.as_ptr(), p(&fst), flags, p(&dat).cast()) }).map(drop)
}

pub fn umount2(target: &Path, flags: c_int) -> io::Result<()> {
    let tgt = cstr(target)?;
    // SAFETY: valid C string.
    cvt_int(unsafe { libc::umount2(tgt.as_ptr(), flags) }).map(drop)
}

pub fn open_tree(dirfd: RawFd, path: &CStr, flags: c_uint) -> io::Result<OwnedFd> {
    // SAFETY: valid fd/C string; the kernel validates flags.
    let r = unsafe { libc::syscall(libc::SYS_open_tree, dirfd, path.as_ptr(), flags) };
    cvt(r).map(owned)
}

pub fn move_mount(
    from_fd: RawFd,
    from_path: &CStr,
    to_fd: RawFd,
    to_path: &CStr,
    flags: c_uint,
) -> io::Result<()> {
    // SAFETY: valid fds/C strings.
    let r = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from_fd,
            from_path.as_ptr(),
            to_fd,
            to_path.as_ptr(),
            flags,
        )
    };
    cvt(r).map(drop)
}

pub fn mount_setattr(dirfd: RawFd, path: &CStr, flags: c_uint, attr: &MountAttr) -> io::Result<()> {
    // SAFETY: `attr` is a valid repr(C) struct of the documented size.
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            dirfd,
            path.as_ptr(),
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    cvt(r).map(drop)
}

/// `openat2(2)` with an explicit `RESOLVE_*` mask.
pub fn openat2(
    dirfd: RawFd,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    // SAFETY: `how` is a valid open_how for the stated size.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    cvt(r).map(owned)
}

pub fn pivot_root(new_root: &Path, put_old: &Path) -> io::Result<()> {
    let (n, o) = (cstr(new_root)?, cstr(put_old)?);
    // SAFETY: valid C strings.
    cvt(unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) }).map(drop)
}

pub fn setns(fd: RawFd, nstype: c_int) -> io::Result<()> {
    // SAFETY: plain syscall on a caller-owned fd.
    cvt_int(unsafe { libc::setns(fd, nstype) }).map(drop)
}

pub fn prctl(
    option: c_int,
    a2: c_ulong,
    a3: c_ulong,
    a4: c_ulong,
    a5: c_ulong,
) -> io::Result<c_int> {
    // SAFETY: integer-only prctl arguments.
    cvt_int(unsafe { libc::prctl(option, a2, a3, a4, a5) })
}

/// Close every fd >= 3 that is not in `keep`.
pub fn close_all_except(keep: &[RawFd]) {
    let mut keep: Vec<RawFd> = keep.iter().copied().filter(|f| *f >= 3).collect();
    keep.sort_unstable();
    let mut start: c_uint = 3;
    for k in keep
        .iter()
        .map(|k| *k as c_uint)
        .chain(std::iter::once(c_uint::MAX))
    {
        if k > start {
            // SAFETY: closing a range of descriptors we own; EINVAL/ENOSYS
            // are handled by the fallback below.
            let r = unsafe { libc::syscall(libc::SYS_close_range, start, k - 1, 0 as c_uint) };
            if r < 0 {
                close_range_fallback(start, k - 1);
            }
        }
        start = k.saturating_add(1);
    }
}

fn close_range_fallback(lo: c_uint, hi: c_uint) {
    let top = hi.min(65535);
    for fd in lo..=top {
        // SAFETY: closing arbitrary fds is memory-safe; errors are ignored.
        unsafe { libc::close(fd as RawFd) };
    }
}

pub fn set_cloexec(fd: RawFd, on: bool) -> io::Result<()> {
    // SAFETY: fcntl on a caller-owned fd.
    let cur = cvt_int(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    let new = if on {
        cur | libc::FD_CLOEXEC
    } else {
        cur & !libc::FD_CLOEXEC
    };
    cvt_int(unsafe { libc::fcntl(fd, libc::F_SETFD, new) }).map(drop)
}

/// Duplicate `fd` to a descriptor >= `min` *without* close-on-exec.
pub fn dup_inheritable(fd: RawFd, min: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl F_DUPFD on a caller-owned fd.
    let r = cvt_int(unsafe { libc::fcntl(fd, libc::F_DUPFD, min) })?;
    Ok(owned(r as c_long))
}

/// Mount id of the mount `fd` (or path) lives on, via `statx(STATX_MNT_ID)`.
pub fn mnt_id(dirfd: RawFd, path: &CStr, flags: c_int) -> io::Result<u64> {
    // SAFETY: zeroed statx is a valid out-buffer.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers; flags/mask are plain integers.
    cvt_int(unsafe { libc::statx(dirfd, path.as_ptr(), flags, libc::STATX_MNT_ID, &mut st) })?;
    if st.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    Ok(st.stx_mnt_id)
}

/// Inode of `/proc/<pid>/ns/<name>` — identifies the namespace.
pub fn ns_inode(pid: i32, name: &str) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}/ns/{name}")).map(|m| m.ino())
}

// ---------------------------------------------------------------- fd passing

/// Send `data` plus (optionally) one fd over a unix stream socket.
pub fn send_with_fd(sock: RawFd, data: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    // SAFETY: cmsg buffer sized with CMSG_SPACE and aligned via u64 storage.
    unsafe {
        let space = libc::CMSG_SPACE(std::mem::size_of::<c_int>() as c_uint) as usize;
        let mut buf = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = buf.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as c_uint) as _;
            std::ptr::copy_nonoverlapping(
                (&fd as *const RawFd).cast::<u8>(),
                libc::CMSG_DATA(c),
                std::mem::size_of::<c_int>(),
            );
        }
        let n = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < data.len() {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
    }
    Ok(())
}

/// Receive up to `buf.len()` bytes and at most one fd (received with
/// `MSG_CMSG_CLOEXEC`). Returns the byte count (0 = EOF).
pub fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: as in `send_with_fd`; received fds are wrapped immediately.
    unsafe {
        let space = libc::CMSG_SPACE(std::mem::size_of::<c_int>() as c_uint) as usize;
        let mut cbuf = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fd = None;
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let mut raw: RawFd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(c).cast_const(),
                    (&mut raw as *mut RawFd).cast::<u8>(),
                    std::mem::size_of::<c_int>(),
                );
                if raw >= 0 && fd.is_none() {
                    fd = Some(OwnedFd::from_raw_fd(raw));
                } else if raw >= 0 {
                    libc::close(raw);
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok((n as usize, fd))
    }
}

pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: valid 2-element out array.
    cvt_int(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    // SAFETY: fresh descriptors from socketpair.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// `PathBuf`-free convenience: `path` relative to `/` (strip leading slashes).
pub fn rel_to_root(p: &Path) -> &Path {
    p.strip_prefix("/").unwrap_or(p)
}

pub fn os(p: &str) -> &OsStr {
    OsStr::new(p)
}

pub fn fd_of<T: AsRawFd>(t: &T) -> RawFd {
    t.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    #[test]
    fn fd_passing_roundtrip() {
        let (a, b) = socketpair().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"hello").unwrap();
        send_with_fd(a.as_raw_fd(), b"R", Some(f.as_raw_fd())).unwrap();
        let mut buf = [0u8; 8];
        let (n, fd) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!((n, &buf[..n]), (1, &b"R"[..]));
        let fd = fd.expect("fd received");
        // same open file description: shares the offset (already at 5) — rewind via /proc
        let mut g = std::fs::File::from(fd);
        use std::io::Seek;
        g.rewind().unwrap();
        let mut s = String::new();
        g.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
        // data without fd
        send_with_fd(a.as_raw_fd(), b"G", None).unwrap();
        let (n, fd) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!((n, &buf[..n]), (1, &b"G"[..]));
        assert!(fd.is_none());
        drop(a);
        let (n, _) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, 0, "EOF after peer closes");
    }

    #[test]
    fn openat2_refuses_symlinks_and_beneath_escapes() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("link")).unwrap();
        let root = std::fs::File::open(d.path()).unwrap();
        let rfd = root.as_fd().as_raw_fd();
        let flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
        let r = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH;
        assert!(openat2(rfd, &cstr_str("sub").unwrap(), flags, 0, r).is_ok());
        let e = openat2(rfd, &cstr_str("link").unwrap(), flags, 0, r).unwrap_err();
        assert!(matches!(e.raw_os_error(), Some(libc::ELOOP)), "{e}");
        let e = openat2(rfd, &cstr_str("../x").unwrap(), flags, 0, r).unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(libc::EXDEV | libc::ENOENT)),
            "{e}"
        );
    }

    #[test]
    fn close_all_except_keeps_only_requested() {
        // Run in a forked child so we never close the harness' descriptors.
        // SAFETY: the child only does raw syscalls and `_exit`s.
        unsafe {
            let a = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            let b = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            let c = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            let pid = libc::fork();
            if pid == 0 {
                close_all_except(&[b]);
                let ok = libc::fcntl(a, libc::F_GETFD) == -1
                    && libc::fcntl(b, libc::F_GETFD) != -1
                    && libc::fcntl(c, libc::F_GETFD) == -1
                    && libc::fcntl(1, libc::F_GETFD) != -1;
                libc::_exit(if ok { 0 } else { 1 });
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            libc::close(a);
            libc::close(b);
            libc::close(c);
            assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0);
        }
    }

    #[test]
    fn mnt_id_and_ns_inode_work_on_self() {
        let id = mnt_id(libc::AT_FDCWD, &cstr_str("/").unwrap(), 0).unwrap();
        assert!(id > 0);
        let me = std::process::id() as i32;
        assert_eq!(ns_inode(me, "pid").unwrap(), ns_inode(me, "pid").unwrap());
        assert!(ns_inode(me, "nonexistent").is_err());
    }
}

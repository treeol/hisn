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

/// Duplicate `fd` to a close-on-exec descriptor numbered >= `min`.
pub fn dup_cloexec_min(fd: RawFd, min: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl F_DUPFD_CLOEXEC on a caller-owned fd.
    let r = cvt_int(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) })?;
    Ok(owned(r as c_long))
}

/// `chroot(2)` onto `dirfd`'s directory *without* a path lookup: the caller
/// passes the sandbox-root directory fd opened after `setns(mnt)`.
pub fn fchdir_chdir_root(dirfd: RawFd) -> io::Result<()> {
    // SAFETY: fchdir on a descriptor the caller owns.
    cvt_int(unsafe { libc::fchdir(dirfd) }).map(drop)
}

/// `(st_dev, st_ino)` of `path` relative to `dirfd` (pass `AT_EMPTY_PATH` and
/// an empty path to identify the descriptor itself). Fails closed when the
/// kernel does not report the inode.
pub fn dev_ino(dirfd: RawFd, path: &CStr, flags: c_int) -> io::Result<(u64, u64)> {
    // SAFETY: zeroed statx is a valid out-buffer.
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers; flags/mask are plain integers.
    cvt_int(unsafe { libc::statx(dirfd, path.as_ptr(), flags, libc::STATX_INO, &mut st) })?;
    if st.stx_mask & libc::STATX_INO == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    let dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);
    Ok((dev, st.stx_ino))
}

pub fn set_dumpable(on: bool) -> io::Result<()> {
    prctl(4 /* PR_SET_DUMPABLE */, u64::from(on), 0, 0, 0).map(drop)
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

/// Parent pid out of a `/proc/<pid>/status` body.
pub fn parse_ppid(status: &str) -> Option<i32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

/// Is `pid` equal to, or a descendant of, `ancestor`? Walks `PPid:` upwards
/// through the world-readable `/proc/<pid>/status`. Every process in a pid
/// namespace descends from that namespace's init, so for `ancestor` = the
/// sandbox init this decides sandbox membership without needing ptrace
/// access. `Err` if the chain cannot be followed (never guessed).
///
/// Retries the whole walk on `ENOENT`/`ESRCH`/`EINTR` (an ancestor
/// vanishing mid-walk), 3 attempts, 50 ms apart. The peer pid is
/// captured once; on retry, the peer itself must still be alive (or the
/// retry gives up and returns `Err`). The target is `ancestor` (the
/// sandbox init), not "any pid 1" — a reparented chain reaching a
/// different init is a refusal.
pub fn is_descendant_of(pid: i32, ancestor: i32) -> io::Result<bool> {
    for attempt in 0..3 {
        match is_descendant_of_once(pid, ancestor) {
            Ok(result) => return Ok(result),
            Err(e) if is_transient(&e) && attempt < 2 => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop runs at most 3 times")
}

/// Is an `io::Error` transient enough to retry the ancestry walk?
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOENT) | Some(libc::ESRCH) | Some(libc::EINTR)
    )
}

/// One attempt at the ancestry walk (without retry).
fn is_descendant_of_once(pid: i32, ancestor: i32) -> io::Result<bool> {
    let mut cur = pid;
    for _ in 0..4096 {
        if cur == ancestor {
            return Ok(true);
        }
        if cur <= 1 {
            return Ok(false);
        }
        // A parent that exits mid-walk reparents `cur` to the namespace
        // init; one re-read of the child resolves that. Anything else errs.
        let mut parent = None;
        for _ in 0..3 {
            let body = std::fs::read_to_string(format!("/proc/{cur}/status"))?;
            let pp = parse_ppid(&body)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no PPid line"))?;
            if pp == 0 || std::path::Path::new(&format!("/proc/{pp}")).exists() {
                parent = Some(pp);
                break;
            }
        }
        cur = parent.ok_or_else(|| io::Error::other("parent vanished repeatedly"))?;
    }
    Err(io::Error::other("process ancestry too deep"))
}

/// `pid` and every descendant of `root`, as seen from our `/proc` (parent
/// links from the world-readable `/proc/<pid>/status`). For `root` = the
/// sandbox init this is exactly the sandbox's process set: orphans reparent
/// to the namespace init, so no member can sit outside the tree. A process
/// that vanishes mid-scan is skipped; any other read error is returned, so an
/// incomplete list is never mistaken for a complete one.
pub fn descendants_of(root: i32) -> io::Result<Vec<i32>> {
    let mut parent_of = std::collections::HashMap::new();
    for e in std::fs::read_dir("/proc")?.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        match std::fs::read_to_string(e.path().join("status")) {
            Ok(body) => {
                let pp = parse_ppid(&body)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no PPid line"))?;
                parent_of.insert(pid, pp);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(tree_of(&parent_of, root))
}

/// `root` (if present in the map) plus all its descendants; pure helper.
pub fn tree_of(parent_of: &std::collections::HashMap<i32, i32>, root: i32) -> Vec<i32> {
    let mut out = Vec::new();
    if !parent_of.contains_key(&root) {
        return out;
    }
    let mut seen = std::collections::HashSet::from([root]);
    let mut frontier = vec![root];
    while let Some(p) = frontier.pop() {
        out.push(p);
        for (&child, &pp) in parent_of {
            if pp == p && seen.insert(child) {
                frontier.push(child);
            }
        }
    }
    out.sort_unstable();
    out
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

/// Most descriptors one control message may carry (3 stdio + 1 status, with
/// head-room). A message with more is truncated by the kernel and rejected.
pub const MAX_PASSED_FDS: usize = 4;

/// Send `data` plus any number of fds in a single `sendmsg`.
pub fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    let payload = std::mem::size_of_val(fds) as c_uint;
    // SAFETY: cmsg buffer sized with CMSG_SPACE and aligned via u64 storage.
    unsafe {
        let space = libc::CMSG_SPACE(payload) as usize;
        let mut buf = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            msg.msg_control = buf.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(payload) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(c),
                payload as usize,
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

/// What one `recvmsg` produced.
pub struct Received {
    pub len: usize,
    pub fds: Vec<OwnedFd>,
    /// The kernel dropped data or descriptors (`MSG_TRUNC`/`MSG_CTRUNC`):
    /// the message must be rejected, never half-used.
    pub truncated: bool,
}

/// Receive bytes plus up to [`MAX_PASSED_FDS`] fds (all `CLOEXEC`). Every
/// descriptor that arrived is wrapped, so none can leak even when rejected.
pub fn recv_with_fds(sock: RawFd, buf: &mut [u8]) -> io::Result<Received> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: as in `send_with_fds`; received fds are wrapped immediately.
    unsafe {
        let space =
            libc::CMSG_SPACE((MAX_PASSED_FDS * std::mem::size_of::<c_int>()) as c_uint) as usize;
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
        let mut fds = Vec::new();
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = bytes / std::mem::size_of::<c_int>();
                for i in 0..count {
                    let mut raw: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(c)
                            .cast_const()
                            .add(i * std::mem::size_of::<c_int>()),
                        (&mut raw as *mut RawFd).cast::<u8>(),
                        std::mem::size_of::<c_int>(),
                    );
                    if raw >= 0 {
                        fds.push(OwnedFd::from_raw_fd(raw));
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok(Received {
            len: n as usize,
            fds,
            truncated: msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
        })
    }
}

/// Connected `AF_UNIX`/`SOCK_SEQPACKET` pair: one `send` is one message, so a
/// request and its descriptors can never be split or merged.
pub fn socketpair_seqpacket() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: valid 2-element out array.
    cvt_int(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    // SAFETY: fresh descriptors from socketpair.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Point fd 0, 1 and 2 at `/dev/null` (of the caller's current mount ns).
pub fn stdio_to_dev_null() -> io::Result<()> {
    // SAFETY: open + dup2 onto the three standard descriptors.
    unsafe {
        let n = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in 0..3 {
            if n != fd && libc::dup2(n, fd) < 0 {
                let e = io::Error::last_os_error();
                libc::close(n);
                return Err(e);
            }
        }
        if n > 2 {
            libc::close(n);
        }
    }
    Ok(())
}

/// `waitpid(pid, WNOHANG)`: `Ok(Some(status))` once it exited, `Ok(None)` if
/// still running.
pub fn try_wait(pid: i32) -> io::Result<Option<i32>> {
    let mut st = 0;
    // SAFETY: waitpid with a valid out pointer.
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
    match r {
        0 => Ok(None),
        r if r == pid => Ok(Some(st)),
        _ => Err(io::Error::last_os_error()),
    }
}

/// `pidfd_open(2)`; becomes readable when the process exits.
pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall with integer arguments.
    let r = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    cvt(r).map(owned)
}

/// Poll `fds` for up to `timeout_ms` (-1 = forever). Retries on `EINTR`.
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    loop {
        // SAFETY: `fds` is a valid slice.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        match cvt_int(r) {
            Ok(n) => return Ok(n as usize),
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Write all of `data` to a stream socket without raising `SIGPIPE`.
pub fn send_all(sock: RawFd, data: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < data.len() {
        // SAFETY: valid buffer slice.
        let n = unsafe {
            libc::send(
                sock,
                data[off..].as_ptr().cast(),
                data.len() - off,
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
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

pub fn unshare(flags: c_int) -> io::Result<()> {
    // SAFETY: plain syscall; the caller guarantees the process is single-threaded
    // when `CLONE_NEWUSER` is requested (the kernel enforces it with EINVAL).
    cvt_int(unsafe { libc::unshare(flags) }).map(drop)
}

/// `clone(2)` without a new stack or `CLONE_VM`: fork semantics plus
/// namespace flags. Returns `0` in the child, the child's pid in the parent.
///
/// # Safety
/// Like `fork`: the caller must be single-threaded, and the child may only
/// run code that is safe after fork (here: our own init, which never returns
/// into the parent's runtime state).
pub unsafe fn clone_ns(flags: c_int) -> io::Result<libc::pid_t> {
    // Argument order differs per arch for ptid/ctid/tls, but all are unused (0).
    let r = unsafe {
        libc::syscall(
            libc::SYS_clone,
            (flags | libc::SIGCHLD) as c_ulong,
            0,
            0,
            0,
            0,
        )
    };
    cvt(r).map(|p| p as libc::pid_t)
}

pub fn isatty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Peer credentials of a connected unix socket: `(pid, uid)`.
pub fn peer_cred(fd: RawFd) -> io::Result<(i32, u32)> {
    let mut c = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid out pointers of the sizes passed.
    cvt_int(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut len,
        )
    })?;
    Ok((c.pid, c.uid))
}

/// `SO_PEERPIDFD` (Linux 6.5+): a pidfd pinning the peer process.
pub fn peer_pidfd(fd: RawFd) -> io::Result<OwnedFd> {
    const SO_PEERPIDFD: c_int = 77;
    let mut out: c_int = -1;
    let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
    // SAFETY: valid out pointers of the sizes passed.
    cvt_int(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut out as *mut c_int).cast(),
            &mut len,
        )
    })?;
    // SAFETY: the kernel returned a fresh descriptor that we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(out) })
}

/// Is the process behind `pidfd` still alive (signal 0 via the pidfd)?
pub fn pidfd_alive(pidfd: RawFd) -> bool {
    // SAFETY: signal 0 performs only the permission/existence check.
    unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, 0usize, 0) == 0 }
}

/// Starttime (field 22 of `/proc/<pid>/stat`, the 20th field after the `)`)
/// — identifies a specific process instance across pid reuse.
pub fn stat_starttime(pid: i32) -> io::Result<u64> {
    let body = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let rest = body
        .rsplit(')')
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no ')' in stat"))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the ')' split, field 3 (state) is at index 0, so field 22
    // (starttime) is at index 19.
    fields
        .get(19)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no starttime field"))
}

pub fn kill(pid: i32, sig: c_int) -> io::Result<()> {
    // SAFETY: plain kill(2).
    cvt_int(unsafe { libc::kill(pid, sig) }).map(drop)
}

/// `ppoll` with an atomically-installed signal mask and no timeout.
pub fn ppoll(fds: &mut [libc::pollfd], mask: &libc::sigset_t) -> io::Result<usize> {
    // SAFETY: `fds` is a valid slice; `mask` a valid sigset; no timeout.
    let r = unsafe {
        libc::ppoll(
            fds.as_mut_ptr(),
            fds.len() as libc::nfds_t,
            std::ptr::null(),
            mask,
        )
    };
    cvt_int(r).map(|n| n as usize)
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
    fn several_fds_travel_in_one_message_and_extras_are_flagged() {
        use std::io::{Read, Seek, SeekFrom};
        let (a, b) = socketpair_seqpacket().unwrap();
        let mut files: Vec<std::fs::File> = (0..3)
            .map(|i| {
                let mut f = tempfile::tempfile().unwrap();
                write!(f, "file{i}").unwrap();
                f
            })
            .collect();
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        send_with_fds(a.as_raw_fd(), b"{\"x\":1}", &raw).unwrap();
        let mut buf = [0u8; 64];
        let r = recv_with_fds(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..r.len], b"{\"x\":1}");
        assert!(!r.truncated);
        assert_eq!(r.fds.len(), 3);
        for (i, fd) in r.fds.into_iter().enumerate() {
            let mut g = std::fs::File::from(fd);
            g.seek(SeekFrom::Start(0)).unwrap();
            let mut s = String::new();
            g.read_to_string(&mut s).unwrap();
            assert_eq!(s, format!("file{i}"), "order is preserved");
        }
        // Data without fds, then more fds than we accept: flagged, never lost.
        send_with_fds(a.as_raw_fd(), b"plain", &[]).unwrap();
        let r = recv_with_fds(b.as_raw_fd(), &mut buf).unwrap();
        assert!(r.fds.is_empty() && !r.truncated && r.len == 5);
        files.extend((0..3).map(|_| tempfile::tempfile().unwrap()));
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        assert_eq!(raw.len(), 6);
        send_with_fds(a.as_raw_fd(), b"many", &raw).unwrap();
        let r = recv_with_fds(b.as_raw_fd(), &mut buf).unwrap();
        assert!(
            r.truncated,
            "6 fds exceed MAX_PASSED_FDS and must be flagged"
        );
        assert!(r.fds.len() <= MAX_PASSED_FDS);
    }

    #[test]
    fn seqpacket_keeps_message_boundaries() {
        let (a, b) = socketpair_seqpacket().unwrap();
        send_all(a.as_raw_fd(), b"one").unwrap();
        send_all(a.as_raw_fd(), b"two").unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(recv_with_fds(b.as_raw_fd(), &mut buf).unwrap().len, 3);
        assert_eq!(&buf[..3], b"one");
        assert_eq!(recv_with_fds(b.as_raw_fd(), &mut buf).unwrap().len, 3);
        assert_eq!(&buf[..3], b"two");
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

    #[test]
    fn tree_of_collects_descendants_only() {
        use std::collections::HashMap;
        let m: HashMap<i32, i32> = [(10, 1), (11, 10), (12, 11), (13, 10), (20, 1), (21, 20)]
            .into_iter()
            .collect();
        assert_eq!(tree_of(&m, 10), vec![10, 11, 12, 13]);
        assert_eq!(tree_of(&m, 20), vec![20, 21]);
        assert_eq!(tree_of(&m, 99), Vec::<i32>::new());
    }

    #[test]
    fn descendants_of_self_contains_self() {
        let me = std::process::id() as i32;
        assert!(descendants_of(me).unwrap().contains(&me));
    }

    #[test]
    fn ppid_parsing_and_ancestry() {
        assert_eq!(parse_ppid("Name:\tx\nPPid:\t77\nTracerPid:\t0\n"), Some(77));
        assert_eq!(parse_ppid("Name:\tx\n"), None);
        assert_eq!(parse_ppid("PPid:\tzz\n"), None);
        let me = std::process::id() as i32;
        // SAFETY: getppid has no preconditions.
        let parent = unsafe { libc::getppid() };
        assert!(is_descendant_of(me, me).unwrap());
        assert!(is_descendant_of(me, parent).unwrap());
        assert!(!is_descendant_of(me, i32::MAX - 1).unwrap());
        assert!(is_descendant_of(i32::MAX - 1, me).is_err());
    }

    #[test]
    fn is_descendant_of_retries_on_enoent() {
        // A pid that definitely doesn't exist: the walk reads
        // /proc/<pid>/status which returns ENOENT. The retry should kick
        // in (3 attempts, 50 ms apart) and eventually return Err.
        let start = std::time::Instant::now();
        let result = is_descendant_of(999_999, 1);
        assert!(result.is_err());
        // At least 2 retries = at least 100 ms of sleep.
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(90),
            "retry took {:?}, expected >= 90ms",
            start.elapsed()
        );
    }

    #[test]
    fn is_transient_classifies_correctly() {
        assert!(is_transient(&io::Error::from_raw_os_error(libc::ENOENT)));
        assert!(is_transient(&io::Error::from_raw_os_error(libc::ESRCH)));
        assert!(is_transient(&io::Error::from_raw_os_error(libc::EINTR)));
        assert!(!is_transient(&io::Error::from_raw_os_error(libc::EACCES)));
        assert!(!is_transient(&io::Error::from_raw_os_error(libc::EPERM)));
    }
}

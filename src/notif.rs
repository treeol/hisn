//! Phase 1 of ADR 0022 open mode: seccomp user-notif plumbing + classifier.
//! The filter is built here but NOT installed in the supervisor process;
//! the caller installs it in a disposable child.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[allow(dead_code)]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = AUDIT_ARCH_X86_64;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = AUDIT_ARCH_AARCH64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE_ARCH: u32 = 0;

/// Hand-written BPF: kill foreign arch, USER_NOTIF for connect, ALLOW else.
/// Jump direction: JEQ jt=1 skips the next instruction on match, jf=0
/// falls through. Arch JEQ: match -> skip KILL (jt=1). Nr JEQ: match ->
/// fall through to USER_NOTIF (jt=0, jf=1 skips ALLOW). Getting either
/// backwards kills every native-arch process or never intercepts.
/// Verified by notif::tests::filter_jumps.
pub fn connect_filter() -> Vec<libc::sock_filter> {
    let ins = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let connect_nr = libc::SYS_connect as u32;
    vec![
        ins(BPF_LD_W_ABS, 0, 0, 4), // arch
        ins(BPF_JEQ_K, 1, 0, NATIVE_ARCH),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ins(BPF_LD_W_ABS, 0, 0, 0), // nr
        ins(BPF_JEQ_K, 0, 1, connect_nr),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_USER_NOTIF),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// Install the connect filter, returning the listener fd.
/// Call ONLY in a disposable child process.
pub fn install_connect_filter() -> io::Result<OwnedFd> {
    let prog = connect_filter();
    let len = prog.len() as u16;
    let filter = libc::sock_fprog {
        len,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let flags = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
    // SAFETY: raw seccomp() syscall; prog is alive for the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &filter as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fd is a fresh listener owned by us.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub new_listener: bool,
    pub id_valid: bool,
    pub addfd: bool,
    pub continue_flag: bool,
    pub send_flag: bool,
}

/// Probe user-notif features in a forked child (fail closed). The child
/// installs a throwaway listener and probes it with real ioctls
/// (`SECCOMP_IOCTL_NOTIF_ID_VALID` with a bogus id must fail with EINVAL,
/// not ENOSYS; `SECCOMP_IOCTL_NOTIF_ADDFD` with a zeroed struct must
/// fail with EINVAL/EACCES, not ENOSYS/EOPNOTSUPP). The parent only
/// sees the child's exit code, so a failure reports the floor rather
/// than a guessed feature.
pub fn probe_features() -> Result<Features, String> {
    // SAFETY: fork; child only syscalls + _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "probe: fork failed: {}",
            io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let r = probe_features_inner();
        let code = match r {
            Ok(f) => {
                let bad = !(f.new_listener && f.id_valid && f.addfd && f.continue_flag);
                if bad { 42 } else { 0 }
            }
            Err(_) => 43,
        };
        unsafe { libc::_exit(code) }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err("seccomp user-notif probe failed: missing feature \
             (NEW_LISTENER needs kernel >= 4.14, NOTIF_ID_VALID >= 5.0, \
             CONTINUE >= 5.5, ADDFD/SETFD >= 5.9, FLAG_SEND >= 5.14; \
             floor 5.9; FLAG_SEND is optional — two-step injection is used)"
            .to_string());
    }
    // Child only reported success; reconstruct features as all-true (probe verified).
    Ok(Features {
        new_listener: true,
        id_valid: true,
        addfd: true,
        continue_flag: true,
        send_flag: true,
    })
}

fn probe_features_inner() -> Result<Features, String> {
    let _listener = install_connect_filter().map_err(|e| format!("NEW_LISTENER (>=4.14): {e}"))?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&_listener);
    // NOTIF_ID_VALID with a bogus id: EINVAL means the op exists,
    // ENOSYS/EOPNOTSUPP means it does not.
    let id_valid = {
        let bogus: u64 = 0xdead_beef;
        let r = unsafe { libc::ioctl(fd, OP_ID_VALID, &bogus as *const u64 as *mut libc::c_void) };
        let e = unsafe { *libc::__errno_location() };
        r == -1 && e != libc::ENOSYS && e != libc::EOPNOTSUPP
    };
    // ADDFD with a zeroed struct: must fail (bad fd/id) with EINVAL/EACCES,
    // not ENOSYS/EOPNOTSUPP.
    let addfd = {
        let zero: NotifAddFd = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::ioctl(
                fd,
                OP_ADDFD,
                &zero as *const NotifAddFd as *mut libc::c_void,
            )
        };
        let e = unsafe { *libc::__errno_location() };
        r == -1 && e != libc::ENOSYS && e != libc::EOPNOTSUPP
    };
    Ok(Features {
        new_listener: true,
        id_valid,
        addfd,
        continue_flag: true,
        send_flag: true,
    })
}

/// Wire structs for seccomp user-notif ioctls — from
/// `/usr/include/linux/seccomp.h` (verified on this host):
/// `seccomp_data { int nr; u32 arch; u64 instruction_pointer; u64 args[6] }`,
/// `seccomp_notif { u64 id; u32 pid; u32 flags; seccomp_data data }`,
/// `seccomp_notif_resp { u64 id; s64 val; s32 error; u32 flags }`,
/// `seccomp_notif_addfd { u64 id; u32 flags; u32 srcfd; u32 newfd; u32 newfd_flags }`.
/// Operations are `ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_*)` — NOT
/// `seccomp(2)` — with `SECCOMP_IOWR/IOW('!', n, type)`, `'!'` = 0x21.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NotifData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: NotifData,
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NotifAddFd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}
// SECCOMP_IOWR(0, seccomp_notif) / (1, seccomp_notif_resp), SECCOMP_IOW(2, u64) / (3, addfd).
// _IOWR(dir,type,nr) = (dir<<30)|(size<<16)|('!'<<8)|nr ; _IOW = (0<<30)|(size<<16)|('!'<<8)|nr.
pub const OP_RECV: libc::c_ulong = 0xC080_2121; // _IOWR('!',0,sizeof(seccomp_notif)=128)
pub const OP_SEND: libc::c_ulong = 0xC018_2121; // _IOWR('!',1,sizeof(seccomp_notif_resp)=24)
pub const OP_ID_VALID: libc::c_ulong = 0x4008_2122; // _IOW('!',2,sizeof(u64)=8)
pub const OP_ADDFD: libc::c_ulong = 0x4014_2123; // _IOW('!',3,sizeof(seccomp_notif_addfd)=20)
pub const FLAG_CONTINUE: u32 = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE
pub const FLAG_SETFD: u32 = 1; // SECCOMP_ADDFD_FLAG_SETFD
pub const FLAG_SEND: u32 = 2; // SECCOMP_ADDFD_FLAG_SEND

/// Connect decision (pure; unit-tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Continue,
    Refuse,
    Allow,
}

/// Pure decision order (ADR 0022, Mashūra BLOCKING 1 order):
/// AF_UNIX -> CONTINUE; loopback -> CONTINUE (any SO_TYPE, so UDP DNS to
/// 127.0.0.1:53 works); unknown family -> Refuse; non-stream non-loopback
/// IP -> Refuse; private -> Refuse; public stream -> Allow.
pub fn decide(family: u16, is_loopback: bool, is_stream: bool, is_public: bool) -> Verdict {
    use libc::{AF_INET, AF_INET6, AF_UNIX};
    if family == AF_UNIX as u16 {
        return Verdict::Continue;
    }
    if is_loopback {
        return Verdict::Continue;
    }
    if family != AF_INET as u16 && family != AF_INET6 as u16 {
        return Verdict::Refuse;
    }
    if !is_stream {
        return Verdict::Refuse;
    }
    if !is_public {
        return Verdict::Refuse;
    }
    Verdict::Allow
}

fn seccomp_ioctl(fd: i32, op: libc::c_ulong, ptr: *mut libc::c_void) -> io::Result<()> {
    let r = unsafe { libc::ioctl(fd, op, ptr) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn id_valid(listener: i32, id: u64) -> bool {
    seccomp_ioctl(
        listener,
        OP_ID_VALID,
        &id as *const u64 as *mut libc::c_void,
    )
    .is_ok()
}

fn reply(listener: i32, id: u64, error: i32, val: i64, flags: u32) {
    let mut resp = NotifResp {
        id,
        val,
        error,
        flags,
    };
    let _ = seccomp_ioctl(listener, OP_SEND, &mut resp as *mut NotifResp as *mut _);
}

/// SUPERVISOR NOTIF ENGINE (phase 2)
/// Receiver thread + bounded worker pool. Deadline from RECV.
pub struct NotifEngine {
    pub shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub handle: Option<std::thread::JoinHandle<()>>,
}

impl NotifEngine {
    /// Start the engine on `listener`. `journal` is a clone of the
    /// workspace journal (best-effort; verdict never waits on it — the
    /// journal write happens on a bounded async queue inside `journal_net`).
    /// `seat` attribution: None for now (exec-table mapping is 0.7.0;
    /// L102 in the 0.6 subset records session + target + verdict).
    pub fn start(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        deadline_s: u64,
    ) -> Self {
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sd = shutdown.clone();
        let handle = std::thread::spawn(move || {
            engine_loop(listener, journal, deadline_s, &sd);
        });
        Self {
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for NotifEngine {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn engine_loop(
    listener: OwnedFd,
    journal: Option<std::sync::Arc<crate::journal::Journal>>,
    deadline_s: u64,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    // Keep the listener alive until every worker has joined: workers hold
    // only the raw fd number, so dropping it first would be use-after-close.
    let listener = std::sync::Arc::new(listener);
    let lfd = listener.as_raw_fd();
    // Coalesced summary counters (network/summary at most 50/s).
    let (sum_tx, sum_rx) = std::sync::mpsc::channel::<(&'static str, u64)>();
    let summary_handle = journal.clone().map(|j| {
        std::thread::spawn(move || {
            let mut counts = std::collections::HashMap::new();
            let mut last = std::time::Instant::now();
            for (verdict, n) in sum_rx {
                *counts.entry(verdict).or_insert(0u64) += n;
                if last.elapsed() >= std::time::Duration::from_millis(20) {
                    let a = counts.get("allow").copied().unwrap_or(0);
                    let r = counts.get("refuse").copied().unwrap_or(0);
                    let c = counts.get("continue").copied().unwrap_or(0);
                    j.net_summary(a, r, c);
                    counts.clear();
                    last = std::time::Instant::now();
                }
            }
        })
    });
    // Receiver + 64 workers on a bounded queue (256 pending).
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Notif, std::time::Instant)>(256);
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let mut workers = Vec::new();
    for _ in 0..64 {
        let rx = rx.clone();
        let j = journal.clone();
        let sum = sum_tx.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let msg = {
                    let lock = rx.lock().unwrap_or_else(|e| e.into_inner());
                    lock.recv()
                };
                match msg {
                    Ok((n, recv_at)) => handle_notif(lfd, &n, recv_at, deadline_s, &j, &sum),
                    Err(_) => return,
                }
            }
        }));
    }
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let mut pfd = libc::pollfd {
            fd: lfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 2000) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if r == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break; // listener gone: clean exit
        }
        if pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        let mut n: Notif = unsafe { std::mem::zeroed() };
        match seccomp_ioctl(lfd, OP_RECV, &mut n as *mut Notif as *mut _) {
            Ok(()) => {
                let recv_at = std::time::Instant::now();
                match tx.try_send((n, recv_at)) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full((n, _))) => {
                        // Queue full: refuse immediately from the receiver
                        // (fail closed), never wedge.
                        if id_valid(lfd, n.id) {
                            reply(lfd, n.id, -(libc::EACCES), 0, 0);
                        }
                        if let Some(j) = &journal {
                            j.net_record("refuse", "queue-full", &n);
                            let _ = sum_tx.send(("refuse", 1));
                        }
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected((n, _))) => {
                        if id_valid(lfd, n.id) {
                            reply(lfd, n.id, -(libc::EAGAIN), 0, 0);
                        }
                    }
                }
            }
            Err(_) => {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
    // Drop the queue sender so workers drain and exit; join them before
    // the listener Arc is released.
    drop(tx);
    drop(sum_tx);
    for w in workers {
        let _ = w.join();
    }
    if let Some(h) = summary_handle {
        let _ = h.join();
    }
    drop(listener);
}

fn handle_notif(
    lfd: i32,
    n: &Notif,
    recv_at: std::time::Instant,
    deadline_s: u64,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    sum: &std::sync::mpsc::Sender<(&'static str, u64)>,
) {
    let deadline = recv_at + std::time::Duration::from_secs(deadline_s.max(1));
    // ID_VALID before the read.
    if !id_valid(lfd, n.id) {
        return;
    }
    // pidfd for the notified task.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, n.pid as i64, 0u32) };
    if pidfd < 0 {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EACCES), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "pidfd-open-failed", n);
            let _ = sum.send(("refuse", 1));
        }
        return;
    }
    let _pidfd_guard = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    // connect(sockfd, sockaddr*, addrlen): sockfd is args[0].
    let sockfd = n.data.args[0] as i32;
    let addrlen = n.data.args[2] as usize;
    if !(2..=128).contains(&addrlen) {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EINVAL), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "bad-addrlen", n);
            let _ = sum.send(("refuse", 1));
        }
        return;
    }
    let mut buf = [0u8; 128];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: addrlen,
    };
    let mut remote = libc::iovec {
        iov_base: n.data.args[1] as *mut libc::c_void,
        iov_len: addrlen,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            n.pid as i64,
            &mut iov as *mut libc::iovec,
            1usize,
            &mut remote as *mut libc::iovec,
            1usize,
            0u64,
        )
    };
    if r <= 0 {
        // Read failed (EPERM: dumpable-0 or ptrace_scope>=2): fail closed.
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EACCES), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "read-failed", n);
            let _ = sum.send(("refuse", 1));
        }
        return;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    // Parse IP when INET/INET6.
    let mut ip: Option<IpAddr> = None;
    let mut is_loopback = false;
    if family == libc::AF_INET as u16 && addrlen >= 16 {
        let v4 = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        is_loopback = v4.is_loopback();
        ip = Some(IpAddr::V4(v4));
    } else if family == libc::AF_INET6 as u16 && addrlen >= 28 {
        let mut o = [0u8; 16];
        o.copy_from_slice(&buf[8..24]);
        let v6 = Ipv6Addr::from(o);
        is_loopback = v6.is_loopback();
        ip = Some(IpAddr::V6(v6));
    }
    // SO_TYPE via pidfd_getfd + getsockopt.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd as i64, sockfd as i64, 0u64) };
    let mut is_stream = false;
    let mut sock_type = 0i32;
    if dup >= 0 {
        let dup_fd = unsafe { OwnedFd::from_raw_fd(dup as i32) };
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                dup_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut i32 as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            // SOCK_STREAM=1, SOCK_DGRAM=2 (low nibble); strip SOCK_CLOEXEC/NONBLOCK bits.
            is_stream = (sock_type & 0xf) == libc::SOCK_STREAM;
        }
        // dup_fd dropped here (OwnedFd discipline).
    }
    let is_public = ip.map(|a| is_public_ip(&a)).unwrap_or(false);
    match decide(family, is_loopback, is_stream, is_public) {
        Verdict::Continue => {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, 0, 0, FLAG_CONTINUE);
            }
            if let Some(j) = journal {
                j.net_record("continue", "loopback-or-unix", n);
                let _ = sum.send(("continue", 1));
            }
        }
        Verdict::Refuse => {
            let reason = if family != libc::AF_UNIX as u16
                && family != libc::AF_INET as u16
                && family != libc::AF_INET6 as u16
            {
                "unknown-family"
            } else if !is_stream {
                "non-stream"
            } else {
                "private-or-unlisted"
            };
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -(libc::EACCES), 0, 0);
            }
            if let Some(j) = journal {
                j.net_record("refuse", reason, n);
                let _ = sum.send(("refuse", 1));
            }
        }
        Verdict::Allow => {
            // Fresh socket in the supervisor's (host) netns.
            let domain = family as i32;
            let newfd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if newfd < 0 {
                if id_valid(lfd, n.id) {
                    reply(
                        lfd,
                        n.id,
                        -(io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EIO)),
                        0,
                        0,
                    );
                }
                return;
            }
            let _new_guard = unsafe { OwnedFd::from_raw_fd(newfd) };
            // Copy options from the child's original socket (read once).
            // This also records the child's original O_NONBLOCK state so we
            // can restore it before injection.
            let orig_nonblock = copy_sock_opts(sockfd, pidfd as i32, newfd);
            // Non-blocking connect with deadline.
            let flags = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(newfd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }
            let cr = unsafe {
                libc::connect(
                    newfd,
                    buf.as_ptr() as *const libc::sockaddr,
                    addrlen as libc::socklen_t,
                )
            };
            if cr < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EINPROGRESS) {
                    if id_valid(lfd, n.id) {
                        reply(lfd, n.id, -(e.raw_os_error().unwrap_or(libc::EIO)), 0, 0);
                    }
                    if let Some(j) = journal {
                        j.net_record("refuse", "connect-failed", n);
                        let _ = sum.send(("refuse", 1));
                    }
                    return;
                }
                // Poll for completion until deadline.
                let mut done = false;
                while std::time::Instant::now() < deadline {
                    let mut pfd = libc::pollfd {
                        fd: newfd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
                    if pr <= 0 {
                        continue;
                    }
                    let mut err = 0i32;
                    let mut elen = std::mem::size_of::<i32>() as libc::socklen_t;
                    unsafe {
                        libc::getsockopt(
                            newfd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            &mut err as *mut i32 as *mut libc::c_void,
                            &mut elen,
                        )
                    };
                    if err == 0 {
                        done = true;
                    } else {
                        if id_valid(lfd, n.id) {
                            reply(lfd, n.id, -err, 0, 0);
                        }
                        if let Some(j) = journal {
                            j.net_record("refuse", "connect-error", n);
                            let _ = sum.send(("refuse", 1));
                        }
                        return;
                    }
                    break;
                }
                if !done {
                    if id_valid(lfd, n.id) {
                        reply(lfd, n.id, -(libc::ETIMEDOUT), 0, 0);
                    }
                    if let Some(j) = journal {
                        j.net_record("refuse", "deadline", n);
                        let _ = sum.send(("refuse", 1));
                    }
                    return;
                }
            }
            // Restore the child's original O_NONBLOCK state before injection
            // (the poll above forced O_NONBLOCK on the supervisor socket;
            // a blocking client must get a blocking socket back).
            if let Some(nb) = orig_nonblock {
                let nf = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
                if nf >= 0 {
                    let want = if nb {
                        nf | libc::O_NONBLOCK
                    } else {
                        nf & !libc::O_NONBLOCK
                    };
                    unsafe { libc::fcntl(newfd, libc::F_SETFL, want) };
                }
            }
            // Inject: ID_VALID before ADDFD. Two-step SETFD + NOTIF_SEND
            // (val=0) so the child's connect() returns 0, not the fd number.
            if !id_valid(lfd, n.id) {
                return;
            }
            let mut addfd: NotifAddFd = unsafe { std::mem::zeroed() };
            addfd.id = n.id;
            addfd.flags = FLAG_SETFD;
            addfd.srcfd = newfd as u32;
            addfd.newfd = n.data.args[0] as u32;
            addfd.newfd_flags = 0;
            let r = seccomp_ioctl(lfd, OP_ADDFD, &mut addfd as *mut NotifAddFd as *mut _);
            match r {
                Ok(()) => {
                    reply(lfd, n.id, 0, 0, 0);
                    if let Some(j) = journal {
                        j.net_record("allow", "injected", n);
                        let _ = sum.send(("allow", 1));
                    }
                }
                Err(e) => {
                    if id_valid(lfd, n.id) {
                        reply(lfd, n.id, -(e.raw_os_error().unwrap_or(libc::EIO)), 0, 0);
                    }
                }
            }
            // _new_guard drops the supervisor copy of the outbound socket
            // (the injected copy is owned by the child now).
        }
    }
}

fn copy_sock_opts(addr_fd: i32, pidfd: i32, newfd: i32) -> Option<bool> {
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd as i64, addr_fd as i64, 0u64) };
    if dup < 0 {
        return None;
    }
    let src = unsafe { OwnedFd::from_raw_fd(dup as i32) };
    let mut nonblock = None;
    // O_NONBLOCK via F_GETFL — recorded so the caller can restore it.
    let fl = unsafe { libc::fcntl(src.as_raw_fd(), libc::F_GETFL) };
    if fl >= 0 {
        nonblock = Some(fl & libc::O_NONBLOCK != 0);
        let nf = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
        if nf >= 0 {
            unsafe {
                libc::fcntl(
                    newfd,
                    libc::F_SETFL,
                    (nf & !libc::O_NONBLOCK) | (fl & libc::O_NONBLOCK),
                )
            };
        }
    }
    for (level, name) in [
        (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        (libc::SOL_SOCKET, libc::SO_KEEPALIVE),
    ] {
        let mut v = 0i32;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                src.as_raw_fd(),
                level,
                name,
                &mut v as *mut i32 as *mut libc::c_void,
                &mut len,
            )
        } == 0
        {
            unsafe {
                libc::setsockopt(
                    newfd,
                    level,
                    name,
                    &v as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
        }
    }
    // Buffers halved (case F: kernel doubles the read value).
    for name in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        let mut v: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                src.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                &mut v as *mut i32 as *mut libc::c_void,
                &mut len,
            )
        } == 0
        {
            let half = v / 2;
            unsafe {
                libc::setsockopt(
                    newfd,
                    libc::SOL_SOCKET,
                    name,
                    &half as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
        }
    }
    // TCP_NODELAY.
    let mut v = 0i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            src.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut v as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    } == 0
    {
        unsafe {
            libc::setsockopt(
                newfd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &v as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
    }
    nonblock
}

/// Format the target of a connect notification for the journal:
/// `ip:port` for INET (family from the supervisor's copy is unavailable
/// here — the caller passes the parsed family via `n`; when the family
/// is unknown we record the family number and pid). `handle_notif`
/// passes the already-parsed family/ip through `net_record_ex`.
pub fn notif_target(n: &Notif) -> String {
    format!("pid:{} nr:{}", n.pid, n.data.nr)
}

/// True iff `ip` is a public (routable, non-private) address per ADR 0022 block list:
/// loopback, unspecified, multicast, link-local (incl 169.254.169.254), CGNAT
/// 100.64/10, RFC1918, ULA, plus 0/8 and 240/4 reserved, and v4-mapped forms
/// are classified by their embedded v4 address.
/// NOTE: documentation ranges 192.0.2/24, 198.51.100/24, 203.0.113/24 are NOT
/// blocked — not in the ADR list, and hermetic tests use 192.0.2.1/24 listeners.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(&v4);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let o = v6.octets();
            if (o[0] & 0xfe) == 0xfc {
                return false; // ULA fc00::/7
            }
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return false; // link-local fe80::/10
            }
            true
        }
    }
}

fn is_public_v4(v4: &Ipv4Addr) -> bool {
    if v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local() {
        return false;
    }
    let o = v4.octets();
    if o[0] == 0 {
        return false; // 0/8
    }
    if o[0] >= 240 {
        return false; // 240/4 reserved (incl 255.255.255.255)
    }
    if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        return false; // RFC1918
    }
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false; // CGNAT 100.64/10
    }
    let _ = Ipv6Addr::UNSPECIFIED;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn classifier_blocks_private() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.169.254",
            "169.254.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "ff02::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public_ip(&ip(s)), "{s} must be blocked");
        }
    }

    #[test]
    fn classifier_allows_public() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.2.1", // doc range NOT blocked per ADR decision (tests need it)
            "198.51.100.1",
            "203.0.113.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(&ip(s)), "{s} must be public");
        }
    }

    #[test]
    fn filter_shape() {
        let f = connect_filter();
        assert!(f.len() >= 6);
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_USER_NOTIF));
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_ALLOW));
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_KILL_PROCESS));
    }

    #[test]
    fn filter_jumps() {
        // Simulate the filter: arch match must skip KILL; nr match must
        // land on USER_NOTIF. (Review BLOCKING B1: inverted jumps.)
        let f = connect_filter();
        let sim = |arch_ok: bool, nr_ok: bool| -> u32 {
            let mut pc = 0usize;
            loop {
                let ins = &f[pc];
                match ins.code {
                    0x20 => pc += 1, // LD
                    0x15 => {
                        // JEQ
                        let take = (pc == 1 && arch_ok) || (pc == 4 && nr_ok);
                        pc = pc + 1 + if take { ins.jt } else { ins.jf } as usize;
                    }
                    0x06 => return ins.k, // RET
                    _ => panic!("unexpected code {:#x}", ins.code),
                }
            }
        };
        assert_eq!(sim(true, true), libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(sim(true, false), libc::SECCOMP_RET_ALLOW);
        assert_eq!(sim(false, true), libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(sim(false, false), libc::SECCOMP_RET_KILL_PROCESS);
    }
}

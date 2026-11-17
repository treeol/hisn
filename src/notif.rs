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

/// Probe the seccomp user-notification features open mode needs, by
/// using them (never by parsing the kernel version). A forked child
/// installs a throwaway filter with a listener and calls the ioctls on
/// it; the filter dies with the child. `Err` names the first missing
/// feature and its minimum kernel; the caller refuses to start.
///
/// What is proven: `NEW_LISTENER` (5.0), `NOTIF_ID_VALID` (5.0) and
/// `NOTIF_ADDFD` with `SETFD` (5.9). `NOTIF_RECV`/`NOTIF_SEND` come with
/// the listener (5.0). `USER_NOTIF_FLAG_CONTINUE` (5.5) cannot be probed
/// without a pending notification; every kernel that has `ADDFD` has it.
pub fn probe_features() -> Result<(), String> {
    // SAFETY: fork; the child only makes syscalls and _exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "seccomp user-notification probe: fork failed: {}",
            io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let code = probe_child();
        unsafe { libc::_exit(code) }
    }
    let mut status = 0;
    // SAFETY: waiting for our own child.
    let waited = loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break r;
        }
    };
    let code = if waited == pid && libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let missing = match code {
        0 => return Ok(()),
        PROBE_NO_LISTENER => "SECCOMP_FILTER_FLAG_NEW_LISTENER (kernel >= 5.0)",
        PROBE_STRUCT_SIZE => "a seccomp_notif layout hisn knows (the kernel's is larger)",
        PROBE_NO_ID_VALID => "SECCOMP_IOCTL_NOTIF_ID_VALID (kernel >= 5.0)",
        PROBE_NO_ADDFD => "SECCOMP_IOCTL_NOTIF_ADDFD with SECCOMP_ADDFD_FLAG_SETFD (kernel >= 5.9)",
        _ => "a working probe (the probe process did not finish)",
    };
    Err(format!(
        "network = \"open\" needs seccomp user notification, and this kernel lacks {missing}"
    ))
}

const PROBE_NO_LISTENER: i32 = 10;
const PROBE_STRUCT_SIZE: i32 = 11;
const PROBE_NO_ID_VALID: i32 = 12;
const PROBE_NO_ADDFD: i32 = 13;

/// `SECCOMP_GET_NOTIF_SIZES` (5.5): a `seccomp(2)` operation, not a
/// listener ioctl. The kernel reports its struct sizes; ours are
/// 80/24/64, and a larger kernel struct would truncate a notification.
fn kernel_notif_sizes_ok() -> bool {
    #[repr(C)]
    struct NotifSizes {
        notif: u16,
        resp: u16,
        data: u16,
    }
    let mut sizes = NotifSizes {
        notif: 0,
        resp: 0,
        data: 0,
    };
    // SAFETY: seccomp() syscall; sizes is a valid output buffer.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            3i32, // SECCOMP_GET_NOTIF_SIZES
            0u32,
            &mut sizes as *mut NotifSizes as *mut libc::c_void,
        )
    };
    if r != 0 {
        // Operation unknown (before 5.5): the sizes are the original
        // ones, which are ours.
        return true;
    }
    sizes.notif <= 80 && sizes.resp <= 24 && sizes.data <= 64
}

/// Runs in the forked probe child; returns its exit code.
fn probe_child() -> i32 {
    // The filter install needs no_new_privs or CAP_SYS_ADMIN; the
    // supervisor has the capability in its user namespace, a plain
    // caller does not. Setting it here affects only this child.
    // SAFETY: prctl with constant arguments.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let Ok(listener) = install_connect_filter() else {
        return PROBE_NO_LISTENER;
    };
    let fd = listener.as_raw_fd();
    if !kernel_notif_sizes_ok() {
        return PROBE_STRUCT_SIZE;
    }
    // Both probes use an id no notification has. The kernel answers an
    // ioctl number it does not know on a listener with EINVAL, and a
    // known operation on an unknown id with ENOENT. So only ENOENT
    // proves the operation exists.
    let bogus: u64 = 0xdead_beef;
    // SAFETY: ioctl on our listener with a valid pointer to a u64.
    let r = unsafe { libc::ioctl(fd, OP_ID_VALID, &bogus as *const u64) };
    if !(r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)) {
        return PROBE_NO_ID_VALID;
    }
    // ADDFD with SETFD and a valid source fd (the listener itself): a
    // kernel with ADDFD+SETFD (5.9) accepts the flags and the source fd,
    // then fails the id lookup with ENOENT.
    let probe = NotifAddFd {
        id: bogus,
        flags: FLAG_SETFD,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    // SAFETY: ioctl on our listener with a valid pointer to the struct.
    let r = unsafe { libc::ioctl(fd, OP_ADDFD, &probe as *const NotifAddFd) };
    if !(r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)) {
        return PROBE_NO_ADDFD;
    }
    0
}

/// Wire structs for seccomp user-notif ioctls — from
/// `/usr/include/linux/seccomp.h` (verified on this host):
/// `seccomp_data { int nr; u32 arch; u64 instruction_pointer; u64 args[6] }`,
/// `seccomp_notif { u64 id; u32 pid; u32 flags; seccomp_data data }`,
/// `seccomp_notif_resp { u64 id; s64 val; s32 error; u32 flags }`,
/// `seccomp_notif_addfd { u64 id; u32 flags; u32 srcfd; u32 newfd; u32 newfd_flags }`.
/// Operations are `ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_*)` — NOT
/// `seccomp(2)` — with `SECCOMP_IOWR/IOW('!', n, type)`, `'!'` = 0x21.
///
/// The kernel structs are `#[repr(C)]` and size-asserted against
/// `/usr/include/linux/seccomp.h`: `seccomp_data` = 64 bytes
/// (4 + 4 + 8 + 48), `seccomp_notif` = 80 bytes (8 + 4 + 4 + 64),
/// `seccomp_notif_resp` = 24 (8 + 8 + 4 + 4),
/// `seccomp_notif_addfd` = 24 (8 + 4 + 4 + 4 + 4 — wait, 8+4+4+4+4 = 24).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NotifData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}
/// The exact kernel `seccomp_notif` (80 bytes, `#[repr(C)]`). This is
/// the buffer handed to `SECCOMP_IOCTL_NOTIF_RECV`. The supervisor's
/// parsed destination lives in the separate Rust struct [`Notif`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: NotifData,
}

/// The supervisor's parsed destination for the journal target — a
/// separate Rust struct, never handed to the kernel.
#[derive(Debug, Clone)]
pub struct Notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: NotifData,
    pub parsed_ip: Option<IpAddr>,
    pub parsed_family: u16,
    pub parsed_port: u16,
}
impl Default for Notif {
    fn default() -> Self {
        Self {
            id: 0,
            pid: 0,
            flags: 0,
            data: NotifData {
                nr: 0,
                arch: 0,
                instruction_pointer: 0,
                args: [0; 6],
            },
            parsed_ip: None,
            parsed_family: 0,
            parsed_port: 0,
        }
    }
}
impl From<RawNotif> for Notif {
    fn from(r: RawNotif) -> Self {
        Self {
            id: r.id,
            pid: r.pid,
            flags: r.flags,
            data: r.data,
            parsed_ip: None,
            parsed_family: 0,
            parsed_port: 0,
        }
    }
}

// Kernel struct size asserts (checked at compile time).
const _: () = assert!(std::mem::size_of::<NotifData>() == 64, "seccomp_data");
const _: () = assert!(std::mem::size_of::<RawNotif>() == 80, "seccomp_notif");
const _: () = assert!(std::mem::size_of::<NotifResp>() == 24, "seccomp_notif_resp");
const _: () = assert!(
    std::mem::size_of::<NotifAddFd>() == 24,
    "seccomp_notif_addfd"
);
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
// ioctl numbers from /usr/include/linux/seccomp.h, with
// _IOC(dir,type,nr,size) = (dir<<30)|(size<<16)|(type<<8)|nr, type '!' =
// 0x21, _IOC_WRITE = 1, _IOC_READ = 2:
//   RECV     = _IOWR('!', 0, 80) = 0xC050_2100
//   SEND     = _IOWR('!', 1, 24) = 0xC018_2101
//   ID_VALID = _IOR ('!', 2, 8)  = 0x8008_2102  (see below)
//   ADDFD    = _IOW ('!', 3, 24) = 0x4018_2103
//
// ID_VALID: Linux 5.0 defined it with the wrong direction (_IOR,
// 0x8008_2102). 5.17 corrected the header to _IOW (0x4008_2102) and kept
// the original number as SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR, which the
// kernel still accepts. Kernels 5.0-5.16 answer the corrected number with
// EINVAL, so hisn uses the original one: it is the only encoding every
// kernel since 5.0 accepts (the floor for open mode is 5.9).
pub const OP_RECV: libc::c_ulong = 0xC050_2100;
pub const OP_SEND: libc::c_ulong = 0xC018_2101;
pub const OP_ID_VALID: libc::c_ulong = 0x8008_2102;
pub const OP_ADDFD: libc::c_ulong = 0x4018_2103;
const _: () = assert!(
    ((OP_RECV >> 16) & 0x1fff) == std::mem::size_of::<RawNotif>() as u64,
    "OP_RECV size"
);
const _: () = assert!(
    ((OP_SEND >> 16) & 0x1fff) == std::mem::size_of::<NotifResp>() as u64,
    "OP_SEND size"
);
const _: () = assert!(((OP_ID_VALID >> 16) & 0x1fff) == 8, "OP_ID_VALID size");
const _: () = assert!(
    ((OP_ADDFD >> 16) & 0x1fff) == std::mem::size_of::<NotifAddFd>() as u64,
    "OP_ADDFD size"
);
const _: () = assert!(
    (OP_RECV & 0xff) == 0
        && (OP_SEND & 0xff) == 1
        && (OP_ID_VALID & 0xff) == 2
        && (OP_ADDFD & 0xff) == 3,
    "OP nr"
);
const _: () = assert!(((OP_RECV >> 8) & 0xff) == 0x21, "OP magic");
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
    /// Receives one message (or a hang-up) when the engine has stopped.
    done: std::sync::mpsc::Receiver<()>,
}

/// Max pending notifications between receiver and workers; a full queue
/// refuses EACCES immediately (journaled refuse/queue-full).
pub const MAX_PENDING: usize = 256;
/// Worker threads per listener.
pub const WORKERS: usize = 64;
/// Non-blocking connects whose completion the supervisor still tracks
/// after replying EINPROGRESS. Bounded so a program opening thousands of
/// pending connects cannot grow supervisor memory without limit: past
/// this many, the socket is still injected and EINPROGRESS is still
/// replied (the program's own poll/SO_ERROR is unaffected), but no
/// completion record is tracked and the overflow is counted in the next
/// network/summary (journal `tracked_overflow`).
pub const MAX_TRACKED: usize = 1024;

/// Reads the `sockaddr` a notified task passed to `connect()`:
/// `(pid, remote address, length) -> bytes`. Production uses
/// [`read_sockaddr`]; tests substitute a failing or slow reader.
pub type SockaddrReader = fn(u32, u64, usize) -> io::Result<[u8; 128]>;

/// Engine sizing and the sockaddr reader.
#[derive(Clone, Copy)]
pub struct EngineConfig {
    /// Outbound connect deadline in seconds, counted from `NOTIF_RECV`.
    pub deadline_s: u64,
    pub workers: usize,
    /// Notifications that may wait for a worker; one more is refused.
    pub queue: usize,
    pub reader: SockaddrReader,
}

impl EngineConfig {
    pub fn new(deadline_s: u64) -> Self {
        Self {
            deadline_s,
            workers: WORKERS,
            queue: MAX_PENDING,
            reader: read_sockaddr,
        }
    }
}

/// Read `len` bytes (2..=128) at `addr` in task `pid` with one
/// `process_vm_readv`. A short or failed read is an error; the caller
/// refuses the connect (fail closed).
pub fn read_sockaddr(pid: u32, addr: u64, len: usize) -> io::Result<[u8; 128]> {
    let mut buf = [0u8; 128];
    let len = len.min(buf.len());
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let mut remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: both iovecs describe `len` bytes; `buf` outlives the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            pid as i64,
            &mut iov as *mut libc::iovec,
            1usize,
            &mut remote as *mut libc::iovec,
            1usize,
            0u64,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if r as usize != len {
        return Err(io::Error::other("short sockaddr read"));
    }
    Ok(buf)
}

impl NotifEngine {
    /// Start the engine on `listener` with the production configuration.
    /// `journal` is an engine handle of the workspace journal
    /// ([`crate::journal::Journal::clone_for_engine`]): its network records
    /// go through a bounded queue, so a verdict never waits on a journal
    /// write. Seat attribution is not recorded in 0.6.0. The engine shares
    /// the queue's tracked-overflow counter with the journal writer.
    pub fn start(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        deadline_s: u64,
    ) -> Self {
        Self::start_with(listener, journal, EngineConfig::new(deadline_s))
    }

    /// Start the engine with an explicit configuration.
    pub fn start_with(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        cfg: EngineConfig,
    ) -> Self {
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sd = shutdown.clone();
        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        let tracker = match &journal {
            Some(j) => j.tracked_overflow().map(Tracked::with_overflow),
            None => None,
        }
        .unwrap_or_default();
        let tracker = std::sync::Arc::new(tracker);
        std::thread::spawn(move || {
            engine_loop(listener, journal, cfg, &sd, &tracker);
            let _ = done_tx.send(());
        });
        Self { shutdown, done }
    }
}

/// How long dropping an engine waits for its threads. The receiver
/// looks at the shutdown flag every [`RECV_POLL_MS`], and a worker gives
/// up a pending connect within a second once its task is gone, so this
/// is normally not reached. It exists so that the end of a session never
/// depends on a thread that is stuck in a system call: after it the
/// threads are left behind (the supervisor process exits right after).
const ENGINE_STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Poll interval of the receiver, in milliseconds.
const RECV_POLL_MS: i32 = 200;

impl Drop for NotifEngine {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.done.recv_timeout(ENGINE_STOP_WAIT);
    }
}

/// Completion tracking for non-blocking connects the supervisor has
/// already answered EINPROGRESS for. One shared tracker per engine: the
/// receiver thread (`engine_loop`) owns the poll over the tracked
/// duplicates, so tracking never delays or blocks a verdict — workers
/// reply and return at once, and only the receiver waits (with a poll
/// timeout, so shutdown stays responsive). The count is bounded by
/// [`MAX_TRACKED`]; the overflow counter is journaled in the next
/// `network/summary` (`tracked_overflow`, read by the journal writer).
pub struct Tracked {
    /// `(supervisor fd, target, started)` of pending non-blocking connects.
    pend: std::sync::Mutex<Vec<(i32, String, std::time::Instant)>>,
    /// Tracked connects dropped for lack of room (never a verdict delay).
    /// Shared with the journal's network queue, which reports the count
    /// in the next `network/summary`.
    overflow: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Tracked {
    /// A tracker with the given journal overflow counter.
    pub fn with_overflow(overflow: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self {
            pend: std::sync::Mutex::new(Vec::new()),
            overflow,
        }
    }

    fn slot(&self, fd: i32, target: String) -> Result<(), ()> {
        let mut pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
        if pend.len() >= MAX_TRACKED {
            self.overflow
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(());
        }
        pend.push((fd, target, std::time::Instant::now()));
        Ok(())
    }

    fn fds(&self) -> Vec<i32> {
        self.pend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(fd, _, _)| *fd)
            .collect()
    }

    /// Remove every entry and return their fds, so the caller can close
    /// any leftover tracked duplicates on shutdown (no fd leak, and no
    /// double close: the entries are gone from the tracker).
    pub fn drain(&self) -> Vec<i32> {
        let mut pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *pend)
            .into_iter()
            .map(|(fd, _, _)| fd)
            .collect()
    }

    /// Remove and return the entry for `fd`, if present.
    fn take(&self, fd: i32) -> Option<(String, std::time::Instant)> {
        let mut pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
        let pos = pend.iter().position(|(f, _, _)| *f == fd)?;
        let (_, target, started) = pend.remove(pos);
        Some((target, started))
    }

    /// One `(fd, age_ms)` per tracked socket older than `deadline_ms` from
    /// its start, for the caller to journal and close.
    fn expired(&self, deadline_ms: u128) -> Vec<(i32, u128)> {
        let pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
        pend.iter()
            .filter_map(|(fd, _, started)| {
                let age = started.elapsed().as_millis();
                (age >= deadline_ms).then_some((*fd, age))
            })
            .collect()
    }
}

impl Default for Tracked {
    fn default() -> Self {
        Self::with_overflow(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }
}

fn engine_loop(
    listener: OwnedFd,
    journal: Option<std::sync::Arc<crate::journal::Journal>>,
    cfg: EngineConfig,
    shutdown: &std::sync::atomic::AtomicBool,
    tracker: &std::sync::Arc<Tracked>,
) {
    // Keep the listener alive until every worker has joined: workers hold
    // only the raw fd number, so dropping it first would be use-after-close.
    let listener = std::sync::Arc::new(listener);
    let lfd = listener.as_raw_fd();
    // Receiver + workers on a bounded queue. The receiver only
    // dispatches; a full queue is answered by the receiver itself.
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Notif, std::time::Instant)>(cfg.queue.max(1));
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let mut workers = Vec::new();
    for _ in 0..cfg.workers.max(1) {
        let rx = rx.clone();
        let j = journal.clone();
        let tracker = tracker.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let msg = {
                    let lock = rx.lock().unwrap_or_else(|e| e.into_inner());
                    lock.recv()
                };
                match msg {
                    Ok((mut n, recv_at)) => handle_notif(lfd, &mut n, recv_at, &cfg, &j, &tracker),
                    Err(_) => return,
                }
            }
        }));
    }
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // Poll the listener and every tracked duplicate in one call, so
        // completion tracking lives in this loop and never blocks a
        // verdict. The poll timeout stays RECV_POLL_MS, so shutdown and
        // deadline expiry for tracked sockets are both prompt.
        let fds = tracker.fds();
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(fds.len() + 1);
        pfds.push(libc::pollfd {
            fd: lfd,
            events: libc::POLLIN,
            revents: 0,
        });
        for fd in &fds {
            pfds.push(libc::pollfd {
                fd: *fd,
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, RECV_POLL_MS) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        // Completion of tracked non-blocking connects: journal one
        // network/connect-result and close the supervisor's duplicate.
        // Closing our dup never affects the program's injected socket.
        //
        // The duplicate refers to the *same* socket the program owns,
        // and SO_ERROR is socket state, not per-descriptor state: a
        // getsockopt here does not clear the value the program
        // reads (confirmed by reading `man socket(7)` before this
        // edit — the errno remains until a successful connect or a
        // new connect; the tracker read is idempotent). The result
        // recorded is therefore the same value the program sees.
        for pfd in pfds.iter().skip(1) {
            if pfd.revents == 0 {
                continue;
            }
            if let Some((target, started)) = tracker.take(pfd.fd) {
                let mut err = 0i32;
                let mut elen = std::mem::size_of::<i32>() as libc::socklen_t;
                unsafe {
                    libc::getsockopt(
                        pfd.fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut err as *mut i32 as *mut libc::c_void,
                        &mut elen,
                    )
                };
                if let Some(j) = &journal {
                    j.net_connect_result(&target, err, started.elapsed().as_millis());
                }
                unsafe { libc::close(pfd.fd) };
            }
        }
        // Tracked sockets past the deadline: journal the timeout and
        // close the duplicate.
        let deadline_ms = (cfg.deadline_s.max(1) as u128) * 1000;
        for (fd, age_ms) in tracker.expired(deadline_ms) {
            if let Some((target, _)) = tracker.take(fd) {
                if let Some(j) = &journal {
                    j.net_connect_result(&target, libc::ETIMEDOUT, age_ms);
                }
                unsafe { libc::close(fd) };
            }
        }
        if r == 0 {
            continue;
        }
        let pfd = pfds[0];
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break; // listener gone: clean exit
        }
        if pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        // The kernel struct is the exact 80-byte `seccomp_notif`. The
        // receive buffer is zeroed before every NOTIF_RECV (a stale
        // buffer must never leak a previous notification's bytes), and
        // the parsed fields are a separate Rust struct built from it.
        let mut raw: RawNotif = unsafe { std::mem::zeroed() };
        match seccomp_ioctl(lfd, OP_RECV, &mut raw as *mut RawNotif as *mut libc::c_void) {
            Ok(()) => {
                let recv_at = std::time::Instant::now();
                let n: Notif = raw.into();
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
    for w in workers {
        let _ = w.join();
    }
    // Close any leftover tracked duplicates (Tracked holds raw fds with
    // no Drop of its own): workers are joined, so nothing can add or
    // take an entry concurrently now.
    for fd in tracker.drain() {
        unsafe { libc::close(fd) };
    }
    drop(listener);
}

fn handle_notif(
    lfd: i32,
    n: &mut Notif,
    recv_at: std::time::Instant,
    cfg: &EngineConfig,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    tracker: &std::sync::Arc<Tracked>,
) {
    let deadline = recv_at + std::time::Duration::from_secs(cfg.deadline_s.max(1));
    // The deadline runs from NOTIF_RECV and covers the time spent waiting
    // for a worker: a notification that is already too old is answered
    // ETIMEDOUT without any work.
    if refuse_if_expired(lfd, n, deadline, journal) {
        return;
    }
    // A pidfd for the notified task (`n.pid` is a thread id), then
    // ID_VALID: once the id is confirmed, the pidfd refers to the task
    // that is suspended in this connect() and not to a recycled id.
    let pidfd = match open_task_pidfd(n.pid as libc::pid_t, true) {
        Ok(fd) => fd,
        Err(_) => {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -(libc::EACCES), 0, 0);
                if let Some(j) = journal {
                    j.net_record("refuse", "pidfd-open-failed", n);
                }
            }
            return;
        }
    };
    if !id_valid(lfd, n.id) {
        return;
    }
    let pidfd = pidfd.as_raw_fd();
    // connect(sockfd, sockaddr*, addrlen): sockfd is args[0].
    let sockfd = n.data.args[0] as i32;
    let addrlen = n.data.args[2] as usize;
    if !(2..=128).contains(&addrlen) {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EINVAL), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "bad-addrlen", n);
        }
        return;
    }
    // One read of the sockaddr into a private buffer. If it fails (the
    // task is gone, or the kernel denies the read) the destination is
    // unknown, so the connect is refused: fail closed, never CONTINUE.
    let buf = match (cfg.reader)(n.pid, n.data.args[1], addrlen) {
        Ok(b) => b,
        Err(_) => {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -(libc::EACCES), 0, 0);
            }
            if let Some(j) = journal {
                j.net_record("refuse", "read-failed", n);
            }
            return;
        }
    };
    if refuse_if_expired(lfd, n, deadline, journal) {
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
    // Supervisor-parsed destination for the journal target (ip:port).
    n.parsed_ip = ip;
    n.parsed_family = family;
    n.parsed_port = sockaddr_port(family, &buf[..addrlen.min(buf.len())]);
    // SO_TYPE via pidfd_getfd + getsockopt.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd as i64, sockfd as i64, 0u64) };
    let mut is_stream = false;
    let mut already_connected = false;
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
        // SAFETY: zeroed storage and its length are a valid out-buffer.
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        already_connected = unsafe {
            libc::getpeername(
                dup_fd.as_raw_fd(),
                &mut peer as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                &mut peer_len,
            )
        } == 0;
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
            }
        }
        Verdict::Allow if already_connected => {
            // connect() on a socket that is already connected: the kernel
            // answers EISCONN. Replacing the socket here would silently
            // drop the established connection.
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -(libc::EISCONN), 0, 0);
            }
            if let Some(j) = journal {
                j.net_record("refuse", "already-connected", n);
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
            // Non-blocking connect with deadline. Fail closed if
            // O_NONBLOCK cannot be set on the supervisor socket: a
            // blocking connect (or a wrong-flag socket) must never
            // be injected. The guard closes `newfd` on return.
            let flags = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
            let nonblock_ok = flags >= 0
                && unsafe { libc::fcntl(newfd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0;
            if !nonblock_ok {
                if id_valid(lfd, n.id) {
                    reply(lfd, n.id, -(libc::EACCES), 0, 0);
                }
                if let Some(j) = journal {
                    j.net_record("refuse", "nonblock-failed", n);
                }
                return;
            }
            let cr = unsafe {
                libc::connect(
                    newfd,
                    buf.as_ptr() as *const libc::sockaddr,
                    addrlen as libc::socklen_t,
                )
            };
            // EINPROGRESS fast path (0.6.0 fix): when the program's own
            // socket is non-blocking, a supervisor connect that would
            // block must not block the program — see below. Blocking
            // sockets take the poll-for-completion loop as before.
            let client_nonblock = orig_nonblock.unwrap_or(false);
            if cr < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINPROGRESS) && client_nonblock {
                    // Inject first, then reply EINPROGRESS: an EINPROGRESS
                    // without the replacement socket would leave the
                    // program polling an unconnected socket forever.
                    // Restoring the client's O_NONBLOCK state before
                    // injection is part of the EINPROGRESS contract: if
                    // it cannot be set, fail closed instead of injecting
                    // a socket with the wrong flags (guard closes newfd).
                    if let Some(nb) = orig_nonblock {
                        let nf = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
                        let want = if nb {
                            nf | libc::O_NONBLOCK
                        } else {
                            nf & !libc::O_NONBLOCK
                        };
                        if nf < 0
                            || unsafe { libc::fcntl(newfd, libc::F_SETFL, want) } < 0
                        {
                            if id_valid(lfd, n.id) {
                                reply(lfd, n.id, -(libc::EACCES), 0, 0);
                            }
                            if let Some(j) = journal {
                                j.net_record("refuse", "nonblock-failed", n);
                            }
                            return;
                        }
                    }
                    if !id_valid(lfd, n.id) {
                        return;
                    }
                    let mut addfd: NotifAddFd = unsafe { std::mem::zeroed() };
                    addfd.id = n.id;
                    addfd.flags = FLAG_SETFD;
                    addfd.srcfd = newfd as u32;
                    addfd.newfd = n.data.args[0] as u32;
                    addfd.newfd_flags = if task_fd_cloexec(n.pid, sockfd) {
                        libc::O_CLOEXEC as u32
                    } else {
                        0
                    };
                    match seccomp_ioctl(lfd, OP_ADDFD, &mut addfd as *mut NotifAddFd as *mut _) {
                        Ok(()) => {
                            reply(lfd, n.id, -(libc::EINPROGRESS), 0, 0);
                            if let Some(j) = journal {
                                j.net_record("allow", "injected-inprogress", n);
                            }
                            // Keep a duplicate for completion tracking:
                            // dup the supervisor fd, then hand tracking the
                            // dup to the receiver thread's poll loop.
                            let dup_fd = unsafe {
                                libc::fcntl(newfd, libc::F_DUPFD_CLOEXEC, 0)
                            };
                            if dup_fd >= 0 {
                                let target = notif_target(
                                    n.parsed_ip.as_ref(),
                                    n.parsed_family,
                                    n.parsed_port,
                                );
                                if tracker.slot(dup_fd, target).is_err() {
                                    unsafe { libc::close(dup_fd) };
                                }
                            }
                        }
                        Err(_e) => {
                            // ADDFD failure contract: -EACCES, like every
                            // other supervisor-side refusal. The guard
                            // closes `newfd`; nothing injected, nothing
                            // extra to close.
                            if id_valid(lfd, n.id) {
                                reply(lfd, n.id, -(libc::EACCES), 0, 0);
                                if let Some(j) = journal {
                                    j.net_record("refuse", "addfd-failed", n);
                                }
                            }
                            return;
                        }
                    }
                    return;
                }
                if e.raw_os_error() != Some(libc::EINPROGRESS) {
                    let errno = e.raw_os_error().unwrap_or(libc::EIO);
                    if id_valid(lfd, n.id) {
                        reply(lfd, n.id, -(errno), 0, 0);
                    }
                    if let Some(j) = journal {
                        j.net_record("refuse", "connect-failed", n);
                        // A non-blocking client's immediate failure is a
                        // known result too: journal it as a connect-result
                        // (no tracking needed, the answer is already here).
                        if client_nonblock {
                            let target = notif_target(
                                n.parsed_ip.as_ref(),
                                n.parsed_family,
                                n.parsed_port,
                            );
                            j.net_connect_result(&target, errno, 0);
                        }
                    }
                    return;
                }
                // EINPROGRESS on a blocking socket: poll for completion
                // until the deadline (unchanged behaviour).
                let mut done = false;
                while std::time::Instant::now() < deadline {
                    let mut pfd = libc::pollfd {
                        fd: newfd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
                    if pr < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                        // poll itself failed: do not retry until the
                        // deadline, answer now.
                        if id_valid(lfd, n.id) {
                            reply(lfd, n.id, -(libc::EIO), 0, 0);
                        }
                        if let Some(j) = journal {
                            j.net_record("refuse", "connect-error", n);
                        }
                        return;
                    }
                    if pr <= 0 {
                        // Still connecting. If the task has gone away
                        // meanwhile (killed, or the session is ending),
                        // nobody waits for this socket: stop now instead
                        // of holding the worker until the deadline.
                        if !id_valid(lfd, n.id) {
                            return;
                        }
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
                    }
                    return;
                }
            }
            // The supervisor's connect completed immediately (cr == 0).
            // Record it, then fall through to restore + inject below.
            if cr == 0 {
                if let Some(j) = journal {
                    j.net_record("allow", "injected", n);
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
            // SETFD replaces the task's descriptor, including its
            // close-on-exec flag: carry the original flag over, so a
            // socket opened with SOCK_CLOEXEC does not start leaking into
            // programs the task executes.
            addfd.newfd_flags = if task_fd_cloexec(n.pid, sockfd) {
                libc::O_CLOEXEC as u32
            } else {
                0
            };
            let r = seccomp_ioctl(lfd, OP_ADDFD, &mut addfd as *mut NotifAddFd as *mut _);
            match r {
                Ok(()) => {
                    reply(lfd, n.id, 0, 0, 0);
                    if let Some(j) = journal {
                        j.net_record("allow", "injected", n);
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

/// When `deadline` has passed: answer the notification ETIMEDOUT, journal
/// `refuse/deadline`, and return true.
fn refuse_if_expired(
    lfd: i32,
    n: &Notif,
    deadline: std::time::Instant,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) -> bool {
    if std::time::Instant::now() < deadline {
        return false;
    }
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, -(libc::ETIMEDOUT), 0, 0);
        if let Some(j) = journal {
            j.net_record("refuse", "deadline", n);
        }
    }
    true
}

/// Open a pidfd through which `tid`'s file descriptors can be taken.
///
/// `tid` may be any thread of a program: connects from threads other
/// than the main one are the normal case (thread pools, Go, Java).
/// With `thread_flag`, `PIDFD_THREAD` (Linux 6.9) opens the thread
/// itself. A kernel without the flag answers EINVAL; then the pidfd of
/// the thread's process is used instead, which is only correct when the
/// thread shares the process's descriptor table, so that is verified
/// with `kcmp(KCMP_FILES)` and anything else is an error (the caller
/// refuses the connect).
fn open_task_pidfd(tid: libc::pid_t, thread_flag: bool) -> io::Result<OwnedFd> {
    const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
    const KCMP_FILES: libc::c_int = 2;
    let open = |pid: libc::pid_t, flags: libc::c_uint| -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes two integers; the result is checked.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: fresh fd owned by us.
            Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        }
    };
    if thread_flag {
        match open(tid, PIDFD_THREAD) {
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
            other => return other,
        }
    }
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    let tgid = parse_tgid(&status).ok_or_else(|| io::Error::other("no Tgid in status"))?;
    let fd = open(tgid, 0)?;
    if tgid != tid {
        // SAFETY: kcmp takes integers only.
        let same = unsafe { libc::syscall(libc::SYS_kcmp, tid, tgid, KCMP_FILES, 0, 0) };
        if same != 0 {
            return Err(io::Error::other(
                "thread does not share its process's descriptor table",
            ));
        }
    }
    Ok(fd)
}

/// Is descriptor `fd` of task `tid` close-on-exec? Read from
/// `/proc/<tid>/fdinfo/<fd>`. When that cannot be read the answer is
/// "yes": losing a socket across exec is the safe side, leaking one is
/// not.
fn task_fd_cloexec(tid: u32, fd: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}")) {
        Ok(text) => fdinfo_cloexec(&text).unwrap_or(true),
        Err(_) => true,
    }
}

/// The close-on-exec bit of an fdinfo text (`flags:` is octal and
/// includes `O_CLOEXEC`).
fn fdinfo_cloexec(fdinfo: &str) -> Option<bool> {
    let flags = fdinfo.lines().find_map(|l| l.strip_prefix("flags:"))?;
    let flags = u32::from_str_radix(flags.trim(), 8).ok()?;
    Some(flags & libc::O_CLOEXEC as u32 != 0)
}

/// The `Tgid:` value of a `/proc/<tid>/status` text.
fn parse_tgid(status: &str) -> Option<libc::pid_t> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))?
        .trim()
        .parse()
        .ok()
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

/// The errno name used in a `network/connect-result` record.
pub fn errno_name(errno: i32) -> String {
    match errno {
        x if x == libc::ECONNREFUSED => "ECONNREFUSED".to_owned(),
        x if x == libc::ETIMEDOUT => "ETIMEDOUT".to_owned(),
        x if x == libc::EHOSTUNREACH => "EHOSTUNREACH".to_owned(),
        x if x == libc::ENETUNREACH => "ENETUNREACH".to_owned(),
        x if x == libc::ECONNRESET => "ECONNRESET".to_owned(),
        _ => format!("errno:{errno}"),
    }
}

/// Format the connect address read from the notification for the journal:
/// `ip:port` for INET, or the raw family for other families (`family:2`).
/// This is the only target form — never a pid/nr (see ADR 0022 L102).
pub fn notif_target(ip: Option<&IpAddr>, family: u16, port: u16) -> String {
    match ip {
        Some(a) => format!("{a}:{port}"),
        None => format!("family:{family}"),
    }
}

/// Extract the destination port from a parsed sockaddr buffer.
pub fn sockaddr_port(family: u16, buf: &[u8]) -> u16 {
    if (family == libc::AF_INET as u16 && buf.len() >= 6)
        || (family == libc::AF_INET6 as u16 && buf.len() >= 24)
    {
        u16::from_be_bytes([buf[2], buf[3]])
    } else {
        0
    }
}

/// True iff `ip` is a public (routable, non-private) address per ADR 0022 block list:
/// loopback, unspecified, multicast, link-local (incl 169.254.169.254), CGNAT
/// 100.64/10, RFC1918, ULA, site-local fec0::/10, plus 0/8 and 240/4
/// reserved. IPv6 forms that embed an IPv4 address are classified by that
/// address, so a private target cannot be reached through a transition
/// prefix: v4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64
/// `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, and Teredo
/// `2001::/32` (server address, and the client address stored inverted).
/// NOTE: documentation ranges 192.0.2/24, 198.51.100/24, 203.0.113/24 are NOT
/// blocked — not in the ADR list, and hermetic tests use 192.0.2.1/24 listeners.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(&v4);
            }
            // NAT64 well-known prefix 64:ff9b::/96 and local-use
            // 64:ff9b:1::/48 embed an IPv4 address; classify by it so a
            // private target cannot ride the translation.
            if let Some(v4) = nat64_embedded(v6) {
                return is_public_v4(&v4);
            }
            let o = v6.octets();
            // 64:ff9b:1::/48 is the local-use NAT64 prefix (RFC 8215).
            // Where the IPv4 address sits in it depends on the prefix
            // length the operator chose (RFC 6052), which is not known
            // here, and the prefix is not public address space: refuse
            // all of it.
            if o[..6] == [0, 0x64, 0xff, 0x9b, 0, 1] {
                return false;
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
            if o[0] == 0xfe && (o[1] & 0xc0) == 0xc0 {
                return false; // site-local fec0::/10 (deprecated, never public)
            }
            // IPv4-compatible ::/96 (deprecated): `::a.b.c.d`. `::` and
            // `::1` were handled above.
            if o[..12].iter().all(|&b| b == 0) {
                return is_public_v4(&Ipv4Addr::new(o[12], o[13], o[14], o[15]));
            }
            // 6to4 2002:AABB:CCDD::/48 embeds the IPv4 address A.B.C.D.
            if o[0] == 0x20 && o[1] == 0x02 {
                return is_public_v4(&Ipv4Addr::new(o[2], o[3], o[4], o[5]));
            }
            // Teredo 2001:0000::/32: bytes 4..8 are the server's IPv4
            // address, bytes 12..16 the client's, bitwise inverted.
            if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 0 {
                let server = Ipv4Addr::new(o[4], o[5], o[6], o[7]);
                let client = Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]);
                return is_public_v4(&server) && is_public_v4(&client);
            }
            true
        }
    }
}

/// The IPv4 address embedded in an address of the well-known NAT64
/// prefix `64:ff9b::/96` (RFC 6052: the last 32 bits).
fn nat64_embedded(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v6.octets();
    if o[..4] == [0, 0x64, 0xff, 0x9b] && o[4..12].iter().all(|&b| b == 0) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
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
    if o[0] == 198 && (o[1] & 0xfe) == 0x12 {
        return false; // 198.18.0.0/15 (benchmarking, not routable public)
    }
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
            "198.18.0.1",
            "198.19.255.255",
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
            // NAT64 embedding private v4.
            "64:ff9b::0a00:0001",
            "64:ff9b::c0a8:0101",
            "64:ff9b:1::0a00:0001",
            // Local-use NAT64 prefix: refused whatever it embeds and
            // wherever (here 10.0.0.1 in the /48 position, bytes 6-7 and
            // 9-10, with a public-looking tail; then a public tail only).
            "64:ff9b:1:0a00:0:100:808:808",
            "64:ff9b:1::808:808",
            // Site-local (deprecated).
            "fec0::1",
            "feff::1",
            // IPv4-compatible ::/96 embedding private / loopback v4.
            "::10.0.0.1",
            "::192.168.1.1",
            "::127.0.0.1",
            "::169.254.169.254",
            // 6to4 2002:V4::/48 embedding private v4.
            "2002:0a00:0001::1",
            "2002:c0a8:0101::1",
            "2002:7f00:0001::1",
            "2002:a9fe:a9fe::1",
            // Teredo 2001:0::/32: client 192.168.1.1 (stored inverted)
            // behind a public server; then a private server.
            "2001:0:4136:e378:8000:63bf:3f57:fefe",
            "2001:0:0a00:0001::f7f7:f7f7",
            // Teredo with client 127.0.0.1 (inverted 80ff:fffe).
            "2001:0:4136:e378:8000:63bf:80ff:fffe",
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
            "198.17.255.255",
            "198.20.0.0",
            "198.51.100.1",
            "203.0.113.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            // NAT64 embedding a public v4 stays public.
            "64:ff9b::0808:0808",
            // Transition forms embedding a public v4 stay public.
            "::8.8.8.8",
            "2002:0808:0808::1",
            // Teredo: public server 65.54.227.120, client 192.0.2.45.
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            // Not Teredo (2001:1::/32) and not site-local (fe00::/10 is
            // unassigned, fec0::/10 is the site-local range).
            "2001:1::1",
            "2001:db8::1",
        ] {
            assert!(is_public_ip(&ip(s)), "{s} must be public");
        }
    }

    // ---- engine tests: a real filter, real connect() calls ----------------

    fn connect_once(port: u16) -> i32 {
        // SAFETY: plain socket + connect on a fresh fd; only libc calls,
        // so this is safe to run in a forked child.
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if s < 0 {
                return 250;
            }
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = libc::INADDR_LOOPBACK.to_be();
            addr.sin_port = port.to_be();
            let rc = libc::connect(
                s,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if rc == 0 {
                0
            } else {
                *libc::__errno_location()
            }
        }
    }

    /// Child side of [`connecting_child`]. Exit code: `16 * refused +
    /// connected`; `100 + n` when all `n` connects timed out; 2xx when
    /// the setup failed.
    fn child_body(sock: i32, n: usize, port: u16) -> i32 {
        // The filter install needs no_new_privs (or CAP_SYS_ADMIN).
        if crate::sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).is_err() {
            return 203;
        }
        let Ok(listener) = install_connect_filter() else {
            return 204;
        };
        if crate::sys::send_with_fds(sock, b"L", &[listener.as_raw_fd()]).is_err() {
            return 205;
        }
        drop(listener);
        let mut pids = Vec::with_capacity(n);
        for _ in 0..n {
            // SAFETY: the grandchild only calls connect_once and _exit.
            let p = unsafe { libc::fork() };
            if p == 0 {
                unsafe { libc::_exit(connect_once(port)) }
            }
            pids.push(p);
        }
        let (mut connected, mut refused, mut timed_out) = (0, 0, 0);
        for p in pids {
            let mut st = 0;
            unsafe { libc::waitpid(p, &mut st, 0) };
            match libc::WEXITSTATUS(st) {
                0 => connected += 1,
                libc::EACCES => refused += 1,
                libc::ETIMEDOUT => timed_out += 1,
                _ => return 206,
            }
        }
        if timed_out > 0 {
            return if timed_out == n as i32 {
                100 + timed_out
            } else {
                207
            };
        }
        16 * refused + connected
    }

    /// Fork a child that installs the real connect filter, hands its
    /// listener to this process, and then lets `n` grandchildren each
    /// `connect()` once to `127.0.0.1:port`. Their connects stay
    /// suspended until an engine serves the returned listener.
    fn connecting_child(n: usize, port: u16) -> (libc::pid_t, OwnedFd) {
        let (ours, theirs) = crate::sys::socketpair_seqpacket().unwrap();
        // SAFETY: the child runs child_body and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            drop(ours);
            let code = child_body(theirs.as_raw_fd(), n, port);
            unsafe { libc::_exit(code) }
        }
        drop(theirs);
        let mut pfd = libc::pollfd {
            fd: ours.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 10_000) };
        let mut buf = [0u8; 8];
        let fd = (ready > 0)
            .then(|| crate::sys::recv_with_fds(ours.as_raw_fd(), &mut buf).ok())
            .flatten()
            .and_then(|r| r.fds.into_iter().next());
        match fd {
            Some(fd) => (pid, fd),
            None => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
                panic!(
                    "the test child could not install a seccomp user-notification \
                     filter (exit status {st:#x}); these tests need kernel >= 5.0 \
                     with seccomp user notification"
                );
            }
        }
    }

    /// Wait for the child of [`connecting_child`]; its exit code.
    fn child_exit(pid: libc::pid_t) -> i32 {
        let mut st = 0;
        for _ in 0..200 {
            if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
                assert!(libc::WIFEXITED(st), "child status {st:#x}");
                return libc::WEXITSTATUS(st);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::waitpid(pid, &mut st, 0) };
        panic!("child did not finish within 10 s: a connect() was left unanswered");
    }

    fn loopback_listener() -> (std::net::TcpListener, u16) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        (l, port)
    }

    fn engine_journal() -> (tempfile::TempDir, std::sync::Arc<crate::journal::Journal>) {
        let d = tempfile::tempdir().unwrap();
        let j = crate::journal::Journal::new(d.path().join("ws"), "s1".into());
        (d, std::sync::Arc::new(j.clone_for_engine()))
    }

    /// `(verdict, reason, target)` of every network/connect record.
    fn connect_records(
        d: &tempfile::TempDir,
        j: &crate::journal::Journal,
    ) -> Vec<(String, String, String)> {
        assert!(j.net_flush(std::time::Duration::from_secs(10)));
        let (records, _) = crate::journal::read_records(&d.path().join("ws"));
        let field = |r: &crate::journal::JournalRecord, k: &str| {
            r.data[k].as_str().unwrap_or("").to_owned()
        };
        records
            .iter()
            .filter(|r| r.kind == "network/connect")
            .map(|r| (field(r, "verdict"), field(r, "reason"), field(r, "target")))
            .collect()
    }

    #[test]
    fn engine_continues_a_loopback_connect_and_journals_the_target() {
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(1, port);
        let engine = NotifEngine::start(listener, Some(j.clone()), 5);
        assert_eq!(child_exit(pid), 1, "one connect, connected");
        drop(engine);
        assert_eq!(
            connect_records(&d, &j),
            [(
                "continue".to_owned(),
                "loopback-or-unix".to_owned(),
                format!("127.0.0.1:{port}")
            )]
        );
    }

    fn failing_reader(_pid: u32, _addr: u64, _len: usize) -> io::Result<[u8; 128]> {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }

    #[test]
    fn failed_sockaddr_read_refuses_eacces_and_journals() {
        // The destination cannot be read, so it is unknown: the connect
        // must be refused (EACCES), never continued, even though the
        // real target is a loopback listener that would be allowed.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(1, port);
        let cfg = EngineConfig {
            reader: failing_reader,
            ..EngineConfig::new(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), 16, "one connect, refused with EACCES");
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "refuse");
        assert_eq!(records[0].1, "read-failed");
    }

    fn slow_reader(pid: u32, addr: u64, len: usize) -> io::Result<[u8; 128]> {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        read_sockaddr(pid, addr, len)
    }

    #[test]
    fn dropping_an_idle_engine_is_quick() {
        let (pid, listener) = connecting_child(0, 1);
        let engine = NotifEngine::start_with(listener, None, EngineConfig::new(30));
        std::thread::sleep(std::time::Duration::from_millis(100));
        let start = std::time::Instant::now();
        drop(engine);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "stopping took {:?}",
            start.elapsed()
        );
        assert_eq!(child_exit(pid), 0);
    }

    #[test]
    fn deadline_covers_queue_time_and_the_read() {
        // Deadline 1 s, one worker whose read takes 1.5 s. The first
        // connect is past the deadline when its read returns; the second
        // waited 1.5 s for the worker and is past it before any work.
        // Both get ETIMEDOUT; neither is continued, although the target
        // is a loopback listener that would be allowed.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(2, port);
        let cfg = EngineConfig {
            workers: 1,
            queue: 4,
            reader: slow_reader,
            ..EngineConfig::new(1)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), 102, "two connects, both ETIMEDOUT");
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(
            records.iter().all(|r| r.0 == "refuse" && r.1 == "deadline"),
            "{records:?}"
        );
    }

    #[test]
    fn full_queue_refuses_eacces_at_once_and_journals() {
        // One worker that needs 1.5 s per connect and room for one
        // waiting notification. Six connects are pending when the engine
        // starts: the worker takes one, at most two more find room in
        // the queue over time, and every other one is refused by the
        // receiver without waiting for the worker.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(6, port);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let cfg = EngineConfig {
            workers: 1,
            queue: 1,
            reader: slow_reader,
            ..EngineConfig::new(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        // Well before the worker finishes its first connect, the refused
        // ones are already journaled.
        std::thread::sleep(std::time::Duration::from_millis(700));
        let early = connect_records(&d, &j);
        let early_full = early.iter().filter(|r| r.1 == "queue-full").count();
        assert!(early_full >= 3, "refused after 0.7 s: {early:?}");
        assert!(early.iter().all(|r| r.1 == "queue-full"), "{early:?}");

        let code = child_exit(pid);
        let (refused, connected) = (code / 16, code % 16);
        drop(engine);
        assert_eq!(refused + connected, 6, "exit code {code}");
        assert!((1..=3).contains(&connected), "connected {connected}");
        let records = connect_records(&d, &j);
        let full = records.iter().filter(|r| r.1 == "queue-full").count();
        let cont = records.iter().filter(|r| r.0 == "continue").count();
        assert_eq!(
            (full as i32, cont as i32),
            (refused, connected),
            "{records:?}"
        );
    }

    #[test]
    fn pidfd_for_a_non_leader_thread() {
        // A connect() from a thread other than the main one arrives with
        // that thread's id. Both ways of opening it must work: the
        // thread flag (6.9+), and the fallback through the process.
        let (tx, rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            // SAFETY: gettid has no arguments.
            tx.send(unsafe { libc::gettid() }).unwrap();
            let _ = stop_rx.recv();
        });
        let tid = rx.recv().unwrap();
        assert_ne!(tid, std::process::id() as libc::pid_t);
        // Without the flag, pidfd_open refuses a thread id; that was the
        // bug: every connect from a non-main thread was refused EACCES.
        let plain = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, 0u32) };
        assert_eq!(plain, -1, "pidfd_open(tid, 0) must fail for a thread");
        for thread_flag in [true, false] {
            let fd = open_task_pidfd(tid, thread_flag)
                .unwrap_or_else(|e| panic!("thread_flag={thread_flag}: {e}"));
            // The pidfd gives access to the thread's descriptors: take
            // a copy of the pidfd itself through it.
            let copy =
                unsafe { libc::syscall(libc::SYS_pidfd_getfd, fd.as_raw_fd(), fd.as_raw_fd(), 0) };
            assert!(copy >= 0, "pidfd_getfd (thread_flag={thread_flag})");
            unsafe { libc::close(copy as i32) };
        }
        drop(stop_tx);
        t.join().unwrap();
        assert_eq!(
            parse_tgid("Name:\tx\nTgid:\t4242\nPid:\t4250\n"),
            Some(4242)
        );
        assert_eq!(parse_tgid("Name:\tx\n"), None);
    }

    #[test]
    fn close_on_exec_is_read_from_fdinfo() {
        assert_eq!(
            fdinfo_cloexec("pos:\t0\nflags:\t02000002\nmnt_id:\t10\n"),
            Some(true)
        );
        assert_eq!(
            fdinfo_cloexec("pos:\t0\nflags:\t02\nmnt_id:\t10\n"),
            Some(false)
        );
        assert_eq!(fdinfo_cloexec("pos:\t0\n"), None);
        // A real descriptor of this process, both ways.
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(s >= 0);
        let me = std::process::id();
        assert!(task_fd_cloexec(me, s));
        unsafe { libc::fcntl(s, libc::F_SETFD, 0) };
        assert!(!task_fd_cloexec(me, s));
        unsafe { libc::close(s) };
        // Unreadable: the safe answer.
        assert!(task_fd_cloexec(me, 1_000_000));
    }

    #[test]
    fn id_valid_number_is_the_one_every_kernel_accepts() {
        // _IOR('!', 2, __u64): direction 2 (read) in bits 30..31.
        assert_eq!(OP_ID_VALID, 0x8008_2102);
        assert_eq!(OP_ID_VALID >> 30, 2);
    }

    #[test]
    fn probe_finds_the_features_on_this_kernel() {
        // Runs the real startup probe: an unknown id must be answered
        // with ENOENT by ID_VALID and by ADDFD+SETFD.
        assert_eq!(probe_features(), Ok(()));
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

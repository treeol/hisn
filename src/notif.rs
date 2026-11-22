//! Phase 1 of ADR 0022 open mode: seccomp user-notif plumbing + classifier.
//! The filter is built here but NOT installed in the supervisor process;
//! the caller installs it in a disposable child.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// Native architecture constant for the seccomp filter. Each target
/// compiles only its own value; an unsupported target is a compile
/// error so a wrong arch value never reaches a seccomp filter.
#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const _UNSUPPORTED_ARCH: () = compile_error!("notif needs x86_64 or aarch64");

/// `SO_NETNS_COOKIE` (Linux 5.14, `socket(7)`): the unique id of the
/// network namespace a socket lives in; readable without privilege.
const SO_NETNS_COOKIE: libc::c_int = 71;

/// Offset of `seccomp_data.args[i]` (low 32-bit word on little endian).
const fn arg_off(i: u32) -> u32 {
    16 + 8 * i
}

const BPF_JSET_K: u16 = 0x45;

/// Hand-written classic BPF. Verdicts:
/// - foreign architecture: `KILL_PROCESS`;
/// - `connect`, `bind`, `listen`: `USER_NOTIF`;
/// - `sendto`/`sendmmsg` (flags = arg 3) and `sendmsg` (flags = arg 2)
///   with `MSG_FASTOPEN`: `ERRNO(EOPNOTSUPP)` — 0.6.2 design C. The flag
///   is a register argument, so the filter decides alone; open mode does
///   not support TCP fast open and programs fall back to a normal
///   connect. No notification, no supervisor decision, hence no
///   check/execute gap. Every other send is `ALLOW`, so ordinary
///   traffic and the helper's own fd passing are never trapped;
/// - everything else: `ALLOW`.
///
/// Jumps only go forward: target = pc + 1 + offset. The program is
/// checked by interpreting this exact array
/// (`notif::tests::filter_verdicts_by_interpretation`).
pub fn connect_filter() -> Vec<libc::sock_filter> {
    let ins = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let direct = [
        libc::SYS_connect as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
    ];
    let s = 4 + direct.len(); // first send-family instruction
    let allow_pc = s + 7;
    let notif_pc = s + 8;
    let err_pc = s + 9; // SECCOMP_RET_ERRNO | EOPNOTSUPP
    let to = |from: usize, target: usize| (target - (from + 1)) as u8;
    let mut v = vec![
        ins(BPF_LD_W_ABS, 0, 0, 4), // arch
        ins(BPF_JEQ_K, 1, 0, NATIVE_ARCH),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ins(BPF_LD_W_ABS, 0, 0, 0), // nr
    ];
    for (i, &nr) in direct.iter().enumerate() {
        v.push(ins(BPF_JEQ_K, to(4 + i, notif_pc), 0, nr));
    }
    // pc s: sendto -> flags in arg 3 (pc s+3); s+1: sendmmsg -> same;
    // s+2: sendmsg -> flags in arg 2 (pc s+5), anything else ALLOW.
    v.push(ins(BPF_JEQ_K, to(s, s + 3), 0, libc::SYS_sendto as u32));
    v.push(ins(
        BPF_JEQ_K,
        to(s + 1, s + 3),
        0,
        libc::SYS_sendmmsg as u32,
    ));
    v.push(ins(
        BPF_JEQ_K,
        to(s + 2, s + 5),
        to(s + 2, allow_pc),
        libc::SYS_sendmsg as u32,
    ));
    v.push(ins(BPF_LD_W_ABS, 0, 0, arg_off(3))); // s+3
    v.push(ins(
        BPF_JSET_K,
        to(s + 4, err_pc),
        to(s + 4, allow_pc),
        libc::MSG_FASTOPEN as u32,
    ));
    v.push(ins(BPF_LD_W_ABS, 0, 0, arg_off(2))); // s+5
    v.push(ins(
        BPF_JSET_K,
        to(s + 6, err_pc),
        to(s + 6, allow_pc),
        libc::MSG_FASTOPEN as u32,
    ));
    v.push(ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW)); // s+7
    v.push(ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_USER_NOTIF)); // s+8
    v.push(ins(
        BPF_RET_K,
        0,
        0,
        libc::SECCOMP_RET_ERRNO | libc::EOPNOTSUPP as u32,
    )); // s+9
    v
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
        0 if own_netns_cookie().is_some() => return Ok(()),
        0 => "SO_NETNS_COOKIE (kernel >= 5.14), which tells a sandbox socket from a host-side one",
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
    let r = unsafe { libc::ioctl(fd, OP_ID_VALID as libc::Ioctl, &bogus as *const u64) };
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
    let r = unsafe { libc::ioctl(fd, OP_ADDFD as libc::Ioctl, &probe as *const NotifAddFd) };
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
    /// 0.6.1: the seat of the exec that caused this notification
    /// (filled at dispatch by the exec-tree engine); `None` for the
    /// main command and in-sandbox services.
    pub seat: Option<String>,
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
            seat: None,
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
            seat: None,
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
// 0x8008_2102). The header was corrected to _IOW (0x4008_2102) and the
// original number kept as SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR, which
// the kernel still accepts (kernel/seccomp.c of v5.14, v5.16, v5.17,
// v6.1 and v6.8 has `case ..._WRONG_DIR:` next to the corrected case; a
// kernel before the correction knows only the original number). So the
// original number is accepted on every kernel since 5.0, and the floor
// for open mode is 5.14 (SO_NETNS_COOKIE).
pub const OP_RECV: u32 = 0xC050_2100;
pub const OP_SEND: u32 = 0xC018_2101;
pub const OP_ID_VALID: u32 = 0x8008_2102;
pub const OP_ADDFD: u32 = 0x4018_2103;
const _: () = assert!(
    ((OP_RECV >> 16) & 0x1fff) == std::mem::size_of::<RawNotif>() as u32,
    "OP_RECV size"
);
const _: () = assert!(
    ((OP_SEND >> 16) & 0x1fff) == std::mem::size_of::<NotifResp>() as u32,
    "OP_SEND size"
);
const _: () = assert!(((OP_ID_VALID >> 16) & 0x1fff) == 8, "OP_ID_VALID size");
const _: () = assert!(
    ((OP_ADDFD >> 16) & 0x1fff) == std::mem::size_of::<NotifAddFd>() as u32,
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
///
/// 0.6.2: `Continue` here means "the kernel may continue the call".
/// That is only answered for call classes covered by the Landlock TCP
/// rules at execution time (design B) or that cannot leave the empty
/// network namespace (AF_UNIX on a confirmed sandbox socket). Loopback
/// INET connects and INET binds/listens are supervisor-executed
/// (design A) and never reach `decide` as `Continue` at runtime — the
/// `Continue` verdict for loopback is retained only as the *policy*
/// classification that selects the supervisor-executed path.
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

fn seccomp_ioctl(fd: i32, op: u32, ptr: *mut libc::c_void) -> io::Result<()> {
    // libc::Ioctl is c_ulong (glibc, 64-bit) or c_int (musl, 32-bit).
    // Casting the u32 bit pattern through libc::Ioctl preserves it on both.
    let request = op as libc::Ioctl;
    let r = unsafe { libc::ioctl(fd, request, ptr) };
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

/// Answer a notification (`SECCOMP_IOCTL_NOTIF_SEND`). An error means
/// the answer did not reach the task: it was killed, or a signal ended
/// the system call (ENOENT).
fn send_reply(listener: i32, id: u64, error: i32, val: i64, flags: u32) -> io::Result<()> {
    let mut resp = NotifResp {
        id,
        val,
        error,
        flags,
    };
    seccomp_ioctl(listener, OP_SEND, &mut resp as *mut NotifResp as *mut _)
}

/// [`send_reply`] for answers after which nothing is left to undo: a
/// refusal or CONTINUE that does not arrive concerns a task that is no
/// longer in the call.
fn reply(listener: i32, id: u64, error: i32, val: i64, flags: u32) {
    let _ = send_reply(listener, id, error, val, flags);
}

/// SUPERVISOR NOTIF ENGINE (phase 2)
/// Receiver thread + bounded worker pool. Deadline from RECV.
pub struct NotifEngine {
    pub shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Receives one message (or a hang-up) when the engine has stopped.
    done: std::sync::mpsc::Receiver<()>,
    /// The engine's completion tracker (see [`Tracked`]).
    tracker: std::sync::Arc<Tracked>,
}

/// Max pending notifications between receiver and workers; a full queue
/// refuses EACCES immediately (journaled refuse/queue-full).
pub const MAX_PENDING: usize = 256;
/// Dispatch threads per listener. They never wait for a connection.
pub const WORKERS: usize = 16;
/// Wait threads per listener: connects of blocking programs that can be
/// in flight at the same time. One more waits in the queue, counted
/// against its deadline, as before.
pub const WAITERS: usize = 64;
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
#[derive(Clone)]
pub struct EngineConfig {
    /// Outbound connect deadline in seconds, counted from `NOTIF_RECV`.
    pub deadline_s: u64,
    /// Dispatch threads: read, decide, start the connect. Never wait
    /// for a connection.
    pub workers: usize,
    /// Wait threads: one per blocking program's connect that is still
    /// in flight.
    pub waiters: usize,
    /// Notifications that may wait for a dispatch thread, and blocking
    /// connects that may wait for a wait thread; one more is refused.
    pub queue: usize,
    pub reader: SockaddrReader,
    /// The supervisor's network-namespace cookie, resolved once per
    /// engine in `start_with_seats` when `None`. Sockets with this cookie
    /// are host-side. Still `None` (unresolvable) means every socket is
    /// treated as host-side: fail closed.
    pub supervisor_cookie: Option<NetnsCookie>,
}

impl EngineConfig {
    pub fn new(deadline_s: u64) -> Self {
        Self {
            deadline_s,
            workers: WORKERS,
            waiters: WAITERS,
            queue: MAX_PENDING,
            reader: read_sockaddr,
            supervisor_cookie: None,
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

/// 0.6.1: seat attribution for an engine's records. The exec-tree
/// engine is given a lookup `(sandbox pid) -> Option<Option<seat>>`
/// over the supervisor's exec table: `None` = not an exec's top pid,
/// `Some(seat)` = that exec's client seat (itself `None` for a client
/// without a seat). The notified task is mapped to an exec by process
/// ancestry ([`resolve_seat`]); the main-command engine has no lookup,
/// so its records keep `seat: null`. DNS records are never attributed:
/// a DNS query cannot be tied to a calling task without guessing (the
/// responder serves the whole session), so they stay null — documented
/// here and in ADR 0022.
pub type SeatLookup = std::sync::Arc<dyn Fn(i32) -> Option<Option<String>> + Send + Sync>;

/// What the ancestry walk needs from `/proc/<tid>/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    pub tgid: i32,
    pub ppid: i32,
    /// `NSpid:` entries, outermost namespace first; the last one is the
    /// pid in the task's own (innermost) pid namespace.
    pub nspid: Vec<i32>,
}

/// Reader of task status; the production one reads `/proc`, tests use a
/// fake.
pub trait ProcReader {
    fn status(&self, tid: i32) -> Option<ProcStatus>;
}

pub struct RealProc;

/// Parse the text of `/proc/<tid>/status`.
pub fn parse_proc_status(text: &str) -> Option<ProcStatus> {
    let (mut tgid, mut ppid, mut nspid) = (None, None, None);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Tgid:") {
            tgid = v.trim().parse::<i32>().ok();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse::<i32>().ok();
        } else if let Some(v) = line.strip_prefix("NSpid:") {
            nspid = v
                .split_whitespace()
                .map(|x| x.parse::<i32>().ok())
                .collect::<Option<Vec<_>>>();
        }
    }
    Some(ProcStatus {
        tgid: tgid?,
        ppid: ppid?,
        nspid: nspid.filter(|v| !v.is_empty())?,
    })
}

impl ProcReader for RealProc {
    fn status(&self, tid: i32) -> Option<ProcStatus> {
        let t = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
        parse_proc_status(&t)
    }
}

/// Maximum ancestry steps of the seat walk.
const SEAT_WALK_MAX: usize = 64;

/// Walk from the notifying thread `tid` up through `PPid` until a task
/// whose pid in the sandbox pid namespace is an exec's top pid
/// (`lookup`) is found. `level` is the `NSpid` depth of tasks of the
/// sandbox pid namespace (the supervisor's own depth + 1); only tasks
/// at that depth are matched, so a pid namespace the program made for
/// itself cannot be mistaken for an exec. Stops without a match at the
/// sandbox init (pid 1 at `level`), at a task above `level` (left the
/// sandbox), at pid 0, after [`SEAT_WALK_MAX`] steps, on a cycle, or on
/// an unreadable status. Never cached: a pid can be reused.
pub fn resolve_seat(
    proc_: &dyn ProcReader,
    tid: i32,
    level: usize,
    lookup: &dyn Fn(i32) -> Option<Option<String>>,
) -> Option<String> {
    let mut pid = proc_.status(tid)?.tgid;
    let mut seen: Vec<i32> = Vec::new();
    for _ in 0..SEAT_WALK_MAX {
        if pid <= 0 || seen.contains(&pid) {
            return None;
        }
        seen.push(pid);
        let st = proc_.status(pid)?;
        let inner = *st.nspid.last()?;
        if st.nspid.len() < level {
            return None;
        }
        if st.nspid.len() == level {
            if let Some(found) = lookup(inner) {
                return found;
            }
            if inner == 1 {
                return None;
            }
        }
        pid = st.ppid;
    }
    None
}

impl NotifEngine {
    /// Start the engine on `listener` with the production configuration.
    /// `journal` is an engine handle of the workspace journal
    /// ([`crate::journal::Journal::clone_for_engine`]): its network records
    /// go through a bounded queue, so a verdict never waits on a journal
    /// write. The engine shares the queue's tracked-overflow counter with
    /// the journal writer. `seats`, when given, stamps each record with
    /// the seat of the exec that caused it (0.6.1); the same lookup is
    /// used for `network/connect` and `network/connect-result`.
    pub fn start(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        deadline_s: u64,
    ) -> Self {
        Self::start_seated(listener, journal, deadline_s, None)
    }

    /// As [`NotifEngine::start`], with seat attribution for the records
    /// caused by an exec'd program.
    pub fn start_seated(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        deadline_s: u64,
        seats: Option<SeatLookup>,
    ) -> Self {
        Self::start_with_seats(listener, journal, EngineConfig::new(deadline_s), seats)
    }

    /// Number of non-blocking connects whose completion is tracked now.
    pub fn tracked(&self) -> usize {
        self.tracker.len()
    }

    /// Start the engine with an explicit configuration.
    pub fn start_with(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        cfg: EngineConfig,
    ) -> Self {
        Self::start_with_seats(listener, journal, cfg, None)
    }

    /// As [`NotifEngine::start_with`], with seat attribution.
    ///
    /// The production cookie is the supervisor's own
    /// netns identity, resolved here (the common sink of all start
    /// paths). Tests set `cfg.supervisor_cookie` themselves — to a
    /// namespace that is not the test netns — so their sockets resolve
    /// as sandbox-side.
    pub fn start_with_seats(
        listener: OwnedFd,
        journal: Option<std::sync::Arc<crate::journal::Journal>>,
        mut cfg: EngineConfig,
        seats: Option<SeatLookup>,
    ) -> Self {
        if cfg.supervisor_cookie.is_none() {
            // Fail closed: without a cookie the engine treats every
            // unresolvable socket as host-side.
            cfg.supervisor_cookie = own_netns_cookie();
        }
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sd = shutdown.clone();
        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        let tracker = match &journal {
            Some(j) => j.tracked_overflow().map(Tracked::with_overflow),
            None => None,
        }
        .unwrap_or_default();
        let tracker = std::sync::Arc::new(tracker);
        let engine_tracker = tracker.clone();
        std::thread::spawn(move || {
            engine_loop(listener, journal, cfg, &sd, &engine_tracker, seats);
            let _ = done_tx.send(());
        });
        Self {
            shutdown,
            done,
            tracker,
        }
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

// `tcpi_state` values (include/net/tcp_states.h).
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_CLOSE: u8 = 7;
const TCP_LISTEN: u8 = 10;

/// What the engine reads from `TCP_INFO`. Reading it changes nothing on
/// the socket.
#[derive(Debug, Clone, Copy)]
struct TcpInfo {
    /// `tcpi_state`.
    state: u8,
    /// `tcpi_bytes_acked`; the peer's acknowledgement of the SYN counts
    /// as one byte. None on a kernel whose `tcp_info` is too short.
    bytes_acked: Option<u64>,
    /// `tcpi_segs_out`: segments sent since the socket was created or
    /// last reset. None on a kernel whose `tcp_info` is too short.
    segs_out: Option<u32>,
}

/// The kernel `struct tcp_info` prefix hisn reads (`linux/tcp.h`):
/// `tcpi_state` (u8) at 0, `tcpi_bytes_acked` (u64) and `tcpi_segs_out`
/// (u32) at their defined offsets. Fields are read by *definition*,
/// not by hardcoded numbers: the offsets are derived from this layout
/// with `core::mem::offset_of!`, and the asserts below pin the layout
/// against the values the old hardcoded offsets encoded. Older kernels
/// return a shorter `tcp_info`; the length checks keep those fields
/// `None`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KernelTcpInfo {
    state: u8,
    _pad: [u8; 119],
    bytes_acked: u64,
    _pad2: [u8; 8],
    segs_out: u32,
}
const _: () = assert!(core::mem::offset_of!(KernelTcpInfo, state) == 0);
const _: () = assert!(core::mem::offset_of!(KernelTcpInfo, bytes_acked) == 120);
const _: () = assert!(core::mem::offset_of!(KernelTcpInfo, segs_out) == 136);
const _: () = assert!(core::mem::size_of::<KernelTcpInfo>() >= 140);

/// `TCP_INFO` of a TCP socket, or None when the option cannot be read
/// (not a TCP socket).
fn tcp_info(fd: i32) -> Option<TcpInfo> {
    let mut info = [0u8; 256];
    let mut len = info.len() as libc::socklen_t;
    // SAFETY: `info` and `len` describe a valid out-buffer.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || len < 1 {
        return None;
    }
    let len = len as usize;
    // Fields are read from the buffer by their defined offsets
    // (`offset_of!` on `KernelTcpInfo`), with unaligned reads: the
    // buffer is a byte array, so no alignment is assumed. The length
    // checks guard each wider field, as before.
    let field =
        |off: usize, n: usize| -> Option<&[u8]> { (len >= off + n).then(|| &info[off..off + n]) };
    let bytes_acked = field(core::mem::offset_of!(KernelTcpInfo, bytes_acked), 8).map(|b| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(b);
        u64::from_ne_bytes(raw)
    });
    let segs_out = field(core::mem::offset_of!(KernelTcpInfo, segs_out), 4).map(|b| {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(b);
        u32::from_ne_bytes(raw)
    });
    Some(TcpInfo {
        state: info[core::mem::offset_of!(KernelTcpInfo, state)],
        bytes_acked,
        segs_out,
    })
}

/// `tcpi_state` alone, see [`tcp_info`].
fn tcp_state(fd: i32) -> Option<u8> {
    tcp_info(fd).map(|i| i.state)
}

/// True for a TCP socket that has been used for a connect before and is
/// not connected or connecting now: closed, but it has sent segments. A
/// socket that was never connected has sent none.
fn used_and_closed(fd: i32) -> bool {
    tcp_info(fd).is_some_and(|i| i.state == TCP_CLOSE && i.segs_out.is_some_and(|n| n > 0))
}

/// How a tracked connect stands, read without changing the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// The handshake completed (the socket may have been closed by the
    /// peer since).
    Connected,
    /// The connect ended without a connection (refused, unreachable,
    /// reset).
    Failed,
    /// The handshake is still in flight.
    Pending,
}

/// State of a connecting TCP socket from `TCP_INFO` (`tcpi_state`,
/// `tcpi_bytes_acked`), with `getpeername` as the fallback when
/// `TCP_INFO` is not available.
///
/// Neither call consumes anything. In particular this never reads
/// `SO_ERROR`: the descriptor is a duplicate of the socket the program
/// owns, and a pending error is handed to exactly one reader. Measured
/// on kernel 7.3.3: after a refused connect a `SO_ERROR` read through a
/// duplicate returned ECONNREFUSED and the program's own read then
/// returned 0, whereas after `TCP_INFO` and `getpeername` on the
/// duplicate the program still read ECONNREFUSED.
///
/// `had_event` only matters for the fallback, where a socket without a
/// peer is `Failed` if poll reported an event and `Pending` otherwise.
pub fn conn_state(fd: i32, had_event: bool) -> ConnState {
    if let Some(info) = tcp_info(fd) {
        let acked = info.bytes_acked;
        return match info.state {
            TCP_SYN_SENT | TCP_SYN_RECV => ConnState::Pending,
            // CLOSE is also the state of a connection that was
            // established and has been closed again since (a program
            // that is done within milliseconds). The peer's
            // acknowledgement of the SYN counts as one acked byte, so a
            // socket that never got that far has acked nothing.
            TCP_CLOSE if acked.is_some_and(|n| n > 0) => ConnState::Connected,
            TCP_CLOSE | TCP_LISTEN => ConnState::Failed,
            _ => ConnState::Connected,
        };
    }
    // SAFETY: zeroed storage and its length are a valid out-buffer.
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let has_peer = unsafe {
        libc::getpeername(
            fd,
            &mut peer as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut peer_len,
        )
    } == 0;
    if has_peer {
        ConnState::Connected
    } else if had_event {
        ConnState::Failed
    } else {
        ConnState::Pending
    }
}

/// One non-blocking connect the supervisor answered EINPROGRESS for.
struct TrackedConn {
    /// The supervisor's own descriptor of the socket the program holds.
    /// Closing it does not close the program's descriptor.
    fd: OwnedFd,
    target: String,
    /// 0.6.1: the seat of the exec that caused the connect, for the
    /// `network/connect-result` record.
    seat: Option<String>,
    started: std::time::Instant,
    /// Poll reported an event while the handshake was still in flight.
    /// The entry is then left out of the poll set, so it cannot make the
    /// receiver spin, and is settled at the deadline.
    muted: bool,
}

/// Completion tracking for non-blocking connects the supervisor has
/// already answered EINPROGRESS for. One tracker per engine. The
/// receiver thread polls the tracked sockets together with the listener
/// and settles them in [`Tracked::sweep`]; no worker ever waits for a
/// tracked socket, so tracking does not hold up a verdict. At most
/// [`MAX_TRACKED`] sockets are tracked; one more is injected and
/// answered as usual but not tracked, and counted (`tracked_overflow` in
/// the next `network/summary`).
pub struct Tracked {
    pend: std::sync::Mutex<Vec<TrackedConn>>,
    /// eventfd the receiver polls: written when a socket is added, so
    /// the receiver starts polling it now and not at its next timeout
    /// (`latency_ms` would otherwise be up to [`RECV_POLL_MS`] too
    /// long). None if the eventfd could not be created.
    wake: Option<OwnedFd>,
    /// Most sockets tracked at a time ([`MAX_TRACKED`]).
    cap: usize,
    /// Connects that were not tracked for lack of room. Shared with the
    /// journal's network queue, which reports and resets it.
    overflow: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Tracked {
    /// A tracker with the given journal overflow counter.
    pub fn with_overflow(overflow: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
        // SAFETY: eventfd returns a fresh descriptor or -1.
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        Self {
            pend: std::sync::Mutex::new(Vec::new()),
            // SAFETY: a non-negative eventfd result is an owned fd.
            wake: (wake >= 0).then(|| unsafe { OwnedFd::from_raw_fd(wake) }),
            cap: MAX_TRACKED,
            overflow,
        }
    }

    /// Track `fd`. False (and `fd` closed, overflow counted) when the
    /// tracker is full. `seat` is the seat of the exec that caused
    /// the connect (0.6.1).
    fn slot_seated(&self, fd: OwnedFd, target: String, seat: Option<String>) -> bool {
        let mut pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
        if pend.len() >= self.cap {
            self.overflow
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        pend.push(TrackedConn {
            fd,
            target,
            seat,
            started: std::time::Instant::now(),
            muted: false,
        });
        drop(pend);
        if let Some(wake) = &self.wake {
            let one = 1u64.to_ne_bytes();
            // SAFETY: writes 8 bytes from a valid buffer; a full
            // counter (EAGAIN) means a wake-up is pending already.
            unsafe { libc::write(wake.as_raw_fd(), one.as_ptr() as *const _, 8) };
        }
        true
    }

    /// The descriptor that becomes readable when a socket was added
    /// (-1, which poll ignores, without an eventfd).
    fn wake_fd(&self) -> i32 {
        self.wake.as_ref().map_or(-1, |w| w.as_raw_fd())
    }

    /// Reset the wake-up after poll reported it.
    fn drain_wake(&self) {
        if let Some(wake) = &self.wake {
            let mut buf = [0u8; 8];
            // SAFETY: reads 8 bytes into a valid buffer (non-blocking).
            unsafe { libc::read(wake.as_raw_fd(), buf.as_mut_ptr() as *mut _, 8) };
        }
    }

    /// Number of tracked sockets.
    pub fn len(&self) -> usize {
        self.pend.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// True when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The descriptors to poll for POLLOUT.
    fn pollfds(&self) -> Vec<i32> {
        self.pend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|c| !c.muted)
            .map(|c| c.fd.as_raw_fd())
            .collect()
    }

    /// Settle what can be settled: sockets poll reported in `ready`
    /// whose connect has ended, and sockets older than `deadline`. Each
    /// settled socket gets one `network/connect-result` record
    /// (`connected`, `failed` or `pending-at-deadline`) and is closed.
    /// Returns the number settled. The journal is written after the lock
    /// is released.
    fn sweep(
        &self,
        ready: &[i32],
        deadline: std::time::Duration,
        journal: Option<&crate::journal::Journal>,
    ) -> usize {
        let ready: std::collections::HashSet<i32> = ready.iter().copied().collect();
        let mut settled: Vec<(String, &'static str, u128, Option<String>)> = Vec::new();
        {
            let mut pend = self.pend.lock().unwrap_or_else(|e| e.into_inner());
            pend.retain_mut(|c| {
                let fd = c.fd.as_raw_fd();
                let had_event = ready.contains(&fd);
                let expired = c.started.elapsed() >= deadline;
                if !had_event && !expired {
                    return true;
                }
                let result = match conn_state(fd, had_event) {
                    ConnState::Connected => "connected",
                    ConnState::Failed => "failed",
                    ConnState::Pending if expired => "pending-at-deadline",
                    ConnState::Pending => {
                        c.muted = true;
                        return true;
                    }
                };
                settled.push((
                    std::mem::take(&mut c.target),
                    result,
                    c.started.elapsed().as_millis(),
                    c.seat.take(),
                ));
                false // dropped: the OwnedFd closes the descriptor
            });
        }
        if let Some(j) = journal {
            for (target, result, latency_ms, seat) in &settled {
                j.net_connect_result_seated(target, result, *latency_ms, seat.as_deref());
            }
        }
        settled.len()
    }

    /// Close every tracked socket without a record (engine shutdown).
    fn clear(&self) {
        self.pend.lock().unwrap_or_else(|e| e.into_inner()).clear();
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
    seats: Option<SeatLookup>,
) {
    // Keep the listener alive until every worker has joined: workers hold
    // only the raw fd number, so dropping it first would be use-after-close.
    let listener = std::sync::Arc::new(listener);
    let lfd = listener.as_raw_fd();
    // NSpid depth of the sandbox pid namespace: ours + 1.
    let seat_level = RealProc
        .status(unsafe { libc::getpid() })
        .map(|s| s.nspid.len() + 1)
        .unwrap_or(2);
    // Two pools, each behind a bounded queue.
    //
    // Dispatch pool: reads and decides every notification and makes the
    // supervisor's (always non-blocking) connect. It never waits for a
    // connection, so a non-blocking connect is answered at once whatever
    // else is pending.
    //
    // Wait pool: holds the connects of blocking programs until they are
    // established, have failed, or reach the deadline.
    //
    // The receiver only dispatches; a full queue is answered EACCES.
    let cfg = std::sync::Arc::new(cfg);
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Notif, std::time::Instant)>(cfg.queue.max(1));
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel::<Waiting>(cfg.queue.max(1));
    let wait_rx = std::sync::Arc::new(std::sync::Mutex::new(wait_rx));
    let mut workers = Vec::new();
    for _ in 0..cfg.workers.max(1) {
        let rx = rx.clone();
        let j = journal.clone();
        let tracker = tracker.clone();
        let wait_tx = wait_tx.clone();
        let seats = seats.clone();
        let cfg = cfg.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let msg = {
                    let lock = rx.lock().unwrap_or_else(|e| e.into_inner());
                    lock.recv()
                };
                match msg {
                    Ok((mut n, recv_at)) => {
                        // 0.6.1: stamp the notification with the seat of
                        // the exec that caused it, once, at dispatch.
                        // The walk is followed by NOTIF_ID_VALID: if the
                        // task is not known to be the same one, null.
                        n.seat = seats
                            .as_ref()
                            .and_then(|f| resolve_seat(&RealProc, n.pid as i32, seat_level, &**f))
                            .filter(|_| id_valid(lfd, n.id));
                        handle_notif(lfd, &mut n, recv_at, &cfg, &j, &tracker, &wait_tx)
                    }
                    Err(_) => return,
                }
            }
        }));
    }
    let mut waiters = Vec::new();
    for _ in 0..cfg.waiters.max(1) {
        let wait_rx = wait_rx.clone();
        let j = journal.clone();
        waiters.push(std::thread::spawn(move || {
            loop {
                let msg = {
                    let lock = wait_rx.lock().unwrap_or_else(|e| e.into_inner());
                    lock.recv()
                };
                match msg {
                    Ok(w) => finish_blocking(lfd, &w, &j),
                    Err(_) => return,
                }
            }
        }));
    }
    let deadline = std::time::Duration::from_secs(cfg.deadline_s.max(1));
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // Poll the listener and the tracked sockets in one call. The
        // timeout stays RECV_POLL_MS, so shutdown and the deadline of
        // tracked sockets are both noticed promptly.
        let fds = tracker.pollfds();
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(fds.len() + 2);
        pfds.push(libc::pollfd {
            fd: lfd,
            events: libc::POLLIN,
            revents: 0,
        });
        pfds.push(libc::pollfd {
            fd: tracker.wake_fd(),
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
        if pfds[1].revents != 0 {
            tracker.drain_wake();
        }
        let ready: Vec<i32> = pfds
            .iter()
            .skip(2)
            .filter(|p| p.revents != 0)
            .map(|p| p.fd)
            .collect();
        tracker.sweep(&ready, deadline, journal.as_deref());
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
    // Drop the queue senders so both pools drain and exit; join them
    // before the listener Arc is released. The dispatch workers hold
    // clones of the wait queue's sender, so they are joined first.
    drop(tx);
    for w in workers {
        let _ = w.join();
    }
    drop(wait_tx);
    for w in waiters {
        let _ = w.join();
    }
    // Close the tracked sockets that are still connecting. Both pools
    // are joined, so nothing can add an entry now.
    tracker.clear();
    drop(listener);
}

/// `bind`, `listen` and a `MSG_FASTOPEN` send (the implicit connect of a
/// stream socket) are notified. 0.6.2 answers by where the socket lives
/// *and* whether the supervisor can act on the very reference it
/// checked (design A):
///
/// - `listen` on ANY socket: the supervisor performs it itself on its own
///   reference (`pidfd_getfd`), in the socket's own namespace. The
///   checked object and the acted-on object are the same, so there is
///   no gap between decision and execution. On a sandbox socket this is
///   a no-op (loopback listen in the empty namespace); on a
///   supervisor-side or unknown socket `listen` is refused with EACCES.
/// - `bind` with an AF_INET/AF_INET6 address: the supervisor performs
///   it the same way on its own reference, with its own copy of the
///   address, and answers the result (including the caller's errno:
///   a supervisor-side socket in the supervisor's namespace may bind a
///   low port the caller could not — the answer is what the supervisor
///   got, which for a sandbox socket is identical to native because
///   both act in the empty namespace with the same credentials... the
///   low-port case is handled by Landlock: a sandboxed task cannot
///   bind a TCP port at all, and the supervisor's bind on a sandbox
///   socket is the loopback bind the program asked for. To keep I3
///   (identical results for ordinary programs), the supervisor's
///   result on a sandbox socket is the native result).
/// - `bind` with any other family, and `MSG_FASTOPEN` sends: Landlock
///   covers TCP bind/connect at execution time (design B), so a
///   CONTINUE is safe; fast-open sends no longer reach here at all
///   (the filter answers EOPNOTSUPP, design C) — this handler is kept
///   for completeness but `send*` is never notified now.
/// - Unknown namespace: refused — the socket is neither confirmed
///   sandbox nor actionable.
///
/// A caller interrupted by a signal while the supervisor works: the
/// notification id becomes invalid and `id_valid` suppresses the
/// answer; the supervisor's dup fd is closed on return (OwnedFd), so
/// no reference leaks and no wait thread is held for `listen`/`bind`
/// (only blocking `connect` uses the wait pool, as before).
#[allow(unreachable_code, unused_variables)]
fn handle_implicit_call(
    lfd: i32,
    n: &Notif,
    cfg: &EngineConfig,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    // Test-only forced-continue (0.6.2 Phase 2): every intercepted call
    // is continued so the kernel-side refusal can be proven. This branch
    // is compiled only with the `force-continue` feature, never in
    // release builds.
    #[cfg(feature = "force-continue")]
    {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, 0, 0, FLAG_CONTINUE);
        }
        if let Some(j) = journal {
            j.net_implicit_record(n, "continue", "forced-continue");
        }
        return;
    }
    #[cfg(not(feature = "force-continue"))]
    {
        let _ = cfg;
    }
    #[allow(unreachable_code)]
    {
        let _ = ();
    }
    let sockfd = n.data.args[0] as i32;
    let nr = n.data.nr;
    let is_listen = nr == libc::SYS_listen as i32;
    let is_bind = nr == libc::SYS_bind as i32;
    // pidfd_getfd takes a pidfd (not a thread id); ID_VALID confirms the
    // pidfd still names the task suspended in this call. The dup fd is
    // the supervisor's own reference to the caller's socket: every
    // operation below acts on that reference (design A).
    let pidfd = open_task_pidfd(n.pid as libc::pid_t, true).ok();
    let dup: Option<OwnedFd> = pidfd
        .as_ref()
        .filter(|_| id_valid(lfd, n.id))
        .and_then(|pidfd| {
            let d = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_getfd,
                    pidfd.as_raw_fd() as i64,
                    sockfd as i64,
                    0u64,
                )
            };
            (d >= 0).then(|| unsafe { OwnedFd::from_raw_fd(d as i32) })
        });
    // `listen` needs no address: perform it on the dup reference,
    // but only after classifying that reference. `listen()` on an
    // unbound socket auto-binds an ephemeral port on the wildcard
    // address in the socket's namespace, so a supervisor-side socket
    // must be refused before listening (I2) — listen on a host socket
    // would open a host port. The answer comes from `verdict_for`
    // after namespace classification (0.6.3: one source for all calls).
    if is_listen {
        let Some(d) = dup else {
            refuse_implicit(lfd, n, libc::EACCES, "netns-unknown", journal);
            return;
        };
        let ns = classify_ns(socket_netns_cookie(d.as_raw_fd()), cfg.supervisor_cookie);
        match listen_plan(ns) {
            ImplicitPlan::Execute => {
                let backlog = n.data.args[1] as i32;
                let rc = unsafe { libc::listen(d.as_raw_fd(), backlog) };
                answer_result(lfd, n, rc, "listen", journal);
            }
            ImplicitPlan::Continue(why) => continue_reply(lfd, n, journal, why),
            ImplicitPlan::Refuse(why) => refuse_implicit(lfd, n, libc::EACCES, why, journal),
        }
        return;
    }
    // `bind`: read the address once into a private buffer and perform an
    // INET/INET6 bind on the dup reference with that copy. The checked
    // object and the acted-on object are the same, so the caller's later
    // changes to its own memory or descriptor cannot change what was
    // decided. The class follows the SOCKET's own domain (SO_DOMAIN), not
    // the caller-written sockaddr family: an AF_UNSPEC address on an INET
    // socket is still a TCP bind.
    if is_bind {
        let addrlen = n.data.args[2] as usize;
        if !(2..=128).contains(&addrlen) {
            refuse_implicit(lfd, n, libc::EINVAL, "bad-addrlen", journal);
            return;
        }
        let buf = match (cfg.reader)(n.pid, n.data.args[1], addrlen) {
            Ok(b) => b,
            Err(_) => {
                refuse_implicit(lfd, n, libc::EACCES, "read-failed", journal);
                return;
            }
        };
        let Some(d) = dup else {
            refuse_implicit(lfd, n, libc::EACCES, "netns-unknown", journal);
            return;
        };
        let ns = classify_ns(socket_netns_cookie(d.as_raw_fd()), cfg.supervisor_cookie);
        let domain = socket_int_opt(d.as_raw_fd(), libc::SO_DOMAIN);
        let sock_type = socket_int_opt(d.as_raw_fd(), libc::SO_TYPE);
        match bind_plan(ns, domain, sock_type) {
            ImplicitPlan::Refuse(why) => {
                refuse_implicit(lfd, n, libc::EACCES, why, journal);
                return;
            }
            ImplicitPlan::Continue(why) => {
                continue_reply(lfd, n, journal, why);
                return;
            }
            ImplicitPlan::Execute => {}
        }
        // I3 low-port parity: the supervisor (creator of the sandbox
        // user namespace) has CAP_NET_BIND_SERVICE over the sandbox
        // netns, the sandboxed task does not. Emulate the caller's
        // result: a port below ip_unprivileged_port_start (read
        // once, default 1024) that the supervisor alone could bind
        // is answered EACCES, exactly as native for the caller. A too
        // short address is passed on: the kernel answers EINVAL itself.
        if low_port_bind_is_privileged(&buf, addrlen, domain.unwrap_or(0) as u16) {
            refuse_implicit(lfd, n, libc::EACCES, "privileged-port", journal);
            return;
        }
        let rc = unsafe {
            libc::bind(
                d.as_raw_fd(),
                buf.as_ptr() as *const libc::sockaddr,
                addrlen as libc::socklen_t,
            )
        };
        answer_result(lfd, n, rc, "bind", journal);
        return;
    }
    // Any other notified non-connect call. Only connect/bind/listen are
    // notified (fast-open sends are answered by the filter), so this is
    // reached only by a call the filter was not meant to notify. 0.6.3:
    // fail closed. The verdict is `ImplicitOther` (Refused) in the table,
    // every hit is journaled, and nothing is handed back to the kernel.
    let cookie = dup
        .as_ref()
        .and_then(|d| socket_netns_cookie(d.as_raw_fd()));
    let ns = classify_ns(cookie, cfg.supervisor_cookie);
    match other_plan(ns) {
        ImplicitPlan::Continue(why) => continue_reply(lfd, n, journal, why),
        ImplicitPlan::Refuse(why) => refuse_implicit(lfd, n, libc::EACCES, why, journal),
        ImplicitPlan::Execute => {
            refuse_implicit(lfd, n, libc::EACCES, "implicit-unexpected-call", journal)
        }
    }
}

/// What `handle_implicit_call` does after classification. Built by pure
/// functions so the decision is unit-testable without a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImplicitPlan {
    /// The supervisor performs the call on its own reference.
    Execute,
    /// The kernel continues the call (only where the table says so).
    Continue(&'static str),
    /// Refuse with EACCES; the string is the journal reason.
    Refuse(&'static str),
}

/// `getsockopt(SOL_SOCKET, opt)` as an int; `None` on any failure.
fn socket_int_opt(fd: i32, opt: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt with an i32 out-buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut v as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<i32>()).then_some(v)
}

/// Namespace gate shared by every implicit class: Host and Unknown are
/// refused whatever the class says.
fn ns_gate(ns: SockNs, host_reason: &'static str) -> Option<ImplicitPlan> {
    match ns {
        SockNs::Sandbox => None,
        SockNs::Host => Some(ImplicitPlan::Refuse(host_reason)),
        SockNs::Unknown => Some(ImplicitPlan::Refuse("netns-unknown")),
    }
}

/// Map a verdict to a plan. `continue_why`/`refuse_why` are the journal
/// reasons for the two non-executing answers.
fn plan_from_verdict(
    class: CallClass,
    continue_why: &'static str,
    refuse_why: &'static str,
) -> ImplicitPlan {
    match verdict_for(class) {
        Answer::SupervisorExecuted => ImplicitPlan::Execute,
        Answer::KernelContinued => ImplicitPlan::Continue(continue_why),
        Answer::Refused | Answer::FilterErrno => ImplicitPlan::Refuse(refuse_why),
    }
}

fn listen_plan(ns: SockNs) -> ImplicitPlan {
    ns_gate(ns, "host-socket-listen").unwrap_or_else(|| {
        plan_from_verdict(CallClass::Listen, "listen-continue", "listen-refused")
    })
}

fn other_plan(ns: SockNs) -> ImplicitPlan {
    ns_gate(ns, "host-socket-implicit").unwrap_or_else(|| {
        plan_from_verdict(
            CallClass::ImplicitOther,
            "implicit-continue",
            "implicit-unexpected-call",
        )
    })
}

/// The bind class from the socket's own domain and type. INET/INET6
/// stream and datagram sockets are `BindInet`; raw INET and every domain
/// other than UNIX, INET, INET6, NETLINK is `BindOtherFamily`.
fn bind_class(domain: i32, sock_type: Option<i32>) -> CallClass {
    match domain {
        libc::AF_UNIX => CallClass::BindUnix,
        libc::AF_NETLINK => CallClass::BindNetlink,
        libc::AF_INET | libc::AF_INET6 => {
            let t = sock_type.map(|t| t & 0xf);
            if t == Some(libc::SOCK_STREAM) || t == Some(libc::SOCK_DGRAM) {
                CallClass::BindInet
            } else {
                CallClass::BindOtherFamily
            }
        }
        _ => CallClass::BindOtherFamily,
    }
}

/// Plan for a `bind` on a socket in namespace `ns`. A socket whose domain
/// cannot be read is refused.
fn bind_plan(ns: SockNs, domain: Option<i32>, sock_type: Option<i32>) -> ImplicitPlan {
    if let Some(p) = ns_gate(ns, "host-socket-bind") {
        return p;
    }
    let Some(domain) = domain else {
        return ImplicitPlan::Refuse("bind-domain-unknown");
    };
    let class = bind_class(domain, sock_type);
    let cont = match class {
        CallClass::BindUnix => "af-unix-bind",
        CallClass::BindNetlink => "netlink-bind",
        _ => "bind-continue",
    };
    plan_from_verdict(class, cont, "bind-other-family")
}

/// True when the port in `buf` is below the privileged port threshold.
/// The sandbox's netns is fresh: `ip_unprivileged_port_start` is per-netns
/// and a new netns starts at 1024. Reading the host's value would
/// mis-emulate in both directions, so use the sandbox value (1024) directly.
fn low_port_bind_is_privileged(buf: &[u8; 128], addrlen: usize, domain: u16) -> bool {
    // Port is at offset 2 for both INET (network order) and INET6. The
    // kernel needs sizeof(sockaddr_in) = 16, or the 24-byte RFC 2133 form
    // of sockaddr_in6, before it reads the port; a shorter address is
    // EINVAL from the kernel, so it is not "privileged" here.
    let min = if domain == libc::AF_INET6 as u16 {
        24
    } else {
        16
    };
    if addrlen < min {
        return false;
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    if port == 0 {
        return false; // ephemeral: never privileged
    }
    port < 1024
}

/// Answer `-errno` (or 0) for a supervisor-executed `listen`/`bind` and
/// journal only refusals (ordinary successes are routine).
fn answer_result(
    lfd: i32,
    n: &Notif,
    rc: i32,
    what: &str,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    let errno = if rc == 0 {
        0
    } else {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    };
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, -errno, 0, 0);
    }
    if errno != 0
        && let Some(j) = journal
    {
        let reason = if what == "listen" {
            "listen-failed"
        } else {
            "bind-failed"
        };
        j.net_implicit_record(n, "refuse", reason);
    }
}

/// Refuse an implicit call with `errno` and journal it.
fn refuse_implicit(
    lfd: i32,
    n: &Notif,
    errno: i32,
    reason: &str,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, -errno, 0, 0);
    }
    if let Some(j) = journal {
        j.net_implicit_record(n, "refuse", reason);
    }
}

#[allow(unreachable_code, unused_variables)]
fn handle_notif(
    lfd: i32,
    n: &mut Notif,
    recv_at: std::time::Instant,
    cfg: &EngineConfig,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    tracker: &Tracked,
    wait_tx: &std::sync::mpsc::SyncSender<Waiting>,
) {
    let deadline = recv_at + std::time::Duration::from_secs(cfg.deadline_s.max(1));
    // The deadline runs from NOTIF_RECV and covers the time spent waiting
    // for a worker: a notification that is already too old is answered
    // ETIMEDOUT without any work.
    if refuse_if_expired(lfd, n, deadline, journal) {
        return;
    }
    // `bind`, `listen` and MSG_FASTOPEN sends are answered by the
    // namespace of their socket (see `handle_implicit_call`); only
    // `connect` carries a sockaddr to parse.
    if n.data.nr != libc::SYS_connect as i32 {
        handle_implicit_call(lfd, n, cfg, journal);
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
    // Force-continue test build: continue everything (Phase 2 proof).
    // Placed after the address read (so the journal target is known)
    // but before any namespace classification or host-socket refusal,
    // so a CONTINUEd connect on *any* socket reaches Landlock.
    #[cfg(feature = "force-continue")]
    {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, 0, 0, FLAG_CONTINUE);
        }
        if let Some(j) = journal {
            j.net_record("continue", "forced-continue", n);
        }
        return;
    }
    #[cfg(not(feature = "force-continue"))]
    {
        let _ = cfg;
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
    // SO_TYPE via pidfd_getfd + getsockopt. I1: ONE pidfd_getfd per
    // notification. Every check (type, state, namespace cookie) and
    // every action (re-connect, supervisor-executed connect, option
    // copy) uses this single OwnedFd, so a sibling thread's dup2
    // between check and action cannot substitute a different socket
    // than the one that was classified.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd as i64, sockfd as i64, 0u64) };
    let dup_owned: Option<OwnedFd> =
        (dup >= 0).then(|| unsafe { OwnedFd::from_raw_fd(dup as i32) });
    let mut is_stream = false;
    let mut already_connected = false;
    let mut already_pending = false;
    let mut already_used = false;
    let mut sock_type = 0i32;
    if let Some(dup_fd) = &dup_owned {
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
        } == 0
            // Only stream sockets: getpeername succeeds on an unconnected
            // netlink socket, which must reach the policy (L109).
            && is_stream;
        // A stream socket whose connect is still in flight: the one an
        // earlier non-blocking connect() put there.
        already_pending = is_stream
            && !already_connected
            && matches!(
                tcp_state(dup_fd.as_raw_fd()),
                Some(TCP_SYN_SENT | TCP_SYN_RECV)
            );
        // A stream socket an earlier connect has ended on without a
        // connection: the one a non-blocking connect() put there, after
        // that connect failed.
        already_used = is_stream
            && !already_connected
            && !already_pending
            && used_and_closed(dup_fd.as_raw_fd());
    }
    // Which netns does the notified socket live in? A socket a program
    // holds is in the sandbox's empty namespace (its own creation, or an
    // approved connect's injection into... see below) or in the
    // supervisor's (an injected socket kept after a failed connect). The
    // loopback/AF_UNIX CONTINUE and the own-socket re-connect are only
    // safe in the empty namespace; `Host` and `Unknown` get the full
    // policy and nothing is continued. Same reference as the state
    // checks above (I1).
    let sock_ns = classify_ns(
        dup_owned
            .as_ref()
            .and_then(|d| socket_netns_cookie(d.as_raw_fd())),
        cfg.supervisor_cookie,
    );
    // 0.6.1: the already-connected / already-pending / already-used
    // answer comes before the private-address verdict, but only for
    // that answer: `connect()` on a socket that is already connected
    // (or pending, or failed) is answered exactly as the kernel would
    // (EISCONN / EALREADY / the pending error), whatever its *new*
    // target — including a private one. A fresh socket to a private
    // address is still refused EACCES below. Nothing is injected on
    // any of these paths.
    if already_connected {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EISCONN), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "already-connected", n);
        }
        return;
    }
    if already_pending {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EALREADY), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "already-pending", n);
        }
        return;
    }
    let off_sandbox = matches!(sock_ns, SockNs::Host | SockNs::Unknown);
    if off_sandbox && !already_used {
        // A socket outside the sandbox namespace that is neither
        // connected, pending nor failed has no approved connection: it
        // serves nothing (invariant a).
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -(libc::EACCES), 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "host-socket-connect", n);
        }
        return;
    }
    if already_used {
        // (a) A supervisor-side socket that failed is answered on the
        // program's own socket as in 0.6.0, but only for a target the
        // full policy approves: the re-connect is made by the
        // supervisor in its own namespace, so loopback, private and
        // unlisted targets are refused here.
        if off_sandbox {
            let public = ip.map(|a| is_public_ip(&a)).unwrap_or(false);
            let class = classify_connect(family, is_loopback, is_stream, public, sock_ns);
            let answer = verdict_for(class);
            if !matches!(answer, Answer::SupervisorExecuted) {
                let reason = if is_loopback || family == libc::AF_UNIX as u16 {
                    "host-socket-loopback-or-unix"
                } else {
                    "private-or-unlisted"
                };
                if id_valid(lfd, n.id) {
                    reply(lfd, n.id, -(libc::EACCES), 0, 0);
                }
                if let Some(j) = journal {
                    j.net_record("refuse", reason, n);
                }
                return;
            }
        }
        {
            let rc = match &dup_owned {
                Some(sock) => unsafe {
                    libc::connect(
                        sock.as_raw_fd(),
                        buf.as_ptr() as *const libc::sockaddr,
                        addrlen as libc::socklen_t,
                    )
                },
                None => -1,
            };
            let errno = if rc == 0 {
                0
            } else {
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            };
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -errno, 0, 0);
            }
            if let Some(j) = journal {
                if errno == 0 || errno == libc::EINPROGRESS {
                    j.net_record("allow", "own-socket", n);
                } else {
                    j.net_record("refuse", "earlier-connect-failed", n);
                }
            }
            return;
        }
    }
    // 0.6.2 design A: loopback and AF_UNIX connects on a sandbox socket
    // are now performed by the supervisor itself on its own reference
    // to the caller's socket (pidfd_getfd), with its own copy of the
    // address. The checked object and the acted-on object are the same;
    // Landlock is a second layer, not the only one. A host-side socket
    // must not be continued: it would run in the supervisor's
    // namespace, where loopback reaches host daemons. Apply the full
    // policy instead — for loopback on a host socket that is a refusal
    // (private).
    //
    // Blocking vs non-blocking: the operation is executed on the dup
    // fd, which shares the file status flags with the caller's
    // descriptor (same open file description). A non-blocking program
    // gets EINPROGRESS exactly as native; a blocking program waits in
    // the wait pool (Waiting) — never in the dispatch pool — until the
    // connection is established or failed, then the same reply is
    // sent. If the caller is interrupted by a signal (id_valid
    // false), the reply is suppressed and the dup fd is closed on
    // return: no leaked reference, no stuck wait thread (the wait
    // pool checks id_valid before injecting).
    let continue_allowed = matches!(sock_ns, SockNs::Sandbox);
    let is_public = ip.map(|a| is_public_ip(&a)).unwrap_or(false);
    // Host/unknown socket: the kernel-continue path (AF_UNIX, loopback)
    // is not safe — it would run in the supervisor's namespace. Refuse
    // those targets before classification; the remaining targets fall
    // through to `verdict_for` with the full policy.
    if !continue_allowed && (is_loopback || family == libc::AF_UNIX as u16) {
        refuse(
            lfd,
            n,
            libc::EACCES,
            "host-socket-loopback-or-unix",
            journal,
        );
        return;
    }
    let class = classify_connect(family, is_loopback, is_stream, is_public, sock_ns);
    match verdict_for(class) {
        Answer::KernelContinued => {
            // AF_UNIX (path/abstract) on the sandbox socket: Landlock
            // does not cover AF_UNIX, and the empty namespace is the
            // boundary (design B covers the TCP case at kernel level).
            // The socket is confirmed sandbox-side by cookie, so the
            // continue cannot leave the empty namespace.
            continue_reply(lfd, n, journal, "loopback-or-unix");
        }
        Answer::SupervisorExecuted if matches!(class, CallClass::ConnectLoopbackInet) => {
            // Loopback INET on the sandbox socket: supervisor-executed
            // on the caller's own reference (design A). The single
            // dup_owned reference is the classified object.
            match &dup_owned {
                Some(d) => exec_sandbox_connect(
                    lfd, n, d, sockfd, &buf, addrlen, deadline, journal, wait_tx,
                ),
                None => refuse(lfd, n, libc::EACCES, "flags-unreadable", journal),
            }
        }
        Answer::SupervisorExecuted => {
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
            let new_guard = unsafe { OwnedFd::from_raw_fd(newfd) };
            // Copy options from the program's socket (read once). This
            // also tells whether that socket is non-blocking, which
            // selects the path below. If the flags cannot be read the
            // connect is refused: guessing "blocking" would make a
            // non-blocking program wait, guessing "non-blocking" would
            // hand EINPROGRESS to a program that does not expect it.
            let Some(client_nonblock) = dup_owned
                .as_ref()
                .and_then(|src| copy_sock_opts(src, newfd))
            else {
                refuse(lfd, n, libc::EACCES, "flags-unreadable", journal);
                return;
            };
            // The supervisor's own connect is always non-blocking, so no
            // thread of the dispatch pool ever waits in connect(). Fail
            // closed if the flag cannot be set.
            let flags = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
            let nonblock_ok = flags >= 0
                && unsafe { libc::fcntl(newfd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0;
            if !nonblock_ok {
                refuse(lfd, n, libc::EACCES, "nonblock-failed", journal);
                return;
            }
            let cr = unsafe {
                libc::connect(
                    newfd,
                    buf.as_ptr() as *const libc::sockaddr,
                    addrlen as libc::socklen_t,
                )
            };
            if cr == 0 {
                // Connected at once: inject and reply 0, for a blocking
                // and a non-blocking program alike.
                inject_connected(lfd, n, &new_guard, sockfd, client_nonblock, journal);
                return;
            }
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno != libc::EINPROGRESS {
                // Failed at once: nothing is injected, the program gets
                // the connect's own errno.
                if id_valid(lfd, n.id) {
                    reply(lfd, n.id, -errno, 0, 0);
                }
                if let Some(j) = journal {
                    j.net_record("refuse", "connect-failed", n);
                    if client_nonblock {
                        j.net_connect_result_seated(&target_of(n), "failed", 0, n.seat.as_deref());
                    }
                }
                return;
            }
            if client_nonblock {
                // The program's socket is non-blocking: it gets the
                // connecting socket and EINPROGRESS now, and watches the
                // outcome itself (POLLOUT, SO_ERROR).
                inject_inprogress(lfd, n, new_guard, sockfd, journal, tracker);
                return;
            }
            // The program's socket is blocking: its connect() returns
            // when the connection is established or has failed. That
            // wait happens in the wait pool, never in this (dispatch)
            // pool, so a non-blocking connect is not held up by it.
            let waiting = Waiting {
                n: n.clone(),
                newfd: new_guard,
                sockfd,
                deadline,
                sandbox_connect: false,
                addr: [0; 128],
                addrlen: 0,
            };
            match wait_tx.try_send(waiting) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(w)) => {
                    refuse(lfd, &w.n, libc::EACCES, "queue-full", journal);
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(w)) => {
                    if id_valid(lfd, w.n.id) {
                        reply(lfd, w.n.id, -(libc::EAGAIN), 0, 0);
                    }
                }
            }
        }
        Answer::Refused => {
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
            refuse(lfd, n, libc::EACCES, reason, journal);
        }
        Answer::FilterErrno => {
            unreachable!("FastopenSend is answered by the BPF filter, not notified")
        }
    }
}

/// Supervisor-executed `connect` on the caller's own sandbox socket
/// (0.6.2 design A): the single `pidfd_getfd` reference of this
/// notification is the classified object; `connect` is performed on
/// it with the supervisor's private copy of the address. The
/// namespace of the reference is the sandbox's empty namespace, so
/// the connection stays there — for loopback this is the native
/// result.
///
/// The reference shares O_NONBLOCK with the caller's descriptor
/// (same open file description), so a blocking caller's `connect`
/// would block the dispatch worker. To honour the deadline and
/// keep the dispatch pool free, blocking callers are queued to the
/// wait pool *before* connecting: the wait pool sets O_NONBLOCK on
/// the reference, connects, and waits for POLLOUT. O_NONBLOCK is
/// restored on the reference before the wait pool replies, so the
/// caller's socket keeps its blocking flag throughout.
#[allow(clippy::too_many_arguments)]
fn exec_sandbox_connect(
    lfd: i32,
    n: &Notif,
    dup_fd: &OwnedFd,
    sockfd: i32,
    buf: &[u8; 128],
    addrlen: usize,
    deadline: std::time::Instant,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    wait_tx: &std::sync::mpsc::SyncSender<Waiting>,
) {
    // O_NONBLOCK of the shared description, read once.
    let fl = unsafe { libc::fcntl(dup_fd.as_raw_fd(), libc::F_GETFL) };
    let client_nonblock = fl >= 0 && (fl & libc::O_NONBLOCK != 0);
    if !client_nonblock {
        // Blocking caller: hand the classified reference to the wait
        // pool, which performs the non-blocking connect and waits.
        // No reference is kept by the dispatch worker after this.
        let cloned = match dup_fd.try_clone() {
            Ok(c) => c,
            Err(_) => {
                refuse(lfd, n, libc::EACCES, "flags-unreadable", journal);
                return;
            }
        };
        let waiting = Waiting {
            n: n.clone(),
            newfd: cloned,
            sockfd,
            deadline,
            sandbox_connect: true,
            addr: *buf,
            addrlen,
        };
        match wait_tx.try_send(waiting) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(w)) => {
                refuse(lfd, &w.n, libc::EACCES, "queue-full", journal);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(w)) => {
                if id_valid(lfd, w.n.id) {
                    reply(lfd, w.n.id, -(libc::EAGAIN), 0, 0);
                }
            }
        }
        return;
    }
    let rc = unsafe {
        libc::connect(
            dup_fd.as_raw_fd(),
            buf.as_ptr() as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        )
    };
    if rc == 0 {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, 0, 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("allow", "supervisor-executed", n);
        }
        return;
    }
    let errno = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    if errno != libc::EINPROGRESS {
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, -errno, 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("refuse", "connect-failed", n);
        }
        return;
    }
    // Non-blocking caller (blocking callers took the wait-pool path
    // above): EINPROGRESS now.
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, -(libc::EINPROGRESS), 0, 0);
    }
    if let Some(j) = journal {
        j.net_record("allow", "supervisor-executed-inprogress", n);
    }
}

/// A blocking program's connect whose outcome is awaited by the wait
/// pool: the notification, the supervisor's connecting socket, the
/// program's descriptor number and the deadline counted from NOTIF_RECV.
struct Waiting {
    n: Notif,
    newfd: OwnedFd,
    sockfd: i32,
    deadline: std::time::Instant,
    /// True when `newfd` is the caller's own sandbox socket (design A):
    /// on success the reply is 0 with no injection (the socket is
    /// already the caller's); false for a supervisor-host socket that
    /// must be injected.
    sandbox_connect: bool,
    /// Supervisor's private copy of the address for a sandbox
    /// (design A) connect the wait pool performs. Zeroed for host
    /// connects, which are already connecting.
    addr: [u8; 128],
    addrlen: usize,
}

/// The journal target (`ip:port`) of a parsed notification.
fn target_of(n: &Notif) -> String {
    notif_target(n.parsed_ip.as_ref(), n.parsed_family, n.parsed_port)
}

/// Answer `-errno` (if the notification is still valid) and journal
/// `refuse/<reason>`.
fn refuse(
    lfd: i32,
    n: &Notif,
    errno: i32,
    reason: &str,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, -errno, 0, 0);
    }
    if let Some(j) = journal {
        j.net_record("refuse", reason, n);
    }
}

/// Wait-pool side of a blocking program's connect: wait until the
/// supervisor's socket is connected or has failed, at most until the
/// deadline, then inject and reply 0, or reply the connect's errno
/// (ETIMEDOUT at the deadline).
fn finish_blocking(
    lfd: i32,
    w: &Waiting,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    let n = &w.n;
    let newfd = w.newfd.as_raw_fd();
    // Design A blocking sandbox connect: perform the connect here
    // (wait pool), non-blocking on the shared description, then
    // restore the caller's blocking flag before replying. A drop
    // guard restores it on every exit.
    struct Restore {
        fd: i32,
        active: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if self.active {
                let fl = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
                if fl >= 0 {
                    unsafe { libc::fcntl(self.fd, libc::F_SETFL, fl & !libc::O_NONBLOCK) };
                }
            }
        }
    }
    let _restore = w.sandbox_connect.then_some(Restore {
        fd: newfd,
        active: true,
    });
    if w.sandbox_connect {
        let fl = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
        if fl < 0 {
            refuse(lfd, n, libc::EIO, "connect-error", journal);
            return;
        }
        unsafe { libc::fcntl(newfd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        let rc = unsafe {
            libc::connect(
                newfd,
                w.addr.as_ptr() as *const libc::sockaddr,
                w.addrlen as libc::socklen_t,
            )
        };
        let errno0 = if rc == 0 {
            0
        } else {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        };
        if errno0 != 0 && errno0 != libc::EINPROGRESS {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -errno0, 0, 0);
            }
            if let Some(j) = journal {
                j.net_record("refuse", "connect-failed", n);
            }
            return;
        }
        if rc == 0 {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, 0, 0, 0);
            }
            if let Some(j) = journal {
                j.net_record("allow", "supervisor-executed", n);
            }
            return;
        }
        // EINPROGRESS: fall through to the poll wait below.
    }
    // For a sandbox connect the socket is the caller's own, so
    // SO_ERROR is NOT the supervisor's alone: a second connect()
    // returns the pending result with native cleanup, instead of
    // consuming SO_ERROR. Poll first, then re-connect.
    if w.sandbox_connect {
        let mut done = false;
        while std::time::Instant::now() < w.deadline {
            let mut pfd = libc::pollfd {
                fd: newfd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if pr < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                refuse(lfd, n, libc::EIO, "connect-error", journal);
                return;
            }
            if pr <= 0 {
                if !id_valid(lfd, n.id) {
                    return;
                }
                continue;
            }
            // POLLOUT: call connect again: 0 = established, errno =
            // the failure (with native state reset).
            let rc2 = unsafe {
                libc::connect(
                    newfd,
                    w.addr.as_ptr() as *const libc::sockaddr,
                    w.addrlen as libc::socklen_t,
                )
            };
            if rc2 == 0 {
                done = true;
            } else {
                let e2 = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                // EISCONN: the handshake completed between the poll and
                // the second connect — this is success, not an error.
                // EALREADY: the handshake is still in flight (the kernel
                // returns EALREADY, not EINPROGRESS, for a repeated connect
                // on a blocking socket that was made non-blocking).
                if e2 == libc::EISCONN {
                    done = true;
                } else if e2 == libc::EINPROGRESS || e2 == libc::EALREADY {
                    continue;
                } else {
                    if id_valid(lfd, n.id) {
                        reply(lfd, n.id, -e2, 0, 0);
                    }
                    if let Some(j) = journal {
                        j.net_record("refuse", "connect-error", n);
                    }
                    return;
                }
            }
            break;
        }
        if !done {
            // Disconnect before replying ETIMEDOUT, so the socket
            // is not left connecting (native: a timed-out blocking
            // connect leaves the socket unusable for re-connect).
            let unspec: libc::sockaddr = unsafe { std::mem::zeroed() };
            unsafe {
                libc::connect(
                    newfd,
                    &unspec as *const _,
                    std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t,
                )
            };
            refuse(lfd, n, libc::ETIMEDOUT, "deadline", journal);
            return;
        }
        if id_valid(lfd, n.id) {
            reply(lfd, n.id, 0, 0, 0);
        }
        if let Some(j) = journal {
            j.net_record("allow", "supervisor-executed", n);
        }
        return;
    }
    let mut done = false;
    while std::time::Instant::now() < w.deadline {
        let mut pfd = libc::pollfd {
            fd: newfd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if pr < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            // poll itself failed: do not retry until the deadline,
            // answer now.
            refuse(lfd, n, libc::EIO, "connect-error", journal);
            return;
        }
        if pr <= 0 {
            // Still connecting. If the task has gone away meanwhile
            // (killed, or the session is ending), nobody waits for this
            // socket: stop now instead of holding the thread until the
            // deadline.
            if !id_valid(lfd, n.id) {
                return;
            }
            continue;
        }
        // This socket is still the supervisor's alone (nothing was
        // injected yet), so reading SO_ERROR takes nothing away from
        // the program.
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
            refuse(lfd, n, err, "connect-error", journal);
            return;
        }
        break;
    }
    if !done {
        refuse(lfd, n, libc::ETIMEDOUT, "deadline", journal);
        return;
    }
    inject_connected(lfd, n, &w.newfd, w.sockfd, false, journal);
}

/// The `seccomp_notif_addfd` that puts `newfd` at the program's own
/// descriptor number (`args[0]`, SETFD), carrying over the close-on-exec
/// flag of the descriptor it replaces: a socket opened with SOCK_CLOEXEC
/// must not start leaking into programs the task executes.
fn addfd_for(n: &Notif, newfd: i32, sockfd: i32) -> NotifAddFd {
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
    addfd
}

/// Inject a connected socket and answer 0. `client_nonblock` is the
/// O_NONBLOCK state of the program's socket, restored on the injected
/// one (the supervisor's connect forced O_NONBLOCK on).
fn inject_connected(
    lfd: i32,
    n: &Notif,
    newfd: &OwnedFd,
    sockfd: i32,
    client_nonblock: bool,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
) {
    let newfd = newfd.as_raw_fd();
    let nf = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
    if nf >= 0 {
        let want = if client_nonblock {
            nf | libc::O_NONBLOCK
        } else {
            nf & !libc::O_NONBLOCK
        };
        unsafe { libc::fcntl(newfd, libc::F_SETFL, want) };
    }
    // Inject: ID_VALID before ADDFD. Two-step SETFD + NOTIF_SEND (val=0)
    // so the program's connect() returns 0, not the fd number.
    if !id_valid(lfd, n.id) {
        return;
    }
    let mut addfd = addfd_for(n, newfd, sockfd);
    match seccomp_ioctl(lfd, OP_ADDFD, &mut addfd as *mut NotifAddFd as *mut _) {
        Ok(()) => {
            let sent = send_reply(lfd, n.id, 0, 0, 0);
            if let Some(j) = journal {
                let reason = if sent.is_ok() {
                    "injected"
                } else {
                    "injected-reply-failed"
                };
                j.net_record("allow", reason, n);
            }
        }
        Err(e) => {
            if id_valid(lfd, n.id) {
                reply(lfd, n.id, -(e.raw_os_error().unwrap_or(libc::EIO)), 0, 0);
            }
        }
    }
    // The caller's OwnedFd closes the supervisor's copy of the socket
    // (the injected copy is the program's now).
}

/// Non-blocking program, supervisor connect in progress: inject the
/// connecting socket at the program's descriptor number, then answer
/// EINPROGRESS. EINPROGRESS is sent only after the injection succeeded:
/// without the replacement socket the program would poll an unconnected
/// socket forever. If the injection fails the answer is EACCES and the
/// supervisor's socket is closed.
///
/// After the answer the supervisor's own descriptor of that socket goes
/// to the tracker, which journals how the connect ended.
fn inject_inprogress(
    lfd: i32,
    n: &Notif,
    newfd: OwnedFd,
    sockfd: i32,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    tracker: &Tracked,
) {
    // The socket is non-blocking already (the supervisor's connect
    // forced the flag on), which is what the program's socket was.
    if !id_valid(lfd, n.id) {
        return;
    }
    let mut addfd = addfd_for(n, newfd.as_raw_fd(), sockfd);
    if seccomp_ioctl(lfd, OP_ADDFD, &mut addfd as *mut NotifAddFd as *mut _).is_err() {
        // Nothing was injected. `newfd` is closed when it goes out of
        // scope.
        refuse(lfd, n, libc::EACCES, "addfd-failed", journal);
        return;
    }
    if send_reply(lfd, n.id, -(libc::EINPROGRESS), 0, 0).is_err() {
        // The socket is in the task, but the answer did not reach it
        // (the task was killed, or a signal ended the call). Nothing is
        // tracked; the supervisor's descriptor is closed on return. A
        // restarted connect() finds the socket connecting and gets
        // EALREADY.
        if let Some(j) = journal {
            j.net_record("allow", "injected-reply-failed", n);
        }
        return;
    }
    if let Some(j) = journal {
        j.net_record("allow", "injected-inprogress", n);
    }
    tracker.slot_seated(newfd, target_of(n), n.seat.clone());
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

// ---- open-mode hardening: which namespace a socket lives in ---------------

/// (device, inode) of a namespace — the identity `fstat` gives and
/// `netns_differs` (supervisor.rs) compares.
type NetnsCookie = u64;

/// Network-namespace cookie of a socket (`SO_NETNS_COOKIE`). `None` on
/// any error (old kernel, not a socket, fd gone): callers fail closed.
/// `SIOCGSKNS` is not used: it needs `CAP_NET_ADMIN` in the namespace's
/// owning user namespace, which the supervisor does not have.
fn socket_netns_cookie(fd: i32) -> Option<NetnsCookie> {
    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    // SAFETY: getsockopt with a u64 out-buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_NETNS_COOKIE,
            &mut cookie as *mut u64 as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<u64>()).then_some(cookie)
}

/// The cookie of the calling process's own network namespace: that of
/// a throwaway socket created here.
fn own_netns_cookie() -> Option<NetnsCookie> {
    // SAFETY: socket() returns a fresh fd or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd is fresh and owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    socket_netns_cookie(fd.as_raw_fd())
}

/// Where a notified socket lives, relative to the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SockNs {
    /// Not the supervisor's namespace: the sandbox's empty namespace
    /// (a program cannot create another one, `CLONE_NEWNET` is denied).
    Sandbox,
    /// The supervisor's namespace: an injected socket the program kept.
    Host,
    /// Either cookie unknown: treated like `Host`, never `Sandbox`.
    Unknown,
}

fn classify_ns(sock: Option<NetnsCookie>, supervisor: Option<NetnsCookie>) -> SockNs {
    match (sock, supervisor) {
        (Some(s), Some(h)) if s == h => SockNs::Host,
        (Some(_), Some(_)) => SockNs::Sandbox,
        _ => SockNs::Unknown,
    }
}

/// 0.6.2 verdict table (I1): for every intercepted call class, the
/// engine's answer and why it is safe. `Continue` is answered only for
/// classes the Landlock TCP rules cover at execution time (design B)
/// or that cannot leave the empty namespace (AF_UNIX on a confirmed
/// sandbox socket). TCP bind/connect/listen on a supervisor-side
/// socket is never continued: it is supervisor-executed (design A)
/// or refused by classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallClass {
    ConnectUnix,
    ConnectLoopbackInet,
    ConnectPublicStream,
    ConnectPrivateOrUnknown,
    BindInet,
    BindUnix,
    /// Bind on an AF_NETLINK socket in the sandbox namespace (0.6.3).
    BindNetlink,
    /// Bind on any other socket domain (0.6.3): refused.
    BindOtherFamily,
    Listen,
    FastopenSend,
    /// Any other notified call that reaches the catch-all (0.6.3): refused.
    ImplicitOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Supervisor performs it on its own reference (design A).
    SupervisorExecuted,
    /// Kernel continues the call; Landlock / empty-netns covers it (B).
    KernelContinued,
    /// Refused (EACCES) by classification.
    Refused,
    /// Answered by the BPF filter itself (design C).
    FilterErrno,
}

pub fn verdict_table() -> &'static [(CallClass, Answer, &'static str)] {
    use Answer::*;
    use CallClass::*;
    &[
        (
            ConnectUnix,
            KernelContinued,
            "AF_UNIX in the empty namespace cannot leave it; Landlock does not cover AF_UNIX",
        ),
        (
            ConnectLoopbackInet,
            SupervisorExecuted,
            "supervisor connects on its own reference to the sandbox socket (A); Landlock second layer (B)",
        ),
        (
            ConnectPublicStream,
            SupervisorExecuted,
            "supervisor host-namespace connect + injection, or re-connect of a failed own socket",
        ),
        (
            ConnectPrivateOrUnknown,
            Refused,
            "policy refusal, journaled",
        ),
        (
            BindInet,
            SupervisorExecuted,
            "supervisor binds on its own reference (A); TCP bind also Landlock-refused at execution time (B)",
        ),
        (
            BindUnix,
            KernelContinued,
            "AF_UNIX bind in the empty namespace cannot leave it (B premise)",
        ),
        (
            BindNetlink,
            KernelContinued,
            "a netlink bind in the empty namespace creates no reachability; getifaddrs, ip and Go's net.Interfaces need it (probe N1)",
        ),
        (
            BindOtherFamily,
            Refused,
            "every other socket domain is refused: nothing else is covered by the empty-namespace argument",
        ),
        (
            Listen,
            SupervisorExecuted,
            "supervisor executes listen on its own reference for every address family after namespace classification (Host/Unknown refused). Landlock covers TCP connect/bind; listen on a host socket is refused by the supervisor (no auto-bind in the supervisor namespace).",
        ),
        (
            FastopenSend,
            FilterErrno,
            "BPF filter answers EOPNOTSUPP; no notification (C)",
        ),
        (
            ImplicitOther,
            Refused,
            "a call the filter was not meant to notify is refused (fail closed), journaled",
        ),
    ]
}

/// The single authority mapping a [`CallClass`] to its [`Answer`].
/// The connect dispatch path in `handle_notif` takes its verdict from
/// this function, which reads the same `verdict_table` that documents
/// the policy. `KernelContinued` is returned only for `ConnectUnix`,
/// `BindUnix` and `BindNetlink`. Since 0.6.3 `handle_implicit_call` takes
/// its answer for bind, listen and the catch-all from this function too
/// (through `bind_plan`, `listen_plan`, `other_plan`), after the socket's
/// namespace was classified: Host and Unknown sockets are refused whatever
/// the class says.
fn verdict_for(class: CallClass) -> Answer {
    verdict_table()
        .iter()
        .find(|(c, _, _)| *c == class)
        .map(|(_, a, _)| *a)
        .expect("verdict_table must cover every CallClass")
}

/// Classify a `connect` notification into its [`CallClass`], using the
/// same inputs as [`decide`] plus the socket's namespace. A host/unknown
/// socket is never `KernelContinued`: AF_UNIX and loopback on a host
/// socket map to `ConnectPrivateOrUnknown` (refused).
fn classify_connect(
    family: u16,
    is_loopback: bool,
    is_stream: bool,
    is_public: bool,
    sock_ns: SockNs,
) -> CallClass {
    use libc::{AF_INET, AF_INET6, AF_UNIX};
    let off_sandbox = matches!(sock_ns, SockNs::Host | SockNs::Unknown);
    if off_sandbox {
        // Host/unknown socket: no KernelContinued. Only a public-stream
        // connect is allowed (re-connect of a failed own socket).
        if is_stream && is_public && !is_loopback && family != AF_UNIX as u16 {
            return CallClass::ConnectPublicStream;
        }
        return CallClass::ConnectPrivateOrUnknown;
    }
    if family == AF_UNIX as u16 {
        return CallClass::ConnectUnix;
    }
    if is_loopback {
        return CallClass::ConnectLoopbackInet;
    }
    if is_stream && is_public && (family == AF_INET as u16 || family == AF_INET6 as u16) {
        return CallClass::ConnectPublicStream;
    }
    CallClass::ConnectPrivateOrUnknown
}

/// The single place in the engine that builds a "continue" response
/// (`FLAG_CONTINUE`). In `handle_notif` it is called only when
/// `verdict_for` returns `KernelContinued` (connect dispatch).
/// In `handle_implicit_call` it is called only for a plan built from
/// `verdict_for` on a `SockNs::Sandbox` socket (AF_UNIX and AF_NETLINK
/// bind). The gate check
/// in `scripts/release-gate.sh` fails if a second `FLAG_CONTINUE` site
/// appears outside this function and outside `cfg(feature =
/// "force-continue")` blocks.
fn continue_reply(
    lfd: i32,
    n: &Notif,
    journal: &Option<std::sync::Arc<crate::journal::Journal>>,
    reason: &str,
) {
    if id_valid(lfd, n.id) {
        reply(lfd, n.id, 0, 0, FLAG_CONTINUE);
    }
    if let Some(j) = journal {
        j.net_record("continue", reason, n);
    }
}

fn copy_sock_opts(src_fd: &OwnedFd, newfd: i32) -> Option<bool> {
    let src = src_fd;
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

/// Format the connect address read from the notification for the journal:
/// `ip:port` for INET, or the raw family for other families (`family:2`).
/// This is the only target form — never a pid/nr (see ADR 0022 L102).
/// Name of an intercepted syscall for the journal (`network/implicit`
/// target); anything else keeps the `nr:<n>` form.
pub fn syscall_name(nr: i32) -> String {
    let n = nr as libc::c_long;
    let name = if n == libc::SYS_connect {
        "connect"
    } else if n == libc::SYS_bind {
        "bind"
    } else if n == libc::SYS_listen {
        "listen"
    } else if n == libc::SYS_sendto {
        "sendto"
    } else if n == libc::SYS_sendmsg {
        "sendmsg"
    } else if n == libc::SYS_sendmmsg {
        "sendmmsg"
    } else {
        return format!("nr:{nr}");
    };
    name.to_string()
}

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
    #[test]
    fn syscall_names_for_implicit_records() {
        use super::syscall_name;
        assert_eq!(syscall_name(libc::SYS_bind as i32), "bind");
        assert_eq!(syscall_name(libc::SYS_listen as i32), "listen");
        assert_eq!(syscall_name(libc::SYS_sendto as i32), "sendto");
        assert_eq!(syscall_name(libc::SYS_sendmsg as i32), "sendmsg");
        assert_eq!(syscall_name(libc::SYS_sendmmsg as i32), "sendmmsg");
        assert_eq!(
            syscall_name(libc::SYS_read as i32),
            format!("nr:{}", libc::SYS_read)
        );
    }
    // ---- 0.6.1 seat ancestry walk (fake /proc) ----
    struct FakeProc(std::collections::HashMap<i32, ProcStatus>);
    impl ProcReader for FakeProc {
        fn status(&self, tid: i32) -> Option<ProcStatus> {
            self.0.get(&tid).cloned()
        }
    }
    /// task: (key id as seen by supervisor, tgid, ppid, nspid)
    fn fake(tasks: &[(i32, i32, i32, &[i32])]) -> FakeProc {
        FakeProc(
            tasks
                .iter()
                .map(|(id, tgid, ppid, ns)| {
                    (
                        *id,
                        ProcStatus {
                            tgid: *tgid,
                            ppid: *ppid,
                            nspid: ns.to_vec(),
                        },
                    )
                })
                .collect(),
        )
    }
    fn exec_table(top: i32) -> impl Fn(i32) -> Option<Option<String>> {
        move |p| (p == top).then(|| Some("member1".to_string()))
    }
    // supervisor ns depth 1, sandbox level 2. Host ids 100.. map to
    // sandbox pids: init 100->1, exec top 150->7.
    const INIT: (i32, i32, i32, &[i32]) = (100, 100, 90, &[100, 1]);

    #[test]
    fn seat_walk_direct_exec_pid_thread_child_grandchild() {
        let p = fake(&[
            INIT,
            (150, 150, 100, &[150, 7]),
            (151, 150, 100, &[151, 8]),  // second thread of the exec
            (160, 160, 150, &[160, 9]),  // child
            (170, 170, 160, &[170, 10]), // grandchild
        ]);
        let l = exec_table(7);
        for tid in [150, 151, 160, 170] {
            assert_eq!(
                resolve_seat(&p, tid, 2, &l).as_deref(),
                Some("member1"),
                "{tid}"
            );
        }
    }

    #[test]
    fn seat_walk_main_command_and_reparented_are_null() {
        let p = fake(&[
            INIT,
            (120, 120, 100, &[120, 3]), // main command tree
            (150, 150, 100, &[150, 7]),
            (180, 180, 100, &[180, 11]), // detached: reparented to init
        ]);
        let l = exec_table(7);
        assert_eq!(resolve_seat(&p, 120, 2, &l), None);
        assert_eq!(resolve_seat(&p, 180, 2, &l), None);
        assert_eq!(resolve_seat(&p, 100, 2, &l), None);
    }

    #[test]
    fn seat_walk_loop_too_deep_and_unreadable_are_null() {
        let l = exec_table(7);
        // cycle between two tasks
        let p = fake(&[(200, 200, 201, &[200, 20]), (201, 201, 200, &[201, 21])]);
        assert_eq!(resolve_seat(&p, 200, 2, &l), None);
        // too deep: a chain of 70 tasks, exec top above the limit
        let mut v: Vec<(i32, i32, i32, Vec<i32>)> = Vec::new();
        for i in 0..70 {
            v.push((300 + i, 300 + i, 301 + i, vec![300 + i, 20 + i]));
        }
        v.push((370, 370, 100, vec![370, 7]));
        let m = FakeProc(
            v.into_iter()
                .map(|(a, b, c, d)| {
                    (
                        a,
                        ProcStatus {
                            tgid: b,
                            ppid: c,
                            nspid: d,
                        },
                    )
                })
                .collect(),
        );
        assert_eq!(resolve_seat(&m, 300, 2, &l), None);
        // unreadable status of the task and of an ancestor
        let p = fake(&[(150, 150, 160, &[150, 7])]);
        assert_eq!(resolve_seat(&p, 999, 2, &l), None);
        assert_eq!(resolve_seat(&p, 150, 2, &exec_table(8)), None);
    }

    #[test]
    fn seat_walk_ignores_nested_pid_namespaces_and_exited_exec_entry() {
        // A task in a pid ns the program made (depth 3) whose inner pid
        // equals the exec top pid is not the exec.
        let p = fake(&[
            INIT,
            (150, 150, 100, &[150, 5]),
            (160, 160, 150, &[160, 7, 1]),
        ]);
        assert_eq!(resolve_seat(&p, 160, 2, &exec_table(7)), None);
        // exec entry removed (lookup returns None): null.
        assert_eq!(resolve_seat(&p, 150, 2, &|_| None), None);
        // an exec whose client has no seat stays null
        let q = fake(&[INIT, (150, 150, 100, &[150, 7])]);
        assert_eq!(
            resolve_seat(&q, 150, 2, &|p| (p == 7).then_some(None)),
            None
        );
    }

    #[test]
    fn proc_status_parses_the_fields_the_walk_needs() {
        let t = "Name:\tx\nTgid:\t12\nPid:\t13\nPPid:\t4\nNSpid:\t13\t5\n";
        assert_eq!(
            parse_proc_status(t),
            Some(ProcStatus {
                tgid: 12,
                ppid: 4,
                nspid: vec![13, 5]
            })
        );
        assert_eq!(parse_proc_status("Tgid:\t1\n"), None);
    }

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

    /// Engine config for tests: every test socket lives in the test's own
    /// network namespace, so a supervisor cookie that matches no
    /// namespace makes them sandbox-side, as in production.
    fn sandbox_cfg(deadline_s: u64) -> EngineConfig {
        EngineConfig {
            supervisor_cookie: Some(u64::MAX),
            ..EngineConfig::new(deadline_s)
        }
    }

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
        let engine = NotifEngine::start_with(listener, Some(j.clone()), sandbox_cfg(5));
        assert_eq!(child_exit(pid), 1, "one connect, connected");
        drop(engine);
        // 0.6.2: loopback INET is supervisor-executed (design A).
        assert_eq!(
            connect_records(&d, &j),
            [(
                "allow".to_owned(),
                "supervisor-executed".to_owned(),
                format!("127.0.0.1:{port}")
            )]
        );
    }

    // ---- completion tracking ---------------------------------------------

    /// A non-blocking loopback socket whose connect to `port` has been
    /// started, and the errno connect() returned.
    fn nonblocking_connect(port: u16) -> (OwnedFd, i32) {
        // SAFETY: plain socket + connect on a fresh fd.
        unsafe {
            let s = libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            );
            assert!(s >= 0);
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = libc::INADDR_LOOPBACK.to_be();
            addr.sin_port = port.to_be();
            let rc = libc::connect(
                s,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let errno = if rc == 0 {
                0
            } else {
                *libc::__errno_location()
            };
            (OwnedFd::from_raw_fd(s), errno)
        }
    }

    fn wait_writable(fd: &OwnedFd, ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
    }

    fn so_error(fd: &OwnedFd) -> i32 {
        let mut err = -1i32;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut i32 as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        err
    }

    /// A loopback port nothing listens on.
    fn closed_port() -> u16 {
        let (l, port) = loopback_listener();
        drop(l);
        port
    }

    /// `(target, result)` of every network/connect-result record.
    fn result_records(d: &tempfile::TempDir, j: &crate::journal::Journal) -> Vec<(String, String)> {
        assert!(j.net_flush(std::time::Duration::from_secs(10)));
        let (records, _) = crate::journal::read_records(&d.path().join("ws"));
        records
            .iter()
            .filter(|r| r.kind == "network/connect-result")
            .map(|r| {
                (
                    r.data["target"].as_str().unwrap_or("").to_owned(),
                    r.data["result"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    }

    /// A loopback listener whose accept queue is full, so that a further
    /// connect stays in SYN_SENT (the kernel drops its SYN), and the
    /// filler sockets that keep the queue full.
    fn saturated_listener() -> (std::net::TcpListener, u16, Vec<OwnedFd>) {
        // SAFETY: socket/bind/listen on a fresh fd; backlog 0.
        let l = unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(s >= 0);
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = libc::INADDR_LOOPBACK.to_be();
            let alen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            assert_eq!(
                libc::bind(s, &addr as *const _ as *const libc::sockaddr, alen),
                0
            );
            assert_eq!(libc::listen(s, 0), 0);
            <std::net::TcpListener as std::os::fd::FromRawFd>::from_raw_fd(s)
        };
        let port = l.local_addr().unwrap().port();
        let mut fill = Vec::new();
        for _ in 0..4 {
            let (fd, _) = nonblocking_connect(port);
            wait_writable(&fd, 200);
            fill.push(fd);
        }
        (l, port, fill)
    }

    #[test]
    fn tracking_a_refused_connect_leaves_so_error_to_the_program() {
        // The tracker holds a duplicate of the program's socket. After it
        // has settled the connect as `failed`, the program's own SO_ERROR
        // must still be ECONNREFUSED.
        let (d, j) = engine_journal();
        let (program, errno) = nonblocking_connect(closed_port());
        assert_eq!(errno, libc::EINPROGRESS);
        assert!(wait_writable(&program, 5000));
        let tracker = Tracked::default();
        let dup = program.try_clone().unwrap();
        let dup_fd = dup.as_raw_fd();
        assert!(tracker.slot_seated(dup, "t:1".into(), None));
        let settled = tracker.sweep(&[dup_fd], std::time::Duration::from_secs(30), Some(&*j));
        assert_eq!(settled, 1);
        assert!(tracker.is_empty());
        assert_eq!(so_error(&program), libc::ECONNREFUSED);
        assert_eq!(
            result_records(&d, &j),
            [("t:1".to_owned(), "failed".to_owned())]
        );
    }

    #[test]
    fn tracking_reports_connected_and_closes_only_its_own_descriptor() {
        let (l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (program, errno) = nonblocking_connect(port);
        assert!(errno == 0 || errno == libc::EINPROGRESS, "errno {errno}");
        assert!(wait_writable(&program, 5000));
        let tracker = Tracked::default();
        let dup = program.try_clone().unwrap();
        let dup_fd = dup.as_raw_fd();
        assert!(tracker.slot_seated(dup, "t:2".into(), None));
        tracker.sweep(&[dup_fd], std::time::Duration::from_secs(30), Some(&*j));
        assert!(tracker.is_empty());
        assert_eq!(
            result_records(&d, &j),
            [("t:2".to_owned(), "connected".to_owned())]
        );
        // The tracker closed its duplicate; the program's socket works.
        assert_eq!(so_error(&program), 0);
        let (mut peer, _) = l.accept().unwrap();
        std::io::Write::write_all(&mut peer, b"x").unwrap();
        let mut byte = [0u8; 1];
        let mut pfd = libc::pollfd {
            fd: program.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut pfd, 1, 5000) } > 0);
        let got = unsafe { libc::read(program.as_raw_fd(), byte.as_mut_ptr() as *mut _, 1) };
        assert_eq!((got, byte[0]), (1, b'x'));
    }

    #[test]
    fn a_connection_closed_before_tracking_looks_is_still_connected() {
        // The program connects, is done and closes within milliseconds;
        // the socket (kept alive by the tracker's duplicate) is then in
        // the same TCP state as after a refused connect. It was
        // connected and must be recorded so.
        let (l, port) = loopback_listener();
        let (program, _) = nonblocking_connect(port);
        assert!(wait_writable(&program, 5000));
        let dup = program.try_clone().unwrap();
        let (peer, _) = l.accept().unwrap();
        unsafe { libc::shutdown(program.as_raw_fd(), libc::SHUT_RDWR) };
        drop(program);
        drop(peer);
        for _ in 0..100 {
            if tcp_state(dup.as_raw_fd()) == Some(TCP_CLOSE) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            tcp_state(dup.as_raw_fd()),
            Some(TCP_CLOSE),
            "precondition: the closed connection reads as TCP_CLOSE"
        );
        assert_eq!(conn_state(dup.as_raw_fd(), true), ConnState::Connected);
        // A refused connect, in the same TCP state, is Failed.
        let (refused, _) = nonblocking_connect(closed_port());
        assert!(wait_writable(&refused, 5000));
        assert_eq!(tcp_state(refused.as_raw_fd()), Some(TCP_CLOSE));
        assert_eq!(conn_state(refused.as_raw_fd(), true), ConnState::Failed);
    }

    #[test]
    fn a_socket_whose_connect_failed_is_told_from_a_fresh_one() {
        let (failed, errno) = nonblocking_connect(closed_port());
        assert_eq!(errno, libc::EINPROGRESS);
        assert!(wait_writable(&failed, 5000));
        assert!(used_and_closed(failed.as_raw_fd()));
        let fresh =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let fresh = unsafe { OwnedFd::from_raw_fd(fresh) };
        assert!(!used_and_closed(fresh.as_raw_fd()));
        let (l, port) = loopback_listener();
        let (connected, _) = nonblocking_connect(port);
        assert!(wait_writable(&connected, 5000));
        assert!(!used_and_closed(connected.as_raw_fd()));
        drop(l);
        // The check itself leaves the pending error to the program.
        assert_eq!(so_error(&failed), libc::ECONNREFUSED);
    }

    #[test]
    fn adding_a_tracked_socket_wakes_the_receiver() {
        let tracker = Tracked::default();
        let mut pfd = libc::pollfd {
            fd: tracker.wake_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 0);
        let (a, _b) = crate::sys::socketpair_seqpacket().unwrap();
        assert!(tracker.slot_seated(a, "t".into(), None));
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);
        tracker.drain_wake();
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 0);
    }

    #[test]
    fn tracking_expires_a_pending_connect_at_the_deadline() {
        let (_l, port, _fill) = saturated_listener();
        let (d, j) = engine_journal();
        let (program, errno) = nonblocking_connect(port);
        assert_eq!(errno, libc::EINPROGRESS);
        assert_eq!(
            tcp_state(program.as_raw_fd()),
            Some(TCP_SYN_SENT),
            "precondition: the connect must be pending (accept queue full)"
        );
        let tracker = Tracked::default();
        let dup = program.try_clone().unwrap();
        let dup_fd = dup.as_raw_fd();
        assert!(tracker.slot_seated(dup, "t:3".into(), None));
        let deadline = std::time::Duration::from_millis(300);
        // Before the deadline, without an event: stays tracked.
        assert_eq!(tracker.sweep(&[], deadline, Some(&*j)), 0);
        // A spurious event while still connecting: stays tracked, but is
        // no longer polled.
        assert_eq!(tracker.sweep(&[dup_fd], deadline, Some(&*j)), 0);
        assert_eq!(tracker.len(), 1);
        assert!(tracker.pollfds().is_empty());
        std::thread::sleep(std::time::Duration::from_millis(350));
        assert_eq!(tracker.sweep(&[], deadline, Some(&*j)), 1);
        assert!(tracker.is_empty());
        assert_eq!(
            result_records(&d, &j),
            [("t:3".to_owned(), "pending-at-deadline".to_owned())]
        );
        // The program's socket is untouched: still connecting.
        assert_eq!(tcp_state(program.as_raw_fd()), Some(TCP_SYN_SENT));
    }

    #[test]
    fn tracker_is_bounded_and_counts_overflow() {
        let overflow = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut tracker = Tracked::with_overflow(overflow.clone());
        tracker.cap = 2;
        let sock = || {
            let (a, _b) = crate::sys::socketpair_seqpacket().unwrap();
            a
        };
        assert!(tracker.slot_seated(sock(), "a".into(), None));
        assert!(tracker.slot_seated(sock(), "b".into(), None));
        assert!(!tracker.slot_seated(sock(), "c".into(), None));
        assert!(!tracker.slot_seated(sock(), "d".into(), None));
        assert_eq!(tracker.len(), 2);
        assert_eq!(overflow.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn stopping_an_engine_closes_its_tracked_sockets() {
        // An engine is dropped while it still tracks a socket: the drop
        // returns promptly and the socket is closed (its peer sees EOF).
        let (pid, listener) = connecting_child(0, 1);
        let engine = NotifEngine::start_with(listener, None, sandbox_cfg(30));
        let (tracked, peer) = crate::sys::socketpair_seqpacket().unwrap();
        assert!(engine.tracker.slot_seated(tracked, "t:4".into(), None));
        let t = std::time::Instant::now();
        drop(engine);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "stop with a tracked socket took {:?}",
            t.elapsed()
        );
        let mut pfd = libc::pollfd {
            fd: peer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut pfd, 1, 2000) } > 0);
        assert_ne!(pfd.revents & libc::POLLHUP, 0, "tracked socket not closed");
        assert_eq!(child_exit(pid), 0);
    }

    #[test]
    fn pending_and_connected_program_sockets_are_told_apart() {
        // What the engine reads from the program's socket before it
        // decides: SYN_SENT is "connect pending" (EALREADY), a fresh
        // socket is not.
        let (_l, port, _fill) = saturated_listener();
        let (pending, errno) = nonblocking_connect(port);
        assert_eq!(errno, libc::EINPROGRESS);
        assert_eq!(tcp_state(pending.as_raw_fd()), Some(TCP_SYN_SENT));
        assert_eq!(conn_state(pending.as_raw_fd(), false), ConnState::Pending);
        let fresh =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let fresh = unsafe { OwnedFd::from_raw_fd(fresh) };
        assert_eq!(tcp_state(fresh.as_raw_fd()), Some(TCP_CLOSE));
        let udp = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        let udp = unsafe { OwnedFd::from_raw_fd(udp) };
        assert_eq!(tcp_state(udp.as_raw_fd()), None);
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
            ..sandbox_cfg(5)
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
        let engine = NotifEngine::start_with(listener, None, sandbox_cfg(30));
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
            ..sandbox_cfg(1)
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
            ..sandbox_cfg(5)
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
        // 0.6.2: loopback INET is supervisor-executed (allow).
        let cont = records.iter().filter(|r| r.0 == "allow").count();
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
    fn op_constants_match_the_header_bit_patterns() {
        // The constants are u32 bit patterns; each must equal the
        // SECCOMP_IOCTL_NOTIF_* value from linux/seccomp.h.
        //   RECV = _IOWR('!', 0, 80) = 0xC050_2100
        //   SEND = _IOWR('!', 1, 24) = 0xC018_2101
        //   ID_VALID = _IOR  ('!', 2, 8) = 0x8008_2102
        //   ADDFD = _IOW ('!', 3, 24) = 0x4018_2103
        assert_eq!(OP_RECV, 0xC050_2100);
        assert_eq!(OP_SEND, 0xC018_2101);
        assert_eq!(OP_ID_VALID, 0x8008_2102);
        assert_eq!(OP_ADDFD, 0x4018_2103);
        // The bit pattern must survive the cast to libc::Ioctl
        // (c_ulong on glibc, c_int on musl): casting back to u32
        // must give the same value.
        assert_eq!(OP_RECV as libc::Ioctl as u32, OP_RECV);
        assert_eq!(OP_SEND as libc::Ioctl as u32, OP_SEND);
        assert_eq!(OP_ID_VALID as libc::Ioctl as u32, OP_ID_VALID);
        assert_eq!(OP_ADDFD as libc::Ioctl as u32, OP_ADDFD);
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

    /// Evaluate a classic-BPF seccomp program on `(arch, nr, args)`,
    /// returning its verdict. Supports exactly the opcodes the filter
    /// may contain and panics on any other, on a jump out of range, and
    /// on a program that runs off its end.
    fn run_bpf(prog: &[libc::sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let load = |off: u32| -> u32 {
            match off {
                0 => nr,
                4 => arch,
                16..=63 if off.is_multiple_of(8) => args[((off - 16) / 8) as usize] as u32,
                _ => panic!("load at unexpected offset {off}"),
            }
        };
        let (mut pc, mut acc) = (0usize, 0u32);
        for _ in 0..prog.len() + 1 {
            let i = prog.get(pc).expect("program ran off its end");
            match i.code {
                0x20 => {
                    acc = load(i.k);
                    pc += 1;
                }
                0x15 => pc += 1 + if acc == i.k { i.jt } else { i.jf } as usize,
                0x45 => pc += 1 + if acc & i.k != 0 { i.jt } else { i.jf } as usize,
                0x06 => return i.k,
                c => panic!("unexpected opcode {c:#x} at {pc}"),
            }
        }
        panic!("program loops");
    }

    #[test]
    fn filter_verdicts_by_interpretation() {
        let f = connect_filter();
        let fast = libc::MSG_FASTOPEN as u64;
        let v = |nr: i64, args: [u64; 6]| run_bpf(&f, NATIVE_ARCH, nr as u32, args);
        let none = [0u64; 6];
        // Intercepted.
        for nr in [libc::SYS_connect, libc::SYS_bind, libc::SYS_listen] {
            assert_eq!(v(nr, none), libc::SECCOMP_RET_USER_NOTIF, "nr {nr}");
        }
        // sendto(fd, buf, len, flags, ..) and sendmmsg(fd, msgs, vlen, flags):
        // flags is arg 3; sendmsg(fd, msg, flags): flags is arg 2.
        // 0.6.2 (C): answered ERRNO(EOPNOTSUPP) by the filter itself.
        let errno_ret = libc::SECCOMP_RET_ERRNO | libc::EOPNOTSUPP as u32;
        let mut a3 = none;
        a3[3] = fast | libc::MSG_NOSIGNAL as u64;
        let mut a2 = none;
        a2[2] = fast;
        assert_eq!(v(libc::SYS_sendto, a3), errno_ret);
        assert_eq!(v(libc::SYS_sendmmsg, a3), errno_ret);
        assert_eq!(v(libc::SYS_sendmsg, a2), errno_ret);
        // The same calls without MSG_FASTOPEN, and with it in the
        // wrong argument, are allowed (the helper's fd passing, all
        // ordinary traffic).
        let mut other = none;
        other[2] = libc::MSG_NOSIGNAL as u64;
        other[3] = libc::MSG_NOSIGNAL as u64;
        for nr in [libc::SYS_sendto, libc::SYS_sendmmsg, libc::SYS_sendmsg] {
            assert_eq!(v(nr, other), libc::SECCOMP_RET_ALLOW, "nr {nr}");
        }
        assert_eq!(v(libc::SYS_sendmsg, a3), libc::SECCOMP_RET_ALLOW);
        assert_eq!(v(libc::SYS_sendto, a2), libc::SECCOMP_RET_ALLOW);
        // Unrelated syscalls, even with a FASTOPEN-looking argument.
        let mut all = [fast; 6];
        all[0] = 3;
        let unrelated = [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_mmap,
            libc::SYS_futex,
            libc::SYS_clone,
            libc::SYS_exit_group,
            libc::SYS_socket,
            libc::SYS_close,
            libc::SYS_openat,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_accept,
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
            libc::SYS_ioctl,
            libc::SYS_execve,
            libc::SYS_brk,
            libc::SYS_munmap,
            libc::SYS_rt_sigaction,
            libc::SYS_epoll_pwait,
            libc::SYS_ppoll,
            libc::SYS_pidfd_getfd,
            libc::SYS_getpid,
        ];
        assert!(unrelated.len() >= 20);
        for nr in unrelated {
            assert_eq!(v(nr, none), libc::SECCOMP_RET_ALLOW, "nr {nr}");
            assert_eq!(v(nr, all), libc::SECCOMP_RET_ALLOW, "nr {nr} fastopen args");
        }
        // Foreign architecture: killed, whatever the syscall.
        for foreign in [
            0u32,
            0x4000_0003,
            NATIVE_ARCH ^ 1,
            0xC000_00B7 ^ NATIVE_ARCH ^ 0xC000_003E,
        ] {
            for nr in [libc::SYS_connect, libc::SYS_read, libc::SYS_sendmsg] {
                assert_eq!(
                    run_bpf(&f, foreign, nr as u32, a2),
                    libc::SECCOMP_RET_KILL_PROCESS,
                    "arch {foreign:#x} nr {nr}"
                );
            }
        }
        // Every instruction is reachable only through forward jumps in
        // range (the interpreter would have panicked), and the verdict
        // set is exactly KILL / USER_NOTIF / ALLOW / ERRNO.
        for i in f.iter().filter(|i| i.code == 0x06) {
            assert!(
                [
                    libc::SECCOMP_RET_KILL_PROCESS,
                    libc::SECCOMP_RET_USER_NOTIF,
                    libc::SECCOMP_RET_ALLOW,
                    errno_ret,
                ]
                .contains(&i.k)
            );
        }
    }

    #[test]
    fn verdict_table_continue_only_where_covered() {
        // I1: every call class has exactly one answer; `KernelContinued`
        // appears only for AF_UNIX (empty namespace) classes and netlink bind. TCP
        // bind/connect/listen are never continued. The test enumerates
        // every class through `verdict_for`, the same function the
        // dispatch path uses, so the table and the dispatch path agree.
        let t = verdict_table();
        assert_eq!(t.len(), 11);
        for (class, answer, why) in t {
            assert!(!why.is_empty(), "{class:?} needs a reason");
            // verdict_for must return the same answer as the table.
            assert_eq!(
                verdict_for(*class),
                *answer,
                "{class:?}: verdict_for disagrees with table"
            );
            if matches!(answer, Answer::KernelContinued) {
                assert!(
                    matches!(
                        class,
                        CallClass::ConnectUnix | CallClass::BindUnix | CallClass::BindNetlink
                    ),
                    "{class:?} continued but not covered by B"
                );
            }
        }
        // The four operations of I2 are never KernelContinued.
        for class in [
            CallClass::ConnectLoopbackInet,
            CallClass::BindInet,
            CallClass::Listen,
            CallClass::FastopenSend,
        ] {
            let ans = verdict_for(class);
            assert_ne!(ans, Answer::KernelContinued, "{class:?}");
        }
        // KernelContinued only for AF_UNIX connect and bind, and netlink bind.
        for class in [
            CallClass::ConnectUnix,
            CallClass::BindUnix,
            CallClass::BindNetlink,
        ] {
            assert_eq!(verdict_for(class), Answer::KernelContinued, "{class:?}");
        }
        for class in [CallClass::BindOtherFamily, CallClass::ImplicitOther] {
            assert_eq!(verdict_for(class), Answer::Refused, "{class:?}");
        }
    }

    #[test]
    fn implicit_catch_all_refuses_sandbox_socket() {
        // L-a: the final catch-all never hands a sandbox socket back.
        assert_eq!(
            other_plan(SockNs::Sandbox),
            ImplicitPlan::Refuse("implicit-unexpected-call")
        );
        assert!(matches!(other_plan(SockNs::Host), ImplicitPlan::Refuse(_)));
        assert!(matches!(
            other_plan(SockNs::Unknown),
            ImplicitPlan::Refuse(_)
        ));
    }

    #[test]
    fn bind_class_follows_socket_domain_not_sockaddr_family() {
        // L-b: the class is a function of the socket's domain and type.
        let st = Some(libc::SOCK_STREAM);
        assert_eq!(bind_class(libc::AF_UNIX, st), CallClass::BindUnix);
        assert_eq!(bind_class(libc::AF_NETLINK, None), CallClass::BindNetlink);
        assert_eq!(bind_class(libc::AF_INET, st), CallClass::BindInet);
        assert_eq!(bind_class(libc::AF_INET6, st), CallClass::BindInet);
        assert_eq!(
            bind_class(libc::AF_INET, Some(libc::SOCK_DGRAM | libc::SOCK_CLOEXEC)),
            CallClass::BindInet
        );
        assert_eq!(
            bind_class(libc::AF_PACKET, None),
            CallClass::BindOtherFamily
        );
        assert_eq!(bind_class(libc::AF_ALG, None), CallClass::BindOtherFamily);
        // Sandbox plans come from the table.
        assert_eq!(
            bind_plan(SockNs::Sandbox, Some(libc::AF_INET), st),
            ImplicitPlan::Execute
        );
        assert_eq!(
            bind_plan(SockNs::Sandbox, Some(libc::AF_UNIX), st),
            ImplicitPlan::Continue("af-unix-bind")
        );
    }

    #[test]
    fn bind_unspec_addr_on_inet_socket_is_port_checked() {
        // An AF_UNSPEC sockaddr on an INET socket is still a TCP bind: the
        // plan depends on the socket (INET -> Execute, port checked).
        let mut buf = [0u8; 128];
        buf[2..4].copy_from_slice(&80u16.to_be_bytes());
        assert!(low_port_bind_is_privileged(&buf, 16, libc::AF_INET as u16));
        assert_eq!(
            bind_plan(
                SockNs::Sandbox,
                Some(libc::AF_INET),
                Some(libc::SOCK_STREAM)
            ),
            ImplicitPlan::Execute
        );
    }

    #[test]
    fn bind_short_addrlen_inet6_24_bytes_is_port_checked() {
        let mut buf = [0u8; 128];
        buf[2..4].copy_from_slice(&80u16.to_be_bytes());
        let v6 = libc::AF_INET6 as u16;
        assert!(low_port_bind_is_privileged(&buf, 24, v6));
        assert!(low_port_bind_is_privileged(&buf, 28, v6));
        // shorter than the kernel needs: EINVAL from the kernel, not here
        assert!(!low_port_bind_is_privileged(&buf, 20, v6));
        assert!(!low_port_bind_is_privileged(&buf, 8, libc::AF_INET as u16));
        buf[2..4].copy_from_slice(&1024u16.to_be_bytes());
        assert!(!low_port_bind_is_privileged(&buf, 16, libc::AF_INET as u16));
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert!(!low_port_bind_is_privileged(&buf, 16, libc::AF_INET as u16));
    }

    #[test]
    fn bind_other_family_is_refused() {
        assert_eq!(
            bind_plan(SockNs::Sandbox, Some(libc::AF_PACKET), None),
            ImplicitPlan::Refuse("bind-other-family")
        );
        assert_eq!(
            bind_plan(SockNs::Sandbox, Some(libc::AF_ALG), None),
            ImplicitPlan::Refuse("bind-other-family")
        );
    }

    #[test]
    fn bind_so_domain_error_refuses() {
        assert_eq!(
            bind_plan(SockNs::Sandbox, None, None),
            ImplicitPlan::Refuse("bind-domain-unknown")
        );
    }

    #[test]
    fn bind_raw_inet_refused() {
        assert_eq!(
            bind_plan(SockNs::Sandbox, Some(libc::AF_INET), Some(libc::SOCK_RAW)),
            ImplicitPlan::Refuse("bind-other-family")
        );
    }

    #[test]
    fn host_netlink_bind_is_refused() {
        for ns in [SockNs::Host, SockNs::Unknown] {
            for dom in [
                libc::AF_NETLINK,
                libc::AF_UNIX,
                libc::AF_INET,
                libc::AF_PACKET,
            ] {
                assert!(
                    matches!(
                        bind_plan(ns, Some(dom), Some(libc::SOCK_STREAM)),
                        ImplicitPlan::Refuse(_)
                    ),
                    "{ns:?} domain {dom}"
                );
            }
            assert!(matches!(listen_plan(ns), ImplicitPlan::Refuse(_)));
        }
        assert_eq!(listen_plan(SockNs::Sandbox), ImplicitPlan::Execute);
    }

    #[test]
    fn unknown_ns_other_family_is_refused() {
        assert_eq!(
            bind_plan(SockNs::Unknown, Some(libc::AF_PACKET), None),
            ImplicitPlan::Refuse("netns-unknown")
        );
    }

    #[test]
    fn socket_int_opt_reads_domain_and_type() {
        let (a, _b) = crate::sys::socketpair_seqpacket().unwrap();
        assert_eq!(
            socket_int_opt(a.as_raw_fd(), libc::SO_DOMAIN),
            Some(libc::AF_UNIX)
        );
        assert_eq!(
            socket_int_opt(a.as_raw_fd(), libc::SO_TYPE),
            Some(libc::SOCK_SEQPACKET)
        );
        assert_eq!(socket_int_opt(-1, libc::SO_DOMAIN), None);
    }

    #[test]
    fn socket_netns_cookie_resolves_and_fails_closed() {
        // Two sockets in this namespace share a cookie; a non-socket and
        // a bogus fd give None (fail closed).
        let (a, b) = crate::sys::socketpair_seqpacket().unwrap();
        let ca = socket_netns_cookie(a.as_raw_fd());
        assert!(ca.is_some(), "SO_NETNS_COOKIE needs kernel >= 5.14");
        assert_eq!(ca, socket_netns_cookie(b.as_raw_fd()));
        assert_eq!(ca, own_netns_cookie());
        let file = std::fs::File::open("/proc/self/ns/net").unwrap();
        assert_eq!(socket_netns_cookie(file.as_raw_fd()), None);
        assert_eq!(socket_netns_cookie(-1), None);
    }

    #[test]
    fn classify_ns_fails_closed() {
        assert_eq!(classify_ns(Some(1), Some(2)), SockNs::Sandbox);
        assert_eq!(classify_ns(Some(2), Some(2)), SockNs::Host);
        assert_eq!(classify_ns(None, Some(2)), SockNs::Unknown);
        assert_eq!(classify_ns(Some(1), None), SockNs::Unknown);
        assert_eq!(classify_ns(None, None), SockNs::Unknown);
    }

    #[test]
    fn engine_refuses_host_side_socket_connects_and_journals() {
        // (b): a loopback connect on a socket in the supervisor's own
        // netns must NOT be CONTINUEd (it would reach the host's
        // loopback). The test simulates the injected-socket case
        // directly: the child's socket is created in the supervisor's
        // netns (no netns switch in the test), and the engine's
        // supervisor cookie is that same namespace, so the child's
        // socket resolves as "host-side".
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        // The supervisor cookie is this process's own netns, where the
        // test's sockets live: they resolve as host-side.
        let mnt_cookie = own_netns_cookie().expect("SO_NETNS_COOKIE");
        let (pid, listener) = connecting_child(1, port);
        let cfg = EngineConfig {
            supervisor_cookie: Some(mnt_cookie),
            ..sandbox_cfg(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), 16, "one connect, refused with EACCES");
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].0, "refuse");
        assert_eq!(records[0].1, "host-socket-connect", "{records:?}");
    }

    #[test]
    fn engine_still_continues_sandbox_socket_loopback() {
        // The same loopback connect, with a supervisor cookie that
        // matches no namespace (u64::MAX): every test socket resolves
        // as sandbox-side. 0.6.2: supervisor-executed (design A), the
        // journal verdict is allow/supervisor-executed.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(1, port);
        let cfg = EngineConfig {
            supervisor_cookie: Some(u64::MAX),
            ..sandbox_cfg(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), 1, "one connect, supervisor-executed");
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].0, "allow", "{records:?}");
        assert_eq!(records[0].1, "supervisor-executed", "{records:?}");
    }

    /// A child whose socket has already failed one connect (to a closed
    /// loopback port, before the filter exists): the state of a socket
    /// the supervisor injected and the program kept. After the filter is
    /// installed it connects that socket to `port`. Exit code: the
    /// connect's errno, 0 on success, 2xx on setup failure.
    fn reconnect_child(port: u16, closed_port: u16) -> (libc::pid_t, OwnedFd) {
        let (ours, theirs) = crate::sys::socketpair_seqpacket().unwrap();
        // SAFETY: the child only makes libc calls and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(ours);
            let code = (|| unsafe {
                let s = libc::socket(
                    libc::AF_INET,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                );
                if s < 0 {
                    return 250;
                }
                let mk = |p: u16| {
                    let mut a: libc::sockaddr_in = std::mem::zeroed();
                    a.sin_family = libc::AF_INET as libc::sa_family_t;
                    a.sin_addr.s_addr = libc::INADDR_LOOPBACK.to_be();
                    a.sin_port = p.to_be();
                    a
                };
                let sz = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                let dead = mk(closed_port);
                libc::connect(s, &dead as *const _ as *const libc::sockaddr, sz);
                // Wait until the refused connect has ended the socket.
                let mut pfd = libc::pollfd {
                    fd: s,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                libc::poll(&mut pfd, 1, 2000);
                if crate::sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).is_err() {
                    return 203;
                }
                let Ok(listener) = install_connect_filter() else {
                    return 204;
                };
                if crate::sys::send_with_fds(theirs.as_raw_fd(), b"L", &[listener.as_raw_fd()])
                    .is_err()
                {
                    return 205;
                }
                let live = mk(port);
                if libc::connect(s, &live as *const _ as *const libc::sockaddr, sz) == 0 {
                    0
                } else {
                    *libc::__errno_location()
                }
            })();
            unsafe { libc::_exit(code) }
        }
        drop(theirs);
        let mut buf = [0u8; 8];
        let mut pfd = libc::pollfd {
            fd: ours.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 10_000) };
        let fd = (ready > 0)
            .then(|| crate::sys::recv_with_fds(ours.as_raw_fd(), &mut buf).ok())
            .flatten()
            .and_then(|r| r.fds.into_iter().next());
        (pid, fd.expect("child installed the filter"))
    }

    fn closed_loopback_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    #[test]
    fn host_socket_reconnect_enters_the_full_policy() {
        // (a): a socket that failed a connect and is kept by the program
        // is, in production, a supervisor-namespace socket. Its next
        // connect must not take the own-socket fast path: loopback is
        // refused (the CONTINUE would run in the supervisor's namespace).
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = reconnect_child(port, closed_loopback_port());
        let cfg = EngineConfig {
            supervisor_cookie: own_netns_cookie(),
            ..EngineConfig::new(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), libc::EACCES);
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].0, "refuse");
        assert_eq!(records[0].1, "host-socket-loopback-or-unix", "{records:?}");
    }

    #[test]
    fn sandbox_socket_reconnect_keeps_the_own_socket_path() {
        // Regression guard for 0.6.0: the same failed-then-reconnected
        // socket in the sandbox namespace is answered on the program's
        // own socket, not refused.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = reconnect_child(port, closed_loopback_port());
        let engine = NotifEngine::start_with(listener, Some(j.clone()), sandbox_cfg(5));
        // The kernel hands the earlier failure (ECONNREFUSED) to the
        // first connect after it, on the program's own socket.
        assert_eq!(child_exit(pid), libc::ECONNREFUSED);
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].1, "earlier-connect-failed", "{records:?}");
    }

    #[test]
    fn engine_without_cookie_source_refuses_everything() {
        // `start_with_seats` fills in the engine's own namespace cookie
        // when none is given, and this test child runs in that same
        // namespace, so the socket is classified `Host` and the
        // loopback connect that 0.6.0 would CONTINUE is refused. The
        // case "cookie unknown" (`Unknown`, treated like `Host`) is
        // covered by `classify_ns_fails_closed`, not by this test.
        let (_l, port) = loopback_listener();
        let (d, j) = engine_journal();
        let (pid, listener) = connecting_child(1, port);
        let cfg = EngineConfig {
            supervisor_cookie: None,
            ..sandbox_cfg(5)
        };
        let engine = NotifEngine::start_with(listener, Some(j.clone()), cfg);
        assert_eq!(child_exit(pid), 16, "refused EACCES");
        drop(engine);
        let records = connect_records(&d, &j);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].0, "refuse");
        assert_eq!(records[0].1, "host-socket-connect", "{records:?}");
    }

    /// Fork a child that installs the seccomp filter, creates an AF_UNIX
    /// SOCK_STREAM socket, binds it to a unique path, and calls `listen()`.
    /// The filter intercepts `listen` and the engine supervisor-executes
    /// it. Exit code: 0 on success, errno on failure, 2xx on setup error.
    fn unix_listen_child() -> (libc::pid_t, OwnedFd) {
        let (ours, theirs) = crate::sys::socketpair_seqpacket().unwrap();
        let path = format!("/tmp/hisn-test-listen-{}.sock", std::process::id());
        // SAFETY: the child only makes libc calls and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            drop(ours);
            let code = (|| unsafe {
                if crate::sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).is_err() {
                    return 203;
                }
                let Ok(listener) = install_connect_filter() else {
                    return 204;
                };
                if crate::sys::send_with_fds(theirs.as_raw_fd(), b"L", &[listener.as_raw_fd()])
                    .is_err()
                {
                    return 205;
                }
                drop(listener);
                let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                if s < 0 {
                    return 250;
                }
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let p = format!("{}\0", path);
                let bytes = p.as_bytes();
                let n = bytes.len().min(addr.sun_path.len());
                addr.sun_path[..n]
                    .copy_from_slice(std::mem::transmute::<&[u8], &[libc::c_char]>(&bytes[..n]));
                if libc::bind(
                    s,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                ) < 0
                {
                    return 251;
                }
                let rc = libc::listen(s, 1);
                if rc == 0 {
                    0
                } else {
                    *libc::__errno_location()
                }
            })();
            let _ = std::fs::remove_file(&path);
            unsafe { libc::_exit(code) }
        }
        drop(theirs);
        let mut buf = [0u8; 8];
        let mut pfd = libc::pollfd {
            fd: ours.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 10_000) };
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
                panic!("test child could not install the seccomp filter");
            }
        }
    }

    #[test]
    fn af_unix_listen_is_supervisor_executed() {
        // After Block 3a, every listen on a sandbox socket is
        // supervisor-executed, regardless of address family. The kernel
        // never executes a continued listen from a sandboxed task.
        // This test verifies an AF_UNIX (non-INET) listen succeeds via
        // supervisor execution. The seccomp filter intercepts the
        // listen syscall; the engine supervisor-executes it on the
        // dup reference; the child sees errno=0 (exit 0).
        let (_d, _j) = engine_journal();
        let (pid, listener) = unix_listen_child();
        let engine = NotifEngine::start_with(listener, None, sandbox_cfg(5));
        assert_eq!(
            child_exit(pid),
            0,
            "AF_UNIX listen should succeed (supervisor-executed)"
        );
        drop(engine);
    }
}

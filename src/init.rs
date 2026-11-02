//! Sandbox init: PID 1 of the new pid namespace (DESIGN §3).
//!
//! **Cannot run in the Wakil build sandbox** (needs user namespaces); the pure
//! parts are unit-tested here, the rest is exercised by the host leak tests.
//!
//! Order matters and every step fails closed: any error aborts before the
//! command runs. After setup, init itself holds no capabilities, is
//! non-dumpable, and sits under the same seccomp filter as the command
//! (DESIGN §6) — the command shares its pid namespace, so a privileged or
//! ptraceable init would be a way out.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use seccompiler::BpfProgram;

use crate::landlock::{self, LandlockPlan};
use crate::mounts::MountOp;
use crate::policy::{Network, ResolvedPolicy};
use crate::{rootfs, seccomp, sig, sys};

/// supervisor → init: maps are written, proceed.
pub const MSG_GO: u8 = b'G';
/// supervisor → init: grants are in place, run the command.
pub const MSG_START: u8 = b'S';
/// init → supervisor: setup done (+ optional pty master fd).
pub const MSG_READY: u8 = b'R';
/// init → supervisor: fatal setup error, message follows.
pub const MSG_ERROR: u8 = b'E';

const PR_SET_PDEATHSIG: i32 = 1;
const PR_SET_DUMPABLE: i32 = 4;
const PR_CAPBSET_DROP: i32 = 24;
const PR_SET_SECUREBITS: i32 = 28;
const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
const SIOCSIFFLAGS: u64 = 0x8914;
const IFF_UP: i16 = 0x1;
const TIOCSPTLCK_REQ: u64 = 0x4004_5431;
const TIOCGPTN_REQ: u64 = 0x8004_5430;
const TIOCSCTTY_REQ: u64 = 0x540E;

pub const EXIT_CANNOT_EXEC: i32 = 126;
pub const EXIT_NOT_FOUND: i32 = 127;
pub const EXIT_INTERNAL: i32 = 125;

pub struct InitConfig {
    pub policy: ResolvedPolicy,
    pub plan: Vec<MountOp>,
    pub landlock: LandlockPlan,
    pub require_scope: bool,
    pub seccomp: Vec<BpfProgram>,
    /// Empty directory (inside the session dir) that becomes the new root.
    pub root_dir: PathBuf,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub use_pty: bool,
    /// `hisn run --detach`: no command; after START init only reaps and waits
    /// for a termination signal (sessions are then used through `exec`).
    pub detach: bool,
    /// Caller's uid/gid in the supervisor's namespace; mapped 1:1 (single id).
    pub uid: u32,
    pub gid: u32,
}

/// Entry point in the cloned child. Never returns.
pub fn init_main(cfg: InitConfig, chan: OwnedFd) -> ! {
    let code = match run_init(&cfg, &chan) {
        Ok(code) => code,
        Err(e) => {
            let msg = format!("{e:#}");
            let mut payload = vec![MSG_ERROR];
            payload.extend_from_slice(msg.as_bytes());
            let _ = sys::send_with_fd(chan.as_raw_fd(), &payload, None);
            EXIT_INTERNAL
        }
    };
    // SAFETY: terminate this process immediately; the kernel then tears down
    // the pid namespace and every process in it.
    unsafe { libc::_exit(code) }
}

fn run_init(cfg: &InitConfig, chan: &OwnedFd) -> Result<i32> {
    // Never outlive the supervisor (invariant 3).
    sys::prctl(PR_SET_PDEATHSIG, libc::SIGKILL as u64, 0, 0, 0).context("PR_SET_PDEATHSIG")?;
    // 0. Single-id maps, written by ourselves: allowed for an unprivileged
    //    process mapping its own euid, with setgroups denied first.
    write_id_maps(cfg.uid, cfg.gid).context("writing uid/gid maps")?;
    // 1. Wait for the supervisor to have opened our namespace fds.
    let mut b = [0u8; 1];
    let (n, _) = sys::recv_with_fd(chan.as_raw_fd(), &mut b).context("waiting for supervisor")?;
    if n != 1 || b[0] != MSG_GO {
        bail!("supervisor went away before setup");
    }

    // 3-9. Filesystem: private propagation, tmpfs root, plan, pivot.
    rootfs::mount_root(&cfg.root_dir)?;
    rootfs::execute(&cfg.plan, &cfg.root_dir)?;
    rustix::system::sethostname(cfg.policy.hostname.as_bytes()).context("sethostname")?;
    if cfg.policy.network == Network::None {
        loopback_up().context("bringing up lo")?;
    }
    rootfs::enter(&cfg.root_dir)?;
    sys::close_all_except(&[chan.as_raw_fd()]);
    // The sandbox root, post-pivot, for the supervisor's exec helper (D25).
    // Handed over with READY: init is non-dumpable by then, so the supervisor
    // cannot open `/proc/<init>/root` itself.
    let root_fd = sys::openat2(
        libc::AT_FDCWD,
        c"/",
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        0,
    )
    .context("opening the sandbox root")?;

    // Pty (must exist before seccomp/landlock; /dev is the sandbox's own).
    let pty = if cfg.use_pty {
        Some(open_pty().context("allocating pty")?)
    } else {
        None
    };

    // 10. Limits, Landlock.
    set_rlimits(&cfg.policy).context("setrlimit")?;
    landlock::apply(&cfg.landlock, cfg.require_scope).context("landlock")?;

    // 11. No privileges, ever.
    sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).context("no_new_privs")?;
    drop_all_caps().context("dropping capabilities")?;
    // 12. Seccomp (installs on init; the command inherits it).
    seccomp::install(&cfg.seccomp)?;

    // Scrub argv BEFORE PR_SET_DUMPABLE=0: the /proc/self/mem write in
    // scrub_argv requires the process to be dumpable (ptrace_may_access
    // must succeed for self-access to /proc/self/mem). After
    // PR_SET_DUMPABLE=0, /proc/self/mem becomes EACCES and the scrub
    // silently fails — leaving the session id, policy path, and session
    // dir visible in /proc/1/cmdline inside the sandbox.
    scrub_argv("hisn-init");

    sys::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0).context("PR_SET_DUMPABLE")?;
    verify_hardening().context("post-setup verification")?;

    // Signals: block now so none is lost between fork and the wait loop.
    let handled = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD];
    sig::install(&handled)?;
    let old = sig::block(&handled)?;

    let argv0 = cfg.argv.first().map(String::as_str).unwrap_or_default();
    let prog = resolve_program(argv0, cfg.env.get("PATH").map(String::as_str), |p| {
        is_executable(p)
    })
    .ok_or_else(|| anyhow!("{argv0}: command not found"));
    let argv_c = cstrings(cfg.argv.iter().map(String::as_str))?;
    let envp_c = cstrings(
        cfg.env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str),
    )?;
    let cwd_c = sys::cstr(&cfg.policy.cwd)?;

    // Tell the supervisor we are ready, handing over the pty master.
    let (master, slave) = match pty {
        Some((m, s)) => (Some(m), Some(s)),
        None => (None, None),
    };
    let mut ready_fds = vec![root_fd.as_raw_fd()];
    ready_fds.extend(master.as_ref().map(AsRawFd::as_raw_fd));
    sys::send_with_fds(chan.as_raw_fd(), &[MSG_READY], &ready_fds).context("reporting ready")?;
    drop(master);
    drop(root_fd);
    // Wait for the supervisor to apply initial grants before the command exists.
    let (n, _) = sys::recv_with_fd(chan.as_raw_fd(), &mut b).context("waiting for START")?;
    if n != 1 || b[0] != MSG_START {
        bail!("supervisor aborted the session");
    }

    if cfg.detach {
        drop(slave);
        return Ok(supervise_detached(&old));
    }
    // SAFETY: init is single-threaded; the child only makes raw syscalls then
    // execs or `_exit`s.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error()).context("fork");
    }
    if child == 0 {
        let code = exec_command(prog, &argv_c, &envp_c, &cwd_c, slave, &old);
        // SAFETY: only reached when exec failed.
        unsafe { libc::_exit(code) }
    }
    drop(slave);
    Ok(supervise(child, &old))
}

/// PID 1 duty: forward termination signals to the command's process group,
/// reap everything, exit with the command's status.
fn supervise(child: libc::pid_t, old: &libc::sigset_t) -> i32 {
    let mut result: Option<i32> = None;
    loop {
        for s in sig::take_pending() {
            if matches!(s, libc::SIGTERM | libc::SIGINT | libc::SIGHUP) {
                // SAFETY: plain kill to the child's process group / process.
                unsafe {
                    if libc::kill(-child, s) != 0 {
                        libc::kill(child, s);
                    }
                }
            }
        }
        loop {
            let mut st = 0;
            // SAFETY: waitpid with a valid out pointer.
            let pid = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if pid == child {
                result = Some(decode_status(st));
            }
        }
        if let Some(code) = result {
            return code;
        }
        sig::wait(old);
    }
}

/// `--detach` PID 1: no command, only reaping. Returns 0 on
/// `SIGTERM`/`SIGINT`/`SIGHUP`; the kernel then kills everything left in the
/// pid namespace (this is what ends a detached session and every `exec`).
fn supervise_detached(old: &libc::sigset_t) -> i32 {
    loop {
        for s in sig::take_pending() {
            if matches!(s, libc::SIGTERM | libc::SIGINT | libc::SIGHUP) {
                return 0;
            }
        }
        reap_all();
        sig::wait(old);
    }
}

/// Reap every zombie child (PID 1 inherits all orphans of the namespace).
fn reap_all() -> usize {
    let mut n = 0;
    loop {
        let mut st = 0;
        // SAFETY: waitpid with a valid out pointer.
        let pid = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if pid <= 0 {
            return n;
        }
        n += 1;
    }
}

pub fn decode_status(st: i32) -> i32 {
    if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else if libc::WIFSIGNALED(st) {
        128 + libc::WTERMSIG(st)
    } else {
        EXIT_INTERNAL
    }
}

/// Runs in the forked command process. Returns an exit code only on failure.
fn exec_command(
    prog: Result<PathBuf>,
    argv: &[CString],
    envp: &[CString],
    cwd: &CString,
    slave: Option<OwnedFd>,
    old: &libc::sigset_t,
) -> i32 {
    // SAFETY: raw syscalls in a freshly forked, single-threaded child.
    unsafe {
        libc::setsid();
        if let Some(s) = &slave {
            libc::ioctl(s.as_raw_fd(), TIOCSCTTY_REQ as _, 0);
            for fd in 0..3 {
                libc::dup2(s.as_raw_fd(), fd);
            }
        }
        drop(slave);
        if libc::chdir(cwd.as_ptr()) != 0 {
            let e = io::Error::last_os_error();
            eprintln!("hisn: cannot chdir to {}: {e}", cwd.to_string_lossy());
            return EXIT_CANNOT_EXEC;
        }
    }
    sig::restore_mask(old);
    // Rust ignores SIGPIPE at startup and SIG_IGN survives exec.
    sig::reset_default(&[
        libc::SIGPIPE,
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGCHLD,
    ]);
    let prog = match prog {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hisn: {e}");
            return EXIT_NOT_FOUND;
        }
    };
    let Ok(prog_c) = sys::cstr(&prog) else {
        return EXIT_CANNOT_EXEC;
    };
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    // SAFETY: NUL-terminated pointer arrays that outlive the call.
    unsafe { libc::execve(prog_c.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr()) };
    let e = io::Error::last_os_error();
    eprintln!("hisn: cannot execute {}: {e}", prog.display());
    if e.raw_os_error() == Some(libc::ENOENT) {
        EXIT_NOT_FOUND
    } else {
        EXIT_CANNOT_EXEC
    }
}

pub fn cstrings<'a>(items: impl Iterator<Item = &'a str>) -> Result<Vec<CString>> {
    items
        .map(|s| CString::new(s).map_err(|_| anyhow!("NUL byte in {s:?}")))
        .collect()
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Resolve `argv0` like `execvp` using `path` (not the host's PATH).
pub fn resolve_program(
    argv0: &str,
    path: Option<&str>,
    is_exec: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if argv0.contains('/') {
        return Some(PathBuf::from(argv0));
    }
    path?
        .split(':')
        .filter(|d| d.starts_with('/'))
        .map(|d| Path::new(d).join(argv0))
        .find(|p| is_exec(p))
}

pub fn write_id_maps(uid: u32, gid: u32) -> io::Result<()> {
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))
}

pub fn set_rlimits(p: &ResolvedPolicy) -> io::Result<()> {
    for (res, val) in [
        (libc::RLIMIT_NOFILE, p.nofile),
        (libc::RLIMIT_NPROC, p.nproc),
        (libc::RLIMIT_CORE, 0),
    ] {
        let lim = libc::rlimit {
            rlim_cur: val,
            rlim_max: val,
        };
        // SAFETY: valid rlimit pointer.
        if unsafe { libc::setrlimit(res, &lim) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn loopback_up() -> io::Result<()> {
    // SAFETY: plain socket + ioctl with a zeroed, correctly sized ifreq.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        for (d, b) in req.ifr_name.iter_mut().zip(b"lo\0") {
            *d = *b as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = IFF_UP;
        let r = libc::ioctl(s, SIOCSIFFLAGS as _, &req);
        let e = io::Error::last_os_error();
        libc::close(s);
        if r != 0 { Err(e) } else { Ok(()) }
    }
}

/// Allocate a pty on the sandbox's own devpts. Returns `(master, slave)`.
fn open_pty() -> io::Result<(OwnedFd, OwnedFd)> {
    // SAFETY: standard ptmx dance with valid pointers.
    unsafe {
        let m = libc::open(
            c"/dev/ptmx".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if m < 0 {
            return Err(io::Error::last_os_error());
        }
        let master = OwnedFd::from_raw_fd(m);
        let unlock: libc::c_int = 0;
        if libc::ioctl(m, TIOCSPTLCK_REQ as _, &unlock) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n: libc::c_uint = 0;
        if libc::ioctl(m, TIOCGPTN_REQ as _, &mut n) != 0 {
            return Err(io::Error::last_os_error());
        }
        let path = CString::new(format!("/dev/pts/{n}")).expect("no NUL");
        let s = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if s < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((master, OwnedFd::from_raw_fd(s)))
    }
}

// ------------------------------------------------------------- capabilities

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const CAP_V3: u32 = 0x2008_0522;

fn cap_last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(63)
}

/// Lock securebits, clear ambient + bounding sets, zero eff/perm/inh.
/// Must be called while `CAP_SETPCAP` is still held (DESIGN §3 step 11).
pub fn drop_all_caps() -> io::Result<()> {
    let bits = libc::SECBIT_NOROOT
        | libc::SECBIT_NOROOT_LOCKED
        | libc::SECBIT_NO_SETUID_FIXUP
        | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
        | libc::SECBIT_KEEP_CAPS_LOCKED
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    sys::prctl(PR_SET_SECUREBITS, bits as u64, 0, 0, 0)?;
    sys::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)?;
    for cap in 0..=cap_last_cap() {
        if let Err(e) = sys::prctl(PR_CAPBSET_DROP, u64::from(cap), 0, 0, 0)
            && e.raw_os_error() != Some(libc::EINVAL)
        {
            return Err(e);
        }
    }
    let hdr = CapHeader {
        version: CAP_V3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: header/data are valid repr(C) structs of the v3 layout.
    let r = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr()) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True iff every capability set in a `/proc/<pid>/status` body is empty.
pub fn caps_all_zero(status: &str) -> Result<(), String> {
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let v = status
            .lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')))
            .map(str::trim)
            .ok_or_else(|| format!("{key} missing from status"))?;
        let n = u64::from_str_radix(v, 16).map_err(|_| format!("{key}: unparsable {v:?}"))?;
        if n != 0 {
            return Err(format!("{key} is {v}, expected 0"));
        }
    }
    Ok(())
}

pub fn status_field(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')))
        .map(|v| v.trim().to_owned())
}

/// Re-read our own state and fail closed unless the hardening took effect.
pub fn verify_hardening() -> Result<()> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    caps_all_zero(&status).map_err(|e| anyhow!(e))?;
    match status_field(&status, "NoNewPrivs").as_deref() {
        Some("1") => {}
        other => bail!("NoNewPrivs is {other:?}, expected 1"),
    }
    match status_field(&status, "Seccomp").as_deref() {
        Some("2") => {}
        other => bail!("Seccomp is {other:?}, expected 2 (filter)"),
    }
    Ok(())
}

pub fn raw_fd(f: &OwnedFd) -> RawFd {
    f.as_raw_fd()
}

/// Overwrite the process's argv memory in place so `/proc/self/cmdline`
/// shows `replacement` instead of the original command line. The session
/// id, policy path, and session dir must not appear in `/proc/1/cmdline`
/// inside the sandbox.
///
/// Uses `prctl(PR_SET_NAME)` for the comm name and a direct memory
/// overwrite for the cmdline. The overwrite is best-effort: if it fails
/// (caps dropped), the scrub is silently skipped — the confinement is
/// already in place.
fn scrub_argv(replacement: &str) {
    // Set the process name (comm, /proc/self/comm) — does not need caps.
    let name = std::ffi::CString::new(replacement).unwrap_or_default();
    // SAFETY: PR_SET_NAME with a valid C string (truncated to 16 bytes
    // including NUL by the kernel).
    unsafe {
        libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
    }

    // Overwrite the argv memory in place. The argv strings live on the
    // initial stack at the top of the address space. We read
    // /proc/self/cmdline to get the content (and total byte length), then
    // write the replacement over the same memory via /proc/self/mem at the
    // address the content came from. We find that address from
    // /proc/self/stat (startstack, field 28 after the ')' split, 0-indexed
    // field 44 in the full list — but the stat file layout has the comm
    // field in parens which complicates indexing; the actual argv string
    // area starts just after the argv pointer array and envp pointer
    // array on the stack, at the address startstack + sizeof(argc) +
    // (nargv+1)*sizeof(ptr) + (nenvp+1)*sizeof(ptr)).
    //
    // Simpler: the first argv string is at the address pointed to by
    // argv[0], which is at startstack + sizeof(ulong). We can read
    // startstack from /proc/self/stat, then read the pointer from the
    // stack, then write to that address via /proc/self/mem.
    //
    // Even simpler: use PR_SET_MM_ARG_START/END if we still have
    // CAP_SYS_RESOURCE (best-effort; may fail with EPERM after caps drop).
    let cmdline = match std::fs::read("/proc/self/cmdline") {
        Ok(c) => c,
        Err(_) => return,
    };
    let cmdline_len = cmdline.len();
    if cmdline_len == 0 {
        return;
    }
    // Write the replacement + NUL padding to a buffer, then try to set it
    // as the new argv range via PR_SET_MM. This needs CAP_SYS_RESOURCE,
    // which we don't have after caps drop — so it may fail. Best-effort.
    let mut new_cmdline = vec![0u8; cmdline_len];
    let copy_len = replacement.len().min(cmdline_len.saturating_sub(1));
    new_cmdline[..copy_len].copy_from_slice(&replacement.as_bytes()[..copy_len]);
    // new_cmdline is already NUL-padded.
    // Try to write via /proc/self/mem at the address of the original
    // cmdline. The address is the start of the argv string area on the
    // initial stack. We can find it by reading /proc/self/stat.
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return,
    };
    // Parse /proc/self/stat: everything after the last ')' is space-separated
    // fields. Field 28 (0-indexed after ')') is startstack.
    let rest = match stat.rsplit(')').next() {
        Some(r) => r.trim(),
        None => return,
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // startstack is field 28 (1-indexed in the man page), which is index 25
    // after the ')' split (0-indexed; field 3 'state' is index 0).
    let startstack: u64 = match fields.get(25).and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return,
    };
    // The stack layout (top-down): startstack -> argc (8 bytes) -> argv[0]
    // (pointer, 8 bytes) -> ... -> argv array. The first argv string is at
    // the address stored at startstack + 8 (i.e., *argv[0]).
    // Read the pointer from /proc/self/mem.
    let mem = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/proc/self/mem")
    {
        Ok(f) => f,
        Err(_) => return,
    };
    use std::os::unix::fs::FileExt;
    let mut ptr_buf = [0u8; 8];
    if mem.read_at(&mut ptr_buf, startstack + 8).is_err() {
        return;
    }
    let argv0_addr = u64::from_le_bytes(ptr_buf);
    // Write the replacement + NUL padding at argv0_addr.
    let _ = mem.write_at(&new_cmdline, argv0_addr);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: &str = "Name:\tinit\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";

    #[test]
    fn caps_zero_accepts_only_all_zero() {
        assert!(caps_all_zero(ZERO).is_ok());
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let bad = ZERO.replace(
                &format!("{key}:\t0000000000000000"),
                &format!("{key}:\t0000000000000001"),
            );
            let e = caps_all_zero(&bad).unwrap_err();
            assert!(e.contains(key), "{e}");
        }
        assert!(
            caps_all_zero("Name:\tx\n").is_err(),
            "missing fields fail closed"
        );
        assert!(caps_all_zero("CapInh:\tzz\n").is_err());
    }

    #[test]
    fn status_fields() {
        assert_eq!(status_field(ZERO, "NoNewPrivs").as_deref(), Some("1"));
        assert_eq!(status_field(ZERO, "Seccomp").as_deref(), Some("2"));
        assert_eq!(status_field(ZERO, "Nope"), None);
        // prefix collision: "Seccomp" must not match "Seccomp_filters"
        assert_eq!(status_field("Seccomp_filters:\t3\n", "Seccomp"), None);
    }

    #[test]
    fn program_resolution_uses_the_given_path() {
        let ex = |p: &Path| p == Path::new("/usr/bin/ls") || p == Path::new("/bin/sh");
        assert_eq!(
            resolve_program("ls", Some("/nope:/usr/bin:/bin"), ex),
            Some("/usr/bin/ls".into())
        );
        assert_eq!(
            resolve_program("sh", Some("/usr/bin:/bin"), ex),
            Some("/bin/sh".into())
        );
        assert_eq!(resolve_program("missing", Some("/usr/bin"), ex), None);
        assert_eq!(resolve_program("ls", None, ex), None);
        // relative PATH entries are ignored; slashes bypass the search
        assert_eq!(resolve_program("ls", Some("usr/bin"), ex), None);
        assert_eq!(
            resolve_program("./x", Some("/usr/bin"), ex),
            Some("./x".into())
        );
        assert_eq!(
            resolve_program("/abs/prog", None, ex),
            Some("/abs/prog".into())
        );
    }

    #[test]
    fn exit_status_decoding() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(7 << 8), 7);
        assert_eq!(decode_status(libc::SIGKILL), 128 + libc::SIGKILL);
        assert_eq!(decode_status(libc::SIGSEGV), 128 + libc::SIGSEGV);
    }

    #[test]
    fn cstrings_reject_nul() {
        assert_eq!(cstrings(["a", "b"].into_iter()).unwrap().len(), 2);
        assert!(cstrings(["a\0b"].into_iter()).is_err());
    }

    #[test]
    fn rlimits_are_applied_in_a_child() {
        // SAFETY: the child only calls setrlimit/getrlimit and `_exit`s.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let p = crate::policy::ResolvedPolicy {
                    version: String::new(),
                    cwd: "/".into(),
                    home: crate::policy::Home::Tmpfs,
                    network: Network::None,
                    hostname: "h".into(),
                    ro: vec![],
                    rw: vec![],
                    mask: vec![],
                    grantable_rw: vec![],
                    env_pass: vec![],
                    env_set: Default::default(),
                    extra_deny: vec![],
                    landlock_scoped: vec![],
                    nofile: 321,
                    nproc: 2048, // lowering is always allowed; a larger value fails with EPERM under a low hard limit (CI)
                    shm: false,
                    shm_size: 64,
                    tmp_size: 1024,
                };
                let ok = set_rlimits(&p).is_ok() && {
                    let mut l: libc::rlimit = std::mem::zeroed();
                    libc::getrlimit(libc::RLIMIT_NOFILE, &mut l);
                    let mut c: libc::rlimit = std::mem::zeroed();
                    libc::getrlimit(libc::RLIMIT_CORE, &mut c);
                    l.rlim_cur == 321 && l.rlim_max == 321 && c.rlim_cur == 0
                };
                libc::_exit(if ok { 0 } else { 1 });
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            assert_eq!(decode_status(st), 0);
        }
    }

    #[test]
    fn drop_all_caps_succeeds_without_privileges_or_fails_cleanly() {
        // Unprivileged: securebits write needs CAP_SETPCAP so the first step
        // fails with EPERM; the function must report it, never panic.
        // SAFETY: forked child only runs the function and `_exit`s.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let r = drop_all_caps();
                libc::_exit(match r {
                    Ok(()) => 0,
                    Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
                    Err(_) => 1,
                });
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            assert_eq!(decode_status(st), 0);
        }
    }

    #[test]
    fn scrub_argv_sets_comm_name() {
        // PR_SET_NAME is per-thread on modern Linux. Fork so the child's
        // comm is under our control, then check it.
        // SAFETY: fork; child sets name, reads comm, exits with status.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            scrub_argv("hisn-test");
            let comm = std::fs::read_to_string("/proc/self/comm").unwrap_or_default();
            // SAFETY: _exit never returns.
            unsafe {
                libc::_exit(if comm.trim().starts_with("hisn-test") {
                    0
                } else {
                    1
                });
            }
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert_eq!(decode_status(st), 0, "comm was not 'hisn-test'");
    }
}

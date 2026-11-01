//! Probe binary for the leak suite (`tests/leak/run.sh`). It runs *inside* a
//! hisn session and reports what the sandbox can see or do as plain text;
//! all assertions are made on the host. `loop DIR` turns it into a tiny
//! command server driven through files in a directory shared with the host:
//! the host writes `in.N`, the probe writes `out.N`.
//!
//! Not part of the installed binary; build with
//! `cargo build --release --example leakprobe`.

use std::cell::RefCell;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

fn errno_name(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT".into(),
        libc::EACCES => "EACCES".into(),
        libc::EPERM => "EPERM".into(),
        libc::EROFS => "EROFS".into(),
        libc::ENETUNREACH => "ENETUNREACH".into(),
        libc::ELOOP => "ELOOP".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::EXDEV => "EXDEV".into(),
        libc::ECONNREFUSED => "ECONNREFUSED".into(),
        libc::EHOSTUNREACH => "EHOSTUNREACH".into(),
        libc::ESRCH => "ESRCH".into(),
        other => format!("E{other}"),
    }
}

fn err_str(e: &std::io::Error) -> String {
    e.raw_os_error()
        .map(errno_name)
        .unwrap_or_else(|| format!("ERR:{e}"))
}

fn last_errno() -> String {
    errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

fn kind(md: &fs::Metadata) -> &'static str {
    let t = md.file_type();
    if t.is_dir() {
        "dir"
    } else if t.is_symlink() {
        "symlink"
    } else if t.is_file() {
        "file"
    } else {
        "other"
    }
}

fn cmd_stat(p: &str) -> String {
    match fs::metadata(p) {
        Ok(m) => format!("OK {}", kind(&m)),
        Err(e) => err_str(&e),
    }
}

fn cmd_ls(p: &str) -> String {
    match fs::read_dir(p) {
        Ok(rd) => {
            let mut v: Vec<String> = rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            format!("OK {}", v.join(","))
        }
        Err(e) => err_str(&e),
    }
}

fn cmd_cat(p: &str) -> String {
    match fs::read(p) {
        Ok(b) => format!("OK {}", String::from_utf8_lossy(&b).trim_end()),
        Err(e) => err_str(&e),
    }
}

fn cmd_write(p: &str) -> String {
    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .and_then(|mut f| f.write_all(b"leak"))
    {
        Ok(()) => "OK".into(),
        Err(e) => err_str(&e),
    }
}

fn cmd_sameino(a: &str, b: &str) -> String {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) => format!("{}", x.dev() == y.dev() && x.ino() == y.ino()),
        (Err(e), _) | (_, Err(e)) => err_str(&e),
    }
}

fn cmd_pids() -> String {
    let mut v: Vec<u32> = fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    format!(
        "OK {}",
        v.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
    )
}

fn cmd_env() -> String {
    let mut v: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    v.sort();
    format!("OK\n{}", v.join("\n"))
}

fn cmd_caps() -> String {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let keep = [
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp:",
    ];
    let lines: Vec<&str> = s
        .lines()
        .filter(|l| keep.iter().any(|k| l.starts_with(k)))
        .collect();
    format!("OK\n{}", lines.join("\n"))
}

fn syscall_result(r: libc::c_long) -> String {
    if r == -1 {
        last_errno()
    } else {
        format!("UNEXPECTED_SUCCESS({r})")
    }
}

fn cmd_syscall(name: &str) -> String {
    // SAFETY: every call below uses valid pointers or deliberately invalid
    // arguments; each is expected to be refused by the sandbox.
    unsafe {
        match name {
            "mount" => {
                let (s, t, f) = (c"none", c"/tmp", c"tmpfs");
                syscall_result(
                    libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), 0, std::ptr::null())
                        as libc::c_long,
                )
            }
            "umount" => {
                syscall_result(libc::umount2(c"/usr".as_ptr(), libc::MNT_DETACH) as libc::c_long)
            }
            "unshare_mnt" => syscall_result(libc::unshare(libc::CLONE_NEWNS) as libc::c_long),
            "unshare_user" => syscall_result(libc::unshare(libc::CLONE_NEWUSER) as libc::c_long),
            "setns" => {
                let fd = libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY);
                if fd < 0 {
                    return format!("OPEN:{}", last_errno());
                }
                syscall_result(libc::setns(fd, libc::CLONE_NEWNS) as libc::c_long)
            }
            "ptrace" => syscall_result(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)),
            "chroot" => syscall_result(libc::chroot(c"/".as_ptr()) as libc::c_long),
            "pivot_root" => syscall_result(libc::syscall(
                libc::SYS_pivot_root,
                c"/".as_ptr(),
                c"/".as_ptr(),
            )),
            "open_tree" => syscall_result(libc::syscall(
                libc::SYS_open_tree,
                -100,
                c"/".as_ptr(),
                1u32,
            )),
            "bpf" => syscall_result(libc::syscall(libc::SYS_bpf, 0, 0, 0)),
            "io_uring_setup" => {
                syscall_result(libc::syscall(libc::SYS_io_uring_setup, 1u32, 0usize))
            }
            "clone3" => syscall_result(libc::syscall(libc::SYS_clone3, 0usize, 0usize)),
            "clone_newuser" => {
                let r = libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong,
                    0,
                    0,
                    0,
                    0,
                );
                if r == 0 {
                    libc::_exit(0);
                }
                syscall_result(r)
            }
            "tiocsti" => {
                let c = b'x';
                syscall_result(libc::ioctl(0, 0x5412, &c) as libc::c_long)
            }
            other => format!("UNKNOWN_SYSCALL {other}"),
        }
    }
}

fn cmd_connect(host: &str, port: &str) -> String {
    let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() else {
        return "BAD_ADDR".into();
    };
    match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => "OK".into(),
        Err(e) => err_str(&e),
    }
}

fn cmd_loopback() -> String {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => return format!("BIND:{}", err_str(&e)),
    };
    let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(_) => "OK".into(),
        Err(e) => format!("CONNECT:{}", err_str(&e)),
    }
}

fn cmd_exec(args: &[String]) -> String {
    match std::process::Command::new(&args[0])
        .args(&args[1..])
        .output()
    {
        Ok(o) => format!(
            "OK exit={}",
            o.status
                .code()
                .map_or_else(|| "signal".into(), |c| c.to_string())
        ),
        Err(e) => format!("SPAWN:{}", err_str(&e)),
    }
}

thread_local! {
    /// A socket pair holding one never-received SCM_RIGHTS fd (L13).
    static QUEUE: RefCell<Option<(OwnedFd, OwnedFd)>> = const { RefCell::new(None) };
}

/// Queue an fd for `path` inside a unix socket pair and never receive it.
fn cmd_hold_queued(path: &str) -> String {
    let c = CString::new(path).expect("no NUL");
    // SAFETY: plain syscalls with valid, owned buffers.
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644);
        if fd < 0 {
            return last_errno();
        }
        let mut sv = [0i32; 2];
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        ) != 0
        {
            return last_errno();
        }
        let payload = b"q";
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut _,
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(4) as usize;
        let mut cbuf = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let c0 = libc::CMSG_FIRSTHDR(&msg);
        (*c0).cmsg_level = libc::SOL_SOCKET;
        (*c0).cmsg_type = libc::SCM_RIGHTS;
        (*c0).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping((&fd as *const i32).cast::<u8>(), libc::CMSG_DATA(c0), 4);
        if libc::sendmsg(sv[0], &msg, 0) < 0 {
            return last_errno();
        }
        libc::close(fd); // only the queued reference remains
        let pair = (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1]));
        QUEUE.with(|q| *q.borrow_mut() = Some(pair));
    }
    "OK queued".into()
}

/// Receive the previously queued fd and write through it.
fn cmd_recv_write() -> String {
    let rx = QUEUE.with(|q| q.borrow().as_ref().map(|(_, rx)| rx.as_raw_fd()));
    let Some(rx) = rx else {
        return "NO_QUEUE".into();
    };
    // SAFETY: standard recvmsg dance with owned buffers.
    unsafe {
        let mut b = [0u8; 4];
        let mut iov = libc::iovec {
            iov_base: b.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(4) as usize;
        let mut cbuf = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        if libc::recvmsg(rx, &mut msg, 0) < 0 {
            return last_errno();
        }
        let c0 = libc::CMSG_FIRSTHDR(&msg);
        if c0.is_null() {
            return "NO_FD".into();
        }
        let mut fd = -1i32;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(c0).cast_const(),
            (&mut fd as *mut i32).cast::<u8>(),
            4,
        );
        let n = libc::write(fd, b"after-revoke".as_ptr().cast(), 12);
        if n == 12 {
            "OK wrote-through-queued-fd".into()
        } else {
            last_errno()
        }
    }
}

fn cmd_mountinfo() -> String {
    format!(
        "OK\n{}",
        fs::read_to_string("/proc/self/mountinfo").unwrap_or_default()
    )
}

fn cmd_ppid() -> String {
    // SAFETY: getppid has no preconditions; reading /proc/self/status is plain IO.
    let me = std::process::id();
    let ppid = unsafe { libc::getppid() };
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let walk = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .map(|v| v.trim().to_string());
    format!(
        "OK pid={} ppid={} status_ppid={} ns_self={}",
        me,
        ppid,
        walk.unwrap_or_default(),
        Path::new("/proc/self").exists()
    )
}

/// Parent chain of this process up to pid 1, read from the sandbox's own
/// /proc (`init -> W -> P` for an exec'd program, DESIGN §14.3).
fn cmd_ppid_chain() -> String {
    let mut chain = vec![std::process::id() as i64];
    for _ in 0..64 {
        let cur = *chain.last().expect("non-empty");
        if cur <= 1 {
            break;
        }
        let st = fs::read_to_string(format!("/proc/{cur}/status")).unwrap_or_default();
        let pp = st
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<i64>().ok());
        match pp {
            Some(p) => chain.push(p),
            None => return format!("UNREADABLE at {cur}"),
        }
    }
    format!(
        "OK chain={}",
        chain
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Zombie processes visible in this pid namespace (state `Z`).
fn cmd_zombies() -> String {
    let mut z = Vec::new();
    for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i64>().ok()) else {
            continue;
        };
        let st = fs::read_to_string(e.path().join("status")).unwrap_or_default();
        if st
            .lines()
            .any(|l| l.starts_with("State:") && l.contains('Z'))
        {
            z.push(pid.to_string());
        }
    }
    format!("OK n={} pids={}", z.len(), z.join(","))
}

static WINCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn winsize_str() -> String {
    // SAFETY: ioctl with a zeroed winsize on fd 0.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
            format!("{}x{}", ws.ws_col, ws.ws_row)
        } else {
            "none".into()
        }
    }
}

/// Print isatty + size, wait (up to 8 s) for SIGWINCH, print the new size.
/// One line each, flushed, so the host-side driver can react between them.
fn cmd_tty_resize() -> String {
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
    // SAFETY: isatty only inspects the descriptor.
    let is = unsafe { libc::isatty(0) == 1 };
    println!("FIRST isatty={} size={}", is as u8, winsize_str());
    let _ = std::io::stdout().flush();
    for _ in 0..160 {
        if WINCH.load(std::sync::atomic::Ordering::SeqCst) {
            return format!("RESIZED size={}", winsize_str());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    "NO_WINCH".into()
}

fn cmd_tty() -> String {
    // SAFETY: isatty and ioctl with a zeroed winsize on fd 0.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        let is = libc::isatty(0) == 1;
        let got = libc::ioctl(0, libc::TIOCGWINSZ, &mut ws);
        format!(
            "OK isatty={} winsize={}x{}",
            is,
            if got == 0 { ws.ws_col } else { 0 },
            if got == 0 { ws.ws_row } else { 0 }
        )
    }
}

fn cmd_fds() -> String {
    let mut v: Vec<i32> = fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    format!(
        "OK {}",
        v.iter().map(i32::to_string).collect::<Vec<_>>().join(",")
    )
}

fn dispatch(a: &[String]) -> String {
    let arg = |i: usize| a.get(i).map(String::as_str).unwrap_or("");
    match arg(0) {
        "ppid" => cmd_ppid(),
        "ppid-chain" => cmd_ppid_chain(),
        "zombies" => cmd_zombies(),
        "tty-resize" => cmd_tty_resize(),
        "tty" => cmd_tty(),
        "fds" => cmd_fds(),
        "stat" => cmd_stat(arg(1)),
        "ls" => cmd_ls(arg(1)),
        "cat" => cmd_cat(arg(1)),
        "write" => cmd_write(arg(1)),
        "sameino" => cmd_sameino(arg(1), arg(2)),
        "pids" => cmd_pids(),
        "env" => cmd_env(),
        "caps" => cmd_caps(),
        "syscall" => cmd_syscall(arg(1)),
        "connect" => cmd_connect(arg(1), arg(2)),
        "loopback" => cmd_loopback(),
        "exec" if a.len() > 1 => cmd_exec(&a[1..]),
        "hold-queued" => cmd_hold_queued(arg(1)),
        "recv-write" => cmd_recv_write(),
        "mountinfo" => cmd_mountinfo(),
        other => format!("UNKNOWN_COMMAND {other}"),
    }
}

/// Command server: `DIR/in.N` → `DIR/out.N`; `quit` ends it.
fn serve(dir: &str) {
    let d = Path::new(dir);
    let _ = fs::write(d.join("ready"), b"1");
    let mut n = 1u64;
    loop {
        let inp = d.join(format!("in.{n}"));
        let Ok(mut f) = fs::File::open(&inp) else {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        let mut line = String::new();
        let _ = f.read_to_string(&mut line);
        let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        if args.first().map(String::as_str) == Some("quit") {
            let _ = fs::write(d.join(format!("out.{n}")), b"OK bye");
            return;
        }
        let out = dispatch(&args);
        let tmp = d.join(format!("out.{n}.tmp"));
        let _ = fs::write(&tmp, out);
        let _ = fs::rename(&tmp, d.join(format!("out.{n}")));
        n += 1;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("loop") if args.len() == 2 => serve(&args[1]),
        Some(_) => println!("{}", dispatch(&args)),
        None => eprintln!("usage: leakprobe loop DIR | <command> [args]"),
    }
}

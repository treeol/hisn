//! `hisn check` — Phase-0 host capability report.
//!
//! Every probe is a real attempt (fork + unshare, raw syscalls with invalid
//! arguments) rather than an inference from version numbers. Probes never
//! mutate host state: namespaces are created in a forked child that exits.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::Serialize;

/// Minimum kernel for open_tree/move_mount/mount_setattr (5.2 for the
/// syscalls, 5.12 for idmapped-mount attrs we rely on in the brief).
pub const MIN_KERNEL: (u32, u32) = (5, 12);

// Syscall numbers shared by x86_64 and aarch64 (unified table, >= 424).
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_MOUNT_SETATTR: libc::c_long = 442;
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
const SECCOMP_GET_ACTION_AVAIL: libc::c_ulong = 2;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    /// Optional feature missing; hisn still works.
    Warn,
    /// Required feature missing; `hisn run` cannot work on this host.
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub arch: &'static str,
    pub items: Vec<Item>,
}

impl Report {
    /// True when every *required* item is `Ok`.
    pub fn ok(&self) -> bool {
        self.items
            .iter()
            .all(|i| !i.required || i.status == Status::Ok)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "hisn host check ({})", self.arch);
        for i in &self.items {
            let tag = match i.status {
                Status::Ok => "ok  ",
                Status::Warn => "warn",
                Status::Fail => "FAIL",
            };
            let req = if i.required { "" } else { " (optional)" };
            let _ = writeln!(out, "  [{tag}] {:<22} {}{req}", i.name, i.detail);
        }
        let _ = writeln!(
            out,
            "result: {}",
            if self.ok() {
                "this host can run hisn"
            } else {
                "this host CANNOT run hisn sessions (required item failed)"
            }
        );
        out
    }
}

/// Parse `"7.2.13-200.fc44.x86_64"` into `(7, 2)`.
pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Count subordinate-id ranges of at least `min` ids for `user` in a
/// `/etc/subuid`-style file body. Matches on user name or numeric uid.
pub fn subid_ranges(body: &str, user: &str, uid: u32, min: u64) -> usize {
    let uid = uid.to_string();
    body.lines()
        .filter_map(|l| {
            let mut f = l.trim().split(':');
            let who = f.next()?;
            let _start: u64 = f.next()?.parse().ok()?;
            let count: u64 = f.next()?.parse().ok()?;
            ((who == user || who == uid) && count >= min).then_some(())
        })
        .count()
}

fn item(name: &'static str, required: bool, status: Status, detail: impl Into<String>) -> Item {
    Item {
        name,
        status,
        detail: detail.into(),
        required,
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn errno_name(e: i32) -> String {
    format!("{} (errno {e})", std::io::Error::from_raw_os_error(e))
}

fn check_kernel() -> Item {
    let uts = rustix::system::uname();
    let release = uts.release().to_string_lossy().into_owned();
    match parse_kernel(&release) {
        Some(v) if v >= MIN_KERNEL => item(
            "kernel",
            true,
            Status::Ok,
            format!("{release} (>= {}.{})", MIN_KERNEL.0, MIN_KERNEL.1),
        ),
        Some(_) => item(
            "kernel",
            true,
            Status::Fail,
            format!("{release} (< {}.{})", MIN_KERNEL.0, MIN_KERNEL.1),
        ),
        None => item(
            "kernel",
            true,
            Status::Fail,
            format!("cannot parse release {release:?}"),
        ),
    }
}

fn read_trim(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_owned())
}

/// Try the exact namespace set `hisn run` needs, in a forked child, and map
/// the caller's uid. Returns `Ok(())` or `(stage, errno)`.
fn probe_userns() -> Result<(), (&'static str, i32)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-element array for pipe2.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(("pipe", errno()));
    }
    // SAFETY: the process is single-threaded here (check runs before any
    // thread is spawned) and the child only calls async-signal-safe functions.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(("fork", errno()));
    }
    if pid == 0 {
        // Child: report "<stage> <errno>" through the pipe, then _exit.
        let report = |stage: &str, e: i32| -> ! {
            let msg = format!("{stage} {e}");
            // SAFETY: valid fd and buffer; _exit never returns.
            unsafe {
                libc::write(fds[1], msg.as_ptr().cast(), msg.len());
                libc::_exit(1)
            }
        };
        // SAFETY: plain syscalls with valid arguments.
        unsafe {
            let uid = libc::getuid();
            let gid = libc::getgid();
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                report("unshare(NEWUSER)", errno());
            }
            let flags =
                libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
            if libc::unshare(flags) != 0 {
                report("unshare(NEWNS|NEWPID|NEWIPC|NEWUTS)", errno());
            }
            let write_file = |path: &str, body: &str| -> i32 {
                let c = std::ffi::CString::new(path).expect("static path");
                let fd = libc::open(c.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return errno();
                }
                let n = libc::write(fd, body.as_ptr().cast(), body.len());
                let e = if n < 0 { errno() } else { 0 };
                libc::close(fd);
                e
            };
            let e = write_file("/proc/self/setgroups", "deny");
            if e != 0 {
                report("setgroups", e);
            }
            let e = write_file("/proc/self/uid_map", &format!("{uid} {uid} 1"));
            if e != 0 {
                report("uid_map", e);
            }
            let e = write_file("/proc/self/gid_map", &format!("{gid} {gid} 1"));
            if e != 0 {
                report("gid_map", e);
            }
            libc::_exit(0)
        }
    }
    // Parent.
    // SAFETY: closing our copy of the write end; reading from the read end.
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 128];
    // SAFETY: buf is valid for buf.len() bytes.
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
    // SAFETY: valid fd / pid.
    unsafe {
        libc::close(fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    if n <= 0 {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    let (stage, e) = text.rsplit_once(' ').unwrap_or((&text, "0"));
    let stage: &'static str = match stage {
        "unshare(NEWUSER)" => "unshare(NEWUSER)",
        "unshare(NEWNS|NEWPID|NEWIPC|NEWUTS)" => "unshare(NEWNS|NEWPID|NEWIPC|NEWUTS)",
        "setgroups" => "setgroups",
        "uid_map" => "uid_map",
        "gid_map" => "gid_map",
        _ => "probe",
    };
    Err((stage, e.parse().unwrap_or(0)))
}

fn check_userns() -> Vec<Item> {
    let mut v = Vec::new();
    let max = read_trim("/proc/sys/user/max_user_namespaces");
    let clone = read_trim("/proc/sys/kernel/unprivileged_userns_clone");
    let apparmor = read_trim("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    let mut sysctl = format!("max_user_namespaces={}", max.as_deref().unwrap_or("n/a"));
    if let Some(c) = clone {
        let _ = write!(sysctl, ", unprivileged_userns_clone={c}");
    }
    if let Some(a) = apparmor {
        let _ = write!(sysctl, ", apparmor_restrict_unprivileged_userns={a}");
    }
    v.push(item("userns sysctls", false, Status::Ok, sysctl));
    match probe_userns() {
        Ok(()) => v.push(item(
            "user namespaces",
            true,
            Status::Ok,
            "unshare(USER|NS|PID|IPC|UTS) + uid/gid map works",
        )),
        Err((stage, e)) => v.push(item(
            "user namespaces",
            true,
            Status::Fail,
            format!("{stage}: {}", errno_name(e)),
        )),
    }
    v
}

fn check_landlock() -> Item {
    // SAFETY: attr=NULL, size=0 with the VERSION flag is the documented probe.
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r >= 1 {
        let status = if r >= 3 { Status::Ok } else { Status::Warn };
        let note = if r >= 3 { "" } else { " (ABI 3+ preferred)" };
        item("landlock", true, status, format!("ABI v{r}{note}"))
    } else {
        let e = errno();
        item(
            "landlock",
            true,
            Status::Fail,
            format!("unavailable: {}", errno_name(e)),
        )
    }
}

fn check_seccomp() -> Item {
    let mut action = SECCOMP_RET_KILL_PROCESS;
    // SAFETY: action is a valid u32 pointer for SECCOMP_GET_ACTION_AVAIL.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0 as libc::c_ulong,
            &mut action as *mut u32,
        )
    };
    // Mode of the *current* process, for context.
    let mode = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Seccomp:").map(|m| m.trim().to_owned()))
        })
        .unwrap_or_else(|| "?".into());
    if r == 0 {
        item(
            "seccomp",
            true,
            Status::Ok,
            format!("filter mode, KILL_PROCESS available (current process mode={mode})"),
        )
    } else {
        let e = errno();
        item(
            "seccomp",
            true,
            Status::Fail,
            format!("seccomp(2) unavailable: {}", errno_name(e)),
        )
    }
}

/// How a mount-API probe ended, from inside a fresh user+mount namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The call ran far enough to be rejected for its (deliberately invalid)
    /// arguments: the kernel implements it and nothing filters it.
    Available(i32),
    Missing,
    /// `EPERM` *inside a user namespace we own* — an outer seccomp/LSM policy.
    Filtered,
}

/// Classify the errno of a deliberately-invalid call made with
/// `CAP_SYS_ADMIN` over our own mount namespace.
///
/// Why inside a namespace: `move_mount(2)` checks `may_mount()` before it
/// looks at any argument, so outside a user namespace an unprivileged process
/// gets `EPERM` regardless of seccomp. Probing there reported a false
/// "blocked by an outer seccomp filter" on a healthy host.
pub fn classify_probe(errno: i32) -> ProbeOutcome {
    match errno {
        libc::ENOSYS => ProbeOutcome::Missing,
        libc::EPERM => ProbeOutcome::Filtered,
        e => ProbeOutcome::Available(e),
    }
}

const PROBE_COUNT: usize = 3;
const MOUNT_PROBES: [&str; PROBE_COUNT] = ["open_tree", "move_mount", "mount_setattr"];

/// Run the three probes in a forked child that first enters a new user+mount
/// namespace with the caller's uid/gid mapped (exactly what `hisn run` does).
/// Returns the errno of each probe, or `(stage, errno)` if the namespace could
/// not be set up (then nothing was probed).
fn probe_mount_api() -> Result<[i32; PROBE_COUNT], (&'static str, i32)> {
    let uid_map = format!("{0} {0} 1", rustix::process::getuid().as_raw());
    let gid_map = format!("{0} {0} 1", rustix::process::getgid().as_raw());
    let mut fds = [0i32; 2];
    // SAFETY: valid 2-element array for pipe2.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(("pipe", errno()));
    }
    // SAFETY: the child below calls only raw syscalls on data prepared before
    // the fork (no allocation), then `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(("fork", errno()));
    }
    if pid == 0 {
        // Wire format: PROBE_COUNT x i32 errnos, or a single i32 stage code
        // (negative) followed by the errno.
        let fail = |stage: i32, e: i32| -> ! {
            let buf = [stage, e];
            // SAFETY: valid fd and buffer; `_exit` never returns.
            unsafe {
                libc::write(fds[1], buf.as_ptr().cast(), std::mem::size_of_val(&buf));
                libc::_exit(1)
            }
        };
        let put = |path: &std::ffi::CStr, body: &str| -> i32 {
            // SAFETY: plain open/write/close on a /proc file.
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return errno();
                }
                let n = libc::write(fd, body.as_ptr().cast(), body.len());
                let e = if n < 0 { errno() } else { 0 };
                libc::close(fd);
                e
            }
        };
        // SAFETY: plain syscalls with valid arguments.
        unsafe {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                fail(-1, errno());
            }
        }
        for (stage, path, body) in [
            (-2, c"/proc/self/setgroups", "deny"),
            (-3, c"/proc/self/uid_map", uid_map.as_str()),
            (-4, c"/proc/self/gid_map", gid_map.as_str()),
        ] {
            let e = put(path, body);
            if e != 0 {
                fail(stage, e);
            }
        }
        let nul = std::ptr::null::<u8>() as libc::c_long;
        let calls: [(libc::c_long, [libc::c_long; 5]); PROBE_COUNT] = [
            (SYS_OPEN_TREE, [-1, nul, 0, 0, 0]),
            (SYS_MOVE_MOUNT, [-1, nul, -1, nul, 0]),
            (SYS_MOUNT_SETATTR, [-1, nul, 0, nul, 0]),
        ];
        let mut out = [0i32; PROBE_COUNT];
        for (i, (nr, a)) in calls.iter().enumerate() {
            // SAFETY: arguments are invalid by construction (bad fd / null),
            // so the call can only fail; it cannot mutate state.
            let r = unsafe { libc::syscall(*nr, a[0], a[1], a[2], a[3], a[4]) };
            out[i] = if r >= 0 { 0 } else { errno() };
        }
        // SAFETY: valid fd and buffer.
        unsafe {
            libc::write(fds[1], out.as_ptr().cast(), std::mem::size_of_val(&out));
            libc::_exit(0)
        }
    }
    // SAFETY: closing our copy of the write end; reading from the read end.
    unsafe { libc::close(fds[1]) };
    let mut buf = [0i32; PROBE_COUNT];
    // SAFETY: buf is valid for its size.
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), std::mem::size_of_val(&buf)) };
    // SAFETY: valid fd / pid.
    unsafe {
        libc::close(fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    parse_probe_reply(&buf, n)
}

/// Interpret the child's reply (`n` bytes read into `buf`).
fn parse_probe_reply(
    buf: &[i32; PROBE_COUNT],
    n: isize,
) -> Result<[i32; PROBE_COUNT], (&'static str, i32)> {
    let full = (PROBE_COUNT * std::mem::size_of::<i32>()) as isize;
    if n == full && buf[0] >= 0 {
        return Ok(*buf);
    }
    if n >= 2 * std::mem::size_of::<i32>() as isize || buf[0] < 0 {
        let stage = match buf[0] {
            -1 => "unshare(NEWUSER|NEWNS)",
            -2 => "setgroups",
            -3 => "uid_map",
            -4 => "gid_map",
            _ => "probe",
        };
        return Err((stage, buf[1]));
    }
    Err(("probe child died", 0))
}

fn check_mount_api() -> Vec<Item> {
    match probe_mount_api() {
        Ok(errnos) => MOUNT_PROBES
            .iter()
            .zip(errnos)
            .map(|(name, e)| match classify_probe(e) {
                ProbeOutcome::Available(0) => item(name, true, Status::Ok, "available"),
                ProbeOutcome::Available(e) => item(
                    name,
                    true,
                    Status::Ok,
                    format!("available (probe errno {e})"),
                ),
                ProbeOutcome::Missing => item(name, true, Status::Fail, "missing (ENOSYS)"),
                ProbeOutcome::Filtered => item(
                    name,
                    true,
                    Status::Fail,
                    "blocked by an outer seccomp/LSM policy (EPERM inside our own user namespace)",
                ),
            })
            .collect(),
        Err((stage, e)) => MOUNT_PROBES
            .iter()
            .map(|name| {
                item(
                    name,
                    true,
                    Status::Fail,
                    format!("not probed: {stage} failed: {}", errno_name(e)),
                )
            })
            .collect(),
    }
}

fn check_subids() -> Item {
    let user = std::env::var("USER").unwrap_or_default();
    let uid = rustix::process::getuid().as_raw();
    let body = fs::read_to_string("/etc/subuid").unwrap_or_default();
    let n = subid_ranges(&body, &user, uid, 65536);
    let helper = [
        "/usr/bin/newuidmap",
        "/bin/newuidmap",
        "/usr/sbin/newuidmap",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    match (n > 0, helper) {
        (true, true) => item(
            "subuid ranges",
            false,
            Status::Ok,
            "65536-id range + newuidmap present (full-range mapping possible)",
        ),
        (true, false) => item(
            "subuid ranges",
            false,
            Status::Warn,
            "range present but newuidmap missing; single-id mapping only",
        ),
        (false, _) => item(
            "subuid ranges",
            false,
            Status::Warn,
            "no >=65536 range in /etc/subuid; single-id mapping only",
        ),
    }
}

fn check_misc() -> Vec<Item> {
    let mut v = Vec::new();
    let lsm = read_trim("/sys/kernel/security/lsm").unwrap_or_else(|| "unreadable".into());
    v.push(item("lsm list", false, Status::Ok, lsm));
    let cg = fs::read_to_string("/proc/self/mountinfo")
        .map(|s| s.contains(" - cgroup2 "))
        .unwrap_or(false);
    v.push(item(
        "cgroup v2",
        false,
        if cg { Status::Ok } else { Status::Warn },
        if cg {
            "mounted (used for limits in v1)"
        } else {
            "not mounted (limits via setrlimit only)"
        },
    ));
    v
}

pub fn run_checks() -> Report {
    let arch = std::env::consts::ARCH;
    let mut items = vec![check_kernel()];
    items.extend(check_userns());
    items.push(check_landlock());
    items.push(check_seccomp());
    items.extend(check_mount_api());
    items.push(check_subids());
    items.extend(check_misc());
    Report { arch, items }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_classification() {
        assert_eq!(classify_probe(libc::ENOSYS), ProbeOutcome::Missing);
        assert_eq!(classify_probe(libc::EPERM), ProbeOutcome::Filtered);
        // the errnos a healthy kernel returns for the deliberately bad calls
        for e in [libc::EBADF, libc::EFAULT, libc::EINVAL, libc::ENOENT] {
            assert_eq!(classify_probe(e), ProbeOutcome::Available(e));
        }
    }

    #[test]
    fn probe_reply_parsing() {
        assert_eq!(parse_probe_reply(&[9, 9, 22], 12), Ok([9, 9, 22]));
        assert_eq!(
            parse_probe_reply(&[0, libc::EBADF, 22], 12),
            Ok([0, libc::EBADF, 22])
        );
        assert_eq!(
            parse_probe_reply(&[-1, libc::EPERM, 0], 8),
            Err(("unshare(NEWUSER|NEWNS)", libc::EPERM))
        );
        assert_eq!(
            parse_probe_reply(&[-3, libc::EACCES, 0], 8),
            Err(("uid_map", libc::EACCES))
        );
        assert_eq!(
            parse_probe_reply(&[0, 0, 0], 0),
            Err(("probe child died", 0))
        );
    }

    #[test]
    fn mount_probes_never_report_a_false_filter_without_a_namespace() {
        // Whatever this machine allows, an un-probed or failed namespace setup
        // must be reported as "not probed", never as an outer seccomp filter
        // blamed on the syscall itself.
        for it in check_mount_api() {
            if it.status == Status::Fail {
                assert!(
                    it.detail.starts_with("not probed")
                        || it.detail.contains("inside our own user namespace")
                        || it.detail.contains("ENOSYS"),
                    "{}: {}",
                    it.name,
                    it.detail
                );
            }
        }
    }

    #[test]
    fn kernel_parse() {
        assert_eq!(parse_kernel("7.2.13-200.fc44.x86_64"), Some((7, 2)));
        assert_eq!(parse_kernel("5.12.0"), Some((5, 12)));
        assert_eq!(parse_kernel("6.1"), Some((6, 1)));
        assert_eq!(parse_kernel("garbage"), None);
    }

    #[test]
    fn subid_matching() {
        let body = "alice:100000:65536\nbob:200000:1000\n1000:300000:65536\n# c\nbad\n";
        assert_eq!(subid_ranges(body, "alice", 5, 65536), 1);
        assert_eq!(subid_ranges(body, "bob", 6, 65536), 0);
        assert_eq!(subid_ranges(body, "carol", 1000, 65536), 1);
        assert_eq!(subid_ranges("", "alice", 1, 1), 0);
    }

    #[test]
    fn report_ok_ignores_optional() {
        let r = Report {
            arch: "x86_64",
            items: vec![
                item("a", true, Status::Ok, ""),
                item("b", false, Status::Fail, ""),
            ],
        };
        assert!(r.ok());
        let r = Report {
            arch: "x86_64",
            items: vec![item("a", true, Status::Fail, "")],
        };
        assert!(!r.ok());
        assert!(r.render().contains("CANNOT"));
    }
}

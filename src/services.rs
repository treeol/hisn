//! Session services (DESIGN §17, §19): `[[host_services]]` and `[[services]]`.
//!
//! Host-service and in-sandbox service start, readiness and stop code, moved
//! out of [`crate::supervisor`] as a pure move (hisn 0.4.3): no behaviour
//! change. The supervisor owns the session lifecycle; this module owns how a
//! service process is started, awaited, and (via [`stop_and_reap`]) stopped.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};

use crate::exec::{self, ExecRules};
use crate::init;
use crate::profile;
use crate::sys;

/// Reap one of our own children (blocking `waitpid`), retrying on `EINTR`.
/// Returns the decoded exit status (see [`init::decode_status`]).
///
/// Merged from the former `reap`/`reap_host` pair in `supervisor.rs`, whose
/// bodies differed only in that one retried `EINTR` and the other did not;
/// the retrying form is the safe one for every caller.
pub fn reap(pid: i32) -> i32 {
    let mut st = 0;
    loop {
        // SAFETY: blocking waitpid on our own child.
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    init::decode_status(st)
}

/// A handle on a started in-sandbox service (DESIGN §19).
pub struct ServiceHandle {
    /// The status socket to the service's monitor `W`.
    pub status: OwnedFd,
    /// Stop spec (signal + grace).
    pub stop: profile::StopSpec,
}

/// Start an in-sandbox service through the exec helper chain (DESIGN §19).
/// The service is spawned like an exec: the exec helper `E` forks `C`, which
/// joins the sandbox namespaces, forks `D` (re-applies confinement), forks `W`
/// (monitor), which forks `P` (the service). The service gets stdio from
/// `/dev/null` (no client connection).
pub fn start_in_sandbox_service(
    shared: &Arc<crate::supervisor::Shared>,
    s: &profile::Service,
    rules: &ExecRules,
) -> Result<ServiceHandle> {
    // Build the ExecSpec for the service.
    let argv: Vec<String> = s.exec.to_vec();
    if argv.is_empty() || argv[0].is_empty() {
        bail!("service {}: exec must not be empty", s.name);
    }
    // The service's cwd is the session cwd.
    let cwd = rules.default_cwd.clone();
    // The service's env is the base env (same as the main command).
    let env = rules.base_env.clone();
    let spec = exec::ExecSpec {
        argv,
        cwd,
        env,
        tty: false,
    };
    // Open /dev/null for stdio (3 fds, non-tty mode). O_RDWR so the service
    // can write to stdout/stderr without EBADF.
    let stdio: Vec<OwnedFd> = (0..3)
        .map(|_| {
            OwnedFd::from(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .expect("opening /dev/null for service stdio"),
            )
        })
        .collect();
    // Spawn through the exec helper.
    let spawned = {
        let _gate = shared
            .spawn_gate()
            .read()
            .unwrap_or_else(|e| e.into_inner());
        shared.exec().spawn(&spec, stdio, exec::SPAWN_TIMEOUT)
    };
    let sp = spawned.map_err(|e| anyhow!("service {}: spawn: {e}", s.name))?;
    // Register the service in the shared state for ls --json.
    {
        let mut svcs = shared.services().lock().expect("services");
        // The status socket is dup'd for the ServiceState so inspect() can
        // poll it for liveness (P26).
        let status_dup = sys::dup_cloexec_min(sp.status.as_raw_fd(), 3)
            .map_err(|e| anyhow!("service {}: dup status fd: {e}", s.name))?;
        svcs.insert(
            s.name.clone(),
            crate::supervisor::ServiceState {
                name: s.name.clone(),
                pid: sp.pid,
                socket: s.socket.clone(),
                state: "ready",
                exit: None,
                status: status_dup,
            },
        );
    }
    // The status socket is owned by the supervisor; we read P and X lines from
    // it to track the service's state for ls --json.
    let stop = s.stop.clone().unwrap_or(profile::StopSpec {
        signal: "TERM".into(),
        grace: 5,
    });
    tracing::info!("service: {} started pid {}", s.name, sp.pid);
    Ok(ServiceHandle {
        status: sp.status,
        stop,
    })
}

/// Wait for an in-sandbox service to become ready (DESIGN §19).
/// Polls `ready.socket` (stat from the supervisor) with a timeout. On
/// timeout returns Err (fail closed). Only `socket` stat is available for
/// in-sandbox services in 0.3 (P25: `command` would run on the host with the
/// user's credentials; `tcp` is not available for in-sandbox services).
pub fn wait_service_readiness(s: &profile::Service, timeout_secs: u64) -> Result<()> {
    let ready = match &s.ready {
        Some(r) => r,
        None => {
            // No readiness check: assume ready immediately.
            return Ok(());
        }
    };
    let deadline = profile::checked_deadline(timeout_secs, "service readiness timeout")?;
    // 0.4.1 step 2: event wait instead of a fixed 100 ms poll. `ready.socket`
    // is stat'ed from the supervisor (userns S); that works for paths under
    // cwd and mounts.ro/rw, not for the sandbox's private tmpfs.
    let ready_fn = || {
        ready
            .socket
            .as_ref()
            .is_some_and(|sock| fs::symlink_metadata(sock).is_ok_and(|m| m.file_type().is_socket()))
    };
    if sys::wait_until(
        deadline.saturating_duration_since(std::time::Instant::now()),
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(20),
        ready_fn,
    ) {
        Ok(())
    } else {
        Err(anyhow!(
            "service {}: readiness timeout ({}s)",
            s.name,
            timeout_secs
        ))
    }
}

/// Start a `[[host_services]]` process on the host (in the supervisor's
/// userns S). The process runs with the user's credentials, the host PATH,
/// and `PR_SET_PDEATHSIG=SIGKILL`. Returns the pid.
pub fn start_host_service(h: &profile::HostService) -> Result<i32> {
    // Build every CString and pointer vector before fork: between fork and
    // exec there must be no allocation, no unwrap, and no panic path (the
    // supervisor may be multithreaded when this runs — the SSH accept thread
    // can already exist). NUL bytes are rejected at profile validation, so
    // CString::new cannot fail here; on the impossible error, fail closed
    // before forking.
    let argv: Vec<std::ffi::CString> = h
        .exec
        .iter()
        .map(|s| std::ffi::CString::new(s.as_str()))
        .collect::<std::result::Result<_, _>>()
        .context("host service exec contains NUL byte")?;
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let prog = argv_ptrs[0];
    let argv_ptr = argv_ptrs.as_ptr();
    // SAFETY: fork + prctl/execvp on our own child. The child path below
    // performs no allocation, no unwrap and no panic path; `execvp` does
    // not allocate on glibc or musl as far as verified — that allocation
    // claim is unverified for the libc versions in use (libc 0.2.191 wraps
    // the host libc, whose version was not checked).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork host service");
    }
    if pid == 0 {
        // Child: set PDEATHSIG so it dies with the supervisor. It stays in
        // the supervisor's process group, as before: nothing kills the
        // host-service group on stop (open point: kill the whole
        // host-service process group on stop, for the later services.rs
        // refactor), and terminal signals must still reach it the old way.
        // SAFETY: prctl with valid scalar arguments.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
        }
        // Close all fds > 2 (don't leak supervisor fds into the host process).
        unsafe {
            // Raw syscall: the libc crate has no close_range wrapper on musl.
            // 4 = CLOSE_RANGE_CLOEXEC.
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                u32::MAX as libc::c_uint,
                4 as libc::c_uint,
            );
        }
        // SAFETY: execve replaces the process image; on failure, _exit.
        // No allocation here — argv was built before fork.
        unsafe { libc::execvp(prog, argv_ptr) };
        // Unreachable: execvp either succeeds (never returns) or fails.
        // _exit unconditionally so a failed exec can never fall through
        // into supervisor code.
        // SAFETY: _exit on exec failure.
        unsafe { libc::_exit(127) };
    }
    tracing::info!("host_service: {} started pid {pid}", h.name);
    Ok(pid)
}

/// Wait for a host service to become ready (DESIGN §17).
/// Polls `ready` (socket stat or command exit 0) until the overall
/// deadline `timeout_secs` from now, passing the time remaining to each
/// probe. On timeout returns Err (fail closed).
pub fn wait_readiness(h: &profile::HostService, timeout_secs: u64) -> Result<()> {
    let ready = match &h.ready {
        Some(r) => r,
        None => {
            // No readiness check: assume the socket exists immediately.
            // Verify the socket path exists.
            if !Path::new(&h.socket).exists() {
                return Err(anyhow!(
                    "host_service {}: socket {} does not exist",
                    h.name,
                    h.socket
                ));
            }
            return Ok(());
        }
    };
    let deadline = profile::checked_deadline(timeout_secs, "host service readiness timeout")?;
    // 0.4.1 step 2: event wait instead of a fixed 100 ms poll. Each probe
    // gets only the time remaining until the overall deadline, so a slow
    // probe can run up to `timeout` and a hung one is killed on time.
    let ready_fn = || {
        check_readiness(
            ready,
            deadline.saturating_duration_since(std::time::Instant::now()),
        )
    };
    if sys::wait_until(
        deadline.saturating_duration_since(std::time::Instant::now()),
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(20),
        ready_fn,
    ) {
        Ok(())
    } else {
        Err(anyhow!(
            "host_service {}: readiness timeout ({}s)",
            h.name,
            timeout_secs
        ))
    }
}

/// Check one readiness probe. Returns true if the service is ready.
///
/// The command probe runs in its own process group, killed and reaped
/// when the given probe deadline expires. `wait_readiness` passes the
/// time remaining until the overall readiness deadline, so a probe may
/// run for up to `ready.timeout` and a hung one is killed on time.
/// Inherited fds are closed in the child and `PDEATHSIG` is set, so a
/// hung probe cannot outlive the supervisor or hold the session open.
pub fn check_readiness(ready: &profile::ReadinessSpec, probe_timeout: std::time::Duration) -> bool {
    check_readiness_with_probe(ready, probe_timeout)
}

/// Test seam for [`check_readiness`] with an injectable probe deadline.
fn check_readiness_with_probe(
    ready: &profile::ReadinessSpec,
    probe_timeout: std::time::Duration,
) -> bool {
    // A spec naming `tcp` is never ready here: validation rejects it, so
    // this is unreachable today — but the fallback "no check: ready" must
    // never be reached by a spec naming a check this code cannot perform.
    // Fail closed.
    if ready.tcp.is_some() {
        return false;
    }
    // Socket stat: check if the socket file exists.
    if let Some(sock) = &ready.socket {
        if let Ok(meta) = fs::symlink_metadata(sock)
            && meta.file_type().is_socket()
        {
            return true;
        }
        return false;
    }
    // Command: run a command, exit 0 = ready.
    if let Some(cmd) = &ready.command {
        if cmd.is_empty() {
            return false;
        }
        // Build every CString and pointer vector before fork: between fork
        // and exec there must be no allocation, no unwrap, and no panic
        // path. NUL bytes are rejected at profile validation.
        let argv: Vec<std::ffi::CString> = match cmd
            .iter()
            .map(|s| std::ffi::CString::new(s.as_str()))
            .collect::<std::result::Result<_, _>>()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let prog = argv_ptrs[0];
        let argv_ptr = argv_ptrs.as_ptr();
        // SAFETY: fork + setpgid/prctl/execvp on our own child. The child
        // path performs no allocation, no unwrap and no panic path;
        // `execvp` does not allocate on glibc or musl as far as verified —
        // that allocation claim is unverified for the libc versions in
        // use (libc 0.2.191 wraps the host libc, whose version was not
        // checked).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                libc::setpgid(0, 0);
                // Close inherited fds (don't hold supervisor sockets open).
                libc::syscall(
                    libc::SYS_close_range,
                    3 as libc::c_uint,
                    u32::MAX as libc::c_uint,
                    4 as libc::c_uint,
                );
                libc::execvp(prog, argv_ptr);
                // Unconditional: a failed exec must never fall through.
                libc::_exit(1);
            }
        }
        // The child also sets its own group; do the same from the parent
        // (the usual both-sides pattern) so `killpg` cannot miss the
        // group if the child was slow to run its setpgid. Error ignored:
        // it fails only if the child already exec'd/exited, in which case
        // the group is the child's own and `kill(pid)` below still hits.
        // SAFETY: setpgid on our own child.
        unsafe {
            libc::setpgid(pid, pid);
        }
        // Poll the probe with the deadline; kill the whole group at the
        // deadline, then reap.
        let deadline = std::time::Instant::now() + probe_timeout;
        loop {
            let mut st = 0;
            // SAFETY: non-blocking waitpid on our own child.
            let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
            if r == pid {
                return st == 0;
            }
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // Any other waitpid error means not ready (and the child
                // is gone or unwaitable — do not spin).
                return false;
            }
            if std::time::Instant::now() >= deadline {
                // Kill the process group and the pid unconditionally, then
                // reap. `killpg` can miss if the child never made its
                // group; the direct `kill` guarantees the blocking reap
                // below can never wait on a live probe.
                // SAFETY: killpg/kill on our own child and its group.
                unsafe {
                    libc::killpg(pid, libc::SIGKILL);
                    libc::kill(pid, libc::SIGKILL);
                };
                let _ = reap(pid);
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    // No readiness check: assume ready.
    true
}

/// A stoppable service process: the signal delivery, the liveness check
/// during the grace period, and the final SIGKILL differ between host
/// services (a real pid) and in-sandbox services (a status socket); the
/// grace handling around them is identical, so [`stop_and_reap`] owns it.
///
/// `signal`: deliver `sig` (the stop signal, then `SIGKILL`).
/// `alive`: whether the process is still running (polled during grace).
pub trait Stoppable {
    fn signal(&self, sig: i32);
    fn alive(&self) -> bool;
}

/// Stop one service: deliver `sig`, wait out up to `grace` seconds while it
/// lives, then SIGKILL if it is still alive. Never panics.
///
/// `grace` is validated ≤ 86400, so `checked_add` cannot overflow in
/// practice; fall back to a far-future deadline on error.
pub fn stop_and_reap(target: &dyn Stoppable, sig: i32, grace: u64) {
    target.signal(sig);
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(grace))
        .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(86400));
    while std::time::Instant::now() < deadline {
        if !target.alive() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if target.alive() {
        target.signal(libc::SIGKILL);
    }
}

/// A `[[host_services]]` process: a real child pid. `alive` reaps it with a
/// non-blocking `waitpid` when it exits (a reaped pid is never signalled
/// again, per the pid-reuse rule); the final `signal(SIGKILL)` is followed
/// by a blocking reap.
pub struct HostServiceTarget {
    pub pid: i32,
}

impl Stoppable for HostServiceTarget {
    fn signal(&self, sig: i32) {
        let _ = sys::kill(self.pid, sig);
        if sig == libc::SIGKILL {
            let _ = reap(self.pid);
        }
    }

    fn alive(&self) -> bool {
        let mut st = 0;
        // SAFETY: non-blocking waitpid on our own child.
        let r = unsafe { libc::waitpid(self.pid, &mut st, libc::WNOHANG) };
        if r == self.pid {
            return false;
        }
        if r == 0 {
            return true;
        }
        // waitpid error: EINTR means still running; anything else (e.g.
        // ECHILD) means the child is gone — no kill may be sent to a
        // reaped pid, whose number may have been reused.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    }
}

impl Stoppable for ServiceHandle {
    fn signal(&self, sig: i32) {
        // The service's pid is in the sandbox pid ns; signal it via the
        // status socket (same as exec signal).
        let _ = sys::send_all(self.status.as_raw_fd(), exec::format_kill(sig).as_bytes());
    }

    fn alive(&self) -> bool {
        // Check if the status socket is still open (service still running).
        // If the service has already exited, the monitor is gone.
        let mut pollfds = [libc::pollfd {
            fd: self.status.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: poll on our own fd, non-blocking.
        let r = unsafe { libc::poll(&mut pollfds[0], 1, 0) };
        !(r > 0 && (pollfds[0].revents & (libc::POLLHUP | libc::POLLERR)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::{check_readiness, check_readiness_with_probe};
    use crate::profile;

    #[test]
    fn readiness_command_hang_is_killed_at_probe_deadline() {
        let ready = profile::ReadinessSpec {
            socket: None,
            tcp: None,
            command: Some(vec!["sh".into(), "-c".into(), "sleep 30".into()]),
            timeout: None,
        };
        let start = std::time::Instant::now();
        assert!(!check_readiness_with_probe(
            &ready,
            std::time::Duration::from_millis(200)
        ));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "probe must be killed at its deadline, not allowed to sleep 30s"
        );
    }

    #[test]
    fn readiness_command_success_and_failure() {
        let ok = profile::ReadinessSpec {
            socket: None,
            tcp: None,
            command: Some(vec!["true".into()]),
            timeout: None,
        };
        assert!(check_readiness(&ok, std::time::Duration::from_secs(2)));
        let fail = profile::ReadinessSpec {
            socket: None,
            tcp: None,
            command: Some(vec!["false".into()]),
            timeout: None,
        };
        assert!(!check_readiness(&fail, std::time::Duration::from_secs(2)));
    }

    #[test]
    fn tcp_only_spec_is_not_ready() {
        // Validation rejects `ready.tcp`, so this is unreachable today —
        // but the fallback "no check: ready" must never be reached by a
        // spec naming a check the code cannot perform. Fail closed.
        let ready = profile::ReadinessSpec {
            socket: None,
            tcp: Some("127.0.0.1:80".into()),
            command: None,
            timeout: None,
        };
        assert!(!check_readiness_with_probe(
            &ready,
            std::time::Duration::from_secs(2)
        ));
    }

    #[test]
    fn readiness_command_slow_probe_succeeds_within_overall_deadline() {
        // A probe that takes 1 s and exits 0 must succeed when the probe
        // deadline is long enough (e.g. the remaining readiness timeout),
        // not be killed by an arbitrary short one.
        let ready = profile::ReadinessSpec {
            socket: None,
            tcp: None,
            command: Some(vec!["sh".into(), "-c".into(), "sleep 1; exit 0".into()]),
            timeout: None,
        };
        let start = std::time::Instant::now();
        assert!(check_readiness_with_probe(
            &ready,
            std::time::Duration::from_secs(3)
        ));
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(1),
            "the 1 s probe must actually have run"
        );
    }

    #[test]
    fn readiness_command_hang_is_killed_at_overall_deadline() {
        // A probe that hangs must be killed when the overall deadline is
        // reached: startup fails at about the timeout, not one probe
        // interval (or a further fixed 2 s) later.
        let ready = profile::ReadinessSpec {
            socket: None,
            tcp: None,
            command: Some(vec!["sh".into(), "-c".into(), "sleep 30".into()]),
            timeout: None,
        };
        let start = std::time::Instant::now();
        assert!(!check_readiness_with_probe(
            &ready,
            std::time::Duration::from_millis(300)
        ));
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "hung probe must be killed near the deadline, took {elapsed:?}"
        );
    }
}

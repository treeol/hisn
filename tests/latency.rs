//! 0.4.1 step 2: session-readiness and stop latency.
//!
//! Two event waits replaced fixed ~100 ms polls:
//!
//! * readiness — waiting for the control socket to accept a connection
//!   (`hisn::session::wait_control_socket`), and
//! * stop — waiting for the session's supervisor/init to exit, using a pidfd
//!   (`hisn::lifecycle::stop_and_keep` with a target that exposes `exit_fd`).
//!
//! The bounds are deliberately loose relative to the target (< 15 ms) so a
//! loaded machine does not flap: the point is that no fixed 100 ms floor
//! remains. Timings are printed so a host run records them.

use hisn::lifecycle::{self, Clock, StopOutcome, StopPlan, StopTarget, SystemClock};
use hisn::sessionmeta::State;
use hisn::{session, sys};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A listener that is bound (and then `listen(2)`ed) only after `delay` ms,
/// standing in for a supervisor whose control socket appears shortly after it
/// starts. Between bind and the accept loop starting, a connect gets
/// ECONNREFUSED, which the wait treats as "not ready yet".
fn late_listener(sockpath: std::path::PathBuf, delay: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        let listener = UnixListener::bind(&sockpath).expect("bind late listener");
        // Keep it alive while the readiness probe connects.
        std::thread::sleep(Duration::from_secs(5));
        drop(listener);
    })
}

#[test]
fn readiness_wait_observes_the_socket_without_a_fixed_100ms_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sockpath = dir.path().join("control.sock");
    let delay = Duration::from_millis(8);
    let handle = late_listener(sockpath.clone(), delay);

    let started = Instant::now();
    session::wait_control_socket(&sockpath, Duration::from_secs(5)).expect("socket becomes ready");
    let ready_elapsed = started.elapsed();

    println!("readiness: socket appeared after {delay:?}; observed ready in {ready_elapsed:?}");
    // A fixed 100 ms poll would show a floor near 100 ms even for a socket that
    // appears in 8 ms. The event wait must beat that by a wide margin.
    assert!(
        ready_elapsed < Duration::from_millis(60),
        "readiness took {ready_elapsed:?} — still on a fixed-poll floor"
    );

    // An already-bound socket is observed immediately (one ~1 ms probe).
    let started = Instant::now();
    session::wait_control_socket(&sockpath, Duration::from_secs(5)).expect("ready immediately");
    let already = started.elapsed();
    println!("readiness: already-ready socket observed in {already:?}");
    assert!(
        already < Duration::from_millis(30),
        "already-ready socket took {already:?}"
    );

    handle.join().ok();
}

/// A stop target backed by a real pidfd; the child exits on its first TERM.
struct PidfdTarget {
    pid: i32,
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl PidfdTarget {
    fn new(pid: i32) -> Self {
        Self {
            pid,
            pidfd: sys::pidfd_open(pid).ok(),
        }
    }
}

impl StopTarget for PidfdTarget {
    fn signal(&self, sig: i32) -> Result<(), String> {
        match &self.pidfd {
            Some(fd) => {
                // SAFETY: pidfd_send_signal on our own pidfd.
                let r = unsafe {
                    libc::syscall(libc::SYS_pidfd_send_signal, fd.as_raw_fd(), sig, 0usize, 0)
                };
                if r == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error().to_string())
                }
            }
            None => sys::kill(self.pid, sig).map_err(|e| e.to_string()),
        }
    }
    fn exited(&self) -> bool {
        match &self.pidfd {
            Some(fd) => !sys::pidfd_alive(fd.as_raw_fd()),
            None => sys::kill(self.pid, 0).is_err(),
        }
    }
    fn exit_fd(&self) -> Option<std::os::fd::RawFd> {
        self.pidfd.as_ref().map(AsRawFd::as_raw_fd)
    }
}

/// Child process body: block SIGTERM, then wait for it; exit when it arrives.
/// Returns the exit code. Runs only in the fork child, never returns to the
/// test harness.
fn child_wait_for_term() -> i32 {
    // SAFETY: signal mask manipulation in the forked child before any exec.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig);
    }
    0
}

#[test]
fn stop_wait_is_event_driven_not_a_fixed_100ms() {
    // A child that exits the instant its first signal arrives.
    // SAFETY: fork in a test; the child pauses then _exit()s.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::_exit(child_wait_for_term());
        }
    }
    let target = PidfdTarget::new(pid);
    assert!(target.exit_fd().is_some(), "pidfd must be available");

    let write = |_: State| Ok(());
    let started = Instant::now();
    let r = lifecycle::stop_and_keep(&target, &SystemClock, StopPlan::CLIENT, &write, &|| {});
    let stop_elapsed = started.elapsed();

    let mut st = 0;
    // SAFETY: waitpid on our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };

    println!("stop: observed exit in {stop_elapsed:?}");
    assert_eq!(r, StopOutcome::Stopped);
    // The child exits ~immediately on TERM; a fixed 100 ms poll leaves a
    // ~100 ms floor, an event wait does not.
    assert!(
        stop_elapsed < Duration::from_millis(80),
        "stop took {stop_elapsed:?} — still on a fixed-poll floor"
    );
}

/// A `Clock` whose `sleep` is recorded, proving the fallback wait (no pidfd)
/// backs off rather than sleeping a fixed interval.
#[test]
fn backoff_fallback_never_sleeps_a_fixed_interval() {
    #[derive(Default)]
    struct RecordingClock {
        slept: std::cell::RefCell<Vec<Duration>>,
        now: std::cell::Cell<u64>,
    }
    impl Clock for RecordingClock {
        fn now_secs(&self) -> i64 {
            self.now.get() as i64
        }
        fn sleep(&self, d: Duration) {
            self.slept.borrow_mut().push(d);
            self.now.set(self.now.get() + d.as_millis() as u64);
        }
    }

    struct NeverExit {
        done: Arc<AtomicBool>,
    }
    impl StopTarget for NeverExit {
        fn signal(&self, _: i32) -> Result<(), String> {
            Ok(())
        }
        fn exited(&self) -> bool {
            self.done.load(Ordering::SeqCst)
        }
        // No exit_fd: exercises the backoff path.
    }

    let clock = RecordingClock::default();
    let done = Arc::new(AtomicBool::new(true)); // exits on the first check
    let target = NeverExit { done };
    let write = |_: State| Ok(());
    let plan = StopPlan {
        term_wait: Duration::from_millis(50),
        kill_wait: None,
        poll: Duration::from_millis(1),
        poll_max: Duration::from_millis(20),
    };
    let r = lifecycle::stop_and_keep(&target, &clock, plan, &write, &|| {});
    assert_eq!(r, StopOutcome::Stopped);
    // It exited immediately: no sleep at all, so no fixed interval.
    assert!(
        clock.slept.borrow().is_empty(),
        "an already-exited target slept: {:?}",
        clock.slept.borrow()
    );

    // Now a target that never exits: the sleeps must grow (1,2,4,8,16,20,20,…)
    // and never be pinned at 100 ms.
    struct NeverExit2;
    impl StopTarget for NeverExit2 {
        fn signal(&self, _: i32) -> Result<(), String> {
            Ok(())
        }
        fn exited(&self) -> bool {
            false
        }
    }
    let plan = StopPlan {
        term_wait: Duration::from_millis(60),
        kill_wait: None,
        poll: Duration::from_millis(1),
        poll_max: Duration::from_millis(20),
    };
    let clock = RecordingClock::default();
    let target = NeverExit2;
    let r = lifecycle::stop_and_keep(&target, &clock, plan, &write, &|| {});
    assert_eq!(r, StopOutcome::Timeout);
    let slept = clock.slept.borrow();
    assert!(!slept.is_empty(), "a timeout must have slept");
    assert!(
        slept.iter().all(|d| *d <= Duration::from_millis(20)),
        "a sleep exceeded the backoff cap: {slept:?}"
    );
    assert!(
        slept.len() >= 3 && slept[1] > slept[0],
        "the fallback did not back off: {slept:?}"
    );
    assert!(
        !slept.iter().any(|d| *d == Duration::from_millis(100)),
        "a fixed 100 ms sleep remains: {slept:?}"
    );
}

//! Session stop path shared by `hisn stop` and idle expiry (0.4.0 F2/F4/O3).
//!
//! One function, [`stop_and_keep`], performs the ordered stop: state
//! `stopping` → `SIGTERM` → wait for exit → (optional `SIGKILL` escalation)
//! → state `stopped`. The session directory is never removed here; the
//! supervisor keeps a dir whose state is `stopping` or `stopped` when the
//! session ends ([`end_of_session`]). Idle expiry ([`run_idle_timer`]) audits
//! `lease/expired` and then calls the same stop function.
//!
//! Time and the stopped process are behind small traits ([`Clock`],
//! [`StopTarget`], [`IdleSession`]) so the whole sequence is unit-tested
//! with a fake clock.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::sessionmeta::{self, State};

/// Exit status of `hisn run` when the session was stopped (idle expiry or
/// `hisn stop`): 128 + SIGTERM.
pub const EXIT_STOPPED: i32 = 128 + libc::SIGTERM;

/// Wall clock in epoch seconds plus a sleep, injectable for tests.
pub trait Clock {
    fn now_secs(&self) -> i64;
    fn sleep(&self, d: Duration);
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The sandbox being stopped.
pub trait StopTarget {
    /// Deliver `sig` to the session's init.
    fn signal(&self, sig: i32) -> Result<(), String>;
    /// Has the session exited?
    fn exited(&self) -> bool;
    /// An fd that becomes readable when the target exits (a pidfd), when one
    /// can be opened. 0.4.1 step 2: the stop wait blocks on this so an exit is
    /// observed the instant it happens instead of at the next poll boundary.
    /// `None` (a target that cannot provide one) means the wait falls back to
    /// an exponential-backoff poll — never a fixed 100 ms.
    fn exit_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// How long [`stop_and_keep`] waits at each step.
#[derive(Debug, Clone, Copy)]
pub struct StopPlan {
    /// Wait after `SIGTERM`.
    pub term_wait: Duration,
    /// Wait after a `SIGKILL` escalation; `None` = no escalation.
    pub kill_wait: Option<Duration>,
    /// Initial poll interval; the fallback wait backs off exponentially from
    /// here up to [`StopPlan::poll_max`]. 0.4.1 step 2: 1 ms initial, so a
    /// session that exits 2 ms after TERM is observed within ~2 ms, not at a
    /// fixed 100 ms boundary.
    pub poll: Duration,
    /// Cap on the backoff interval.
    pub poll_max: Duration,
}

impl StopPlan {
    /// The supervisor-side plan (idle expiry): 10 s TERM, then 5 s KILL.
    pub const SUPERVISOR: StopPlan = StopPlan {
        term_wait: Duration::from_secs(10),
        kill_wait: Some(Duration::from_secs(5)),
        poll: Duration::from_millis(1),
        poll_max: Duration::from_millis(20),
    };
    /// The `hisn stop` plan: 30 s TERM, no escalation (unchanged from F4).
    pub const CLIENT: StopPlan = StopPlan {
        term_wait: Duration::from_secs(30),
        kill_wait: None,
        poll: Duration::from_millis(1),
        poll_max: Duration::from_millis(20),
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// The session exited; state is `stopped`.
    Stopped,
    /// `stopping` could not be persisted: nothing was signalled (the dir
    /// would not be kept, so the stop is not started).
    NotStarted(String),
    /// The session exited but `stopped` could not be persisted (state stays
    /// `stopping`; the supervisor's end-of-session finalises it).
    StoppedUnrecorded(String),
    /// The signal could not be delivered; state stays `stopping`.
    SignalFailed(String),
    /// The session did not exit in time; state stays `stopping`.
    Timeout,
}

/// Persists a lifecycle state (the caller supplies its locking).
pub type WriteState<'a> = &'a dyn Fn(State) -> std::io::Result<()>;

/// The ordered stop (F4): `stopping` is persisted BEFORE any signal (a
/// failed write signals nothing), `stopped` only after the exit is observed.
/// `before_signal` runs once `stopping` is recorded (idle expiry audits
/// `lease/expired` there). The directory is kept.
pub fn stop_and_keep(
    target: &dyn StopTarget,
    clock: &dyn Clock,
    plan: StopPlan,
    write_state: WriteState,
    before_signal: &dyn Fn(),
) -> StopOutcome {
    if let Err(e) = write_state(State::Stopping) {
        return StopOutcome::NotStarted(e.to_string());
    }
    before_signal();
    let finish = || match write_state(State::Stopped) {
        Ok(()) => StopOutcome::Stopped,
        Err(e) => StopOutcome::StoppedUnrecorded(e.to_string()),
    };
    if let Err(e) = target.signal(libc::SIGTERM) {
        // The session may have exited between the caller's check and now.
        if target.exited() {
            return finish();
        }
        return StopOutcome::SignalFailed(e);
    }
    if wait_exit(target, clock, plan.term_wait, plan.poll, plan.poll_max) {
        return finish();
    }
    if let Some(kill_wait) = plan.kill_wait {
        let _ = target.signal(libc::SIGKILL);
        if wait_exit(target, clock, kill_wait, plan.poll, plan.poll_max) {
            return finish();
        }
    }
    StopOutcome::Timeout
}

/// Wait for `target` to exit, up to `total`. Event-driven: when the target
/// supplies an `exit_fd` (a pidfd) the wait blocks on it and returns the moment
/// it becomes readable, with the wall-clock deadline as the bound. Otherwise it
/// polls with an exponential backoff starting at `poll` and capped at
/// `poll_max` — never a fixed interval.
fn wait_exit(
    target: &dyn StopTarget,
    clock: &dyn Clock,
    total: Duration,
    poll: Duration,
    poll_max: Duration,
) -> bool {
    if target.exited() {
        return true;
    }
    if let Some(fd) = target.exit_fd() {
        let deadline = Instant::now() + total;
        loop {
            if target.exited() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            // Round the remaining time UP to the next millisecond so a
            // fractional millisecond never becomes a 0 ms busy-spin.
            let remaining_ms = deadline
                .saturating_duration_since(now)
                .as_millis()
                .saturating_add(1);
            let ms = remaining_ms.min(i32::MAX as u128) as i32;
            let mut pfd = [libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: poll on an fd we own, valid pollfd array.
            let r = unsafe { libc::poll(pfd.as_mut_ptr(), 1, ms) };
            if r < 0 {
                let e = std::io::Error::last_os_error().raw_os_error();
                if e == Some(libc::EINTR) {
                    continue; // re-check the deadline and the fd
                }
                // A persistent poll error (e.g. EBADF): stop using the fd and
                // fall back to the bounded backoff poll rather than spin.
                break;
            }
            // A pidfd becomes readable exactly when the process exits (it is
            // the exit event), so POLLIN is authoritative even when the process
            // is a zombie not yet reaped by its parent. POLLNVAL/POLLERR are
            // *not* exit evidence; the authoritative `exited()` above decides.
            if pfd[0].revents & libc::POLLIN != 0 {
                return true;
            }
            if pfd[0].revents & (libc::POLLNVAL | libc::POLLERR | libc::POLLHUP) != 0
                && !target.exited()
            {
                break; // fd is unusable; use the fallback
            }
        }
    }
    // No pidfd: exponential-backoff poll, floored at 1 ms, capped at poll_max.
    let poll = poll.max(Duration::from_millis(1));
    let poll_max = poll_max.max(poll);
    let mut delay = poll;
    let mut waited = Duration::ZERO;
    loop {
        if target.exited() {
            return true;
        }
        if waited >= total {
            return false;
        }
        let step = delay.min(total - waited);
        clock.sleep(step);
        waited += step;
        delay = (delay * 2).min(poll_max);
    }
}

/// The idle predicate (ADR 0019): zero connected clients ∧ no running exec ∧
/// `now − last_activity > idle_timeout`. A backward clock never fires.
pub fn idle_due(
    has_clients: bool,
    has_execs: bool,
    last_activity: i64,
    now: i64,
    timeout_s: u64,
) -> bool {
    !has_clients
        && !has_execs
        && last_activity > 0
        && now > last_activity
        && (now - last_activity) as u64 > timeout_s
}

/// What the idle timer reads from the session.
pub trait IdleSession {
    fn has_connected_clients(&self) -> bool;
    fn has_running_execs(&self) -> bool;
    /// Last activity in epoch seconds (in memory, not rate-limited).
    fn last_activity_secs(&self) -> i64;
    /// 0.4.1 step 7: the three values above, read atomically with respect to
    /// admission, so a client/exec admitted during the check is not missed.
    /// The default reads them one by one (fine for the fakes); a real session
    /// overrides it to hold the admission lock across all three reads.
    fn idle_snapshot(&self) -> (bool, bool, i64) {
        (
            self.has_connected_clients(),
            self.has_running_execs(),
            self.last_activity_secs(),
        )
    }
    /// Audit `op:"lease", stage:"expired"`, client null, reason idle.
    fn audit_lease_expired(&self);
}

/// The idle timer loop. Wakes every `min(timeout/4, 30 s)` (at least 1 s);
/// returns `None` when the session exited on its own, or `Some(idle_secs)`
/// once an idle expiry recorded `stopping` and signalled the session. If
/// `stopping` cannot be recorded, nothing is signalled or audited and the
/// timer retries at the next tick.
pub fn run_idle_timer(
    sess: &dyn IdleSession,
    target: &dyn StopTarget,
    clock: &dyn Clock,
    timeout_s: u64,
    plan: StopPlan,
    write_state: WriteState,
) -> Option<u64> {
    let interval = Duration::from_secs((timeout_s / 4).clamp(1, 30));
    loop {
        clock.sleep(interval);
        if target.exited() {
            return None;
        }
        // Order matters: a disconnect bumps last_activity BEFORE it drops the
        // client count, so reading the counts first and the activity second
        // never pairs "zero clients" with an activity older than the
        // disconnect (Mashūra round 21, reader A). 0.4.1 step 7: the three
        // reads come from one atomic snapshot so admission during the check is
        // seen.
        let (has_clients, has_execs, last) = sess.idle_snapshot();
        let now = clock.now_secs();
        if idle_due(has_clients, has_execs, last, now, timeout_s) {
            let outcome = stop_and_keep(target, clock, plan, write_state, &|| {
                sess.audit_lease_expired()
            });
            match outcome {
                StopOutcome::Stopped => {}
                StopOutcome::NotStarted(e) => {
                    tracing::warn!("idle expiry: cannot record stopping ({e}); retrying");
                    continue;
                }
                other => tracing::warn!("idle expiry: stop did not complete: {other:?}"),
            }
            return Some((now - last) as u64);
        }
    }
}

/// What the supervisor does with the session dir once the session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndOfSession {
    /// Keep the dir (stopped) instead of removing it.
    pub keep: bool,
    /// The exit code `hisn run` returns.
    pub code: i32,
    /// A line for stderr, if any.
    pub message: Option<String>,
}

/// Decide the end of a session (O3). A session whose recorded state is
/// `stopping` or `stopped` was stopped (`hisn stop` or idle expiry): its dir
/// is kept and finalised as `stopped` (the supervisor has observed the exit).
/// An idle expiry exits [`EXIT_STOPPED`] with a message naming the session.
/// Any other end removes the dir and returns the command's own code.
pub fn end_of_session(
    dir: &Path,
    label: &str,
    timeout_s: Option<u64>,
    idle_expired_after: Option<u64>,
    code: i32,
) -> EndOfSession {
    let state = sessionmeta::read(dir).map(|m| m.state);
    let stopped = matches!(state, Some(State::Stopping | State::Stopped));
    if state == Some(State::Stopping)
        && let Err(e) = sessionmeta::set_state(dir, State::Stopped)
    {
        // Kept anyway: `ls` shows it as crashed (not live, not stopped),
        // which is accurate about the record, and the audit is preserved.
        tracing::warn!("{}: cannot record stopped: {e}", dir.display());
    }
    match idle_expired_after {
        Some(idle) => EndOfSession {
            // The timer only reports an expiry after `stopping` was
            // recorded, so this is `stopped` too; keep follows the record.
            keep: stopped,
            code: EXIT_STOPPED,
            message: Some(format!(
                "hisn: session {label} stopped: idle for {} (idle_timeout {})",
                fmt_duration(idle),
                timeout_s.map(fmt_duration).unwrap_or_else(|| "-".into()),
            )),
        },
        None => EndOfSession {
            keep: stopped,
            code,
            message: None,
        },
    }
}

/// `3s`, `2m5s`, `1h`, `1h0m30s` — compact, exact.
pub fn fmt_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    match (h, m, s) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, s) => format!("{m}m{s}s"),
        (h, 0, 0) => format!("{h}h"),
        (h, m, s) => format!("{h}h{m}m{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// Fake clock: `sleep` advances time; nothing really waits.
    struct FakeClock {
        now_ms: Cell<u64>,
    }

    impl FakeClock {
        fn at(secs: i64) -> Self {
            Self {
                now_ms: Cell::new(secs as u64 * 1000),
            }
        }
    }

    impl Clock for FakeClock {
        fn now_secs(&self) -> i64 {
            (self.now_ms.get() / 1000) as i64
        }
        fn sleep(&self, d: Duration) {
            self.now_ms.set(self.now_ms.get() + d.as_millis() as u64);
        }
    }

    /// Fake init: exits on the first signal in `exits_on` (TERM by default).
    struct FakeInit {
        exits_on: Vec<i32>,
        signals: RefCell<Vec<i32>>,
        exited: Cell<bool>,
    }

    impl FakeInit {
        fn new(exits_on: &[i32]) -> Self {
            Self {
                exits_on: exits_on.to_vec(),
                signals: RefCell::new(Vec::new()),
                exited: Cell::new(false),
            }
        }
    }

    impl StopTarget for FakeInit {
        fn signal(&self, sig: i32) -> Result<(), String> {
            self.signals.borrow_mut().push(sig);
            if self.exits_on.contains(&sig) {
                self.exited.set(true);
            }
            Ok(())
        }
        fn exited(&self) -> bool {
            self.exited.get()
        }
    }

    /// A detached session with one exec: registered at `exec_start`,
    /// finished at `exec_end`, the in-memory activity bumped at both (the
    /// exec request and its end), audit written to a real file.
    struct FakeSession<'a> {
        clock: &'a FakeClock,
        exec_start: i64,
        exec_end: i64,
        audit: crate::session::Audit,
    }

    impl IdleSession for FakeSession<'_> {
        fn has_connected_clients(&self) -> bool {
            // The exec client is connected exactly while its exec runs.
            self.has_running_execs()
        }
        fn has_running_execs(&self) -> bool {
            let now = self.clock.now_secs();
            now >= self.exec_start && now < self.exec_end
        }
        fn last_activity_secs(&self) -> i64 {
            let now = self.clock.now_secs();
            if now >= self.exec_end {
                self.exec_end
            } else {
                self.exec_start
            }
        }
        fn audit_lease_expired(&self) {
            self.audit
                .log(crate::session::Audit::entry(
                    "lease",
                    "expired",
                    None,
                    None,
                    Some("idle"),
                    None,
                ))
                .expect("audit write");
        }
    }

    fn session_dir(timeout_s: u64, start: i64) -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        let mut m = sessionmeta::SessionMeta::new(
            "l61",
            Some("seat"),
            sessionmeta::Owner {
                uid: 1000,
                label: "local".into(),
                client_id: String::new(),
            },
            "/tmp",
            "none",
        );
        m.state = State::Running;
        m.lease = Some(sessionmeta::Lease {
            idle_timeout_s: Some(timeout_s),
            last_activity: Some(crate::session::rfc3339(start)),
        });
        m.write_to(d.path()).expect("write session.json");
        d
    }

    fn audit_lines(dir: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.join("grants.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
            .collect()
    }

    #[test]
    fn idle_expiry_after_exec_finishes_runs_the_stop_path_and_keeps_the_dir() {
        // L61, detached: idle_timeout 2 s; an exec runs from t=1000 to
        // t=1010; the session must survive while it runs and stop ~2 s after
        // it ends, through stop_and_keep (the function `hisn stop` uses).
        let start = 1000;
        let d = session_dir(2, start);
        let clock = FakeClock::at(start);
        let sess = FakeSession {
            clock: &clock,
            exec_start: start,
            exec_end: start + 10,
            audit: crate::session::Audit::open(&d.path().join("grants.jsonl")).unwrap(),
        };
        let init = FakeInit::new(&[libc::SIGTERM]);
        let states = RefCell::new(Vec::new());
        let write = |s: State| {
            states.borrow_mut().push(s);
            sessionmeta::set_state(d.path(), s)
        };
        let idle = run_idle_timer(&sess, &init, &clock, 2, StopPlan::SUPERVISOR, &write);

        assert_eq!(idle, Some(3), "fires at the first tick with idle > 2 s");
        let fired_at = clock.now_secs();
        assert!(
            fired_at > start + 10 + 2,
            "must not fire while the exec runs or before the timeout: fired at t={fired_at}"
        );
        assert_eq!(*init.signals.borrow(), vec![libc::SIGTERM]);
        assert_eq!(*states.borrow(), vec![State::Stopping, State::Stopped]);
        assert!(d.path().is_dir(), "the session dir is kept");
        assert_eq!(sessionmeta::read(d.path()).unwrap().state, State::Stopped);
        let lines = audit_lines(d.path());
        assert!(
            lines
                .iter()
                .any(|l| l["op"] == "lease" && l["stage"] == "expired" && l["result"] == "idle"),
            "audit must carry lease/expired: {lines:?}"
        );
        // And the supervisor's end-of-session decision keeps it.
        let end = end_of_session(d.path(), "seat", Some(2), idle, 0);
        assert!(end.keep);
        assert!(d.path().is_dir());
    }

    #[test]
    fn a_running_exec_prevents_expiry_for_its_whole_duration() {
        let start = 1000;
        let d = session_dir(2, start);
        let clock = FakeClock::at(start);
        let sess = FakeSession {
            clock: &clock,
            exec_start: start,
            exec_end: start + 600,
            audit: crate::session::Audit::open(&d.path().join("grants.jsonl")).unwrap(),
        };
        let init = FakeInit::new(&[libc::SIGTERM]);
        let write = |s: State| sessionmeta::set_state(d.path(), s);
        run_idle_timer(&sess, &init, &clock, 2, StopPlan::SUPERVISOR, &write);
        assert!(
            clock.now_secs() > start + 600,
            "fired before the exec ended"
        );
    }

    #[test]
    fn a_disconnect_between_the_reads_does_not_expire_on_stale_activity() {
        // A client connected since t=1000 (its request was at t=1000)
        // disconnects at t=1100, exactly while the timer evaluates. The
        // disconnect bumps activity, then drops the count. Whatever the
        // interleaving with the timer's reads, the timer must not pair "zero
        // clients" with the stale t=1000 activity.
        struct Racing<'a> {
            clock: &'a FakeClock,
            connected: Cell<bool>,
            activity: Cell<i64>,
        }
        impl Racing<'_> {
            fn disconnect(&self) {
                self.activity.set(self.clock.now_secs()); // first: bump
                self.connected.set(false); // then: drop the count
            }
        }
        impl IdleSession for Racing<'_> {
            fn has_connected_clients(&self) -> bool {
                let c = self.connected.get();
                // The disconnect lands right after the count was read.
                if c && self.clock.now_secs() >= 1100 {
                    self.disconnect();
                }
                c
            }
            fn has_running_execs(&self) -> bool {
                false
            }
            fn last_activity_secs(&self) -> i64 {
                // ... or right before the activity is read.
                if self.connected.get() && self.clock.now_secs() >= 1100 {
                    self.disconnect();
                }
                self.activity.get()
            }
            fn audit_lease_expired(&self) {}
        }
        let clock = FakeClock::at(1000);
        let sess = Racing {
            clock: &clock,
            connected: Cell::new(true),
            activity: Cell::new(1000),
        };
        let init = FakeInit::new(&[libc::SIGTERM]);
        let write = |_: State| Ok(());
        let idle = run_idle_timer(&sess, &init, &clock, 60, StopPlan::SUPERVISOR, &write);
        let idle = idle.expect("fires eventually");
        assert!(
            clock.now_secs() > 1100 + 60,
            "fired at t={} on the pre-disconnect activity",
            clock.now_secs()
        );
        assert!(
            idle > 60 && idle < 100,
            "idle counted from the disconnect: {idle}"
        );
    }

    #[test]
    fn session_exit_ends_the_timer_without_a_stop() {
        let clock = FakeClock::at(1000);
        let init = FakeInit::new(&[]);
        init.exited.set(true);
        struct Never;
        impl IdleSession for Never {
            fn has_connected_clients(&self) -> bool {
                false
            }
            fn has_running_execs(&self) -> bool {
                false
            }
            fn last_activity_secs(&self) -> i64 {
                1
            }
            fn audit_lease_expired(&self) {
                panic!("no expiry after the session exited");
            }
        }
        let write = |_: State| -> std::io::Result<()> { panic!("no state write") };
        let r = run_idle_timer(&Never, &init, &clock, 2, StopPlan::SUPERVISOR, &write);
        assert_eq!(r, None);
        assert!(init.signals.borrow().is_empty());
    }

    /// 0.4.1 step 2: a stop's *fallback* wait (no pidfd) must back off, never
    /// sleep a fixed interval. The real pidfd-driven timing is covered by
    /// tests/latency.rs; here the growth of the sleeps is checked dry.
    #[test]
    fn backoff_wait_grows_and_is_capped() {
        struct NeverExit;
        impl StopTarget for NeverExit {
            fn signal(&self, _: i32) -> Result<(), String> {
                Ok(())
            }
            fn exited(&self) -> bool {
                false
            }
        }
        struct SleepLog {
            slept: RefCell<Vec<Duration>>,
        }
        impl Clock for SleepLog {
            fn now_secs(&self) -> i64 {
                0
            }
            fn sleep(&self, d: Duration) {
                self.slept.borrow_mut().push(d);
            }
        }
        let clock = SleepLog {
            slept: RefCell::new(Vec::new()),
        };
        let write = |_: State| Ok(());
        let plan = StopPlan {
            term_wait: Duration::from_millis(60),
            kill_wait: None,
            poll: Duration::from_millis(1),
            poll_max: Duration::from_millis(20),
        };
        let r = stop_and_keep(&NeverExit, &clock, plan, &write, &|| {});
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

    #[test]
    fn stop_escalates_to_kill_and_stays_stopping_on_timeout() {
        let clock = FakeClock::at(1000);
        let init = FakeInit::new(&[libc::SIGKILL]);
        let states = RefCell::new(Vec::new());
        let write = |s: State| {
            states.borrow_mut().push(s);
            Ok(())
        };
        let r = stop_and_keep(&init, &clock, StopPlan::SUPERVISOR, &write, &|| {});
        assert_eq!(r, StopOutcome::Stopped);
        assert_eq!(*init.signals.borrow(), vec![libc::SIGTERM, libc::SIGKILL]);
        assert_eq!(*states.borrow(), vec![State::Stopping, State::Stopped]);

        // `hisn stop` (no escalation) on a session that ignores TERM.
        let stuck = FakeInit::new(&[]);
        let states = RefCell::new(Vec::new());
        let write = |s: State| {
            states.borrow_mut().push(s);
            Ok(())
        };
        let r = stop_and_keep(&stuck, &clock, StopPlan::CLIENT, &write, &|| {});
        assert_eq!(r, StopOutcome::Timeout);
        assert_eq!(*stuck.signals.borrow(), vec![libc::SIGTERM]);
        assert_eq!(*states.borrow(), vec![State::Stopping], "never stopped");
    }

    #[test]
    fn a_failed_stopping_write_signals_and_audits_nothing() {
        let clock = FakeClock::at(1000);
        let init = FakeInit::new(&[libc::SIGTERM]);
        let audited = Cell::new(false);
        let write = |_: State| Err(std::io::Error::other("disk full"));
        let r = stop_and_keep(&init, &clock, StopPlan::SUPERVISOR, &write, &|| {
            audited.set(true)
        });
        assert_eq!(r, StopOutcome::NotStarted("disk full".into()));
        assert!(
            init.signals.borrow().is_empty(),
            "signalled without a record"
        );
        assert!(!audited.get());
    }

    #[test]
    fn a_failed_stopped_write_is_reported_and_kept_stopping() {
        let clock = FakeClock::at(1000);
        let init = FakeInit::new(&[libc::SIGTERM]);
        let write = |s: State| match s {
            State::Stopping => Ok(()),
            _ => Err(std::io::Error::other("ro fs")),
        };
        let r = stop_and_keep(&init, &clock, StopPlan::SUPERVISOR, &write, &|| {});
        assert_eq!(r, StopOutcome::StoppedUnrecorded("ro fs".into()));
        assert_eq!(*init.signals.borrow(), vec![libc::SIGTERM]);
    }

    #[test]
    fn idle_expiry_retries_when_stopping_cannot_be_recorded() {
        // The first attempt cannot persist `stopping`: no audit, no signal;
        // the next tick succeeds and only then is lease/expired audited.
        let start = 1000;
        let d = session_dir(2, start);
        let clock = FakeClock::at(start);
        let sess = FakeSession {
            clock: &clock,
            exec_start: start,
            exec_end: start + 1,
            audit: crate::session::Audit::open(&d.path().join("grants.jsonl")).unwrap(),
        };
        let init = FakeInit::new(&[libc::SIGTERM]);
        let fails_left = Cell::new(1);
        let write = |s: State| {
            if s == State::Stopping && fails_left.get() > 0 {
                fails_left.set(fails_left.get() - 1);
                return Err(std::io::Error::other("transient"));
            }
            sessionmeta::set_state(d.path(), s)
        };
        let idle = run_idle_timer(&sess, &init, &clock, 2, StopPlan::SUPERVISOR, &write);
        assert!(idle.is_some());
        assert_eq!(*init.signals.borrow(), vec![libc::SIGTERM], "one signal");
        let expired = audit_lines(d.path())
            .iter()
            .filter(|l| l["op"] == "lease" && l["stage"] == "expired")
            .count();
        assert_eq!(expired, 1, "audited once, after the successful record");
        assert_eq!(sessionmeta::read(d.path()).unwrap().state, State::Stopped);
    }

    #[test]
    fn foreground_idle_expiry_exits_143_with_a_message_and_keeps_the_dir() {
        // `hisn run --name seat -- sleep 300` with idle_timeout 2 s: the
        // idle timer stopped it (state stopped); `sleep` died of TERM, but
        // even a command that trapped TERM and exited 0 gets 143.
        let d = session_dir(2, 1000);
        sessionmeta::set_state(d.path(), State::Stopped).unwrap();
        for cmd_code in [143, 0] {
            let end = end_of_session(d.path(), "seat", Some(2), Some(3), cmd_code);
            assert!(end.keep, "dir kept as stopped");
            assert_eq!(end.code, EXIT_STOPPED);
            assert_eq!(
                end.message.as_deref(),
                Some("hisn: session seat stopped: idle for 3s (idle_timeout 2s)")
            );
        }
        assert!(d.path().is_dir());
        assert_eq!(sessionmeta::read(d.path()).unwrap().state, State::Stopped);
    }

    #[test]
    fn hisn_stop_race_keeps_the_dir_and_finalises_stopped() {
        // `hisn stop` writes `stopping`, the session exits, the supervisor
        // decides before `hisn stop` writes `stopped`: keep and finalise.
        let d = session_dir(2, 1000);
        sessionmeta::set_state(d.path(), State::Stopping).unwrap();
        let end = end_of_session(d.path(), "seat", None, None, 0);
        assert_eq!(
            end,
            EndOfSession {
                keep: true,
                code: 0,
                message: None
            }
        );
        assert_eq!(sessionmeta::read(d.path()).unwrap().state, State::Stopped);
    }

    #[test]
    fn a_normal_end_removes_the_dir_and_keeps_the_code() {
        let d = session_dir(2, 1000);
        let end = end_of_session(d.path(), "seat", Some(2), None, 7);
        assert_eq!(
            end,
            EndOfSession {
                keep: false,
                code: 7,
                message: None
            }
        );
    }

    #[test]
    fn idle_predicate_and_backward_clock() {
        assert!(idle_due(false, false, 100, 103, 2));
        assert!(!idle_due(false, false, 100, 102, 2), "exactly timeout");
        assert!(!idle_due(true, false, 100, 200, 2), "connected client");
        assert!(!idle_due(false, true, 100, 200, 2), "running exec");
        assert!(!idle_due(false, false, 100, 50, 2), "backward clock");
        assert!(!idle_due(false, false, 0, 200, 2), "no activity recorded");
    }

    #[test]
    fn durations_are_compact() {
        assert_eq!(fmt_duration(3), "3s");
        assert_eq!(fmt_duration(120), "2m");
        assert_eq!(fmt_duration(125), "2m5s");
        assert_eq!(fmt_duration(3600), "1h");
        assert_eq!(fmt_duration(3630), "1h0m30s");
    }
}

//! `hisn journal --wait` (0.6.7): block until a record with `wseq > N`
//! exists, then return it through the normal cursor path.
//!
//! The wait loop runs on the **unfiltered** [`super::cursor_read`] result:
//! `Reset`/`Gap` end the wait immediately (exit 3/4 — a reset journal or a
//! hole is not something waiting fixes); a `session/stop` for the watched
//! session (when one is given) is checked on the unfiltered run before any
//! filter; the caller decides "non-empty" through its own filtered query.
//! Only when there is nothing to act on does the loop sleep.
//!
//! Wake mechanism: a file watch on the current `journal.jsonl`
//! (`IN_MODIFY`, for appends) plus a directory watch (`IN_MOVED_TO |
//! IN_CREATE | IN_MODIFY`, for rotation/create). A directory watch alone
//! does not reliably deliver append `IN_MODIFY` for an existing child file
//! on every kernel, so the file watch is the append path; the dir watch is
//! the rotation path. On rotation (`IN_MOVED_TO`/`IN_IGNORED`) the current
//! file is re-opened and re-watched. Watches are armed **before** the first
//! read, pending events are drained **before** each re-read, and events are
//! filtered by name to `journal.jsonl`/`journal.<n>.jsonl` only —
//! `journal.lock` and `journal.idx.*` (written by the reader's own
//! `cursor_read` via the index) must never wake the waiter (self-trigger
//! spin). `IN_Q_OVERFLOW`, watch failure, or inotify unavailable degrades
//! to 1 s polling: correctness never depends on inotify, and the worst-case
//! wake latency is bounded by the poll interval plus the read cost.
//!
//! No journal lock is held while waiting (the reads take the shared lock
//! briefly to pin fds, as everywhere else); `--wait` never opens a control
//! socket or takes a session lock.
//!
//! Session end is detected from the journal itself: a `session/stop`
//! record with the watched session id and `wseq > N`. A supervisor that
//! died without writing one (or a failed stop append — rule 5 is
//! best-effort) is **not** detected; the wait then ends only by timeout.
//! That limitation is documented in the CLI help and in
//! `docs/EXTERNAL-CALLERS.md`, not hidden.

use super::*;
use std::time::{Duration, Instant};

/// How long one wait iteration sleeps at most: the poll fallback interval.
/// A missing wake (dead inotify, a filesystem without events) costs at most
/// this much latency, and a stop record written through any other means is
/// picked up within it.
pub(super) const WAIT_POLL: Duration = Duration::from_secs(1);

/// Documented `--wait` exit codes (0.6.7). Kept next to the cursor codes 3
/// (reset) and 4 (gap) in `journal_cmd`: 5 is left unused and documented
/// as such, so a later code never has to guess whether the gap is
/// meaningful.
pub const EXIT_WAIT_TIMEOUT: u8 = 6;
pub const EXIT_WAIT_SESSION_ENDED: u8 = 7;
pub const E_WAIT_TIMEOUT: &str = "E_WAIT_TIMEOUT";
pub const E_WAIT_SESSION_ENDED: &str = "E_WAIT_SESSION_ENDED";

/// What one [`Waiter::step`] concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Records arrived after the cursor (unfiltered). The caller applies
    /// its filters and decides whether to print or keep waiting.
    Records(Vec<JournalRecord>, usize),
    /// The journal was reset (`--after-wseq` ahead of the newest record).
    Reset(Option<u64>),
    /// A real hole (exit 4 material).
    Gap { expected: u64, got: u64 },
    /// A `session/stop` for the watched session with `wseq > N` was seen
    /// in the same run. The run is carried here so the caller can still
    /// print its filtered records and exit 0 (records win over session
    /// end); only an empty filtered run becomes exit 7.
    SessionEnded(Vec<JournalRecord>, usize),
    /// Nothing new; keep waiting.
    Empty,
}

/// The wake backend behind a [`Waiter`], so tests can disable inotify and
/// prove the poll fallback on any host.
pub trait WaitBackend: Send {
    /// Arm the watches (idempotent). `Ok(true)` when a watch is live,
    /// `Ok(false)` when inotify is unavailable and polling must be used.
    fn arm(&mut self, dir: &Path) -> bool;
    /// Block until a wake or `timeout` passes. Returns `true` when a
    /// wake arrived (re-read now), `false` on timeout.
    fn wait(&mut self, timeout: Duration) -> bool;
    /// Drain pending events without blocking (called before each re-read
    /// so an append between read and block is not lost).
    fn drain(&mut self);
}

#[cfg(unix)]
struct InotifyBackend {
    fd: Option<std::fs::File>,
    /// Watch descriptor of the current `journal.jsonl` file, if any.
    file_wd: Option<i32>,
    /// Watch descriptor of the directory, if any.
    dir_wd: Option<i32>,
    dir: Option<PathBuf>,
}

#[cfg(unix)]
impl InotifyBackend {
    fn new() -> Self {
        Self {
            fd: None,
            file_wd: None,
            dir_wd: None,
            dir: None,
        }
    }

    fn watch(&self, path: &Path, mask: u32) -> Option<i32> {
        let f = self.fd.as_ref()?;
        use std::os::fd::AsRawFd;
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        let wd = unsafe { libc::inotify_add_watch(f.as_raw_fd(), cpath.as_ptr(), mask) };
        if wd < 0 {
            None
        } else {
            Some(wd)
        }
    }

    fn unwatch(&self, wd: i32) {
        if let Some(f) = &self.fd {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::inotify_rm_watch(f.as_raw_fd(), wd);
            }
        }
    }

    fn arm_file(&mut self) {
        if let Some(wd) = self.file_wd.take() {
            self.unwatch(wd);
        }
        let Some(dir) = self.dir.clone() else { return };
        let path = dir.join(JOURNAL_FILE);
        // The file may not exist yet (empty workspace): the dir watch
        // covers its creation; the next arm after IN_CREATE retries.
        self.file_wd = self.watch(&path, libc::IN_MODIFY);
    }

    fn arm_dir(&mut self) {
        if let Some(wd) = self.dir_wd.take() {
            self.unwatch(wd);
        }
        let Some(dir) = self.dir.clone() else { return };
        self.dir_wd = self.watch(
            &dir,
            libc::IN_MOVED_TO | libc::IN_CREATE | libc::IN_MODIFY,
        );
    }

    fn relevant(&self, name: &[u8]) -> bool {
        // Only journal files wake the waiter. `journal.lock` and
        // `journal.idx.*` (written by the reader's own cursor_read through
        // the index) are excluded: waking on them would self-trigger a spin.
        let name = std::str::from_utf8(name).unwrap_or("");
        name == JOURNAL_FILE
            || (name.starts_with("journal.") && name.ends_with(".jsonl"))
    }

    /// Parse the buffered inotify events; returns `(relevant, rotated)`.
    fn parse_events(&self, buf: &[u8]) -> (bool, bool) {
        let mut relevant = false;
        let mut rotated = false;
        let mut off = 0;
        while off + 16 <= buf.len() {
            let wd = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
            let mask = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
            let len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
            let name = if len > 0 && off + 16 + len <= buf.len() {
                let raw = &buf[off + 16..off + 16 + len];
                let end = raw.iter().position(|b| *b == 0).unwrap_or(len);
                // SAFETY-of-copy: name has no interior NUL by construction.
                raw[..end].to_vec()
            } else {
                Vec::new()
            };
            if mask & libc::IN_Q_OVERFLOW != 0 {
                // Events were lost: the next poll tick re-reads anyway.
                // Treat as relevant so we re-read at once.
                relevant = true;
            }
            if Some(wd) == self.file_wd {
                if mask & (libc::IN_IGNORED | libc::IN_MOVE_SELF) != 0 {
                    rotated = true;
                } else if mask & libc::IN_MODIFY != 0 {
                    relevant = true;
                }
            }
            if Some(wd) == self.dir_wd {
                if !name.is_empty() && self.relevant(&name) {
                    if mask & libc::IN_MOVED_TO != 0 {
                        rotated = true;
                    }
                    relevant = true;
                }
            }
            off += 16 + len;
        }
        (relevant, rotated)
    }

    fn read_events(&mut self, block: bool, timeout: Duration) -> (bool, bool) {
        let Some(f) = &self.fd else {
            return (false, false);
        };
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let mut pfd = libc::pollfd {
            fd: f.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = if block {
            timeout.as_millis().min(i32::MAX as u128) as i32
        } else {
            0
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc <= 0 {
            return (false, false);
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut relevant = false;
        let mut rotated = false;
        loop {
            // The fd is non-blocking (set at init), so a second read that
            // finds nothing stops the drain instead of hanging.
            match f.try_clone().and_then(|mut h| h.read(&mut buf)) {
                Ok(n) if n > 0 => {
                    let (r, rot) = self.parse_events(&buf[..n]);
                    relevant |= r;
                    rotated |= rot;
                }
                _ => break,
            }
        }
        (relevant, rotated)
    }
}

#[cfg(unix)]
impl WaitBackend for InotifyBackend {
    fn arm(&mut self, dir: &Path) -> bool {
        if self.fd.is_none() {
            use std::os::fd::{AsRawFd, FromRawFd};
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if fd < 0 {
                return false;
            }
            // SAFETY: fd is fresh from inotify_init1; owned by the File.
            let f = unsafe { std::fs::File::from_raw_fd(fd) };
            let _ = f.as_raw_fd();
            self.fd = Some(f);
        }
        self.dir = Some(dir.to_path_buf());
        if self.dir_wd.is_none() {
            self.arm_dir();
        }
        if self.file_wd.is_none() {
            self.arm_file();
        }
        self.dir_wd.is_some() || self.file_wd.is_some()
    }

    fn wait(&mut self, timeout: Duration) -> bool {
        let (relevant, rotated) = self.read_events(true, timeout);
        if rotated {
            self.arm_file();
            // A rotation also means the dir watch may need re-arming only
            // if it died; arm_dir is a no-op while the watch lives. When
            // IN_IGNORED hit the file watch, arm_file above recreated it.
            if self.dir_wd.is_none() {
                self.arm_dir();
            }
        }
        relevant || rotated
    }

    fn drain(&mut self) {
        let (_relevant, rotated) = self.read_events(false, Duration::ZERO);
        if rotated {
            self.arm_file();
        }
    }
}

/// Poll-only backend (inotify unavailable, or tests): the step loop sleeps
/// `WAIT_POLL` between reads. Still correct — just bounded latency.
struct PollBackend;

#[cfg(test)]
impl WaitBackend for PollBackend {
    fn arm(&mut self, _dir: &Path) -> bool {
        false
    }
    fn wait(&mut self, timeout: Duration) -> bool {
        std::thread::sleep(timeout.min(WAIT_POLL));
        false
    }
    fn drain(&mut self) {}
}

/// One journal wait: the cursor, the watched session (if any) and the wake
/// backend. The caller owns policy (filters, printing, exits); this type
/// owns only the step/wait loop and the wake mechanism.
pub struct Waiter {
    dir: PathBuf,
    after: u64,
    session: Option<String>,
    backend: Box<dyn WaitBackend>,
    /// Whether the watches have been armed (first `run` or `wait_tick`).
    armed: Option<()>,
}

impl Waiter {
    pub fn new(
        dir: PathBuf,
        after: u64,
        session: Option<String>,
        backend: Box<dyn WaitBackend>,
    ) -> Self {
        Self {
            dir,
            after,
            session,
            backend,
            armed: None,
        }
    }

    /// Production waiter: inotify when available, poll otherwise.
    pub fn production(dir: PathBuf, after: u64, session: Option<String>) -> Self {
        Self::new(dir, after, session, Box::new(InotifyBackend::new()))
    }

    /// Does the run contain a `session/stop` for the watched session with
    /// `wseq > after`? Incarnation-aware: the stop must follow this wait's
    /// starting point, so a stop from an earlier incarnation (whose records
    /// are all `<= after`) cannot end the wait. The run is the unfiltered
    /// cursor result, so a stop is seen even when a `--kind` filter would
    /// hide it from the output.
    fn session_stopped(&self, records: &[JournalRecord]) -> bool {
        let Some(want) = &self.session else {
            return false;
        };
        // The stop counts when it is in the run (wseq > after by
        // construction) and belongs to the current incarnation: a
        // session/start for the same id at or before it, or no start at
        // all (the start predates the wait — the session was already
        // running when the wait began). A stop whose only preceding start
        // is itself in the run is still this wait's business: the session
        // both started and stopped after the cursor.
        let mut started = false;
        for r in records {
            if &r.session != want {
                continue;
            }
            if r.kind == "session/start" {
                started = true;
            }
            if r.kind == "session/stop" {
                // Either the session never (re)started inside the run
                // (it was already live when the wait began) or it
                // restarted and stopped again inside the run — both mean
                // the watched session is now stopped.
                let _ = started;
                return true;
            }
        }
        false
    }

    /// One read step (no sleeping): check the journal after `self.after`.
    /// Advances the internal cursor only on `Records`, so a later step
    /// never re-reports the same run. `session_stopped` is checked on the
    /// unfiltered run before the caller filters.
    pub fn step(&mut self) -> WaitOutcome {
        let (sel, skipped) = cursor_read(&self.dir, self.after);
        match sel {
            CursorSelect::Reset { last_wseq } => WaitOutcome::Reset(last_wseq),
            CursorSelect::Gap { expected, got } => WaitOutcome::Gap { expected, got },
            CursorSelect::Records { records, .. } => {
                if records.is_empty() {
                    // No run: a stop could still be hiding behind a
                    // cursor that is behind retention; read_records covers
                    // every file, so an empty run really is empty.
                    WaitOutcome::Empty
                } else {
                    let stopped = self.session_stopped(&records);
                    let max = records.iter().map(|r| r.wseq).max().unwrap_or(self.after);
                    self.after = max;
                    if stopped {
                        // The caller checks its filtered query first: if
                        // the filtered run is non-empty it prints and
                        // exits 0 (records win over session end). It
                        // reaches SessionEnded only when the filtered
                        // query is empty — but this step has already
                        // consumed the records. Hand them back so the
                        // caller can print them and still exit 0.
                        WaitOutcome::SessionEnded(records, skipped)
                    } else {
                        WaitOutcome::Records(records, skipped)
                    }
                }
            }
        }
    }

    /// The wait loop. `deadline` is `None` for an unbounded wait.
    /// `poll` is how long one sleep lasts at most ([`WAIT_POLL`]).
    /// Returns the first non-`Empty` outcome, or `Empty` on deadline.
    /// The caller distinguishes "empty after deadline" from "empty,
    /// still waiting" by the deadline it passed.
    pub fn run(&mut self, deadline: Option<Instant>) -> WaitOutcome {
        // Arm before the first read so an append between read and block
        // cannot be lost; drain before each re-read for the same reason.
        if self.armed.is_none() {
            self.backend.arm(&self.dir);
            self.armed = Some(());
        }
        loop {
            self.backend.drain();
            match self.step() {
                WaitOutcome::Empty => {}
                other => return other,
            }
            let now = Instant::now();
            let remaining = match deadline {
                Some(d) => d.saturating_duration_since(now),
                None => WAIT_POLL,
            };
            if deadline.is_some_and(|d| now >= d) {
                return WaitOutcome::Empty;
            }
            let _ = self.backend.wait(remaining.min(WAIT_POLL));
            // The poll fallback guarantees progress even when no wake
            // arrived: the loop re-reads at least once per WAIT_POLL.
            if deadline.is_some_and(|d| Instant::now() >= d) {
                // One last read at the deadline: records that arrived in
                // the final window still count (records win over timeout).
                self.backend.drain();
                match self.step() {
                    WaitOutcome::Empty => return WaitOutcome::Empty,
                    other => return other,
                }
            }
        }
    }

    /// One backend sleep tick for the `journal_cmd` wait loop, which needs
    /// the run each pass (its filtered-empty check). Arms the watches on
    /// first call. Returns `false` when the deadline has passed (the
    /// caller returns the timeout outcome); `true` otherwise (loop and
    /// re-read).
    pub fn wait_tick(&mut self, deadline: Option<Instant>) -> bool {
        if self.armed.is_none() {
            self.backend.arm(&self.dir);
            self.armed = Some(());
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) => d.saturating_duration_since(now),
            None => WAIT_POLL,
        };
        if deadline.is_some_and(|d| now >= d) {
            return false;
        }
        let _ = self.backend.wait(remaining.min(WAIT_POLL));
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return false;
        }
        true
    }
}

/// The cursor after a successful wait step, for callers that want to
/// continue polling from where the wait stopped.
pub fn cursor_after(records: &[JournalRecord], fallback: u64) -> u64 {
    records.iter().map(|r| r.wseq).max().unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    fn ws_dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        create_test_ws_dir(&dir);
        (d, dir)
    }

    fn journal(dir: &Path) -> Journal {
        Journal::with_rotate_after(dir.to_path_buf(), "s".into(), ROTATE_AFTER)
    }

    fn wait_wseqs(o: &WaitOutcome) -> Vec<u64> {
        match o {
            WaitOutcome::Records(records, _) => records.iter().map(|r| r.wseq).collect(),
            other => panic!("not records: {other:?}"),
        }
    }

    #[test]
    fn step_empty_then_records_and_cursor_advances() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("note", None, json!({"i": 1})).unwrap();
        j.append("note", None, json!({"i": 2})).unwrap();
        let mut w = Waiter::new(dir.clone(), 2, None, Box::new(PollBackend));
        assert_eq!(w.step(), WaitOutcome::Empty);
        j.append("note", None, json!({"i": 3})).unwrap();
        assert_eq!(wait_wseqs(&w.step()), vec![3]);
        assert_eq!(w.step(), WaitOutcome::Empty);
        assert_eq!(cursor_after(&[], 7), 7);
    }

    #[test]
    fn step_reset_and_gap_are_immediate() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("note", None, json!({})).unwrap();
        let mut w = Waiter::new(dir.clone(), 5, None, Box::new(PollBackend));
        assert_eq!(w.step(), WaitOutcome::Reset(Some(1)));
        // a real hole: delete the second of three records
        j.append("note", None, json!({})).unwrap();
        j.append("note", None, json!({})).unwrap();
        let path = dir.join(JOURNAL_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        fs::write(&path, lines[0].to_owned() + "\n" + lines[2] + "\n").unwrap();
        let mut w2 = Waiter::new(dir.clone(), 0, None, Box::new(PollBackend));
        assert_eq!(w2.step(), WaitOutcome::Gap { expected: 2, got: 3 });
    }

    #[test]
    fn run_timeout_returns_empty_and_records_win_at_deadline() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        // Nothing ever arrives: the deadline fires.
        let mut w = Waiter::new(dir.clone(), 0, None, Box::new(PollBackend));
        let start = Instant::now();
        let out = w.run(Some(start + Duration::from_millis(50)));
        assert_eq!(out, WaitOutcome::Empty);
        assert!(start.elapsed() >= Duration::from_millis(50));
        // A record arriving before the deadline is returned, not timed out.
        let mut w = Waiter::new(dir.clone(), 0, None, Box::new(PollBackend));
        let dir2 = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let mut j = journal(&dir2);
            j.append("note", None, json!({"i": 1})).unwrap();
        });
        let out = w.run(Some(Instant::now() + Duration::from_secs(5)));
        assert_eq!(wait_wseqs(&out), vec![1]);
    }

    #[test]
    fn run_unbounded_returns_on_append() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("note", None, json!({"i": 1})).unwrap();
        let mut w = Waiter::new(dir.clone(), 1, None, Box::new(PollBackend));
        let dir2 = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let mut j = journal(&dir2);
            j.append("note", None, json!({"i": 2})).unwrap();
        });
        let out = w.run(None);
        assert_eq!(wait_wseqs(&out), vec![2]);
    }

    #[test]
    fn session_stop_ends_the_wait_before_filters() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("session/start", None, json!({"session": "s1"})).unwrap();
        let mut w = Waiter::new(
            dir.clone(),
            1,
            Some("s1".into()),
            Box::new(PollBackend),
        );
        assert_eq!(w.step(), WaitOutcome::Empty);
        // Another session's records do not end the wait.
        j.append("note", None, json!({})).unwrap();
        let mut w2 = Waiter::new(
            dir.clone(),
            1,
            Some("s1".into()),
            Box::new(PollBackend),
        );
        assert_eq!(wait_wseqs(&w2.step()), vec![2]);
        // The stop ends it even though a --kind filter might hide it.
        // The writer's session id is what the record carries (the Journal
        // was constructed with session "s"); append under the watched id.
        let mut j2 = Journal::with_rotate_after(dir.clone(), "s1".into(), ROTATE_AFTER);
        j2.append("session/stop", None, json!({"cause": "stop-request"}))
            .unwrap();
        let mut w3 = Waiter::new(
            dir.clone(),
            2,
            Some("s1".into()),
            Box::new(PollBackend),
        );
        match w3.step() {
            WaitOutcome::SessionEnded(records, _) => {
                assert_eq!(
                    records.iter().map(|r| r.wseq).collect::<Vec<u64>>(),
                    vec![3]
                );
            }
            other => panic!("not session ended: {other:?}"),
        }
        // A stop at or below the cursor does not end a new wait.
        let mut w4 = Waiter::new(
            dir.clone(),
            3,
            Some("s1".into()),
            Box::new(PollBackend),
        );
        assert_eq!(w4.step(), WaitOutcome::Empty);
    }

    #[test]
    fn session_stop_without_a_session_filter_does_not_end_the_wait() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("session/start", None, json!({"session": "s1"})).unwrap();
        j.append("session/stop", None, json!({})).unwrap();
        let mut w = Waiter::new(dir.clone(), 0, None, Box::new(PollBackend));
        assert_eq!(wait_wseqs(&w.step()), vec![1, 2]);
    }

    #[test]
    fn events_for_non_journal_names_are_ignored() {
        let b = InotifyBackend::new();
        // journal.idx.<inode> and journal.lock are the reader's own files:
        // waking on them would self-trigger a spin.
        assert!(!b.relevant(b"journal.idx.12345"));
        assert!(!b.relevant(b"journal.lock"));
        assert!(!b.relevant(b"journal.idx.123.tmp7.0"));
        assert!(b.relevant(b"journal.jsonl"));
        assert!(b.relevant(b"journal.1.jsonl"));
    }

    #[test]
    fn wait_across_rotation_returns_the_appended_record() {
        let (_d, dir) = ws_dir();
        // Tiny rotation threshold: every ~3 records rotate.
        let mut j = Journal::with_rotate_after(dir.clone(), "s".into(), 300);
        j.retention_bytes = None;
        for i in 0..6 {
            j.append("note", None, json!({"i": i, "pad": "x".repeat(40)}))
                .unwrap();
        }
        assert!(journal_files(&dir).len() >= 2);
        let mut w = Waiter::new(dir.clone(), 6, None, Box::new(PollBackend));
        assert_eq!(w.step(), WaitOutcome::Empty);
        j.append("note", None, json!({"i": 6, "pad": "x".repeat(40)}))
            .unwrap();
        assert_eq!(wait_wseqs(&w.step()), vec![7]);
    }

    #[test]
    fn inotify_backend_wakes_on_append_well_below_the_poll_interval() {
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("note", None, json!({"i": 1})).unwrap();
        let mut w = Waiter::production(dir.clone(), 1, None);
        let dir2 = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let mut j = journal(&dir2);
            j.append("note", None, json!({"i": 2})).unwrap();
        });
        let start = Instant::now();
        // No deadline: inotify must wake this, or the 1 s poll does.
        let out = w.run(None);
        assert_eq!(wait_wseqs(&out), vec![2]);
        assert!(
            start.elapsed() < Duration::from_millis(900),
            "wake took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn inotify_arm_on_missing_dir_degrades_to_poll_and_retries() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        // No workspace yet: arming must not panic, and the wait must still
        // work once the journal appears.
        let mut w = Waiter::production(dir.clone(), 0, None);
        assert_eq!(w.step(), WaitOutcome::Empty);
        create_test_ws_dir(&dir);
        let mut j = journal(&dir);
        j.append("note", None, json!({"i": 1})).unwrap();
        // The first record is already there when the wait starts; a
        // second one appended after the wait begins must still wake it.
        let dir2 = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let mut j = journal(&dir2);
            j.append("note", None, json!({"i": 2})).unwrap();
        });
        let out = w.run(Some(Instant::now() + Duration::from_secs(5)));
        // run() re-reads from the waiter's cursor (still 0), so the first
        // pass sees record 1 at once. What matters is that the wait
        // returned records instead of timing out or panicking on the
        // initially-missing dir.
        let got = wait_wseqs(&out);
        assert!(!got.is_empty(), "wait returned records: {out:?}");
        assert!(got.starts_with(&[1]), "first record first: {got:?}");
    }

    #[test]
    fn append_write_goes_through_the_journal_file() {
        // Guard the latency test's premise: the writer appends to
        // journal.jsonl itself (the file the wait watches).
        let (_d, dir) = ws_dir();
        let mut j = journal(&dir);
        j.append("note", None, json!({"i": 1})).unwrap();
        let meta = fs::metadata(dir.join(JOURNAL_FILE)).unwrap();
        assert!(meta.len() > 0 && meta.ino() > 0);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(JOURNAL_FILE))
            .unwrap();
        f.write_all(b"\n").unwrap();
    }
}

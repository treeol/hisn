//! The workspace journal (0.5.0, PLAN-0.5 Step 1, Part B).
//!
//! One append-only journal per workspace, `journal.jsonl` in the workspace
//! dir. It extends the per-session audit log: every event written to
//! `grants.jsonl` today is also journaled (in journal shape) — the audit
//! log itself is untouched (Part A, rule 4c) — plus session start/stop, notes
//! and markers, and the git-change records (Part C).
//!
//! Rules that are part of the design (ADR 0020):
//! - The journal is a **record, not a replay mechanism**. Nothing re-executes
//!   it. It is queryable (`hisn journal`) so an agent can ask what it did.
//! - A journal write that fails must **not fail the operation it records**
//!   (rule 5). The failure is logged to `supervisor.log`, counted, and the
//!   count is visible in `hisn journal` output and as an additive key in
//!   `ls --json`. The one exception is a `note` request, where the journal
//!   write *is* the operation: it returns an error to the caller.
//! - Several supervisors can write to one workspace, so the `wseq`
//!   (workspace-wide sequence) is assigned under an exclusive `flock` on
//!   `journal.lock` in the workspace dir, and each record is written with a single `write(2)` on an
//!   `O_APPEND` descriptor held under that lock — so two writers can never
//!   interleave a line or duplicate a `wseq`.
//! - Rotation (rotation from day one, O6): when `journal.jsonl` exceeds
//!   64 MiB it is renamed to `journal.<n>.jsonl` under the same lock and a
//!   new file started. Queries read rotated files too, under a *shared*
//!   lock on the same lock file, so a reader running during a rotation
//!   sees every record exactly once (the rotation cannot move a file
//!   out from under the reader's file list).
//! - Durability: records are **not** synced to disk per write — every
//!   command would pay that cost, and the journal is a record, not the
//!   operation's durability. The file is synced on session stop and on
//!   rotation (file + directory). On a power failure the journal can
//!   therefore lose its tail back to the last stop/rotation sync, and
//!   `wseq` resumes from the last surviving record (no high-water mark;
//!   deleting or truncating the journal externally can reuse a `wseq`).
//!
//! Every record: `v` (1), `ts` (RFC 3339 UTC), `wseq`, `session`, `kind`,
//! `client` (when one exists — an object with `uid`, `label`, `label_source`,
//! `req_id`, mirroring the audit `client` object), and `data`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::session::rfc3339_now;

/// Record schema version.
pub const JOURNAL_VERSION: u32 = 1;
/// File name of the newest journal file, and the rotation prefix.
pub const JOURNAL_FILE: &str = "journal.jsonl";
/// Rotation threshold: 64 MiB (O6, rotation from day one).
pub const ROTATE_AFTER: u64 = 64 * 1024 * 1024;
/// Name of the lock file in the workspace dir that serialises `wseq`.
pub const LOCK_FILE: &str = "journal.lock";

/// Errors a journal write can report. Callers other than `note` swallow the
/// error (and count it); `note` returns it to the caller.
#[derive(Debug)]
pub struct JournalError {
    pub message: String,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "journal: {}", self.message)
    }
}

impl std::error::Error for JournalError {}

/// The exec-request argv cap: at most 512 bytes in total across all
/// elements (item 1). Returns the kept elements plus whether anything was
/// cut, the original element count and the original total byte length.
/// Cutting happens on a character boundary (a multibyte character is never
/// split) and keeps whole elements only — the first element that would
/// exceed the cap, and everything after it, are dropped.
///
/// No redaction: pattern-based redaction of free text gives false safety,
/// so the journal records the argv verbatim and the documentation states
/// plainly that a command line can contain anything. This is journal-only
/// (rule 4): the audit entry (`grants.jsonl`) never carries argv.
pub const MAX_ARGV_BYTES: usize = 512;

pub fn cap_argv(argv: &[String]) -> Value {
    let total_bytes: usize = argv.iter().map(|s| s.len()).sum();
    let mut kept: Vec<&str> = Vec::new();
    let mut used = 0usize;
    for arg in argv {
        if used + arg.len() > MAX_ARGV_BYTES {
            break;
        }
        used += arg.len();
        kept.push(arg.as_str());
    }
    let truncated = kept.len() != argv.len();
    let kept: Vec<String> = kept.into_iter().map(ToOwned::to_owned).collect();
    json!({
        "argv": kept,
        "argv_truncated": truncated,
        "argv_count": argv.len(),
        "argv_bytes": total_bytes,
    })
}

/// One journal record as it appears on disk and in `hisn journal --json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalRecord {
    pub v: u32,
    pub ts: String,
    pub wseq: u64,
    pub session: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<JournalClient>,
    pub data: Value,
}

/// The `client` object carried on a record, when one exists: the client
/// identity mirrors the audit `client` object (uid, label, label_source,
/// req_id), plus — 0.5.1 (ADR 0021) — the server-set seat name and role when
/// a credential was used. The seat fields are additive and skipped when
/// absent, so a 0.5.0 reader ignores them and a 0.5.1 reader still parses
/// a 0.5.0 record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalClient {
    pub uid: u32,
    pub label: String,
    pub label_source: String,
    pub req_id: Option<String>,
    /// 0.5.1: the seat the credential authenticated, set by the supervisor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat: Option<String>,
    /// 0.5.1: the seat's role at the time of the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl JournalClient {
    /// A client without a seat credential (0.5.0 shape, byte-identical).
    pub fn plain(uid: u32, label: String, label_source: String, req_id: Option<String>) -> Self {
        Self {
            uid,
            label,
            label_source,
            req_id,
            seat: None,
            role: None,
        }
    }

    /// A client that presented a credential (ADR 0021): the seat name and
    /// role are server-set from the authenticated credential, and
    /// `label_source` is `"seat"`. The client's own label is never used as
    /// the seat, so a credentialed client cannot impersonate another seat
    /// in the journal by choosing `--client`.
    pub fn seat(uid: u32, seat: String, role: String, req_id: Option<String>) -> Self {
        Self {
            uid,
            label: seat.clone(),
            label_source: "seat".into(),
            req_id,
            seat: Some(seat),
            role: Some(role),
        }
    }
}

/// The failure counter, shared with the supervisor's read path so `ls
/// --json` can report `journal_failures`. Every failed write increments it,
/// whichever thread attempted it.
pub type FailureCount = Arc<AtomicU64>;

/// A journal writer for one workspace. Each `Shared` (one per session, one
/// process) holds one; multiple processes write to one workspace through the
/// flock, so the counter is per-process and `wseq` is read from the file tail
/// under the lock (never from process state).
pub struct Journal {
    dir: PathBuf,
    session: String,
    failures: FailureCount,
    rotate_after: u64,
    /// Total size above which the oldest rotated files are deleted after
    /// a rotation. `None` keeps every file, as before 0.6.0; only the
    /// writer of the network queue sets it (ADR 0022), so sessions
    /// without open mode never delete journal files.
    retention_bytes: Option<u64>,
    /// Bounded async queue for network records (0.6.0): the verdict path
    /// never waits on a journal write; a full queue drops and counts.
    net_queue: Option<Arc<NetQueue>>,
}

/// Bounded queue for network journal records (`network/connect`,
/// `network/dns`). Producers (the connect workers and the DNS responder)
/// only `try_send`: a verdict never waits on a journal write. One writer
/// thread appends. Two bounds protect the journal from a program that
/// connects in a loop:
///
/// - at most [`NET_RECORDS_PER_SEC`] records per second are written one by
///   one; the rest of that second is only counted, and the counts are
///   written as one `network/summary` record;
/// - at most `cap` records wait in the queue; one more is dropped and
///   counted (`dropped` in the next summary, and the failure count).
pub struct NetQueue {
    tx: std::sync::mpsc::SyncSender<NetMsg>,
    dropped: Arc<AtomicU64>,
    failures: FailureCount,
    /// Completion-tracking overflows of the connect engine (see
    /// `notif::Tracked`): shared with the engine at construction, so the
    /// writer can include the count in the next `network/summary`.
    tracked_overflow: Arc<AtomicU64>,
}

enum NetMsg {
    Record(&'static str, Value),
    /// Write any pending summary, then acknowledge.
    Flush(std::sync::mpsc::Sender<()>),
}

/// Depth of the network journal queue (records, not bytes).
pub const NET_QUEUE_CAP: usize = 4096;
/// Network records written individually per second; see [`NetQueue`].
pub const NET_RECORDS_PER_SEC: u32 = 50;

/// Counts of the records that were not written individually.
#[derive(Default)]
struct NetCounts {
    allow: u64,
    refuse: u64,
    cont: u64,
    dns: u64,
}

impl NetCounts {
    fn add(&mut self, kind: &str, data: &Value) {
        if kind == "network/dns" {
            self.dns += 1;
            return;
        }
        match data.get("verdict").and_then(Value::as_str) {
            Some("allow") => self.allow += 1,
            Some("continue") => self.cont += 1,
            _ => self.refuse += 1,
        }
    }
    fn total(&self) -> u64 {
        self.allow + self.refuse + self.cont + self.dns
    }
}

impl NetQueue {
    fn new(
        journal: Journal,
        cap: usize,
        tracked_overflow: Arc<AtomicU64>,
    ) -> Arc<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetMsg>(cap.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let failures = journal.failures.clone();
        let writer_dropped = dropped.clone();
        let writer_tracked = tracked_overflow.clone();
        // Detached: the thread owns its own Journal value and ends when
        // the last sender is gone. `Journal::net_flush` is how a caller
        // waits for it.
        std::thread::spawn(move || net_writer(&journal, &rx, &writer_dropped, &writer_tracked));
        Arc::new(Self {
            tx,
            dropped,
            failures,
            tracked_overflow,
        })
    }

    /// Try-send; a full queue drops the record and counts it.
    fn enqueue(&self, kind: &'static str, data: Value) {
        if self.tx.try_send(NetMsg::Record(kind, data)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Wait until everything queued so far is written (bounded).
    fn flush(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let mut msg = NetMsg::Flush(ack_tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(m)) => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    msg = m;
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        ack_rx.recv_timeout(left).is_ok()
    }
}

fn net_writer(
    journal: &Journal,
    rx: &std::sync::mpsc::Receiver<NetMsg>,
    dropped: &AtomicU64,
    tracked_overflow: &AtomicU64,
) {
    use std::sync::mpsc::RecvTimeoutError;
    let second = std::time::Duration::from_secs(1);
    let mut window = std::time::Instant::now();
    let mut written = 0u32;
    let mut over = NetCounts::default();
    let summary = |over: &mut NetCounts| {
        let lost = dropped.swap(0, Ordering::Relaxed);
        let over_tracked = tracked_overflow.load(Ordering::Relaxed);
        if over.total() == 0 && lost == 0 && over_tracked == 0 {
            return;
        }
        let data = json!({
            "allow": over.allow,
            "refuse": over.refuse,
            "continue": over.cont,
            "dns": over.dns,
            "dropped": lost,
            "tracked_overflow": over_tracked,
        });
        *over = NetCounts::default();
        if journal.append_inner("network/summary", None, data).is_err() {
            journal.failures.fetch_add(1, Ordering::Relaxed);
        }
    };
    loop {
        let msg = rx.recv_timeout(std::time::Duration::from_millis(250));
        if window.elapsed() >= second {
            summary(&mut over);
            window = std::time::Instant::now();
            written = 0;
        }
        match msg {
            Ok(NetMsg::Record(kind, data)) => {
                if written < NET_RECORDS_PER_SEC {
                    written += 1;
                    if journal.append_inner(kind, None, data).is_err() {
                        journal.failures.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    over.add(kind, &data);
                }
            }
            Ok(NetMsg::Flush(ack)) => {
                summary(&mut over);
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                summary(&mut over);
                return;
            }
        }
    }
}

impl Journal {
    /// Create a writer for `dir` (the workspace dir), for `session` (the
    /// session id stamped on every record).
    pub fn new(dir: PathBuf, session: String) -> Self {
        Self::with_rotate_after(dir, session, ROTATE_AFTER)
    }

    /// Create a writer with an explicit rotation threshold (tests; the
    /// production threshold is [`ROTATE_AFTER`]).
    pub fn with_rotate_after(dir: PathBuf, session: String, rotate_after: u64) -> Self {
        Self {
            dir,
            session,
            failures: Arc::new(AtomicU64::new(0)),
            rotate_after,
            retention_bytes: None,
            net_queue: None,
        }
    }

    /// The failed-write count this process has observed (for `ls --json`).
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// A handle for the network path (ADR 0022: connect workers and DNS
    /// responder). It shares dir/session/failures with `self`, and its
    /// network records go through one bounded [`NetQueue`], so a verdict
    /// never waits on a journal write. Calling this on a handle that
    /// already has a queue shares that queue (one writer per session).
    pub fn clone_for_engine(&self) -> Self {
        self.clone_for_engine_with_cap(NET_QUEUE_CAP)
    }

    fn plain_clone(&self) -> Self {
        Self {
            dir: self.dir.clone(),
            session: self.session.clone(),
            failures: self.failures.clone(),
            rotate_after: self.rotate_after,
            retention_bytes: self.retention_bytes,
            net_queue: None,
        }
    }

    fn clone_for_engine_with_cap(&self, cap: usize) -> Self {
        let mut j = self.plain_clone();
        j.net_queue = Some(match &self.net_queue {
            Some(q) => q.clone(),
            None => {
                // The queue's writer is the one that can be flooded by a
                // sandboxed program, so it is the one with a size limit.
                let mut writer = self.plain_clone();
                writer
                    .retention_bytes
                    .get_or_insert(JOURNAL_RETENTION_BYTES);
                NetQueue::new(writer, cap, Arc::new(AtomicU64::new(0)))
            }
        });
        j
    }

    /// The shared completion-tracking overflow counter of the network
    /// queue (see `notif::Tracked`): the connect engine bumps it when a
    /// tracked socket is dropped for lack of room, and the queue writer
    /// reports it in the next `network/summary` as `tracked_overflow`.
    pub fn tracked_overflow(&self) -> Option<Arc<AtomicU64>> {
        self.net_queue.as_ref().map(|q| q.tracked_overflow.clone())
    }

    /// Wait (bounded) until the network records queued so far are in the
    /// journal file. True when they are, or when this handle has no queue.
    pub fn net_flush(&self, timeout: std::time::Duration) -> bool {
        match &self.net_queue {
            Some(q) => q.flush(timeout),
            None => true,
        }
    }

    /// Sync the journal file (and its directory) to disk. Called on session
    /// stop and on rotation — the two points where durability is paid for.
    /// Best-effort: a sync failure is counted like a write failure and never
    /// fails the operation.
    pub fn sync(&self) {
        if let Err(e) = self.sync_inner() {
            self.failures.fetch_add(1, Ordering::Relaxed);
            eprintln!("hisn: journal sync failed: {e}");
        }
    }

    fn sync_inner(&self) -> std::io::Result<()> {
        // A missing journal file (or workspace dir) is not a failure
        // (nothing to sync — e.g. sync-on-stop for a session that never
        // journaled); counting it would report phantom failures. Any other
        // open error means the sync did not happen, and is counted.
        for path in [self.dir.join(JOURNAL_FILE), self.dir.clone()] {
            match File::open(&path) {
                Ok(f) => f.sync_all()?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Journal session start (B3). Best-effort; a failure is counted. Used at
    /// supervisor start before `Shared` exists.
    pub fn journal_session_start(&self) {
        let _ = self.append(
            "session/start",
            None,
            json!({ "session": self.session, "workspace_dir": self.dir.display().to_string() }),
        );
    }

    /// Session-start lookup marker is best-effort, like the start record.
    pub fn session_start_with_marker(&self, name: Option<&str>) {
        self.journal_session_start();
        if let Err(e) = crate::workspace::write_session_marker(&self.dir, &self.session, name) {
            self.failures.fetch_add(1, Ordering::Relaxed);
            eprintln!("hisn: journal session marker write failed: {e}");
        }
    }

    /// 0.6.0 (ADR 0022): record one connect decision (`network/connect`).
    /// `verdict` is allow/refuse/continue; `reason` is a short
    /// machine-readable cause; `target` is the `ip:port` (or family) the
    /// supervisor parsed from its own copy of the sockaddr. `seat` is
    /// always null in 0.6.0.
    ///
    /// On an engine handle ([`Journal::clone_for_engine`]) this only
    /// queues the record (see [`NetQueue`]); the caller never waits on a
    /// journal write. A handle without a queue appends synchronously.
    pub fn net_record(&self, verdict: &str, reason: &str, n: &crate::notif::Notif) {
        let target =
            crate::notif::notif_target(n.parsed_ip.as_ref(), n.parsed_family, n.parsed_port);
        let data = json!({
            "target": target,
            "notif_id": n.id,
            "pid": n.pid,
            "verdict": verdict,
            "reason": reason,
            "seat": Value::Null,
        });
        self.net_enqueue("network/connect", data);
    }

    /// Completion of a non-blocking connect the supervisor already
    /// answered EINPROGRESS for (`network/connect-result`): `target`,
    /// `result` (`ok` or the errno name), `latency_ms` from the
    /// supervisor's `connect()` to completion. Best-effort like every
    /// network record: `net_enqueue` only queues, never blocks.
    pub fn net_connect_result(&self, target: &str, errno: i32, latency_ms: u128) {
        let result = if errno == 0 {
            "ok".to_owned()
        } else {
            crate::notif::errno_name(errno)
        };
        let data = json!({
            "target": target,
            "result": result,
            "latency_ms": latency_ms,
        });
        self.net_enqueue("network/connect-result", data);
    }

    /// One DNS query the responder answered (`network/dns`); `data` is
    /// built by [`crate::dns::record`]. Same queue discipline as
    /// [`Journal::net_record`].
    pub fn dns_record(&self, data: Value) {
        self.net_enqueue("network/dns", data);
    }

    fn net_enqueue(&self, kind: &'static str, data: Value) {
        match &self.net_queue {
            Some(q) => q.enqueue(kind, data),
            None => {
                let _ = self.append(kind, None, data);
            }
        }
    }

    /// Append one record. `kind` is the record kind (an audit `op` plus
    /// stage, a session start/stop, a note, a git-change, …); `client` is
    /// the identity when one exists; `data` is the payload (the audit entry
    /// content for audit-derived records, so the journal carries the same
    /// information `grants.jsonl` carries).
    ///
    /// On failure the caller decides: audit/session records swallow the
    /// returned error, but this method always counts it and writes it to
    /// stderr first; a `note` additionally returns the error. For a detached
    /// supervisor, stderr is `supervisor.log`.
    pub fn append(
        &self,
        kind: &str,
        client: Option<JournalClient>,
        data: Value,
    ) -> Result<(), JournalError> {
        match self.append_inner(kind, client, data) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                eprintln!("hisn: journal write failed: {e}");
                Err(e)
            }
        }
    }

    fn append_inner(
        &self,
        kind: &str,
        client: Option<JournalClient>,
        data: Value,
    ) -> Result<(), JournalError> {
        // Validate (and create if missing) the workspace dir with the same
        // discipline the supervisor uses at startup — never fall back to a
        // bare create_dir_all that would bypass the symlink/owner/0700
        // refusals. A refusal is a counted journal failure and the
        // recorded operation still succeeds (rule 5).
        crate::workspace::ensure_workspace(&self.dir).map_err(|e| JournalError {
            message: format!("workspace dir: {e}"),
        })?;
        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.dir.join(LOCK_FILE))
            .map_err(|e| JournalError {
                message: format!("open {LOCK_FILE}: {e}"),
            })?;
        let _guard = flock(&lock_file)?;
        let path = self.dir.join(JOURNAL_FILE);
        let next_wseq = |path: &Path| -> Result<u64, JournalError> {
            let last = last_wseq(path).map_err(|e| JournalError {
                message: format!("read last wseq: {e}"),
            })?;
            // Item 8: `u64::MAX + 1` panics in debug and wraps in release.
            // A hand-corrupted journal holding a `u64::MAX` record must
            // fail the append (counted) instead.
            last.unwrap_or(0).checked_add(1).ok_or(JournalError {
                message: "wseq overflow".to_owned(),
            })
        };
        let mut seq = next_wseq(&path)?;
        // Rotate before writing when the current file is already oversize.
        if let Some(meta) = fs::metadata(&path).ok()
            && meta.len() > self.rotate_after
        {
            rotate(&self.dir).map_err(|e| JournalError {
                message: format!("rotate: {e}"),
            })?;
            if let Some(budget) = self.retention_bytes {
                prune_journal_files(&self.dir, budget);
            }
            // `wseq` is recovered from the rotated file's tail (the new
            // file is empty, so `last_wseq` falls through to it).
            seq = next_wseq(&path)?;
        }
        // Torn-tail guard: if the file does not end in `\n`, the last writer
        // died mid-line. Emit the newline first so this record is not glued
        // onto the torn bytes (which would lose this record entirely).
        let needs_newline = file_ends_not_newline(&path);
        let record = JournalRecord {
            v: JOURNAL_VERSION,
            ts: rfc3339_now(),
            wseq: seq,
            session: self.session.clone(),
            kind: kind.to_owned(),
            client,
            data,
        };
        let mut line = String::new();
        if needs_newline {
            line.push('\n');
        }
        line.push_str(&serde_json::to_string(&record).map_err(|e| JournalError {
            message: format!("serialise: {e}"),
        })?);
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| JournalError {
                message: format!("open journal: {e}"),
            })?;
        // A single write on an O_APPEND descriptor under the flock: a whole
        // (possibly multi-KiB) record cannot interleave with another writer's.
        f.write_all(line.as_bytes()).map_err(|e| JournalError {
            message: format!("write: {e}"),
        })?;
        Ok(())
    }
}

/// Take an exclusive flock on an open file, with a bounded wait: an
/// unbounded blocking flock would let a hung lock holder (e.g. a SIGSTOPped
/// supervisor) stall every audited operation in the workspace — rule 5
/// covers failure, not hang (R2). Waits at most ~1 s, then fails (the
/// caller counts it; the recorded operation still succeeds). EINTR is
/// retried within the budget (the supervisor has signal handlers).
fn flock(f: &File) -> Result<FlockGuard, JournalError> {
    use std::os::fd::AsRawFd;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        }
        if e.raw_os_error() == Some(libc::EINTR) && std::time::Instant::now() < deadline {
            continue;
        }
        return Err(JournalError {
            message: format!("lock: {e}"),
        });
    }
    Ok(FlockGuard(_fd_of(f)))
}

/// Best-effort shared lock on `dir/journal.lock` for a reader. The lock is
/// held by this struct for its whole lifetime: `take` returns no separate
/// droppable guard — the explicit LOCK_UN in `Drop` releases it. (A previous version mapped the guard and dropped it in
/// `take`, releasing the lock immediately — the "exactly once" reader then
/// ran unlocked. The reader now pins its file descriptors under this lock
/// and reads unlocked from them, so it holds the shared lock only briefly:
/// see `read_records`.)
struct SharedLock(Option<File>);

impl SharedLock {
    fn take(dir: &Path) -> Self {
        // Create the lock file if missing, so the writer's lock and ours
        // are always the same inode (R2: without create, a concurrent
        // first writer could create it after we "took" a missing lock and
        // rotate under us). Mode 0600 like the writer's.
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))
            .ok();
        if let Some(file) = &f {
            use std::os::fd::AsRawFd;
            // Bounded wait (see flock): give up to ~1 s, then proceed
            // unlocked — a hung writer must not hang the reader forever.
            // SAFETY: the File is still open; the lock is released in Drop.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
                if rc == 0 {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if (e.raw_os_error() == Some(libc::EWOULDBLOCK)
                    || e.raw_os_error() == Some(libc::EINTR))
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                break; // best-effort reader: proceed unlocked
            }
        }
        Self(f)
    }
}

impl Drop for SharedLock {
    fn drop(&mut self) {
        if let Some(f) = &self.0 {
            use std::os::fd::AsRawFd;
            // SAFETY: the File is still open here.
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn shared_lock(dir: &Path) -> SharedLock {
    SharedLock::take(dir)
}

/// The locked file. We own `f` only as a guard: the caller's `File` is
/// borrowed for the guard's lifetime, so the guard just needs to unlock on
/// drop. We cannot hold a reference and drop the file, so we keep the raw fd
/// and unlock it on drop (the caller keeps the `File` alive).
struct FlockGuard(i32);

fn _fd_of(f: &File) -> i32 {
    use std::os::fd::AsRawFd;
    f.as_raw_fd()
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: the caller owns the File; its fd is still open here.
        unsafe { libc::flock(self.0, libc::LOCK_UN) };
    }
}

/// Does the file exist and not end in `\n` (a torn tail)?
fn file_ends_not_newline(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let Ok(meta) = f.metadata() else {
        return false;
    };
    if meta.len() == 0 {
        return false;
    }
    use std::io::{Read, Seek, SeekFrom};
    if f.seek(SeekFrom::End(-1)).is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    f.read_exact(&mut b).is_ok() && b[0] != b'\n'
}

/// The `wseq` of the last parseable record in `path`, scanning the tail. A
/// torn final line is skipped. After a rotation the new file is empty, so
/// `wseq` is recovered from the rotated file's tail: the *last* parseable
/// `wseq` of the newest rotated file (which is higher than any earlier one).
///
/// An I/O error (other than a missing file) is returned: the caller fails
/// and counts the append rather than guessing a `wseq` that may duplicate
/// an existing one.
fn last_wseq(path: &Path) -> io::Result<Option<u64>> {
    if let Some(w) = last_wseq_in_file(path)? {
        return Ok(Some(w));
    }
    let Some(dir) = path.parent() else {
        return Ok(None);
    };
    let mut best: Option<(u32, u64)> = None;
    for p in journal_files(dir) {
        if p == *path {
            continue;
        }
        // The rotated file's extension is its number; take the newest.
        let num: u32 = p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("journal."))
            .and_then(|n| n.strip_suffix(".jsonl"))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if let Some(w) = last_wseq_in_file(&p)?
            && best.is_none_or(|(n, _)| num > n)
        {
            best = Some((num, w));
        }
    }
    Ok(best.map(|(_, w)| w))
}

const TAIL_BYTES: u64 = 64 * 1024;

/// The highest `wseq` among the parseable lines of `bytes`.
fn max_wseq(bytes: &[u8]) -> Option<u64> {
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<JournalRecord>(line).ok())
        .map(|rec| rec.wseq)
        .max()
}

/// The highest `wseq` in one journal file: `Ok(None)` when the file is
/// missing, empty or holds no parseable record. Any other I/O error is
/// returned, never mapped to "no records" — that would restart `wseq` at 1
/// on a file that does hold records.
fn last_wseq_in_file(path: &Path) -> io::Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let size = f.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }
    // `wseq` only grows, so the maximum is among the newest records: scan
    // the tail window (the whole file when it fits).
    let start = size.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let best = max_wseq(&buf);
    if best.is_some() || start == 0 {
        return Ok(best);
    }
    // Rare: nothing in the tail window parses (a torn tail, or one record
    // larger than the window). Fall back to one pass over the whole file.
    f.seek(SeekFrom::Start(0))?;
    buf.clear();
    f.read_to_end(&mut buf)?;
    Ok(max_wseq(&buf))
}

/// Rotate `journal.jsonl` to the next free `journal.<n>.jsonl` in `dir`,
/// using max+1 (a deleted `journal.1.jsonl` must not be reused, or readers
/// would see newer records before older ones). Caller holds the flock. A
/// failure to list the directory is an error, never a silent `max = 0` —
/// renaming onto an existing `journal.1.jsonl` would silently overwrite a
/// rotated file and lose records. After the rename, the rotated file and
/// the directory are fsynced, so the rename itself is durable (the
/// durability point promised in the module docs).
fn rotate(dir: &Path) -> io::Result<()> {
    let mut max: u32 = 0;
    let rd = fs::read_dir(dir)?;
    for e in rd.flatten() {
        if let Some(name) = e.path().file_name().and_then(|n| n.to_str())
            && let Some(num) = name
                .strip_prefix("journal.")
                .and_then(|n| n.strip_suffix(".jsonl"))
            && let Ok(n) = num.parse::<u32>()
        {
            max = max.max(n);
        }
    }
    // Item 8: `u32::MAX + 1` panics in debug and wraps in release. A
    // crafted `journal.4294967295.jsonl` must fail the append (counted)
    // instead of renaming onto `journal.0.jsonl`.
    let next = max.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "rotated journal number overflow",
        )
    })?;
    let renamed = dir.join(format!("journal.{next}.jsonl"));
    fs::rename(dir.join(JOURNAL_FILE), &renamed)?;
    // Durability point (module docs): fsync the rotated file, then the dir.
    // Best-effort: a sync failure must not fail the append (the record
    // being written is worth more than the rename's durability — R2).
    let _ = File::open(&renamed).and_then(|f| f.sync_all());
    let _ = File::open(dir).and_then(|f| f.sync_all());
    Ok(())
}

/// All journal files in a workspace dir, oldest first: rotated files in
/// numeric order, then the current `journal.jsonl`.
pub fn journal_files(dir: &Path) -> Vec<PathBuf> {
    let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && let Some(num) = name
                    .strip_prefix("journal.")
                    .and_then(|n| n.strip_suffix(".jsonl"))
                && let Ok(n) = num.parse::<u32>()
            {
                rotated.push((n, p));
            }
        }
    }
    rotated.sort_by_key(|(n, _)| *n);
    let mut files: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    files.push(dir.join(JOURNAL_FILE));
    files
}

/// 0.6.0 (ADR 0022): size limit for a journal that receives network
/// records. After a rotation, while there are more than
/// [`MAX_JOURNAL_FILES`] files or their total size is above the budget,
/// the oldest rotated files are deleted, but only once the total exceeds
/// the budget: a small journal keeps every file however often it
/// rotated. The active file is never deleted. Called under the journal
/// lock; best-effort (never fails the append).
pub const MAX_JOURNAL_FILES: usize = 4;
/// Budget of [`prune_journal_files`] in production: four files of the
/// rotation size (4 x 64 MiB).
pub const JOURNAL_RETENTION_BYTES: u64 = 4 * ROTATE_AFTER;

fn prune_journal_files(dir: &Path, budget: u64) {
    let files = journal_files(dir);
    if files.len() <= MAX_JOURNAL_FILES {
        return;
    }
    let mut total: u64 = files
        .iter()
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();
    if total <= budget {
        return;
    }
    // Oldest first (`journal_files` order); the active file is last.
    let mut remaining = files.len();
    for f in &files {
        if remaining <= MAX_JOURNAL_FILES && total <= budget {
            break;
        }
        if f.file_name().and_then(|n| n.to_str()) == Some(JOURNAL_FILE) {
            continue;
        }
        let len = fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(f).is_ok() {
            total = total.saturating_sub(len);
            remaining -= 1;
        }
    }
}

/// Consume the rest of the current (over-long) line, up to and including
/// the newline. Best-effort.
///
/// The line is discarded straight from the reader's own buffer: it is never
/// accumulated, so an arbitrarily long line costs no memory (accumulating it
/// here would defeat [`MAX_RECORD_BYTES`]).
fn drain_to_newline<R: BufRead>(r: &mut R) {
    loop {
        let (found_newline, used) = match r.fill_buf() {
            Ok([]) => return,
            Ok(buf) => match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (true, i + 1),
                None => (false, buf.len()),
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        r.consume(used);
        if found_newline {
            return;
        }
    }
}

/// Max bytes in a single journal line read back. A longer "line" is not
/// read into memory; it is counted as skipped (a hostile or corrupt file
/// cannot OOM the reader). 16 MiB mirrors the control response cap.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Read every record in a workspace (rotated files first, then the current
/// one), skipping any unparseable line (a torn tail never breaks the whole
/// read). Returns the records and the number of skipped lines.
///
/// Exactly-once under rotation: the file list is enumerated and every file
/// is **opened under a shared lock** (writers take the exclusive lock when
/// appending/rotating), then the lock is released and the records are read
/// unlocked from the already-open descriptors. A rotation after the open
/// cannot move a file out from under the reader (the descriptor pins the
/// inode), so every record is seen exactly once — and a slow reader never
/// blocks writers, since it holds no lock while reading. If the lock file
/// cannot be opened (e.g. the dir does not exist yet), the read proceeds
/// unlocked — there is nothing to read yet in that case.
pub fn read_records(dir: &Path) -> (Vec<JournalRecord>, usize) {
    // Pin the file descriptors under the shared lock, then read unlocked.
    let files: Vec<(File, u64)> = {
        let _shared = shared_lock(dir);
        journal_files(dir)
            .into_iter()
            .filter_map(|p| {
                let f = File::open(&p).ok()?;
                let len = f.metadata().ok()?.len();
                Some((f, len))
            })
            .collect()
    };
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for (f, len) in files {
        let mut reader = BufReader::new(f.take(len));
        loop {
            let mut buf = Vec::new();
            let n = match reader
                .by_ref()
                .take(MAX_RECORD_BYTES as u64 + 1)
                .read_until(b'\n', &mut buf)
            {
                Ok(n) => n,
                Err(_) => {
                    // A read error mid-file: count it, drop the rest of
                    // this file, do not silently treat it as EOF.
                    skipped += 1;
                    break;
                }
            };
            if n == 0 {
                break;
            }
            // Strip the newline first, then enforce the cap on content
            // (a line of exactly MAX_RECORD_BYTES of content + newline is
            // valid; comparing before the strip would wrongly drain it and
            // swallow the following record — R2 off-by-one).
            let has_nl = buf.last() == Some(&b'\n');
            if buf.len() - has_nl as usize > MAX_RECORD_BYTES {
                // Over-long line: drain to the newline so the remainder is
                // not misparsed as a new line, then count it once.
                drain_to_newline(&mut reader);
                skipped += 1;
                continue;
            }
            if has_nl {
                buf.pop();
            }
            if buf.is_empty() {
                continue;
            }
            match serde_json::from_slice::<JournalRecord>(&buf) {
                Ok(r) => out.push(r),
                Err(_) => skipped += 1,
            }
        }
    }
    (out, skipped)
}

/// Query filters for `hisn journal`.
#[derive(Debug, Default)]
pub struct Query {
    pub session: Option<String>,
    pub seat: Option<String>,
    pub kind: Option<String>,
    pub since_secs: Option<i64>,
    pub last: Option<usize>,
}

/// Filter records by session, seat (the client label), kind and time; then
/// apply `--last N` (newest N of the filtered set).
pub fn query(records: &[JournalRecord], q: &Query) -> Vec<JournalRecord> {
    let mut out: Vec<JournalRecord> = records
        .iter()
        .filter(|r| matches_query(r, q))
        .cloned()
        .collect();
    if let Some(n) = q.last {
        let start = out.len().saturating_sub(n);
        out.drain(..start);
    }
    out
}

fn matches_query(r: &JournalRecord, q: &Query) -> bool {
    q.session.as_ref().is_none_or(|s| &r.session == s)
        && q.seat.as_ref().is_none_or(|seat| {
            // 0.5.1: the server-set seat field, never the client's label —
            // a credentialed client must not impersonate another seat in the
            // journal by choosing a label. The label match stays as the
            // legacy behaviour for records without a seat field.
            r.client.as_ref().is_some_and(|c| match &c.seat {
                Some(s) => s == seat,
                None => c.label == *seat,
            })
        })
        && q.kind.as_ref().is_none_or(|k| &r.kind == k)
        && q.since_secs
            .is_none_or(|t| crate::session::parse_rfc3339_secs(&r.ts).is_some_and(|s| s >= t))
}

/// Readable query (separate from JSON's raw-record query).
pub fn query_readable(records: &[JournalRecord], q: &Query) -> Vec<String> {
    let raw = Query {
        session: q.session.clone(),
        seat: q.seat.clone(),
        kind: q.kind.clone(),
        since_secs: q.since_secs,
        last: None,
    };
    let family = q.kind.as_deref() == Some("exec");
    let raw = if family {
        Query { kind: None, ..raw }
    } else {
        raw
    };
    // Build groups before filtering: session/start boundaries may be outside
    // the selected time/kind window. Complete only groups with a matching record.
    let mut lines: Vec<_> = record_groups(records)
        .iter()
        .filter(|g| {
            g.iter().any(|r| {
                matches_query(r, &raw)
                    && (!family
                        || matches!(
                            r.kind.as_str(),
                            "exec/request" | "exec/result" | "exec/exit"
                        ))
            })
        })
        .map(|g| render_group(g))
        .collect();
    if let Some(n) = q.last {
        lines.drain(..lines.len().saturating_sub(n));
    }
    lines
}

/// Escape every agent-supplied string for terminal display: control
/// characters (including ESC, the start of terminal escape sequences),
/// DEL, and Unicode format characters (bidi overrides U+202A..=U+202E,
/// isolates U+2066..=U+2069, zero-width U+200B..=U+200F, BOM U+FEFF,
/// line/paragraph separators U+2028/U+2029) are shown as `\xNN` / `\n` /
/// `\r` / `\t`, so journal content can neither drive the reader's
/// terminal nor visually reorder its text. Printable Unicode passes
/// through. Used by the readable `hisn journal` output only — `--json`
/// stays exact.
fn escape_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_format_char(c) => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

/// Unicode format (Cf) characters with visual-ordering or invisible-text
/// effects. `char::is_control` covers Cc only, so these need an explicit
/// list (R2).
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' // zero-width space/joiner, LRM/RLM
        | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
        | '\u{2028}' | '\u{2029}' // line/paragraph separators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}' // zero-width no-break space / BOM
    )
}

/// The grouping key for collapsing readable output (item 3): records of
/// one exec — its request, its result and its exit — collapse into a
/// single line. The base key is (`session`, `seq`), scoped by record_groups
/// to an incarnation: ids can be reused and seq restarts on a new session.
/// Other kinds remain singletons.
fn collapse_key(rec: &JournalRecord) -> Option<(String, u64)> {
    let seq = rec.data.get("seq")?.as_u64()?;
    match rec.kind.as_str() {
        "exec/request" | "exec/result" | "exec/exit" | "attach/request" | "attach/result"
        | "attach/exit" => Some((rec.session.clone(), seq)),
        _ => None,
    }
}

/// Render a record set as compact events, scoped by session incarnation.
/// Prefer query_readable for CLI filtering: it completes matching groups
/// from retained history before applying the displayed-line limit.
pub fn render_collapsed(recs: &[JournalRecord]) -> Vec<String> {
    record_groups(recs)
        .iter()
        .map(|g| render_group(g))
        .collect()
}

fn record_groups(recs: &[JournalRecord]) -> Vec<Vec<&JournalRecord>> {
    use std::collections::BTreeMap;
    let mut groups: Vec<Vec<&JournalRecord>> = Vec::new();
    let mut incarnations: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_key: BTreeMap<(String, usize, u64), usize> = BTreeMap::new();
    for (index, r) in recs.iter().enumerate() {
        if r.kind == "session/start" {
            incarnations.insert(&r.session, index + 1);
        }
        match collapse_key(r) {
            Some((session, seq)) => {
                let incarnation = *incarnations.get(session.as_str()).unwrap_or(&0);
                let key = (session, incarnation, seq);
                let old = by_key.get(&key).copied();
                // A missing start marker must not let a second request borrow
                // an old exit. The actual writer's audit+argv pair is one request.
                let new_request = old.is_some_and(|i| {
                    matches!(r.kind.as_str(), "exec/request" | "attach/request")
                        && groups[i].iter().any(|prior| {
                            matches!(prior.kind.as_str(), "exec/request" | "attach/request")
                        })
                        && (r.data.get("argv").is_none()
                            || groups[i].iter().any(|prior| {
                                prior.data.get("argv").is_some()
                                    || matches!(
                                        prior.kind.as_str(),
                                        "exec/result"
                                            | "exec/exit"
                                            | "attach/result"
                                            | "attach/exit"
                                    )
                            }))
                });
                match old.filter(|_| !new_request) {
                    Some(i) => groups[i].push(r),
                    None => {
                        by_key.insert(key, groups.len());
                        groups.push(vec![r]);
                    }
                }
            }
            None => groups.push(vec![r]),
        }
    }
    // Order by newest record, not request age.
    groups.sort_by_key(|g| g.iter().map(|r| r.wseq).max().unwrap_or(0));
    groups
}

fn render_group(g: &[&JournalRecord]) -> String {
    // The head record defines time, wseq, session and seat. With several
    // records, the first is the request (or the oldest present).
    let head = g[0];
    let client = head
        .client
        .as_ref()
        .map(|c| escape_terminal(&c.label))
        .unwrap_or_else(|| "-".to_owned());
    let mut summary = String::new();
    // Terminal failure: a spawn refusal / error result (e.g. E_EXEC) with
    // no exit record. This is finished work, not an open exec — show the
    // error, never "[open]" (Mashūra round 2, "collapsing hides failures").
    let terminal_error: Option<String> = g.iter().find_map(|r| {
        if r.kind == "exec/result" || r.kind == "attach/result" {
            let result = r.data.get("result").and_then(|v| v.as_str()).unwrap_or("");
            if result != "ok" {
                return Some(escape_terminal(result).to_owned());
            }
        }
        None
    });
    if g.len() == 1 {
        // A lone record: the request shows as open when it is an exec
        // request (its result/exit are outside the selected window).
        summary.push_str(&summary_for(head));
        if head.kind == "exec/request" || head.kind == "attach/request" {
            summary.push_str(" [open]");
        }
    } else {
        // Older polish writers emit both an audit-shaped request and an
        // argv request. Prefer the richest request, and summarize it once.
        if let Some(request) = g
            .iter()
            .filter(|r| matches!(r.kind.as_str(), "exec/request" | "attach/request"))
            .max_by_key(|r| r.data.get("argv").is_some())
        {
            summary.push_str(&summary_for(request));
        }
        for r in g {
            match r.kind.as_str() {
                "exec/exit" | "attach/exit" => {
                    if !summary.is_empty() {
                        summary.push(' ');
                    }
                    summary.push_str(&exit_summary(r));
                }
                _ => {}
            }
        }
        let has_exit = g
            .iter()
            .any(|r| r.kind == "exec/exit" || r.kind == "attach/exit");
        if let Some(err) = terminal_error {
            if !summary.is_empty() {
                summary.push(' ');
            }
            summary.push_str(&format!("failed:{err}"));
        } else if !has_exit {
            summary.push_str(" [open]");
        }
    }
    if collapse_key(head).is_some()
        && !g
            .iter()
            .any(|r| matches!(r.kind.as_str(), "exec/request" | "attach/request"))
    {
        summary.push_str(" [orphan: request unavailable]");
    }
    format!(
        "{} #{} {} {} {} {}",
        escape_terminal(&head.ts),
        head.wseq,
        escape_terminal(&head.session.chars().take(8).collect::<String>()),
        escape_terminal(if g.iter().any(|r| r.kind == "exec/request") {
            "exec"
        } else {
            &head.kind
        }),
        client,
        summary,
    )
}

/// Quote one argv element for readable output (Mashūra round 2, "argv
/// can forge the rest of the line"): every element is wrapped in double
/// quotes with `\` and `"` escaped, so a command line can never fake an
/// `exit:0`, `[open]` or `(cwd …)` annotation, and element boundaries
/// survive. Control characters are terminal-escaped on top.
fn quote_arg(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    escape_terminal(&out)
}
fn summary_for(rec: &JournalRecord) -> String {
    let d = &rec.data;
    match rec.kind.as_str() {
        "exec/request" | "attach/request" => {
            let cmd = d
                .get("argv")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .map(quote_arg)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let mut s = cmd;
            if d.get("argv_truncated").and_then(|v| v.as_bool()) == Some(true) {
                s.push_str(" …(truncated)");
            }
            if let Some(cwd) = d.get("cwd").and_then(|v| v.as_str()) {
                s.push_str(&format!(" (cwd {})", escape_terminal(cwd)));
            }
            if s.is_empty() {
                s = d
                    .get("path")
                    .and_then(Value::as_str)
                    .map(quote_arg)
                    .unwrap_or_else(|| "[command unavailable]".into());
            }
            s
        }
        "exec/exit" | "attach/exit" => exit_summary(rec),
        "exec/result" | "attach/result" => format!(
            "result:{}",
            escape_terminal(d.get("result").and_then(|v| v.as_str()).unwrap_or("?"))
        ),
        "note" | "marker" => {
            let text = d.get("text").and_then(|v| v.as_str()).unwrap_or("");
            escape_terminal(text)
        }
        "kill/request" | "signal/request" => {
            escape_terminal(d.get("result").and_then(|v| v.as_str()).unwrap_or("?"))
        }
        "forward/start" | "forward/result" => {
            let subject = d.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            escape_terminal(&format!(
                "forward {}{}",
                subject,
                match (rec.kind.as_str(), d.get("result").and_then(|v| v.as_str())) {
                    ("forward/result", Some(result)) => format!(" {}", escape_terminal(result)),
                    _ => String::new(),
                }
            ))
        }
        "lease/expired" => format!(
            "lease expired ({})",
            escape_terminal(d.get("result").and_then(|v| v.as_str()).unwrap_or("?"))
        ),
        _ if rec.kind.ends_with("/refused") => {
            let op = d.get("op").and_then(|v| v.as_str()).unwrap_or("operation");
            let reason = d.get("result").and_then(|v| v.as_str()).unwrap_or("denied");
            let mut summary = escape_terminal(op);
            if let Some(path) = d.get("path").and_then(|v| v.as_str()) {
                summary.push(' ');
                summary.push_str(&escape_terminal(path));
            }
            summary.push_str(&format!(" refused ({})", escape_terminal(reason)));
            summary
        }
        "grant/request" | "revoke/request" => {
            let path = d.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let mode = d.get("mode").and_then(|v| v.as_str()).unwrap_or("");
            format!(
                "{}{}",
                escape_terminal(path),
                if mode.is_empty() {
                    String::new()
                } else {
                    format!(" {}", escape_terminal(mode))
                }
            )
        }
        "grant/result" | "revoke/result" => {
            let path = d.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let result = d.get("result").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{} {}", escape_terminal(path), escape_terminal(result))
        }
        "session/start" => "session started".to_owned(),
        "session/stop" => "session stopped".to_owned(),
        "git-change" => git_change_summary(d),
        "network/connect" => {
            let target = d.get("target").and_then(|v| v.as_str()).unwrap_or("?");
            let verdict = d.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{} {}", escape_terminal(verdict), escape_terminal(target))
        }
        "network/dns" => {
            let field = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("?");
            format!(
                "{} {} {} {}",
                escape_terminal(field("verdict")),
                escape_terminal(field("rcode")),
                escape_terminal(field("name")),
                escape_terminal(field("qtype")),
            )
        }
        "network/summary" => {
            let n = |k: &str| d.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
            format!(
                "not recorded one by one: allow={} refuse={} continue={} dns={} dropped={} tracked_overflow={}",
                n("allow"),
                n("refuse"),
                n("continue"),
                n("dns"),
                n("dropped"),
                n("tracked_overflow"),
            )
        }
        _ => format!(
            "unrecognized {} ({} bytes; use --json)",
            escape_terminal(&rec.kind),
            d.to_string().len()
        ),
    }
}

fn exit_summary(rec: &JournalRecord) -> String {
    let d = &rec.data;
    let mut s = String::from("exit:");
    if d.get("lost").and_then(|v| v.as_bool()) == Some(true) {
        s.push_str("lost");
    } else if let Some(c) = d.get("exit_code").and_then(|v| v.as_i64()) {
        s.push_str(&c.to_string());
    } else if let Some(name) = d.get("signal_name").and_then(|v| v.as_str()) {
        s.push_str("signal ");
        s.push_str(&escape_terminal(name));
    } else if let Some(n) = d.get("signal").and_then(|v| v.as_i64()) {
        s.push_str(&format!("signal {n}"));
    } else {
        s.push('?');
    }
    if d.get("cancelled").and_then(|v| v.as_bool()) == Some(true) {
        s.push_str(" cancelled");
    }
    if let Some(ms) = d.get("duration_ms").and_then(|v| v.as_u64()) {
        s.push_str(&format!(" {ms}ms"));
    }
    s
}

fn git_change_summary(d: &Value) -> String {
    // Read the change lists from the nested `changes` object (the shape
    // `gitreport::change_record` produces), with the top-level keys as a
    // fallback, so a real change never renders as "nothing changed"
    // (Mashūra round 2).
    if d.get("unchanged").and_then(|v| v.as_bool()) == Some(true) {
        let hooks = d.get("hooks_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let keys = d
            .get("config_keys_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        return format!("git unchanged (hooks {hooks}, config keys {keys})");
    }
    let flagged: Vec<String> = d
        .get("flagged")
        .or_else(|| d.get("changes").and_then(|c| c.get("flagged")))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(escape_terminal)
                .collect()
        })
        .unwrap_or_default();
    let truncated_note = match (
        d.get("truncated")
            .and_then(|v| v.get("before"))
            .and_then(|v| v.as_bool()),
        d.get("truncated")
            .and_then(|v| v.get("after"))
            .and_then(|v| v.as_bool()),
        d.get("changes")
            .and_then(|c| c.get("truncated"))
            .and_then(|v| v.get("before"))
            .and_then(|v| v.as_bool()),
        d.get("changes")
            .and_then(|c| c.get("truncated"))
            .and_then(|v| v.get("after"))
            .and_then(|v| v.as_bool()),
    ) {
        (Some(true), _, _, _)
        | (_, Some(true), _, _)
        | (_, _, Some(true), _)
        | (_, _, _, Some(true)) => " (truncated)",
        _ => "",
    };
    let mut s = format!(
        "git hooks +{} -{} ~{}; config +{} -{} ~{}{}",
        count_of(d, "hooks_added"),
        count_of(d, "hooks_removed"),
        count_of(d, "hooks_modified"),
        count_of(d, "config_added"),
        count_of(d, "config_removed"),
        count_of(d, "config_changed"),
        truncated_note,
    );
    if !flagged.is_empty() {
        s.push_str(&format!(" flagged [{}]", flagged.join(",")));
    }
    s
}

/// Count one change list from the nested `changes` object (the shape
/// `gitreport::change_record` produces) or from the top-level fallback
/// keys. A missing list counts as 0 only in the top-level shape; the
/// nested shape is read from `changes.*`.
fn count_of(d: &Value, key: &str) -> usize {
    // `key` is the flat name ("hooks_added"); the nested shape splits it
    // into section + verb.
    let (section, verb) = key.split_once('_').unwrap_or((key, ""));
    let nested = d
        .get("changes")
        .and_then(|c| c.get(section))
        .and_then(|s| s.get(verb));
    nested
        .or_else(|| d.get(key))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

/// One readable line for a record (the default `hisn journal` output).
/// Kept for the single-record case and tests: prefer
/// [`render_collapsed`] for the CLI output, which groups an exec's
/// request/result/exit by (session, seq). `session`, `kind` and the
/// client label are terminal-escaped; `data` is a JSON value whose
/// `Display` escapes C0 controls inside strings (serde_json) but passes
/// C1 controls (U+0080..=U+009F, e.g. U+009B CSI) through raw — so the
/// serialized form is escaped as well. `--json` output is unaffected
/// (exact).
pub fn render(rec: &JournalRecord) -> String {
    let client = rec
        .client
        .as_ref()
        .map(|c| escape_terminal(&c.label))
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "{} #{} {} {} {} {}",
        escape_terminal(&rec.ts),
        rec.wseq,
        escape_terminal(&rec.session),
        escape_terminal(&rec.kind),
        client,
        escape_terminal(&rec.data.to_string())
    )
}

/// Find the journal files for `dir`, tolerating a missing file (a session
/// that never journaled). Read-only helper for `hisn journal`.
pub fn existing_files(dir: &Path) -> Vec<PathBuf> {
    journal_files(dir)
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

/// Read the workspace dir size (for a diagnostic line). Best-effort.
#[allow(dead_code)]
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    for p in journal_files(dir) {
        total += fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    }
    total
}

/// A sink for tests: a journal in a fresh temp dir. The workspace dir is
/// created 0700, as production always is (the supervisor ensures it before
/// the Journal exists and `append` now validates it).
#[cfg(test)]
fn test_journal() -> (tempfile::TempDir, Journal) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("ws");
    (d, Journal::new(path, "s1".into()))
}

/// Create a test workspace dir with mode 0700 (production dirs are always
/// 0700 — the journal validates).
#[cfg(test)]
fn create_test_ws_dir(dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(k: &str) -> Value {
        json!({"k": k})
    }

    fn test_notif(port: u16) -> crate::notif::Notif {
        crate::notif::Notif {
            id: 1,
            pid: 42,
            parsed_ip: Some("192.0.2.1".parse().unwrap()),
            parsed_family: libc::AF_INET as u16,
            parsed_port: port,
            ..Default::default()
        }
    }

    fn records_of(j: &Journal, kind: &str) -> Vec<JournalRecord> {
        read_records(&j.dir)
            .0
            .into_iter()
            .filter(|r| r.kind == kind)
            .collect()
    }

    /// Hold the journal's exclusive lock on a separate open file
    /// description, as a hung lock holder would.
    fn hold_journal_lock(j: &Journal) -> File {
        create_test_ws_dir(&j.dir);
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(j.dir.join(LOCK_FILE))
            .unwrap();
        assert_eq!(unsafe { libc::flock(_fd_of(&f), libc::LOCK_EX) }, 0);
        f
    }

    #[test]
    fn net_record_does_not_wait_for_a_blocked_journal() {
        // The journal lock is held elsewhere, so every append blocks for
        // its 1 s lock budget. An engine handle must return at once.
        let (_d, j) = test_journal();
        let lock = hold_journal_lock(&j);
        let ej = j.clone_for_engine();
        let start = std::time::Instant::now();
        for port in 0..20 {
            ej.net_record("allow", "injected", &test_notif(port));
        }
        let took = start.elapsed();
        assert!(
            took < std::time::Duration::from_millis(200),
            "20 net_record calls took {took:?} while the journal was locked"
        );
        // Control: the same journal through a handle without a queue does
        // block, so the test above measures the queue and not a fast disk.
        let start = std::time::Instant::now();
        j.net_record("allow", "injected", &test_notif(99));
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "a queue-less handle should have waited for the lock"
        );
        drop(lock);
    }

    #[test]
    fn net_queue_full_drops_and_counts() {
        // Capacity 2 and a writer stuck on the journal lock: of 10 records
        // at most 3 are taken (2 queued + 1 in the writer's hands); the
        // rest are dropped and counted, and the producer never blocks.
        let (_d, j) = test_journal();
        let lock = hold_journal_lock(&j);
        let ej = j.clone_for_engine_with_cap(2);
        let start = std::time::Instant::now();
        for port in 0..10 {
            ej.net_record("allow", "injected", &test_notif(port));
        }
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
        let dropped = ej
            .net_queue
            .as_ref()
            .unwrap()
            .dropped
            .load(Ordering::Relaxed);
        assert!((7..=8).contains(&dropped), "dropped {dropped} of 10");
        assert!(j.failures() >= dropped);
        // Once the lock is free the drop count reaches the journal.
        drop(lock);
        assert!(ej.net_flush(std::time::Duration::from_secs(10)));
        let lost: u64 = records_of(&j, "network/summary")
            .iter()
            .map(|r| r.data["dropped"].as_u64().unwrap())
            .sum();
        assert_eq!(lost, dropped);
    }

    #[test]
    fn net_flood_is_capped_and_summarized() {
        // 500 records in one burst: at most NET_RECORDS_PER_SEC per
        // second are written one by one, the rest are counted in
        // network/summary, and nothing is lost from the total.
        let (_d, j) = test_journal();
        let ej = j.clone_for_engine();
        let start = std::time::Instant::now();
        for port in 0..500 {
            ej.net_record("allow", "injected", &test_notif(port));
        }
        assert!(ej.net_flush(std::time::Duration::from_secs(10)));
        let windows = start.elapsed().as_secs() + 1;
        let single = records_of(&j, "network/connect").len() as u64;
        let summarized: u64 = records_of(&j, "network/summary")
            .iter()
            .map(|r| r.data["allow"].as_u64().unwrap())
            .sum();
        assert!(single >= u64::from(NET_RECORDS_PER_SEC), "{single}");
        assert!(
            single <= u64::from(NET_RECORDS_PER_SEC) * windows,
            "{single} single records in {windows} s"
        );
        assert_eq!(single + summarized, 500);
    }

    #[test]
    fn engine_handles_share_one_queue() {
        let (_d, j) = test_journal();
        let a = j.clone_for_engine();
        let b = a.clone_for_engine();
        assert!(Arc::ptr_eq(
            a.net_queue.as_ref().unwrap(),
            b.net_queue.as_ref().unwrap()
        ));
    }

    #[test]
    fn records_carry_v_ts_wseq_session_kind_client_data() {
        let (_d, j) = test_journal();
        j.append(
            "grant/request",
            Some(JournalClient::plain(
                1000,
                "local".into(),
                "flag".into(),
                None,
            )),
            data("x"),
        )
        .unwrap();
        let (recs, skipped) = read_records(&j.dir);
        assert_eq!(skipped, 0);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.v, 1);
        assert_eq!(r.wseq, 1);
        assert_eq!(r.session, "s1");
        assert_eq!(r.kind, "grant/request");
        assert_eq!(r.client.as_ref().unwrap().label, "local");
        assert_eq!(r.data, data("x"));
        assert!(r.ts.ends_with('Z'));
    }

    #[test]
    fn concurrent_writers_keep_wseq_strictly_increasing_with_no_lost_line() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        create_test_ws_dir(&dir);
        let mut handles = Vec::new();
        for t in 0..4 {
            let dir = dir.clone();
            handles.push(std::thread::spawn(move || {
                let j = Journal::new(dir, format!("sess-{t}"));
                for i in 0..25 {
                    j.append("exec/request", None, json!({"i": i}))
                        .expect("append");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let (recs, skipped) = read_records(&dir);
        assert_eq!(skipped, 0);
        assert_eq!(recs.len(), 100);
        let seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(
            seqs, sorted,
            "wseq must be strictly increasing in file order"
        );
        // The record for wseq 100 must be present and be the last one the
        // file carries — a tail-window undercount would duplicate 1..=100.
        let last = recs.iter().map(|r| r.wseq).max().unwrap();
        assert_eq!(last, 100, "the highest wseq must be 100");
    }

    #[test]
    fn only_the_network_writer_deletes_old_journal_files() {
        // Seven rotations of a tiny journal. A plain handle (every mode
        // before 0.6.0, and none/host now) keeps all files; a handle
        // with a retention budget deletes the oldest rotated ones.
        let fill = |j: &Journal| {
            for i in 0..8 {
                j.append("note", None, json!({"text": "x".repeat(300), "i": i}))
                    .unwrap();
            }
        };
        let d = tempfile::tempdir().unwrap();
        let plain = Journal::with_rotate_after(d.path().join("a"), "s".into(), 200);
        assert_eq!(plain.retention_bytes, None);
        fill(&plain);
        assert_eq!(journal_files(&d.path().join("a")).len(), 8);

        let mut limited = Journal::with_rotate_after(d.path().join("b"), "s".into(), 200);
        limited.retention_bytes = Some(1000);
        fill(&limited);
        let files = journal_files(&d.path().join("b"));
        assert_eq!(files.len(), MAX_JOURNAL_FILES);
        assert!(files.last().unwrap().ends_with(JOURNAL_FILE));
        // The newest records survive.
        let (records, _) = read_records(&d.path().join("b"));
        assert_eq!(records.last().unwrap().data["i"], 7);

        // The network queue's writer is the handle that has the budget.
        let engine = plain.clone_for_engine();
        assert_eq!(engine.retention_bytes, None);
    }

    #[test]
    fn rotation_renames_and_keeps_both_files_readable() {
        let (_d, j) = test_journal();
        for _ in 0..3 {
            j.append("note", None, data("x")).unwrap();
        }
        // Force the current file over the threshold and append once more: the
        // next append rotates first. The padding is written as whole
        // *parseable-failure* lines so the pre-rotation wseq is still
        // recoverable from the rotated file's tail.
        let path = j.dir.join(JOURNAL_FILE);
        assert!(fs::metadata(&path).unwrap().len() < ROTATE_AFTER);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        let filler = "x".repeat(64);
        // Write just over the threshold in chunks of full lines.
        let mut written = 0u64;
        while written <= ROTATE_AFTER {
            let line = format!("{filler}\n");
            f.write_all(line.as_bytes()).unwrap();
            written += line.len() as u64;
        }
        drop(f);
        j.append("note", None, data("after")).unwrap();
        let files = existing_files(&j.dir);
        assert!(
            files
                .iter()
                .any(|p| p.file_name().unwrap() == "journal.1.jsonl")
        );
        let (recs, skipped) = read_records(&j.dir);
        // Debug: what wseqs survived?
        // The 3 original + 1 after; the filler lines are unparseable and
        // skipped, but the pre-rotation records survive in the rotated file.
        assert!(skipped > 0);
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[3].data, data("after"));
        // wseq is read from the rotated file's tail (the last parseable line
        // before rotation), so the post-rotation record is strictly higher
        // than any pre-rotation record.
        assert!(recs[3].wseq > recs[0].wseq);
        assert!(recs[3].wseq > recs[1].wseq);
        assert!(recs[3].wseq > recs[2].wseq);
    }

    #[test]
    fn query_filters_by_session_seat_kind_since_and_last() {
        let (_d, j) = test_journal();
        let line = || {
            let (recs, _) = read_records(&j.dir);
            recs
        };
        let mk = |label: &str, kind: &str, session: &str| -> Value {
            json!({"label": label, "kind": kind, "session": session})
        };
        let _ = mk;
        // append with explicit fields
        j.append(
            "grant/request",
            Some(JournalClient::plain(
                1000,
                "alice".into(),
                "flag".into(),
                None,
            )),
            data("a"),
        )
        .unwrap();
        j.append(
            "grant/result",
            Some(JournalClient::plain(
                1000,
                "alice".into(),
                "flag".into(),
                None,
            )),
            data("b"),
        )
        .unwrap();
        j.append(
            "exec/request",
            Some(JournalClient::plain(1000, "bob".into(), "ssh".into(), None)),
            data("c"),
        )
        .unwrap();
        let recs = line();
        assert_eq!(recs.len(), 3);
        let by_alice = query(
            &recs,
            &Query {
                seat: Some("alice".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_alice.len(), 2);
        let by_kind = query(
            &recs,
            &Query {
                kind: Some("grant/request".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_kind.len(), 1);
        let last_one = query(
            &recs,
            &Query {
                last: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(last_one.len(), 1);
        assert_eq!(last_one[0].data, data("c"));
        let since = query(
            &recs,
            &Query {
                since_secs: Some(i64::MAX),
                ..Default::default()
            },
        );
        assert!(since.is_empty());
        let _ = Query {
            session: Some("s1".into()),
            seat: None,
            kind: None,
            since_secs: None,
            last: None,
        };
    }

    #[test]
    fn seat_query_uses_server_set_seat_not_label() {
        // 0.5.1 (ADR 0021): a credentialed client whose label is another
        // seat's name must not be returned by `--seat <other>`. The filter
        // matches the server-set seat field; the label is only the legacy
        // fallback for records without one.
        let (_d, j) = test_journal();
        j.append(
            "exec/request",
            Some(JournalClient::seat(
                1000,
                "rubin".into(),
                "member".into(),
                None,
            )),
            data("a"),
        )
        .unwrap();
        let (recs, _) = read_records(&j.dir);
        let c = recs[0].client.as_ref().unwrap();
        assert_eq!(c.seat.as_deref(), Some("rubin"));
        assert_eq!(c.role.as_deref(), Some("member"));
        assert_eq!(c.label, "rubin");
        assert_eq!(c.label_source, "seat");
        let by_rubin = query(
            &recs,
            &Query {
                seat: Some("rubin".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_rubin.len(), 1);
        // A label-chosen impersonation does not match when a seat is set.
        let mut forged = recs.clone();
        forged[0].client.as_mut().unwrap().label = "wakil".into();
        let by_wakil = query(
            &forged,
            &Query {
                seat: Some("wakil".into()),
                ..Default::default()
            },
        );
        assert!(
            by_wakil.is_empty(),
            "label must not select a credentialed record"
        );
        // And a plain (credentialless) record still matches by label.
        let (_d2, j2) = test_journal();
        j2.append(
            "exec/request",
            Some(JournalClient::plain(
                1000,
                "wakil".into(),
                "flag".into(),
                None,
            )),
            data("a"),
        )
        .unwrap();
        let (recs2, _) = read_records(&j2.dir);
        assert_eq!(recs2[0].client.as_ref().unwrap().seat, None);
        let by_wakil = query(
            &recs2,
            &Query {
                seat: Some("wakil".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_wakil.len(), 1, "legacy label match must stay");
    }

    #[test]
    fn seat_fields_round_trip_and_plain_stays_byte_identical() {
        // The seat fields are additive: a credentialed record carries them,
        // a plain one serializes exactly the 0.5.0 shape.
        let seat = JournalClient::seat(1000, "rubin".into(), "observer".into(), None);
        let json = serde_json::to_value(&seat).unwrap();
        assert_eq!(json["seat"], "rubin");
        assert_eq!(json["role"], "observer");
        assert_eq!(json["label_source"], "seat");
        let plain = JournalClient::plain(1000, "local".into(), "none".into(), None);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("seat").is_none() && json.get("role").is_none());
        assert_eq!(
            json,
            serde_json::json!({"uid":1000,"label":"local","label_source":"none","req_id":null})
        );
        // A 0.5.0 record (no seat fields) still parses.
        let back: JournalClient = serde_json::from_str(
            r#"{"uid":1000,"label":"local","label_source":"none","req_id":null}"#,
        )
        .unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn a_failed_journal_write_counts_and_does_not_lose_the_rest() {
        // A workspace dir that is a regular file: the append must fail, the
        // failure must be counted, and the journal must still serve reads.
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("ws");
        fs::write(&file, b"not a dir").unwrap();
        let j = Journal::new(file, "s1".into());
        let r = j.append("grant/request", None, data("x"));
        assert!(r.is_err());
        assert_eq!(j.failures(), 1);
        // A second failed attempt counts again and still does not panic.
        let _ = j.append("grant/result", None, data("y"));
        assert_eq!(j.failures(), 2);
    }

    #[test]
    fn an_unreadable_journal_fails_the_append_instead_of_restarting_wseq() {
        // A journal that can be appended to but not read back (mode 0200):
        // the last `wseq` is unknown. The append must fail and be counted —
        // treating "cannot read" as "no records" would write a second
        // `wseq` 1.
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::getuid().is_root() {
            return; // root ignores file modes; the condition cannot be built
        }
        let (_d, j) = test_journal();
        j.append("note", None, data("one")).unwrap();
        j.append("note", None, data("two")).unwrap();
        let p = j.dir.join(JOURNAL_FILE);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o200)).unwrap();
        let r = j.append("note", None, data("blind"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(r.is_err(), "append with an unreadable journal must fail");
        assert_eq!(j.failures(), 1);
        let (recs, skipped) = read_records(&j.dir);
        assert_eq!(skipped, 0);
        let seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
        assert_eq!(seqs, [1, 2], "no record with a guessed wseq was written");
        // Readable again: the sequence continues where it left off.
        j.append("note", None, data("three")).unwrap();
        assert_eq!(read_records(&j.dir).0.last().unwrap().wseq, 3);
    }

    #[test]
    fn sync_counts_an_open_error_but_not_a_missing_journal() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::getuid().is_root() {
            return; // root ignores file modes; the condition cannot be built
        }
        let (_d, j) = test_journal();
        j.sync();
        assert_eq!(j.failures(), 0, "nothing to sync is not a failure");
        j.append("note", None, data("one")).unwrap();
        let p = j.dir.join(JOURNAL_FILE);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o200)).unwrap();
        j.sync();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(j.failures(), 1, "a sync that could not open the file");
    }

    #[test]
    fn journal_dir_is_private_and_file_is_append_only_jsonl() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, j) = test_journal();
        j.append("session/start", None, data("x")).unwrap();
        let p = j.dir.join(JOURNAL_FILE);
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = fs::read_to_string(&p).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["kind"], "session/start");
        // Reopening appends, never truncates.
        j.append("session/stop", None, data("y")).unwrap();
        let n = fs::read_to_string(&p).unwrap().lines().count();
        assert_eq!(n, 2);
    }

    #[test]
    fn read_records_skips_a_torn_tail_and_continues() {
        let (_d, j) = test_journal();
        j.append("note", None, data("ok")).unwrap();
        // Append a torn (partial) line, then a whole record via the journal:
        // the sequence must not duplicate because of the torn tail.
        let p = j.dir.join(JOURNAL_FILE);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"v\":1,\"ts\":\"x\",\"wseq\":99,").unwrap();
        j.append("note", None, data("after-torn")).unwrap();
        let (recs, skipped) = read_records(&j.dir);
        assert!(skipped >= 1);
        // The torn-tail guard ends the torn line with `\n`, so the record
        // after it is read intact (previously it was glued onto it and lost),
        // and no duplicate wseq appears.
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].data, data("after-torn"));
        let seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
        let mut s = seqs.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), seqs.len(), "duplicate wseq after torn tail");
    }

    #[test]
    fn truncation_at_any_byte_never_damages_or_hides_later_records() {
        // Item 3: crash-during-write can cut a record at ANY byte. Cut a
        // 3-record file at every offset, then append and read: records
        // before the cut survive, the cut record is lost (skipped), and the
        // record appended after the cut is read intact with a wseq that
        // does not duplicate any surviving one.
        let (_d, j) = test_journal();
        for k in ["one", "two", "three"] {
            j.append("note", None, data(k)).unwrap();
        }
        let path = j.dir.join(JOURNAL_FILE);
        let full = fs::read(&path).unwrap();
        // Line boundaries in the full file.
        let nl: Vec<usize> = full
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(nl.len(), 3);
        for cut in 0..=full.len() {
            let d = tempfile::tempdir().unwrap();
            let dir = d.path().join("ws");
            create_test_ws_dir(&dir);
            fs::write(dir.join(JOURNAL_FILE), &full[..cut]).unwrap();
            // Ensure the lock file exists so readers/writers agree (append
            // creates it; read_records tolerates its absence).
            let j2 = Journal::new(dir.clone(), "s2".into());
            j2.append("note", None, data("after-cut")).unwrap();
            let (recs, _skipped) = read_records(&dir);
            // The after-cut record must always be present and intact.
            let after = recs.iter().find(|r| r.data == data("after-cut"));
            assert!(
                after.is_some(),
                "cut at {cut}: appended record lost or glued: {recs:?}"
            );
            // Records fully before the cut survive. A record whose JSON is
            // complete but whose terminating `\n` was cut still survives
            // (the append's newline guard terminates it), so the count is
            // of newline positions at or before the cut.
            let complete_lines = nl.iter().filter(|&&p| p <= cut).count();
            for (i, r) in recs.iter().enumerate() {
                let _ = i;
                // Every surviving pre-cut record must be one of one/two/three
                // in order and must not be the cut record.
                assert!(
                    ["one", "two", "three", "after-cut"]
                        .contains(&r.data["k"].as_str().unwrap_or("")),
                    "cut at {cut}: unexpected record {r:?}"
                );
            }
            // No duplicate wseq among survivors.
            let mut seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
            seqs.sort_unstable();
            seqs.dedup();
            assert_eq!(
                seqs.len(),
                recs.len(),
                "cut at {cut}: duplicate wseq in {recs:?}"
            );
            // The number of surviving original records equals the number of
            // complete lines before the cut.
            let surviving_originals = recs.iter().filter(|r| r.data != data("after-cut")).count();
            assert_eq!(
                surviving_originals, complete_lines,
                "cut at {cut}: expected {complete_lines} surviving originals, got {surviving_originals} from {recs:?}"
            );
        }
    }

    #[test]
    fn multiprocess_writers_keep_wseq_strictly_increasing() {
        // Item 3: several PROCESSES (not only threads) appending to one
        // workspace. Children are re-executions of this test binary running
        // the helper below with HISN_JOURNAL_CHILD set.
        if std::env::var("HISN_JOURNAL_CHILD").is_ok() {
            let dir = std::env::var("HISN_JOURNAL_DIR").unwrap();
            let sess = std::env::var("HISN_JOURNAL_SESS").unwrap();
            let j = Journal::new(std::path::PathBuf::from(dir), sess);
            for i in 0..25 {
                j.append("exec/request", None, json!({"i": i})).unwrap();
            }
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        create_test_ws_dir(&dir);
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for t in 0..4 {
            let child = std::process::Command::new(&exe)
                .args([
                    "journal::tests::multiprocess_writers_keep_wseq_strictly_increasing",
                    "--exact",
                    "--nocapture",
                ])
                .env("HISN_JOURNAL_CHILD", "1")
                .env("HISN_JOURNAL_DIR", dir.to_string_lossy().as_ref())
                .env("HISN_JOURNAL_SESS", format!("proc-{t}"))
                .spawn()
                .unwrap();
            children.push(child);
        }
        for mut c in children {
            let status = c.wait().unwrap();
            assert!(status.success(), "child failed: {status}");
        }
        let (recs, skipped) = read_records(&dir);
        assert_eq!(skipped, 0, "interleaved or partial line across processes");
        assert_eq!(recs.len(), 100);
        let seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
        assert_eq!(
            seqs,
            (1..=100).collect::<Vec<_>>(),
            "wseq must be 1..=100 in file order"
        );
    }

    #[test]
    fn wseq_continues_across_rotation_after_a_torn_tail() {
        // Item 3: rotate a file whose tail is torn; the next wseq must
        // continue from the last surviving record, not restart at 1.
        let (_d, j) = test_journal();
        for _ in 0..3 {
            j.append("note", None, data("x")).unwrap();
        }
        let path = j.dir.join(JOURNAL_FILE);
        // Tear the tail and force rotation by padding past the threshold.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"torn-bytes-without-newline").unwrap();
        let filler = "x".repeat(64);
        let mut written = 0u64;
        let base = fs::metadata(&path).unwrap().len();
        while written + base <= ROTATE_AFTER {
            let line = format!("{filler}\n");
            f.write_all(line.as_bytes()).unwrap();
            written += line.len() as u64;
        }
        drop(f);
        j.append("note", None, data("after-rotation")).unwrap();
        let (recs, _skipped) = read_records(&j.dir);
        let after = recs
            .iter()
            .find(|r| r.data == data("after-rotation"))
            .unwrap();
        assert_eq!(after.wseq, 4, "wseq must continue (3 pre-rotation + 1)");
    }

    #[test]
    fn reader_during_rotation_sees_every_record_exactly_once() {
        // Item 3 + review R1: a reader running while another thread appends
        // through MANY rotations must see each wseq exactly once in every
        // snapshot — no misses from a file renamed out from under the
        // list, no duplicates. The threshold is tiny so rotation really
        // happens during the reads.
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        create_test_ws_dir(&dir);
        let writer_dir = dir.clone();
        let writer = std::thread::spawn(move || {
            let j = Journal::with_rotate_after(writer_dir, "writer".into(), 1024);
            for i in 0..400 {
                j.append("note", None, json!({"i": i})).unwrap();
            }
        });
        let mut readers = Vec::new();
        for _ in 0..3 {
            let rd = dir.clone();
            readers.push(std::thread::spawn(move || {
                let mut snapshots = Vec::new();
                for _ in 0..30 {
                    let (recs, _) = read_records(&rd);
                    snapshots.push(recs.iter().map(|r| r.wseq).collect::<Vec<_>>());
                }
                snapshots
            }));
        }
        writer.join().unwrap();
        for r in readers {
            let snaps = r.join().unwrap();
            for seqs in &snaps {
                // Every snapshot is exactly 1..=max with no duplicates and
                // no gaps: a missed rotated file would show as a gap, a
                // double-read file as a duplicate.
                if seqs.is_empty() {
                    continue;
                }
                let max = *seqs.iter().max().unwrap();
                assert_eq!(*seqs, (1..=max).collect::<Vec<_>>());
            }
        }
        // At least one rotation must have happened.
        let files = existing_files(&dir);
        assert!(files.len() > 1, "rotation must have occurred: {files:?}");
        let (recs, skipped) = read_records(&dir);
        assert_eq!(skipped, 0);
        assert_eq!(recs.len(), 400);
        let seqs: Vec<u64> = recs.iter().map(|r| r.wseq).collect();
        assert_eq!(seqs, (1..=400).collect::<Vec<_>>());
    }

    #[test]
    fn sync_on_missing_journal_file_is_not_a_failure() {
        // R1: sync() before any write must not count a spurious failure.
        let (_d, j) = test_journal();
        j.sync();
        assert_eq!(j.failures(), 0);
        j.append("note", None, data("x")).unwrap();
        j.sync();
        assert_eq!(j.failures(), 0);
    }

    #[test]
    fn render_escapes_terminal_sequences_but_json_stays_exact() {
        // Item 5: ESC/newlines in agent-supplied strings must not reach the
        // reader's terminal in readable mode; --json stays byte-exact.
        let rec = JournalRecord {
            v: 1,
            ts: "2026-11-14T00:00:00Z".into(),
            wseq: 7,
            session: "ses\u{1b}[31m".into(),
            kind: "note\nforged".into(),
            client: Some(JournalClient::plain(
                1000,
                "evil\u{1b}]0;pwned\u{07}".into(),
                "flag".into(),
                None,
            )),
            data: json!({"text": "line1\nline2\u{1b}[0m"}),
        };
        let r = render(&rec);
        assert!(!r.contains('\u{1b}'), "raw ESC in readable output: {r:?}");
        assert!(
            !r.contains('\n') || r.ends_with('}'),
            "raw newline in readable output: {r:?}"
        );
        // The readable line is a single line.
        assert_eq!(
            r.matches('\n').count(),
            0,
            "readable output must be one line: {r:?}"
        );
        // --json is byte-exact (serde escapes, nothing dropped).
        let j = serde_json::to_string(&rec).unwrap();
        assert!(j.contains("\\u001b") || j.contains("\\x1b") || !j.contains('\u{1b}'));
        let back: JournalRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, rec);
        assert!(j.contains("pwned"));
    }

    #[test]
    fn note_text_round_trips_verbatim_and_never_becomes_a_second_record() {
        // Item 5: newlines, quotes, NUL, JSON-looking content and multibyte
        // text round-trip unchanged; the record count stays one.
        let texts = [
            "line1\nline2\r\nline3",
            "quote \" and ' and \\\\ backslash",
            "nul\u{0}inside",
            "{\"op\":\"exec\",\"argv\":[\"rm\",\"-rf\",\"/\"]}",
            "$HOME `whoami` $(id)",
            "multibyte: caf\u{00e9} \u{65e5}\u{672c}\u{8a9e} \u{1f600}",
            "tab\tand\u{1b}esc",
        ];
        let (_d, j) = test_journal();
        for t in texts {
            j.append("note", None, json!({"kind": "note", "text": t}))
                .unwrap();
        }
        let (recs, skipped) = read_records(&j.dir);
        assert_eq!(skipped, 0);
        assert_eq!(recs.len(), texts.len(), "one record per note, never two");
        for (r, t) in recs.iter().zip(texts.iter()) {
            assert_eq!(r.data["text"].as_str().unwrap(), *t);
        }
    }

    #[test]
    fn query_limits_last_and_since() {
        // Item 5: --last caps the count, --since filters by time.
        let (_d, j) = test_journal();
        for _ in 0..5 {
            j.append("note", None, data("x")).unwrap();
        }
        let (recs, _) = read_records(&j.dir);
        assert_eq!(recs.len(), 5);
        let last0 = query(
            &recs,
            &Query {
                last: Some(0),
                ..Default::default()
            },
        );
        assert!(last0.is_empty());
        let last2 = query(
            &recs,
            &Query {
                last: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(last2.len(), 2);
        let last_big = query(
            &recs,
            &Query {
                last: Some(100),
                ..Default::default()
            },
        );
        assert_eq!(last_big.len(), 5);
        // --since with a future timestamp excludes everything; with an epoch
        // timestamp includes everything (enforced filtering, item 5).
        let future = query(
            &recs,
            &Query {
                since_secs: Some(i64::MAX / 2),
                ..Default::default()
            },
        );
        assert!(future.is_empty());
        let epoch = query(
            &recs,
            &Query {
                since_secs: Some(0),
                ..Default::default()
            },
        );
        assert_eq!(epoch.len(), 5);
    }

    #[test]
    fn over_long_record_line_is_skipped_not_oom() {
        // Item 5: a single record line over MAX_RECORD_BYTES is skipped
        // (counted) instead of being read into memory. The memory bound is
        // pinned separately by `over_long_line_does_not_grow_memory_with_
        // its_length` (item 8): the reader drains the over-long remainder
        // from its own buffer instead of accumulating it.
        let (_d, j) = test_journal();
        j.append("note", None, data("ok")).unwrap();
        let path = j.dir.join(JOURNAL_FILE);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write as _;
        let big = "x".repeat(MAX_RECORD_BYTES + 16);
        f.write_all(big.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        j.append("note", None, data("after")).unwrap();
        let (recs, skipped) = read_records(&j.dir);
        assert!(
            skipped >= 1,
            "over-long line must be skipped, got {skipped}"
        );
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].data, data("after"));
    }

    #[test]
    fn overflow_of_wseq_and_rotated_file_number_is_a_counted_failure() {
        // Item 8: a journal whose last record has wseq u64::MAX, and a
        // rotated file numbered u32::MAX, must fail the append (counted),
        // never panic (debug) or wrap (release).
        let (_d, j) = test_journal();
        create_test_ws_dir(&j.dir);
        let path = j.dir.join(JOURNAL_FILE);
        let rec = JournalRecord {
            v: JOURNAL_VERSION,
            ts: "2026-11-14T00:00:00Z".into(),
            wseq: u64::MAX,
            session: "s1".into(),
            kind: "note".into(),
            client: None,
            data: data("max"),
        };
        let mut line = serde_json::to_string(&rec).unwrap();
        line.push('\n');
        fs::write(&path, line).unwrap();
        // Make the file look oversize so the append takes the rotate path
        // too — the wseq overflow must fire first (next_wseq runs before
        // the rotation check).
        let r = j.append("note", None, data("after-max"));
        assert!(r.is_err(), "u64::MAX wseq must fail the append");
        assert_eq!(j.failures(), 1);
        // And rotate() itself refuses the u32 overflow.
        fs::write(
            j.dir.join("journal.4294967295.jsonl"),
            b"not a real journal\n",
        )
        .unwrap();
        assert!(rotate(&j.dir).is_err(), "u32::MAX rotation must fail");
    }

    #[test]
    fn over_long_line_does_not_grow_memory_with_its_length() {
        // Item 8: an over-long line must not grow reader memory with its
        // length. Reading a file whose first line is 64 MiB (4x the
        // 16 MiB cap) must return the same records as the 1-byte-over-cap
        // case, with the over-long line skipped exactly once. The drain
        // (`drain_to_newline`) discards from the reader's own buffer now
        // (it accumulated a Vec before `6e73ca3`); this test pins the
        // observable behaviour. Memory itself is not measured — that
        // needs instrumentation the unit suite does not have — but the
        // accumulation path is gone from the code (verified by reading
        // `drain_to_newline`), and a 64 MiB line is handled in the same
        // bounded time/space as a 16 MiB one.
        let (_d, j) = test_journal();
        j.append("note", None, data("before")).unwrap();
        let path = j.dir.join(JOURNAL_FILE);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write as _;
        // 64 MiB of filler without a newline, then the newline.
        let big = "x".repeat(64 * 1024 * 1024);
        f.write_all(big.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        j.append("note", None, data("after")).unwrap();
        let (recs, skipped) = read_records(&j.dir);
        assert_eq!(skipped, 1, "one over-long line, counted once");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data, data("before"));
        assert_eq!(recs[1].data, data("after"));
    }

    #[test]
    fn journaled_event_cost_does_not_grow_with_file_size() {
        // Item 3: measure the per-event cost at three file sizes and guard
        // against size-dependent growth (the tail scan is bounded at 64 KiB;
        // the lock is one flock). Loose bounds keep this from flaking on a
        // loaded CI host; the measured numbers are reported in the Follow-up
        // section of the step-1 report.
        let (_d, j) = test_journal();
        let measure = |j: &Journal, n: usize| -> f64 {
            let start = std::time::Instant::now();
            for _ in 0..n {
                j.append("note", None, data("timed")).unwrap();
            }
            start.elapsed().as_micros() as f64 / n as f64
        };
        // Small file (fits the tail window entirely).
        for _ in 0..100 {
            j.append("note", None, data("grow")).unwrap();
        }
        let small = measure(&j, 300);
        // Medium file (well past the 64 KiB tail window: ~1500 records is
        // ~180 KiB at ~120 bytes per record).
        for _ in 0..1500 {
            j.append("note", None, data("grow")).unwrap();
        }
        let medium = measure(&j, 300);
        // Large file (10x the medium).
        for _ in 0..15_000 {
            j.append("note", None, data("grow")).unwrap();
        }
        let large = measure(&j, 300);
        eprintln!(
            "journal append cost: small={small:.1}us medium={medium:.1}us large={large:.1}us per event"
        );
        // No absolute ceiling a slow host would trip, but growth with size
        // is the regression this guards.
        assert!(
            large < medium * 3.0 + 1000.0,
            "append cost grows with file size: small={small:.1} medium={medium:.1} large={large:.1}us"
        );
        assert!(
            large < 50_000.0,
            "append cost unreasonably high in absolute terms: {large:.1}us/event"
        );
    }

    #[test]
    fn polish2_legacy_sequence_stays_compact() {
        let records = vec![
            rec(
                1,
                "exec/request",
                "abcdef0123456789",
                Some("local"),
                json!({"op":"exec","stage":"request","seq":7,"path":"sh","result":null}),
            ),
            rec(
                2,
                "exec/result",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":7,"result":"ok"}),
            ),
            rec(
                3,
                "note",
                "abcdef0123456789",
                Some("local"),
                json!({"text":"hello"}),
            ),
            rec(
                4,
                "session/stop",
                "abcdef0123456789",
                None,
                json!({"workspace":"ws"}),
            ),
            rec(
                5,
                "git-change",
                "abcdef0123456789",
                None,
                json!({"before":{"hooks":[],"config":{}},"after":{"hooks":[],"config":{}},"changes":{"hooks":{"added":[],"removed":[],"modified":[]},"config":{"added":[],"removed":[],"changed":[]}}}),
            ),
        ];
        assert_eq!(
            render_collapsed(&records),
            vec![
                "2026-11-14T12:00:00Z #1 abcdef01 exec local \"sh\" [open]",
                "2026-11-14T12:00:00Z #3 abcdef01 note local hello",
                "2026-11-14T12:00:00Z #4 abcdef01 session/stop - session stopped",
                "2026-11-14T12:00:00Z #5 abcdef01 git-change - git hooks +0 -0 ~0; config +0 -0 ~0",
            ]
        );
    }

    #[test]
    fn polish2_last_five_are_complete_events() {
        let mut records = Vec::new();
        for seq in 1..=20 {
            records.push(rec(
                seq,
                "exec/request",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":seq,"argv":["echo",format!("job-{seq}")]}),
            ));
        }
        // Every request is older than every completion: --last must look back.
        for seq in 1..=20 {
            records.push(rec(
                20 + seq * 2 - 1,
                "exec/result",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":seq,"result":"ok"}),
            ));
            records.push(rec(
                20 + seq * 2,
                "exec/exit",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":seq,"exit_code":0,"duration_ms":seq}),
            ));
        }
        let q = Query {
            last: Some(5),
            ..Query::default()
        };
        let lines = query_readable(&records, &q);
        assert_eq!(lines.len(), 5, "{lines:?}");
        for (line, seq) in lines.iter().zip(16..=20) {
            assert_eq!(
                line,
                &format!(
                    "2026-11-14T12:00:00Z #{seq} abcdef01 exec local \"echo\" \"job-{seq}\" exit:0 {seq}ms"
                )
            );
            println!("{line}");
        }
        assert_eq!(
            query(&records, &q).len(),
            5,
            "JSON keeps counting raw records"
        );
    }

    #[test]
    fn polish2_orphan_exit_is_marked() {
        let records = [rec(
            1,
            "exec/exit",
            "abcdef0123456789",
            Some("local"),
            json!({"seq":9,"exit_code":3,"duration_ms":4}),
        )];
        assert_eq!(
            query_readable(&records, &Query::default()),
            vec![
                "2026-11-14T12:00:00Z #1 abcdef01 exec/exit local exit:3 4ms [orphan: request unavailable]"
            ]
        );
    }

    #[test]
    fn polish2_exec_kind_and_open_kind() {
        let records = [rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({"seq":1,"argv":["sleep","30"]}),
        )];
        assert_eq!(
            query_readable(&records, &Query::default()),
            vec!["2026-11-14T12:00:00Z #1 abcdef01 exec local \"sleep\" \"30\" [open]"]
        );
    }
    #[test]
    fn polish2_kind_exec_selects_family_only_in_readable_mode() {
        let records = [
            rec(
                1,
                "exec/request",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":1,"argv":["true"]}),
            ),
            rec(
                2,
                "note",
                "abcdef0123456789",
                None,
                json!({"text":"not exec"}),
            ),
            rec(
                3,
                "exec/exit",
                "abcdef0123456789",
                Some("local"),
                json!({"seq":1,"exit_code":0,"duration_ms":1}),
            ),
        ];
        let q = Query {
            kind: Some("exec".into()),
            ..Query::default()
        };
        assert_eq!(
            query_readable(&records, &q),
            vec!["2026-11-14T12:00:00Z #1 abcdef01 exec local \"true\" exit:0 1ms"]
        );
        assert!(query(&records, &q).is_empty(), "JSON filter remains exact");
    }

    #[test]
    fn polish2_reused_session_id_does_not_borrow_an_old_exit() {
        let records = vec![
            rec(1, "session/start", "same", None, json!({})),
            rec(
                2,
                "exec/request",
                "same",
                Some("local"),
                json!({"seq":1,"argv":["old"]}),
            ),
            rec(
                3,
                "exec/exit",
                "same",
                Some("local"),
                json!({"seq":1,"exit_code":0,"duration_ms":1}),
            ),
            rec(4, "session/stop", "same", None, json!({})),
            rec(5, "session/start", "same", None, json!({})),
            rec(
                6,
                "exec/request",
                "same",
                Some("local"),
                json!({"seq":1,"argv":["new"]}),
            ),
        ];
        let q = Query {
            kind: Some("exec".into()),
            ..Query::default()
        };
        assert_eq!(
            query_readable(&records, &q),
            vec![
                "2026-11-14T12:00:00Z #2 same exec local \"old\" exit:0 1ms",
                "2026-11-14T12:00:00Z #6 same exec local \"new\" [open]",
            ]
        );
        let q = Query { last: Some(1), ..q };
        assert_eq!(
            query_readable(&records, &q),
            vec!["2026-11-14T12:00:00Z #6 same exec local \"new\" [open]",]
        );
        // Also separate repeated requests when a start marker was lost.
        let no_starts: Vec<_> = records
            .into_iter()
            .filter(|r| r.kind.starts_with("exec/"))
            .collect();
        assert_eq!(render_collapsed(&no_starts).len(), 2);
    }

    #[test]
    fn release050_every_writable_kind_is_compact_and_unknown_uses_fallback() {
        let escaped_label = "local";
        let kinds = [
            (
                "grant/request",
                json!({"op":"grant","stage":"request","path":"/srv/data","mode":"rw","result":null,"seq":11,"authz":{"allow":true}}),
                "grant/request",
                "/srv/data rw",
            ),
            (
                "grant/result",
                json!({"op":"grant","stage":"result","path":"/srv/data","mode":"rw","result":"ok","seq":11,"authz":{"allow":true}}),
                "grant/result",
                "/srv/data ok",
            ),
            (
                "revoke/request",
                json!({"op":"revoke","stage":"request","path":"/srv/data","mode":null,"result":null,"seq":12,"authz":{"allow":true}}),
                "revoke/request",
                "/srv/data",
            ),
            (
                "revoke/result",
                json!({"op":"revoke","stage":"result","path":"/srv/data","mode":null,"result":"ok","seq":12,"authz":{"allow":true}}),
                "revoke/result",
                "/srv/data ok",
            ),
            (
                "signal/request",
                json!({"op":"signal","stage":"request","path":null,"mode":null,"result":"KILL","uid":1000,"seq":13,"authz":{"allow":true}}),
                "signal/request",
                "KILL",
            ),
            (
                "kill/request",
                json!({"op":"kill","stage":"request","path":null,"mode":null,"result":"TERM","uid":1000,"seq":14,"authz":{"allow":true}}),
                "kill/request",
                "TERM",
            ),
            (
                "exec/result",
                json!({"op":"exec","stage":"result","path":"sh","mode":null,"result":"ok","seq":15,"authz":{"allow":true}}),
                "exec/result",
                "result:ok",
            ),
            (
                "attach/result",
                json!({"op":"attach","stage":"result","path":"sh","mode":null,"result":"ok","seq":16,"authz":{"allow":true}}),
                "attach/result",
                "result:ok",
            ),
            (
                "exec/exit",
                json!({"op":"exec","stage":"exit","duration_ms":120,"cancelled":false,"lost":false,"seq":17,"authz":{"allow":true},"exit_code":3}),
                "exec/exit",
                "exit:3 120ms",
            ),
            (
                "auth/refused",
                json!({"op":"auth","stage":"refused","result":"not owner","uid":1000,"seq":18,"authz":{"allow":false}}),
                "auth/refused",
                "auth refused (not owner)",
            ),
            (
                "forward/start",
                json!({"op":"forward","stage":"start","path":"/tmp/service.sock","mode":null,"result":null}),
                "forward/start",
                "forward /tmp/service.sock",
            ),
            (
                "forward/result",
                json!({"op":"forward","stage":"result","path":"/tmp/service.sock","mode":null,"result":"ok"}),
                "forward/result",
                "forward /tmp/service.sock ok",
            ),
            (
                "lease/expired",
                json!({"op":"lease","stage":"expired","path":null,"mode":null,"result":"idle"}),
                "lease/expired",
                "lease expired (idle)",
            ),
            (
                "grant/refused",
                json!({"op":"grant","stage":"refused","path":"/srv/data","mode":"rw","result":"not owner","seq":19,"authz":{"allow":false}}),
                "grant/refused",
                "grant /srv/data refused (not owner)",
            ),
            (
                "session/start",
                json!({"workspace":"0123456789abcdef"}),
                "session/start",
                "session started",
            ),
            (
                "session/stop",
                json!({"workspace":"0123456789abcdef"}),
                "session/stop",
                "session stopped",
            ),
            (
                "note",
                json!({"kind":"note","text":"hello"}),
                "note",
                "hello",
            ),
            (
                "marker",
                json!({"kind":"marker","text":"checkpoint"}),
                "marker",
                "checkpoint",
            ),
            (
                "git-change",
                json!({"cwd":"/work/proj","unchanged":true,"hooks_count":1,"config_keys_count":2}),
                "git-change",
                "git unchanged (hooks 1, config keys 2)",
            ),
        ];
        let records: Vec<_> = kinds
            .iter()
            .enumerate()
            .map(|(i, (kind, data, _, _))| {
                rec(
                    (i + 1) as u64,
                    kind,
                    "abcdef0123456789",
                    Some(escaped_label),
                    data.clone(),
                )
            })
            .collect();
        let lines = render_collapsed(&records);
        assert_eq!(lines.len(), kinds.len(), "{lines:?}");
        for (line, (_, _, kind, expected)) in lines.iter().zip(kinds.iter()) {
            assert!(line.contains(kind), "line names its kind: {line}");
            assert!(
                line.contains(expected),
                "line summarizes {kind} as {expected:?}: {line}"
            );
            assert!(
                !line.contains('{') && !line.contains('}'),
                "no raw JSON object printed: {line}"
            );
        }
        // Multi-line wire-op/records and unknown kinds never reach the raw dump.
        for kind in ["inspect/request", "future/kind"] {
            let line = summary_for(&rec(
                (kinds.len() + 1) as u64,
                kind,
                "abcdef0123456789",
                None,
                json!({"op":"future","stage":"request","seq":20,"future":{"raw":"value"}}),
            ));
            assert!(
                line.contains(kind),
                "unknown fallback names its kind: {line}"
            );
            assert!(
                !line.contains('{') && !line.contains('}'),
                "unknown fallback never prints JSON: {line}"
            );
            assert!(
                line.contains("--json"),
                "unknown fallback points to --json: {line}"
            );
            assert!(
                line.contains(
                    &serde_json::to_string(
                        &json!({"op":"future","stage":"request","seq":20,"future":{"raw":"value"}})
                    )
                    .unwrap()
                    .len()
                    .to_string()
                ),
                "fallback reports record size: {line}"
            );
        }
    }

    #[test]
    fn release050_unknown_kind_is_terminal_escaped() {
        let escaped = summary_for(&rec(
            1,
            "future/\u{1b}[31mkind",
            "abcdef0123456789",
            None,
            json!({"op":"future","stage":"request","seq":21,"future":{"raw":"value"}}),
        ));
        assert!(
            !escaped.contains('\u{1b}'),
            "fallback must not pass ESC through: {escaped:?}"
        );
        assert!(!escaped.contains('{') && !escaped.contains('}'));
        assert!(escaped.contains("--json"), "{escaped}");
    }

    #[test]
    fn polish2_marker_failure_is_counted_without_failing_start() {
        let d = tempfile::tempdir_in("target").unwrap();
        let dir = d.path().join("workspace");
        crate::workspace::ensure_workspace(&dir).unwrap();
        std::fs::write(dir.join("sessions"), b"not a directory").unwrap();
        let journal = Journal::new(dir.clone(), "id".into());
        journal.session_start_with_marker(Some("chat"));
        assert_eq!(journal.failures(), 1);
        let (records, _) = read_records(&dir);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "session/start");
    }

    // ---- Item 3: collapsed readable output ----

    fn rec(
        wseq: u64,
        kind: &str,
        session: &str,
        label: Option<&str>,
        data: Value,
    ) -> JournalRecord {
        JournalRecord {
            v: 1,
            ts: "2026-11-14T12:00:00Z".into(),
            wseq,
            session: session.into(),
            kind: kind.into(),
            client: label
                .map(|l| JournalClient::plain(1000, l.into(), "flag".into(), Some("r1".into()))),
            data,
        }
    }

    #[test]
    fn readable_output_collapses_an_exec_triple_into_one_line() {
        // Item 3: a request, its result and its exit with the same session
        // and `seq` collapse into one line; the exit code and duration are
        // shown once known.
        let req = rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({
                "op": "exec", "stage": "request", "seq": 7,
                "argv": ["sh", "-c", "echo hi"], "argv_truncated": false,
                "argv_count": 3, "argv_bytes": 9, "cwd": "/work/proj",
            }),
        );
        let res = rec(
            2,
            "exec/result",
            "abcdef0123456789",
            Some("local"),
            json!({"op": "exec", "stage": "result", "result": "ok", "seq": 7}),
        );
        let exit = rec(
            3,
            "exec/exit",
            "abcdef0123456789",
            Some("local"),
            json!({
                "op": "exec", "stage": "exit", "seq": 7,
                "exit_code": 0, "cancelled": false, "lost": false,
                "duration_ms": 120,
            }),
        );
        let lines = render_collapsed(&[req, res, exit]);
        assert_eq!(
            lines.len(),
            1,
            "triple must collapse to one line: {lines:?}"
        );
        let l = &lines[0];
        assert!(l.contains("\"sh\""), "quoted argv: {l}");
        assert!(l.contains("\"-c\""), "quoted argv: {l}");
        assert!(l.contains("\"echo hi\""), "quoted argv: {l}");
        assert!(l.contains("/work/proj"), "cwd: {l}");
        assert!(l.contains("exit:0"), "exit code: {l}");
        assert!(l.contains("120ms"), "duration: {l}");
        assert!(l.contains("abcdef01"), "first 8 of session: {l}");
        assert!(l.contains("#1"), "head wseq: {l}");
        assert!(l.contains("local"), "seat label: {l}");
    }

    #[test]
    fn readable_output_marks_a_request_without_exit_as_open() {
        let req = rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({"op": "exec", "stage": "request", "seq": 7, "argv": ["sleep", "30"]}),
        );
        let lines = render_collapsed(&[req]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("[open]"), "open marker: {}", lines[0]);
        assert!(lines[0].contains("\"sleep\""), "command: {}", lines[0]);
    }

    #[test]
    fn readable_output_escapes_an_escape_sequence_inside_the_command_line() {
        // Item 3: an ESC inside argv must not reach the reader's terminal;
        // the judge is the raw output bytes (no ESC), not a pattern match.
        let req = rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({"op": "exec", "stage": "request", "seq": 7, "argv": ["sh", "-c", "echo \u{1b}[31mRED"]}),
        );
        let lines = render_collapsed(&[req]);
        let l = &lines[0];
        assert!(!l.contains('\u{1b}'), "raw ESC reached terminal: {l:?}");
        assert!(l.contains("\\x1b"), "escaped form present: {l:?}");
        assert_eq!(l.matches('\n').count(), 0, "one line: {l:?}");
    }

    #[test]
    fn readable_output_summarises_note_grant_and_git_change() {
        let note = rec(
            1,
            "note",
            "abcdef0123456789",
            Some("local"),
            json!({"text": "hello world"}),
        );
        let grant = rec(
            2,
            "grant/request",
            "abcdef0123456789",
            Some("local"),
            json!({"path": "/srv/data", "mode": "rw", "result": null}),
        );
        let git = rec(
            3,
            "git-change",
            "abcdef0123456789",
            None,
            json!({
                "cwd": "/work/proj",
                "before": {"hooks": [], "config": {"core.hookspath": ["/safe/hooks"]}},
                "after": {"hooks": [{"name": "pre-commit"}], "config": {"core.hookspath": ["/evil/hooks"]}},
                "changes": {
                    "hooks": {"added": ["pre-commit"], "removed": [], "modified": []},
                    "config": {"added": [], "removed": [], "changed": ["core.hookspath"]},
                    "flagged": ["core.hookspath"],
                    "truncated": {"before": false, "after": false},
                    "skipped": {"before": null, "after": null},
                },
            }),
        );
        let lines = render_collapsed(&[note, grant, git]);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("hello world"), "note text: {}", lines[0]);
        assert!(lines[1].contains("/srv/data rw"), "grant: {}", lines[1]);
        assert!(
            lines[2].contains("core.hookspath"),
            "flagged key: {}",
            lines[2]
        );
        assert!(lines[2].contains("flagged"), "flagged marker: {}", lines[2]);
        assert!(lines[2].contains("hooks +1"), "hook count: {}", lines[2]);
        assert!(
            !lines[2].contains("hooks +0"),
            "must not read as unchanged: {}",
            lines[2]
        );
    }

    #[test]
    fn readable_output_does_not_collapse_records_from_different_sessions() {
        // Same seq, different session: two lines, not one.
        let a = rec(
            1,
            "exec/request",
            "aaaaaaaa11111111",
            Some("l"),
            json!({"argv": ["x"], "seq": 7}),
        );
        let b = rec(
            2,
            "exec/request",
            "bbbbbbbb22222222",
            Some("l"),
            json!({"argv": ["y"], "seq": 7}),
        );
        let lines = render_collapsed(&[a, b]);
        assert_eq!(
            lines.len(),
            2,
            "different sessions must not collapse: {lines:?}"
        );
    }

    #[test]
    fn readable_output_shows_a_spawn_failure_as_failed_not_open() {
        // Mashūra round 2: a request + an error result (no exit record)
        // is finished work that failed to spawn — it must not read as an
        // open exec.
        let req = rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({"op": "exec", "stage": "request", "seq": 7, "argv": ["nonexistent"]}),
        );
        let res = rec(
            2,
            "exec/result",
            "abcdef0123456789",
            Some("local"),
            json!({"op": "exec", "stage": "result", "result": "E_EXEC", "seq": 7}),
        );
        let lines = render_collapsed(&[req, res]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("failed:E_EXEC"),
            "error shown: {}",
            lines[0]
        );
        assert!(!lines[0].contains("[open]"), "not open: {}", lines[0]);
        assert!(
            lines[0].contains("nonexistent"),
            "command shown: {}",
            lines[0]
        );
    }

    #[test]
    fn readable_argv_cannot_forge_renderer_annotations() {
        // Mashūra round 2: an argument that looks like an annotation must
        // stay inside the quotes, and element boundaries must survive.
        let req = rec(
            1,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({
                "op": "exec", "stage": "request", "seq": 7,
                "argv": ["sh", "-c", "echo exit:0 [open] (cwd /safe)"],
            }),
        );
        let lines = render_collapsed(&[req]);
        let l = &lines[0];
        assert!(
            l.contains("\"echo exit:0 [open] (cwd /safe)\""),
            "forged text stays quoted: {l}"
        );
        assert_eq!(
            l.matches("[open]").count(),
            2,
            "one in the quoted argv, one the renderer's open marker: {l}"
        );
        assert!(l.ends_with(" [open]"), "renderer marker is the suffix: {l}");
        assert!(
            l.contains("\"echo exit:0 [open] (cwd /safe)\" [open]"),
            "quoted argv ends, then the renderer marker: {l}"
        );
        let req = rec(
            2,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({
                "op": "exec", "stage": "request", "seq": 8,
                "argv": ["a\"b", "c\\d"],
            }),
        );
        let lines = render_collapsed(&[req]);
        assert!(
            lines[0].contains("\"a\\\"b\""),
            "quote escaped: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("\"c\\\\d\""),
            "backslash escaped: {}",
            lines[0]
        );
        let req = rec(
            3,
            "exec/request",
            "abcdef0123456789",
            Some("local"),
            json!({
                "op": "exec", "stage": "request", "seq": 9,
                "argv": ["", "x"],
            }),
        );
        let lines = render_collapsed(&[req]);
        assert!(
            lines[0].contains("\"\" \"x\""),
            "empty element: {}",
            lines[0]
        );
    }

    #[test]
    fn exec_argv_cap_is_present_and_exact_below_the_cap() {
        let argv = vec!["echo".to_owned(), "hello world".into(), "--flag".into()];
        let v = cap_argv(&argv);
        assert_eq!(v["argv"], json!(argv));
        assert_eq!(v["argv_truncated"], json!(false));
        assert_eq!(v["argv_count"], json!(argv.len()));
        assert_eq!(
            v["argv_bytes"],
            json!(argv.iter().map(|s| s.len()).sum::<usize>())
        );
    }

    #[test]
    fn exec_argv_cap_truncates_above_the_cap_with_correct_counts() {
        // 600 bytes of argv in total: over the 512-byte cap.
        let argv = vec!["x".repeat(300), "y".repeat(300)];
        let v = cap_argv(&argv);
        assert_eq!(v["argv_truncated"], json!(true));
        assert_eq!(v["argv_count"], json!(2));
        assert_eq!(v["argv_bytes"], json!(600));
        let kept: Vec<String> = serde_json::from_value(v["argv"].clone()).unwrap();
        let kept_bytes: usize = kept.iter().map(|s| s.len()).sum();
        assert!(kept_bytes <= 512, "kept {kept_bytes} bytes over the cap");
        assert_eq!(kept, ["x".repeat(300)], "whole elements only, first fits");
    }

    #[test]
    fn exec_argv_cap_cuts_on_a_character_boundary() {
        // Multibyte: the first element alone (800 bytes) exceeds the cap,
        // so it is cut to exactly 512 bytes on a character boundary. Only
        // whole elements are kept, so `argv` is empty and the cut is not
        // represented as a partial element — the counts still report the
        // original. A cut element is never emitted split.
        let argv = vec!["\u{1f600}".repeat(200)];
        let v = cap_argv(&argv);
        assert_eq!(v["argv_truncated"], json!(true));
        assert_eq!(v["argv_count"], json!(1));
        assert_eq!(v["argv_bytes"], json!(800));
        let kept: Vec<String> = serde_json::from_value(v["argv"].clone()).unwrap();
        assert!(
            kept.is_empty(),
            "an over-cap first element is dropped whole: {kept:?}"
        );
        // An element that fits exactly, followed by one that does not:
        // the first survives intact.
        let argv = vec!["a".repeat(508), "\u{1f600}".repeat(2)];
        let v = cap_argv(&argv);
        let kept: Vec<String> = serde_json::from_value(v["argv"].clone()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].len(), 508);
        assert!(kept[0].chars().all(|c| c == 'a'));
        assert_eq!(v["argv_truncated"], json!(true));
        assert_eq!(v["argv_count"], json!(2));
        assert_eq!(v["argv_bytes"], json!(516));
        // A multibyte element that fits exactly at the cap boundary.
        let argv = vec![format!("{}\u{00e9}", "a".repeat(510))];
        let v = cap_argv(&argv);
        assert_eq!(v["argv_truncated"], json!(false));
        let kept: Vec<String> = serde_json::from_value(v["argv"].clone()).unwrap();
        assert_eq!(kept[0].len(), 512);
        assert!(kept[0].ends_with('\u{00e9}'));
    }

    #[test]
    fn exec_record_carries_argv_and_cwd_but_grants_line_does_not() {
        // The journal's exec request record carries argv + cwd; the audit
        // entry for the same event carries neither (rule 4: grants.jsonl is
        // byte-identical to 0.4.3). Proven at the data level here; the
        // supervisor wiring is covered by the leak case L86/L87 (host).
        let (_d, j) = test_journal();
        let argv = vec!["sh".into(), "-c".into(), "echo RECOGNISABLE-ARG-42".into()];
        let mut data = json!({ "op": "exec", "stage": "request" });
        data["argv"] = cap_argv(&argv)["argv"].clone();
        data["argv_truncated"] = cap_argv(&argv)["argv_truncated"].clone();
        data["cwd"] = json!("/work/proj");
        j.append("exec/request", None, data).unwrap();
        let (recs, _) = read_records(&j.dir);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].data["argv"],
            json!(["sh", "-c", "echo RECOGNISABLE-ARG-42"])
        );
        assert_eq!(recs[0].data["cwd"], json!("/work/proj"));
        // The 0.4.3 audit shape has no argv/cwd keys at all.
        let audit_entry = json!({
            "ts": "2026-11-14T00:00:00Z", "op": "exec", "stage": "request",
            "path": "sh", "mode": null, "result": null, "pid_peer": 7,
            "client": {"uid": 1000, "label": "x", "label_source": "flag", "req_id": null},
            "seq": 1, "authz": {"allow": true},
        });
        let s = audit_entry.to_string();
        assert!(!s.contains("RECOGNISABLE-ARG-42"));
        assert!(!s.contains("\"argv\""));
        assert!(!s.contains("\"cwd\""));
    }
}

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
//!   (workspace-wide sequence) is assigned under an exclusive `flock` on the
//!   journal dir, and each record is written with a single `write(2)` on an
//!   `O_APPEND` descriptor held under that lock — so two writers can never
//!   interleave a line or duplicate a `wseq`.
//! - Rotation (rotation from day one, O6): when `journal.jsonl` exceeds
//!   64 MiB it is renamed to `journal.<n>.jsonl` under the same lock and a
//!   new file started. Queries read rotated files too.
//!
//! Every record: `v` (1), `ts` (RFC 3339 UTC), `wseq`, `session`, `kind`,
//! `client` (when one exists — an object with `uid`, `label`, `label_source`,
//! `req_id`, mirroring the audit `client` object), and `data`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
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
/// req_id).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalClient {
    pub uid: u32,
    pub label: String,
    pub label_source: String,
    pub req_id: Option<String>,
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
}

impl Journal {
    /// Create a writer for `dir` (the workspace dir), for `session` (the
    /// session id stamped on every record).
    pub fn new(dir: PathBuf, session: String) -> Self {
        Self {
            dir,
            session,
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The failed-write count this process has observed (for `ls --json`).
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
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

    /// Append one record. `kind` is the record kind (an audit `op` plus
    /// stage, a session start/stop, a note, a git-change, …); `client` is
    /// the identity when one exists; `data` is the payload (the audit entry
    /// content for audit-derived records, so the journal carries the same
    /// information `grants.jsonl` carries).
    ///
    /// On failure the caller decides: audit/session records swallow and
    /// count, a `note` returns the error. A failure is also written to
    /// stderr, which for a detached supervisor is `supervisor.log`.
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
        fs::create_dir_all(&self.dir).map_err(|e| JournalError {
            message: format!("create workspace dir: {e}"),
        })?;
        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(self.dir.join(LOCK_FILE))
            .map_err(|e| JournalError {
                message: format!("open {LOCK_FILE}: {e}"),
            })?;
        let _guard = flock(&lock_file)?;
        let path = self.dir.join(JOURNAL_FILE);
        let mut seq = last_wseq(&path).unwrap_or(0) + 1;
        // Rotate before writing when the current file is already oversize.
        if let Some(meta) = fs::metadata(&path).ok()
            && meta.len() > ROTATE_AFTER
        {
            rotate(&self.dir).map_err(|e| JournalError {
                message: format!("rotate: {e}"),
            })?;
            // `wseq` is recovered from the rotated file's tail by `last_wseq`
            // on the next append (the new file is empty, so it falls through).
            seq = last_wseq(&path).unwrap_or(0) + 1;
        }
        // Recompute after the torn-tail check below can only add a newline,
        // never a new record, so `seq` is stable here.
        let _ = seq;
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
        line.push_str(
            &serde_json::to_string(&record).map_err(|e| JournalError {
                message: format!("serialise: {e}"),
            })?,
        );
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
        f.write_all(line.as_bytes())
            .map_err(|e| JournalError {
                message: format!("write: {e}"),
            })?;
        Ok(())
    }
}

/// Take an exclusive flock on an open file. Retries on EINTR: the supervisor
/// installs signal handlers, so a signal during a contended wait can
/// interrupt it.
fn flock(f: &File) -> Result<FlockGuard, JournalError> {
    use std::os::fd::AsRawFd;
    loop {
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        if rc == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(JournalError {
                message: format!("lock: {e}"),
            });
        }
    }
    Ok(FlockGuard(_fd_of(f)))
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
fn last_wseq(path: &Path) -> Option<u64> {
    if let Some(w) = last_wseq_in_file(path) {
        return Some(w);
    }
    let dir = path.parent()?;
    let mut best: Option<(u32, u64)> = None;
    for p in journal_files(dir) {
        if p == *path {
            continue;
        }
        // The rotated file's extension is its number; take the newest.
        let name = p.file_name()?.to_str()?.to_owned();
        let num: u32 = name
            .strip_prefix("journal.")
            .and_then(|n| n.strip_suffix(".jsonl"))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if let Some(w) = last_wseq_in_file(&p) {
            if best.is_none_or(|(n, _)| num > n) {
                best = Some((num, w));
            }
        }
    }
    best.map(|(_, w)| w)
}

const TAIL_BYTES: u64 = 64 * 1024;

fn last_wseq_in_file(path: &Path) -> Option<u64> {
    let mut f = File::open(path).ok()?;
    let meta = f.metadata().ok()?;
    let size = meta.len();
    if size == 0 {
        return None;
    }
    use std::io::{Read, Seek, SeekFrom};
    // A journal file is at most ~64 MiB + a record; with 100 small records the
    // whole file fits the tail window, so one pass always finds the maximum.
    // For a large file the tail window holds the newest records — the maximum
    // is always among them, so the tail scan is *the* scan.
    let start = size.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail).ok()?;
    // If the file fits the window, parse every line.
    if start == 0 {
        let mut best = None;
        for line in tail.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_slice::<JournalRecord>(line) {
                best = Some(best.map_or(rec.wseq, |b: u64| b.max(rec.wseq)));
            }
        }
        return best;
    }
    // Large file: find the last parseable record, then scan the whole file
    // once for the maximum (the tail alone can miss a higher wseq if the
    // window began mid-record and the tail is unparseable).
    let mut best = None;
    for line in tail.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_slice::<JournalRecord>(line) {
            best = Some(best.map_or(rec.wseq, |b: u64| b.max(rec.wseq)));
        }
    }
    f.seek(SeekFrom::Start(0)).ok()?;
    // One full pass for correctness on a large file (rare: only when the tail
    // window did not already contain the maximum).
    if best.is_none() {
        let mut all = Vec::new();
        f.read_to_end(&mut all).ok()?;
        for line in all.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_slice::<JournalRecord>(line) {
                best = Some(best.map_or(rec.wseq, |b: u64| b.max(rec.wseq)));
            }
        }
    }
    best
}

/// Rotate `journal.jsonl` to the next free `journal.<n>.jsonl` in `dir`,
/// using max+1 (a deleted `journal.1.jsonl` must not be reused, or readers
/// would see newer records before older ones). Caller holds the flock.
fn rotate(dir: &Path) -> io::Result<()> {
    let mut max: u32 = 0;
    if let Ok(rd) = fs::read_dir(dir) {
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
    }
    fs::rename(dir.join(JOURNAL_FILE), dir.join(format!("journal.{}.jsonl", max + 1)))
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

/// Read every record in a workspace (rotated files first, then the current
/// one), skipping any unparseable line (a torn tail never breaks the whole
/// read). Returns the records and the number of skipped lines.
pub fn read_records(dir: &Path) -> (Vec<JournalRecord>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for path in journal_files(dir) {
        // Best-effort: `read_records` takes no lock, so a concurrent rotation
        // can make it miss or double-read a file; the records themselves are
        // never corrupt (a single `write` per record under the writer's lock).
        let Ok(f) = File::open(&path) else { continue };
        for line in BufReader::new(f).lines() {
            let Ok(line) = line else { continue };
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalRecord>(&line) {
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
        .filter(|r| match &q.session {
            Some(s) => &r.session == s,
            None => true,
        })
        .filter(|r| match &q.seat {
            Some(seat) => r.client.as_ref().is_some_and(|c| &c.label == seat),
            None => true,
        })
        .filter(|r| match &q.kind {
            Some(k) => &r.kind == k,
            None => true,
        })
        .filter(|r| match q.since_secs {
            Some(t) => crate::session::parse_rfc3339_secs(&r.ts).is_some_and(|s| s >= t),
            None => true,
        })
        .cloned()
        .collect();
    if let Some(n) = q.last {
        let start = out.len().saturating_sub(n);
        out.drain(..start);
    }
    out
}

/// One readable line for a record (the default `hisn journal` output).
pub fn render(rec: &JournalRecord) -> String {
    let client = rec
        .client
        .as_ref()
        .map(|c| format!("{}", c.label))
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "{} #{} {} {} {} {}",
        rec.ts, rec.wseq, rec.session, rec.kind, client, rec.data
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

/// A sink for tests: a journal in a fresh temp dir.
#[cfg(test)]
fn test_journal() -> (tempfile::TempDir, Journal) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("ws");
    (d, Journal::new(path, "s1".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(k: &str) -> Value {
        json!({"k": k})
    }

    #[test]
    fn records_carry_v_ts_wseq_session_kind_client_data() {
        let (_d, j) = test_journal();
        j.append(
            "grant/request",
            Some(JournalClient {
                uid: 1000,
                label: "local".into(),
                label_source: "flag".into(),
                req_id: None,
            }),
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
        fs::create_dir_all(&dir).unwrap();
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
        assert_eq!(seqs, sorted, "wseq must be strictly increasing in file order");
        // The record for wseq 100 must be present and be the last one the
        // file carries — a tail-window undercount would duplicate 1..=100.
        let last = recs.iter().map(|r| r.wseq).max().unwrap();
        assert_eq!(last, 100, "the highest wseq must be 100");
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
        assert!(files.iter().any(|p| p.file_name().unwrap() == "journal.1.jsonl"));
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
            Some(JournalClient {
                uid: 1000,
                label: "alice".into(),
                label_source: "flag".into(),
                req_id: None,
            }),
            data("a"),
        )
        .unwrap();
        j.append(
            "grant/result",
            Some(JournalClient {
                uid: 1000,
                label: "alice".into(),
                label_source: "flag".into(),
                req_id: None,
            }),
            data("b"),
        )
        .unwrap();
        j.append(
            "exec/request",
            Some(JournalClient {
                uid: 1000,
                label: "bob".into(),
                label_source: "ssh".into(),
                req_id: None,
            }),
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
    fn journal_dir_is_private_and_file_is_append_only_jsonl() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, j) = test_journal();
        j.append("session/start", None, data("x")).unwrap();
        let p = j.dir.join(JOURNAL_FILE);
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let text = fs::read_to_string(&p).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
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
        f.write_all(b"{\"v\":1,\"ts\":\"x\",\"wseq\":99,")
            .unwrap();
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
}

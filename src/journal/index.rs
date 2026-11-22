//! Journal cursor index and forward reader (0.6.4, plan sections 2.10, 2.11,
//! 7 B7/B8 and 10).
//!
//! `journal --after-wseq N` used to parse the whole journal. Here the reader
//! seeks to a nearby record instead, using a small offset index kept next to
//! the journal as `journal.idx.<inode>` (mode 0600, JSON lines). The index is
//! keyed by the inode **inside its content and in its name**, so the rename in
//! a rotation needs no hook and writers are untouched.
//!
//! The index is a cache. Everything it says is checked before use (device and
//! inode, boundary byte, the line at the offset must parse and carry the
//! recorded `wseq`); the run read from there is checked for contiguity by
//! `cursor_select`; any result other than a clean `Records` is re-run by a full
//! scan before it is reported. A wrong, truncated, garbage or missing index can
//! therefore cost time and never give a different answer.
//!
//! The same forward reader turns an unreadable line into one
//! `journal/unreadable` record per missing `wseq`, so a corrupt line no
//! longer blocks the cursor forever (B8).

use super::*;

use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{FileExt, MetadataExt};

/// One index entry per this many readable records.
pub const INDEX_EVERY: u64 = 1024;
/// Largest index file read back; a bigger one is treated as garbage.
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
/// Prefix of the index file names. Never matches `journal_files`.
pub const INDEX_PREFIX: &str = "journal.idx.";

#[cfg(test)]
thread_local! {
    static EVERY_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn index_every() -> u64 {
    #[cfg(test)]
    {
        let o = EVERY_OVERRIDE.with(|c| c.get());
        if o > 0 {
            return o;
        }
    }
    INDEX_EVERY
}

/// A journal file pinned under the shared lock: the descriptor keeps the inode
/// alive across a rotation or a prune, `len` bounds every read.
pub(super) struct Pinned {
    file: File,
    len: u64,
    dev: u64,
    ino: u64,
    name: String,
}

/// Pin every journal file under the shared lock (as `read_records` does).
pub(super) fn pin_files(dir: &Path) -> Vec<Pinned> {
    let _shared = shared_lock(dir);
    journal_files(dir)
        .into_iter()
        .filter_map(|p| {
            let file = File::open(&p).ok()?;
            let m = file.metadata().ok()?;
            Some(Pinned {
                file,
                len: m.len(),
                dev: m.dev(),
                ino: m.ino(),
                name: p.file_name()?.to_str()?.to_owned(),
            })
        })
        .collect()
}

/// What `scan` found on one line.
pub(super) enum Line {
    Good(Box<JournalRecord>),
    /// Unparseable or over-long.
    Bad,
    /// A read error: the rest of the file is not trustworthy.
    Err,
}

pub(super) struct Ev {
    pub kind: Line,
    /// Byte offset of the line start.
    pub off: u64,
    /// Byte offset after the line (and its newline, when it has one).
    pub end: u64,
    /// The line ended in `\n`. A torn tail does not.
    pub terminated: bool,
}

/// Like `drain_to_newline`, returning the bytes dropped and whether a newline
/// ended the line.
fn drain_counted<R: BufRead>(r: &mut R) -> (u64, bool) {
    let mut total = 0u64;
    loop {
        let (nl, used) = match r.fill_buf() {
            Ok([]) => return (total, false),
            Ok(buf) => match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (true, i + 1),
                None => (false, buf.len()),
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return (total, false),
        };
        r.consume(used);
        total += used as u64;
        if nl {
            return (total, true);
        }
    }
}

/// Read the lines of `file` in `[start, end)` and hand each to `f` (return
/// `false` to stop). Same line rules as `read_records`: an empty line is
/// ignored, a line over `MAX_RECORD_BYTES` is `Bad` and costs no memory.
pub(super) fn scan(file: &File, start: u64, end: u64, mut f: impl FnMut(Ev) -> bool) {
    let err = |off| Ev {
        kind: Line::Err,
        off,
        end: off,
        terminated: false,
    };
    let Ok(mut h) = file.try_clone() else {
        f(err(start));
        return;
    };
    if h.seek(SeekFrom::Start(start)).is_err() {
        f(err(start));
        return;
    }
    let mut r = BufReader::new(h.take(end.saturating_sub(start)));
    let mut off = start;
    loop {
        let mut buf = Vec::new();
        let n = match r
            .by_ref()
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(n) => n,
            Err(_) => {
                f(err(off));
                return;
            }
        };
        if n == 0 {
            return;
        }
        let has_nl = buf.last() == Some(&b'\n');
        let mut consumed = n as u64;
        if buf.len() - has_nl as usize > MAX_RECORD_BYTES {
            let (extra, nl) = drain_counted(&mut r);
            consumed += extra;
            let ev = Ev {
                kind: Line::Bad,
                off,
                end: off + consumed,
                terminated: nl,
            };
            if !f(ev) {
                return;
            }
            off += consumed;
            continue;
        }
        if has_nl {
            buf.pop();
        }
        let next = off + consumed;
        if buf.is_empty() {
            off = next;
            continue;
        }
        let kind = match serde_json::from_slice::<JournalRecord>(&buf) {
            Ok(r) => Line::Good(Box::new(r)),
            Err(_) => Line::Bad,
        };
        let ev = Ev {
            kind,
            off,
            end: next,
            terminated: has_nl,
        };
        if !f(ev) {
            return;
        }
        off = next;
    }
}

/// The in-memory form of one index file.
struct Index {
    first_wseq: Option<u64>,
    /// End of the last newline-terminated line covered.
    len: u64,
    records: u64,
    unreadable: u64,
    entries: Vec<(u64, u64)>,
}

impl Index {
    fn empty() -> Self {
        Self {
            first_wseq: None,
            len: 0,
            records: 0,
            unreadable: 0,
            entries: Vec::new(),
        }
    }

    /// Cover `[self.len, p.len)`. `false` on a read error (the index is then
    /// not to be used).
    fn extend(&mut self, p: &Pinned) -> bool {
        let every = index_every();
        let mut ok = true;
        let start = self.len;
        scan(&p.file, start, p.len, |ev| {
            if !ev.terminated && !matches!(ev.kind, Line::Err) {
                return false; // a torn tail is not covered
            }
            match ev.kind {
                Line::Err => {
                    ok = false;
                    false
                }
                Line::Good(rec) => {
                    if self.records.is_multiple_of(every) {
                        self.entries.push((rec.wseq, ev.off));
                    }
                    self.first_wseq.get_or_insert(rec.wseq);
                    self.records += 1;
                    self.len = ev.end;
                    true
                }
                Line::Bad => {
                    self.unreadable += 1;
                    self.len = ev.end;
                    true
                }
            }
        });
        ok
    }

    fn to_text(&self, p: &Pinned) -> String {
        let mut s = json!({
            "v": 1, "dev": p.dev, "ino": p.ino, "first_wseq": self.first_wseq,
            "len": self.len, "records": self.records, "unreadable": self.unreadable,
        })
        .to_string();
        s.push('\n');
        for (w, o) in &self.entries {
            s.push_str(&json!({"wseq": w, "off": o}).to_string());
            s.push('\n');
        }
        s
    }
}

pub(super) fn index_path(dir: &Path, ino: u64) -> PathBuf {
    dir.join(format!("{INDEX_PREFIX}{ino}"))
}

/// Does the line at `off` parse and carry `wseq`, after a newline (or the file
/// start)?
fn verify_entry(p: &Pinned, wseq: u64, off: u64) -> bool {
    if off >= p.len {
        return false;
    }
    if off > 0 {
        let mut b = [0u8; 1];
        if p.file.read_exact_at(&mut b, off - 1).is_err() || b[0] != b'\n' {
            return false;
        }
    }
    let mut ok = false;
    scan(&p.file, off, p.len, |ev| {
        ok = ev.off == off && matches!(&ev.kind, Line::Good(r) if r.wseq == wseq);
        false
    });
    ok
}

/// Parse and validate the index file of `p`. `None` for anything wrong.
fn load(dir: &Path, p: &Pinned) -> Option<Index> {
    let path = index_path(dir, p.ino);
    let mut f = File::open(&path).ok()?;
    if f.metadata().ok()?.len() > MAX_INDEX_BYTES {
        return None;
    }
    let mut text = String::new();
    f.read_to_string(&mut text).ok()?;
    let mut lines = text.lines();
    let h: Value = serde_json::from_str(lines.next()?).ok()?;
    if h["v"] != 1 || h["dev"].as_u64()? != p.dev || h["ino"].as_u64()? != p.ino {
        return None;
    }
    let len = h["len"].as_u64()?;
    if len > p.len {
        return None; // the file got shorter: it is not the file indexed
    }
    if len > 0 {
        let mut b = [0u8; 1];
        p.file.read_exact_at(&mut b, len - 1).ok()?;
        if b[0] != b'\n' {
            return None;
        }
    }
    let mut idx = Index {
        first_wseq: h["first_wseq"].as_u64(),
        len,
        records: h["records"].as_u64()?,
        unreadable: h["unreadable"].as_u64()?,
        entries: Vec::new(),
    };
    for l in lines {
        let e: Value = serde_json::from_str(l).ok()?;
        let (w, o) = (e["wseq"].as_u64()?, e["off"].as_u64()?);
        if let Some(&(pw, po)) = idx.entries.last()
            && (w <= pw || o <= po)
        {
            return None;
        }
        if o >= len {
            return None;
        }
        idx.entries.push((w, o));
    }
    match (idx.entries.first(), idx.entries.last()) {
        (Some(&(w0, o0)), Some(&(w1, o1))) => {
            if idx.first_wseq != Some(w0) || !verify_entry(p, w0, o0) || !verify_entry(p, w1, o1) {
                return None;
            }
        }
        _ => {
            if idx.records != 0 {
                return None;
            }
        }
    }
    Some(idx)
}

/// R-1: remove temp files (`journal.idx.<ino>.tmp<pid>.<n>`) left by a reader
/// that was killed between create and rename. Only files whose writer pid no
/// longer exists are removed; the pid of a live reader (this one included) is
/// never touched.
fn remove_stale_temps(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(INDEX_PREFIX)) else {
            continue;
        };
        let Some((_, tail)) = rest.split_once(".tmp") else {
            continue;
        };
        let Some(Ok(pid)) = tail.split('.').next().map(str::parse::<u32>) else {
            continue;
        };
        if pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Atomic write (temp + rename); errors are ignored: it is only a cache.
fn store(dir: &Path, p: &Pinned, idx: &Index) {
    remove_stale_temps(dir);
    use std::sync::atomic::AtomicU32;
    static N: AtomicU32 = AtomicU32::new(0);
    let tmp = dir.join(format!(
        "{INDEX_PREFIX}{}.tmp{}.{}",
        p.ino,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(idx.to_text(p).as_bytes())?;
        fs::rename(&tmp, index_path(dir, p.ino))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
}

/// The index of `p`, loaded (unless `fresh`) and extended to the pinned
/// length, and written back when it changed in a way worth a write: it is new,
/// it gained an entry, or `always_write` (for `--info`, which wants an exact
/// count). `None` when the file cannot be read.
fn ensure(dir: &Path, p: &Pinned, fresh: bool, always_write: bool) -> Option<Index> {
    let loaded = if fresh { None } else { load(dir, p) };
    let is_new = loaded.is_none();
    let mut idx = loaded.unwrap_or_else(Index::empty);
    let (before_len, before_entries) = (idx.len, idx.entries.len());
    if !idx.extend(p) {
        return None;
    }
    if is_new || idx.entries.len() != before_entries || (always_write && idx.len != before_len) {
        store(dir, p, &idx);
    }
    Some(idx)
}

/// Offset in `p` to start reading for a cursor at `target = after + 1`: the
/// verified entry with the greatest `wseq <= target`.
fn locate(dir: &Path, p: &Pinned, target: u64) -> Option<u64> {
    for attempt in 0..2 {
        let idx = ensure(dir, p, attempt > 0, false)?;
        let &(w, o) = idx.entries.iter().rev().find(|e| e.0 <= target)?;
        if verify_entry(p, w, o) {
            return Some(o);
        }
        // Inconsistent: drop it and rebuild once from the file.
        let _ = fs::remove_file(index_path(dir, p.ino));
    }
    None
}

/// The first parseable record's `wseq` in the head window of `p`.
fn head_first_wseq(p: &Pinned) -> Option<u64> {
    let want = p.len.min(TAIL_BYTES) as usize;
    let mut buf = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match p.file.read_at(&mut buf[got..], got as u64) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    buf.truncate(got);
    buf.split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .find_map(|l| serde_json::from_slice::<JournalRecord>(l).ok())
        .map(|r| r.wseq)
}

/// Remove the indexes whose inode is no longer a live journal file.
fn cleanup_orphans(dir: &Path, pins: &[Pinned]) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(INDEX_PREFIX)) else {
            continue;
        };
        if let Ok(ino) = rest.parse::<u64>()
            && !pins.iter().any(|p| p.ino == ino)
        {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// What a forward read produced.
pub(super) struct Forward {
    pub records: Vec<JournalRecord>,
    /// Unreadable lines met (explained or not).
    pub skipped: usize,
    /// Lines handed to the parser, for the bounded-work test.
    pub lines: usize,
}

/// Read from `(pins[start], off)` to the end of the journal. A run of
/// unreadable lines between good records `a` and `b` explains
/// `missing = b - max(a, after) - 1` wseq values when `0 < missing <= lines`:
/// one `journal/unreadable` record per explained wseq (B8). Unreadable lines at
/// the end, an unterminated tail and a read error explain nothing.
pub(super) fn read_forward(pins: &[Pinned], start: usize, off: u64, after: u64) -> Forward {
    struct Bad {
        file: String,
        off: u64,
    }
    let mut out = Forward {
        records: Vec::new(),
        skipped: 0,
        lines: 0,
    };
    let mut last_good: Option<u64> = None;
    let mut pending: Vec<Bad> = Vec::new();
    for (i, p) in pins.iter().enumerate().skip(start) {
        let from = if i == start { off } else { 0 };
        scan(&p.file, from, p.len, |ev| {
            out.lines += 1;
            match ev.kind {
                Line::Err => {
                    out.skipped += 1;
                    pending.clear();
                    false
                }
                Line::Bad => {
                    out.skipped += 1;
                    if ev.terminated {
                        pending.push(Bad {
                            file: p.name.clone(),
                            off: ev.off,
                        });
                    }
                    true
                }
                Line::Good(rec) => {
                    let anchor = last_good.map_or(after, |a| a.max(after));
                    if rec.wseq > anchor.saturating_add(1) && !pending.is_empty() {
                        let missing = rec.wseq - anchor - 1;
                        if missing <= pending.len() as u64 {
                            for (k, b) in pending.iter().take(missing as usize).enumerate() {
                                let w = anchor + 1 + k as u64;
                                out.records.push(JournalRecord {
                                    v: JOURNAL_VERSION,
                                    ts: rec.ts.clone(),
                                    wseq: w,
                                    session: String::new(),
                                    kind: "journal/unreadable".to_owned(),
                                    client: None,
                                    data: json!({
                                        "file": b.file, "offset": b.off,
                                        "wseq_from": w, "wseq_to": w, "count": 1,
                                    }),
                                });
                            }
                        }
                    }
                    pending.clear();
                    last_good = Some(last_good.map_or(rec.wseq, |a| a.max(rec.wseq)));
                    out.records.push(*rec);
                    true
                }
            }
        });
    }
    out
}

/// The cursor read through the index. `None` = not applicable here (empty
/// journal, unreadable index): the caller runs the full scan.
pub(super) fn cursor_indexed(dir: &Path, after: u64) -> Option<(CursorSelect, usize, usize)> {
    let pins = pin_files(dir);
    let target = after.checked_add(1)?;
    let firsts: Vec<Option<u64>> = pins.iter().map(head_first_wseq).collect();
    let (start, off) = match firsts.iter().rposition(|f| f.is_some_and(|w| w <= target)) {
        Some(i) => (i, locate(dir, &pins[i], target)?),
        // The cursor is behind the oldest record: read it all.
        None => (firsts.iter().position(Option::is_some)?, 0),
    };
    cleanup_orphans(dir, &pins);
    let f = read_forward(&pins, start, off, after);
    Some((cursor_select(&f.records, after), f.skipped, f.lines))
}

/// The pre-index behaviour: every file from the start.
pub(super) fn cursor_full(dir: &Path, after: u64) -> (CursorSelect, usize) {
    let pins = pin_files(dir);
    let f = read_forward(&pins, 0, 0, after);
    (cursor_select(&f.records, after), f.skipped)
}

/// Unreadable lines over all journal files, from the indexes (built or
/// extended on the way). `None` when a file cannot be read.
pub(super) fn unreadable_total(dir: &Path) -> Option<u64> {
    let pins = pin_files(dir);
    let mut total = 0u64;
    for p in &pins {
        total += ensure(dir, p, false, true)?.unreadable;
    }
    cleanup_orphans(dir, &pins);
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace with `n` records, rotating at `rotate_after` bytes, and a
    /// small index interval so a few dozen records give several entries.
    fn ws(rotate_after: u64, n: usize) -> (tempfile::TempDir, PathBuf) {
        EVERY_OVERRIDE.with(|c| c.set(4));
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ws");
        create_test_ws_dir(&dir);
        let mut j = Journal::with_rotate_after(dir.clone(), "s".into(), rotate_after);
        j.retention_bytes = None;
        for i in 0..n {
            j.append("note", None, json!({"i": i, "pad": "x".repeat(40)}))
                .unwrap();
        }
        (d, dir)
    }

    fn wseqs(sel: &CursorSelect) -> Vec<u64> {
        match sel {
            CursorSelect::Records { records, .. } => records.iter().map(|r| r.wseq).collect(),
            other => panic!("not records: {other:?}"),
        }
    }

    fn unreadable_count(sel: &CursorSelect) -> usize {
        match sel {
            CursorSelect::Records { records, .. } => records
                .iter()
                .filter(|r| r.kind == "journal/unreadable")
                .count(),
            other => panic!("not records: {other:?}"),
        }
    }

    fn idx_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(INDEX_PREFIX))
            })
            .collect();
        v.sort();
        v
    }

    /// Rewrite a journal file line by line, keeping its inode (the index is
    /// keyed by it).
    fn edit_lines(path: &Path, f: impl Fn(usize, &str) -> Option<String>) {
        let text = fs::read_to_string(path).unwrap();
        let mut out = String::new();
        for (i, l) in text.lines().enumerate() {
            if let Some(n) = f(i, l) {
                out.push_str(&n);
                out.push('\n');
            }
        }
        let mut w = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        w.write_all(out.as_bytes()).unwrap();
    }

    /// The answer of the pre-index reader for the same journal.
    fn full(dir: &Path, after: u64) -> CursorSelect {
        cursor_full(dir, after).0
    }

    #[test]
    fn index_files_are_not_journal_files() {
        let (_d, dir) = ws(ROTATE_AFTER, 20);
        let _ = cursor_read(&dir, 5);
        assert!(!idx_files(&dir).is_empty(), "an index was written");
        fs::write(dir.join(format!("{INDEX_PREFIX}77.tmp1.0")), b"x").unwrap();
        for f in journal_files(&dir) {
            let n = f.file_name().unwrap().to_str().unwrap().to_owned();
            assert!(!n.starts_with(INDEX_PREFIX), "{n}");
        }
        assert_eq!(journal_files(&dir).len(), 1);
    }

    #[test]
    fn stale_index_temp_of_a_dead_reader_is_removed_on_next_write() {
        let (_d, dir) = ws(ROTATE_AFTER, 20);
        // pid 4294967294 cannot exist (above pid_max); the own pid is live.
        let dead = dir.join(format!("{INDEX_PREFIX}77.tmp4294967294.0"));
        let live = dir.join(format!("{INDEX_PREFIX}77.tmp{}.9", std::process::id()));
        fs::write(&dead, b"x").unwrap();
        fs::write(&live, b"x").unwrap();
        let _ = cursor_read(&dir, 5);
        assert!(!dead.exists(), "dead reader's temp file removed");
        assert!(live.exists(), "a live pid's temp file is left alone");
    }

    #[test]
    fn index_is_keyed_by_inode_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, dir) = ws(ROTATE_AFTER, 20);
        let _ = cursor_read(&dir, 5);
        let ino = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().ino();
        let p = index_path(&dir, ino);
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let head: Value =
            serde_json::from_str(fs::read_to_string(&p).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(head["ino"], ino);
        assert_eq!(head["first_wseq"], 1);
    }

    #[test]
    fn index_cursor_read_equals_full_scan() {
        let (_d, dir) = ws(400, 60);
        assert!(journal_files(&dir).len() >= 4);
        for after in [0u64, 1, 3, 4, 5, 17, 30, 55, 58, 59, 60] {
            let (got, _) = cursor_read(&dir, after);
            assert_eq!(got, full(&dir, after), "after={after}");
        }
        // twice: the second run goes through the stored index
        for after in [2u64, 33, 59] {
            let (got, _) = cursor_read(&dir, after);
            assert_eq!(got, full(&dir, after), "after={after} (warm)");
        }
    }

    #[test]
    fn index_survives_rotation_by_inode() {
        let (_d, dir) = ws(ROTATE_AFTER, 30);
        let _ = cursor_read(&dir, 20);
        let ino = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().ino();
        // rotate by hand: same inode, new name; a new current file follows
        fs::rename(dir.join(JOURNAL_FILE), dir.join("journal.1.jsonl")).unwrap();
        fs::write(dir.join(JOURNAL_FILE), b"").unwrap();
        let (got, _) = cursor_read(&dir, 20);
        assert_eq!(wseqs(&got), (21..=30).collect::<Vec<u64>>());
        assert!(
            index_path(&dir, ino).exists(),
            "the old index is still the file's"
        );
        let before = fs::read_to_string(index_path(&dir, ino)).unwrap();
        let _ = cursor_read(&dir, 25);
        assert_eq!(fs::read_to_string(index_path(&dir, ino)).unwrap(), before);
    }

    #[test]
    fn index_extends_when_the_journal_grows() {
        let (_d, dir) = ws(ROTATE_AFTER, 12);
        let _ = cursor_read(&dir, 6);
        let mut j = Journal::with_rotate_after(dir.clone(), "s".into(), ROTATE_AFTER);
        j.retention_bytes = None;
        for i in 0..20 {
            j.append("note", None, json!({"i": i})).unwrap();
        }
        let (got, _) = cursor_read(&dir, 28);
        assert_eq!(wseqs(&got), vec![29, 30, 31, 32]);
        let ino = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().ino();
        let t = fs::read_to_string(index_path(&dir, ino)).unwrap();
        assert!(t.lines().count() > 3, "gained entries: {t}");
    }

    /// Run cursor reads after `damage` on the indexes and compare them to the
    /// full scan.
    fn damaged(damage: impl Fn(&Path)) {
        let (_d, dir) = ws(300, 50);
        for a in [0u64, 20] {
            let _ = cursor_read(&dir, a);
        }
        let idx = idx_files(&dir);
        assert!(!idx.is_empty());
        for p in &idx {
            damage(p);
        }
        for after in [0u64, 7, 24, 49] {
            let (got, _) = cursor_read(&dir, after);
            assert_eq!(got, full(&dir, after), "after={after}");
        }
    }

    #[test]
    fn index_garbage_gives_correct_answer() {
        damaged(|p| fs::write(p, b"\xff\x00not json at all\n{{{").unwrap());
        // valid JSON lines, wrong content
        damaged(|p| {
            let t = fs::read_to_string(p).unwrap();
            let mut l: Vec<String> = t.lines().map(str::to_owned).collect();
            for x in l.iter_mut().skip(1) {
                *x = json!({"wseq": 1, "off": 3}).to_string();
            }
            fs::write(p, l.join("\n") + "\n").unwrap();
        });
    }

    #[test]
    fn index_truncated_gives_correct_answer() {
        damaged(|p| {
            let t = fs::read(p).unwrap();
            fs::write(p, &t[..t.len() / 2]).unwrap();
        });
        damaged(|p| fs::write(p, b"").unwrap());
    }

    #[test]
    fn index_deleted_gives_correct_answer() {
        damaged(|p| fs::remove_file(p).unwrap());
    }

    #[test]
    fn index_lying_offsets_give_correct_answer() {
        // every offset shifted by one byte: the line at the offset does not
        // start a record
        damaged(|p| {
            let t = fs::read_to_string(p).unwrap();
            let mut l = t.lines();
            let mut out = l.next().unwrap().to_owned() + "\n";
            for x in l {
                let mut v: Value = serde_json::from_str(x).unwrap();
                v["off"] = json!(v["off"].as_u64().unwrap() + 1);
                out.push_str(&(v.to_string() + "\n"));
            }
            fs::write(p, out).unwrap();
        });
        // a header claiming a longer file than it is
        damaged(|p| {
            let t = fs::read_to_string(p).unwrap();
            let mut l = t.lines();
            let mut h: Value = serde_json::from_str(l.next().unwrap()).unwrap();
            h["len"] = json!(h["len"].as_u64().unwrap() + 100_000);
            let rest: Vec<&str> = l.collect();
            fs::write(p, h.to_string() + "\n" + &rest.join("\n") + "\n").unwrap();
        });
    }

    #[test]
    fn index_of_another_inode_is_ignored() {
        let (_d, dir) = ws(ROTATE_AFTER, 30);
        let _ = cursor_read(&dir, 10);
        let ino = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().ino();
        // a second, different journal: its index copied under this inode's name
        let (_d2, dir2) = ws(ROTATE_AFTER, 8);
        let _ = cursor_read(&dir2, 3);
        let ino2 = fs::metadata(dir2.join(JOURNAL_FILE)).unwrap().ino();
        fs::copy(index_path(&dir2, ino2), index_path(&dir, ino)).unwrap();
        let (got, _) = cursor_read(&dir, 10);
        assert_eq!(got, full(&dir, 10));
        assert_eq!(wseqs(&got), (11..=30).collect::<Vec<u64>>());
    }

    #[test]
    fn index_orphan_removed_with_its_file() {
        let (_d, dir) = ws(ROTATE_AFTER, 10);
        let _ = cursor_read(&dir, 3);
        let ino = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().ino();
        let stale = index_path(&dir, ino + 1_000_000);
        fs::write(&stale, b"{}").unwrap();
        let _ = cursor_read(&dir, 3);
        assert!(!stale.exists(), "orphan removed");
        assert!(index_path(&dir, ino).exists(), "live index kept");
    }

    #[test]
    fn index_reset_and_gap_reported_via_full_scan() {
        let (_d, dir) = ws(ROTATE_AFTER, 20);
        let _ = cursor_read(&dir, 5);
        assert_eq!(
            cursor_read(&dir, 21).0,
            CursorSelect::Reset {
                last_wseq: Some(20)
            }
        );
        // delete one line (a real gap): exit 4 material
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| {
            (i != 10).then(|| l.to_owned())
        });
        assert_eq!(
            cursor_read(&dir, 5).0,
            CursorSelect::Gap {
                expected: 11,
                got: 12
            }
        );
    }

    #[test]
    fn indexed_read_scans_a_bounded_number_of_lines() {
        let (_d, dir) = ws(ROTATE_AFTER, 400);
        let _ = cursor_read(&dir, 390); // builds the index
        let (sel, _, lines) = cursor_indexed(&dir, 390).unwrap();
        assert_eq!(wseqs(&sel), (391..=400).collect::<Vec<u64>>());
        // entries every 4 records: at most 4 + 10 lines, nowhere near 400
        assert!(lines <= 4 + 10 + 1, "scanned {lines} lines");
    }

    // ---- B2: unreadable lines ----

    #[test]
    fn unreadable_line_in_the_middle_is_one_record() {
        let (_d, dir) = ws(ROTATE_AFTER, 12);
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| {
            Some(if i == 5 {
                "this is not json".into()
            } else {
                l.to_owned()
            })
        });
        for warm in [false, true] {
            let (sel, skipped) = cursor_read(&dir, 2);
            assert_eq!(wseqs(&sel), (3..=12).collect::<Vec<u64>>(), "warm={warm}");
            assert!(skipped >= 1);
            let CursorSelect::Records { records, .. } = &sel else {
                panic!()
            };
            let u = &records[3]; // wseq 6
            assert_eq!(u.kind, "journal/unreadable");
            assert_eq!(u.wseq, 6);
            assert_eq!(u.data["wseq_from"], 6);
            assert_eq!(u.data["wseq_to"], 6);
            assert_eq!(u.data["file"], JOURNAL_FILE);
            assert!(u.data["offset"].as_u64().unwrap() > 0);
            assert_eq!(u.session, "");
            assert_eq!(unreadable_count(&sel), 1);
        }
    }

    #[test]
    fn unreadable_record_shape() {
        let (_d, dir) = ws(ROTATE_AFTER, 6);
        let path = dir.join(JOURNAL_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let off: usize = text.lines().take(2).map(|l| l.len() + 1).sum();
        edit_lines(&path, |i, l| {
            Some(if i == 2 {
                "{broken".into()
            } else {
                l.to_owned()
            })
        });
        let (sel, _) = cursor_read(&dir, 0);
        let CursorSelect::Records { records, .. } = sel else {
            panic!()
        };
        let u = records
            .iter()
            .find(|r| r.kind == "journal/unreadable")
            .unwrap();
        assert_eq!(u.data["offset"], off as u64, "byte offset of the bad line");
        assert_eq!(u.data["count"], 1);
        assert_eq!(u.v, JOURNAL_VERSION);
        assert!(!u.ts.is_empty());
        let line = serde_json::to_string(u).unwrap();
        assert!(serde_json::from_str::<JournalRecord>(&line).is_ok());
    }

    #[test]
    fn unreadable_line_at_the_end_is_counted_not_emitted() {
        let (_d, dir) = ws(ROTATE_AFTER, 6);
        let path = dir.join(JOURNAL_FILE);
        edit_lines(&path, |i, l| {
            Some(if i == 5 {
                "garbage".into()
            } else {
                l.to_owned()
            })
        });
        let (sel, skipped) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel), vec![1, 2, 3, 4, 5]);
        assert_eq!(skipped, 1);
        // the cursor at 5 is at the head: nothing after it, no error
        assert_eq!(wseqs(&cursor_read(&dir, 5).0), Vec::<u64>::new());
    }

    #[test]
    fn unreadable_line_across_a_rotation_boundary() {
        let (_d, dir) = ws(300, 30);
        let files = journal_files(&dir);
        assert!(files.len() >= 3, "{files:?}");
        // last line of the first rotated file is corrupt
        let first = &files[0];
        let n = fs::read_to_string(first).unwrap().lines().count();
        edit_lines(first, |i, l| {
            Some(if i == n - 1 {
                "###".into()
            } else {
                l.to_owned()
            })
        });
        let (sel, _) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel), (1..=30).collect::<Vec<u64>>());
        assert_eq!(unreadable_count(&sel), 1);
        // a cursor in the middle of the second file
        let (sel2, _) = cursor_read(&dir, n as u64 + 2);
        assert_eq!(wseqs(&sel2), ((n as u64 + 3)..=30).collect::<Vec<u64>>());
        // the first line of the second file corrupt instead
        let (_d, dir) = ws(300, 30);
        let files = journal_files(&dir);
        edit_lines(&files[1], |i, l| {
            Some(if i == 0 { "###".into() } else { l.to_owned() })
        });
        let (sel3, _) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel3), (1..=30).collect::<Vec<u64>>());
        assert_eq!(unreadable_count(&sel3), 1);
    }

    #[test]
    fn unreadable_real_gap_without_corrupt_line_is_still_a_gap() {
        let (_d, dir) = ws(ROTATE_AFTER, 12);
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| {
            (i != 5).then(|| l.to_owned())
        });
        assert_eq!(
            cursor_read(&dir, 0).0,
            CursorSelect::Gap {
                expected: 6,
                got: 7
            }
        );
    }

    #[test]
    fn unreadable_two_adjacent_lines() {
        let (_d, dir) = ws(ROTATE_AFTER, 12);
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| {
            Some(if i == 4 || i == 5 {
                "x".into()
            } else {
                l.to_owned()
            })
        });
        let (sel, _) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel), (1..=12).collect::<Vec<u64>>());
        assert_eq!(unreadable_count(&sel), 2);
    }

    #[test]
    fn gap_larger_than_unreadable_count_is_a_gap() {
        // two records gone, one corrupt line left in their place
        let (_d, dir) = ws(ROTATE_AFTER, 12);
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| match i {
            4 => Some("x".into()),
            5 => None,
            _ => Some(l.to_owned()),
        });
        assert_eq!(
            cursor_read(&dir, 0).0,
            CursorSelect::Gap {
                expected: 5,
                got: 7
            }
        );
    }

    #[test]
    fn unreadable_line_without_missing_wseq_is_counted_only() {
        // an extra garbage line between two consecutive records
        let (_d, dir) = ws(ROTATE_AFTER, 6);
        edit_lines(&dir.join(JOURNAL_FILE), |i, l| {
            Some(if i == 2 {
                format!("{l}\nnot json")
            } else {
                l.to_owned()
            })
        });
        let (sel, skipped) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel), (1..=6).collect::<Vec<u64>>());
        assert_eq!(skipped, 1);
        assert_eq!(unreadable_count(&sel), 0);
    }

    #[test]
    fn unreadable_overlong_line_is_explained() {
        let (_d, dir) = ws(ROTATE_AFTER, 6);
        let path = dir.join(JOURNAL_FILE);
        let big = "a".repeat(MAX_RECORD_BYTES + 10);
        edit_lines(&path, |i, l| {
            Some(if i == 2 { big.clone() } else { l.to_owned() })
        });
        let (sel, _) = cursor_read(&dir, 0);
        assert_eq!(wseqs(&sel), (1..=6).collect::<Vec<u64>>());
        let CursorSelect::Records { records, .. } = &sel else {
            panic!()
        };
        assert_eq!(records[2].kind, "journal/unreadable");
        assert_eq!(records[3].kind, "note");
    }

    #[test]
    fn journal_info_counts_unreadable_lines() {
        let (_d, dir) = ws(300, 30);
        let files = journal_files(&dir);
        edit_lines(&files[0], |i, l| {
            Some(if i == 1 { "bad".into() } else { l.to_owned() })
        });
        edit_lines(&files[2], |i, l| {
            Some(if i == 0 { "bad".into() } else { l.to_owned() })
        });
        let info = journal_info_with_unreadable(&dir);
        assert_eq!(info.unreadable, Some(2));
        assert_eq!(info.first_wseq, journal_info(&dir).first_wseq);
        // a second run reads the stored indexes and agrees
        assert_eq!(journal_info_with_unreadable(&dir).unreadable, Some(2));
        assert_eq!(
            journal_info(&dir).unreadable,
            None,
            "the cheap form scans nothing"
        );
    }
}

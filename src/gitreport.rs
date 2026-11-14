//! The git-change report (0.5.0, PLAN-0.5 Step 1, Part C). Report only.
//!
//! At session start, if the working directory contains a `.git` *directory*,
//! hisn snapshots: for each file under `.git/hooks`, its name, size, mode and
//! SHA-256; and the SHA-256 plus parsed keys of `.git/config`. At session
//! stop it snapshots again and journals one `git-change` record: hooks
//! added, removed or modified, and config keys added, removed or changed.
//! Config keys that can make git run programs are flagged (see
//! [`DANGEROUS_KEYS`]).
//!
//! Reading is bounded and symlink-safe: it reads plain files only, bounded in
//! size and count, without following symlinks out of `.git`, and without
//! invoking git. If `.git` is a file (a linked worktree / submodule) or is
//! missing, one record says the report was skipped and why.
//!
//! A supervisor that dies mid-session leaves **no stop snapshot**: the
//! stop-time diff is written only on the orderly stop path, and the next
//! session in the workspace simply takes a fresh start snapshot as its new
//! baseline, so the death window is invisible in `git-change` diffs. This
//! is documented rather than fixed because closing it needs new machinery
//! (persisting the last snapshots across sessions), which is out of scope.
//! (Hook *path* lengths are bounded by the OS `NAME_MAX`; no additional
//! limit is needed.)
//!
//! Nothing is blocked, reverted or made read-only. No profile key is required
//! to get the report. Enforcement (Part C of PLAN-0.5 is reporting only by
//! design) is not part of this release.

use std::collections::BTreeMap;
use std::fs;
use std::os::raw::c_char;
use std::os::unix::io::FromRawFd;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Max bytes read from a single file (hooks / config). Larger files are
/// recorded by size but their content is not read (or hashed beyond the
/// prefix) — a hostile repo cannot make the report do unbounded work.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Max files enumerated in `.git/hooks`.
pub const MAX_HOOK_FILES: usize = 256;

/// Config keys that can make git run a program. When such a key is added,
/// removed or changed during a session, the `git-change` record flags it.
/// The list is from the git documentation (`git-config(1)`, `gitattributes`
/// `textconv`); each name is taken verbatim so a reader can check it
/// against that source. All entries are **lowercase**: matching is
/// case-insensitive because git's section and key names are (`is_dangerous_key`
/// lowercases the key before comparing — a mixed-case entry here could
/// never match, which is how `include.path` was silently unflagged).
///
/// Sources: https://git-scm.com/docs/git-config — keys:
///   core.hooksPath, core.fsmonitor, core.sshCommand, core.pager,
///   core.editor, sequence.editor, alias.*, filter.* (driver), diff.*.textconv,
///   diff.external, merge.*.driver, credential.helper, gpg.program,
///   include.path, includeIf.*, url.*.insteadOf, core.askPass, core.gitProxy,
///   difftool.*.cmd, mergetool.*.cmd.
pub const DANGEROUS_KEYS: &[&str] = &[
    "core.hookspath",
    "core.fsmonitor",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "sequence.editor",
    "alias",
    "filter",
    "diff.textconv",
    "diff.external",
    "merge.driver",
    "credential.helper",
    "gpg.program",
    "include.path",
    "includeif",
    "url.insteadof",
    "difftool",
    "mergetool",
    "pager",
    "browser",
    "man",
];

/// Is `key` (a `section.subsection.key` or `section.key`) a dangerous key?
/// Matching follows git's own key parsing: section and key are case-insensitive
/// (so `CORE.HOOKSPATH`, `IncludeIf.gitdir` and `ALIAS.st` all match),
/// the subsection (for `alias.*`, `filter.*`, `diff.*.textconv`, …) is not
/// needed for the flag — any key under a dangerous section counts.
pub fn is_dangerous_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let section = parts[0];
    let last = parts[parts.len() - 1];
    // Exact keys, case-insensitive (git's own rule). This covers
    // `include.path`, which no section-wide or leaf rule catches.
    let full = lower.as_str();
    if DANGEROUS_KEYS.contains(&full) {
        return true;
    }
    // Two-part exact keys, case-insensitive.
    let two = format!("{section}.{last}");
    if DANGEROUS_KEYS.contains(&two.as_str()) {
        return true;
    }
    // Section-wide dangerous families: alias.*, filter.*, includeIf.*, url.*
    // (insteadOf), difftool.*, mergetool.* — any key under those.
    if matches!(
        section,
        "alias"
            | "filter"
            | "includeif"
            | "url"
            | "difftool"
            | "mergetool"
            | "pager"
            | "browser"
            | "man"
    ) {
        return true;
    }
    // Composite (section, leaf) rules for keys that run commands under
    // otherwise-safe sections (R2, checked against git-config(1)):
    // diff.<d>.command, remote.<n>.uploadpack/receivepack,
    // interactive.diffFilter, core.alternateRefsCommand,
    // submodule.<n>.update (!cmd), man.<tool>.cmd is covered by section.
    if matches!(
        (section, last),
        ("diff", "command")
            | ("remote", "uploadpack")
            | ("remote", "receivepack")
            | ("interactive", "difffilter")
            | ("core", "alternaterefscommand")
            | ("submodule", "update")
    ) {
        return true;
    }
    // Dangerous leaf keys under a safe section.
    matches!(
        last,
        "hookspath"
            | "fsmonitor"
            | "sshcommand"
            | "pager"
            | "editor"
            | "askpass"
            | "gitproxy"
            | "alternaterefscommand"
            | "difffilter"
            | "textconv"
            | "external"
            | "driver"
            | "helper"
            | "program"
    )
}

/// Per-hook snapshot entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookEntry {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub sha256: Option<String>,
}

/// A git snapshot. `skipped` is `Some(reason)` when no snapshot could be
/// taken (`.git` missing / a file / unreadable); otherwise the hooks and the
/// config keys are the observed state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(default)]
    pub hooks: Vec<HookEntry>,
    /// Config keys to values, in file order. A key may be multi-valued in
    /// git (`include.path`, `url.*.insteadOf`, `credential.helper`): all
    /// values are kept, so adding a second one is detected as a change
    /// instead of collapsing into the last (R1).
    #[serde(default)]
    pub config: BTreeMap<String, Vec<String>>,
    /// Set when the enumeration hit a bound (too many hook files) or a file
    /// was too large to hash fully — an empty map with this flag is "some
    /// data was not read", not "nothing there". Always serialized: the
    /// whole point of the flag is that the record carries it (a
    /// `skip_serializing_if = "is_true"` would drop the marker exactly
    /// when it is set).
    #[serde(default)]
    pub truncated: bool,
}

/// Snapshot `<cwd>/.git`. Returns the snapshot; never errors (an unreadable
/// repo yields a `skipped` snapshot, so the journal can record why).
///
/// The `.git` directory is pinned by an opened dir fd (`O_NOFOLLOW |
/// O_DIRECTORY`) and everything inside it (`hooks`, `config`, individual
/// hook files) is opened relative to that fd with `openat`, so swapping
/// `.git` or `.git/hooks` for a symlink mid-snapshot cannot redirect the
/// read to an arbitrary host path (R1 TOCTOU fix). If the pin fails, the
/// snapshot is `skipped` with the reason.
pub fn snapshot(cwd: &Path) -> Snapshot {
    let git = cwd.join(".git");
    let md = match fs::symlink_metadata(&git) {
        Ok(m) => m,
        Err(_) => {
            return Snapshot {
                skipped: Some("no .git".into()),
                ..Default::default()
            };
        }
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        // `.git` is a file (linked worktree / submodule) or a symlink: the
        // real git dir lives elsewhere; we do not follow it out of `.git`.
        return Snapshot {
            skipped: Some(".git is a file (worktree/submodule), not followed".into()),
            ..Default::default()
        };
    }
    // Pin `.git` by fd. A failure here is not "no data": skip with a reason.
    let git_fd = match open_git_dir(&git) {
        Some(fd) => fd,
        None => {
            return Snapshot {
                skipped: Some(".git could not be pinned".into()),
                ..Default::default()
            };
        }
    };
    let (hooks, hooks_truncated) = snapshot_hooks(git_fd, &git.join("hooks"));
    let (config, config_truncated) = snapshot_config(git_fd, &git.join("config"));
    close_fd(git_fd);
    Snapshot {
        skipped: None,
        hooks,
        config,
        truncated: hooks_truncated || config_truncated,
    }
}

/// Max hook names collected from a hooks dir before giving up enumeration.
/// Bounds the memory of a hostile directory with millions of entries;
/// the kept subset (first 256, sorted) is still deterministic.
const MAX_HOOK_NAMES: usize = 10_000;

/// Open `<git>` as a pinned directory fd: `O_NOFOLLOW | O_DIRECTORY`, so a
/// symlink or non-dir is refused. The fd is a raw descriptor (closed by the
/// caller via `close_fd`).
fn open_git_dir(git: &Path) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(git.as_os_str().as_bytes()).ok()?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    (fd >= 0).then_some(fd)
}

fn close_fd(fd: i32) {
    unsafe { libc::close(fd) };
}

/// A stat result for a hook entry (the fields the report needs).
struct EntryStat {
    is_symlink: bool,
    is_file: bool,
    size: u64,
    mode: u32,
}

/// Stat `name` relative to a pinned dir fd, without following symlinks
/// (`fstatat` with `AT_SYMLINK_NOFOLLOW` — the `symlink_metadata`
/// equivalent for an fd-relative name).
fn fstatat(dir_fd: i32, name: &str) -> Option<EntryStat> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(std::ffi::OsStr::new(name).as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir_fd,
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
        )
    };
    if rc != 0 {
        return None;
    }
    let m = st.st_mode as u32;
    Some(EntryStat {
        is_symlink: (m & libc::S_IFMT) == libc::S_IFLNK,
        is_file: (m & libc::S_IFMT) == libc::S_IFREG,
        size: st.st_size as u64,
        mode: m & 0o7777,
    })
}

/// Read the link target of `name` relative to a pinned dir fd (`readlinkat`,
/// bounded at 4 KiB — a longer target reads as truncation, never followed).
fn readlinkat(dir_fd: i32, name: &str) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(std::ffi::OsStr::new(name).as_bytes()).ok()?;
    let mut buf = [0u8; 4096];
    let n = unsafe {
        libc::readlinkat(
            dir_fd,
            c.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// Open `name` relative to a pinned dir fd, refusing symlinks
/// (`O_NOFOLLOW`) and non-directories when `is_dir`. Returns the raw fd.
fn openat(dir_fd: i32, name: &str, is_dir: bool) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(std::ffi::OsStr::new(name).as_bytes()).ok()?;
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if is_dir {
        flags |= libc::O_DIRECTORY;
    } else {
        flags |= libc::O_NONBLOCK;
    }
    let fd = unsafe { libc::openat(dir_fd, c.as_ptr(), flags) };
    (fd >= 0).then_some(fd)
}

fn snapshot_hooks(git_fd: i32, dir: &Path) -> (Vec<HookEntry>, bool) {
    let mut out = Vec::new();
    // No hooks dir: empty (not truncation — there is nothing to read).
    // A hooks dir that exists but cannot be opened (or is a symlink /
    // non-dir, refused by O_NOFOLLOW|O_DIRECTORY on the pinned fd) is
    // truncation: hooks data was not read.
    let hooks_fd = match openat(git_fd, "hooks", true) {
        Some(fd) => fd,
        None => {
            if !dir.exists() {
                return (out, false);
            }
            return (out, true);
        }
    };
    // List names through the pinned fd (`/proc/self/fd/<fd>` is the
    // standard way to read_dir a borrowed fd).
    let Ok(rd) = fs::read_dir(Path::new(&format!("/proc/self/fd/{hooks_fd}"))) else {
        close_fd(hooks_fd);
        return (out, true);
    };
    // Sort names *before* taking the first MAX_HOOK_FILES, so the kept
    // subset is deterministic (read_dir order is arbitrary — item 6).
    // Collection is capped at MAX_HOOK_NAMES so a huge directory is
    // bounded in memory (and flagged truncated).
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    let mut truncated = false;
    for e in rd.flatten() {
        if names.len() >= MAX_HOOK_NAMES {
            truncated = true;
            break;
        }
        names.push(e.file_name());
    }
    names.sort();
    if names.len() > MAX_HOOK_FILES {
        names.truncate(MAX_HOOK_FILES);
        truncated = true;
    }
    for name_os in names {
        let name = name_os.to_string_lossy().into_owned();
        // Stat the entry relative to the pinned hooks fd (fstatat, never
        // by path — R2: the hooks dir itself was pinned, so its members
        // must be reached the same way).
        let Some(md) = fstatat(hooks_fd, &name_os.to_string_lossy()) else {
            continue;
        };
        if md.is_symlink {
            // Record the link target (readlinkat on the pinned fd, bounded,
            // never followed) — a bare `sha256: None` made a same-length
            // retarget invisible in the diff (R1). Hash the target string.
            let target = readlinkat(hooks_fd, &name_os.to_string_lossy()).unwrap_or_default();
            let mut h = Sha256::new();
            h.update(target.as_bytes());
            out.push(HookEntry {
                name,
                size: md.size,
                mode: md.mode,
                sha256: Some(format!("{:x}", h.finalize())),
            });
            continue;
        }
        if !md.is_file {
            continue; // directories and specials are not hooks
        }
        let sha = hash_file(hooks_fd, &name_os.to_string_lossy(), md.size);
        let oversized = sha.is_none();
        out.push(HookEntry {
            name,
            size: md.size,
            mode: md.mode,
            sha256: sha,
        });
        if oversized {
            truncated = true;
        }
    }
    close_fd(hooks_fd);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, truncated)
}

/// SHA-256 of a plain file, bounded, opened relative to a pinned dir fd.
/// A file larger than [`MAX_FILE_BYTES`] is not read in full (returns
/// `None`, size still recorded). The file is opened with `O_NOFOLLOW |
/// O_NONBLOCK` so a FIFO or a swapped-in symlink cannot hang or redirect
/// the read, and its type is verified on the opened fd (a FIFO swapped in
/// after the lstat would otherwise read as empty and hash as garbage).
/// The read itself is capped at `MAX_FILE_BYTES + 1` so a file that grows
/// between the lstat and the read cannot exceed the bound (item 6) — an
/// over-read returns `None` like an oversized file.
fn hash_file(dir_fd: i32, name: &str, size: u64) -> Option<String> {
    if size > MAX_FILE_BYTES {
        return None;
    }
    use std::io::Read;
    let fd = openat(dir_fd, name, false)?;
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    f.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(format!("{:x}", h.finalize()))
}

/// Parse `.git/config` into a flat `section.subsection.key = value` map, plus
/// a truncation flag. The file is opened `O_NOFOLLOW` and read with a byte
/// cap, so a symlink, a FIFO or a huge file cannot redirect or OOM the
/// report. A deliberately small parser: it understands the git syntax that
/// matters for change detection — `[section]`, `[section "subsection"]`
/// (with `\"`/`\\` escapes), legacy `[a.b]`, `key = value`, bare keys,
/// `;`/`#` comments (full-line and inline), quoted values with escapes, and
/// backslash line continuations. Section and key names are case-insensitive;
/// subsection names are case-sensitive (git's rule). It does not invoke git
/// and does not need to be a full git-config implementation — it only needs
/// the keys git would act on, and it must never panic on arbitrary bytes.
/// Values are journaled verbatim (the journal is the user's own state home).
fn snapshot_config(git_fd: i32, path: &Path) -> (BTreeMap<String, Vec<String>>, bool) {
    use std::io::Read;
    let mut out = BTreeMap::new();
    // A missing config is not truncation (no data there), but a config that
    // exists and cannot be read (symlink, unreadable, not a file) is: empty
    // with truncated=false would be indistinguishable from "no config".
    // `symlink_metadata` (not `exists()`) decides — a dangling config
    // symlink is "present but unreadable", i.e. truncation (R1).
    let present = fs::symlink_metadata(path).is_ok();
    let Some(fd) = openat(git_fd, "config", false) else {
        return (out, present);
    };
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let Ok(md) = f.metadata() else {
        return (out, true);
    };
    if !md.is_file() {
        return (out, true);
    }
    // Read the file through the O_NOFOLLOW handle, capped at
    // MAX_FILE_BYTES + 1 so an oversize (or hostile) file cannot OOM the
    // report; the cap is a flag, not silence.
    let mut buf = Vec::new();
    let _ = f.by_ref().take(MAX_FILE_BYTES + 1).read_to_end(&mut buf);
    let truncated = buf.len() as u64 > MAX_FILE_BYTES;
    if truncated {
        buf.truncate(MAX_FILE_BYTES as usize);
    }
    // `from_utf8_lossy` always yields a valid String (a byte cap that split
    // a multibyte character becomes U+FFFD), so no slicing panic is
    // possible; the truncated tail is still a flag, not silence.
    let text = String::from_utf8_lossy(&buf).into_owned();
    parse_git_config(&text, &mut out);
    (out, truncated)
}

/// Join continuation lines: a line ending in an odd number of backslashes
/// is joined with the next (git's rule, both inside and outside values),
/// EXCEPT that a comment line (`;`/`#`, after trimming) is never continued:
/// verified with git 2.39.5 — `# x\` followed by `hooksPath = /evil` gives
/// `core.hookspath=/evil`, so the comment does not continue (joining it
/// would hide the key). A value line continued with a `;` line DOES join
/// (verified: `foo = a\` + `; comment` + `b` → `foo=a`, bare `b`).
fn join_continuations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        // A standalone comment line never continues (verified with git);
        // an accumulated line that IS a comment therefore never joins.
        let prev_is_comment = out
            .last()
            .is_some_and(|l: &String| l.trim_start().starts_with([';', '#']));
        if let Some(last) = out.last_mut()
            && !prev_is_comment
            && trailing_backslashes(last) % 2 == 1
        {
            last.pop();
            last.push_str(line);
        } else {
            out.push(line.to_owned());
        }
    }
    out
}

fn trailing_backslashes(s: &str) -> usize {
    s.bytes().rev().take_while(|b| *b == b'\\').count()
}

/// Parse the git-config text into `out`. Never panics on arbitrary bytes:
/// every slice is taken on char boundaries derived from safe splits.
/// Multi-valued keys append (git keeps every value).
fn parse_git_config(text: &str, out: &mut BTreeMap<String, Vec<String>>) {
    let mut section: Option<String> = None;
    for line in join_continuations(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if line.starts_with('[') {
            // `[section] key = value` on one line is legal (verified with
            // git 2.39.5): parse the header, then treat the remainder as a
            // key line. A remainder that is a comment (`[sec] ; note`) is
            // NOT a key — without this check `parse_key_line` inserts a
            // bogus `sec.; note` key (R2).
            if let Some((sec, rest)) = parse_section_header(line) {
                section = Some(sec);
                if rest.is_empty() || rest.starts_with([';', '#']) {
                    continue;
                }
                parse_key_line(&rest, &section, out);
                continue;
            }
            // A malformed header (no closing `]`, junk) keeps the previous
            // section — git would error, but the report must not.
            continue;
        }
        parse_key_line(line, &section, out);
    }
}

fn parse_key_line(line: &str, section: &Option<String>, out: &mut BTreeMap<String, Vec<String>>) {
    if let Some(sec) = section {
        // `key = value`, `key=value`, or bare `key` (boolean true).
        // An inline comment (`;`/`#` outside quotes) ends the value.
        let (k, v) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), parse_value(v)),
            None => (line.to_ascii_lowercase(), "true".to_owned()),
        };
        if !k.is_empty() {
            out.entry(format!("{sec}.{k}")).or_default().push(v);
        }
    }
}

/// Parse a section header line: `[name]`, `[name "subsection"]` (subsection
/// may contain `\"` and `\\`), the legacy `[name.subsection]`, with an
/// optional trailing comment after `]`. Returns the flattened
/// `name.subsection` (name lowercased, subsection case-preserved) plus the
/// remainder of the line after `]` (a same-line `key = value`, or empty),
/// or `None` if the header is malformed.
fn parse_section_header(line: &str) -> Option<(String, String)> {
    let close = line.find(']')?;
    let trailing = line.get(close + 1..).unwrap_or("").trim().to_owned();
    let inner = line.get(1..close)?.trim();
    // `[name "subsection"]`
    if let Some(qpos) = inner.find('"') {
        let name = inner.get(..qpos)?.trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        let rest = inner.get(qpos..)?;
        // Read the quoted subsection, honouring backslash escapes.
        let mut sub = String::new();
        let mut chars = rest.char_indices();
        // Skip the opening quote.
        let (_, first) = chars.next()?;
        if first != '"' {
            return None;
        }
        let mut escaped = false;
        let mut closed = false;
        for (_, c) in chars.by_ref() {
            if escaped {
                sub.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                closed = true;
                break;
            } else {
                sub.push(c);
            }
        }
        if !closed {
            return None;
        }
        return Some((format!("{name}.{sub}"), trailing));
    }
    // `[name]` or legacy `[name.subsection]` (the whole name lowercased).
    let name = inner.to_ascii_lowercase();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name, trailing))
}

/// Parse a config value: process quoted segments (with `\"`, `\\`, `\n`,
/// `\t` escapes — git's set) and unquoted runs; an unquoted `;` or `#`
/// starts an inline comment; surrounding whitespace is trimmed.
fn parse_value(v: &str) -> String {
    let mut out = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in v.chars() {
        if in_quotes {
            if escaped {
                out.push(match c {
                    'n' => '\n',
                    't' => '\t',
                    c => c,
                });
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quotes = false;
            } else {
                out.push(c);
            }
        } else if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = true;
        } else if c == ';' || c == '#' {
            break; // inline comment
        } else {
            out.push(c);
        }
    }
    out.trim().to_owned()
}

/// The diff between two snapshots, as a JSON value for the journal record.
///
/// When either side is `skipped` (no snapshot could be taken), every
/// added/removed entry would be a read artifact, not a change — so the
/// change lists are empty and the status is reported instead (R1). The
/// `truncated` flags are always surfaced: a truncated side can make
/// apparent removals (or additions) that are read artifacts, and the
/// record must say so.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Value {
    let skipped = before.skipped.is_some() || after.skipped.is_some();
    let mut hooks_added = Vec::new();
    let mut hooks_removed = Vec::new();
    let mut hooks_modified = Vec::new();
    if !skipped {
        let bhooks: BTreeMap<&str, &HookEntry> =
            before.hooks.iter().map(|h| (h.name.as_str(), h)).collect();
        let ahooks: BTreeMap<&str, &HookEntry> =
            after.hooks.iter().map(|h| (h.name.as_str(), h)).collect();
        for (name, h) in &ahooks {
            match bhooks.get(name) {
                None => hooks_added.push(*name),
                Some(b) if b.sha256 != h.sha256 || b.mode != h.mode || b.size != h.size => {
                    hooks_modified.push(*name);
                }
                _ => {}
            }
        }
        for name in bhooks.keys() {
            if !ahooks.contains_key(name) {
                hooks_removed.push(*name);
            }
        }
    } // if !skipped (hooks block)

    let mut keys_added = Vec::new();
    let mut keys_removed = Vec::new();
    let mut keys_changed = Vec::new();
    let mut flagged: Vec<String> = Vec::new();
    if !skipped {
        for (k, v) in &after.config {
            match before.config.get(k) {
                None => {
                    keys_added.push(k.clone());
                    if is_dangerous_key(k) {
                        flagged.push(k.clone());
                    }
                }
                Some(bv) if bv != v => {
                    keys_changed.push(k.clone());
                    if is_dangerous_key(k) {
                        flagged.push(k.clone());
                    }
                }
                _ => {}
            }
        }
        for k in before.config.keys() {
            if !after.config.contains_key(k) {
                keys_removed.push(k.clone());
                if is_dangerous_key(k) {
                    flagged.push(k.clone());
                }
            }
        }
    }
    flagged.sort();
    json!({
        "hooks": {
            "added": hooks_added,
            "removed": hooks_removed,
            "modified": hooks_modified,
        },
        "config": {
            "added": keys_added,
            "removed": keys_removed,
            "changed": keys_changed,
        },
        "flagged": flagged,
        "truncated": {
            "before": before.truncated,
            "after": after.truncated,
        },
        "skipped": {
            "before": before.skipped,
            "after": after.skipped,
        },
    })
}

/// The `git-change` record data for a start snapshot and a stop snapshot.
pub fn change_record(before: &Snapshot, after: &Snapshot) -> Value {
    let d = diff(before, after);
    json!({
        "cwd": "",
        "before": before,
        "after": after,
        "changes": d,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn git_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        let cwd = tmp.path().join("work");
        let git = cwd.join(".git");
        fs::create_dir_all(git.join("hooks")).unwrap();
        cwd
    }

    fn write(p: &Path, b: &[u8]) {
        fs::write(p, b).unwrap();
    }

    #[test]
    fn unchanged_repo_has_no_changes() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(&cwd.join(".git/hooks/pre-commit"), b"#!/bin/sh\nexit 0\n");
        write(
            &cwd.join(".git/config"),
            b"[core]\n\trepositoryformatversion = 0\n",
        );
        let a = snapshot(&cwd);
        let b = snapshot(&cwd);
        let diff = diff(&a, &b);
        assert!(diff["hooks"]["added"].as_array().unwrap().is_empty());
        assert!(diff["config"]["added"].as_array().unwrap().is_empty());
        assert!(diff["flagged"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_new_hook_and_a_changed_dangerous_key_are_flagged() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[core]\n\thooksPath = /safe/hooks\n",
        );
        let before = snapshot(&cwd);
        write(&cwd.join(".git/hooks/pre-commit"), b"#!/bin/sh\necho hi\n");
        write(
            &cwd.join(".git/config"),
            b"[core]\n\thooksPath = /evil/hooks\n",
        );
        let after = snapshot(&cwd);
        let diff = diff(&before, &after);
        assert_eq!(diff["hooks"]["added"], json!(["pre-commit"]));
        assert_eq!(diff["config"]["changed"], json!(["core.hookspath"]));
        assert_eq!(diff["flagged"], json!(["core.hookspath"]));
    }

    #[test]
    fn a_git_file_skips_the_report() {
        let d = tempfile::tempdir().unwrap();
        let cwd = d.path().join("work");
        fs::create_dir_all(&cwd).unwrap();
        write(&cwd.join(".git"), b"gitdir: /elsewhere/.git\n");
        let s = snapshot(&cwd);
        assert!(s.skipped.is_some());
        assert!(s.skipped.unwrap().contains("worktree"));
    }

    #[test]
    fn a_missing_git_dir_skips_the_report() {
        let d = tempfile::tempdir().unwrap();
        let cwd = d.path().join("work");
        fs::create_dir_all(&cwd).unwrap();
        let s = snapshot(&cwd);
        assert_eq!(s.skipped.as_deref(), Some("no .git"));
    }

    #[test]
    fn a_symlink_in_hooks_is_recorded_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        let outside = d.path().join("outside");
        write(&outside, b"secret");
        std::os::unix::fs::symlink(&outside, cwd.join(".git/hooks/pre-commit")).unwrap();
        let s = snapshot(&cwd);
        let h = s.hooks.iter().find(|h| h.name == "pre-commit").unwrap();
        // The symlink is never read through, but its TARGET is hashed, so a
        // retarget shows in the diff (R1 fix; previously `None` made a
        // same-length retarget invisible).
        let mut hasher = Sha256::new();
        hasher.update(outside.to_string_lossy().as_bytes());
        let want = format!("{:x}", hasher.finalize());
        assert_eq!(h.sha256.as_deref(), Some(want.as_str()));
    }

    #[test]
    fn an_oversized_hook_is_sized_not_hashed() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        let big = cwd.join(".git/hooks/big");
        let mut f = fs::File::create(&big).unwrap();
        // Write MAX_FILE_BYTES + 1 without needing 64 MiB in the repo.
        let chunk = vec![b'x'; 65536];
        let mut written = 0u64;
        while written <= MAX_FILE_BYTES {
            f.write_all(&chunk).unwrap();
            written += chunk.len() as u64;
        }
        let s = snapshot(&cwd);
        let h = s.hooks.iter().find(|h| h.name == "big").unwrap();
        assert!(h.size > MAX_FILE_BYTES);
        assert_eq!(h.sha256, None);
    }

    #[test]
    fn dangerous_keys_match_the_documented_set() {
        for k in [
            "core.hooksPath",
            "core.fsmonitor",
            "core.sshCommand",
            "core.pager",
            "core.editor",
            "sequence.editor",
            "diff.external",
            "gpg.program",
            "include.path",
            "credential.helper",
            "alias.st",
            "filter.lfs.clean",
            "diff.mydriver.textconv",
            "merge.tool.driver",
            "includeIf.gitdir",
            "url.https://example.com.insteadOf",
            "core.askPass",
            "core.gitProxy",
            "difftool.mydiff.cmd",
            "mergetool.mytool.cmd",
            "pager.log",
            "browser.firefox.cmd",
            "man.man.cmd",
            "diff.mydriver.command",
            "remote.origin.uploadpack",
            "remote.origin.receivepack",
            "interactive.diffFilter",
            "core.alternateRefsCommand",
            "submodule.x.update",
        ] {
            assert!(is_dangerous_key(k), "{k} must be flagged");
        }
        for k in ["core.bare", "user.email", "init.defaultBranch"] {
            assert!(!is_dangerous_key(k), "{k} must not be flagged");
        }
    }

    #[test]
    fn dangerous_keys_match_case_insensitively_incl_wildcards() {
        // Item 6: git's section and key names are case-insensitive, so the
        // wildcard families and the exact keys must match in any case.
        for k in [
            "CORE.HOOKSPATH",
            "Core.HooksPath",
            "ALIAS.st",
            "Filter.LFS.Clean",
            "INCLUDEIF.gitdir",
            "IncludeIf.gitdir",
            "URL.x.insteadOf",
            "INCLUDE.PATH",
            "Include.Path",
            "CORE.ASKPASS",
            "DiffTool.x.Cmd",
            "MERGETOOL.x.cmd",
            "DIFF.x.TEXTCONV",
            "Sequence.Editor",
        ] {
            assert!(
                is_dangerous_key(k),
                "{k} must be flagged (case-insensitive)"
            );
        }
        for k in ["CORE.BARE", "User.Email", "INIT.DEFAULTBRANCH"] {
            assert!(!is_dangerous_key(k), "{k} must not be flagged");
        }
    }

    #[test]
    fn config_parser_handles_comments_quotes_continuation_and_case() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[CORE] ; trailing comment\n\
              HooksPath = /safe ; inline comment\n\
              key = \"quoted ; not a comment\"\n\
              cont = /ev\\\n\
              il/hooks\n\
              bare\n\
              [filter \"My Sub\"]\n\
              clean = git lfs clean # another comment\n\
              [alias]\n\
              st = status\n",
        );
        let s = snapshot(&cwd);
        assert_eq!(s.config["core.hookspath"], ["/safe"]);
        assert_eq!(s.config["core.key"], ["quoted ; not a comment"]);
        assert_eq!(s.config["core.cont"], ["/evil/hooks"]);
        assert_eq!(s.config["core.bare"], ["true"]);
        // Subsection case is preserved (git's rule); section/key lowercased.
        assert_eq!(s.config["filter.My Sub.clean"], ["git lfs clean"]);
        assert_eq!(s.config["alias.st"], ["status"]);
        assert!(is_dangerous_key("core.hookspath"));
    }

    #[test]
    fn config_parser_does_not_continue_comment_lines_and_reads_same_line_keys() {
        // Verified with git 2.39.5: a comment line ending in a backslash
        // does NOT continue (the next line is a real key), while
        // `[core] hooksPath = x` on one line IS a real key. Both were
        // dropped by the previous parser (false negatives on dangerous
        // keys).
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[core]\n# comment ending in backslash\\\nhooksPath = /evil\n[alias] st = status\n",
        );
        let s = snapshot(&cwd);
        assert_eq!(s.config["core.hookspath"], ["/evil"]);
        assert_eq!(s.config["alias.st"], ["status"]);
    }

    #[test]
    fn multi_valued_keys_are_all_detected() {
        // R1: git keys can be multi-valued; adding a second value before
        // the last must be detected as a change, not collapse.
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[include]\n\tpath = /safe\n[url \"https://x\"]\n\tinsteadOf = a\n",
        );
        let before = snapshot(&cwd);
        write(
            &cwd.join(".git/config"),
            b"[include]\n\tpath = /safe\n\tpath = /evil\n[url \"https://x\"]\n\tinsteadOf = a\n\tinsteadOf = b\n",
        );
        let after = snapshot(&cwd);
        let diff = diff(&before, &after);
        assert_eq!(
            diff["config"]["changed"],
            json!(["include.path", "url.https://x.insteadof"]),
            "adding a second value must be a change"
        );
        assert_eq!(
            diff["flagged"],
            json!(["include.path", "url.https://x.insteadof"])
        );
    }

    #[test]
    fn symlink_hook_retarget_and_dangling_config_symlink_are_visible() {
        // R1: a symlink hook retargeted at the same length must show as
        // modified (the target is hashed), and a dangling config symlink
        // must be truncation, not "no config".
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        let t1 = d.path().join("aaa-target");
        let t2 = d.path().join("bbb-target"); // same length as t1's name
        write(&t1, b"one");
        write(&t2, b"two");
        std::os::unix::fs::symlink(&t1, cwd.join(".git/hooks/pre-commit")).unwrap();
        let before = snapshot(&cwd);
        fs::remove_file(cwd.join(".git/hooks/pre-commit")).unwrap();
        std::os::unix::fs::symlink(&t2, cwd.join(".git/hooks/pre-commit")).unwrap();
        let after = snapshot(&cwd);
        let diff = diff(&before, &after);
        assert_eq!(
            diff["hooks"]["modified"],
            json!(["pre-commit"]),
            "same-length retarget must be visible"
        );
        // Dangling config symlink.
        let cfg = cwd.join(".git/config");
        std::os::unix::fs::symlink(d.path().join("nope"), &cfg).unwrap();
        let s = snapshot(&cwd);
        assert!(s.truncated, "dangling config symlink must be truncation");
    }

    #[test]
    fn section_header_trailing_comment_is_not_a_key() {
        // R2: `[sec] ; trailing comment` must not insert a bogus key.
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[core] ; trailing comment\nbare = true\n",
        );
        let s = snapshot(&cwd);
        assert_eq!(s.config["core.bare"], ["true"]);
        assert!(
            s.config.keys().all(|k| !k.contains(';')),
            "bogus key from header comment: {:?}",
            s.config.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn diff_surfaces_truncated_and_skipped_without_artifact_changes() {
        // R1: when a side is skipped, the change lists must be empty (every
        // entry would be a read artifact); truncated is always surfaced.
        let skipped = Snapshot {
            skipped: Some("no .git".into()),
            ..Default::default()
        };
        let mut real = Snapshot::default();
        real.hooks.push(HookEntry {
            name: "x".into(),
            size: 1,
            mode: 0o755,
            sha256: Some("h".into()),
        });
        let d = diff(&skipped, &real);
        assert!(d["hooks"]["added"].as_array().unwrap().is_empty());
        assert!(d["config"]["added"].as_array().unwrap().is_empty());
        assert_eq!(d["skipped"]["before"], "no .git");
        assert_eq!(d["truncated"]["before"], false);
        let trunc = Snapshot {
            truncated: true,
            ..Default::default()
        };
        let d2 = diff(&real, &trunc);
        assert_eq!(d2["truncated"]["after"], true);
    }

    #[test]
    fn config_reader_never_panics_on_arbitrary_bytes() {
        // Item 6: generated-input no-panic property. A deterministic PRNG
        // (xorshift) generates random byte strings, including multibyte
        // splits at the 1 MiB cap; snapshot_config must return, never panic.
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        let cfg = cwd.join(".git/config");
        // Pin the real .git dir so the parser actually runs.
        let git_fd = open_git_dir(&cwd.join(".git")).unwrap();
        for i in 0..200 {
            let len = (next() % 4096) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((next() % 256) as u8);
            }
            // Sprinkle git-ish structure so the parser actually exercises
            // sections and keys.
            if i % 3 == 0 {
                bytes.extend_from_slice(b"\n[core]\nhooksPath = /x\n[alias]\n");
            }
            write(&cfg, &bytes);
            // Must return (any map), never panic.
            let (map, _) = snapshot_config(git_fd, &cfg);
            let _ = map.len();
        }
        // A multibyte character split exactly at the byte cap.
        let mut big = vec![b'a'; MAX_FILE_BYTES as usize - 1];
        big.extend_from_slice("caf\u{00e9}".as_bytes()); // 2-byte char straddling the cap
        write(&cfg, &big);
        let (map, truncated) = snapshot_config(git_fd, &cfg);
        assert!(truncated);
        let _ = map;
        close_fd(git_fd);
    }

    #[test]
    fn truncated_flag_reaches_the_record() {
        // Item 6: an oversized config (or too many hooks) sets `truncated`
        // on the snapshot, and `change_record` (which embeds before/after)
        // therefore carries the marker.
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        let big = vec![b'x'; MAX_FILE_BYTES as usize + 10];
        write(&cwd.join(".git/config"), &big);
        let s = snapshot(&cwd);
        assert!(s.truncated, "oversized config must set truncated");
        let rec = change_record(&Snapshot::default(), &s);
        assert_eq!(rec["after"]["truncated"], true);
        // A symlinked hooks dir is truncation, not "no hooks".
        let d2 = tempfile::tempdir().unwrap();
        let cwd2 = git_dir(&d2);
        let hooks = cwd2.join(".git/hooks");
        fs::remove_dir(&hooks).unwrap();
        let elsewhere = d2.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        write(&elsewhere.join("sneaky"), b"#!/bin/sh\n");
        std::os::unix::fs::symlink(&elsewhere, &hooks).unwrap();
        let s2 = snapshot(&cwd2);
        assert!(s2.truncated, "symlinked hooks dir must be truncated");
        assert!(s2.hooks.is_empty());
    }

    #[test]
    fn config_parses_section_subsection_and_keys() {
        let d = tempfile::tempdir().unwrap();
        let cwd = git_dir(&d);
        write(
            &cwd.join(".git/config"),
            b"[core]\n\tbare = true\n[alias]\n\tst = status\n[filter \"lfs\"]\n\tclean = git lfs clean\n",
        );
        let s = snapshot(&cwd);
        assert_eq!(s.config["core.bare"], ["true"]);
        assert_eq!(s.config["alias.st"], ["status"]);
        assert_eq!(s.config["filter.lfs.clean"], ["git lfs clean"]);
    }
}

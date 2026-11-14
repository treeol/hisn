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
//! Nothing is blocked, reverted or made read-only. No profile key is required
//! to get the report. Enforcement (Part C of PLAN-0.5 is reporting only by
//! design) is not part of this release.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
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
/// against that source.
///
/// Sources: https://git-scm.com/docs/git-config — keys:
///   core.hooksPath, core.fsmonitor, core.sshCommand, core.pager,
///   core.editor, sequence.editor, alias.*, filter.* (driver), diff.*.textconv,
///   diff.external, merge.*.driver, credential.helper, gpg.program,
///   include.path, includeIf.*, url.*.insteadOf.
pub const DANGEROUS_KEYS: &[&str] = &[
    "core.hooksPath",
    "core.fsmonitor",
    "core.sshCommand",
    "core.pager",
    "core.editor",
    "sequence.editor",
    "alias",
    "filter",
    "diff.textconv",
    "diff.external",
    "merge.driver",
    "credential.helper",
    "gpg.program",
    "include.path",
    "includeIf",
    "url.insteadOf",
];

/// Is `key` (a `section.subsection.key` or `section.key`) a dangerous key?
/// Matching follows git's own key parsing: section and key are case-insensitive,
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
    // Two-part exact keys, case-insensitive (git's own rule).
    let two = format!("{section}.{last}");
    if DANGEROUS_KEYS.contains(&two.as_str()) {
        return true;
    }
    // Section-wide dangerous families: alias.*, filter.*, includeIf.*, url.*
    // (insteadOf) — any key under those, and the dangerous leaf names.
    if matches!(section, "alias" | "filter" | "includeif" | "url") {
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
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    /// Set when the enumeration hit a bound (too many hook files) or a file
    /// was too large to hash fully — an empty map with this flag is "some
    /// data was not read", not "nothing there".
    #[serde(default, skip_serializing_if = "is_true")]
    pub truncated: bool,
}

fn is_true(b: &bool) -> bool {
    *b
}

/// Snapshot `<cwd>/.git`. Returns the snapshot; never errors (an unreadable
/// repo yields a `skipped` snapshot, so the journal can record why).
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
    // `hooks` itself must not be a symlink: `read_dir` follows it, so a
    // symlinked hooks dir would list an arbitrary host directory. Same for
    // `config` — it is opened with O_NOFOLLOW below.
    let (hooks, hooks_truncated) = {
        let hd = git.join("hooks");
        match fs::symlink_metadata(&hd) {
            Ok(md) if md.file_type().is_symlink() || !md.is_dir() => (Vec::new(), false),
            _ => snapshot_hooks(&hd),
        }
    };
    let (config, config_truncated) = snapshot_config(&git.join("config"));
    Snapshot {
        skipped: None,
        hooks,
        config,
        truncated: hooks_truncated || config_truncated,
    }
}

fn snapshot_hooks(dir: &Path) -> (Vec<HookEntry>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let Ok(rd) = fs::read_dir(dir) else {
        return (out, truncated); // no hooks dir: empty
    };
    for e in rd.flatten() {
        if out.len() >= MAX_HOOK_FILES {
            truncated = true;
            break;
        }
        let path = e.path();
        let Ok(md) = fs::symlink_metadata(&path) else {
            continue;
        };
        // Never follow a symlink; record only plain files (and record the
        // symlink itself by name/size so it shows in the diff).
        let name = e.file_name().to_string_lossy().into_owned();
        if md.file_type().is_symlink() {
            out.push(HookEntry {
                name,
                size: md.len(),
                mode: md.mode() & 0o7777,
                sha256: None,
            });
            continue;
        }
        if !md.is_file() {
            continue; // directories and specials are not hooks
        }
        let sha = hash_file(&path, md.len());
        let oversized = sha.is_none();
        out.push(HookEntry {
            name,
            size: md.len(),
            mode: md.mode() & 0o7777,
            sha256: sha,
        });
        if oversized {
            truncated = true;
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, truncated)
}

/// SHA-256 of a plain file, bounded: a file larger than [`MAX_FILE_BYTES`]
/// is not read in full (returns `None`, size still recorded). The caller
/// already checked the entry is not a symlink, and the file is opened with
/// `O_NOFOLLOW|O_NONBLOCK` so a FIFO or a swapped-in symlink cannot hang or
/// redirect the read.
fn hash_file(path: &Path, size: u64) -> Option<String> {
    if size > MAX_FILE_BYTES {
        return None;
    }
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(format!("{:x}", h.finalize()))
}

/// Parse `.git/config` into a flat `section.subsection.key = value` map, plus
/// a truncation flag. The file is opened `O_NOFOLLOW` and read with a byte
/// cap, so a symlink, a FIFO or a huge file cannot redirect or OOM the
/// report. A deliberately small parser: it understands the INI-ish shape git
/// writes (`[section]`, `[section "subsection"]`, `key = value`, `;`/`#`
/// comments, bare keys). It does not invoke git and does not need to be a
/// full TOML/INI implementation — it only needs the keys git would act on.
/// Values are journaled verbatim (the journal is the user's own state home).
fn snapshot_config(path: &Path) -> (BTreeMap<String, String>, bool) {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut out = BTreeMap::new();
    let mut truncated = false;
    let Ok(mut f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    else {
        return (out, truncated);
    };
    let Ok(md) = f.metadata() else {
        return (out, truncated);
    };
    if !md.is_file() {
        return (out, truncated);
    }
    // Read the file through the O_NOFOLLOW handle, capped at
    // MAX_FILE_BYTES + 1 so an oversize (or hostile) file cannot OOM the
    // report; the cap is a flag, not silence.
    let mut buf = Vec::new();
    let _ = f.by_ref().take(MAX_FILE_BYTES + 1).read_to_end(&mut buf);
    if buf.len() as u64 > MAX_FILE_BYTES {
        truncated = true;
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let text = &text[..(text.len().min(MAX_FILE_BYTES as usize))];
    let mut section: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let inner = line[1..line.len() - 1].trim();
            // `[section]` or `[section "subsection"]`
            let mut it = inner.splitn(2, char::is_whitespace);
            let name = it.next().unwrap_or(inner).trim().to_ascii_lowercase();
            let sub = it
                .next()
                .map(|s| s.trim().trim_matches('"').to_owned())
                .unwrap_or_default();
            section = Some(if sub.is_empty() {
                name
            } else {
                format!("{name}.{sub}")
            });
            continue;
        }
        if let Some(sec) = &section {
            // `key = value`, `key=value`, or bare `key` (boolean true).
            let (k, v) = match line.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_owned()),
                None => (line.to_ascii_lowercase(), "true".to_owned()),
            };
            if !k.is_empty() {
                out.insert(format!("{sec}.{k}"), v);
            }
        }
    }
    (out, truncated)
}

/// The diff between two snapshots, as a JSON value for the journal record.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Value {
    let mut hooks_added = Vec::new();
    let mut hooks_removed = Vec::new();
    let mut hooks_modified = Vec::new();
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

    let mut keys_added = Vec::new();
    let mut keys_removed = Vec::new();
    let mut keys_changed = Vec::new();
    let mut flagged: Vec<String> = Vec::new();
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
        "examples": {
            "before_skipped": before.skipped,
            "after_skipped": after.skipped,
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
        assert_eq!(h.sha256, None, "a symlink is never read through");
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
        ] {
            assert!(is_dangerous_key(k), "{k} must be flagged");
        }
        for k in ["core.bare", "user.email", "init.defaultBranch"] {
            assert!(!is_dangerous_key(k), "{k} must not be flagged");
        }
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
        assert_eq!(s.config["core.bare"], "true");
        assert_eq!(s.config["alias.st"], "status");
        assert_eq!(s.config["filter.lfs.clean"], "git lfs clean");
    }
}

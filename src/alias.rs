//! R1b (DESIGN §9): detect bind aliases of the hisn runtime directory.
//!
//! Lexical path rules cannot see that `<cwd>/alias` is a bind mount of the
//! runtime root. This module parses `/proc/self/mountinfo` and decides, from
//! device numbers and in-filesystem roots, whether a tree that is about to be
//! bound into the sandbox *is*, *contains*, or *lies inside* the runtime
//! directory. Pure: the caller supplies the mountinfo text.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub id: u64,
    pub dev: String,
    /// Root of the mount *within its filesystem*.
    pub root: PathBuf,
    pub mountpoint: PathBuf,
}

/// Undo the kernel's octal escaping (`\040` for space, etc.) in mountinfo.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo; malformed lines are an error (caller fails closed).
pub fn parse_mountinfo(text: &str) -> Result<Vec<MountEntry>, String> {
    let mut v = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 7 {
            return Err(format!("mountinfo line {} is malformed", n + 1));
        }
        let id = f[0]
            .parse()
            .map_err(|_| format!("mountinfo line {}: bad mount id", n + 1))?;
        v.push(MountEntry {
            id,
            dev: f[2].to_owned(),
            root: PathBuf::from(unescape(f[3])),
            mountpoint: PathBuf::from(unescape(f[4])),
        });
    }
    Ok(v)
}

/// The mount that contains `path`: the entry with the longest mountpoint
/// prefix. When several mounts share a mountpoint (over-mounts) the *last*
/// listed one is on top.
pub fn containing<'a>(entries: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    entries
        .iter()
        .filter(|e| path.starts_with(&e.mountpoint))
        .max_by_key(|e| e.mountpoint.components().count())
        .map(|best| {
            let depth = best.mountpoint.components().count();
            entries
                .iter()
                .rfind(|e| {
                    e.mountpoint == best.mountpoint && e.mountpoint.components().count() == depth
                })
                .unwrap_or(best)
        })
}

/// Location of `path` as (device, path-within-filesystem).
pub fn fs_location(entries: &[MountEntry], path: &Path) -> Option<(String, PathBuf)> {
    let m = containing(entries, path)?;
    let rel = path.strip_prefix(&m.mountpoint).ok()?;
    Some((m.dev.clone(), m.root.join(rel)))
}

fn related(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Why a tree was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alias {
    /// The tree itself is (an ancestor of, or inside) the runtime directory
    /// on the same filesystem object, reached by a different path.
    Tree { tree: PathBuf },
    /// A mount inside the tree aliases the runtime directory.
    Submount { tree: PathBuf, mountpoint: PathBuf },
}

/// Check `tree` (an absolute, canonical path about to be bound — recursively
/// if `recursive`) against every runtime root. `Err(String)` means the
/// mountinfo could not be interpreted: callers must reject (fail closed).
pub fn check_tree(
    mountinfo: &str,
    tree: &Path,
    recursive: bool,
    runtime_roots: &[PathBuf],
) -> Result<Option<Alias>, String> {
    let entries = parse_mountinfo(mountinfo)?;
    let tree_loc = fs_location(&entries, tree);
    for root in runtime_roots {
        // A runtime root that does not exist yet has no aliases.
        let Some((rdev, rfs)) = fs_location(&entries, root).filter(|_| root.exists()) else {
            continue;
        };
        // 1. the tree itself, via a different path
        if let Some((tdev, tfs)) = &tree_loc
            && *tdev == rdev
            && related(tfs, &rfs)
        {
            return Ok(Some(Alias::Tree {
                tree: tree.to_path_buf(),
            }));
        }
        // 2. mounts inside a recursive tree
        if recursive {
            for e in &entries {
                if e.mountpoint != tree
                    && e.mountpoint.starts_with(tree)
                    && e.dev == rdev
                    && related(&e.root, &rfs)
                {
                    return Ok(Some(Alias::Submount {
                        tree: tree.to_path_buf(),
                        mountpoint: e.mountpoint.clone(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host layout: / on 8:1, /run/user/1000 tmpfs 0:50 (runtime root is
    /// /run/user/1000/hisn), /home on 8:2.
    const BASE: &str = "\
20 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
30 20 0:50 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw
40 20 8:2 / /home rw - ext4 /dev/sda2 rw
";

    /// check_tree consults the real filesystem for existence of the runtime
    /// root; tests use a real temp dir layout via `Fixture`.
    struct Fixture {
        _d: tempfile::TempDir,
        root: PathBuf,
    }
    fn fixture() -> Fixture {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path())
            .unwrap()
            .join("run/user/1000/hisn");
        std::fs::create_dir_all(&root).unwrap();
        Fixture { _d: d, root }
    }

    fn info_for(fx: &Fixture, extra: &str) -> String {
        let base = fx.root.parent().unwrap(); // .../run/user/1000
        format!(
            "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 20 0:50 / {} rw - tmpfs tmpfs rw\n40 20 8:2 / /home rw - ext4 /dev/sda2 rw\n{extra}",
            base.display()
        )
    }

    #[test]
    fn unescape_octal() {
        assert_eq!(unescape(r"/a\040b"), "/a b");
        assert_eq!(unescape(r"/a\134b"), r"/a\b");
        assert_eq!(unescape("/plain"), "/plain");
        assert_eq!(unescape(r"/x\04"), r"/x\04", "short escape left alone");
    }

    #[test]
    fn parse_and_locate() {
        let e = parse_mountinfo(BASE).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(
            fs_location(&e, Path::new("/run/user/1000/hisn/s1")).unwrap(),
            ("0:50".to_owned(), PathBuf::from("/hisn/s1"))
        );
        assert_eq!(fs_location(&e, Path::new("/etc")).unwrap().0, "8:1");
        assert!(parse_mountinfo("short line").is_err());
        assert!(parse_mountinfo("x 1 8:1 / / rw - a b c").is_err());
    }

    #[test]
    fn topmost_overmount_wins() {
        let t = "1 0 8:1 / / rw - ext4 a b\n2 1 0:5 / /mnt rw - tmpfs t t\n3 1 8:2 /sub /mnt rw - ext4 c d\n";
        let e = parse_mountinfo(t).unwrap();
        let c = containing(&e, Path::new("/mnt/x")).unwrap();
        assert_eq!(c.id, 3);
        assert_eq!(
            fs_location(&e, Path::new("/mnt/x")).unwrap(),
            ("8:2".to_owned(), PathBuf::from("/sub/x"))
        );
    }

    #[test]
    fn unrelated_trees_pass() {
        let fx = fixture();
        let mi = info_for(&fx, "");
        let r = vec![fx.root.clone()];
        assert_eq!(
            check_tree(&mi, Path::new("/home/u/proj"), true, &r).unwrap(),
            None
        );
        assert_eq!(check_tree(&mi, Path::new("/usr"), true, &r).unwrap(), None);
        // same tmpfs, sibling directory of the runtime root
        let sib = fx.root.parent().unwrap().join("other");
        assert_eq!(check_tree(&mi, &sib, true, &r).unwrap(), None);
    }

    #[test]
    fn submount_alias_of_runtime_root_is_found() {
        let fx = fixture();
        // /home/u/proj/alias is a bind of the runtime root: same dev 0:50, root /hisn
        let mi = info_for(
            &fx,
            "50 40 0:50 /hisn /home/u/proj/alias rw - tmpfs tmpfs rw\n",
        );
        let r = vec![fx.root.clone()];
        let a = check_tree(&mi, Path::new("/home/u/proj"), true, &r).unwrap();
        assert!(
            matches!(a, Some(Alias::Submount { ref mountpoint, .. }) if mountpoint == Path::new("/home/u/proj/alias")),
            "{a:?}"
        );
        // non-recursive bind cannot import the submount
        assert_eq!(
            check_tree(&mi, Path::new("/home/u/proj"), false, &r).unwrap(),
            None
        );
    }

    #[test]
    fn alias_of_an_ancestor_or_a_descendant_is_found() {
        let fx = fixture();
        // a mount exposing the whole tmpfs (root "/") contains the runtime root
        let mi = info_for(&fx, "51 40 0:50 / /home/u/all rw - tmpfs tmpfs rw\n");
        let r = vec![fx.root.clone()];
        assert!(
            check_tree(&mi, Path::new("/home/u"), true, &r)
                .unwrap()
                .is_some()
        );
        // a mount of one session dir inside the runtime root
        let mi = info_for(
            &fx,
            "52 40 0:50 /hisn/sess1 /home/u/s1 rw - tmpfs tmpfs rw\n",
        );
        assert!(
            check_tree(&mi, Path::new("/home/u"), true, &r)
                .unwrap()
                .is_some()
        );
        // a mount of an unrelated dir on the same tmpfs is fine
        let mi = info_for(&fx, "53 40 0:50 /elsewhere /home/u/e rw - tmpfs tmpfs rw\n");
        assert_eq!(
            check_tree(&mi, Path::new("/home/u"), true, &r).unwrap(),
            None
        );
    }

    #[test]
    fn the_tree_itself_bound_from_the_runtime_dir_is_found() {
        let fx = fixture();
        // /srv/x is a bind of the runtime root => binding /srv/x aliases it
        let mi = info_for(&fx, "54 20 0:50 /hisn /srv/x rw - tmpfs tmpfs rw\n");
        let r = vec![fx.root.clone()];
        let a = check_tree(&mi, Path::new("/srv/x"), false, &r).unwrap();
        assert!(matches!(a, Some(Alias::Tree { .. })), "{a:?}");
        // a subdirectory of it too
        let a = check_tree(&mi, Path::new("/srv/x/sess"), false, &r).unwrap();
        assert!(matches!(a, Some(Alias::Tree { .. })), "{a:?}");
    }

    #[test]
    fn missing_runtime_root_and_garbage_input() {
        let r = vec![PathBuf::from("/nonexistent/hisn")];
        assert_eq!(
            check_tree(BASE, Path::new("/home"), true, &r).unwrap(),
            None
        );
        let fx = fixture();
        assert!(
            check_tree(
                "garbage",
                Path::new("/home"),
                true,
                std::slice::from_ref(&fx.root)
            )
            .is_err()
        );
    }
}

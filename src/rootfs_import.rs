//! `hisn rootfs import`: streaming, hardened extraction of an untrusted tar
//! archive into the rootfs store (0.3.2, ADR 0010).
//!
//! The archive is read from a `Read` (file, stdin, or `docker export` stdout)
//! and never buffered. The `tar` crate is used only to iterate entries and to
//! resolve ustar prefix / GNU LongLink / PAX path headers; **every** hardening
//! check below is explicit and none is delegated to the crate's `unpack`.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::rootfs_store::{self, Manifest};

/// What the extractor did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExtractStats {
    pub files: u64,
    pub skipped: u64,
    pub size_bytes: u64,
}

/// Reader that feeds every byte it hands out into a SHA-256 hasher.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Normalise a tar member path: absolute names become relative, `.` and empty
/// components vanish. `Err(())` means the path contains `..` and is hostile.
fn normalize_entry_path(path: &Path) -> std::result::Result<Option<PathBuf>, ()> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => return Err(()),
            Component::Normal(s) => out.push(s),
        }
    }
    Ok(if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    })
}

/// True if `path` (inside `base`) is, or lies below, an extracted symlink.
fn traverses_symlink(base: &Path, path: &Path, symlinks: &HashSet<PathBuf>) -> bool {
    let Ok(rel) = path.strip_prefix(base) else {
        return false;
    };
    let mut cur = base.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if symlinks.contains(&cur) {
            return true;
        }
    }
    false
}

/// Extract a tar stream into `dest` with explicit hardening.
///
/// * `..` anywhere in a member name → hard error naming the entry.
/// * absolute names are made relative.
/// * entries below (or at) an already extracted symlink are skipped (S1).
/// * hard links whose target is outside the tree or passes through an
///   extracted symlink are skipped.
/// * setuid/setgid bits are stripped (sticky is kept) from files and directories.
/// * device nodes, fifos and anything else exotic are skipped and counted.
pub fn extract_tar<R: Read>(dest: &Path, reader: R) -> Result<ExtractStats> {
    // Confinement precondition: the destination is a fresh, empty, real
    // directory, so every symlink below it was created by this archive and
    // is tracked in `symlinks`.
    let md = fs::symlink_metadata(dest).with_context(|| format!("stat {}", dest.display()))?;
    if !md.is_dir() {
        bail!(
            "extraction target {} is not a real directory",
            dest.display()
        );
    }
    if fs::read_dir(dest)?.next().is_some() {
        bail!("extraction target {} is not empty", dest.display());
    }
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    let mut archive = tar::Archive::new(reader);
    let mut st = ExtractStats::default();
    let mut symlinks: HashSet<PathBuf> = HashSet::new();

    for entry in archive.entries().context("reading tar stream")? {
        let mut entry = entry.context("reading tar entry")?;
        // `Entry::path`/`link_name` apply GNU LongLink and PAX overrides;
        // `Header::path` would not (that was the S6 truncation bug).
        let raw_path = entry.path().context("tar entry path")?.into_owned();
        let rel = match normalize_entry_path(&raw_path) {
            Err(()) => bail!("tar entry {:?} contains '..'; refusing to import", raw_path),
            Ok(None) => {
                st.skipped += 1;
                continue;
            }
            Ok(Some(p)) => p,
        };
        let target = dest.join(&rel);
        if traverses_symlink(dest, &target, &symlinks) {
            st.skipped += 1;
            continue;
        }
        let ty = entry.header().entry_type();
        let mode = entry.header().mode().unwrap_or(0o644) & !0o6000;
        let size = entry.size();

        if ty == tar::EntryType::Regular || ty == tar::EntryType::Continuous {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                st.skipped += 1;
                continue;
            }
            let mut f = fs::File::create(&target)
                .with_context(|| format!("creating {}", target.display()))?;
            io::copy(&mut entry, &mut f)
                .with_context(|| format!("writing {}", target.display()))?;
            drop(f);
            fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o1777))?;
            st.files += 1;
            st.size_bytes += size;
        } else if ty == tar::EntryType::Directory {
            fs::create_dir_all(&target)?;
            // Applied after the walk: a mode-000 directory must not block
            // the entries below it, nor the cleanup of a failed import.
            dir_modes.push((target, mode & 0o1777));
            st.files += 1;
        } else if ty == tar::EntryType::Symlink {
            let link = entry
                .link_name()
                .context("symlink target")?
                .ok_or_else(|| anyhow!("symlink entry {:?} has no target", raw_path))?
                .into_owned();
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(&link, &target)
                .with_context(|| format!("symlink {}", target.display()))?;
            symlinks.insert(target);
            st.files += 1;
        } else if ty == tar::EntryType::Link {
            let link = entry
                .link_name()
                .context("hard link target")?
                .ok_or_else(|| anyhow!("hard link entry {:?} has no target", raw_path))?
                .into_owned();
            let Ok(Some(lrel)) = normalize_entry_path(&link) else {
                st.skipped += 1;
                continue;
            };
            let src = dest.join(&lrel);
            if traverses_symlink(dest, &src, &symlinks) {
                st.skipped += 1;
                continue;
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::hard_link(&src, &target).is_ok() {
                st.files += 1;
            } else {
                st.skipped += 1;
            }
        } else {
            // Char/Block devices, fifos, sparse files, ...
            st.skipped += 1;
        }
    }
    // Deepest first, so a restrictive parent does not hide its children.
    dir_modes.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    for (p, m) in dir_modes {
        fs::set_permissions(&p, fs::Permissions::from_mode(m))?;
    }
    Ok(st)
}

/// What to import.
pub struct ImportOpts<'a> {
    pub name: &'a str,
    pub from_tar: Option<&'a Path>,
    pub from_image: Option<&'a str>,
    pub replace: bool,
}

/// Read to the end so the digest covers the whole input (tar pads with zero
/// blocks past the end-of-archive marker) and a `docker export` writer never
/// blocks on a full pipe.
fn drain_and_digest<R: Read>(mut hr: HashingReader<R>) -> Result<String> {
    io::copy(&mut hr, &mut io::sink()).context("reading the rest of the archive")?;
    Ok(format!("{:x}", hr.hasher.finalize()))
}

/// A private, unique sibling name for staging / the displaced old tree.
fn unique_sibling(root: &Path, kind: &str, name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    root.join(format!(".{kind}-{name}-{}-{nanos}", std::process::id()))
}

/// Write `manifest.json` without following anything the archive planted: an
/// existing entry of that name (symlink, directory, file) is removed first
/// and the new file is created exclusively with `O_NOFOLLOW`.
fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let p = dir.join("manifest.json");
    if let Ok(m) = fs::symlink_metadata(&p) {
        if m.is_dir() {
            fs::remove_dir_all(&p)?;
        } else {
            fs::remove_file(&p)?;
        }
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    f.write_all(serde_json::to_string_pretty(manifest)?.as_bytes())?;
    Ok(())
}

/// Import into `root` (the store root). On any failure no store entry and no
/// staging directory is left behind. Publication never clobbers: without
/// `replace` the final `rename` fails if a non-empty entry appeared meanwhile;
/// with `replace` the old tree is moved aside, the new one renamed in, and the
/// old one removed only afterwards (restored if the rename fails).
pub fn import(root: &Path, opts: &ImportOpts, docker: &str) -> Result<Manifest> {
    if !rootfs_store::is_valid_name(opts.name) {
        bail!("invalid rootfs name {:?}", opts.name);
    }
    let final_path = root.join(opts.name);
    if fs::symlink_metadata(&final_path).is_ok() && !opts.replace {
        bail!(
            "rootfs {} already exists (use --replace to overwrite)",
            opts.name
        );
    }
    match (opts.from_tar, opts.from_image) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => bail!("exactly one of --from-tar or --from-image is required"),
    }
    fs::create_dir_all(root)?;
    // Unique and created with `create_dir` (fails if it exists): never reuse
    // or delete a directory we did not create.
    let staging = unique_sibling(root, "staging", opts.name);
    fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;

    let (source, sha, st) = match run_import(&staging, opts, docker) {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    let manifest = Manifest {
        name: opts.name.to_owned(),
        source,
        source_digest: None,
        import_timestamp: crate::session::rfc3339_now(),
        hisn_version: env!("CARGO_PKG_VERSION").to_owned(),
        sha256: Some(sha),
        files: st.files,
        skipped: st.skipped,
        size_bytes: st.size_bytes,
    };
    let publish = || -> Result<()> {
        write_manifest(&staging, &manifest)?;
        if opts.replace && fs::symlink_metadata(&final_path).is_ok() {
            let old = unique_sibling(root, "old", opts.name);
            fs::rename(&final_path, &old).context("moving the old rootfs aside")?;
            if let Err(e) = fs::rename(&staging, &final_path) {
                let _ = fs::rename(&old, &final_path);
                return Err(anyhow!(e).context("publishing the new rootfs"));
            }
            let _ = fs::remove_dir_all(&old);
        } else {
            fs::rename(&staging, &final_path).context("publishing the rootfs")?;
        }
        Ok(())
    };
    if let Err(e) = publish() {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }
    Ok(manifest)
}

fn run_import(
    staging: &Path,
    opts: &ImportOpts,
    docker: &str,
) -> Result<(String, String, ExtractStats)> {
    match (opts.from_tar, opts.from_image) {
        (Some(p), None) if p == Path::new("-") => {
            let hr = HashingReader {
                inner: io::stdin().lock(),
                hasher: Sha256::new(),
            };
            let (st, sha) = extract_hashed(staging, hr)?;
            Ok(("stdin".into(), sha, st))
        }
        (Some(p), None) => {
            let f = fs::File::open(p).with_context(|| format!("reading tar {}", p.display()))?;
            let hr = HashingReader {
                inner: f,
                hasher: Sha256::new(),
            };
            let (st, sha) = extract_hashed(staging, hr)?;
            Ok((format!("file:{}", p.display()), sha, st))
        }
        (None, Some(image)) => {
            if image.is_empty() || image.starts_with('-') {
                bail!("invalid image reference {image:?} (must not start with '-')");
            }
            if Command::new(docker).arg("--version").output().is_err() {
                bail!("docker CLI not found (required for --from-image)");
            }
            let ctr = format!("hisn-rootfs-{}", opts.name);
            let created = Command::new(docker)
                .args(["create", "--name", &ctr, image])
                .output()
                .context("docker create")?;
            if !created.status.success() {
                bail!(
                    "docker create failed: {}",
                    String::from_utf8_lossy(&created.stderr)
                );
            }
            let result = (|| -> Result<(ExtractStats, String)> {
                let mut child = Command::new(docker)
                    .args(["export", &ctr])
                    .stdout(Stdio::piped())
                    .spawn()
                    .context("docker export")?;
                let out = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
                let hr = HashingReader {
                    inner: out,
                    hasher: Sha256::new(),
                };
                let extracted = extract_hashed(staging, hr);
                if extracted.is_err() {
                    let _ = child.kill();
                }
                let status = child.wait().context("waiting for docker export")?;
                let got = extracted?;
                if !status.success() {
                    bail!("docker export failed ({status})");
                }
                Ok(got)
            })();
            // Always remove the container, success or not.
            let _ = Command::new(docker).args(["rm", &ctr]).output();
            let (st, sha) = result?;
            Ok((format!("docker:{image}"), sha, st))
        }
        _ => unreachable!("checked by the caller"),
    }
}

fn extract_hashed<R: Read>(
    staging: &Path,
    mut hr: HashingReader<R>,
) -> Result<(ExtractStats, String)> {
    let st = extract_tar(staging, &mut hr)?;
    let sha = drain_and_digest(hr)?;
    Ok((st, sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// A header written verbatim (no path validation), for hostile names.
    fn raw(
        name: &[u8],
        ty: tar::EntryType,
        mode: u32,
        size: u64,
        link: Option<&[u8]>,
    ) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name);
            if let Some(l) = link {
                old.linkname[..l.len()].copy_from_slice(l);
            }
        }
        h.set_entry_type(ty);
        h.set_mode(mode);
        h.set_size(size);
        h.set_cksum();
        h
    }

    fn build(f: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        f(&mut b);
        b.into_inner().unwrap()
    }

    fn file(b: &mut tar::Builder<Vec<u8>>, name: &[u8], mode: u32, data: &[u8]) {
        let h = raw(name, tar::EntryType::Regular, mode, data.len() as u64, None);
        b.append(&h, data).unwrap();
    }

    fn extract(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, Result<ExtractStats>) {
        let d = tmp();
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        let r = extract_tar(&dest, bytes);
        (d, dest, r)
    }

    // 1
    #[test]
    fn ustar_prefix_path_is_extracted_in_full() {
        let path = format!(
            "{}/{}/{}/file.txt",
            "p".repeat(40),
            "q".repeat(40),
            "r".repeat(40)
        );
        assert!(path.len() > 100);
        let tarb = build(|b| {
            let mut h = tar::Header::new_ustar();
            h.set_path(&path).unwrap();
            h.set_size(2);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            assert_ne!(
                h.as_ustar().unwrap().prefix[0],
                0,
                "must use the prefix field"
            );
            h.set_cksum();
            b.append(&h, &b"hi"[..]).unwrap();
        });
        let (_d, dest, r) = extract(&tarb);
        r.unwrap();
        assert_eq!(fs::read(dest.join(&path)).unwrap(), b"hi");
    }

    // 2
    #[test]
    fn gnu_longlink_name_and_link_are_extracted_in_full() {
        let long = format!("{}/{}", "n".repeat(120), "f.txt");
        let target = "t".repeat(180);
        let tarb = build(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            b.append_data(&mut h, &long, &b"x"[..]).unwrap();
            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Symlink);
            l.set_size(0);
            b.append_link(&mut l, "lnk", &target).unwrap();
        });
        let (_d, dest, r) = extract(&tarb);
        r.unwrap();
        assert_eq!(fs::read(dest.join(&long)).unwrap(), b"x");
        assert_eq!(
            fs::read_link(dest.join("lnk")).unwrap(),
            PathBuf::from(&target)
        );
    }

    // 3
    #[test]
    fn pax_path_and_linkpath_are_honoured() {
        let long = format!("{}/{}", "x".repeat(130), "pax.txt");
        let target = "y".repeat(200);
        let tarb = build(|b| {
            b.append_pax_extensions([("path", long.as_bytes())])
                .unwrap();
            file(b, b"short", 0o644, b"p");
            b.append_pax_extensions([("path", &b"paxlink"[..]), ("linkpath", target.as_bytes())])
                .unwrap();
            let h = raw(
                b"placeholder",
                tar::EntryType::Symlink,
                0o777,
                0,
                Some(b"z"),
            );
            b.append(&h, io::empty()).unwrap();
        });
        let (_d, dest, r) = extract(&tarb);
        r.unwrap();
        assert_eq!(fs::read(dest.join(&long)).unwrap(), b"p");
        assert!(!dest.join("short").exists());
        assert_eq!(
            fs::read_link(dest.join("paxlink")).unwrap(),
            PathBuf::from(&target)
        );
    }

    // 4
    #[test]
    fn dotdot_entries_fail_the_import_naming_the_entry() {
        for bad in ["../escape", "a/../../escape"] {
            let tarb = build(|b| file(b, bad.as_bytes(), 0o644, b"evil"));
            let (d, _dest, r) = extract(&tarb);
            let e = r.unwrap_err().to_string();
            assert!(e.contains(bad), "{e}");
            assert!(!d.path().join("escape").exists(), "{bad} escaped");
        }
    }

    // 5
    #[test]
    fn absolute_names_become_relative() {
        let tarb = build(|b| file(b, b"/usr/bin/x", 0o755, b"bin"));
        let (_d, dest, r) = extract(&tarb);
        r.unwrap();
        assert_eq!(fs::read(dest.join("usr/bin/x")).unwrap(), b"bin");
    }

    // 6
    #[test]
    fn hard_link_to_a_target_outside_the_tree_is_rejected() {
        let d = tmp();
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        fs::write(d.path().join("outside"), b"secret").unwrap();
        let tarb = build(|b| {
            let h = raw(b"h", tar::EntryType::Link, 0o644, 0, Some(b"../outside"));
            b.append(&h, io::empty()).unwrap();
        });
        let st = extract_tar(&dest, &tarb[..]).unwrap();
        assert!(!dest.join("h").exists());
        assert_eq!(st.skipped, 1);
        assert_eq!(fs::read(d.path().join("outside")).unwrap(), b"secret");
    }

    // 7
    #[test]
    fn write_through_an_extracted_symlink_is_rejected() {
        let d = tmp();
        let dest = d.path().join("dest");
        let victim = d.path().join("victim");
        fs::create_dir(&dest).unwrap();
        fs::create_dir(&victim).unwrap();
        let tarb = build(|b| {
            let h = raw(
                b"usr",
                tar::EntryType::Symlink,
                0o777,
                0,
                Some(victim.to_str().unwrap().as_bytes()),
            );
            b.append(&h, io::empty()).unwrap();
            file(b, b"usr/file", 0o644, b"pwn");
        });
        let st = extract_tar(&dest, &tarb[..]).unwrap();
        assert!(!victim.join("file").exists(), "wrote through the symlink");
        assert_eq!(st.skipped, 1);
    }

    // 8
    #[test]
    fn hard_link_through_an_extracted_symlink_is_rejected() {
        let d = tmp();
        let dest = d.path().join("dest");
        let victim = d.path().join("victim");
        fs::create_dir(&dest).unwrap();
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("secret"), b"s").unwrap();
        let tarb = build(|b| {
            let h = raw(
                b"s",
                tar::EntryType::Symlink,
                0o777,
                0,
                Some(victim.to_str().unwrap().as_bytes()),
            );
            b.append(&h, io::empty()).unwrap();
            let l = raw(b"h", tar::EntryType::Link, 0o644, 0, Some(b"s/secret"));
            b.append(&l, io::empty()).unwrap();
        });
        let st = extract_tar(&dest, &tarb[..]).unwrap();
        assert!(
            !dest.join("h").exists(),
            "hard link through symlink created"
        );
        assert_eq!(st.skipped, 1);
        assert_eq!(fs::metadata(victim.join("secret")).unwrap().nlink(), 1);
    }

    // 9
    #[test]
    fn setuid_and_setgid_bits_are_stripped_sticky_is_kept() {
        let tarb = build(|b| {
            file(b, b"suid", 0o4755, b"");
            file(b, b"sgid", 0o2755, b"");
            file(b, b"both", 0o6777, b"");
            let h = raw(b"dir/", tar::EntryType::Directory, 0o3777, 0, None);
            b.append(&h, io::empty()).unwrap();
        });
        let (_d, dest, r) = extract(&tarb);
        r.unwrap();
        let mode = |p: &str| fs::metadata(dest.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(mode("sgid"), 0o755);
        assert_eq!(mode("both"), 0o777);
        assert_eq!(mode("dir"), 0o1777, "sticky kept, setgid stripped");
    }

    // 10
    #[test]
    fn devices_and_fifos_are_skipped_and_counted_in_the_manifest() {
        let d = tmp();
        let root = d.path().join("store");
        let tarb = build(|b| {
            file(b, b"ok", 0o644, b"1");
            for (n, t) in [
                (&b"null"[..], tar::EntryType::Char),
                (&b"blk"[..], tar::EntryType::Block),
                (&b"pipe"[..], tar::EntryType::Fifo),
            ] {
                b.append(&raw(n, t, 0o666, 0, None), io::empty()).unwrap();
            }
        });
        let tf = d.path().join("in.tar");
        fs::write(&tf, &tarb).unwrap();
        let opts = ImportOpts {
            name: "dev",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        import(&root, &opts, "docker").unwrap();
        let j: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("dev/manifest.json")).unwrap())
                .unwrap();
        assert_eq!(j["skipped"], 3);
        assert_eq!(j["files"], 1);
        for n in ["null", "blk", "pipe"] {
            assert!(!root.join("dev").join(n).exists());
        }
    }

    /// No `.staging-*` / `.old-*` directory left in the store root.
    fn no_leftovers(root: &Path) -> bool {
        fs::read_dir(root).is_ok_and(|rd| {
            rd.flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with('.'))
        })
    }

    fn small_tar(content: &[u8]) -> Vec<u8> {
        build(|b| file(b, b"f", 0o644, content))
    }

    // 11
    #[test]
    fn existing_name_needs_replace_and_replace_swaps_cleanly() {
        let d = tmp();
        let root = d.path().join("store");
        let tf = d.path().join("in.tar");
        let mk = |replace| ImportOpts {
            name: "n",
            from_tar: Some(&tf),
            from_image: None,
            replace,
        };
        fs::write(&tf, small_tar(b"old")).unwrap();
        import(&root, &mk(false), "docker").unwrap();
        fs::write(&tf, build(|b| file(b, b"g", 0o644, b"new"))).unwrap();
        let e = import(&root, &mk(false), "docker").unwrap_err().to_string();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(fs::read(root.join("n/f")).unwrap(), b"old", "untouched");
        assert!(
            !root.join(".staging-n").exists(),
            "refused before any write"
        );
        import(&root, &mk(true), "docker").unwrap();
        assert!(!root.join("n/f").exists(), "old tree gone");
        assert_eq!(fs::read(root.join("n/g")).unwrap(), b"new");
        assert!(no_leftovers(&root));
    }

    // 12
    #[test]
    fn truncated_archive_fails_and_leaves_nothing_behind() {
        let d = tmp();
        let root = d.path().join("store");
        let full = build(|b| {
            file(b, b"a", 0o644, b"first");
            file(b, b"big", 0o644, &vec![7u8; 8192]);
        });
        let cut = &full[..1024 + 512 + 1000]; // mid-way through `big`
        let tf = d.path().join("cut.tar");
        fs::write(&tf, cut).unwrap();
        let opts = ImportOpts {
            name: "t",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        assert!(import(&root, &opts, "docker").is_err());
        assert!(!root.join("t").exists(), "no partial store entry");
        assert!(no_leftovers(&root), "staging cleaned up");
    }

    // 13
    #[test]
    fn manifest_sha256_covers_every_input_byte_including_padding() {
        let d = tmp();
        let root = d.path().join("store");
        let mut bytes = small_tar(b"data");
        bytes.resize(bytes.len().div_ceil(10240) * 10240 + 10240, 0); // blocking-factor padding
        let tf = d.path().join("in.tar");
        fs::write(&tf, &bytes).unwrap();
        let opts = ImportOpts {
            name: "s",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        let m = import(&root, &opts, "docker").unwrap();
        let want = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(m.sha256.as_deref(), Some(want.as_str()));
        if let Ok(o) = Command::new("sha256sum").arg(&tf).output() {
            let line = String::from_utf8_lossy(&o.stdout).into_owned();
            assert_eq!(line.split_whitespace().next(), Some(want.as_str()));
        }
    }

    /// A `Read` that yields a tar of `n` zero-filled files of `size` bytes
    /// each without ever materialising them.
    struct ZeroTar {
        n: u32,
        size: u64,
        next: u32,
        buf: Vec<u8>,
        pos: usize,
        zeros_left: u64,
        tail_left: usize,
    }

    impl ZeroTar {
        fn new(n: u32, size: u64) -> Self {
            Self {
                n,
                size,
                next: 0,
                buf: Vec::new(),
                pos: 0,
                zeros_left: 0,
                tail_left: 1024,
            }
        }
    }

    impl Read for ZeroTar {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            loop {
                if self.pos < self.buf.len() {
                    let k = out.len().min(self.buf.len() - self.pos);
                    out[..k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
                    self.pos += k;
                    return Ok(k);
                }
                if self.zeros_left > 0 {
                    let k = (out.len() as u64).min(self.zeros_left) as usize;
                    out[..k].fill(0);
                    self.zeros_left -= k as u64;
                    return Ok(k);
                }
                if self.next < self.n {
                    let name = format!("big/f{}", self.next);
                    let h = raw(
                        name.as_bytes(),
                        tar::EntryType::Regular,
                        0o644,
                        self.size,
                        None,
                    );
                    self.buf = h.as_bytes().to_vec();
                    self.pos = 0;
                    self.zeros_left = self.size.div_ceil(512) * 512; // data + padding
                    self.next += 1;
                    continue;
                }
                if self.tail_left > 0 {
                    let k = out.len().min(self.tail_left);
                    out[..k].fill(0);
                    self.tail_left -= k;
                    return Ok(k);
                }
                return Ok(0);
            }
        }
    }

    /// Wait out `ETXTBSY`: another test thread may fork while our freshly
    /// written script still has a write fd open in the child.
    fn wait_executable(p: &Path) {
        for _ in 0..200 {
            match Command::new(p).arg("--version").output() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => return,
            }
        }
        panic!("{} stayed ETXTBSY", p.display());
    }

    fn vm_kb(field: &str) -> Option<u64> {
        let s = fs::read_to_string("/proc/self/status").ok()?;
        let l = s.lines().find(|l| l.starts_with(field))?;
        l.split_whitespace().nth(1)?.parse().ok()
    }

    // 14
    #[test]
    fn streaming_512mb_stays_under_64mb_of_extra_rss() {
        if std::env::var("HISN_BIG_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: set HISN_BIG_TESTS=1 to run the 512 MB streaming test");
            return;
        }
        if vm_kb("VmHWM:").is_none() {
            eprintln!("skipped: /proc/self/status unavailable");
            return;
        }
        let d = tmp();
        let fsst = rustix::fs::statvfs(d.path()).unwrap();
        let free = fsst.f_bavail * fsst.f_frsize;
        if free < 1 << 30 {
            eprintln!("skipped: scratch dir has {} MiB free (< 1 GiB)", free >> 20);
            return;
        }
        // Reset the peak counter so other tests in this process do not count.
        let reset = fs::write("/proc/self/clear_refs", "5").is_ok();
        let base = if reset {
            vm_kb("VmRSS:").unwrap()
        } else {
            vm_kb("VmHWM:").unwrap()
        };
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        let st = extract_tar(&dest, ZeroTar::new(8, 64 << 20)).unwrap();
        let hwm = vm_kb("VmHWM:").unwrap();
        let delta_kb = hwm.saturating_sub(base);
        eprintln!("VmHWM delta = {delta_kb} kB (reset={reset}, base={base} kB, hwm={hwm} kB)");
        assert_eq!(st.files, 8);
        assert_eq!(st.size_bytes, 512 << 20);
        assert!(delta_kb < 64 * 1024, "peak RSS grew by {delta_kb} kB");
    }

    // from-image plumbing with a fake docker
    #[test]
    fn from_image_pipes_docker_export_into_the_extractor() {
        if Command::new("sh").arg("-c").arg("true").status().is_err() {
            eprintln!("skipped: sh unavailable");
            return;
        }
        let d = tmp();
        let root = d.path().join("store");
        let tarf = d.path().join("img.tar");
        fs::write(&tarf, build(|b| file(b, b"usr/bin/hello", 0o755, b"img"))).unwrap();
        let log = d.path().join("calls.log");
        let fake = d.path().join("docker");
        let mut f = fs::File::create(&fake).unwrap();
        writeln!(
            f,
            "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in\n  --version) echo fake;;\n  create) echo cid;;\n  export) cat '{}';;\n  rm) ;;\nesac",
            log.display(),
            tarf.display()
        )
        .unwrap();
        drop(f);
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        wait_executable(&fake);
        let opts = ImportOpts {
            name: "img",
            from_tar: None,
            from_image: Some("golang:1.24"),
            replace: false,
        };
        let m = import(&root, &opts, fake.to_str().unwrap()).unwrap();
        assert_eq!(m.source, "docker:golang:1.24");
        assert_eq!(fs::read(root.join("img/usr/bin/hello")).unwrap(), b"img");
        let calls = fs::read_to_string(&log).unwrap();
        assert!(
            calls.contains("create --name hisn-rootfs-img golang:1.24"),
            "{calls}"
        );
        assert!(
            calls.contains("rm hisn-rootfs-img"),
            "container removed: {calls}"
        );
    }

    #[test]
    fn a_failing_docker_export_fails_the_import_and_removes_the_container() {
        if Command::new("sh").arg("-c").arg("true").status().is_err() {
            return;
        }
        let d = tmp();
        let root = d.path().join("store");
        let log = d.path().join("calls.log");
        let fake = d.path().join("docker");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in\n  export) exit 3;;\nesac\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        wait_executable(&fake);
        let opts = ImportOpts {
            name: "bad",
            from_tar: None,
            from_image: Some("x"),
            replace: false,
        };
        assert!(import(&root, &opts, fake.to_str().unwrap()).is_err());
        assert!(!root.join("bad").exists());
        assert!(no_leftovers(&root));
        assert!(
            fs::read_to_string(&log)
                .unwrap()
                .contains("rm hisn-rootfs-bad")
        );
    }

    #[test]
    fn manifest_symlink_in_the_archive_cannot_redirect_the_manifest_write() {
        let d = tmp();
        let root = d.path().join("store");
        let sentinel = d.path().join("sentinel");
        fs::write(&sentinel, b"untouched").unwrap();
        let tarb = build(|b| {
            let h = raw(
                b"manifest.json",
                tar::EntryType::Symlink,
                0o777,
                0,
                Some(sentinel.to_str().unwrap().as_bytes()),
            );
            b.append(&h, io::empty()).unwrap();
        });
        let tf = d.path().join("in.tar");
        fs::write(&tf, tarb).unwrap();
        let opts = ImportOpts {
            name: "m",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        import(&root, &opts, "docker").unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), b"untouched");
        let md = fs::symlink_metadata(root.join("m/manifest.json")).unwrap();
        assert!(
            md.is_file(),
            "manifest is a regular file, not the planted link"
        );
    }

    #[test]
    fn a_store_entry_that_looks_like_staging_is_never_deleted() {
        let d = tmp();
        let root = d.path().join("store");
        fs::create_dir_all(root.join(".staging-x")).unwrap();
        fs::write(root.join(".staging-x/keep"), b"k").unwrap();
        let tf = d.path().join("in.tar");
        fs::write(&tf, small_tar(b"1")).unwrap();
        let opts = ImportOpts {
            name: "x",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        import(&root, &opts, "docker").unwrap();
        assert_eq!(fs::read(root.join(".staging-x/keep")).unwrap(), b"k");
    }

    #[test]
    fn restrictive_directory_modes_do_not_break_extraction_or_cleanup() {
        let d = tmp();
        let root = d.path().join("store");
        let tarb = build(|b| {
            b.append(
                &raw(b"locked/", tar::EntryType::Directory, 0o000, 0, None),
                io::empty(),
            )
            .unwrap();
            file(b, b"locked/file", 0o644, b"x");
            file(b, b"z", 0o644, b"z");
        });
        let tf = d.path().join("in.tar");
        fs::write(&tf, &tarb).unwrap();
        let opts = ImportOpts {
            name: "l",
            from_tar: Some(&tf),
            from_image: None,
            replace: false,
        };
        // Succeeds (mode applied after the walk) ...
        import(&root, &opts, "docker").unwrap();
        assert_eq!(
            fs::metadata(root.join("l/locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0
        );
        // make it removable for tempdir cleanup
        fs::set_permissions(root.join("l/locked"), fs::Permissions::from_mode(0o755)).unwrap();
        // ... and a truncated variant fails without leaving a staging dir.
        let tf2 = d.path().join("cut.tar");
        fs::write(&tf2, &tarb[..1024 + 100]).unwrap();
        let opts2 = ImportOpts {
            name: "l2",
            from_tar: Some(&tf2),
            from_image: None,
            replace: false,
        };
        assert!(import(&root, &opts2, "docker").is_err());
        assert!(no_leftovers(&root));
    }

    #[test]
    fn extraction_target_must_be_a_fresh_real_directory() {
        let d = tmp();
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("pre"), b"x").unwrap();
        assert!(
            extract_tar(&real, &small_tar(b"1")[..]).is_err(),
            "non-empty"
        );
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(extract_tar(&link, &small_tar(b"1")[..]).is_err(), "symlink");
    }

    #[test]
    fn option_like_image_references_are_refused_before_docker_runs() {
        let d = tmp();
        let root = d.path().join("store");
        let log = d.path().join("calls.log");
        let opts = ImportOpts {
            name: "o",
            from_tar: None,
            from_image: Some("--env-file=/etc/passwd"),
            replace: false,
        };
        let e = import(&root, &opts, "/nonexistent/docker")
            .unwrap_err()
            .to_string();
        assert!(e.contains("invalid image reference"), "{e}");
        assert!(!log.exists());
        assert!(no_leftovers(&root));
    }
}

# hisn 0.3.2 follow-up — hardening + leak coverage before tag

Follow-up to the 0.3.2 implementation, closing the open points from the
Mashūra verification round and the close-out review. Version stays 0.3.2.
No tag, no push, no release — the user does that after the host leak run passes.

## Baseline

- HEAD: `cbab8db` on `main`, v0.3.2, 6 commits ahead of `009a5bd` (v0.3.1)
- 258 in-sandbox tests pass; clippy clean; fmt clean
- Open points from the prior session's Mashūra round 2:
  - S2: import reads whole tar into RAM; no total-size cap
  - S3: `[home] persist` refuse list doesn't check ancestors of host `$HOME`
  - S5: nosuid/nodev on rootfs mounts are plan flags, not verified at runtime
  - S6: no ustar prefix / GNU L,K / PAX x header handling in `extract_tar`
  - S7: proxy accept loop breaks on first EMFILE; sign-forward logged only when allowlist is set
  - ADRs say `profile validate` resolves rootfs name/path; `profile::validate` uses `Overrides::default()` which doesn't set rootfs
  - CI expected-SKIP allowlist in ci.yml doesn't list L43/L45
  - RISK lines via CLI overrides (`--home-persist`, `--rootfs-path`) print no RISK line
  - Leak tests L42–L45 do not cover the security invariants the features claim
  - Rootfs risk-label text is wrong (Data instead of Trust)

## A. Streaming tar extraction (S2, S6)

### Problem
`extract_tar` (`src/main.rs:408–611`) is a hand-rolled parser that reads the
whole tar into a `&[u8]`. `rootfs_import` reads the entire archive into a
`Vec<u8>` before calling it. No ustar `prefix`, GNU `././@LongLink`/`L`, or
PAX `x` header handling — long paths (>100 chars) are silently truncated.

### Change
- Add `tar = "0.4"` and `sha2 = "0.10"` to `Cargo.toml`.
- Replace `extract_tar` with a streaming extractor using the `tar` crate:
  `tar::Archive::new(reader)` iterates entries from a `Read` — file, stdin
  (`--from-tar -`), or `docker export` stdout (`--from-image`) — never
  buffering the archive.
- `--from-image` pipes `docker export` stdout straight into the extractor
  (spawn with `Stdio::piped()`, take `stdout`, wait after extraction). No
  temp file, no `Vec<u8>`.
- SHA-256 computed in-process via `sha2::Sha256` through a `HasherReader`
  wrapper that hashes as it reads — no external `sha256sum` process, no
  re-reading.
- Keep every hardening check as a layer over the crate's entries, applied
  explicitly (do not rely on the crate's `unpack` defaults):
  1. Path traversal: reject `..` after normalisation; absolute names made
     relative (strip leading `/`).
  2. Hard links: reject if `link_name()` target resolves outside `dest` or
     passes through an extracted symlink.
  3. S1 symlink-then-write: track extracted symlinks; reject entries whose
     path traverses through one.
  4. setuid/setgid: strip mode bits `0o6000` before setting permissions.
  5. Device nodes and fifos: skip and count.
  6. No overwrite without `--replace`: refuse if target exists.
- Remove the old `extract_tar`, `parse_tar_string`, `parse_tar_octal`,
  `normalize_tar_path`, `path_traverses_symlink` functions — one parser.

### Tests
- Synthetic tars built by the test:
  - ustar prefix path (>100 chars): extracted correctly.
  - GNU `././@LongLink` name and link: extracted correctly.
  - PAX `path`/`linkpath`: extracted correctly.
  - Hard link escape: target outside `dest` → rejected.
  - Symlink-through-write (S1): symlink `usr → /home`, then `usr/file` →
    rejected.
  - setuid bit: mode `0o4755` → stripped to `0o755`.
- One test streams a generated tar of ≥512 MB of zero-filled files from a
  pipe and asserts peak RSS (`VmHWM` from `/proc/self/status`) stays under
  64 MB. Skip if `/proc` unavailable.

## B. Home refuse list (S3)

### Problem
`resolve_home_persist` (`src/policy.rs:550–634`) refuses real `$HOME` (exact
match only), `/`, session cwd, ancestors of session cwd, and runtime-root
overlaps. It does **not** refuse ancestors of real `$HOME` —
`persist = "/home"` is accepted when `$HOME = /home/valon`, handing the
session the parent of the real home.

### Change
- Add a check: if the resolved persist path is an **ancestor** of the
  canonicalised real `$HOME`, refuse. Error message names the rule that
  fired ("must not be an ancestor of the real host $HOME").
- Also refuse if the path exists and is not a directory (already partially
  present; make it explicit and name the rule).
- Resolve symlinks first (already done via `canonicalize` on the parent;
  add a final `canonicalize` on the full path and compare).
- Unit tests for each of the six refuse cases + the accepting case:
  1. Real `$HOME` (exact match).
  2. Ancestor of real `$HOME` (e.g. `/home` when `$HOME=/home/valon`).
  3. `/`.
  4. Session cwd (exact match).
  5. Ancestor of session cwd.
  6. Not a directory after creation.
  7. Accepting case: a valid path under `$HOME`'s parent.

## C. Leak tests — cover the claimed invariants

Extend existing tests with numbered sub-checks (Rn convention) and add new
L-numbers where a prepared fixture is needed. Every sub-check must be
registered in the host leak run; skips are declared with the condition.

### L42 (home) — extend
- R1: persist dir created.
- R2: file written in session A readable in session B with the same persist
  path (cross-session persistence).
- R3: a symlink created inside the persist dir to a host path outside it
  (e.g. the real `$HOME`) cannot be read or written through (symlink escape
  blocked).
- R4: writes under the pre-0.3.2 home location (`/run/hisn/home/...`) fail
  when persist is set (the mount is the persist dir, not tmpfs).
- R5: each refuse-list case is rejected before any namespace exists — assert
  no session dir/socket was created (the `hisn run` exits 125, the runtime
  root has no `l42-refuse-*` dir).
- R6: `HOME=/run/hisn/home` in the session env.
- R7: persist ≠ real `$HOME`.

### L43 (rootfs, HISN_TEST_ROOTFS) — extend
- R1: host `/usr`, `/opt`, `/nix` not visible — assert by a host-only marker:
  the test creates a file under a host path hisn would normally expose
  (use a path the harness already controls, otherwise
  `/opt/hisn-leak-marker-<pid>` if writable, else skip that sub-check) and
  asserts it is absent in the session.
- R2: a host-only binary (the harness's own `leakprobe` helper) is not
  executable inside the session (`exec` → `ENOENT` or `EPERM`).
- R3: rootfs mounts show `ro,nosuid,nodev` in `/proc/self/mountinfo` inside
  the session (closes S5).
- R4: a `remount(MS_REMOUNT|MS_RDWR)` attempt from inside the session cannot
  drop the read-only/nosuid/nodev flags (write to `/usr` still fails).
- R5: username equals host username.
- R6: a setuid-root copy of a rootfs binary, placed in a test copy of the
  rootfs, runs without privilege (`euid` unchanged — nosuid is enforced).

### L46 (rootfs symlink traps, HISN_TEST_ROOTFS) — new
- On a test copy of the rootfs:
  - `/usr/local/bin/trap → ../../../../home` — neither reaches host data.
  - An absolute symlink to the host home — neither reaches host data.
  - A dangling-symlink mountpoint dir in the rootfs makes session start fail
    with the message naming it, not mount something else.
- Registered in MANIFEST as L46.
- Skip condition: `HISN_TEST_ROOTFS` not set.

### L45 (SSH agent, skip if no ssh-agent binary) — extend
- Start a throwaway `ssh-agent` with two ed25519 keys.
- With `keys = [fingerprint of key 1]`:
  - `ssh-add -l` in session lists exactly key 1.
  - `ssh-keygen -Y sign` (or equivalent sign operation) with key 1 succeeds
    inside the session.
  - Sign with key 2 fails.
  - `ssh-add` (add a key) from inside the session fails.
  - `ssh-add -D` (remove all) from inside the session fails.
  - Host agent still lists both keys afterwards (add/remove didn't reach it).
  - Host `SSH_AUTH_SOCK` path not visible inside the session.
  - Proxy socket absent after teardown.
- Without `keys =`:
  - `ssh-add -l` lists both keys (empty allowlist = all).
  - Add/remove still fail.
- Skip condition: no `ssh-agent` binary.

### CI expected-SKIP allowlist
- Add L43 (skips if no `HISN_TEST_ROOTFS`).
- Add L45 (skips if no `ssh-agent`).
- Add L46 (skips if no `HISN_TEST_ROOTFS`).
- Update the `grep -Ev` pattern in `ci.yml` to include L43/L45/L46 skip
  patterns.

## D. Labels, validate, logging

### Risk label texts
Add `Trust` to the `RiskLabel` enum (between `None` and `Data` in ordering):
```
None < Trust < Data < Signing < HostExec < RootEquivalent < KernelSurface
```

`profile explain` prints the exact label text for each capability:
- **home-persist** (Data, medium):
  "state persists across sessions in `<path>`; a session can read and poison
  caches used by later sessions sharing this directory"
- **rootfs** (Trust, low):
  "the toolchain comes from the imported image `<name|path>` instead of the
  host; host /usr, /opt and /nix are not visible — you trust the image, not
  the host install"
- **ssh-agent** (Signing, medium):
  "the session can sign and authenticate with `<N listed keys | all keys the
  host agent offers>` for its lifetime; it cannot add, remove or extract keys"

Add a `description: String` field to `RiskEntry`; populate it in
`compute_risks` with the contextual text. `format_risk_lines` includes the
description in the RISK line. `explain` includes it in the JSON output.

Change rootfs from `RiskLabel::Data` to `RiskLabel::Trust` in `compute_risks`.

Add `Trust` to `kebab()`, `explain()`, `requires_ack()`, and
`forward_label`'s explicit-risk matching.

### `profile validate` resolves rootfs
- Extract `[rootfs] name/path` from the profile and pass it as an override
  (same code path as `supervisor::prepare`).
- Fail if the resolved rootfs path does not exist or is not a directory.
- `profile explain` shows the resolved rootfs path.

### RISK lines from effective config
- Compute `risk_entries` from the effective configuration (profile + CLI
  overrides), not just the profile text. In `supervisor.rs`, after
  `prepare()`, build the risk entries from `prep.policy.home`,
  `prep.policy.rootfs`, `prep.ssh`, `prep.forwards`, `prep.host_services`,
  `prep.services`.
- `--home-persist` and `--rootfs-path` without a profile now print RISK
  lines.

### Every forwarded SIGN_REQUEST logged once
- In `ssh_agent.rs::handle_client`, log every forwarded SIGN_REQUEST
  (fingerprint, session id, timestamp) — allowlist or not. Currently only
  logged when `!allowed.is_empty()`.
- Denied requests logged with the message type (already partially present;
  make it consistent — every non-forwarded message type is logged at info
  with `msg_type`).

## E. Proxy robustness (S7)

### Accept loop
- In `ssh_agent.rs::spawn_accept_loop`, on `EMFILE`/`ENFILE`/`EAGAIN` from
  `listener.incoming()` (or `accept()`): log at warn, sleep 50 ms, continue.
- Break only on the session-teardown signal (the listener is closed/dropped)
  or a fatal socket error (anything that is not `EMFILE`/`ENFILE`/`EAGAIN`).
- Test: spawn a child process with a lowered `RLIMIT_NOFILE`, start the
  proxy, open enough connections to exhaust fds, assert the proxy survives
  and continues to accept after fds are freed.

## F. Docs

- ADRs 0009–0011: updated where behaviour changed (streaming extraction,
  ancestor-of-`$HOME` refuse, Trust label, sign-forward logging,
  EMFILE retry).
- README: profile reference updated with `Trust` label, corrected label
  texts, `profile validate` resolves rootfs.
- CHANGELOG: 0.3.2 entry amended (no new version).
- `docs/PLAN-0.3.2-followup.md`: this file; open-points list at the end.

## Open points — not done

Items that are hardening for follow-up, not blocking for the tag:

- S2 residual: no total-size cap on the tar stream (per-entry `MAX_MSG_SIZE`
  is enforced, but a malicious tar could exhaust disk in the staging dir).
  Mitigated by `--replace` guard and the atomic rename.
- No ustar `prefix`/GNU `L`/PAX `x` test for hardlink targets that
  themselves use long names (the `tar` crate handles this, but the test
  doesn't cover the combination).
- `profile explain` for a profile loaded from `$HISN_PROFILES` doesn't
  resolve the rootfs name (it doesn't set `XDG_DATA_HOME` to the profile's
  dir; the session start does via `prepare()`).

## Security contract (DO NOT ALTER)

1. One tar parser: the `tar` crate, streaming, with hardening checks
   applied explicitly on top. Reason: the hand-rolled parser is the source
   of S2 and S6; keeping both means two code paths to audit.
2. Rootfs mounts are `ro+nosuid+nodev`, verified from inside the session
   by a leak test, and host `/usr`, `/opt`, `/nix` are not visible when a
   rootfs is set. Reason: this is the feature's whole claim; before this
   session it had no test.
3. Home refuse list includes ancestors of real `$HOME` and of the cwd.
   Reason: Wakil will point persist at `~/.cache/wakil/home/<project>`;
   `/home` or `/` slipping through hands the session the real home.
4. `[ssh]` forwards only `REQUEST_IDENTITIES` and `SIGN_REQUEST` and is
   proven by a leak test that performs a real add/remove attempt against
   a throwaway agent. Reason: unit tests on the filter do not prove the
   path through the sandbox.
5. Leak tests are only extended or added, never weakened, removed or
   renumbered; every new invariant lands in the host leak run. Reason:
   the host leak run is the user's release gate.
6. No tag, no push, no release.

## Closing session — review round 1 (Mashūra) and what was done

Review coverage (per commit group; see the session report for the delivery table):
extractor — gpt-6-astra (round 1) + fable VOID twice, so one reader only;
home/rootfs mount plan — fable only (gpt 429 twice); ssh proxy — both;
leak tests — both. Round 1 was therefore NOT complete for groups 1 and 2.

### Fixed in this session (BLOCKING)
- Import: `manifest.json` planted as a symlink in the archive was followed by the
  publish step. Now removed first and recreated with `O_NOFOLLOW|O_EXCL`.
- Import: staging dir was a predictable `.staging-<name>` (a valid store name
  could collide and be deleted). Now a unique `.staging-<name>-<pid>-<ns>`
  created with `create_dir`; never reuses or deletes a directory it did not make.
- Import: `--replace` is now rename-aside, rename-in, delete-old (old tree
  restored if the rename fails); without `--replace` an existing entry is never
  removed.
- Import: directory modes are applied after the walk, so a mode-000 directory
  neither fails the import nor blocks cleanup.
- Import: `extract_tar` refuses a non-empty or symlinked target; `--from-image`
  refuses option-like image references.
- `[rootfs] name` that does not resolve failed open to the host toolchain while
  the RISK line claimed otherwise. Now a hard error (`profile::rootfs_spec`,
  shared by `profile validate` and session start); name+path together or neither
  is an error.
- `[home] persist` refuses `/etc /dev /proc /sys /usr /boot /bin /sbin /lib
  /lib64 /opt /nix` subtrees, `/tmp /var /var/tmp /run /root /home` as the exact
  dir, hisn's own config/data dirs, and a directory not owned by the invoking user.
- A rootfs overlapping cwd / `mounts.rw` / `grantable_rw` / the persist dir is
  refused (the session could rewrite its own toolchain).
- Rootfs `/etc` that is a symlink (incl. dangling) is refused naming the path;
  a symlinked rootfs `resolv.conf` is not followed.
- ssh proxy: malformed SIGN_REQUEST (anything but string,string,u32, no trailing
  bytes) and a REQUEST_IDENTITIES with a body are rejected locally, never
  forwarded; client cap (32) and idle timeout (300 s); worker spawn failure no
  longer panics; umask restored on bind failure; chmod error propagated.
- Leak harness: probe failures (TIMEOUT/UNKNOWN_COMMAND/OK) no longer count as
  "isolation holds" (`refused`); L43 flag globs replaced by member checks; L43 R2
  uses a real host-only binary; L44 setuid check is bitwise; L45 uses separate
  messages, a third key for the add attempt, and never touches an inherited agent;
  L46 copies the rootfs with `cp -a` (no hardlinks, no chmod of the source).

### Open points — not done
- Source-path TOCTOU in the mount executor: rootfs/persist sources are opened by
  path with `AT_SYMLINK_NOFOLLOW` on the final component only; a concurrent
  same-user writer could swap an intermediate directory. Fix is an `O_PATH` root
  fd + `openat2(RESOLVE_BENEATH|NO_SYMLINKS)`. The new overlap refusal removes the
  realistic writer (the session itself).
- Masks are probed against host paths even when a rootfs is set.
- `$HOME` is read from the environment, not passwd (`HOME=/tmp` bypasses the
  real-$HOME refusal); bind-mount aliases of $HOME/cwd are not detected.
- persist vs `mounts.ro`/`mask` overlap is not refused.
- `resolv.conf` with a rootfs and `network = "host"` comes from the image, not
  the host.
- Import has no entry/byte/extension-size caps; GNU/PAX extension bodies are
  buffered by the `tar` crate; concurrent imports of one name are not locked.
- Hard link that precedes its target in the archive is skipped (counted).
- ssh proxy: certificates are fingerprinted over the whole blob (allowlist a
  cert identity by that fingerprint, not `ssh-add -l`'s inner-key one); response
  types for SIGN_REQUEST are not validated; extension messages (incl.
  `session-bind@openssh.com`) are denied, so destination-constrained keys will
  not sign; `keys = []` means all keys; no shutdown signal for the accept loop;
  no integration test with a fake host agent.
- CI does not provision a rootfs fixture, so L43/L46 (traps) are skip-allowed in
  CI; they run only where `HISN_TEST_ROOTFS` is set.
- Risk lines with `--profile` plus CLI overrides are computed from the profile.
- ADR 0011 comment about "multithreaded" corrected in code; ADR text not re-read.

### Review round 2 (fixes only) and its follow-up
Round 2 delivered from fable only (gpt-6-astra returned VOID on both parts).
Fixed from it: deferred directory chmod re-checks for a symlink that replaced the
directory; directory modes keep owner rwx (defeats cleanup/--replace otherwise);
a failed restore after `--replace` names the `.old-*` path; `refused()` is an
allowlist of bare errno names; the missing-rootfs leak check also requires the
name in the message; the home ownership check uses the same uid as `prepare`.
Not changed: empty `[rootfs]` table is now an error (intended; the previous
meaning was "no rootfs" and the RISK line still printed trust); persist under
`$XDG_DATA_HOME/hisn` is refused (hisn documents no default there); state dirs
are compared after canonicalising only when they exist; `rename` of a dir onto an
empty dir in the no-`--replace` path is not `RENAME_NOREPLACE`; handler panic
leaks one client slot; `rootfs_store::list` filtering of dot-entries unchecked.

## Release-gate review (session 4) — targeted review of the import code

Chunk 1 (`rootfs_import.rs`, non-test): read by BOTH reviewers (gpt-6-astra, fable-5.1).
Chunk 2 (fix commits b16ebb0, 2b35ec3 + `run_import`): first attempt void for both
(429 / VOID); retried once after 60 s, then read by BOTH reviewers.

Fixed (BLOCKING-conditional, one commit):
- Case-/normalisation-insensitive store filesystem could alias `Etc` (archive symlink)
  and `etc`: the symlink set is now case-folded (over-matching only skips entries).
- Names with a leading `.` are no longer valid store names, so `.staging-*` / `.old-*`
  leftovers (which may contain an archive-planted `manifest.json`) can never be listed
  or resolved as a rootfs.
- An archive with zero importable entries is no longer published as an empty rootfs.
- `manifest.json` is fsynced and the store directory is fsynced after publish.

Open points — not done:
- File data is not fsynced before publish; a power loss can publish a torn tree
  (SIGKILL is covered by staging + rename). Needs a recovery/fsync protocol.
- Casefold fix is a string-level guard; a dirfd/`openat2(RESOLVE_BENEATH)` extractor
  would be the real primitive. Unicode NFC/NFD aliasing is not covered.
- Crash leftovers `.staging-*`/`.old-*` are never garbage-collected; `--replace` has a
  window where the name is absent and the old tree is only under `.old-*`.
- Truncated-stream behaviour relies on the `tar` crate erroring (unit test 12 passes
  here); a stream cut exactly on a header boundary is indistinguishable from EOF.
- `hard_link` failures (EXDEV/EPERM) are counted as skipped, not errors.
- `--from-image`: fixed container name `hisn-rootfs-<name>` means a leftover container
  (killed between create and rm) blocks later imports until `docker rm`; using the
  container id and an explicit command for CMD-less images would be better.
- Persist state-dir refusal: `canonicalize(state).unwrap_or(state)` falls back to
  lexical when the state dir does not exist yet; refusal applies only to `home.persist`
  (not to cwd / `mounts.rw` overlapping the hisn store or profiles dir); skipped when
  `HOME` and XDG vars are unset; `geteuid` vs `getuid` only matters for setuid launches.
- `resolve_home_persist` creates the dir (0700) before the trust check for untrusted
  profiles; bounded by the refuse list.
- ssh proxy: client-slot counter is not panic-safe (use a Drop guard); host-agent
  connection has no read timeout.
- No size/entry-count caps on import.

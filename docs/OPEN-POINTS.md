# Open points

Non-blocking findings and known limits. Blocking findings from review rounds
are folded into DESIGN.md (see its §12 deviations table); they are not repeated
here except where residual risk remains.

## Review log

**Round 1 (design review)** — panel: one model answered
(`openai/gpt-6-astra`), the second (`anthropic/claude-fable-5.1`) returned an
empty response, so this round had a single reviewer. The reviewer stated it
had not executed anything; every finding below is an *argument from the
documents*, to be confirmed by host leak tests.

| # | finding | triage | resolution |
|---|---------|--------|-----------|
| 1 | later-created `/etc/*.key` etc. bypass start-time masks (live `/etc` bind) | BLOCKING | D12: `/etc` is a tmpfs of per-entry binds (allowlist at start) |
| 2 | revoke can report success while an `SCM_RIGHTS`-queued fd survives | BLOCKING | D14: soft revoke only claims `guarantee:"lookup"`; `hard` kills every sandbox process |
| 3 | R1–R4 are lexical; a bind alias of the runtime dir inside a recursive tree makes `control.sock` nameable | BLOCKING (host-topology-conditional) | D13: R5 peer-pidns check (primary) + R1b mountinfo alias scan |
| 4 | grant helper does not say how it acquires the sandbox root before its path walk | NON-BLOCKING | P2 |
| 5 | shared-subtree fallback is unproven and conflicts with the private-mount setup | NON-BLOCKING | P1 |
| 6 | holder scan: races, unreadable `/proc` entries, PID reuse | NON-BLOCKING | P3 (unreadable ⇒ holder `unknown`, done in D14) |
| 7 | securebits ordering; `clone3→ENOSYS` is caller-dependent | NON-BLOCKING | P4 |

**Round 2 (implementation review)** — panel: one model answered
(`openai/gpt-6-astra`); the other (`anthropic/claude-fable-5.1`) was cut off at
`max_tokens` and returned nothing. The reviewer saw only part of the files
(not `mounts.rs`, `run.sh`, BRIEF) and, like round 1, ran nothing. Findings and
disposition (no third round is allowed, so everything is closed here or listed):

| # | finding | triage | resolution |
|---|---------|--------|-----------|
| 1 | grant reopens the target by pathname after `move_mount` (rename race); revoke drops its handle before detach succeeds; no rollback | BLOCKING | fixed: handle = the `open_tree` fd (D19), rollback on failure, handle/table entry kept until detach succeeded |
| 2 | L8 accepted any host submount beneath any planned mount, and ignored mount flags | BLOCKING (weak test) | fixed: typed comparator (recursion + ro), 12 self-tests in `tests/leak/test_l8.py` incl. the reviewer's case |
| 3 | Landlock scope "applied" inferred from "requested" | NON-BLOCKING | fixed anyway (D20) |
| 4 | init ordering differs from DESIGN prose; unit test cannot prove caplessness | NON-BLOCKING | DESIGN updated where it differs; runtime caplessness is checked by init's own post-setup verification and by L3 on a host |
| 5 | DESIGN §10 prose contradicted D15/D17 | NON-BLOCKING | DESIGN §10 corrected |
| 6 | proc hardening differs from DESIGN; every `openat2` error treated as "absent" | NON-BLOCKING | fixed: only ENOENT is skipped; DESIGN §4.3 describes the real set |
| 7 | initial rw grants rejected by `grantable_rw` although in the write set; absent Landlock roots skipped silently | NON-BLOCKING | initial rw grants now count as grantable; skipping an absent root remains (nothing to anchor) — P13 |
| 8 | holder enumeration not fail-closed | NON-BLOCKING | fixed: unreadable same-uid process ⇒ enumeration error; unparsable fdinfo / failed map lookup ⇒ `unknown` holder |

## Open

* **P1 — grant mechanism verified on one host only.** Cross-userns
  `move_mount` of a detached tree after `setns(U)+setns(M)` is the brief's
  mechanism. L6/L11/L13 pass on one Fedora host (kernel 7.2, x86_64); other
  kernels/distros and aarch64 remain **[HOST-VERIFY]**.
  The shared-subtree fallback (DESIGN §10) is a *separate design* with its own
  proof burden: it needs a shared root in S, a slave in U, atomic ro
  publication and fd-based revoke equivalent. It must **not** be auto-selected
  at runtime after a syscall failure; if `move_mount` fails, grants fail
  closed (`E_INTERNAL`) and the leaktest reports it. Switching mechanism is a
  design change plus a fresh leak run.
* **P2 — helper root acquisition.** `setns(CLONE_NEWNS)` sets the caller's
  root and cwd to the target namespace's root, but the implementation must not
  rely on that implicitly: after `setns` the helper must `chdir("/")`, open
  `/` as a dirfd, resolve the target **relative to that dirfd** with
  `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`,
  `move_mount` onto the final dirfd, then reopen the *attached* mount root
  (not the covered mountpoint fd). Verify mount ids match in the leak tests.
* **P3 — holder scan precision.** Soft revoke is advisory by definition
  (`guarantee:"lookup"`). Races with `fork`/fd passing are inherent; do not
  strengthen the wording. Hard revoke is the only strong form.
* **P4 — seccomp/caps ordering.** Verify on x86_64 and aarch64: securebits are
  set while `CAP_SETPCAP` is still held (before clearing sets); `clone3`
  `ENOSYS` fallback behaviour of musl/glibc/Go; the compiled filter's
  contents are unit-tested, runtime behaviour only on a host.
* **P5 — nested secrets in bound trees.** Only top-level `/etc` entries are
  allowlisted; secrets created later *inside* a bound directory (a recursively
  bound cwd, `mounts.*`, `/etc/foo.d/`) remain visible. Those trees are the
  user's explicit grant.
* **P6 — single-id uid map**, no `newuidmap` range in v0 (DESIGN D4).
* **P7 — no `/dev/shm`**; some programs (Chrome, some test runners) need it.
* **P8 — terminal escapes** from the command reach the user's terminal.
* **P9 — covert channels / resource exhaustion**: rlimits only; tmpfs sizes are
  bounded but memory-backed; cgroups are v1.
* **P10 — kernel attack surface** (userns + unfiltered syscalls); denylist
  seccomp is defence in depth, not a proof. An allowlist profile is a v1
  candidate.
* **P11 — `network = "host"`** is unfiltered; abstract-socket scope requires
  Landlock ABI ≥ 6 (DESIGN §7).
* **P12 — "grant over mask"** (WAKIL-INTEGRATION §3) is the one place R3 is
  relaxed; keep it restricted to *exact* mask paths.

## Leak tests added beyond L1–L11 (from round-1 findings)

* **L12** host creates `/etc/hisn-test.key` *after* session start → sandbox
  `stat`/`open` must fail ENOENT.
* **L13** revoke with a queued `SCM_RIGHTS` fd: soft revoke must return
  `guarantee:"lookup"` (never `hard`); `hard` revoke must leave the queued fd
  unusable (reader process is dead).
* **L14** fixture with a runtime-dir bind alias under cwd: session start must
  be rejected (R1b) *and*, with R1b disabled by a test hook, the socket must
  still refuse the sandbox peer (R5).
* **P13 — absent Landlock write roots are skipped**, so a `grantable_rw`
  prefix that cannot be opened gives no write rule. The mount plan pre-creates
  every grantable prefix as an empty directory, so this should not trigger;
  unverified on a host.
* **P14 — bind sources are still passed to `open_tree` as pathnames** in
  `rootfs::execute` (targets are fd-walked, sources are the policy's canonical
  paths). A sandbox cannot influence them before it exists, but a concurrent
  host-side rename between policy resolution and session start could redirect
  a source. Dynamic grant sources *are* resolved with `openat2(NO_SYMLINKS)`.
* **P15 — `hisn inspect` and L8 trust the sandbox's own mountinfo** as read by
  the supervisor from `/proc/<init>/mountinfo`; an init that lied would be a
  kernel bug, not a policy bug.

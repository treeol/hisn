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

## Review log — v0.2 exec design

**Round 1 (design review of DESIGN §14)** — a *weak* round, recorded as such.
One reviewer answered (`openai/gpt-6-astra`); the other
(`anthropic/claude-fable-5.1`) was cut off at `max_tokens` and returned nothing.
The answering reviewer stated that its copy of `docs/DESIGN.md` **ended at §13**
(the file on disk had §14, 789 lines), so it reviewed the D21-D24 summaries and
the brief, not the mechanism in §14. It reported **no BLOCKING finding** and
explicitly did not approve §14. Its non-blocking points are P17-P19 below plus
requirements on the host tests (fd inventory per stage, gate lifetime on
failure, a `getppid()==1` proof, env rejection / confinement-equality /
grants-visible tests). Only two review rounds are allowed per task, so §14 was
**not** re-reviewed at design time; the implementation review (round 2) is the
second and last look. Three refinements to §14 were made by the author while
triaging (not by the panel): `C` sets non-dumpable before and after
`setns(user)` and closes the ns fds before forking `D`; `D` keeps the client's
stdio fds at high numbers until `P`; the `getppid()==1` wait is bounded and the
spawn gate is held until `C` is reaped on failure.

## Review log — v0.2 implementation (round 2)

**Round 2 (implementation + tests)** — one reviewer answered
(`openai/gpt-6-astra`), the second (`anthropic/claude-fable-5.1`) was again
cut off at `max_tokens`. The reviewer saw `src/exec.rs` (partly), `src/
control.rs`, `src/supervisor.rs`, `src/init.rs` — but **not** `docs/DESIGN.md`
§14, `tests/leak/run.sh`, `src/execcli.rs` (its copy was truncated), so its
"which leak test is weaker" answer is generic guidance, not a verdict on
L15-L20. No third round is allowed. Disposition:

| # | finding | triage | resolution |
|---|---------|--------|-----------|
| A | `setns(mnt)` does not move root/cwd into the sandbox | BLOCKING (real) | **fixed**: supervisor opens `/proc/<init>/root`, `C` fchdirs onto it after `setns(mnt)` (D25) |
| B | failed-spawn teardown waits only for `C`; `W` may outlive it | NON-BLOCKING (contained) | teardown closes the status socket → `W` SIGKILLs `P` and exits; `C` waits for `D`; `W`/`P` are PDEATHSIG-chained. Residual: if `W` forks `P` *during* the teardown window, `P` is killed by the socket EOF path. **[HOST-VERIFY]** L17 |
| C | handover failure desyncs the helper protocol | BLOCKING (real) | **fixed**: request ids + channel poisoning on ambiguity (D26), unit-tested |
| D | pre-reply client disconnect never cancels | BLOCKING (real) | **fixed**: `drive` pre-cancelled path, TERM-then-KILL (D28), unit-tested (caught the missing TERM) |
| E | errno-pipe EOF conflation | NON-BLOCKING (hardening) | **fixed**: partial/failed read ⇒ exec failure, never success (D27) |
| F | PDEATHSIG race parent died before prctl | NON-BLOCKING | **fixed**: `C` checks `getppid()==0` after setting PDEATHSIG |
| G | leak tests weaker than claimed (L15 filter-identity, L17 reaping, L19 helper fds) | NON-BLOCKING | L15 now asserts `Seccomp: 2` + EPERM set + no-write (filter identity itself is unit-tested); L17 keeps a sleeper alive across session end; L19 watches the supervisor fd only (helpers are short-lived per exec) — **[HOST-VERIFY]** what actually runs on a host |
| H | "reaped by PID 1" wording: P is reaped by W | NON-BLOCKING (wording) | DESIGN §14.3 states the arrangement; W is reaped by init, P by W |

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
  be rejected (R1b). **L14b**: the same alias offered as a *grant source* of a
  running session must be refused (`E_PATH_FORBIDDEN`). The R5 half of the
  original L14 idea (socket still refuses the sandbox peer with R1b disabled)
  was **not** built; see P16.
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
* **P16 - R5 has unit coverage only (accepted for v0).**
  *What the rule claims:* the control socket refuses every peer that is the
  sandbox init or one of its descendants (PPid ancestry, DESIGN §9 R5), so even
  if a bind alias, an inherited fd or any other topology accident made
  `control.sock` *nameable* from inside the sandbox, no sandbox process could
  issue a grant. Undecidable ancestry refuses (fail closed).
  *Why unit coverage is accepted:* the decision is a pure function
  (`supervisor::authorize_peer`, five tests: same-uid host peer allowed, in-tree
  peer refused by either signal, other uid refused, every missing fact refused)
  over facts gathered by `sys::is_descendant_of`, which is tested on the real
  process tree. R5 is defence in depth behind R1/R1b, which are tested end to
  end (L6, L14, L14b, L11); R5's own failure mode on a real host, refusing a
  legitimate client, *is* exercised end to end by every L6/L11/L13 control
  call (it regressed once, `10dcb86`, and the suite caught it).
  *What an end-to-end test would require:* a sandbox process that can name and
  connect to `control.sock`, i.e. either (a) a test-only supervisor option that
  bind-mounts the session dir into the sandbox, deliberately defeating R1/R1b,
  or (b) a host fixture in which the alias survives R1b. (a) adds a way to
  weaken the isolation to the production binary or needs a separate
  `cfg(test)`/feature-gated build of the supervisor, so the leak suite would no
  longer test the shipped binary; (b) does not exist, because R1b exists to
  prevent it. Revisit if R1b is ever relaxed.
* **P17 — exec'd processes are sibling Landlock domains.** Each exec applies
  its own ruleset (DESIGN §14.12), so with ABI >= 6 scoping an exec'd program
  cannot signal, or connect abstract unix sockets of, the main command or
  another exec's processes (`EPERM`). Stricter than needed but a behaviour
  change tool authors may trip over; the supervisor-side `signal` op is not
  affected. Alternatives (one shared domain) would need init to fork the
  program, which §14.10 rejects.
* **P18 — Landlock write roots in exec are re-resolved by pathname** (§14.12).
  Can only weaken, never widen; fix = inode-anchored root fds captured at
  start.
* **P19 — exec confinement window is argued, not shown.** `D` holds
  capabilities in the sandbox userns from `setns(user)` until `drop_all_caps`.
  The design closes the known routes (non-dumpable before and after the userns
  join, no inherited ns fds, seccomp denies `ptrace`/`process_vm_*`/
  `pidfd_getfd`, `/proc/<D>/*` unreadable when non-dumpable) but the *absence*
  of a route is only demonstrable on a host: L17/L15 check the end state (all
  five cap sets zero, NNP, seccomp 2 in the exec'd process), not the window.
  A hostile-probe test that races `/proc/<pid>/{mem,fd,status}` of new
  processes during a burst of execs is a v0.3 candidate.

* **P20 — RESOLVED (build-sandbox artifact): HUP is not delivered here.** The
  `monitor_forwards_signals_to_the_process_group` unit test used SIGHUP and
  failed "randomly" (second run, under `tools/verification.sh`, …). Root
  cause, proven in the sandbox with plain shell: `kill(-pgid, SIGHUP)`
  returns 0 **and the target survives** in this build container (HUP is
  swallowed somewhere in its process supervisor), while SIGTERM works. Every
  failure was the test's child living to its natural `sleep 60` death
  (`Code(0)`), with the monitor's forwarding path instrument-verified as
  correct (every `K` line popped, `signal_group` executed, kill returning 0).
  No hisn defect: `signal_group` forwards whatever signal was requested, and
  on a normal host HUP kills. The test now uses SIGTERM (and notes the
  artifact). Residual: **[HOST-VERIFY]** that HUP delivery through the exec
  `K` path works on a real host (L16/L19 cover signal delivery generally). Under the script the test
  fails after exactly the child's sleep timeout with `got=Code(0)`;
  40+ direct runs are green. Instrumented runs (commit history) proved the
  shipped path works: the monitor pops every `K` line from the status socket
  and calls `signal_group` (no error), i.e. the forward mechanism itself is
  correct; the anomaly is the *child's* exit-status attribution
  (`sh -c 'sleep 60'` exiting 0 despite a delivered SIGHUP to its group) in
  the double-run script context. The on-failure diagnostic in the test
  (`P20 diag: got=… child_alive=… unread_status_bytes=…`) captures the facts
  if it recurs. Because the shipped `monitor`/`signal_group` path is
  instrument-verified and the failure mode is confined to this unit test,
  P20 stays open as a test-quality question, with **[HOST-VERIFY]** L16/L19
  as the authoritative check of signal delivery to real exec'd programs. In
  two `tools/verification.sh` runs, `exec::tests::monitor_forwards_signals_to_
  the_process_group` failed after exactly the child's `sleep` timeout: the
  `K <sig>` line the test wrote to the status socket never reached
  `signal_group`, so the child died naturally. 25 isolated runs of the same
  test and 5 sequential full-suite runs were green; the two failures happened
  only while the script ran other work around the suite. If the loss is real
  in `monitor`'s read loop (not a test artifact), a lost `K` line means a
  cancelled exec is never killed. **[HOST-VERIFY]**: L16/L19 on a real host
  (signal delivery to a running exec, 50+10 execs) plus a targeted burst test
  would settle it. The test now waits for the child to be signalable before
  writing (`8287313`), which removes the spawn/exec race as a cause.
* **P21 — teardown-B residual.** A `W` that exists when a failed spawn is
  torn down gets the socket-EOF kill path, but the supervisor does not
  *observe* `W`'s death (only `C`'s). If `W` ignored the EOF, a hard revoke
  would still sweep it (it is in init's tree), so the gate release is safe;
  the residual is only about prompt resource reaping. **[HOST-VERIFY]**.

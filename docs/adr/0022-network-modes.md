# ADR 0022 — Network modes: none / allowlist / open via connect interception

Title: Controlled outbound network for sandboxed sessions — `none` (unchanged
default), `allowlist`, and `open`, implemented by intercepting `connect()`
with seccomp user notification and letting the supervisor decide.

Status: Accepted (implemented 0.6.0, open mode). Date: 2026-11-16, implementation note 2026-11-17. Origin: the connect-interception
probe series (`.wakil/probes/connect-notify/`, passes 1–6; report
`.wakil/reports/probe-connect-notify.md`). This ADR replaces the transport
design of ADR 0018 (a host-side HTTP/SOCKS proxy) with a `connect()`
interception transport that works for any TCP client without the client
knowing, and that keeps the empty netns as the security boundary. ADR
0018's policy language (`[net] allow`, default deny, rebinding guard)
carries over; its proxy transport does not.

## Phase 0 — what hisn does today (read in src/, before designing)

- **Namespaces.** `network = "none"` adds only `CLONE_NEWNET` to the init
  clone: `NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS` (+ `NEWNET` iff
  `Network::None`) (`src/supervisor.rs:3401-3408`). The supervisor first
  unshares `NEWUSER|NEWNS` + uid/gid maps, then clones init;
  init brings up loopback only (`src/init.rs:393`, SIOCSIFFLAGS, no route,
  no DNS setup). The netns fd is opened pre-GO while init is still
  dumpable (`src/supervisor.rs:3431`) and passed to the exec helper, which
  `setns()`es net before the program runs (`src/exec.rs:894-898`).
- **Ancestor chain.** supervisor (host, in userns S) → init (PID 1, direct
  clone child, `PDEATHSIG=SIGKILL`, `src/init.rs:89`) → D (exec helper:
  sets `PR_SET_DUMPABLE=0` at `src/exec.rs:962`, again at `:983`) → W →
  P (the program, after `execve`). The supervisor stays an ancestor of
  every sandboxed program for the program's whole life. **execve resets
  dumpable to 1 even with `no_new_privs`** (probe pass 4, measured), so
  the running program P is dumpable and readable by its ancestor under
  Yama `ptrace_scope=1`.
- **Seccomp denylist.** `BASE_DENY` (`src/seccomp.rs:127-177`) contains
  `mount`, `unshare`, `ptrace`, `io_uring_*`, etc. — **not** `connect`,
  `socket`, `socketpair`, `sendto`, `sendmsg`, `sendmmsg`. `socket` and
  `connect` appear only in the `COMMON` lookup table
  (`src/seccomp.rs:107-108`) so profiles *could* name them in
  `extra_deny`; a test asserts they stay ALLOW by default
  (`src/seccomp.rs:472-497`). Kernel precedence is
  KILL > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW, so an ERRNO
  verdict for `connect` from any stacked filter would outrank the
  USER_NOTIF verdict; hisn must never put `connect` in `extra_deny`.
  `seccompiler 0.5.0` (`Cargo.toml:26`) builds `SeccompAction::{Allow,
  Errno, KillThread, KillProcess, Log, Trace, Trap}` only
  (`src/seccomp.rs:273-281`) — no `UserNotif`; the interception filter
  must be hand-written BPF, following the x32-guard precedent
  (`src/seccomp.rs:301-312`).
- **Filesystem view of host sockets.** `/run` is a **fresh private
  tmpfs**, not the host `/run` (`src/mounts.rs:664-672`); `/tmp` likewise
  (`:655-663`); `/var`, `/sys`, `/home`, `/root` are never mounted
  (`:1432-1435`). So by default the sandbox sees **no** host
  `/run/user/<uid>`, no dbus (`/run/dbus`), no docker/podman socket, no
  `/run/systemd/resolve/io.systemd.Resolve`, no `/var/run`. The only
  host trees visible are toolchain dirs read-only (`/usr /bin /sbin
  /lib /lib64 /opt /nix`), `cwd` rw, and explicitly granted
  `[[forward]]` / `[[host_services]]` / `[docker]` mounts, each behind
  `risk_ack` (`src/profile.rs:907-955`). ssh-agent is a filtering proxy
  bound in the session dir, forwarded to `/run/ssh-agent.sock`
  (`src/ssh_agent.rs:14-17`). The host `/etc/resolv.conf` is read
  out-of-band; only `network = "host"` sessions get a generated
  resolv.conf (`src/mounts.rs:63-69,124-169`). Landlock has **no**
  network scope: only `AccessFs` PathBeneath rules
  (`src/landlock.rs:88-118`) — it cannot restrict `connect()` to unix
  sockets; the mount view above is what hides host sockets.
- **Policy storage.** Profile: `[policy] session.network` (enum
  `Network::{None, Host}`, `src/policy.rs:41-44`) + optional `[net]
  nameservers` (`src/profile.rs:382-386`, validated non-loopback).
  `session.json` records `network: "none"|"host"` and
  `protocol_revision` (`src/sessionmeta.rs:113-142`); the wire revision
  is `PROTOCOL_REVISION = 3` (`src/sessionmeta.rs:43`), the only version
  compared (`client.protocol_version`; absent = rev 1; higher declared
  → `E_VERSION`). Authz: `allows(role, op)` with roles
  `Owner > Member > Observer` (`src/authz.rs:115-122`); `required_role`
  (`:184-190`) gates every op by table. Nothing runtime reads
  `ptrace_scope`; no Yama handling exists in `src/`.

## Context and the probe verdict

hisn today offers only `network = "none"` (empty netns, loopback, no
route) and `network = "host"` (shares the host netns, unfiltered).
ADR 0018 (draft, not in the tree) proposed an allowlist proxy for the
`host` mode; it was never built. The question this ADR answers: can the
supervisor decide each outbound `connect()` from inside the empty netns,
transparently, for any agent, with no manual work — and is that safer
than sharing the host netns? The probe series ran on a Fedora 45 host
(kernel 7.3.3-300.fc45.x86_64); every probe compiles with
`gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2`.

One table: fact → probe case → host result. Host results are only from
host output pasted after each pass; pass-6 host results are pending.

| Fact | Probe case | Host result |
|---|---|---|
| `USER_NOTIF` on `connect()` + supervisor connects in host netns + `NOTIF_ADDFD` hands the socket in | Q1 | PASS |
| Same, across a user+net namespace boundary | Q2 | PASS |
| Blocking, non-blocking, IPv6 connects; real curl/python3/git unmodified | Q3/Q3b | PASS |
| ~20–25 µs extra per intercepted connect (5.2 ms/100 vs 3.3 ms/100) | Q5 | PASS |
| Supervisor death → pending `connect()` returns `ENOSYS` (38) | Q5/G | PASS |
| Supervisor (ancestor in the owning userns) reads the `sockaddr` of the exec'd program via `process_vm_readv` **and** `/proc/<pid>/mem`; execve resets dumpable to 1 even with NNP so the program is readable; `NOTIF_ID_VALID=0` after the read | B2 | PASS |
| A non-dumpable process that never exec'd cannot be read (EPERM). This does not carry over to a program inside a hisn sandbox, see the correction under connect-flow step 2. | B1 | INFO (as expected) |
| Loopback, unix-path and abstract-unix connects continue via `CONTINUE` | C1–C3 | PASS |
| `CONTINUE` is subject to a TOCTOU race (child rewrites the buffer): 22 of 2000 rewrites won (`continued=1975, refused=25`); harmless only because the netns is empty. Pass 6 measured `enetunreach=47, refused=25, continued=1975, attempts=2000, toctou_wins=22`. | C4 pass 6 | INFO (race measured) |
| `sendto`/`sendmsg`/`sendmmsg`/`MSG_FASTOPEN` to outside addresses fail `ENETUNREACH` in the empty netns; control from host namespace reaches | E1–E4, E-control | PASS |
| Socket options survive the swap when copied via `pidfd_getfd`; `SO_RCVBUF`/`SO_SNDBUF` read back 2× the requested value, so the supervisor requests half | F | PASS |
| A program's own nested filter with ALLOW for `connect` does not break interception; its own ERRNO filter wins over the outer `USER_NOTIF` (only for that program) | H1, H3 | PASS |
| A second listener in one filter chain fails `EBUSY` (errno=16) | H2 pass 6 (preconditions checked) | PASS |
| A stalled supervisor blocks the sandboxed process indefinitely (`seccomp_do_user_notification`) | pass-4 host finding 3 | observed (old `probe_d` still blocked) |
| DNS through the supervisor | D1a–D3 (not proven by the probe: the probe's DNS socket was not served inside the sandbox netns, so `dns_queries=0`; D1b already had `hosts: files dns` and still failed) | not proven by the probe — covered by L94 on the host |

**DNS was not proven.** Pass 6's draft claim — "host `/etc/nsswitch.conf`
is `hosts: files dns`, nss-resolve hypothesis refuted" — was read from
inside a hisn session, which sees the session's own `/etc/nsswitch.conf`.
A real host's file (from pasted host output) is
`hosts: files myhostname mdns4_minimal [NOTFOUND=return] resolve
[!UNAVAIL=return] dns`. `nss-resolve` therefore runs before `dns` and
answers or stops the chain, and the probe reached `Temporary failure in
name resolution` with `dns_queries=0`. The correction is recorded in
`.wakil/reports/probe-connect-notify.md` (Pass 6 + final summary). The
failure is probe plumbing (no sandbox-local `hosts: files dns` nsswitch,
DNS socket placement), not a kernel result. The design below makes
hisn ship its own sandbox nsswitch + resolv.conf, which removes the
host's nss-resolve from the path entirely — but **DNS must be re-tested
on the host with that in place before the design can claim it works**,
and the test plan includes exactly that.

## Decision

The eleven decided points, refined by Phase 0. Points 1, 2, 3, 6, 10 are
unchanged from the task; the rest are stated with their refinement.

1. **Three modes.** `none` (unchanged, stays default), `allowlist`,
   `open`. `open` uses the same interception with an allow-all policy
   and full journaling. hisn never shares the host netns; `network =
   "host"` is **unchanged with a deprecation warning, not aliased** to
   `open` (Valon's decision, 2026-11-16). `Network` gains two
   variants (`src/policy.rs:41-44`). **`open` is not "host":** the
   supervisor connects from the host netns, so `open` can reach
   host-loopback services — see the Threat model and the connect-time
   private-address block below, which applies to `open` too. A
   `NETNS` startup assertion is required: the supervisor verifies its
   own `/proc/self/ns/net` inode differs from init's and fails closed
   otherwise, so a new mode that accidentally omits `CLONE_NEWNET`
   (the worst possible silent failure) cannot start.
2. **The empty netns is the security boundary; interception is only the
   controlled exit.** No design element relies on the supervisor seeing
   every `connect()`. Everything outside `connect()` (all of case E:
   `sendto`/`sendmsg`/`sendmmsg`/`MSG_FASTOPEN`) already fails with
   `ENETUNREACH` in the empty netns, so there is no path out the
   supervisor does not decide — the supervisor's job is to *allow*, not
   to *see everything*. **Every new mode creates `CLONE_NEWNET` and
   opens `open_ns(pid, "net")`** — the `Network::None`-only gating in
   `src/supervisor.rs:3400-3435`, `src/init.rs` loopback-up, and the
   exec-helper `setns(net)` must all treat `Allowlist`/`Open` like
   `None` (Mashūra plumbing gap). Landlock: hisn does not use Landlock
   network rules today (`src/landlock.rs:88-118` is `AccessFs` only);
   the kernel ABI has had TCP connect/bind rights since ABI v4, but
   they cannot express hostname pins or unix sockets, so v1 adds none —
   stated explicitly, not assumed away.
3. **Hostname allowlist is DNS-pinned.** hisn runs a DNS responder on
   `127.0.0.1:53` (UDP and TCP) inside the sandbox netns, bound before
   the filter is installed and before exec. It forwards only allowed
   names to the host resolver (the existing resolver discovery in
   `src/mounts.rs:63-169`, reused: upstreams from the host file or
   `/run/systemd/resolve/resolv.conf`), answers NXDOMAIN for everything
   else, and remembers `(name, ip, expires)` for every address it
   handed out, expires = answer TTL + 60 s grace. **Authorisation test
   (exact):** a `connect()` to `ip:port` is allowed iff there is an
   explicit IP/CIDR rule matching `ip:port`, **or** there is an allow
   rule matching `(queried_name, port)` and `ip` is a live pin for that
   name. CNAME chains pin the terminal name's addresses but are checked
   against the originally queried name; A/AAAA pins are kept per-family;
   TTL=0 answers are never pinned; trailing-dot and IDNA/punycode
   spellings of the same name are normalised to one comparison key.
   hisn mounts its own `/etc/resolv.conf` (`nameserver 127.0.0.1`) and
   `/etc/nsswitch.conf` (`hosts: files dns`, plus `passwd: files` /
   `group: files`), ignoring the host's nss-resolve entirely — in
   `allowlist` and `open` alike. This removes the exact failure the
   probe hit. **In `none`, no resolv.conf/nsswitch is added** — `none`
   stays byte-identical to today; adding files there would be a
   behaviour change to the default mode (Mashūra finding).
   **Who runs the responder (Mashūra BLOCKING 2).** init (or `E` for
   exec trees) brings up loopback for all three modes **before
   `drop_all_caps()`**, binds `127.0.0.1:53` (UDP+TCP) there, and
   passes the bound fds to the supervisor via `SCM_RIGHTS` in the
   `READY` handshake. The supervisor runs the responder thread on
   those fds; the pin store lives in the supervisor. If port 53 is
   already taken by an in-sandbox service, the session refuses to start
   with a clear error. **Upstream transport.** The responder forwards
   allowed queries with sockets created in the host netns — never via
   an intercepted `connect()`, never via a general UDP path out of the
   sandbox. Responder death fails DNS closed (`SERVFAIL`) and is
   journaled; there is no fallback resolver in the sandbox.
4. **Only `connect()` is intercepted in v1 — and only for stream sockets.**
   `connect()` on a `SOCK_DGRAM` socket (QUIC/HTTP3, STUN, WireGuard,
   glibc's RFC 6724 source-address probing) is **refused** with
   `EACCES`, never injected: the supervisor reads `SO_TYPE` via
   `pidfd_getfd`+`getsockopt` and refuses anything that is not
   `SOCK_STREAM` for IP connects (Mashūra BLOCKING: `open` must not
   become a silent UDP exit). Outbound UDP beyond DNS is therefore
   unsupported in v1 by construction. Clients that support fallback
   (most HTTP stacks) drop to TCP; clients that do not fail with a
   clear `EACCES` (documented limitation L104). `sendto`/`sendmsg`/
   `sendmmsg`/`MSG_FASTOPEN` to outside addresses fail `ENETUNREACH`
   in the empty netns regardless (case E).
5. **Loopback and abstract unix connects CONTINUE; path unix sockets are
   the filesystem view's job.** Loopback (`127.0.0.0/8`, `::1`) and
   abstract unix → `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (C1–C3). Path unix
   connects are **always CONTINUEd**; the kernel's mount-namespace path
   resolution then returns `ENOENT` for a hidden host socket (matching
   test L97) or reaches the in-view socket (matching its mount
   grant). The supervisor does **not** return `EACCES` for path unix —
   it would have to resolve the path in the sandbox's mount namespace,
   which it cannot do from the host mount ns (Mashūra finding 4).
   Phase 0 shows the mount view already hides every host socket by
   default: `/run` is a fresh tmpfs (`src/mounts.rs:664-672`), so
   `/run/user/<uid>`, dbus, docker/podman, and
   `/run/systemd/resolve/io.systemd.Resolve` are invisible unless a
   profile grants one explicitly through `[[forward]]` /
   `[[host_services]]` (risk-gated). Path unix connects are therefore
   governed by mount visibility in all three modes. **Every other
   `sa_family`** (`AF_VSOCK`, `AF_NETLINK`, `AF_BLUETOOTH`, `AF_ALG`,
   `AF_PACKET`, …) is refused with `EACCES` unless it is
   `AF_INET`/`AF_INET6`/`AF_UNIX`: vsock is not governed by the IP
   netns at all, and an explicit refuse is the only safe default
   (Mashūra BLOCKING 5). `AF_NETLINK` is refused too. Netlink to the
   local kernel is not needed inside the sandbox.
6. **Every notification has a deadline, answered by a concurrent
   supervisor.** The supervisor is **not** single-threaded:
   the `NOTIF_RECV` loop only dispatches; each notification is handled
   by a worker (bounded pool, e.g. 64) that does the read, the decision,
   and the outbound connect — so one blackholed IP cannot head-of-line
   block every other `connect()` in the sandbox (Mashūra BLOCKING 3).
   The deadline (default 30 s for the outbound connect, decision 6,
   configurable per `[net]`) runs from dispatch; on expiry the worker
   replies `-ETIMEDOUT` **from the worker**, never by waiting for the
   wedged thread. When the queue is full, new notifications are
   refused with `EACCES` immediately (fail closed). Outbound connects
   in the supervisor are made **non-blocking** with an async completion
   state machine; the deadline applies to the completion, not to a
   blocking syscall. Supervisor death: the probe measured `ENOSYS`
   for a pending `connect()` (kernel behaviour, Q5/G), but a program
   in a hisn session never sees it, because sandbox init and the exec
   helper are killed with the supervisor (`PR_SET_PDEATHSIG`) and every
   program dies with them (L100).
   `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19) is optional
   hardening, not the deadline mechanism.
7. **Atomic handover with option copy — `SETFD` is mandatory, always.**
   The socket is injected with
   `SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SETFD` +
   `SECCOMP_ADDFD_FLAG_SEND`, `newfd = notif.data.args[0]` (the
   child's original fd number). **Without `SETFD`, `ADDFD` allocates a
   new fd number and the child's `connect()` succeeds on an
   unconnected socket while its original fd stays disconnected**
   (Mashūra BLOCKING 3/7). `SETFD` requires kernel 5.0; `FLAG_SEND`
   requires 5.14, and without it the fallback is `SETFD` + a separate
   `NOTIF_SEND` (decision 10). Before injecting, the supervisor takes
   the child's original socket via `pidfd_getfd` (supervisor is the
   ancestor, B2), reads `O_NONBLOCK`, `SO_REUSEADDR`, `SO_RCVBUF`,
   `SO_SNDBUF`, `SO_KEEPALIVE`, `TCP_NODELAY`, and sets them on its new
   socket — requesting **half** the read value for the two buffer
   sizes (case F). A prior `bind()` by the child (source address/port)
   is lost on a fresh socket; the supervisor cannot reconstruct it —
   documented limitation L105; programs that bind before connect lose
   their local address choice. Epoll registrations are lost on fd
   replacement (probe F); the client re-registers after `connect()`
   returns, same as with any fd replacement. **Blocking and
   non-blocking sockets:** the supervisor creates its socket, copies
   the options as above, sets `O_NONBLOCK` on it and calls `connect()`:
   - returns 0 → inject with `SETFD` to args[0], reply 0 (reason
     `injected`);
   - returns any other error than `EINPROGRESS` → no injection, reply
     that `-errno` (`ECONNREFUSED`, `EHOSTUNREACH`, …), never a generic
     `EACCES` (Mashūra finding 6);
   - returns `EINPROGRESS` and the program's socket is **blocking** →
     wait for the result under the deadline, then inject and reply 0,
     or reply the connect's `-errno` (`ETIMEDOUT` at the deadline);
   - returns `EINPROGRESS` and the program's socket is **non-blocking**
     → inject the connecting socket with `SETFD` to args[0] (`ADDFD`
     without `FLAG_SEND`), then `NOTIF_SEND` with `-EINPROGRESS`
     (reason `injected-inprogress`). The program sees `EINPROGRESS` and
     later `POLLOUT`/`SO_ERROR` on that socket. `EINPROGRESS` is only
     sent after the injection succeeded; if it fails the supervisor
     closes its socket and replies `EACCES`. The supervisor keeps its
     own descriptor of the socket and journals how the connect ended
     (decision 8); it must never read `SO_ERROR` through it, because a
     pending socket error is delivered to one reader only.
   If the program's `O_NONBLOCK` state cannot be read the connect is
   refused (`EACCES`), never guessed.
8. **Every connect decision is a journal record.** One `network/connect`
   record per notification, workspace journal (ADR 0020): `target`
   (ip:port or unix path), `resolved_name` when the pin knows it,
   `verdict` (`allow`/`refuse`/`continue`/`dns`), `latency_ms`,
   `seat` (attribution: the exec's `client`, same field as exec
   records), `session`, `wseq`. Workspace-wide, like every other record;
   it is how a user answers "what did my agent reach" without asking
   the agent.
9. **Runtime policy change is owner-only, journal-only, future connects.**
   A new op `net-policy-set` (below) requires role `owner`
   (`src/authz.rs:115-122`); it updates the supervisor's live policy
   table and a `net/policy.json` in the workspace state dir, journaled
   as `network/policy-changed`. It does not recreate namespaces and
   does not affect in-flight connects. There is no op to widen a
   *running* session's netns; nothing can create a route.
10. **Fail closed on missing kernel features.** `allowlist`/`open` check
    at startup: `SECCOMP_RET_USER_NOTIF` (5.0),
    `SECCOMP_FILTER_FLAG_NEW_LISTENER` (5.0),
    `SECCOMP_IOCTL_NOTIF_RECV`/`SEND`/`ID_VALID` (5.0),
    `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (5.5),
    `SECCOMP_IOCTL_NOTIF_ADDFD` incl. `SETFD` (5.9),
    `SECCOMP_ADDFD_FLAG_SEND` (5.14), `SO_NETNS_COOKIE` (5.14, 0.6.1;
    hard floor). If a hard-floor feature is missing,
    startup fails with a clear error naming the feature and the minimum
    kernel. `none` never touches these and keeps working.
    Minimum kernels: **floor 5.14** (0.6.1: `SO_NETNS_COOKIE`, needed to
    tell a socket in the sandbox's namespace from one in the
    supervisor's; with it `FLAG_SEND` one-step injection is always
    available). 0.6.0 had floor 5.9 (`SETFD` + a separate `NOTIF_SEND`
    on 5.9–5.13); the code still injects in two steps on every kernel
    (see "Implementation (0.6.0)"), which is not reachable as a
    5.9–5.13 path any more because those kernels refuse to start.
    Sources: `seccomp_unotify(2)`, `seccomp(2)`, `pidfd_open(2)`,
    `pidfd_getfd(2)` (Linux man pages).
11. **Separate hand-written BPF filter.** The interception filter
    (`connect` → `USER_NOTIF`, everything else → `ALLOW`) is
    hand-assembled, following the x32-guard precedent
    (`src/seccomp.rs:301-312`). `seccompiler` cannot express it. The
    existing denylist stays exactly as it is and **must not** return
    ERRNO for `connect` (precedence, Phase 0): `extra_deny` entries
    `connect`/`socket` are rejected at profile validate with a message
    pointing at this ADR.

**Where the single listener is created (refined).** The listener is
created **once per exec helper chain, not once per session**, because
seccomp filters are inherited only across `fork()`/`clone()` — the exec
helper `E` is forked by the **supervisor** (`start_helpers`), not by
sandbox init, so `hisn exec` / `hisn attach` / `[[services]]` programs
would otherwise never see the `USER_NOTIF` filter (Mashūra round-1
finding 1, confirmed in `src/supervisor.rs`/`src/exec.rs`). The design
is therefore: the supervisor spawns `E`, which installs the
`connect`→`USER_NOTIF` filter with `NEW_LISTENER` (one filter, one
listener per *exec tree* — `EBUSY` forbids a second listener in the
same chain, H2) and sends the listener fd to the supervisor over the
existing helper socketpair via `SCM_RIGHTS` (the `send_with_fd` idiom,
`src/sys.rs:468-494`), **before** `helper_loop` starts accepting work.
`E` itself never calls `connect()` after installing, so the filter
never intercepts the helper's own traffic. init's main command follows
the same pattern: init installs its own listener at
`src/init.rs:150` (after caps drop, before `PR_SET_DUMPABLE=0`) and
hands it to the supervisor over the `sup_end`/`init_end` socketpair.
Two listeners per session (init's + each exec tree's) are distinct
chains — the kernel's one-listener rule is per chain, not per session.
A leak test for an **exec'd** program (not only the main command) is
required (L103).

## Policy format

Profile TOML, under the existing `[net]` table (`src/profile.rs:382`):

```toml
[policy.session]
network = "allowlist"        # none (default) | allowlist | open

[net]
mode = "allowlist"           # same value; [policy.session.network] wins on conflict (validate error if both, different)
allow = [
  "github.com:443",          # name + port  (DNS-pinned)
  "*.example.com:443",       # one-label wildcard; see below
  "192.0.2.10:443",          # explicit IP + port (no DNS involved)
  "10.0.0.0/8:8080",         # CIDR + port
  "pypi.org:443",
]
nameservers = ["1.1.1.1"]    # existing key; host resolver used when absent
connect_deadline_s = 30      # default; decision 6
```

- Host entries: `name` or `*.suffix` + mandatory `:port` (or `:port1-port2`).
  `*.suffix` matches exactly one label (`a.example.com`, not `example.com`
  itself, not `a.b.example.com`); the bare name must be listed separately.
- IP entries never go through DNS; a name that resolves to an IP needs
  either the name listed or the IP/CIDR listed (rebinding guard from
  ADR 0018 — a name may not smuggle in an unlisted address).
- `open` ignores `allow`; an empty `allow` under `allowlist` means
  deny-all (loopback/unix only) — stated on stderr at startup so it is
  never a silent hole.
- Defaults: mode `none`, deadline 30 s, resolver = host's.
- What a seat/agent sees: nothing to configure. The effective policy is
  readable via `hisn net explain <host[:port]>` (prints the decision the
  supervisor *would* make for that target, using the same rule above —
  no connection is attempted) and `hisn net status` (mode + allow list),
  and every decision lands in the journal (`hisn journal --kind
  network`). An agent that wants a host added asks the user to update
  the profile; there is no self-serve widening (decision 9).

## Connect flow and DNS flow

Connect (allowlist/open), per notification, in this exact order:

1. Supervisor polls the listener (`poll` 2 s, child-exit aware via
   `waitid(WNOWAIT)`), receives the notification, dispatches it to a
   worker (decision 6). The 30 s deadline starts at `NOTIF_RECV`.
2. `NOTIF_ID_VALID` **read once, before the sockaddr read**; opens a
   pidfd for `notif.pid`; validates `addrlen` (`>= sizeof(sa_family_t)`,
   `<= sizeof(sockaddr_storage)`, and the family-specific minimum for
   `AF_INET`/`AF_INET6`) — out of range → `-EINVAL`. Reads the
   `sockaddr` of the notified task with `process_vm_readv`, at most
   `sizeof(sockaddr_storage)` bytes, **once**, into a private buffer
   (B2; a racing rewrite after the read is harmless — the supervisor
   acts on its copy). `NOTIF_ID_VALID` again before replying. If the
   read fails → reply `-EACCES`, journal `refuse/read-failed` (fail
   closed; covered by a unit test that simulates a failed read).
   **Correction (0.6.0, measured on kernel 7.3.3):** an earlier version
   of this step said that a program which sets `PR_SET_DUMPABLE=0`
   after exec cannot be read and is refused. That is wrong. After exec
   inside the sandbox the program's memory belongs to the sandbox user
   namespace, which the supervisor owns, so the supervisor holds
   `CAP_SYS_PTRACE` there and may read a non-dumpable target. The
   probe's B1 `EPERM` came from a process that never exec'd, whose
   memory still belonged to the initial namespace. A program therefore
   cannot hide its connects by making itself non-dumpable: the connect
   is intercepted, decided and journaled like any other (L110).
3. **Loopback and `AF_UNIX` `CONTINUE` — before the `SOCK_STREAM` check.**
   `AF_UNIX` (path/abstract, decision 5) always `CONTINUE`s. Loopback
   (`127.0.0.0/8`, `::1`) always `CONTINUE`s *regardless of socket type*,
   so DNS over UDP to `127.0.0.1:53` (leak case L112) works in `open`
   (loopback always stays inside the sandbox netns; never forwarded;
   host services only via `[[host_services]]`/`[[forward]]).
4. `SOCK_STREAM` check: refuses any non-`SOCK_STREAM` non-loopback IP
   connect with `EACCES` (decision 4). Other families (vsock, …) → `EACCES`.
5. **Private-address block (Mashūra BLOCKING 4 — applies to `open`
   too).** At connect time, in **both** modes, the supervisor refuses
   unspecified, multicast, loopback, link-local (`169.254.0.0/16`,
   `fe80::/10`, incl. the metadata address `169.254.169.254`), CGNAT
   (`100.64.0.0/10`), RFC1918, ULA (`fc00::/7`), `198.18.0.0/15`
   (benchmarking), `0.0.0.0/8`, `240.0.0.0/4` (reserved, incl.
   `255.255.255.255`), site-local `fec0::/10`, and the forms that
   embed an IPv4 address, classified by that address: IPv4-mapped,
   IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`
   and Teredo `2001::/32` (the client address is stored inverted, and
   both the server and the client address must be public). The
   local-use NAT64 prefix `64:ff9b:1::/48` is refused as a whole —
   **unless** an explicit IP/CIDR rule matches that exact target
   (0.7.0; 0.6.0 has no rules). Loopback is *not* in this list as a
   refusal: loopback always
   stays inside the sandbox netns (step 3, never forwarded; host
   services only via `[[host_services]]`/`[[forward]]`). A DNS pin
   alone never authorises a non-public address. This is what stops
   `open` from silently reaching host-loopback daemons: `open` is
   allow-all *public*, not allow-all at all.
6. On allow: copies socket options from the child's original socket
   (`pidfd_getfd`; buffers halved) onto the new socket, restores the
   child's original `O_NONBLOCK` state, connects non-blocking from the
   host netns, injects with `ADDFD|SETFD` (+ `SEND` on 5.14+; two-step
   `SETFD` + separate `NOTIF_SEND` on 5.9–5.13), replies 0 with the
   injected fd. If the outbound connect fails, replies `-errno` from
   that connect (`ECONNREFUSED`, `EHOSTUNREACH`, …), never a generic
   `EACCES`. A non-blocking program socket is injected while the
   connect is still in progress and answered `EINPROGRESS` (decision
   7); the client's `poll(POLLOUT)`/`SO_ERROR` then report the outcome
   of that connect. Journal failure never blocks a verdict.
7. IPv4 and IPv6 are handled identically; the sockaddr family comes
   from the supervisor's copy. Deadline runs from `NOTIF_RECV`
   (decision 6).

**DNS flow (decision 3, as shipped).** The responder socket is bound by
init on `127.0.0.1:53` (UDP+TCP, before caps drop) and handed to the
supervisor over `SCM_RIGHTS`. The supervisor forwards queries to the
first of these that names a resolver: `[net] nameservers`,
`/run/systemd/resolve/resolv.conf`,
`/run/NetworkManager/no-stub-resolv.conf`, `/etc/resolv.conf`.
Loopback resolvers such as `127.0.0.53` are valid, because the
supervisor is in the host netns. If none names a resolver, the session
does not start and the error lists the files. The responder answers
`SERVFAIL` when the upstream fails or does not answer in 2 s. The
sandbox ships its *own* `/etc/resolv.conf` (`nameserver 127.0.0.1`) and
`/etc/nsswitch.conf` (`hosts: files dns`) so the host's nss chain is
not in the path. The earlier DNS probe failed (`dns_queries=0`)
because its DNS socket was not served inside the sandbox netns — the
probe's own socket was never populated; D1b already had
`hosts: files dns` and still failed for that reason. The probe result
is therefore *not* evidence for or against the shipped responder; L94
on the host is the gate (the script's `192.0.2.2:53` server can only
be reached through the shipped files + responder).
`network = "none"` gets neither file (byte-identical to 0.5.1);
`network = "host"` is unchanged (with its deprecation warning) and is
*not* aliased to `open`.

Errors returned to the program: allow → 0 (connected); path unix not
in view is **not** hisn's verdict — `CONTINUE` lets the kernel return
`ENOENT` for a hidden path; IP not allowed / private / wrong family /
non-stream → `EACCES`; deadline → `ETIMEDOUT`; a socket that is
already connected → `EISCONN`; supervisor died → the program is killed
with the sandbox (see decision 6); `ENETUNREACH` can only come from
the netns itself (e.g. a rewritten loopback CONTINUE, C4), never from
hisn's refusal.

## Threat model

Protects against: an agent exfiltrating to, or being redirected to,
an arbitrary host (default deny); DNS rebinding (pins bound to TTL +
grace, ports checked at connect; private/loopback/link-local addresses
refused unless explicitly listed, even in `open`); a `sendto`-only
exfiltration channel (none exists in the empty netns, case E); a
resolver outside hisn's control (sandbox nsswitch/resolv.conf are
hisn's, decision 3).

Does not protect against: exfiltration through an *allowed* host (an
allowlisted git host can read what the agent pushes — that is what
allowlisting means); tunneling through allowed domains (DNS pinning
pins the *address*, not the content — a connection to an allowed IP is
a connection to that IP for any protocol); the `CONTINUE` TOCTOU race
(C4: 22/2000 rewrites won) — harmless here because every rewritten
address still resolves inside the empty netns (loopback, or a TEST-NET
range with no route, or a path with no listener); the shared-Unix-user
caveat (ADR 0021 decision A: a same-uid process can omit the
credential, read the user's files, and race the supervisor's
`process_vm_readv` — seats are attribution, not a boundary, and the
journal is the audit trail, not the control).

**Stated limitation (Mashūra BLOCKING 6).** With `CONTINUE`, any
sandbox process can reach **any loopback endpoint visible in the
sandbox** — an in-sandbox service's listener, the DNS responder at
`127.0.0.1:53`, a forwarded path-unix socket (e.g. the ssh-agent proxy
at `/run/ssh-agent.sock`, which the view intentionally contains) —
regardless of the network mode's policy. Mount visibility (Phase 0)
is the *only* gate for path sockets, and loopback is by design open
inside the sandbox. The supervisor is not consulted for these, and
does not pretend to be: `CONTINUE` is accepted as "the empty netns
confines the damage, the filesystem view is the policy". If stronger
loopback policy is wanted later, loopback must go through
supervisor-mediated proxying like IP does — out of scope for v1 and
stated here instead of claimed.

## Control protocol and journal changes

- Protocol revision: 0.6.0 shipped at revision 3 (`src/sessionmeta.rs:43`,
  `PROTOCOL_REVISION = 3`); no new op was added, so there was no bump.
  The 3 → 4 bump, op `net-policy-set {mode, allow[]}` (role `owner`,
  `src/authz.rs:115`) and op `net-explain {target}` (role `member`,
  read-only) are 0.7.0 (allowlist), not 0.6.0. `client.protocol_version`
  gating already exists; absent = rev 1, higher declared → `E_VERSION`;
  older clients are unaffected (they never send the new ops, and the
  supervisor never requires them).
- `session.json` records `network_mode` beside the existing `network`
  field (the profile value, kept for `ls --json` compatibility —
  same compat rule as the 0.5.x plan: `ls --json` keeps emitting the
  profile's value). `net/policy.json` (workspace state dir, 0600)
  persists a runtime policy change across supervisor restarts;
  `net-policy-set` is session-live *and* persisted, and the widened
  policy is printed by `hisn net status`. A policy change never tears
  down established connections (revocation is prospective only), and
  the change is owner-only in the ADR 0021 sense — under the
  shared-uid caveat that means "any same-uid process", stated plainly
  (decision 9).
- Journal: `network/connect` per decision (decision 8),
  `network/policy-changed` on `net-policy-set`. New `Request` variants
  must be added to the authz table (`src/authz.rs:141-190`) — the
  exhaustive `Op` match fails to compile until they are. Journal write
  failure never blocks a verdict (step 7 of the connect flow); the
  journal has a size cap from day one (open question 3 resolved: the
  cap ships with `open` in 0.6.0, not "later" — an un-capped
  per-connect record is a disk-flood vector the sandboxed program
  controls).

## Kernel requirements

| Feature | Minimum kernel | Effect if missing |
|---|---|---|
| `SECCOMP_RET_USER_NOTIF` | 5.0 | refuse to start |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER` | 5.0 | refuse to start |
| `SECCOMP_IOCTL_NOTIF_RECV` | 5.0 | refuse to start |
| `SECCOMP_IOCTL_NOTIF_SEND` | 5.0 | refuse to start |
| `SECCOMP_IOCTL_NOTIF_ID_VALID` | 5.0 | refuse to start |
| `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | 5.5 | refuse to start |
| `SECCOMP_IOCTL_NOTIF_ADDFD` (incl. `SETFD`) | 5.9 | refuse to start (no correct injection below 5.9) |
| `SECCOMP_ADDFD_FLAG_SEND` | 5.14 | two-step inject (`SETFD` + separate `NOTIF_SEND`), slower, same result |
| `SO_NETNS_COOKIE` (0.6.1) | 5.14 | refuse to start |
| `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` | 5.19 | not required (deadline + workers cover the hang) |
| `pidfd_open` | 5.3 | refuse to start |
| `pidfd_getfd` | 5.6 | refuse to start |

Feature detection is by **attempting the ioctl/filter install** at
startup and logging what was found — not by parsing `uname -r` (distro
backports make the version string lie). Floor is **5.14** since 0.6.1
(`SO_NETNS_COOKIE`; before that 5.9, where `SETFD` injection was the
hard floor). The startup error names the first missing feature and its
minimum kernel. Sources: `seccomp_unotify(2)`, `seccomp(2)`,
`pidfd_open(2)`, `pidfd_getfd(2)` (Linux man pages).

## Test plan

Leak-suite cases (named; `tests/leak/MANIFEST`), each with expected
result:

- `L90` allowlisted TCP reachable (curl through the mechanism)
- `L91` non-allowlisted host refused (`EACCES`)
- `L92` raw IP of a non-listed host refused
- `L93` allowed name resolving to an unlisted private IP refused (rebinding guard)
- `L94` DNS: `probe.test` resolves to the pinned address via the supervisor's responder (the unproven probe case, now a hisn gate)
- `L95` DNS: unlisted name → NXDOMAIN
- `L96` loopback listener inside the sandbox reached (CONTINUE)
- `L97` host unix socket invisible (connect to `/run/...` fails `ENOENT` — the path does not exist in the view, not a net decision)
- `L98` `sendto` to an outside address fails `ENETUNREACH` (no connect, no leak)
- `L99` non-blocking connect + poll works through the mechanism
- `L100` supervisor killed mid-connect: nothing hangs; the sandbox and the connecting program die with the supervisor, the exec client exits non-zero, the session is listed as crashed
- `L101` policy change mid-session affects only new connects, journaled
- `L102` journal has a `network/connect` record per decision with seat attribution (attribution = the exec's `client` for `hisn exec` programs, `null` for the main command and in-sandbox services, which have no seat — the pid→exec mapping is the exec table's, stated here so it is not discovered by accident)
- `L103` an **exec'd** program (not only the main command) is intercepted (the listener is per exec tree, where the listener is created (refined)) — `hisn exec curl` through the mechanism
- `L104` `connect()` on a `SOCK_DGRAM` socket is refused `EACCES` in `open` and `allowlist`
- `L105` a program that `bind()`s before `connect()` loses its local address (documented limitation, asserted)
- `L106` a stalled upstream connect does not wedge unrelated connects (worker concurrency, decision 6)
- `L107` host-loopback, link-local (incl. `169.254.169.254`-style), RFC1918 and ULA targets refused in `open` unless explicitly listed (the private-address block, connect-flow step 6)
- `L108` an allowed name resolving to a private IP is refused (pins never authorise non-public addresses)
- `L109` `AF_VSOCK` connect refused `EACCES` in all modes
- `L110` dumpable-0 program (sets `PR_SET_DUMPABLE=0` after exec, before `connect`): the connect is intercepted, decided and journaled with target ip:port like any other (see the correction under connect-flow step 2)
- `L112` DNS over a connected UDP socket and over TCP to `127.0.0.1:53`
- `L113` a failed lookup is never journaled as `ok` (NXDOMAIN → `failed`, upstream timeout → `error` with `SERVFAIL`)
- `L114` journal flood cap: at most 50 records per second one by one, the rest counted in `network/summary`
- `L115` `none` mode: no route, no interception, no generated resolver files
- `L116` `extra_deny = ["connect"]` rejected under `open`, accepted under `none`
- `L111` sandbox netns differs from the supervisor's (`/proc/self/ns/net` inode) — startup assertion, fails closed

Host verification, one script `scripts/host-verify-network.sh` (run on a
host with unprivileged userns, no hisn session): builds one session per
mode, asserts L90–L111 against loopback/`192.0.2.0/24` listeners the
script starts itself. **No traffic leaves the host.** L94 (DNS) is a
**pre-merge host gate**, not a post-merge leak test: the script runs
the real nsswitch hisn ships inside the sandbox, on a host whose own
nsswitch is the host's `resolve`-first one — so a pass proves the
sandbox-local files, not the host's, do the work. The same gate covers
H2 (second listener `EBUSY` measured cleanly) and the "supervisor polls
a listener created in another thread group" case, both still pending
from the probe.

## Rollout

- **0.6.0 — `open` + interception, no allowlist.** Mode plumbing
  (including `CLONE_NEWNET` for the new modes, the netns-difference
  startup assertion, and the exec-tree listener placement), hand-written
  BPF filter, worker-based supervisor, DNS responder (allow-all
  forward), connect-time private-address block (decision: `open` is
  allow-all *public* from day one — the blocklist ships with `open`,
  not with allowlist, or `open` trains users to equate it with host
  networking), journal records with the size cap, startup feature
  probing. Smallest useful step: an agent gets outbound TCP; `none`
  unchanged; default unchanged.
- **0.7.0 — `allowlist`** (DNS pinning, policy format, `net-policy-set`,
  `net explain`, leak cases L90–L111). `network = "host"` stays
  unchanged with its deprecation warning (not aliased to `open`).

## Valon's decisions (2026-11-16)

- **Ship `open` first** (0.6.0) — allow-all public, fully journaled,
  with the private-address block from day one; allowlist is 0.7.0.
- **`network = "host"` is not aliased** to `open`; it stays unchanged
  with its deprecation warning.
- **Per-seat netns is out of scope** for this ADR's v1; session-level
  policy + per-decision journaling is the v1 boundary.
- **Yama `ptrace_scope >= 2` refuses to start** (`open`/`allowlist`
  fail closed at startup; absent or `< 2` is fine — `process_vm_readv`
  would otherwise fail every connect at read time). As implemented, a
  file that exists but cannot be read or is not a number also refuses.
- **E (the exec helper) sets `PR_SET_NO_NEW_PRIVS` itself** before
  installing its connect filter; the filter install never relies on
  `CAP_SYS_ADMIN`.
- **Private-address block ships with `open`** (allow-all *public*, not
  allow-all at all); no `[net] allow` exceptions in 0.6.0.

## Review record

### Implementation (0.6.0)

Implemented on `work/0.6.0`: `open` only; `allowlist`, the policy
format, `net-policy-set` and `net explain` are 0.7.0. What the code
does where it differs from or sharpens the text above:

- **Injection** is always two steps, `ADDFD` with `SETFD` and then
  `NOTIF_SEND` with value 0, on every kernel. `SECCOMP_ADDFD_FLAG_SEND`
  is not used (injection around `src/notif.rs:1897`; the
  constant `FLAG_SEND` is defined and unused). Since 0.6.1 the floor is
  5.14, so the 5.9–5.13 path of 0.6.0 is unreachable; the code is
  unchanged and its removal or a switch to `FLAG_SEND` is a later
  change.
  The descriptor's close-on-exec flag is carried over.
- **`NOTIF_ID_VALID`** uses the number `0x80082102`, which every
  kernel since 5.0 accepts. The start-up probe counts an operation as
  present only when an unknown notification id gives `ENOENT`.
- **Threads.** A notification carries a thread id. The supervisor
  opens it with `PIDFD_THREAD` (Linux 6.9); on older kernels it opens
  the process and verifies with `kcmp` that the thread shares its
  descriptor table, otherwise the connect is refused.
- **Deadline.** 30 s from `NOTIF_RECV`, checked before any work, after
  the address read, and during the outbound connect. A pending connect
  is given up as soon as its notification is no longer valid, so a
  session does not wait for it at its end.
- **Already connected or connecting.** `connect()` on a connected
  socket is answered `EISCONN`, on a socket whose connect is still
  pending (`tcpi_state` SYN_SENT or SYN_RECV) `EALREADY`; nothing is
  injected. On a socket whose earlier connect failed (closed, but
  `tcpi_segs_out` > 0) the supervisor makes the `connect()` on the
  program's own socket and passes on the kernel's answer (the pending
  error, or `ECONNABORTED`): the socket is not replaced.
- **Sizes.** 16 dispatch threads read, decide and start the
  (non-blocking) connect and never wait for a connection; 64 wait
  threads hold the connects of blocking programs until they end. Each
  pool has a queue of 256 (full: `EACCES`, `refuse/queue-full`). DNS:
  16 workers, queue 256, 2 s per query shared over the upstreams, at
  most 64 TCP clients.
- **Completion tracking.** After `EINPROGRESS` the supervisor's own
  descriptor of the injected socket goes to a tracker (at most
  `MAX_TRACKED` = 1024 sockets, `src/notif.rs`; one more is not
  tracked and counted). The receiver thread polls the tracked sockets
  together with the listener, so no thread waits for them. The outcome
  is read from `TCP_INFO` (`tcpi_state`; a socket in `CLOSE` with
  `tcpi_bytes_acked` > 0 was connected and has been closed since), with
  `getpeername` as fallback: `connected`, `failed`, or at the deadline
  `pending-at-deadline`. `SO_ERROR` is never read: measured on kernel
  7.3.3, a read through a duplicate returned `ECONNREFUSED` and the
  program's own read then returned 0, while `TCP_INFO` and
  `getpeername` on the duplicate left the program's `SO_ERROR` at
  `ECONNREFUSED`. Tracked sockets are closed when the engine stops.
- **`NOTIF_SEND` after an injection** is checked: if the answer does
  not reach the task, the record's reason is `injected-reply-failed`,
  nothing is tracked and the supervisor's descriptor is closed.
- **Journal.** Network records pass through one bounded queue per
  session (4096 entries; full: the record is dropped and counted). At
  most 50 per second are written one by one, the rest are counted in
  `network/summary` (with `result_connected`, `result_other` and
  `tracked_overflow`). `network/connect` has no `latency_ms` or
  `resolved_name`. Since 0.6.1 it carries `notif_id` and `pid` (the
  notified thread id in the supervisor's pid namespace) and `seat`
  (found by process ancestry, see "Seat attribution" below).
  `network/implicit` (0.6.1) records a `bind`, `listen` or fast-open
  `sendto`/`sendmsg`/`sendmmsg` the engine saw: `target` is
  `<syscall> <reason>`, `verdict` `continue` or `refuse`, `reason`
  `implicit-sandbox-socket`, `host-socket-implicit` or `netns-unknown`,
  plus `notif_id`, `pid`, `seat`. `journal/pruned` (0.6.1) names the
  rotated files a retention pass deleted.
  `network/connect-result` (`target`, `result`, `latency_ms`, no
  errno) is how a non-blocking connect ended that was answered
  `EINPROGRESS`, or `failed` with latency 0 when it failed at once.
  `network/dns` carries
  `name`, `qtype`, `proto`, `upstream`, `rcode` and `verdict`
  `ok` / `failed` / `error`. The size limit (oldest rotated files
  deleted beyond 256 MiB in more than four files) applied only to
  journals of sessions in `open` in 0.6.0; since 0.6.1 it applies to
  every session, whatever its network mode, and each deletion writes a
  `journal/pruned` record.
- **`nsswitch.conf`** is generated only in `open`; `none` and `host`
  keep the host's file.
- **No `[net] allow` exceptions**: private targets are always refused.
- **Not implemented from decision 3**: the responder forwards every
  name and keeps no pins (that is the allowlist's part).

Measured on kernel 7.3.3-300.fc45.x86_64 (Fedora 45, Yama
`ptrace_scope = 1`), commit `4ec88bc`:
`scripts/host-verify-network.sh --real` ended with
`RESULT: pass=103 fail=0 timeout=0 skipped=0`. 100 connects cost
about 97 µs each through interception (medians 112.6, 97.4,
97.4 µs) against about 21 µs direct (21.4, 20.6, 19.4 µs); the probe
had measured 20–25 µs extra with a single-threaded C supervisor. The
`kcmp` fallback for kernels before 6.9 has unit coverage only.

Known gaps, accepted for 0.6.0 and listed in the release notes: an
epoll registration or a duplicate made before `connect()` refers to
the old socket; only a few socket options are carried over; another
thread of the program that closes and reuses the descriptor number
while `connect()` is suspended gets the socket injected at that
number.

Mashūra round 1 (open questions: "What is missing or wrong in this
design? Where can it fail open? What would an agent other than Wakil
stumble over?") returned BLOCKING findings from all three panel
members; the same three arrived independently: **exec-tree listener
placement**, **DNS responder process/ownership**, **UDP `connect()`
fail-open**, plus **host-loopback/private reachability in `open`**,
**unspecified address families**, **CONTINUE TOCTOU scope**,
**`SETFD` missing**, and **deadline ≠ wedged supervisor**. All were
incorporated above (decisions 1–7, connect-flow steps 1–8, threat-model
limitation, L103–L111). Round 2 was not needed — the panel converged
and the fixes are additive and scoped. Non-blocking notes, listed as
open points:

- `hisn net explain` cannot know live pins without an RPC to the
  running supervisor; specified as: `net-explain` is an op on the
  running session (static approximation when no session is running).
- `/etc/hosts` entries bypass DNS by design (`files` first); they are
  not DNS-pinned and need explicit IP/CIDR rules in `allow` — stated,
  not fixed, because `files` is how local names should work.
- DoH/custom-resolver tools break under `allowlist` while
  system-resolver tools work; documented (allowlist effectively
  mandates the system resolver). QUIC/HTTP3 tools that hard-fail
  instead of falling back are a documented L104 limitation, not
  silently assumed to fall back.
- `hisn net explain`/`net status` are host-side commands (in-sandbox
  peers are refused by `authorize_peer`); in-sandbox agents see only
  `EACCES`/`NXDOMAIN` and the journal is the explanation path.

## 0.6.1 hardening

**Property.** In `open`, a program in the sandbox can only hold two kinds
of socket: one in the sandbox's empty network namespace, which reaches
nothing but the sandbox's own loopback, and one in the supervisor's
namespace that the supervisor injected for a connection the policy
approved. Since 0.6.0 the injection happens before the connect has
completed, so a program can keep an injected socket after that connect
failed. The second kind must therefore serve only the connection it was
approved for. Every call by which a socket of that kind could start
another connection or open a port (`connect`, `bind`, `listen`, a
`MSG_FASTOPEN` send) is notified to the supervisor and answered by the
namespace of the socket, or refused; every other syscall is `ALLOW`ed by
the filter. The supervisor makes the answer on the socket itself (a
`pidfd_getfd` duplicate and `SO_NETNS_COOKIE`), after `NOTIF_ID_VALID`,
never on the address argument. If the namespace cannot be determined the
call is refused.

| # | Invariant | Code (`src/notif.rs`) | Test |
|---|---|---|---|
| a | An injected socket serves only its approved connection; a further `connect` to another target goes through the full policy (a socket already connected or pending only gets `EISCONN`/`EALREADY`, no new connection) | `off_sandbox && !already_used` refuses `host-socket-connect` (1545); a failed host-side socket is re-connected only on `Allow` (1558) | unit `engine_refuses_host_side_socket_connects_and_journals`, `host_socket_reconnect_enters_the_full_policy`; leak `L125` |
| b | `CONTINUE` only for a socket with a known namespace cookie that is not the supervisor's; otherwise the full policy | `classify_ns` (2110), `continue_allowed` (1619); unknown cookie is `Unknown`, treated as `Host` | unit `classify_ns_fails_closed`, `engine_still_continues_sandbox_socket_loopback`, `socket_netns_cookie_resolves_and_fails_closed` (`engine_without_cookie_source_refuses_everything` shows a same-namespace socket is classified `Host`, not the unknown-cookie case); leak `L96` (sandbox loopback still works), `L125` |
| c | Fast-open sends cannot leave on a supervisor-side socket | `connect_filter` (46) notifies `sendto`/`sendmmsg`/`sendmsg` with `MSG_FASTOPEN`; `handle_implicit_call` (1314) answers by namespace | unit `filter_verdicts_by_interpretation` (runs the installed array); leak `L125` (fast-open sendto EACCES), `L98` |
| d | `bind`/`listen` on a supervisor-side socket cannot open a port in the supervisor's namespace | same filter entries; `handle_implicit_call` refuses `host-socket-implicit` | leak `L125` (bind and listen EACCES; the journal has one `network/implicit` record each) |
| e | The only verdict the filter gives other than `ALLOW` for an unrelated syscall is the kill of a foreign architecture | `ALLOW` is the default | unit `filter_verdicts_by_interpretation` interprets the installed array (23 unrelated syscalls, foreign architecture). It shows the filter's verdicts, not that no program is delayed: every `bind`/`listen` now round-trips the supervisor and is refused `EACCES` when the notification queue is full |

**Comparison with 0.6.0** (`.wakil/host-run-061.sh v060`, L125 sub-checks
against a v0.6.0 build): see the 0.6.1 release notes for the result.
The `host-socket-loopback-or-unix` and `host-socket-implicit` records are
new in 0.6.1.

**Known gap (open point, not fixed in 0.6.1).** `CONTINUE` lets the
kernel run the original call, and the supervisor's check was made on a
duplicate of the descriptor. A second thread of the program that
replaces the descriptor number between the check and the call can make
the kernel run it on another socket. This is the same time-of-check gap
as decision 7's descriptor-reuse race and the `CONTINUE` buffer race
measured in the probes; it was open in 0.6.0 as well. It matters only
for a program that holds a supervisor-side socket (kept after a failed
connect) and a second thread, and it needs a design change to close
(the supervisor performing the call itself on the verified socket
instead of continuing it). No test in this release shows it closed.

//! `exec` into a running session (DESIGN §14).
//!
//! **The process chain (`helper_serve` → C → D → W → P) needs user
//! namespaces and cannot run in the Wakil build sandbox.** Everything around
//! it is pure or uses only ordinary processes and sockets, and is unit
//! tested: request validation, the status protocol, the monitor loop, the
//! supervisor-side spawn handshake (against a fake helper) and the driver
//! that turns status lines into responses.
//!
//! Chain: the persistent helper `E` (userns S) forks `C` per exec; `C` joins
//! the sandbox namespaces and forks `D` (now inside the pid ns); `D`
//! re-applies the full confinement and forks the monitor `W`, then exits, so
//! `W` is reparented to sandbox init; `W` forks the program `P` and relays
//! status and signals over a per-exec status socket.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use seccompiler::BpfProgram;
use serde::{Deserialize, Serialize};

use crate::env as senv;
use crate::init::{self, EXIT_CANNOT_EXEC, EXIT_INTERNAL, EXIT_NOT_FOUND};
use crate::landlock::{self, LandlockPlan};
use crate::policy::ResolvedPolicy;
use crate::{seccomp, sig, sys};

pub const MAX_ARGV: usize = 4096;
pub const MAX_ENV: usize = 256;
/// Bound on argv + env + cwd bytes (the control line itself is ≤ 64 KiB).
pub const MAX_TOTAL: usize = 48 * 1024;
/// How long a spawn may take from "sent to the helper" to "program started".
pub const SPAWN_TIMEOUT: Duration = Duration::from_secs(10);
/// After a client disconnects: `TERM`, then `KILL` once this has passed.
pub const CANCEL_GRACE: Duration = Duration::from_secs(5);
/// How long `W` waits to be adopted by sandbox init before giving up.
const REPARENT_TIMEOUT: Duration = Duration::from_secs(5);
/// Descriptors handed to the helper are moved above this number so that
/// `dup2` onto 0-2 in `D`/`P` can never clobber one.
const HIGH_FD: RawFd = 16;

// ------------------------------------------------------------ validation

/// What the supervisor needs to turn an `exec` request into a [`ExecSpec`].
#[derive(Debug, Clone)]
pub struct ExecRules {
    /// `env.pass` of the policy: the only keys a request may set.
    pub env_pass: Vec<String>,
    /// The environment init gave the main command.
    pub base_env: BTreeMap<String, String>,
    /// Working directory when the request has none.
    pub default_cwd: String,
}

/// A validated request, exactly as sent to the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    /// The final environment (base + request), never merged again.
    pub env: BTreeMap<String, String>,
    pub tty: bool,
}

impl ExecSpec {
    /// Stdio descriptors that travel with the request: the slave of a pty, or
    /// stdin/stdout/stderr.
    pub fn fd_count(&self) -> usize {
        if self.tty { 1 } else { 3 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    Argv(String),
    Cwd(String),
    Env(String),
    /// Request env keys outside `env.pass` (or computed): the whole request is
    /// refused, nothing is dropped silently. Names only, never values.
    RejectedEnvKeys(Vec<String>),
    Fds {
        want: usize,
        got: usize,
    },
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Argv(m) => write!(f, "argv: {m}"),
            Invalid::Cwd(m) => write!(f, "cwd: {m}"),
            Invalid::Env(m) => write!(f, "env: {m}"),
            Invalid::RejectedEnvKeys(k) => write!(
                f,
                "env keys not allowed by the policy's env.pass: {}",
                k.join(", ")
            ),
            Invalid::Fds { want, got } => write!(
                f,
                "expected {want} stdio descriptor(s) with this request, got {got}"
            ),
        }
    }
}

/// Validate an `exec` request (DESIGN §14.5). Pure.
pub fn validate(
    argv: Vec<String>,
    cwd: Option<String>,
    req_env: BTreeMap<String, String>,
    tty: bool,
    fds: usize,
    rules: &ExecRules,
) -> Result<ExecSpec, Invalid> {
    let want = if tty { 1 } else { 3 };
    if fds != want {
        return Err(Invalid::Fds { want, got: fds });
    }
    if argv.is_empty() || argv.len() > MAX_ARGV {
        return Err(Invalid::Argv(format!("1..={MAX_ARGV} entries required")));
    }
    if argv[0].is_empty() {
        return Err(Invalid::Argv("argv[0] is empty".into()));
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Err(Invalid::Argv("NUL byte".into()));
    }
    let cwd = match cwd {
        None => rules.default_cwd.clone(),
        Some(c) => {
            if !c.starts_with('/') || c.contains('\0') || c.split('/').any(|s| s == "..") {
                return Err(Invalid::Cwd(
                    "must be an absolute path without NUL or `..` segments".into(),
                ));
            }
            c
        }
    };
    if req_env.len() > MAX_ENV {
        return Err(Invalid::Env(format!("at most {MAX_ENV} variables")));
    }
    for (k, v) in &req_env {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            return Err(Invalid::Env(
                "names must be non-empty without `=`; no NUL anywhere".into(),
            ));
        }
    }
    let rejected: Vec<String> = req_env
        .keys()
        .filter(|k| senv::is_computed(k) || !rules.env_pass.iter().any(|p| p == *k))
        .cloned()
        .collect();
    if !rejected.is_empty() {
        return Err(Invalid::RejectedEnvKeys(rejected));
    }
    let mut env = rules.base_env.clone();
    env.extend(req_env);
    let total: usize = argv.iter().map(String::len).sum::<usize>()
        + env
            .iter()
            .map(|(k, v)| k.len() + v.len() + 2)
            .sum::<usize>()
        + cwd.len();
    if total > MAX_TOTAL {
        return Err(Invalid::Argv(format!("request exceeds {MAX_TOTAL} bytes")));
    }
    Ok(ExecSpec {
        argv,
        cwd,
        env,
        tty,
    })
}

// -------------------------------------------------------- status protocol

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

/// One line on the per-exec status socket, `W`/`D`/`C` → supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `P <pid>`: the program was `execve`d; `pid` is its pid in the sandbox.
    Started(i32),
    /// `X exit <code>` | `X sig <n>`.
    Exited(Exit),
    /// `E <message>`: confinement or setup failed; nothing was started.
    SetupFailed(String),
    /// `F <errno> <message>`: confinement succeeded, `execve` failed.
    ExecFailed { errno: i32, message: String },
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

pub fn format_status(s: &Status) -> String {
    match s {
        Status::Started(p) => format!("P {p}\n"),
        Status::Exited(Exit::Code(c)) => format!("X exit {c}\n"),
        Status::Exited(Exit::Signal(n)) => format!("X sig {n}\n"),
        Status::SetupFailed(m) => format!("E {}\n", one_line(m)),
        Status::ExecFailed { errno, message } => format!("F {errno} {}\n", one_line(message)),
    }
}

pub fn parse_status(line: &str) -> Option<Status> {
    let (kind, rest) = line.split_once(' ')?;
    match kind {
        "P" => rest
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .map(Status::Started),
        "X" => {
            let (what, n) = rest.split_once(' ')?;
            let n: i32 = n.trim().parse().ok()?;
            match what {
                "exit" if (0..=255).contains(&n) => Some(Status::Exited(Exit::Code(n))),
                "sig" if (1..=64).contains(&n) => Some(Status::Exited(Exit::Signal(n))),
                _ => None,
            }
        }
        "E" => Some(Status::SetupFailed(rest.to_owned())),
        "F" => {
            let (e, m) = rest.split_once(' ').unwrap_or((rest, ""));
            Some(Status::ExecFailed {
                errno: e.parse().ok()?,
                message: m.to_owned(),
            })
        }
        _ => None,
    }
}

/// `K <n>`: supervisor → `W`, deliver signal `n` to the program's group.
pub fn format_kill(sig: i32) -> String {
    format!("K {sig}\n")
}

pub fn parse_kill(line: &str) -> Option<i32> {
    let n: i32 = line.strip_prefix("K ")?.trim().parse().ok()?;
    (1..=64).contains(&n).then_some(n)
}

pub fn exit_from_wait_status(st: i32) -> Exit {
    if libc::WIFSIGNALED(st) {
        Exit::Signal(libc::WTERMSIG(st))
    } else {
        Exit::Code(libc::WEXITSTATUS(st))
    }
}

/// Accumulates bytes from a status socket and yields complete lines.
#[derive(Debug, Default)]
pub struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    const MAX: usize = 16 * 1024;

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Next complete line. A runaway line (no newline within [`Self::MAX`]
    /// bytes) is discarded and yielded as an unparsable marker, never as a
    /// prefix that could parse as something else.
    pub fn pop_line(&mut self) -> Option<String> {
        if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            let rest = self.buf.split_off(pos + 1);
            let mut line = std::mem::replace(&mut self.buf, rest);
            line.pop();
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        if self.buf.len() > Self::MAX {
            self.buf.clear();
            return Some("!overflow".into());
        }
        None
    }
}

pub(crate) fn read_some(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: reading into a valid buffer from a descriptor we own.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}

// ---------------------------------------------------------------- monitor

/// `W`'s loop (also run directly by the tests): wait for `p`, forward `K`
/// lines to its process group, and treat EOF on `status` as cancellation
/// (`SIGKILL` the group). `p` must be a child of the caller. Returns how `p`
/// ended; the caller reports it.
pub fn monitor(p: i32, status: RawFd) -> io::Result<Exit> {
    let pfd = sys::pidfd_open(p)?;
    let mut lines = Lines::default();
    let mut eof = false;
    let mut buf = [0u8; 512];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: if eof { -1 } else { status },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        sys::poll(&mut fds, -1)?;
        if fds[1].revents != 0 {
            let mut st = 0;
            // SAFETY: waitpid on our own, already-exited child.
            let r = unsafe { libc::waitpid(p, &mut st, 0) };
            if r != p {
                return Err(io::Error::last_os_error());
            }
            return Ok(exit_from_wait_status(st));
        }
        if fds[0].revents != 0 {
            let n = read_some(status, &mut buf).unwrap_or(0);
            if n == 0 {
                eof = true;
                signal_group(p, libc::SIGKILL);
            } else {
                lines.push(&buf[..n]);
                while let Some(l) = lines.pop_line() {
                    if let Some(sig) = parse_kill(&l) {
                        signal_group(p, sig);
                    }
                }
            }
        }
    }
}

/// Signal the program's process group (it is a session leader, so its pgid is
/// its pid); fall back to the process itself.
fn signal_group(p: i32, sig: i32) {
    if sys::kill(-p, sig).is_err() {
        let _ = sys::kill(p, sig);
    }
}

// -------------------------------------------------------- supervisor side

#[derive(Debug)]
pub enum SpawnError {
    /// Confinement or `execve` failed; `errno` is set for an `execve` failure.
    Exec {
        errno: Option<i32>,
        message: String,
    },
    Internal(String),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::Exec { message, .. } | SpawnError::Internal(message) => {
                f.write_str(message)
            }
        }
    }
}

/// A started program as seen by the supervisor.
pub struct Spawned {
    /// Pid inside the sandbox pid namespace (only a handle for `signal`).
    pub pid: i32,
    pub status: OwnedFd,
    /// Status lines that arrived together with `P` (already buffered).
    pub pending: Lines,
}

/// Supervisor-side handle on the exec helper `E`.
pub struct ExecClient {
    /// `None` once a handover went ambiguous: the channel is no longer in a
    /// known state (a reply may still arrive and would otherwise be consumed
    /// as the answer to the *next* request). Every later exec then fails
    /// closed with `E_INTERNAL` instead of desynchronising.
    chan: Mutex<Option<OwnedFd>>,
    /// Monotonic request id echoed by the helper, correlating replies.
    next_id: std::sync::atomic::AtomicU64,
    /// How long to wait for a failed spawn's `C` to disappear.
    pub reap_grace: Duration,
}

impl ExecClient {
    pub fn new(chan: OwnedFd) -> Self {
        Self {
            chan: Mutex::new(Some(chan)),
            next_id: std::sync::atomic::AtomicU64::new(1),
            reap_grace: Duration::from_secs(2),
        }
    }

    /// Hand `spec` + its stdio to the helper and wait until the program has
    /// started (or failed). On any failure the half-started chain is torn
    /// down before returning, so the caller may release the spawn gate
    /// (DESIGN §14.6). The supervisor's copies of the stdio fds are closed.
    pub fn spawn(
        &self,
        spec: &ExecSpec,
        stdio: Vec<OwnedFd>,
        timeout: Duration,
    ) -> Result<Spawned, SpawnError> {
        if stdio.len() != spec.fd_count() {
            return Err(SpawnError::Internal("wrong stdio descriptor count".into()));
        }
        let (mine, theirs) =
            sys::socketpair().map_err(|e| SpawnError::Internal(format!("socketpair: {e}")))?;
        let body = serde_json::to_vec(spec)
            .map_err(|e| SpawnError::Internal(format!("encoding request: {e}")))?;
        let mut raw: Vec<RawFd> = stdio.iter().map(AsRawFd::as_raw_fd).collect();
        raw.push(theirs.as_raw_fd());
        let cpid = self.hand_over(&body, &raw)?;
        drop(stdio);
        drop(theirs);
        match wait_started(&mine, timeout) {
            Ok((pid, pending)) => Ok(Spawned {
                pid,
                status: mine,
                pending,
            }),
            Err(e) => {
                self.tear_down(cpid, mine);
                Err(e)
            }
        }
    }

    /// Send one request to `E` and wait for its acknowledgement. The channel
    /// lock is held for the whole exchange: the reply is correlated by a
    /// request id, and on any ambiguity (timeout, EOF, garbage) the channel
    /// is *poisoned* (`None`) so no later exec can misread a stale reply.
    /// Returns the pid of the `C` it forked.
    fn hand_over(&self, body: &[u8], fds: &[RawFd]) -> Result<i32, SpawnError> {
        let mut guard = self.chan.lock().expect("exec channel");
        let internal = |m: String| SpawnError::Internal(m);
        let Some(ch) = guard.as_ref() else {
            return Err(internal(
                "exec helper is unreachable (earlier failure)".into(),
            ));
        };
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut line = format!("{id} ").into_bytes();
        line.extend_from_slice(body);
        sys::send_with_fds(ch.as_raw_fd(), &line, fds)
            .map_err(|e| internal(format!("exec helper unreachable: {e}")))?;
        let mut p = [libc::pollfd {
            fd: ch.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let ready = sys::poll(&mut p, 5_000).map_err(|e| internal(e.to_string()))?;
        if ready == 0 {
            *guard = None; // the reply may still arrive later: poisoned
            return Err(internal("exec helper did not answer".into()));
        }
        let mut buf = [0u8; 512];
        let r = sys::recv_with_fds(ch.as_raw_fd(), &mut buf)
            .map_err(|e| internal(format!("exec helper: {e}")))?;
        if r.len == 0 {
            *guard = None;
            return Err(internal("exec helper exited".into()));
        }
        let reply = String::from_utf8_lossy(&buf[..r.len]).into_owned();
        let Some(rest) = reply.strip_prefix("ok ") else {
            *guard = None; // could be a stale reply to an earlier request
            return Err(internal(format!(
                "exec helper refused: {}",
                reply.strip_prefix("err ").unwrap_or(&reply)
            )));
        };
        // Correlate: the id must match this request.
        match rest.split_once(' ') {
            Some((their_id, cpid)) if their_id.trim() == id.to_string() => cpid
                .trim()
                .parse()
                .map_err(|_| internal(format!("bad helper reply {reply:?}"))),
            _ => {
                *guard = None;
                Err(internal(format!("uncorrelated helper reply {reply:?}")))
            }
        }
    }

    /// Failure path: kill `C` (its `D` follows through `PDEATHSIG`), close the
    /// status socket (a `W` that already exists then kills the program), and
    /// wait until `C` is gone, bounded by `reap_grace`.
    fn tear_down(&self, cpid: i32, status: OwnedFd) {
        if cpid > 1 {
            let _ = sys::kill(cpid, libc::SIGKILL);
        }
        drop(status);
        let end = Instant::now() + self.reap_grace;
        while cpid > 1 && sys::kill(cpid, 0).is_ok() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn wait_started(status: &OwnedFd, timeout: Duration) -> Result<(i32, Lines), SpawnError> {
    let deadline = Instant::now() + timeout;
    let mut lines = Lines::default();
    let mut buf = [0u8; 512];
    loop {
        if let Some(l) = lines.pop_line() {
            return match parse_status(&l) {
                Some(Status::Started(p)) => Ok((p, lines)),
                Some(Status::SetupFailed(m)) => Err(SpawnError::Exec {
                    errno: None,
                    message: m,
                }),
                Some(Status::ExecFailed { errno, message }) => Err(SpawnError::Exec {
                    errno: Some(errno),
                    message,
                }),
                _ => Err(SpawnError::Internal(format!("unexpected status {l:?}"))),
            };
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(SpawnError::Internal(
                "timed out starting the program".into(),
            ));
        }
        let mut p = [libc::pollfd {
            fd: status.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let ms = left.as_millis().min(i32::MAX as u128) as i32;
        sys::poll(&mut p, ms.max(1)).map_err(|e| SpawnError::Internal(e.to_string()))?;
        if p[0].revents != 0 {
            let n = read_some(status.as_raw_fd(), &mut buf)
                .map_err(|e| SpawnError::Internal(e.to_string()))?;
            if n == 0 {
                return Err(SpawnError::Internal(
                    "exec process vanished before starting the program".into(),
                ));
            }
            lines.push(&buf[..n]);
        }
    }
}

/// How a running exec ended, as the supervisor learned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Exited(Exit),
    /// The status socket closed without an exit line (monitor killed,
    /// session torn down): the program's status is unknown.
    Lost,
}

/// Drive a started exec to its end: relay the status socket and watch the
/// client connection `conn`. A client that disconnects (or sends anything
/// further) cancels: `TERM` at once, `KILL` after `grace`.
pub fn drive(status: &OwnedFd, lines: Lines, conn: RawFd, grace: Duration) -> Outcome {
    drive_from(status, lines, conn, grace, false)
}

/// [`drive`] with the client already gone at entry (`already_cancelled`):
/// starts in the `TERM`-then-`KILL` path instead of waiting for a poll event
/// that a dead connection can never produce.
pub fn drive_from(
    status: &OwnedFd,
    mut lines: Lines,
    conn: RawFd,
    grace: Duration,
    already_cancelled: bool,
) -> Outcome {
    let mut cancelled: Option<Instant> = None;
    let mut sent_term = false;
    if already_cancelled {
        // The client is already gone: the cancellation sequence (TERM, then
        // KILL after the grace) starts immediately instead of on a poll
        // event that a dead connection can never produce.
        let _ = sys::send_all(status.as_raw_fd(), format_kill(libc::SIGTERM).as_bytes());
        cancelled = Some(Instant::now());
        sent_term = true;
    }
    let mut killed = false;
    let mut buf = [0u8; 512];
    loop {
        while let Some(l) = lines.pop_line() {
            if let Some(Status::Exited(x)) = parse_status(&l) {
                return Outcome::Exited(x);
            }
        }
        let timeout = match cancelled {
            Some(t0) if !killed => {
                let left = (t0 + grace).saturating_duration_since(Instant::now());
                left.as_millis().min(i32::MAX as u128) as i32
            }
            _ => -1,
        };
        let mut fds = [
            libc::pollfd {
                fd: status.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if cancelled.is_some() { -1 } else { conn },
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
        ];
        if sys::poll(&mut fds, timeout).is_err() {
            return Outcome::Lost;
        }
        if let Some(t0) = cancelled
            && !killed
            && Instant::now() >= t0 + grace
        {
            let _ = sys::send_all(status.as_raw_fd(), format_kill(libc::SIGKILL).as_bytes());
            killed = true;
        }
        if !sent_term && cancelled.is_none() && fds[1].revents != 0 {
            let _ = sys::send_all(status.as_raw_fd(), format_kill(libc::SIGTERM).as_bytes());
            cancelled = Some(Instant::now());
            sent_term = true;
        }
        if fds[0].revents != 0 {
            match read_some(status.as_raw_fd(), &mut buf) {
                Ok(0) | Err(_) => return Outcome::Lost,
                Ok(n) => lines.push(&buf[..n]),
            }
        }
    }
}

// ------------------------------------------------------------ helper side

/// Namespaces the helper joins, opened by the supervisor before `GO`.
pub struct NsFds {
    pub user: OwnedFd,
    pub mnt: OwnedFd,
    pub ipc: OwnedFd,
    pub uts: OwnedFd,
    pub pid: OwnedFd,
    /// Present iff the session has its own network namespace.
    pub net: Option<OwnedFd>,
    /// The sandbox root directory (opened by the supervisor from
    /// `/proc/<init>/root`). `setns(mnt)` does NOT move the caller's root/cwd
    /// into the target namespace: `C` fchdirs onto this fd so every later
    /// path resolution happens inside the sandbox (review finding A).
    pub root: OwnedFd,
}

impl NsFds {
    fn raws(&self) -> Vec<RawFd> {
        let mut v = vec![
            self.user.as_raw_fd(),
            self.mnt.as_raw_fd(),
            self.ipc.as_raw_fd(),
            self.uts.as_raw_fd(),
            self.pid.as_raw_fd(),
            self.root.as_raw_fd(),
        ];
        v.extend(self.net.as_ref().map(AsRawFd::as_raw_fd));
        v
    }
}

/// Everything the helper needs to confine a new process exactly like init
/// confined the main command. Copied into the helper by `fork`.
pub struct ExecContext {
    pub policy: ResolvedPolicy,
    pub landlock: LandlockPlan,
    pub require_scope: bool,
    pub seccomp: Vec<BpfProgram>,
    pub ns: NsFds,
}

/// The helper `E`: forked once by the supervisor while single-threaded, stays
/// in the supervisor's user namespace, and forks one `C` per request.
/// Never returns.
pub fn helper_serve(chan: OwnedFd, ctx: ExecContext) -> ! {
    let code = match helper_loop(&chan, &ctx) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("hisn exec helper: {e}");
            1
        }
    };
    // SAFETY: terminate without running the parent's atexit machinery.
    unsafe { libc::_exit(code) }
}

fn helper_loop(chan: &OwnedFd, ctx: &ExecContext) -> io::Result<()> {
    sys::prctl(1 /* PR_SET_PDEATHSIG */, libc::SIGKILL as u64, 0, 0, 0)?;
    // Auto-reap every `C`: no zombies, and "C is gone" is observable by
    // `kill(pid, 0)` from the supervisor.
    // SAFETY: installing SIG_IGN for SIGCHLD is always valid.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    let mut keep = ctx.ns.raws();
    keep.push(chan.as_raw_fd());
    sys::close_all_except(&keep);
    // The supervisor's stdin/stdout are not ours to hold (stderr stays for
    // diagnostics).
    // SAFETY: open + dup2 onto 0 and 1.
    unsafe {
        let n = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if n >= 0 {
            libc::dup2(n, 0);
            libc::dup2(n, 1);
            if n > 2 {
                libc::close(n);
            }
        }
    }
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let r = sys::recv_with_fds(chan.as_raw_fd(), &mut buf)?;
        if r.len == 0 {
            return Ok(()); // supervisor closed its end
        }
        let (_id, reply) = match parse_helper_line(&buf[..r.len]) {
            None => (0, "err bad request line".to_string()),
            Some((id, body)) => match prepare_request(body, r.fds, r.truncated) {
                Ok((spec, fds)) => {
                    // SAFETY: the helper is single-threaded (forked before
                    // any supervisor thread); the child only runs `child_c`.
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        child_c(ctx, &spec, fds);
                    }
                    // The parent's copies of the stdio and status fds close here.
                    drop(fds);
                    (
                        id,
                        if pid < 0 {
                            format!("err fork: {}", io::Error::last_os_error())
                        } else {
                            format!("ok {id} {pid}")
                        },
                    )
                }
                Err(e) => (id, format!("err {id} {e}")),
            },
        };
        sys::send_with_fds(chan.as_raw_fd(), reply.as_bytes(), &[])?;
    }
}

/// Split `<id> <json>`; `None` if there is no id prefix.
fn parse_helper_line(body: &[u8]) -> Option<(u64, &[u8])> {
    let text = std::str::from_utf8(body).ok()?;
    let (id, rest) = text.split_once(' ')?;
    let id = id.parse().ok()?;
    Some((id, rest.as_bytes()))
}

/// Decode one helper request and move its descriptors above [`HIGH_FD`].
fn prepare_request(
    body: &[u8],
    fds: Vec<OwnedFd>,
    truncated: bool,
) -> Result<(ExecSpec, Vec<OwnedFd>), String> {
    if truncated {
        return Err("request truncated".into());
    }
    let spec: ExecSpec = serde_json::from_slice(body).map_err(|e| format!("bad request: {e}"))?;
    if fds.len() != spec.fd_count() + 1 {
        return Err(format!(
            "expected {} descriptors, got {}",
            spec.fd_count() + 1,
            fds.len()
        ));
    }
    let high = fds
        .iter()
        .map(|f| sys::dup_cloexec_min(f.as_raw_fd(), HIGH_FD))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|e| format!("dup: {e}"))?;
    Ok((spec, high))
}

/// Report a setup failure on the status socket and exit (never returns).
fn die(status: RawFd, msg: &str) -> ! {
    let _ = sys::send_all(
        status,
        format_status(&Status::SetupFailed(msg.into())).as_bytes(),
    );
    // SAFETY: terminate this process immediately.
    unsafe { libc::_exit(EXIT_INTERNAL) }
}

/// `C`: still outside the sandbox pid ns; joins the namespaces, forks `D`.
fn child_c(ctx: &ExecContext, spec: &ExecSpec, fds: Vec<OwnedFd>) -> ! {
    // SAFETY: restoring the default disposition inherited as SIG_IGN from E.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let status = fds.last().expect("status fd").as_raw_fd();
    let step = |what: &str, r: io::Result<()>| {
        if let Err(e) = r {
            die(status, &format!("{what}: {e}"));
        }
    };
    let _ = sys::prctl(1 /* PR_SET_PDEATHSIG */, libc::SIGKILL as u64, 0, 0, 0);
    // PDEATHSIG race: if the parent died between fork and prctl we are
    // already orphaned — fail closed instead of running unparented.
    // SAFETY: plain getppid.
    if unsafe { libc::getppid() } == 0 {
        die(status, "helper died before the exec could start");
    }
    // Dumpable is reset by credential changes (joining a userns), so it is
    // cleared before and after (DESIGN §14.2).
    step("dumpable", sys::set_dumpable(false));
    // The user namespace first: this process (uid of the owner, in the
    // owner-ancestor namespace S) then holds all capabilities in it, which is
    // what the remaining `setns` calls need.
    step(
        "setns(user)",
        sys::setns(ctx.ns.user.as_raw_fd(), libc::CLONE_NEWUSER),
    );
    step("dumpable", sys::set_dumpable(false));
    step(
        "setns(mnt)",
        sys::setns(ctx.ns.mnt.as_raw_fd(), libc::CLONE_NEWNS),
    );
    // setns(mnt) swaps the mount tree but NOT this process's root/cwd:
    // adopt the sandbox root by fd, never by path (a path would resolve in
    // the old namespace first). Every later lookup — /dev/null, the Landlock
    // roots, cwd, the executable — then happens inside the sandbox.
    step("root", sys::fchdir_chdir_root(ctx.ns.root.as_raw_fd()));
    step(
        "setns(ipc)",
        sys::setns(ctx.ns.ipc.as_raw_fd(), libc::CLONE_NEWIPC),
    );
    step(
        "setns(uts)",
        sys::setns(ctx.ns.uts.as_raw_fd(), libc::CLONE_NEWUTS),
    );
    if let Some(net) = &ctx.ns.net {
        step(
            "setns(net)",
            sys::setns(net.as_raw_fd(), libc::CLONE_NEWNET),
        );
    }
    // The pid namespace last: it only affects children (D).
    step(
        "setns(pid)",
        sys::setns(ctx.ns.pid.as_raw_fd(), libc::CLONE_NEWPID),
    );
    step("chdir", std::env::set_current_dir("/"));
    // D25: the sandbox root is established twice (setns(mnt) sets root and
    // cwd, the fchdir adopts the fd). Fail closed unless "/" and "." really
    // are the directory the supervisor opened as init's root. The expected
    // identity is handed to `D`, which no longer holds the root fd.
    let root_id = match sys::dev_ino(ctx.ns.root.as_raw_fd(), c"", sys::AT_EMPTY_PATH as _) {
        Ok(id) => id,
        Err(e) => die(status, &format!("root identity: {e}")),
    };
    step("root check", check_root(root_id));
    // Nothing but the stdio and status fds may reach `D`: no namespace fds,
    // no channel to the helper.
    let keep: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    sys::close_all_except(&keep);
    // SAFETY: single-threaded; `D` only runs `child_d` and never returns here.
    let d = unsafe { libc::fork() };
    if d < 0 {
        die(status, &format!("fork: {}", io::Error::last_os_error()));
    }
    if d == 0 {
        child_d(ctx, spec, &keep, root_id);
    }
    let mut st = 0;
    // SAFETY: waiting for our own child.
    unsafe { libc::waitpid(d, &mut st, 0) };
    // SAFETY: terminate this process immediately.
    unsafe { libc::_exit(0) }
}

/// D25: `/` and the current directory must both be the sandbox root
/// (`expected` = device/inode of init's root, as opened by the supervisor).
fn check_root(expected: (u64, u64)) -> io::Result<()> {
    for path in [c"/", c"."] {
        let got = sys::dev_ino(libc::AT_FDCWD, path, 0)?;
        if got != expected {
            return Err(io::Error::other(format!(
                "{} is {got:?}, not the sandbox root {expected:?}",
                path.to_string_lossy()
            )));
        }
    }
    Ok(())
}

/// `D`: inside the pid namespace (its parent `C` is outside), holding
/// capabilities in the sandbox user namespace until `drop_all_caps`.
/// Re-applies exactly what init applied (DESIGN §14.4), then forks `W` and
/// exits. Any failure is reported and nothing is started (fail closed).
fn child_d(ctx: &ExecContext, spec: &ExecSpec, keep: &[RawFd], root_id: (u64, u64)) -> ! {
    let status = *keep.last().expect("status fd");
    let step = |what: &str, r: io::Result<()>| {
        if let Err(e) = r {
            die(status, &format!("{what}: {e}"));
        }
    };
    let _ = sys::prctl(1 /* PR_SET_PDEATHSIG */, libc::SIGKILL as u64, 0, 0, 0);
    // 1. first action: nobody in the sandbox may inspect us while we hold caps
    step("dumpable", sys::set_dumpable(false));
    // 2. fds 0-2 -> the sandbox's /dev/null; the passed stdio stays in `keep`
    step("stdio", sys::stdio_to_dev_null());
    // SAFETY: setsid in a freshly forked child.
    unsafe { libc::setsid() };
    // 3-5. same functions and inputs as init
    step("setrlimit", init::set_rlimits(&ctx.policy));
    step("chdir", std::env::set_current_dir("/"));
    // D25: re-verify before any Landlock root is resolved by pathname.
    step("root check", check_root(root_id));
    if let Err(e) = landlock::apply(&ctx.landlock, ctx.require_scope) {
        die(status, &format!("landlock: {e}"));
    }
    step(
        "no_new_privs",
        sys::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).map(drop),
    );
    step("dropping capabilities", init::drop_all_caps());
    if let Err(e) = seccomp::install(&ctx.seccomp) {
        die(status, &format!("seccomp: {e}"));
    }
    step("dumpable", sys::set_dumpable(false));
    if let Err(e) = init::verify_hardening() {
        die(status, &format!("post-setup verification: {e:#}"));
    }
    // 6. only now: the working directory (resolved inside the sandbox)
    step("chdir(cwd)", std::env::set_current_dir(&spec.cwd));
    let (argv, envp) = match (
        init::cstrings(spec.argv.iter().map(String::as_str)),
        init::cstrings(
            spec.env
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .iter()
                .map(String::as_str),
        ),
    ) {
        (Ok(a), Ok(e)) => (a, e),
        _ => die(status, "NUL byte in request"),
    };
    // SAFETY: `D` is single-threaded; `W` only runs `child_w`.
    let d_pid = unsafe { libc::getpid() };
    let w = unsafe { libc::fork() };
    if w < 0 {
        die(status, &format!("fork: {}", io::Error::last_os_error()));
    }
    if w == 0 {
        child_w(spec, &argv, &envp, keep, d_pid);
    }
    // SAFETY: terminate; `W` is reparented to the sandbox init.
    unsafe { libc::_exit(0) }
}

/// `W`: waits until sandbox init has adopted it, forks the program, relays.
fn child_w(spec: &ExecSpec, argv: &[CString], envp: &[CString], keep: &[RawFd], d_pid: i32) -> ! {
    let status = *keep.last().expect("status fd");
    let stdio = &keep[..keep.len() - 1];
    // SAFETY: plain getppid.
    let ppid = || unsafe { libc::getppid() };
    let deadline = Instant::now() + REPARENT_TIMEOUT;
    loop {
        match ppid() {
            1 => break,
            p if p == d_pid && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            p => die(
                status,
                &format!("not adopted by the sandbox init (ppid {p})"),
            ),
        }
    }
    // Exec-failure channel: closes on a successful `execve` (CLOEXEC), carries
    // the errno otherwise.
    let mut pipe = [0 as libc::c_int; 2];
    // SAFETY: valid 2-element out array.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        die(status, &format!("pipe: {}", io::Error::last_os_error()));
    }
    // SAFETY: `W` is single-threaded; `P` only runs `child_p`.
    let w_pid = unsafe { libc::getpid() };
    let p = unsafe { libc::fork() };
    if p < 0 {
        die(status, &format!("fork: {}", io::Error::last_os_error()));
    }
    if p == 0 {
        child_p(spec, argv, envp, stdio, pipe[1], w_pid);
    }
    // SAFETY: closing our copy of the write end.
    unsafe { libc::close(pipe[1]) };
    // From here `W` holds only the status socket: the stdio copies must go,
    // or a pty master would never see the slave close.
    sys::close_all_except(&[status, pipe[0]]);
    // A 4-byte record = `P` reported an exec failure before `execve`.
    // Clean EOF = the write end was closed by CLOEXEC: `execve` succeeded.
    // Anything else (read error, partial record) is ambiguous and treated
    // as an exec failure — `Started` is never reported on ambiguous evidence.
    let mut errno = [0u8; 4];
    let got = match read_some(pipe[0], &mut errno) {
        Ok(4) => 4,
        Ok(0) => 0,
        _ => 1,
    };
    // SAFETY: closing the read end.
    unsafe { libc::close(pipe[0]) };
    if got != 0 {
        let e = if got == 4 {
            i32::from_le_bytes(errno)
        } else {
            libc::EIO
        };
        let mut st = 0;
        // SAFETY: reaping our exited child.
        unsafe { libc::waitpid(p, &mut st, 0) };
        let msg = format!(
            "cannot execute {}: {}",
            spec.argv[0],
            io::Error::from_raw_os_error(e)
        );
        let _ = sys::send_all(
            status,
            format_status(&Status::ExecFailed {
                errno: e,
                message: msg,
            })
            .as_bytes(),
        );
        // SAFETY: terminate.
        unsafe { libc::_exit(0) }
    }
    let _ = sys::send_all(status, format_status(&Status::Started(p)).as_bytes());
    let exit = match monitor(p, status) {
        Ok(x) => x,
        Err(_) => Exit::Code(EXIT_INTERNAL),
    };
    let _ = sys::send_all(status, format_status(&Status::Exited(exit)).as_bytes());
    // SAFETY: terminate; init reaps us.
    unsafe { libc::_exit(0) }
}

/// `P`: becomes the program. On failure before `execve` the errno goes to
/// `W` through `errpipe` and the process exits 126/127.
fn child_p(
    spec: &ExecSpec,
    argv: &[CString],
    envp: &[CString],
    stdio: &[RawFd],
    errpipe: RawFd,
    w_pid: i32,
) -> ! {
    let fail = |errno: i32| -> ! {
        // SAFETY: write of a 4-byte buffer to a descriptor we own, then exit.
        unsafe {
            let b = errno.to_le_bytes();
            libc::write(errpipe, b.as_ptr().cast(), 4);
            libc::_exit(if errno == libc::ENOENT {
                EXIT_NOT_FOUND
            } else {
                EXIT_CANNOT_EXEC
            })
        }
    };
    let last_errno = || {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    };
    // SAFETY: raw syscalls in a freshly forked, single-threaded child.
    unsafe {
        // Dies with `W` (and so never outlives the monitor that reports it).
        libc::prctl(1 /* PR_SET_PDEATHSIG */, libc::SIGKILL as u64, 0, 0, 0);
        if libc::getppid() != w_pid {
            libc::_exit(EXIT_INTERNAL);
        }
        if libc::setsid() < 0 {
            fail(last_errno());
        }
        if spec.tty {
            // The slave becomes fd 0-2 and the controlling terminal.
            for fd in 0..3 {
                if libc::dup2(stdio[0], fd) < 0 {
                    fail(last_errno());
                }
            }
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
        } else {
            for (i, fd) in stdio.iter().take(3).enumerate() {
                if libc::dup2(*fd, i as RawFd) < 0 {
                    fail(last_errno());
                }
            }
        }
    }
    // Everything else (status socket, the high stdio copies) closes; only the
    // error pipe stays, and it is CLOEXEC.
    sys::close_all_except(&[errpipe]);
    sig::reset_default(&[
        libc::SIGPIPE,
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGCHLD,
    ]);
    // SAFETY: an empty mask is always valid.
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }
    let prog = init::resolve_program(
        &spec.argv[0],
        spec.env.get("PATH").map(String::as_str),
        init::is_executable,
    );
    let Some(prog) = prog else {
        fail(libc::ENOENT);
    };
    let Ok(prog_c) = sys::cstr(&prog) else {
        fail(libc::EINVAL);
    };
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    // SAFETY: NUL-terminated pointer arrays that outlive the call.
    unsafe { libc::execve(prog_c.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr()) };
    fail(last_errno())
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    #[test]
    fn dev_ino_matches_std_metadata() {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata("/").unwrap();
        let (dev, ino) = sys::dev_ino(libc::AT_FDCWD, c"/", 0).unwrap();
        assert_eq!(ino, m.ino());
        assert_eq!(dev, m.dev());
        // by descriptor, as the supervisor's root fd is identified
        let f = std::fs::File::open("/").unwrap();
        let id = sys::dev_ino(f.as_raw_fd(), c"", sys::AT_EMPTY_PATH as _).unwrap();
        assert_eq!(id, (dev, ino));
    }

    #[test]
    fn root_check_fails_closed_on_mismatch() {
        // D25: a root identity that is not this "/" must be refused.
        let e = check_root((0, 0)).expect_err("mismatched root must fail");
        assert!(e.to_string().contains("not the sandbox root"), "{e}");
        // "/" alone matches; "." only matches when the cwd is "/", so only
        // assert the "/" half here (the test must not chdir the process).
        let real = sys::dev_ino(libc::AT_FDCWD, c"/", 0).unwrap();
        if std::env::current_dir().unwrap() == std::path::Path::new("/") {
            check_root(real).unwrap();
        } else {
            assert!(check_root(real).is_err(), "cwd != / must fail the check");
        }
    }

    fn rules() -> ExecRules {
        ExecRules {
            env_pass: vec!["GOFLAGS".into(), "HISN_LEAK_PASSED".into(), "HOME".into()],
            base_env: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/run/hisn/home".into()),
                ("CI".into(), "1".into()),
            ]),
            default_cwd: "/work/p".into(),
        }
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn env(e: &[(&str, &str)]) -> BTreeMap<String, String> {
        e.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- validation

    #[test]
    fn a_plain_request_gets_the_base_env_and_default_cwd() {
        let s = validate(argv(&["ls", "-l"]), None, env(&[]), false, 3, &rules()).unwrap();
        assert_eq!(s.argv, ["ls", "-l"]);
        assert_eq!(s.cwd, "/work/p");
        assert_eq!(s.env, rules().base_env);
        assert!(!s.tty && s.fd_count() == 3);
    }

    #[test]
    fn passed_env_keys_are_applied_over_the_base() {
        let s = validate(
            argv(&["x"]),
            Some("/srv/x".into()),
            env(&[("GOFLAGS", "-mod=mod"), ("HISN_LEAK_PASSED", "v")]),
            false,
            3,
            &rules(),
        )
        .unwrap();
        assert_eq!(s.env["GOFLAGS"], "-mod=mod");
        assert_eq!(s.env["HISN_LEAK_PASSED"], "v");
        assert_eq!(s.env["CI"], "1", "base env is kept");
        assert_eq!(s.cwd, "/srv/x");
    }

    #[test]
    fn env_keys_outside_env_pass_reject_the_whole_request() {
        let e = validate(
            argv(&["x"]),
            None,
            env(&[
                ("GOFLAGS", "a"),
                ("AWS_SECRET_ACCESS_KEY", "hunter2"),
                ("CI", "0"),
            ]),
            false,
            3,
            &rules(),
        )
        .unwrap_err();
        // Sorted names, never values; `GOFLAGS` (allowed) is not listed.
        assert_eq!(
            e,
            Invalid::RejectedEnvKeys(vec!["AWS_SECRET_ACCESS_KEY".into(), "CI".into()])
        );
        let msg = e.to_string();
        assert!(msg.contains("AWS_SECRET_ACCESS_KEY") && !msg.contains("hunter2"));
    }

    #[test]
    fn computed_names_cannot_be_set_even_if_listed_in_env_pass() {
        // `HOME` is in env_pass in `rules()`: still refused (computed).
        let e = validate(
            argv(&["x"]),
            None,
            env(&[("HOME", "/evil")]),
            false,
            3,
            &rules(),
        )
        .unwrap_err();
        assert_eq!(e, Invalid::RejectedEnvKeys(vec!["HOME".into()]));
        let mut r = rules();
        r.env_pass.push("CARGO_HOME".into());
        assert!(
            validate(
                argv(&["x"]),
                None,
                env(&[("CARGO_HOME", "/e")]),
                false,
                3,
                &r
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let ok_env = env(&[]);
        let r = rules();
        let bad = |a: Vec<String>, c: Option<&str>, e: BTreeMap<String, String>, tty, fds| {
            validate(a, c.map(str::to_owned), e, tty, fds, &r).is_err()
        };
        assert!(bad(vec![], None, ok_env.clone(), false, 3), "empty argv");
        assert!(
            bad(argv(&[""]), None, ok_env.clone(), false, 3),
            "empty argv[0]"
        );
        assert!(
            bad(argv(&["a\0b"]), None, ok_env.clone(), false, 3),
            "NUL in argv"
        );
        assert!(
            bad(argv(&["x"]), Some("rel"), ok_env.clone(), false, 3),
            "relative cwd"
        );
        assert!(
            bad(argv(&["x"]), Some("/a/../b"), ok_env.clone(), false, 3),
            ".. in cwd"
        );
        assert!(
            bad(argv(&["x"]), Some("/a\0"), ok_env.clone(), false, 3),
            "NUL in cwd"
        );
        assert!(
            bad(argv(&["x"]), None, env(&[("", "v")]), false, 3),
            "empty env name"
        );
        assert!(
            bad(argv(&["x"]), None, env(&[("A=B", "v")]), false, 3),
            "= in env name"
        );
        assert!(
            bad(argv(&["x"]), None, env(&[("GOFLAGS", "a\0")]), false, 3),
            "NUL in value"
        );
        assert!(bad(
            vec!["x".into(); MAX_ARGV + 1],
            None,
            ok_env.clone(),
            false,
            3
        ));
        assert!(
            bad(vec!["x".repeat(MAX_TOTAL)], None, ok_env, false, 3),
            "too big"
        );
    }

    #[test]
    fn descriptor_count_must_match_the_mode() {
        let r = rules();
        let e = validate(argv(&["x"]), None, env(&[]), false, 1, &r).unwrap_err();
        assert_eq!(e, Invalid::Fds { want: 3, got: 1 });
        assert!(validate(argv(&["x"]), None, env(&[]), true, 3, &r).is_err());
        assert!(validate(argv(&["x"]), None, env(&[]), true, 1, &r).is_ok());
        assert!(validate(argv(&["x"]), None, env(&[]), false, 0, &r).is_err());
    }

    #[test]
    fn spec_round_trips_and_rejects_unknown_keys() {
        let s = validate(argv(&["x"]), None, env(&[]), false, 3, &rules()).unwrap();
        let j = serde_json::to_vec(&s).unwrap();
        assert_eq!(serde_json::from_slice::<ExecSpec>(&j).unwrap(), s);
        assert!(
            serde_json::from_str::<ExecSpec>(
                r#"{"argv":["x"],"cwd":"/","env":{},"tty":false,"extra":1}"#
            )
            .is_err()
        );
    }

    // ---- status protocol

    #[test]
    fn status_lines_round_trip() {
        for s in [
            Status::Started(42),
            Status::Exited(Exit::Code(0)),
            Status::Exited(Exit::Code(255)),
            Status::Exited(Exit::Signal(15)),
            Status::SetupFailed("landlock: nope".into()),
            Status::ExecFailed {
                errno: 2,
                message: "cannot execute x: No such file".into(),
            },
        ] {
            let line = format_status(&s);
            assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
            assert_eq!(parse_status(line.trim_end_matches('\n')), Some(s));
        }
        // A message can never smuggle in a second line.
        let l = format_status(&Status::SetupFailed("a\nP 7".into()));
        assert_eq!(l.matches('\n').count(), 1);
    }

    #[test]
    fn garbage_status_lines_do_not_parse() {
        for bad in [
            "",
            "P",
            "P 0",
            "P -1",
            "P x",
            "X",
            "X exit",
            "X exit 256",
            "X exit -1",
            "X sig 0",
            "X sig 65",
            "X what 1",
            "Z 1",
            "!overflow",
            "F x y",
        ] {
            assert_eq!(parse_status(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn kill_lines() {
        assert_eq!(parse_kill(format_kill(15).trim_end()), Some(15));
        for bad in ["K 0", "K 65", "K x", "K", "kill 9", "K -9"] {
            assert_eq!(parse_kill(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn lines_split_across_pushes_and_runaway_input_is_contained() {
        let mut l = Lines::default();
        l.push(b"P 1");
        assert_eq!(l.pop_line(), None);
        l.push(b"2\nX exit 0\nX si");
        assert_eq!(l.pop_line().as_deref(), Some("P 12"));
        assert_eq!(l.pop_line().as_deref(), Some("X exit 0"));
        assert_eq!(l.pop_line(), None, "partial line is kept");
        l.push(b"g 9\n");
        assert_eq!(l.pop_line().as_deref(), Some("X sig 9"));
        let mut r = Lines::default();
        r.push(&vec![b'a'; Lines::MAX + 1]);
        let junk = r.pop_line().unwrap();
        assert_eq!(parse_status(&junk), None);
        assert_eq!(r.pop_line(), None);
    }

    #[test]
    fn wait_status_decoding() {
        assert_eq!(exit_from_wait_status(3 << 8), Exit::Code(3));
        assert_eq!(
            exit_from_wait_status(libc::SIGTERM),
            Exit::Signal(libc::SIGTERM)
        );
    }

    // ---- monitor (real child process, no namespaces needed)

    fn spawn_group(script: &str) -> (i32, Vec<OwnedFd>) {
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        std::mem::forget(child); // the monitor reaps it
        (pid, vec![])
    }

    #[test]
    fn monitor_reports_exit_codes_and_death_by_signal() {
        let (a, _b) = sys::socketpair().unwrap();
        let (p, _) = spawn_group("exit 3");
        assert_eq!(monitor(p, a.as_raw_fd()).unwrap(), Exit::Code(3));
        let (p, _) = spawn_group("kill -KILL $$");
        assert_eq!(
            monitor(p, a.as_raw_fd()).unwrap(),
            Exit::Signal(libc::SIGKILL)
        );
    }

    #[test]
    fn monitor_forwards_signals_to_the_process_group() {
        let (a, b) = sys::socketpair().unwrap();
        // The child must exist before we signal it: spawn+exec can be slow
        // under load, and a signal to a not-yet-exec'd pid is racy.
        let wait_up = |p: i32| {
            for _ in 0..300 {
                if sys::kill(p, 0).is_ok() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        };
        let (p, _) = spawn_group("sleep 60");
        assert!(wait_up(p));
        sys::send_all(b.as_raw_fd(), format_kill(libc::SIGTERM).as_bytes()).unwrap();
        assert_eq!(
            monitor(p, a.as_raw_fd()).unwrap(),
            Exit::Signal(libc::SIGTERM)
        );
        drop(a);
        drop(b);
    }

    #[test]
    fn monitor_kills_the_group_when_the_status_socket_closes() {
        let (a, b) = sys::socketpair().unwrap();
        let (p, _) = spawn_group("sleep 30");
        drop(b); // the supervisor went away: cancel
        assert_eq!(
            monitor(p, a.as_raw_fd()).unwrap(),
            Exit::Signal(libc::SIGKILL)
        );
    }

    // ---- drive (supervisor side), fake monitor on the other end

    #[test]
    fn drive_returns_the_exit_line() {
        let (mine, w) = sys::socketpair().unwrap();
        let (conn, _client) = sys::socketpair().unwrap();
        sys::send_all(w.as_raw_fd(), b"X exit 5\n").unwrap();
        let o = drive(
            &mine,
            Lines::default(),
            conn.as_raw_fd(),
            Duration::from_secs(5),
        );
        assert_eq!(o, Outcome::Exited(Exit::Code(5)));
        // buffered lines that arrived with `P` are honoured too
        let mut pre = Lines::default();
        pre.push(b"X sig 9\n");
        let o = drive(&mine, pre, conn.as_raw_fd(), Duration::from_secs(5));
        assert_eq!(o, Outcome::Exited(Exit::Signal(9)));
    }

    #[test]
    fn drive_reports_lost_when_the_monitor_vanishes() {
        let (mine, w) = sys::socketpair().unwrap();
        let (conn, _client) = sys::socketpair().unwrap();
        drop(w);
        let o = drive(
            &mine,
            Lines::default(),
            conn.as_raw_fd(),
            Duration::from_secs(5),
        );
        assert_eq!(o, Outcome::Lost);
    }

    #[test]
    fn drive_cancels_with_term_then_kill_when_the_client_disconnects() {
        let (mine, w) = sys::socketpair().unwrap();
        let (conn, client) = sys::socketpair().unwrap();
        let t = std::thread::spawn(move || {
            // Fake monitor: ignores TERM (like a stubborn program), dies on KILL.
            let mut seen = Vec::new();
            let mut lines = Lines::default();
            let mut buf = [0u8; 64];
            loop {
                let n = read_some(w.as_raw_fd(), &mut buf).unwrap();
                assert!(n > 0, "supervisor must not close before the exit line");
                lines.push(&buf[..n]);
                while let Some(l) = lines.pop_line() {
                    seen.push(parse_kill(&l).unwrap());
                    if seen.last() == Some(&libc::SIGKILL) {
                        sys::send_all(w.as_raw_fd(), b"X sig 9\n").unwrap();
                        return seen;
                    }
                }
            }
        });
        drop(client); // client disconnects
        let start = Instant::now();
        let o = drive(
            &mine,
            Lines::default(),
            conn.as_raw_fd(),
            Duration::from_millis(300),
        );
        assert_eq!(o, Outcome::Exited(Exit::Signal(9)));
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "KILL waits for the grace"
        );
        assert_eq!(t.join().unwrap(), [libc::SIGTERM, libc::SIGKILL]);
    }

    #[test]
    fn drive_does_not_cancel_while_the_client_stays_connected() {
        let (mine, w) = sys::socketpair().unwrap();
        let (conn, client) = sys::socketpair().unwrap();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            sys::send_all(w.as_raw_fd(), b"X exit 0\n").unwrap();
            w // keep it open until joined
        });
        let o = drive(
            &mine,
            Lines::default(),
            conn.as_raw_fd(),
            Duration::from_millis(50),
        );
        assert_eq!(o, Outcome::Exited(Exit::Code(0)));
        drop(client);
        drop(t.join().unwrap());
    }

    // ---- spawn handshake against a fake helper

    /// A fake `E`: answers one request like the real one would, then plays the
    /// role of `W` on the status socket with `script`.
    fn fake_helper<F>(script: F) -> (ExecClient, std::thread::JoinHandle<ExecSpec>)
    where
        F: FnOnce(OwnedFd) + Send + 'static,
    {
        let (sup, helper) = sys::socketpair_seqpacket().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            let r = sys::recv_with_fds(helper.as_raw_fd(), &mut buf).unwrap();
            // Real protocol: `<id> <json>`.
            let (id, body) = parse_helper_line(&buf[..r.len]).expect("id prefix");
            let spec: ExecSpec = serde_json::from_slice(body).unwrap();
            assert_eq!(r.fds.len(), spec.fd_count() + 1, "stdio + status socket");
            let mut fds = r.fds;
            let status = fds.pop().unwrap();
            // A pid that is nobody in particular: a fake reply must not let the
            // supervisor kill anything of ours.
            let reply = format!("ok {id} 1");
            sys::send_with_fds(helper.as_raw_fd(), reply.as_bytes(), &[]).unwrap();
            script(status);
            spec
        });
        let mut c = ExecClient::new(sup);
        c.reap_grace = Duration::from_millis(50);
        (c, t)
    }

    fn stdio3() -> Vec<OwnedFd> {
        (0..3)
            .map(|_| {
                let f = std::fs::File::open("/dev/null").unwrap();
                OwnedFd::from(f)
            })
            .collect()
    }

    fn a_spec() -> ExecSpec {
        validate(argv(&["true"]), None, env(&[]), false, 3, &rules()).unwrap()
    }

    #[test]
    fn spawn_succeeds_when_the_monitor_reports_started() {
        let (c, t) = fake_helper(|st| {
            sys::send_all(st.as_raw_fd(), b"P 7\nX exit 0\n").unwrap();
            std::mem::forget(st);
        });
        let sp = c
            .spawn(&a_spec(), stdio3(), Duration::from_secs(5))
            .unwrap();
        assert_eq!(sp.pid, 7);
        // the exit line that arrived with `P` is not lost
        let o = drive(&sp.status, sp.pending, -1, Duration::from_secs(1));
        assert_eq!(o, Outcome::Exited(Exit::Code(0)));
        assert_eq!(t.join().unwrap(), a_spec());
    }

    #[test]
    fn spawn_maps_setup_and_exec_failures() {
        let (c, t) = fake_helper(|st| {
            sys::send_all(st.as_raw_fd(), b"E landlock: boom\n").unwrap();
        });
        match c.spawn(&a_spec(), stdio3(), Duration::from_secs(5)) {
            Err(SpawnError::Exec {
                errno: None,
                message,
            }) => assert_eq!(message, "landlock: boom"),
            other => panic!("{:?}", other.err()),
        }
        t.join().unwrap();
        let (c, t) = fake_helper(|st| {
            sys::send_all(st.as_raw_fd(), b"F 2 cannot execute nope\n").unwrap();
        });
        match c.spawn(&a_spec(), stdio3(), Duration::from_secs(5)) {
            Err(SpawnError::Exec { errno: Some(2), .. }) => {}
            other => panic!("{:?}", other.err()),
        }
        t.join().unwrap();
    }

    #[test]
    fn spawn_fails_when_the_chain_dies_before_starting() {
        let (c, t) = fake_helper(drop); // status socket closes at once
        let e = c
            .spawn(&a_spec(), stdio3(), Duration::from_secs(5))
            .err()
            .unwrap();
        assert!(matches!(e, SpawnError::Internal(m) if m.contains("vanished")));
        t.join().unwrap();
    }

    #[test]
    fn a_stuck_spawn_times_out_and_the_chain_is_torn_down() {
        // The fake helper reports a real, killable pid as "C" and then goes silent.
        let victim = Command::new("sleep").arg("30").spawn().unwrap();
        let vpid = victim.id();
        let (sup, helper) = sys::socketpair_seqpacket().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf2 = vec![0u8; 64 * 1024];
            let r = sys::recv_with_fds(helper.as_raw_fd(), &mut buf2).unwrap();
            let id = parse_helper_line(&buf2[..r.len]).expect("id prefix").0;
            let raw = format!("ok {id} {vpid}");
            sys::send_with_fds(helper.as_raw_fd(), raw.as_bytes(), &[]).unwrap();
            std::thread::sleep(Duration::from_millis(600));
            drop(r);
        });
        let mut c = ExecClient::new(sup);
        c.reap_grace = Duration::from_millis(50);
        let started = Instant::now();
        let e = c
            .spawn(&a_spec(), stdio3(), Duration::from_millis(200))
            .err()
            .unwrap();
        assert!(matches!(e, SpawnError::Internal(m) if m.contains("timed out")));
        assert!(started.elapsed() < Duration::from_secs(3));
        let mut victim = victim;
        let st = victim.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(st.signal(), Some(libc::SIGKILL), "C was killed on timeout");
        t.join().unwrap();
    }

    #[test]
    fn a_refusing_helper_is_an_internal_error_and_stdio_is_closed() {
        let (sup, helper) = sys::socketpair_seqpacket().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf3 = vec![0u8; 64 * 1024];
            let r = sys::recv_with_fds(helper.as_raw_fd(), &mut buf3).unwrap();
            let id = parse_helper_line(&buf3[..r.len]).expect("id prefix").0;
            let raw = format!("err {id} request truncated");
            sys::send_with_fds(helper.as_raw_fd(), raw.as_bytes(), &[]).unwrap();
            drop(r);
        });
        let c = ExecClient::new(sup);
        let e = c
            .spawn(&a_spec(), stdio3(), Duration::from_secs(1))
            .err()
            .unwrap();
        assert!(matches!(e, SpawnError::Internal(m) if m.contains("truncated")));
        t.join().unwrap();
    }

    #[test]
    fn spawn_refuses_a_wrong_descriptor_count_without_contacting_the_helper() {
        let (sup, _helper) = sys::socketpair_seqpacket().unwrap();
        let c = ExecClient::new(sup);
        let two: Vec<OwnedFd> = stdio3().into_iter().take(2).collect();
        assert!(matches!(
            c.spawn(&a_spec(), two, Duration::from_secs(1))
                .err()
                .unwrap(),
            SpawnError::Internal(_)
        ));
    }

    // ---- helper-side request decoding

    #[test]
    fn replies_are_correlated_and_stale_replies_poison_the_channel() {
        use std::sync::atomic::Ordering;
        // Helper: answers the FIRST request with the id of a LATER one.
        let (sup, helper) = sys::socketpair_seqpacket().unwrap();
        let t = std::thread::spawn(move || {
            let mut b = vec![0u8; 64 * 1024];
            let r = sys::recv_with_fds(helper.as_raw_fd(), &mut b).unwrap();
            let id = parse_helper_line(&b[..r.len]).expect("id prefix").0;
            let raw = format!("ok {} 99", id + 1);
            let _ = sys::send_with_fds(helper.as_raw_fd(), raw.as_bytes(), &[]);
        });
        let c = ExecClient::new(sup);
        assert_eq!(c.next_id.load(Ordering::SeqCst), 1);
        let e = c
            .spawn(&a_spec(), stdio3(), Duration::from_secs(1))
            .err()
            .unwrap();
        assert!(
            matches!(&e, SpawnError::Internal(m) if m.contains("uncorrelated")),
            "{e:?}"
        );
        // Poisoned: a later exec fails without contacting the helper.
        let e2 = c
            .spawn(&a_spec(), stdio3(), Duration::from_secs(1))
            .err()
            .unwrap();
        assert!(
            matches!(&e2, SpawnError::Internal(m) if m.contains("unreachable")),
            "{e2:?}"
        );
        t.join().unwrap();
    }

    #[test]
    fn drive_pre_cancelled_kills_without_waiting_for_the_dead_client() {
        // A program that ignores TERM must still be killed after the grace
        // when drive starts already cancelled.
        let (mine, w) = sys::socketpair().unwrap();
        let child = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; sleep 60")
            .process_group(0)
            .spawn()
            .unwrap();
        let wpid = child.id() as i32;
        std::mem::forget(child);
        let t = std::thread::spawn(move || {
            // Fake W: ignores TERM, dies on KILL.
            let mut lines = Lines::default();
            let mut buf = [0u8; 64];
            let mut seen = Vec::new();
            loop {
                let n = read_some(w.as_raw_fd(), &mut buf).unwrap();
                lines.push(&buf[..n]);
                while let Some(l) = lines.pop_line() {
                    if let Some(sig) = parse_kill(&l) {
                        seen.push(sig);
                        if sig == libc::SIGKILL {
                            let _ = sys::kill(wpid, libc::SIGKILL);
                            sys::send_all(w.as_raw_fd(), b"X sig 9\n").unwrap();
                            return seen;
                        } else {
                            let _ = sys::kill(wpid, sig); // ignore TERM like a stubborn program
                        }
                    }
                }
            }
        });
        let start = Instant::now();
        let o = drive_from(
            &mine,
            Lines::default(),
            -1,
            Duration::from_millis(200),
            true,
        );
        assert_eq!(o, Outcome::Exited(Exit::Signal(9)));
        assert!(
            start.elapsed() >= Duration::from_millis(200),
            "KILL waited for the grace"
        );
        assert_eq!(t.join().unwrap(), [libc::SIGTERM, libc::SIGKILL]);
    }
    #[test]
    fn helper_decoding_checks_counts_truncation_and_moves_fds_high() {
        let s = a_spec();
        let body = serde_json::to_vec(&s).unwrap();
        let four: Vec<OwnedFd> = (0..4)
            .map(|_| OwnedFd::from(std::fs::File::open("/dev/null").unwrap()))
            .collect();
        let (got, fds) = prepare_request(&body, four, false).unwrap();
        assert_eq!(got, s);
        assert_eq!(fds.len(), 4);
        assert!(fds.iter().all(|f| f.as_raw_fd() >= HIGH_FD));
        let three: Vec<OwnedFd> = stdio3();
        assert!(
            prepare_request(&body, three, false).is_err(),
            "status fd missing"
        );
        assert!(prepare_request(&body, vec![], true).is_err(), "truncated");
        assert!(prepare_request(b"{", vec![], false).is_err(), "bad json");
        let mut tty_spec = s;
        tty_spec.tty = true;
        let b = serde_json::to_vec(&tty_spec).unwrap();
        let two: Vec<OwnedFd> = stdio3().into_iter().take(2).collect();
        assert!(
            prepare_request(&b, two, false).is_ok(),
            "tty: slave + status"
        );
    }

    #[test]
    fn die_reports_on_the_status_socket_in_a_forked_child() {
        let (a, b) = sys::socketpair().unwrap();
        // SAFETY: the child only writes to a socket and `_exit`s.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                die(a.as_raw_fd(), "confinement exploded");
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            assert_eq!(init::decode_status(st), EXIT_INTERNAL);
        }
        let mut buf = [0u8; 128];
        let n = read_some(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(
            parse_status(std::str::from_utf8(&buf[..n]).unwrap().trim_end()),
            Some(Status::SetupFailed("confinement exploded".into()))
        );
    }
}

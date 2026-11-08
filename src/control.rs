//! Control socket protocol (POLICY-SPEC §7) and server loop.
//!
//! The wire format is newline-delimited JSON, one response line per request.
//! The server is transport only: authorisation of the peer (DESIGN §9 R5) and
//! the operations themselves are supplied through [`Handler`], which keeps
//! this module testable without namespaces.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

/// Maximum accepted request line (bytes, excluding the newline).
pub const MAX_LINE: usize = 64 * 1024;

/// Maximum accepted *response* line on the client side. Responses such as
/// `inspect` (full mountinfo + resolved policy) are legitimately larger than
/// any request.
pub const MAX_RESPONSE_LINE: usize = 16 * 1024 * 1024;

pub const E_BAD_REQUEST: &str = "E_BAD_REQUEST";
pub const E_PATH_FORBIDDEN: &str = "E_PATH_FORBIDDEN";
pub const E_NOT_FOUND: &str = "E_NOT_FOUND";
pub const E_NOT_GRANTABLE: &str = "E_NOT_GRANTABLE";
pub const E_EXISTS: &str = "E_EXISTS";
pub const E_NOT_GRANTED: &str = "E_NOT_GRANTED";
pub const E_HELD: &str = "E_HELD";
pub const E_INTERNAL: &str = "E_INTERNAL";
/// The authorization seam refused the request (0.4.0, src/authz.rs).
pub const E_UNAUTHORIZED: &str = "E_UNAUTHORIZED";
/// The program could not be started (confinement failed, not found, not executable).
pub const E_EXEC: &str = "E_EXEC";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Ro,
    Rw,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Ro => "ro",
            Mode::Rw => "rw",
        }
    }
}

fn term() -> String {
    "TERM".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Grant {
        path: String,
        #[serde(default)]
        mode: Mode,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        client: Option<ClientField>,
    },
    Revoke {
        path: String,
        #[serde(default)]
        hard: bool,
        #[serde(default)]
        kill_holders: bool,
        #[serde(default)]
        client: Option<ClientField>,
    },
    // Struct variants (not unit): serde ignores unknown fields on unit variants
    // of internally tagged enums, which would break "unknown keys are errors".
    List {
        #[serde(default)]
        client: Option<ClientField>,
    },
    Inspect {
        #[serde(default)]
        client: Option<ClientField>,
    },
    Kill {
        #[serde(default = "term")]
        signal: String,
        #[serde(default)]
        client: Option<ClientField>,
    },
    /// Run a program inside the running session (DESIGN §14). The request
    /// travels with its stdio descriptors (`SCM_RIGHTS`).
    Exec {
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        tty: bool,
        /// 0.4.0 step 2: an attach is an exec with `attach: true`. The
        /// supervisor starts the session's shell ($SHELL from the env
        /// snapshot, else /bin/sh) in the session cwd. Old clients that
        /// don't send this field default to `false` (a normal exec).
        #[serde(default)]
        attach: bool,
        #[serde(default)]
        client: Option<ClientField>,
    },
    /// Signal a live exec'd program (by `exec_id` preferred, or by
    /// in-sandbox pid for 0.2 clients — deprecated).
    Signal {
        #[serde(default)]
        exec_id: Option<String>,
        #[serde(default)]
        pid: Option<i32>,
        #[serde(default = "term")]
        signal: String,
        #[serde(default)]
        client: Option<ClientField>,
    },
    /// 0.4.1 step 3: report live clients and execs for `ls --json` (the
    /// per-session view that the on-disk `session.json` cannot supply).
    SessionInfo {
        #[serde(default)]
        client: Option<ClientField>,
    },
}

/// The client-supplied identity fields (0.4.0 F1). The supervisor fills
/// uid/pid from SO_PEERCRED; these are the labels the client may send.
/// `uid` is not a field here (nor in the request): uid comes only from
/// SO_PEERCRED. A request whose `client` object contains `uid` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientField {
    pub label: Option<String>,
    pub label_source: Option<String>,
    pub req_id: Option<String>,
}

impl Request {
    pub fn op_name(&self) -> &'static str {
        match self {
            Request::Grant { .. } => "grant",
            Request::Revoke { .. } => "revoke",
            Request::List { .. } => "list",
            Request::Inspect { .. } => "inspect",
            Request::Kill { .. } => "kill",
            Request::Exec { .. } => "exec",
            Request::Signal { .. } => "signal",
            Request::SessionInfo { .. } => "sessioninfo",
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Request::Grant { path, .. } | Request::Revoke { path, .. } => Some(path),
            _ => None,
        }
    }

    /// 0.4.1 R2: a read-only observer. An observer connection is never a
    /// client: it is not listed in `clients[]`, creates no member, and touches
    /// neither the lease nor the idle clock, on request or on disconnect. These
    /// are the `ls --json` / `inspect` / `list` queries a watcher makes.
    /// Authorized mutations (exec, attach, grant, revoke, signal, kill/stop) are
    /// clients and activity.
    pub fn is_observer(&self) -> bool {
        matches!(
            self,
            Request::SessionInfo { .. } | Request::Inspect { .. } | Request::List { .. }
        )
    }

    /// The client-supplied identity fields (0.4.0 F1), if any.
    pub fn client_field(&self) -> Option<&ClientField> {
        match self {
            Request::Grant { client, .. }
            | Request::Revoke { client, .. }
            | Request::List { client, .. }
            | Request::Inspect { client, .. }
            | Request::Kill { client, .. }
            | Request::Exec { client, .. }
            | Request::Signal { client, .. }
            | Request::SessionInfo { client, .. } => client.as_ref(),
        }
    }
}

pub fn parse_request(line: &str) -> Result<Request, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

pub fn ok(extra: Value) -> Value {
    let mut v = json!({ "ok": true });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    v
}

pub fn err(code: &str, message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": code, "message": message.into() })
}

/// One table for both directions, so a name the supervisor prints is always a
/// name the client (and `signal`) accepts.
const SIGNALS: [(&str, i32); 30] = [
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("CHLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
    ("URG", libc::SIGURG),
    ("XCPU", libc::SIGXCPU),
    ("XFSZ", libc::SIGXFSZ),
    ("VTALRM", libc::SIGVTALRM),
    ("PROF", libc::SIGPROF),
    ("WINCH", libc::SIGWINCH),
    ("IO", libc::SIGIO),
    ("PWR", libc::SIGPWR),
    ("SYS", libc::SIGSYS),
];

/// Signal name (with or without `SIG`, any case) or number → signal number.
/// `None` for unknown input.
pub fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return (1..=64).contains(&n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// Signal number → the name clients print and send back (`TERM`, not
/// `SIGTERM`); numbers without a name (real-time signals) stay numeric, which
/// [`parse_signal`] accepts again.
pub fn signal_name(n: i32) -> String {
    SIGNALS
        .iter()
        .find(|(_, v)| *v == n)
        .map_or_else(|| n.to_string(), |(name, _)| (*name).to_owned())
}

/// A control connection's identity, unique for the life of the process.
///
/// Not the fd: the kernel reuses a closed descriptor number immediately, so a
/// record keyed by fd could be replaced by a later connection and then removed
/// (or left behind) by the wrong disconnect. A sequence number is never reused.
pub type ConnId = u64;

/// Source of [`ConnId`]s.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Operations behind the socket. Implemented by the supervisor.
pub trait Handler: Send + Sync + 'static {
    /// Decide whether this peer may talk to the socket (R5). Called on accept
    /// and again before every request. `Err` closes the connection.
    fn authorize(&self, peer: &UnixStream) -> Result<(), String>;
    /// F2 fix: a client connected (serve_conn thread started, after authorize).
    /// Called once per connection, on its first request line only.
    fn connect(&self, _conn: ConnId) {}
    /// 0.4.1 R2: should this parsed request make its connection a counted
    /// client? Asked before `connect`. Only a request that will actually be
    /// admitted counts: observers never do, and a mutation the authorization
    /// decision refuses does not register. The default is "any non-observer".
    fn admit(&self, req: &Request, _peer: &UnixStream, _conn: ConnId) -> bool {
        !req.is_observer()
    }
    /// F2 fix: a client disconnected (serve_conn thread exited). Called exactly
    /// once for every `connect`, on every close path (EOF, error, misuse).
    fn disconnect(&self, _conn: ConnId) {}
    /// Handle one request and return its (final) response line. `fds` are the
    /// descriptors that arrived with the request: the server only lets them
    /// through on the *first* request line of a connection and only for
    /// `exec`, so every other handler can assume `fds` is empty. A handler may
    /// write intermediate response lines to `conn` before returning the final
    /// one (`exec`: `{"ok":true,"pid":N}`, later `{"exit":…}`).
    fn handle(&self, req: Request, fds: Vec<OwnedFd>, conn: &UnixStream, id: ConnId) -> Value;
}

/// One request line plus the descriptors that arrived with it.
pub struct ReadLine {
    pub line: String,
    pub fds: Vec<OwnedFd>,
}

/// Line reader over a unix stream socket that also receives `SCM_RIGHTS`.
///
/// Every descriptor that arrives is owned from the moment of `recvmsg`, so a
/// rejected request can never leak one. Descriptors received while a line is
/// still incomplete are attached to that line when it completes. Truncated
/// ancillary data is an error (a half-delivered descriptor set must never be
/// used).
pub struct FdLineReader {
    fd: RawFd,
    buf: Vec<u8>,
    fds: Vec<OwnedFd>,
}

impl FdLineReader {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            buf: Vec::new(),
            fds: Vec::new(),
        }
    }

    /// Bytes already read past the last returned line.
    pub fn leftover(&self) -> usize {
        self.buf.len()
    }

    /// `Ok(None)` = clean EOF; `Err(InvalidData)` = oversized, non-UTF-8 or
    /// truncated input.
    pub fn next_line(&mut self) -> io::Result<Option<ReadLine>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                if pos > MAX_LINE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                let rest = self.buf.split_off(pos + 1);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.pop();
                let line = String::from_utf8(line)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not UTF-8"))?;
                return Ok(Some(ReadLine {
                    line,
                    fds: std::mem::take(&mut self.fds),
                }));
            }
            if self.buf.len() > MAX_LINE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            let mut chunk = [0u8; 8192];
            let r = match crate::sys::recv_with_fds(self.fd, &mut chunk) {
                Ok(r) => r,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            };
            self.fds.extend(r.fds);
            if r.truncated {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ancillary data truncated",
                ));
            }
            if r.len == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..r.len]);
        }
    }
}

/// Read one `\n`-terminated line of at most [`MAX_LINE`] bytes.
/// `Ok(None)` = clean EOF; `Err(InvalidData)` = oversized line.
pub fn read_line_limited<R: BufRead>(r: &mut R) -> io::Result<Option<String>> {
    read_line_max(r, MAX_LINE)
}

/// Like [`read_line_limited`] with an explicit byte limit.
pub fn read_line_max<R: BufRead>(r: &mut R, max: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not UTF-8"))
}

/// Requests currently being handled or answered.
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

struct Inflight;

impl Inflight {
    fn enter() -> Self {
        INFLIGHT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        INFLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Wait until every in-flight request has been answered (or `timeout`).
/// The supervisor calls this before exiting so that e.g. the response to a
/// hard revoke — which kills the command and thereby ends the session — is
/// delivered first. Returns `true` if drained.
pub fn drain(timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while INFLIGHT.load(Ordering::SeqCst) > 0 {
        if Instant::now() > end {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    true
}

/// F2 fix: calls `disconnect` on drop so the connection count stays accurate
/// even if `serve_conn` returns early (EOF, error, misuse).
struct ClientGuard<'a> {
    handler: &'a dyn Handler,
    conn: ConnId,
}

impl Drop for ClientGuard<'_> {
    fn drop(&mut self) {
        self.handler.disconnect(self.conn);
    }
}

fn serve_conn(h: &dyn Handler, stream: UnixStream) {
    if h.authorize(&stream).is_err() {
        return;
    }
    // A connection is a client (idle accounting) only once it sent a request
    // line: a bare connect-and-close (`hisn ls` liveness probe, is_stale) is
    // neither a connected client nor activity — counting it made every `ls`
    // poll reset the idle timer (0.4.0 L61).
    let id: ConnId = NEXT_CONN_ID.fetch_add(1, Ordering::SeqCst);
    let mut _guard: Option<ClientGuard> = None;
    let mut reader = FdLineReader::new(stream.as_raw_fd());
    let mut out = &stream;
    let mut lines = 0usize;
    loop {
        let ReadLine { line, fds } = match reader.next_line() {
            Ok(Some(l)) => l,
            _ => return, // EOF, oversized, truncated or malformed framing: close
        };
        lines += 1;
        if h.authorize(&stream).is_err() {
            return;
        }
        let _inflight = Inflight::enter();
        let resp = match parse_request(&line) {
            Ok(req) => {
                // 0.4.1 R2: an observer request does not make this connection a
                // client. Registration waits for the first non-observer
                // request, so a connection that only observes is never counted
                // and never touches the idle clock.
                if _guard.is_none() && h.admit(&req, &stream, id) {
                    h.connect(id);
                    _guard = Some(ClientGuard {
                        handler: h,
                        conn: id,
                    });
                }
                let is_exec = matches!(req, Request::Exec { .. });
                // Descriptors are valid only with the first line of a
                // connection and only for `exec`; `exec` itself must be the
                // first line and must not be pipelined with further input.
                let misuse = (!fds.is_empty() && !(is_exec && lines == 1))
                    || (is_exec && (lines != 1 || reader.leftover() > 0));
                if misuse {
                    let _ = writeln!(
                        out,
                        "{}",
                        err(
                            E_BAD_REQUEST,
                            "descriptors are only accepted with a first, unpipelined `exec` request"
                        )
                    );
                    return; // `fds` dropped: every received descriptor is closed
                }
                h.handle(req, fds, &stream, id)
            }
            // Unknown op / bad JSON closes the connection (POLICY-SPEC §7).
            Err(m) => {
                let _ = writeln!(out, "{}", err(E_BAD_REQUEST, m));
                return;
            }
        };
        if writeln!(out, "{resp}").is_err() {
            return;
        }
    }
}

/// Accept loop; one thread per connection. Never returns while the listener
/// is open; run it on a dedicated thread.
pub fn serve(listener: UnixListener, handler: Arc<dyn Handler>) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let h = Arc::clone(&handler);
        thread::spawn(move || serve_conn(h.as_ref(), stream));
    }
}

/// Client side: send one request line, return the parsed response.
pub fn request(socket: &std::path::Path, req: &Value) -> io::Result<Value> {
    let mut s = UnixStream::connect(socket)?;
    writeln!(s, "{req}")?;
    let mut r = BufReader::new(s);
    let line = read_line_max(&mut r, MAX_RESPONSE_LINE)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no response"))?;
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::idle_due;
    use std::io::Cursor;
    use std::sync::Mutex;

    #[test]
    fn requests_parse_with_defaults() {
        assert_eq!(
            parse_request(r#"{"op":"grant","path":"/a"}"#).unwrap(),
            Request::Grant {
                path: "/a".into(),
                mode: Mode::Ro,
                recursive: false,
                client: None
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"grant","path":"/a","mode":"rw","recursive":true}"#).unwrap(),
            Request::Grant {
                path: "/a".into(),
                mode: Mode::Rw,
                recursive: true,
                client: None
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"revoke","path":"/a"}"#).unwrap(),
            Request::Revoke {
                path: "/a".into(),
                hard: false,
                kill_holders: false,
                client: None
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"list"}"#).unwrap(),
            Request::List { client: None }
        );
        assert_eq!(
            parse_request(r#"{"op":"inspect"}"#).unwrap(),
            Request::Inspect { client: None }
        );
        assert_eq!(
            parse_request(r#"{"op":"kill"}"#).unwrap(),
            Request::Kill {
                signal: "TERM".into(),
                client: None
            }
        );
    }

    #[test]
    fn bad_requests_are_rejected() {
        for bad in [
            "",
            "not json",
            r#"{"op":"exec","cmd":"id"}"#,
            r#"{"op":"exec"}"#,
            r#"{"op":"exec","argv":"id"}"#,
            r#"{"op":"exec","argv":["id"],"tty":"yes"}"#,
            r#"{"op":"signal","pid":"1"}"#,
            r#"{"op":"grant"}"#,
            r#"{"op":"grant","path":"/a","mode":"rwx"}"#,
            r#"{"op":"list","extra":1}"#,
            r#"{"path":"/a"}"#,
            r#"["grant"]"#,
        ] {
            assert!(parse_request(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn signals() {
        assert_eq!(parse_signal("TERM"), Some(libc::SIGTERM));
        assert_eq!(parse_signal("sigint"), Some(libc::SIGINT));
        assert_eq!(parse_signal("9"), Some(9));
        assert_eq!(parse_signal("0"), None);
        assert_eq!(parse_signal("65"), None);
        assert_eq!(parse_signal("BOGUS"), None);
    }

    #[test]
    fn signal_names_round_trip_through_parse_signal() {
        for n in 1..=64 {
            assert_eq!(parse_signal(&signal_name(n)), Some(n), "signal {n}");
        }
        assert_eq!(signal_name(libc::SIGTERM), "TERM");
        assert_eq!(signal_name(40), "40");
    }

    #[test]
    fn response_shapes() {
        assert_eq!(
            ok(json!({"mount_id": 7})),
            json!({"ok": true, "mount_id": 7})
        );
        assert_eq!(
            err(E_EXISTS, "x"),
            json!({"ok": false, "error": "E_EXISTS", "message": "x"})
        );
    }

    #[test]
    fn line_reader_enforces_limit_and_framing() {
        let mut c = Cursor::new(b"abc\ndef\n".to_vec());
        assert_eq!(read_line_limited(&mut c).unwrap().as_deref(), Some("abc"));
        assert_eq!(read_line_limited(&mut c).unwrap().as_deref(), Some("def"));
        assert_eq!(read_line_limited(&mut c).unwrap(), None);
        // exactly MAX_LINE bytes + newline is fine
        let mut ok_line = vec![b'a'; MAX_LINE];
        ok_line.push(b'\n');
        assert_eq!(
            read_line_limited(&mut Cursor::new(ok_line))
                .unwrap()
                .unwrap()
                .len(),
            MAX_LINE
        );
        // one byte more is not
        let mut long = vec![b'a'; MAX_LINE + 1];
        long.push(b'\n');
        assert!(read_line_limited(&mut Cursor::new(long)).is_err());
        // no newline, over the limit
        assert!(read_line_limited(&mut Cursor::new(vec![b'a'; MAX_LINE + 10])).is_err());
        assert!(read_line_limited(&mut Cursor::new(vec![0xff, b'\n'])).is_err());
    }

    #[test]
    fn responses_larger_than_a_request_are_accepted_by_the_client_reader() {
        // `inspect` replies (mountinfo + policy) exceed MAX_LINE.
        let mut big = vec![b'a'; MAX_LINE * 4];
        big.push(b'\n');
        assert!(read_line_limited(&mut Cursor::new(big.clone())).is_err());
        let got = read_line_max(&mut Cursor::new(big), MAX_RESPONSE_LINE)
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), MAX_LINE * 4);
    }

    struct Fake {
        allow: Mutex<bool>,
        seen: Mutex<Vec<String>>,
    }
    impl Handler for Fake {
        fn authorize(&self, _: &UnixStream) -> Result<(), String> {
            if *self.allow.lock().unwrap() {
                Ok(())
            } else {
                Err("denied".into())
            }
        }
        fn handle(&self, req: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
            self.seen.lock().unwrap().push(req.op_name().to_owned());
            match req {
                Request::List { .. } => ok(json!({"grants": []})),
                _ => err(E_INTERNAL, "unsupported in test"),
            }
        }
    }

    fn start(allow: bool) -> (tempfile::TempDir, std::path::PathBuf, Arc<Fake>) {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("c.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let h = Arc::new(Fake {
            allow: Mutex::new(allow),
            seen: Mutex::new(vec![]),
        });
        let hc: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hc));
        (d, sock, h)
    }

    #[test]
    fn server_roundtrip_and_ordering() {
        let (_d, sock, h) = start(true);
        let mut s = UnixStream::connect(&sock).unwrap();
        writeln!(s, r#"{{"op":"list"}}"#).unwrap();
        writeln!(s, r#"{{"op":"inspect"}}"#).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let a: Value = serde_json::from_str(&read_line_limited(&mut r).unwrap().unwrap()).unwrap();
        let b: Value = serde_json::from_str(&read_line_limited(&mut r).unwrap().unwrap()).unwrap();
        assert_eq!(a["ok"], true);
        assert_eq!(b["error"], E_INTERNAL);
        assert_eq!(*h.seen.lock().unwrap(), ["list", "inspect"]);
        // helper client
        assert_eq!(request(&sock, &json!({"op":"list"})).unwrap()["ok"], true);
    }

    #[test]
    fn unauthorized_peer_gets_nothing_and_is_never_dispatched() {
        let (_d, sock, h) = start(false);
        let mut s = UnixStream::connect(&sock).unwrap();
        let _ = writeln!(s, r#"{{"op":"list"}}"#);
        let mut r = BufReader::new(s);
        // Closed without a single response byte: clean EOF, or ECONNRESET
        // because the server closed with our request still unread.
        match read_line_limited(&mut r) {
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected a closed connection, got {other:?}"),
        }
        assert!(h.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn large_response_is_delivered_byte_for_byte_with_connection_accounting() {
        // Regression (0.4.0 L4): a response larger than one pipe buffer must
        // arrive intact while the connection accounting (connect/disconnect)
        // is active. The payload is ~256 KiB, far above the 64 KiB pipe
        // buffer, so a writer that stops early or a count that closes the
        // socket early shows up as truncation.
        use std::sync::atomic::{AtomicU64, Ordering as O};
        struct Counting {
            open: AtomicU64,
            payload: String,
        }
        impl Handler for Counting {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn connect(&self, _: ConnId) {
                self.open.fetch_add(1, O::SeqCst);
            }
            fn disconnect(&self, _: ConnId) {
                self.open.fetch_sub(1, O::SeqCst);
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                ok(json!({ "env": self.payload }))
            }
        }
        let payload = "PIP_CACHE_DIR=/run/hisn\n".repeat(10_000); // ~250 KiB
        let h = Arc::new(Counting {
            open: AtomicU64::new(0),
            payload: payload.clone(),
        });
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("big.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let hh: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hh));
        for _ in 0..3 {
            let got = request(&sock, &json!({"op":"list"})).unwrap();
            assert_eq!(
                got["env"].as_str().unwrap(),
                payload,
                "response truncated or altered"
            );
        }
        // Every serve_conn thread must have run its disconnect guard.
        let t0 = Instant::now();
        while h.open.load(O::SeqCst) != 0 && t0.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(h.open.load(O::SeqCst), 0, "connection count leaked");
    }

    #[test]
    fn a_bare_connect_is_not_a_client() {
        // Regression (0.4.0 L61): `hisn ls` probes liveness with a bare
        // connect-and-close; that must not count as a connected client (the
        // idle timer would never see zero clients while `ls` is polled), and
        // a real request still does.
        use std::sync::atomic::{AtomicU64, Ordering as O};
        #[derive(Default)]
        struct Counting {
            connects: AtomicU64,
            disconnects: AtomicU64,
        }
        impl Handler for Counting {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn connect(&self, _: ConnId) {
                self.connects.fetch_add(1, O::SeqCst);
            }
            fn disconnect(&self, _: ConnId) {
                self.disconnects.fetch_add(1, O::SeqCst);
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                ok(json!({}))
            }
        }
        let h = Arc::new(Counting::default());
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("probe.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let hh: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hh));
        for _ in 0..5 {
            drop(UnixStream::connect(&sock).unwrap());
        }
        request(
            &sock,
            &json!({"op":"signal","exec_id":"e-0","signal":"TERM"}),
        )
        .unwrap();
        let t0 = Instant::now();
        while h.disconnects.load(O::SeqCst) != 1 && t0.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(50));
        assert_eq!(h.connects.load(O::SeqCst), 1, "bare connects were counted");
        assert_eq!(h.disconnects.load(O::SeqCst), 1);
    }

    #[test]
    fn observer_queries_never_count_while_an_exec_connection_is_the_client() {
        // 0.4.1 R2, the scenario the L74/L61 suite observes: one exec-style
        // client holds a connection, then ten `ls --json`-style observer queries
        // each open and close a connection. Only the exec connection is a
        // client, so `clients` is 1 while it lives and 0 after it closes, and
        // the observers never register. The activity bump happens only for a
        // registered (counted) disconnect.
        use std::sync::Mutex;
        use std::sync::atomic::AtomicI64;
        use std::sync::atomic::{AtomicU64, Ordering as O};
        // Fake clock: the test owns time. Activity is the last counted
        // disconnect (or the start), as in production.
        const TIMEOUT: u64 = 30;
        const T_START: i64 = 1_000;
        #[derive(Default)]
        struct Observed {
            clients: Mutex<std::collections::BTreeSet<ConnId>>,
            activity_bumps: AtomicU64,
            last_activity: AtomicI64,
            fake_now: AtomicI64,
        }
        impl Handler for Observed {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn connect(&self, c: ConnId) {
                self.clients.lock().unwrap().insert(c);
            }
            fn disconnect(&self, c: ConnId) {
                // Mirrors Shared::disconnect_client: removal and the activity
                // bump happen under one lock, so no observer sees a removed
                // client with a stale timestamp. Bump only if registered.
                let mut clients = self.clients.lock().unwrap();
                if clients.remove(&c) {
                    self.activity_bumps.fetch_add(1, O::SeqCst);
                    let now = self.fake_now.load(O::SeqCst);
                    self.last_activity.fetch_max(now, O::SeqCst);
                }
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                ok(json!({}))
            }
        }
        let h = Arc::new(Observed::default());
        h.last_activity.store(T_START, O::SeqCst);
        h.fake_now.store(T_START + 5, O::SeqCst);
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("observers.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let hh: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hh));

        // The exec-style client: a mutation (a non-observer request) that stays
        // connected while the queries run.
        let mut exec = UnixStream::connect(&sock).unwrap();
        writeln!(exec, r#"{{"op":"signal","exec_id":"e-1","signal":"TERM"}}"#).unwrap();
        let mut exec_r = BufReader::new(exec.try_clone().unwrap());
        let _ = read_line_limited(&mut exec_r);
        let wait_for = |want: usize| {
            let t0 = Instant::now();
            while h.clients.lock().unwrap().len() != want && t0.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(5));
            }
        };
        wait_for(1);
        assert_eq!(
            h.clients.lock().unwrap().len(),
            1,
            "exec client not counted"
        );

        // Ten observer queries, each a fresh connection, each closed. Activity
        // must not move: capture it before, compare after.
        let activity_before = h.last_activity.load(O::SeqCst);
        for _ in 0..10 {
            request(&sock, &json!({"op":"sessioninfo"})).unwrap();
        }
        // Give the server threads time to run their disconnects.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            h.last_activity.load(O::SeqCst),
            activity_before,
            "observer queries moved last_activity"
        );
        // While the exec is connected the session is never idle, however long.
        h.fake_now.store(T_START + 10_000, O::SeqCst);
        assert!(
            !idle_due(
                !h.clients.lock().unwrap().is_empty(),
                false,
                h.last_activity.load(O::SeqCst),
                h.fake_now.load(O::SeqCst),
                TIMEOUT
            ),
            "idle fired while an exec client was connected"
        );
        assert_eq!(
            h.clients.lock().unwrap().len(),
            1,
            "an observer query was counted as a client"
        );
        assert_eq!(
            h.activity_bumps.load(O::SeqCst),
            0,
            "observer queries bumped activity"
        );

        // The exec ends: clients drops to 0, and that one counted disconnect
        // is the only activity bump.
        drop(exec_r);
        drop(exec);
        wait_for(0);
        assert_eq!(
            h.clients.lock().unwrap().len(),
            0,
            "client not removed on close"
        );
        assert_eq!(
            h.activity_bumps.load(O::SeqCst),
            1,
            "one counted disconnect, one bump"
        );
        // Idle counts from the exec's disconnect (the one counted activity),
        // not from the observer queries: not idle inside the window, idle once
        // the timeout has elapsed from that disconnect.
        let closed_at = h.last_activity.load(O::SeqCst);
        assert_eq!(
            closed_at,
            T_START + 10_000,
            "the exec disconnect is the last activity"
        );
        assert!(
            !idle_due(
                false,
                false,
                closed_at,
                closed_at + TIMEOUT as i64 - 1,
                TIMEOUT
            ),
            "idle fired inside the timeout window"
        );
        assert!(
            idle_due(
                false,
                false,
                closed_at,
                closed_at + TIMEOUT as i64 + 1,
                TIMEOUT
            ),
            "idle did not fire after the timeout with no clients"
        );
    }

    #[test]
    fn a_refused_or_observer_first_request_never_registers_until_admitted() {
        // The admission rule, at serve_conn: a connection registers on the first
        // ADMITTED request, exactly once. An observer first, then a mutation on
        // the same connection: one connect, one disconnect. A request the
        // handler refuses at admission never registers.
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering as O};
        #[derive(Default)]
        struct Gate {
            connects: AtomicU64,
            disconnects: AtomicU64,
            // Test knob: refuse every mutation at admission (a denied peer).
            deny_mutations: Mutex<bool>,
        }
        impl Handler for Gate {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn admit(&self, req: &Request, _: &UnixStream, _: ConnId) -> bool {
                !req.is_observer() && !*self.deny_mutations.lock().unwrap()
            }
            fn connect(&self, _: ConnId) {
                self.connects.fetch_add(1, O::SeqCst);
            }
            fn disconnect(&self, _: ConnId) {
                self.disconnects.fetch_add(1, O::SeqCst);
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                ok(json!({}))
            }
        }
        let h = Arc::new(Gate::default());
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("gate.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let hh: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hh));

        let settle = |n: u64| {
            let t0 = Instant::now();
            while h.disconnects.load(O::SeqCst) < n && t0.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(5));
            }
        };

        // Observer first, then a mutation, then another mutation: one connection.
        let mut s = UnixStream::connect(&sock).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        writeln!(s, r#"{{"op":"sessioninfo"}}"#).unwrap();
        let _ = read_line_limited(&mut r);
        assert_eq!(h.connects.load(O::SeqCst), 0, "observer registered");
        writeln!(s, r#"{{"op":"signal","exec_id":"e-1","signal":"TERM"}}"#).unwrap();
        let _ = read_line_limited(&mut r);
        writeln!(s, r#"{{"op":"signal","exec_id":"e-1","signal":"TERM"}}"#).unwrap();
        let _ = read_line_limited(&mut r);
        assert_eq!(
            h.connects.load(O::SeqCst),
            1,
            "admitted connection registered more than once"
        );
        drop(r);
        drop(s);
        settle(1);
        assert_eq!(
            h.disconnects.load(O::SeqCst),
            1,
            "one connect, one disconnect"
        );

        // A refused mutation never registers, and its disconnect is never sent.
        *h.deny_mutations.lock().unwrap() = true;
        let mut s = UnixStream::connect(&sock).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        writeln!(s, r#"{{"op":"signal","exec_id":"e-1","signal":"TERM"}}"#).unwrap();
        let _ = read_line_limited(&mut r);
        drop(r);
        drop(s);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            h.connects.load(O::SeqCst),
            1,
            "a refused request registered"
        );
        assert_eq!(
            h.disconnects.load(O::SeqCst),
            1,
            "a refused request was disconnected as a client"
        );
    }

    #[test]
    fn every_connect_has_exactly_one_disconnect_on_every_close_path() {
        // 0.4.1 R2: the client count must return to zero once connections are
        // gone, whatever the close path. Covers connect-then-close with and
        // without a request, a request followed by a clean close, and a
        // malformed line. Connection ids come from a counter, not the fd, so
        // rapid reuse of a closed descriptor number cannot mis-pair them.
        use std::collections::BTreeSet;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicI64, Ordering as O};
        #[derive(Default)]
        struct Tracking {
            live: Mutex<BTreeSet<ConnId>>,
            seen: Mutex<Vec<ConnId>>,
            violations: Mutex<Vec<String>>,
            net: AtomicI64,
            disconnects: AtomicUsize,
        }
        impl Handler for Tracking {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            // Record violations instead of panicking under the lock (a panic
            // here would poison the mutex and mask the real failure).
            fn connect(&self, c: ConnId) {
                if !self.live.lock().unwrap().insert(c) {
                    self.violations
                        .lock()
                        .unwrap()
                        .push(format!("connect twice for {c}"));
                }
                self.seen.lock().unwrap().push(c);
                self.net.fetch_add(1, O::SeqCst);
            }
            fn disconnect(&self, c: ConnId) {
                if !self.live.lock().unwrap().remove(&c) {
                    self.violations
                        .lock()
                        .unwrap()
                        .push(format!("disconnect for {c} without a matching connect"));
                }
                self.net.fetch_sub(1, O::SeqCst);
                self.disconnects.fetch_add(1, Ordering::SeqCst);
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                ok(json!({}))
            }
        }
        let h = Arc::new(Tracking::default());
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("close-paths.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let hh: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hh));

        const N: usize = 40;
        // (a) connect-then-close, no request: never a client.
        for _ in 0..N {
            drop(UnixStream::connect(&sock).unwrap());
        }
        // (b) request then close (the fd is reused by the next connect).
        for _ in 0..N {
            request(
                &sock,
                &json!({"op":"signal","exec_id":"e-0","signal":"TERM"}),
            )
            .unwrap();
        }
        // (c) a malformed first line: it does not parse, so it is never
        // admitted and never registers (no connect, no disconnect).
        for _ in 0..N {
            let mut s = UnixStream::connect(&sock).unwrap();
            let _ = writeln!(s, "not json");
            let mut r = BufReader::new(s);
            let _ = read_line_limited(&mut r);
        }
        // (d) request, then the client goes away. Read to EOF before dropping
        // so each server thread has finished this connection before the test
        // moves on: no case leaves work in flight when the state is checked.
        for _ in 0..N {
            let mut s = UnixStream::connect(&sock).unwrap();
            let _ = writeln!(s, r#"{{"op":"signal","exec_id":"e-0","signal":"TERM"}}"#);
            // Half-close: the server reads EOF after its one line and ends the
            // connection. Without this, read_to_end waits for a server that is
            // waiting for the next line.
            let _ = s.shutdown(std::net::Shutdown::Write);
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink);
        }

        // Settle, then take ONE snapshot of the authoritative set and assert
        // on that snapshot only. Re-reading the mutex inside an assertion
        // message can observe a later state than the one that was checked.
        // Every counted connection must finish (its disconnect must run) before
        // the state is read: wait for `connects == disconnects` with a bound, so
        // an in-flight server thread is waited for, not missed.
        let t0 = Instant::now();
        let (live_now, net_now) = loop {
            let live: Vec<ConnId> = h.live.lock().unwrap().iter().copied().collect();
            let net = h.net.load(O::SeqCst);
            let connects = h.seen.lock().unwrap().len();
            let disconnects = h.disconnects.load(O::SeqCst);
            let done = live.is_empty() && net == 0 && disconnects == connects;
            if done || t0.elapsed() > Duration::from_secs(5) {
                break (live, net);
            }
            thread::sleep(Duration::from_millis(5));
        };
        let violations = h.violations.lock().unwrap().clone();
        assert!(violations.is_empty(), "pairing violated: {violations:?}");
        assert!(
            live_now.is_empty(),
            "connections left registered: {live_now:?}"
        );
        assert_eq!(net_now, 0, "client count did not return to zero");
        // Exactly the admitted connections register: (b) and (d) each send an
        // admitted `signal`, so 2N; the bare connects (a) and the unparseable
        // lines (c) never register. (d) reads to EOF before it drops, so every
        // line was processed before the count is taken.
        let seen = h.seen.lock().unwrap().len();
        assert_eq!(seen, 2 * N, "admitted connections did not register exactly");
    }

    #[test]
    fn drain_waits_for_a_slow_response_to_be_written() {
        struct Slow;
        impl Handler for Slow {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn handle(&self, _: Request, _: Vec<OwnedFd>, _: &UnixStream, _: ConnId) -> Value {
                thread::sleep(Duration::from_millis(150));
                ok(json!({"late": true}))
            }
        }
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let h: Arc<dyn Handler> = Arc::new(Slow);
        thread::spawn(move || serve(l, h));
        let client = {
            let sock = sock.clone();
            thread::spawn(move || request(&sock, &json!({"op":"list"})).unwrap())
        };
        thread::sleep(Duration::from_millis(50)); // request is now in flight
        assert!(drain(Duration::from_secs(3)), "drained");
        assert_eq!(
            client.join().unwrap()["late"],
            true,
            "response delivered before drain returned"
        );
        assert!(
            drain(Duration::from_millis(10)),
            "idle server drains immediately"
        );
    }

    #[test]
    fn exec_requests_parse_with_defaults() {
        assert_eq!(
            parse_request(r#"{"op":"exec","argv":["sh","-c","true"]}"#).unwrap(),
            Request::Exec {
                argv: vec!["sh".into(), "-c".into(), "true".into()],
                cwd: None,
                env: BTreeMap::new(),
                tty: false,
                attach: false,
                client: None
            }
        );
        let r =
            parse_request(r#"{"op":"exec","argv":["x"],"cwd":"/w","env":{"K":"V"},"tty":true}"#)
                .unwrap();
        assert_eq!(
            r,
            Request::Exec {
                argv: vec!["x".into()],
                cwd: Some("/w".into()),
                env: BTreeMap::from([("K".into(), "V".into())]),
                tty: true,
                attach: false,
                client: None
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"exec","argv":["x"],"cwd":null}"#).unwrap(),
            Request::Exec {
                argv: vec!["x".into()],
                cwd: None,
                env: BTreeMap::new(),
                tty: false,
                attach: false,
                client: None
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"signal","pid":7}"#).unwrap(),
            Request::Signal {
                exec_id: None,
                pid: Some(7),
                signal: "TERM".into(),
                client: None
            }
        );
    }

    #[test]
    fn client_field_is_parsed() {
        let r = parse_request(
            r#"{"op":"exec","argv":["x"],"client":{"label":"wakil@rubin","label_source":"ssh"}}"#,
        )
        .unwrap();
        match r {
            Request::Exec {
                client: Some(c), ..
            } => {
                assert_eq!(c.label.as_deref(), Some("wakil@rubin"));
                assert_eq!(c.label_source.as_deref(), Some("ssh"));
            }
            _ => panic!("expected Exec with client"),
        }
    }

    #[test]
    fn client_field_with_uid_is_refused() {
        // `uid` is not a field of ClientField — deny_unknown_fields rejects it.
        let r = parse_request(r#"{"op":"exec","argv":["x"],"client":{"label":"x","uid":1000}}"#);
        assert!(r.is_err(), "uid in client object must be refused");
    }

    /// Handler that records what reached it and streams two lines for exec.
    struct Recorder {
        got: Mutex<Vec<(String, usize)>>,
    }
    impl Handler for Recorder {
        fn authorize(&self, _: &UnixStream) -> Result<(), String> {
            Ok(())
        }
        fn handle(&self, req: Request, fds: Vec<OwnedFd>, conn: &UnixStream, _: ConnId) -> Value {
            self.got
                .lock()
                .unwrap()
                .push((req.op_name().to_owned(), fds.len()));
            if matches!(req, Request::Exec { .. }) {
                let mut w = conn;
                writeln!(w, "{}", ok(json!({"pid": 5}))).unwrap();
                return json!({"exit": {"code": 0}});
            }
            ok(json!({}))
        }
    }

    fn start_recorder() -> (tempfile::TempDir, std::path::PathBuf, Arc<Recorder>) {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("r.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let h = Arc::new(Recorder {
            got: Mutex::new(vec![]),
        });
        let hc: Arc<dyn Handler> = h.clone();
        thread::spawn(move || serve(l, hc));
        (d, sock, h)
    }

    fn three_fds() -> Vec<std::fs::File> {
        (0..3).map(|_| tempfile::tempfile().unwrap()).collect()
    }

    fn read_resp(r: &mut BufReader<UnixStream>) -> Option<Value> {
        read_line_limited(r)
            .ok()
            .flatten()
            .map(|l| serde_json::from_str(&l).unwrap())
    }

    #[test]
    fn exec_with_descriptors_reaches_the_handler_and_streams_lines() {
        let (_d, sock, h) = start_recorder();
        let s = UnixStream::connect(&sock).unwrap();
        let files = three_fds();
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        crate::sys::send_with_fds(
            s.as_raw_fd(),
            b"{\"op\":\"exec\",\"argv\":[\"true\"]}\n",
            &raw,
        )
        .unwrap();
        let mut r = BufReader::new(s);
        assert_eq!(read_resp(&mut r).unwrap()["pid"], 5);
        assert_eq!(read_resp(&mut r).unwrap()["exit"]["code"], 0);
        assert_eq!(*h.got.lock().unwrap(), [("exec".to_owned(), 3)]);
    }

    #[test]
    fn descriptors_with_any_other_op_are_refused_and_closed() {
        let (_d, sock, h) = start_recorder();
        let s = UnixStream::connect(&sock).unwrap();
        let files = three_fds();
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        crate::sys::send_with_fds(s.as_raw_fd(), b"{\"op\":\"list\"}\n", &raw).unwrap();
        let mut r = BufReader::new(s);
        assert_eq!(read_resp(&mut r).unwrap()["error"], E_BAD_REQUEST);
        assert!(read_resp(&mut r).is_none(), "connection closed");
        assert!(h.got.lock().unwrap().is_empty(), "never dispatched");
    }

    #[test]
    fn exec_must_be_the_first_line_and_not_pipelined() {
        let (_d, sock, h) = start_recorder();
        // second line
        let s = UnixStream::connect(&sock).unwrap();
        let mut w = &s;
        writeln!(w, r#"{{"op":"list"}}"#).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        assert_eq!(read_resp(&mut r).unwrap()["ok"], true);
        let files = three_fds();
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        crate::sys::send_with_fds(
            s.as_raw_fd(),
            b"{\"op\":\"exec\",\"argv\":[\"true\"]}\n",
            &raw,
        )
        .unwrap();
        assert_eq!(read_resp(&mut r).unwrap()["error"], E_BAD_REQUEST);
        // pipelined: a further line in the same segment as the exec request
        let s = UnixStream::connect(&sock).unwrap();
        crate::sys::send_with_fds(
            s.as_raw_fd(),
            b"{\"op\":\"exec\",\"argv\":[\"true\"]}\n{\"op\":\"list\"}\n",
            &raw,
        )
        .unwrap();
        let mut r = BufReader::new(s);
        assert_eq!(read_resp(&mut r).unwrap()["error"], E_BAD_REQUEST);
        let seen = h.got.lock().unwrap().clone();
        assert_eq!(seen, [("list".to_owned(), 0)], "no exec was dispatched");
    }

    #[test]
    fn too_many_descriptors_are_rejected_not_truncated_into_a_valid_request() {
        let (_d, sock, h) = start_recorder();
        let s = UnixStream::connect(&sock).unwrap();
        let files: Vec<_> = (0..6).map(|_| tempfile::tempfile().unwrap()).collect();
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        crate::sys::send_with_fds(
            s.as_raw_fd(),
            b"{\"op\":\"exec\",\"argv\":[\"true\"]}\n",
            &raw,
        )
        .unwrap();
        let mut r = BufReader::new(s);
        assert!(
            read_resp(&mut r).is_none(),
            "connection closed, no response"
        );
        assert!(h.got.lock().unwrap().is_empty());
    }

    #[test]
    fn unknown_op_closes_the_connection() {
        let (_d, sock, h) = start(true);
        let mut s = UnixStream::connect(&sock).unwrap();
        writeln!(s, r#"{{"op":"detonate"}}"#).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let resp: Value =
            serde_json::from_str(&read_line_limited(&mut r).unwrap().unwrap()).unwrap();
        assert_eq!(resp["error"], E_BAD_REQUEST);
        assert_eq!(read_line_limited(&mut r).unwrap(), None);
        assert!(h.seen.lock().unwrap().is_empty());
    }
}

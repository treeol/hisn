//! Control socket protocol (POLICY-SPEC §7) and server loop.
//!
//! The wire format is newline-delimited JSON, one response line per request.
//! The server is transport only: authorisation of the peer (DESIGN §9 R5) and
//! the operations themselves are supplied through [`Handler`], which keeps
//! this module testable without namespaces.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    },
    Revoke {
        path: String,
        #[serde(default)]
        hard: bool,
        #[serde(default)]
        kill_holders: bool,
    },
    // Struct variants (not unit): serde ignores unknown fields on unit variants
    // of internally tagged enums, which would break "unknown keys are errors".
    List {},
    Inspect {},
    Kill {
        #[serde(default = "term")]
        signal: String,
    },
}

impl Request {
    pub fn op_name(&self) -> &'static str {
        match self {
            Request::Grant { .. } => "grant",
            Request::Revoke { .. } => "revoke",
            Request::List {} => "list",
            Request::Inspect {} => "inspect",
            Request::Kill { .. } => "kill",
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Request::Grant { path, .. } | Request::Revoke { path, .. } => Some(path),
            _ => None,
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

/// Signal name or number → signal number. `None` for unknown input.
pub fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return (1..=64).contains(&n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "TERM" => libc::SIGTERM,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "WINCH" => libc::SIGWINCH,
        _ => return None,
    })
}

/// Operations behind the socket. Implemented by the supervisor.
pub trait Handler: Send + Sync + 'static {
    /// Decide whether this peer may talk to the socket (R5). Called on accept
    /// and again before every request. `Err` closes the connection.
    fn authorize(&self, peer: &UnixStream) -> Result<(), String>;
    fn handle(&self, req: Request, peer: &UnixStream) -> Value;
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

fn serve_conn(h: &dyn Handler, stream: UnixStream) {
    if h.authorize(&stream).is_err() {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut out = &stream;
    loop {
        let line = match read_line_limited(&mut reader) {
            Ok(Some(l)) => l,
            _ => return, // EOF, oversized, or malformed framing: close
        };
        if h.authorize(&stream).is_err() {
            return;
        }
        let _inflight = Inflight::enter();
        let resp = match parse_request(&line) {
            Ok(req) => h.handle(req, &stream),
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
    use std::io::Cursor;
    use std::sync::Mutex;

    #[test]
    fn requests_parse_with_defaults() {
        assert_eq!(
            parse_request(r#"{"op":"grant","path":"/a"}"#).unwrap(),
            Request::Grant {
                path: "/a".into(),
                mode: Mode::Ro,
                recursive: false
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"grant","path":"/a","mode":"rw","recursive":true}"#).unwrap(),
            Request::Grant {
                path: "/a".into(),
                mode: Mode::Rw,
                recursive: true
            }
        );
        assert_eq!(
            parse_request(r#"{"op":"revoke","path":"/a"}"#).unwrap(),
            Request::Revoke {
                path: "/a".into(),
                hard: false,
                kill_holders: false
            }
        );
        assert_eq!(parse_request(r#"{"op":"list"}"#).unwrap(), Request::List {});
        assert_eq!(
            parse_request(r#"{"op":"inspect"}"#).unwrap(),
            Request::Inspect {}
        );
        assert_eq!(
            parse_request(r#"{"op":"kill"}"#).unwrap(),
            Request::Kill {
                signal: "TERM".into()
            }
        );
    }

    #[test]
    fn bad_requests_are_rejected() {
        for bad in [
            "",
            "not json",
            r#"{"op":"exec","cmd":"id"}"#,
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
        fn handle(&self, req: Request, _: &UnixStream) -> Value {
            self.seen.lock().unwrap().push(req.op_name().to_owned());
            match req {
                Request::List {} => ok(json!({"grants": []})),
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
    fn drain_waits_for_a_slow_response_to_be_written() {
        struct Slow;
        impl Handler for Slow {
            fn authorize(&self, _: &UnixStream) -> Result<(), String> {
                Ok(())
            }
            fn handle(&self, _: Request, _: &UnixStream) -> Value {
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
    fn unknown_op_closes_the_connection() {
        let (_d, sock, h) = start(true);
        let mut s = UnixStream::connect(&sock).unwrap();
        writeln!(s, r#"{{"op":"exec"}}"#).unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let resp: Value =
            serde_json::from_str(&read_line_limited(&mut r).unwrap().unwrap()).unwrap();
        assert_eq!(resp["error"], E_BAD_REQUEST);
        assert_eq!(read_line_limited(&mut r).unwrap(), None);
        assert!(h.seen.lock().unwrap().is_empty());
    }
}

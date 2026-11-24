//! Client side of `exec` (DESIGN §14): `hisn exec`.
//!
//! Sends the request with the caller's stdio descriptors (or the slave of a
//! *fresh* pty with `--tty`), relays the pty, forwards termination signals
//! through a second connection and turns the final `{"exit":…}` line into the
//! process exit status. Prints nothing of its own on stdout.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::cli::{ExecArgs, parse_env_spec};
use crate::exec::{Lines, read_some};
use crate::init::{EXIT_CANNOT_EXEC, EXIT_INTERNAL, EXIT_NOT_FOUND};
use crate::supervisor::{self, RawTerm, resize_to};
use crate::{control, sig, sys};

/// The seat credential for the control requests a command issues (0.5.1,
/// ADR 0021, decision H): from `HISN_SEAT_TOKEN` or a file, never from a
/// command-line argument, and never into a session's environment. An
/// unreadable file or both sources set at once is an error, never a silent
/// "credential absent".
pub fn seat_token(token_file: Option<&std::path::Path>) -> Result<Option<String>> {
    match (std::env::var("HISN_SEAT_TOKEN").ok(), token_file) {
        (Some(_), Some(_)) => {
            bail!("both HISN_SEAT_TOKEN and --seat-token-file are set; set only one")
        }
        (Some(t), None) => {
            let t = t.trim().to_owned();
            if t.is_empty() {
                bail!("HISN_SEAT_TOKEN is empty");
            }
            Ok(Some(t))
        }
        (None, Some(p)) if p == std::path::Path::new("-") => {
            // 0.6.3: the credential comes from stdin, one line. A terminal
            // is refused (the prompt would be invisible and echoed).
            if sys::isatty(0) {
                bail!("--seat-token-file - reads the credential from stdin, which is a terminal");
            }
            // Unbuffered on fd 0: std's `Stdin` reads a whole buffer ahead,
            // which would swallow what follows the credential line.
            // SAFETY: fd 0 is borrowed, never closed (`ManuallyDrop`).
            let mut fd0 = std::mem::ManuallyDrop::new(unsafe {
                <fs::File as std::os::fd::FromRawFd>::from_raw_fd(0)
            });
            let t = read_token_line(&mut *fd0, MAX_TOKEN_BYTES)
                .context("reading the seat credential from stdin")?;
            if t.is_empty() {
                bail!("the seat credential on stdin is empty");
            }
            Ok(Some(t))
        }
        (None, Some(p)) => {
            let body = fs::read_to_string(p)
                .with_context(|| format!("reading --seat-token-file {}", p.display()))?;
            let t = body.trim().to_owned();
            if t.is_empty() {
                bail!("--seat-token-file {} is empty", p.display());
            }
            Ok(Some(t))
        }
        (None, None) => Ok(None),
    }
}

/// `--seat-token-file -` on `exec` needs `--no-tty` (0.6.3): by default the
/// caller's own fds 0-2 are passed on, so the program would inherit whatever
/// follows the credential line; with `--no-tty` its stdin is `/dev/null`.
/// Checked before anything is read from stdin.
/// 0.6.5: the message names the opt-in: `--no-tty` alone keeps stdin at
/// /dev/null; `--stdin-limit N` passes the caller's stdin through a capped
/// relay (the credential line is read first, the cap counts the rest).
pub fn refuse_stdin_token_unless_no_tty(
    token_file: Option<&std::path::Path>,
    no_tty: bool,
) -> Result<()> {
    if token_file == Some(std::path::Path::new("-")) && !no_tty {
        bail!(
            "--seat-token-file - on exec requires --no-tty (without --stdin-limit the program's stdin is /dev/null, \
             so it cannot read what follows the credential; with --stdin-limit the rest is passed through)"
        );
    }
    Ok(())
}

/// The longest credential line read from stdin (a real one is ~50 bytes).
const MAX_TOKEN_BYTES: usize = 4096;

/// Read one line (up to `limit` bytes) from `r`, byte by byte, so nothing
/// after the newline is consumed: whatever follows stays on the stream for
/// the next reader. Returns the trimmed line; EOF ends the line.
fn read_token_line<R: std::io::Read>(r: &mut R, limit: usize) -> Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => {
                if line.len() >= limit {
                    bail!("the credential line is longer than {limit} bytes");
                }
                line.push(b[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(String::from_utf8(line)
        .context("the credential is not UTF-8")?
        .trim()
        .to_owned())
}

/// The `client` object for a request: the label when one was given, the
/// seat credential when one was configured (both when both are given — the
/// supervisor sets the journal seat from the credential, never from the
/// label), and the protocol revision when talking to a supervisor that
/// declares revision 3 or higher.
pub fn client_field(
    label: Option<&str>,
    token: Option<&str>,
    revision: Option<u32>,
) -> Option<Value> {
    if label.is_none() && token.is_none() && revision.is_none() {
        return None;
    }
    let mut c = serde_json::Map::new();
    if let Some(l) = label {
        c.insert("label".into(), json!(l));
        c.insert("label_source".into(), json!("flag"));
    }
    if let Some(v) = revision {
        c.insert("protocol_version".into(), json!(v));
    }
    if let Some(t) = token {
        c.insert("seat_token".into(), json!(t));
    }
    Some(Value::Object(c))
}

/// The protocol revision of a session (absent = revision 1, 0.4.3).
pub fn session_revision(session: &str) -> Option<u32> {
    let uid = rustix::process::getuid().as_raw();
    let roots =
        crate::session::runtime_roots(std::env::var("XDG_RUNTIME_DIR").ok().as_deref(), uid);
    let reg_root = crate::registry::registry_root(uid);
    let id = crate::session::resolve_session_arg(&roots, &reg_root, session).ok()?;
    let dir = crate::session::find_session(&roots, &id).ok()?;
    crate::sessionmeta::read(&dir).and_then(|m| m.protocol_revision)
}

/// The credential a command may send to `session`, and the revision it may
/// declare. A configured credential against a session below revision 3 is
/// refused here (exit 2, nothing sent) — dropping the token to preserve
/// compatibility would silently run a member/observer request as the
/// owner, which decision F forbids.
pub fn seat_material(
    session: &str,
    token_file: Option<&std::path::Path>,
) -> Result<(Option<String>, Option<u32>)> {
    let token = seat_token(token_file)?;
    let revision = session_revision(session);
    if token.is_some() && !revision.is_some_and(|r| r >= 3) {
        bail!("session {session} predates seat credentials (protocol revision < 3); not sent");
    }
    let declare = revision
        .filter(|r| *r >= 3)
        .map(|_| crate::sessionmeta::PROTOCOL_VERSION);
    Ok((token, declare))
}

/// How the program ended, from the client's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    Code(i32),
    Signal(i32),
    Lost,
}

/// Process exit status for a [`Finish`]: the code, `128+sig`, or `125` when the
/// status is unknown.
pub fn exit_code(f: &Finish) -> i32 {
    match f {
        Finish::Code(c) => (*c).clamp(0, 255),
        Finish::Signal(n) => 128 + n,
        Finish::Lost => EXIT_INTERNAL,
    }
}

/// Build the request line's JSON (pure; unit-tested).
pub fn build_request(args: &ExecArgs) -> Result<Value> {
    build_request_with(args, None, None)
}

/// As [`build_request`], with the seat credential and protocol revision a
/// revision-3 session may receive.
pub fn build_request_with(
    args: &ExecArgs,
    token: Option<&str>,
    revision: Option<u32>,
) -> Result<Value> {
    let mut env = BTreeMap::new();
    for spec in &args.env {
        let (k, v) = parse_env_spec(spec).map_err(|e| anyhow!(e))?;
        env.insert(k, v);
    }
    let mut req = json!({
        "op": "exec",
        "argv": args.command,
        "cwd": args.cwd,
        "env": env,
        "tty": args.tty,
        "client": client_field(args.client.as_deref(), token, revision),
    });
    // 0.6.4: the key exists only when asked for, so every request without
    // `--detach` is byte-identical to v0.6.3.
    if args.detach {
        req["detach"] = json!(true);
    }
    Ok(req)
}

/// The client's decision before it sends a revision-4 request (plan 2.6 and
/// section 7 B3): the session must record `protocol_revision >= min`.
/// `Err((code, message))` is printed as a `hisn-error/v1` object (exit 125)
/// and nothing is sent. `None` = the session could not be resolved, which is
/// reported separately from "too old".
pub fn require_revision(
    session: &str,
    found: Option<u32>,
    min: u32,
) -> Result<(), (&'static str, String)> {
    match found {
        None => Err((
            control::E_NOT_FOUND,
            format!("session {session} not found (or it records no protocol revision)"),
        )),
        Some(r) if r < min => Err((
            control::E_UNSUPPORTED,
            format!("requires protocol revision {min}, session has {r}"),
        )),
        Some(_) => Ok(()),
    }
}

/// The `hisn-error/v1` object printed on stderr by the revision-4 commands.
pub fn error_object(code: &str, message: &str) -> Value {
    json!({"schema": "hisn-error/v1", "code": code, "message": message})
}

/// Seat material for a revision-4 request: the credential, and the revision
/// it declares ([`crate::sessionmeta::DETACH_REVISION`]). The session must
/// already have passed [`require_revision`].
pub fn seat_material_v4(
    token_file: Option<&std::path::Path>,
) -> Result<(Option<String>, Option<u32>)> {
    let token = seat_token(token_file)?;
    Ok((token, Some(crate::sessionmeta::DETACH_REVISION)))
}

/// `hisn exec --detach`: send one request with no descriptors, print the
/// reply's identity as a JSON object, exit. The connection is then closed;
/// the exec runs on. Never relays anything.
fn run_detached(args: ExecArgs) -> Result<i32> {
    let found = session_revision(&args.session);
    if let Err((code, msg)) =
        require_revision(&args.session, found, crate::sessionmeta::DETACH_REVISION)
    {
        eprintln!("{}", error_object(code, &msg));
        return Ok(EXIT_INTERNAL);
    }
    let (token, revision) = seat_material_v4(args.seat_token_file.as_deref())?;
    let req = build_request_with(&args, token.as_deref(), revision)?;
    if refuse_oversized_request(&req) {
        return Ok(EXIT_INTERNAL);
    }
    let sock = supervisor::socket_for(&args.session)?;
    let reply = control::request(&sock, &req)
        .with_context(|| format!("talking to session {}", args.session))?;
    if reply["ok"] != true {
        let code = reply["error"].as_str().unwrap_or(control::E_INTERNAL);
        let msg = reply["message"].as_str().unwrap_or("");
        eprintln!("{}", error_object(code, msg));
        return Ok(EXIT_INTERNAL);
    }
    println!(
        "{}",
        json!({
            "schema": "hisn-exec-start/v1",
            "exec_id": reply["exec_id"],
            "incarnation": reply["incarnation"],
            "pid": reply["pid"],
        })
    );
    Ok(0)
}

// ------------------------------------------------- exec-status/output/signal

/// The request line of one of the three revision-4 operations (pure;
/// unit-tested). Optional keys are present only when given, so a request
/// without `--incarnation` names the live one.
pub fn exec_query_request(
    op: &str,
    exec: &str,
    incarnation: Option<&str>,
    extra: Value,
    client: Option<Value>,
) -> Value {
    let mut req = json!({ "op": op, "exec_id": exec });
    if let Some(i) = incarnation {
        req["incarnation"] = json!(i);
    }
    if let (Some(o), Some(e)) = (req.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    if let Some(c) = client {
        req["client"] = c;
    }
    req
}

/// Send one revision-4 query and return the supervisor's `ok` reply. Every
/// failure (old session, refusal, error reply) prints a `hisn-error/v1`
/// object on stderr and is returned as `Err(exit code)` (125).
fn exec_query(
    session: &str,
    token_file: Option<&std::path::Path>,
    label: Option<&str>,
    build: impl FnOnce(Option<Value>) -> Value,
) -> Result<std::result::Result<Value, i32>> {
    let found = session_revision(session);
    if let Err((code, msg)) = require_revision(session, found, crate::sessionmeta::DETACH_REVISION)
    {
        eprintln!("{}", error_object(code, &msg));
        return Ok(Err(EXIT_INTERNAL));
    }
    let (token, revision) = seat_material_v4(token_file)?;
    let req = build(client_field(label, token.as_deref(), revision));
    let sock = supervisor::socket_for(session)?;
    let reply =
        control::request(&sock, &req).with_context(|| format!("talking to session {session}"))?;
    if reply["ok"] != true {
        let code = reply["error"].as_str().unwrap_or(control::E_INTERNAL);
        let msg = reply["message"].as_str().unwrap_or("");
        eprintln!("{}", error_object(code, msg));
        return Ok(Err(EXIT_INTERNAL));
    }
    Ok(Ok(reply))
}

/// A reply without its `ok` key.
fn without_ok(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("ok");
    }
    v
}

/// `hisn exec-status`.
pub fn run_exec_status(a: crate::cli::ExecStatusArgs) -> Result<i32> {
    let reply = match exec_query(
        &a.session,
        a.seat_token_file.as_deref(),
        a.client.as_deref(),
        |c| {
            exec_query_request(
                "execstatus",
                &a.exec,
                a.incarnation.as_deref(),
                json!({}),
                c,
            )
        },
    )? {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    let st = without_ok(reply);
    if a.json {
        println!("{st}");
    } else {
        print!("{}", status_text(&st));
    }
    Ok(0)
}

/// The plain-text `exec-status` rendering (pure).
pub fn status_text(st: &Value) -> String {
    let mut out = String::new();
    let s = |k: &str| st[k].as_str().unwrap_or("-").to_owned();
    out.push_str(&format!(
        "{} (incarnation {}) {}\n",
        s("exec_id"),
        s("incarnation"),
        s("state")
    ));
    out.push_str(&format!("  command  {}\n", s("argv0")));
    out.push_str(&format!(
        "  seat     {}\n",
        st["seat"].as_str().unwrap_or("-")
    ));
    out.push_str(&format!("  started  {}\n", s("started")));
    if let Some(e) = st["ended"].as_str() {
        out.push_str(&format!("  ended    {e}\n"));
    }
    if let Some(c) = st["exit_code"].as_i64() {
        out.push_str(&format!("  exit     {c}\n"));
    }
    if let Some(n) = st["signal_name"].as_str() {
        out.push_str(&format!("  signal   {n}\n"));
    }
    if let Some(c) = st["cause"].as_str() {
        out.push_str(&format!("  cause    {c}\n"));
    }
    for k in ["stdout", "stderr"] {
        out.push_str(&format!(
            "  {k:<8} total {} oldest {}\n",
            st[k]["total"], st[k]["base"]
        ));
    }
    if st["output_open"] == true {
        out.push_str("  output   still open\n");
    }
    out
}

/// `hisn exec-output`: raw bytes on stdout and `next=<n>` on stderr, or the
/// reply object with `--json`.
pub fn run_exec_output(a: crate::cli::ExecOutputArgs) -> Result<i32> {
    let reply = match exec_query(
        &a.session,
        a.seat_token_file.as_deref(),
        a.client.as_deref(),
        |c| {
            exec_query_request(
                "execoutput",
                &a.exec,
                a.incarnation.as_deref(),
                json!({ "stream": a.stream.as_str(), "offset": a.offset }),
                c,
            )
        },
    )? {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    let r = without_ok(reply);
    if a.json {
        println!("{r}");
        return Ok(0);
    }
    let Some(data) = r["data_b64"].as_str().and_then(crate::execlog::b64_decode) else {
        eprintln!(
            "{}",
            error_object(control::E_INTERNAL, "reply carries no readable data_b64")
        );
        return Ok(EXIT_INTERNAL);
    };
    let mut out = io::stdout().lock();
    out.write_all(&data)?;
    out.flush()?;
    let mut note = format!("next={}", r["next"]);
    if r["rotated_away"] == true {
        note.push_str(&format!(" rotated_away oldest={}", r["oldest"]));
    }
    if r["eof"] == true {
        note.push_str(" eof");
    }
    eprintln!("{note}");
    Ok(0)
}

/// `hisn exec-signal`.
pub fn run_exec_signal(a: crate::cli::ExecSignalArgs) -> Result<i32> {
    match exec_query(
        &a.session,
        a.seat_token_file.as_deref(),
        a.client.as_deref(),
        |c| {
            exec_query_request(
                "execsignal",
                &a.exec,
                a.incarnation.as_deref(),
                json!({ "signal": a.signal.as_str() }),
                c,
            )
        },
    )? {
        Ok(_) => Ok(0),
        Err(code) => Ok(code),
    }
}

/// One parsed response line from the supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Started(i32, Option<String>),
    Exit(Finish),
    Error { code: String, message: String },
}

pub fn parse_reply(line: &str) -> Option<Reply> {
    let v: Value = serde_json::from_str(line).ok()?;
    if let Some(x) = v.get("exit") {
        if x["lost"] == true {
            return Some(Reply::Exit(Finish::Lost));
        }
        if let Some(c) = x["code"].as_i64() {
            return Some(Reply::Exit(Finish::Code(c as i32)));
        }
        let n = control::parse_signal(x["signal"].as_str()?)?;
        return Some(Reply::Exit(Finish::Signal(n)));
    }
    if v["ok"] == true {
        let pid = v["pid"].as_i64()? as i32;
        let exec_id = v["exec_id"].as_str().map(|s| s.to_owned());
        return Some(Reply::Started(pid, exec_id));
    }
    Some(Reply::Error {
        code: v["error"].as_str().unwrap_or("E_INTERNAL").to_owned(),
        message: v["message"].as_str().unwrap_or("").to_owned(),
    })
}

/// Parse an `exit` line (the `{"exit":…}` shape) shared by the exec and
/// attach clients: returns the [`Finish`] if `line` is an exit line, else
/// `None`. A line carrying an `error` counts as lost (the attach client
/// treats a refused attach as a lost session; the exec client parses
/// errors separately via [`parse_reply`]).
pub fn parse_exit(line: &str) -> Option<Finish> {
    let v: Value = serde_json::from_str(line).ok()?;
    if let Some(x) = v.get("exit") {
        if x["lost"] == true {
            return Some(Finish::Lost);
        }
        if let Some(c) = x["code"].as_i64() {
            return Some(Finish::Code(c as i32));
        }
        if let Some(s) = x["signal"].as_str()
            && let Some(n) = control::parse_signal(s)
        {
            return Some(Finish::Signal(n));
        }
    }
    if v.get("error").is_some() {
        return Some(Finish::Lost);
    }
    None
}

/// Allocate a fresh pty on the *host*. Returns `(master, slave)`.
///
/// The one shared implementation (0.4.3): `attach` previously used
/// `openpty`, `exec` used `posix_openpt`/`grantpt`/`unlockpt`/`ptsname_r`
/// by hand. `openpty` is the same glibc call sequence internally, so the
/// behaviour is identical; on musl both go through the same functions.
pub fn open_host_pty() -> io::Result<(OwnedFd, OwnedFd)> {
    // SAFETY: standard pty allocation with checked return values; every
    // descriptor is wrapped immediately.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(io::Error::last_os_error());
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(m, name.as_mut_ptr(), name.len()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let s = libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if s < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((master, OwnedFd::from_raw_fd(s)))
    }
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        // SAFETY: valid buffer slice.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    let mut p = [libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    }];
                    let _ = sys::poll(&mut p, 1000);
                    continue;
                }
                _ => return,
            }
        }
        data = &data[n as usize..];
    }
}

/// Refuse to hand the caller's own terminal to the sandbox (DESIGN §14.8).
/// `--tty` allocates its own pty and `--no-tty` passes pipes/`/dev/null`
/// instead, so neither hands over the caller's terminal.
pub fn refuse_real_terminal(
    tty_flag: bool,
    no_tty_flag: bool,
    is_tty: impl Fn(RawFd) -> bool,
) -> Result<()> {
    if tty_flag || no_tty_flag {
        return Ok(());
    }
    let names = ["stdin", "stdout", "stderr"];
    let ttys: Vec<&str> = (0..3)
        .filter(|fd| is_tty(*fd))
        .map(|fd| names[fd as usize])
        .collect();
    if ttys.is_empty() {
        return Ok(());
    }
    bail!(
        "{} is a terminal; hisn never hands your terminal to the sandbox. \
         Use --tty to run on a pty, or --no-tty to run without one (stdin from /dev/null, \
         stdout/stderr as pipes), or redirect it",
        ttys.join(" and ")
    )
}

/// 0.6.5: refuse a request whose line would exceed the supervisor's
/// [`control::MAX_LINE`] (bytes, excluding the newline), before anything is
/// sent. Prints the `hisn-error/v1` object on stderr and returns `true` when
/// the request must not be sent (caller exits 125). The newline formatted
/// into `line` is not counted: `MAX_LINE` excludes it.
pub(crate) fn refuse_oversized_request(req: &Value) -> bool {
    let line_len = req.to_string().len();
    if line_len > control::MAX_LINE {
        let msg = format!(
            "request is {line_len} bytes, over the {} byte limit",
            control::MAX_LINE
        );
        eprintln!("{}", error_object(control::E_TOO_LARGE, &msg));
        return true;
    }
    false
}

/// Run `hisn exec`; returns the process exit code.
pub fn run(args: ExecArgs) -> Result<i32> {
    if args.detach {
        // No stdio is passed on, so a credential read from stdin cannot leak
        // into the program: `--seat-token-file -` is fine here.
        return run_detached(args);
    }
    refuse_stdin_token_unless_no_tty(args.seat_token_file.as_deref(), args.no_tty)?;
    let (token, revision) = seat_material(&args.session, args.seat_token_file.as_deref())?;
    let req = build_request_with(&args, token.as_deref(), revision)?;
    if refuse_oversized_request(&req) {
        return Ok(EXIT_INTERNAL);
    }
    refuse_real_terminal(args.tty, args.no_tty, sys::isatty)?;
    let sock = supervisor::socket_for(&args.session)?;
    let conn = UnixStream::connect(&sock)
        .with_context(|| format!("connecting to session {}", args.session))?;

    let (master, slave) = if args.tty {
        let (m, s) = open_host_pty().context("allocating a pty")?;
        (Some(m), Some(s))
    } else {
        (None, None)
    };
    if let Some(m) = &master {
        // Start with the caller's size (or a sane default when stdin is not a tty).
        // SAFETY: winsize ioctl on fds we own, zeroed storage.
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) != 0 || ws.ws_col == 0 {
                ws.ws_row = 24;
                ws.ws_col = 80;
            }
            libc::ioctl(m.as_raw_fd(), libc::TIOCSWINSZ, &ws);
        }
    }

    // The request line and its descriptors travel in one sendmsg. The sandbox
    // never receives a descriptor that refers to the caller's terminal:
    // - default (no pty flag): fds 0-2 are the caller's, as before (a terminal
    //   on any of them was already refused above);
    // - --no-tty: stdin is /dev/null, or — with --stdin-limit — the read end
    //   of a client-owned pipe whose write end a relay thread feeds from the
    //   caller's stdin (0.6.5 opt-in); stdout and stderr are client-owned
    //   pipes whose read ends the client copies to its own fd 1 and 2.
    let line = format!("{req}\n");
    let stdin_cap = effective_stdin_limit(args.stdin_limit)?;
    // tty on fd 0: never read from the caller's terminal (0.6.3 property).
    let stdin_tty = !args.tty && stdin_cap.is_some() && sys::isatty(0);
    let use_stdin_relay = stdin_cap.is_some() && !stdin_tty;
    // (relay pipe write end, cap, wakeup read end) for the relay thread.
    let mut stdin_relay: Option<(OwnedFd, u64, OwnedFd)> = None;
    let mut stdin_wakeup_w: Option<OwnedFd> = None;
    let mut relay_pipes: Option<[(OwnedFd, RawFd); 2]> = None;
    if let Some(s) = &slave {
        sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), &[s.as_raw_fd()])
            .context("sending request")?;
    } else if args.no_tty {
        // The sandbox's stdin fd for this call (one of ours):
        // - no --stdin-limit (or fd 0 is a tty): /dev/null, as in 0.6.4;
        // - --stdin-limit with a non-tty fd 0: the read end of a pipe the
        //   relay thread below feeds from fd 0.
        let (stdin_fd, relay_pair) = if use_stdin_relay {
            let (r, w) = open_pipe().context("creating stdin pipe")?;
            (r, Some(w))
        } else {
            if stdin_tty {
                eprintln!("hisn: stdin was not passed: fd 0 is a terminal (use a pipe or file)");
            }
            let null =
                fs::File::open("/dev/null").context("opening /dev/null for --no-tty stdin")?;
            // SAFETY: `null` is a file we opened and own.
            (unsafe { OwnedFd::from_raw_fd(null.into_raw_fd()) }, None)
        };
        let (out_r, out_w) = open_pipe().context("creating stdout pipe")?;
        let (err_r, err_w) = open_pipe().context("creating stderr pipe")?;
        let fds = [stdin_fd.as_raw_fd(), out_w.as_raw_fd(), err_w.as_raw_fd()];
        sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), &fds).context("sending request")?;
        // The client's write ends close now: the read ends see EOF exactly
        // when the sandbox's side has closed. The sandbox holds its own copy
        // of stdin_fd (SCM_RIGHTS); ours is dropped.
        drop((out_w, err_w, stdin_fd));
        relay_pipes = Some([(out_r, 1), (err_r, 2)]);
        if let Some(w) = relay_pair {
            let (wake_r, wake_w) = open_pipe().context("creating wakeup pipe")?;
            stdin_relay = Some((w, stdin_cap.unwrap(), wake_r));
            stdin_wakeup_w = Some(wake_w);
        }
    } else {
        sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), &[0, 1, 2])
            .context("sending request")?;
    }
    drop(slave); // the master sees EOF/EIO once the program's side closes

    // The stdin relay thread (opt-in): copies fd 0 to the sandbox pipe until
    // EOF, the cap, or `stop`. The wakeup pipe ends its poll when `stop` is
    // set, so it is always joinable.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdin_thread = stdin_relay.map(|(w, cap, wake_r)| {
        let stop = stop.clone();
        std::thread::spawn(move || relay_stdin(0, w, cap, &stop, &wake_r))
    });
    let pump = relay_pipes.map(|p| {
        let stop = stop.clone();
        std::thread::spawn(move || pump_pipes(p, &stop))
    });
    let finish = relay(&conn, &args.session, master);
    // The exit line is in (or the relay failed). The pumps drain what is
    // already buffered, then stop at EOF or after their grace period. The
    // stdin relay stops via the wakeup pipe.
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(w) = &stdin_wakeup_w {
        let byte = [0u8; 1];
        // SAFETY: one byte into our own wakeup pipe.
        let _ = unsafe { libc::write(w.as_raw_fd(), byte.as_ptr() as *const _, 1) };
    }
    if let Some(h) = pump {
        let _ = h.join();
    }
    let stdin_outcome = stdin_thread.map(|h| {
        h.join().unwrap_or(StdinRelayOutcome {
            exceeded: false,
            bytes: 0,
        })
    });
    if let Some(out) = &stdin_outcome
        && out.exceeded
    {
        let cap = stdin_cap.unwrap();
        let msg = format!(
            "the command's stdin exceeded the {cap} byte limit (read {} bytes)",
            out.bytes
        );
        eprintln!("{}", error_object(control::E_TOO_LARGE, &msg));
        return Ok(EXIT_INTERNAL);
    }
    Ok(exit_code(&finish?))
}

/// 0.6.5 opt-in stdin relay for `exec --no-tty --stdin-limit`.
pub(crate) const MAX_STDIN_LIMIT: u64 = 1024 * 1024 * 1024;

/// Resolve the effective stdin cap for `exec`. `None` = no passthrough
/// (--no-tty without --stdin-limit keeps /dev/null, byte-identical to 0.6.4).
/// A value outside 1..=MAX_STDIN_LIMIT is a usage error (bail).
pub(crate) fn effective_stdin_limit(requested: Option<u64>) -> Result<Option<u64>> {
    match requested {
        None => Ok(None),
        Some(n) if (1..=MAX_STDIN_LIMIT).contains(&n) => Ok(Some(n)),
        Some(n) => bail!("--stdin-limit must be between 1 and {MAX_STDIN_LIMIT} bytes, got {n}"),
    }
}

/// The result of one stdin relay: whether the cap was exceeded.
pub(crate) struct StdinRelayOutcome {
    pub exceeded: bool,
    /// Total bytes read from the source.
    pub bytes: u64,
}

/// Copy the caller's stdin (`src_fd`, normally fd 0, blocking — never
/// O_NONBLOCK on a shared description) to `dst` (a pipe write end we own, set
/// non-blocking) until EOF, until the cap is exceeded (then stop after cap+1
/// bytes have been seen, so exactly-at-cap ends cleanly), or until `stop` is
/// set. `wakeup` is the read end of a pipe the main thread writes to when
/// `stop` is set, so the poll always ends. EPIPE (the program closed stdin
/// early) is a normal end.
fn relay_stdin(
    src_fd: RawFd,
    dst: OwnedFd,
    cap: u64,
    stop: &std::sync::atomic::AtomicBool,
    wakeup: &OwnedFd,
) -> StdinRelayOutcome {
    use std::sync::atomic::Ordering;
    // O_NONBLOCK on our own pipe end (never on fd 0).
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(dst.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(dst.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let mut buf = vec![0u8; 16384];
    let dst_fd = dst.as_raw_fd();
    let wake_fd = wakeup.as_raw_fd();
    let mut read_total: u64 = 0;
    let mut exceeded = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut pfds = [
            libc::pollfd {
                fd: src_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        match sys::poll(&mut pfds, 200) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(_) => break,
        }
        if pfds[1].revents & libc::POLLIN != 0 {
            break; // stop requested via wakeup pipe
        }
        if pfds[0].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            continue;
        }
        // Read at most cap+1-sent bytes: one byte past the cap decides.
        let sent = read_total.min(cap);
        let want = ((cap + 1).saturating_sub(sent)).min(buf.len() as u64) as usize;
        if want == 0 {
            exceeded = true;
            break;
        }
        // SAFETY: read into a buffer we own; `src_fd` is borrowed, never closed.
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut _, want) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if n == 0 {
            break; // EOF: normal end
        }
        let n = n as usize;
        read_total += n as u64;
        if read_total > cap {
            // One byte over the cap: deliver up to the cap, then stop.
            let deliver = (cap - (read_total - n as u64)) as usize;
            if deliver > 0 {
                drain_write(dst_fd, &buf[..deliver]);
            }
            exceeded = true;
            break;
        }
        drain_write(dst_fd, &buf[..n]);
    }
    StdinRelayOutcome {
        exceeded,
        bytes: read_total,
    }
}

/// Write all of `data` to a non-blocking pipe end; stop on EPIPE (the reader
/// closed) or when the pipe is full (the program is not reading — the exit
/// path ends the relay via `stop`, so this never blocks).
fn drain_write(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        // SAFETY: write into a buffer we own.
        let n = unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return, // pipe full: stop writing (normal)
                Some(libc::EPIPE) => return,  // reader closed: normal end
                _ => return,
            }
        }
        data = &data[n as usize..];
    }
}

/// A fresh anonymous pipe as `(read, write)`, both close-on-exec.
fn open_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors into the array we own.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both are fresh descriptors owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Idle window for the pump after the exit line has been seen: it stops once
/// the pipes have been silent for this long. Data arriving resets the window,
/// so output that is still flowing (or still pending in the pipe) is never
/// cut off by a wall-clock deadline. Bounds a background grandchild that holds
/// a pipe open: it cannot keep the client alive by writing nothing.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Copy the `--no-tty` pipes to the destination descriptors until both reach
/// EOF, or until they have been idle for `STOP_GRACE` after `stop` was set.
/// `dests` are `(read end, write fd)` pairs; the write fds are not closed.
fn pump_pipes(pipes: [(OwnedFd, RawFd); 2], stop: &std::sync::atomic::AtomicBool) {
    let mut open: Vec<(OwnedFd, RawFd)> = pipes.into_iter().collect();
    let mut buf = vec![0u8; 16384];
    // Idle clock: starts once `stop` is seen; reset on every read that returns
    // data. A single empty poll is not enough to stop (0.4.0 L4 regression:
    // one 16 KiB pass dropped the rest of a large `env` listing).
    let mut idle_since: Option<std::time::Instant> = None;
    while !open.is_empty() {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            let since = *idle_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() > STOP_GRACE {
                break;
            }
        }
        let mut pfds: Vec<libc::pollfd> = open
            .iter()
            .map(|(f, _)| libc::pollfd {
                fd: f.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: a valid pollfd array of the length passed.
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 200) };
        if r < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let mut i = 0;
        while i < open.len() {
            let ready = pfds[i].revents != 0;
            let mut closed = false;
            if ready {
                let fd = open[i].0.as_raw_fd();
                // SAFETY: reading into our buffer from a pipe we own.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    write_all_fd(open[i].1, &buf[..n as usize]);
                    // Data arrived: the pipe is not idle, restart the window.
                    if idle_since.is_some() {
                        idle_since = Some(std::time::Instant::now());
                    }
                } else if n == 0 {
                    closed = true; // EOF
                } else {
                    // A transient error (EINTR, EAGAIN) keeps the pipe; only
                    // a terminal error closes it.
                    let e = io::Error::last_os_error().raw_os_error();
                    if e != Some(libc::EINTR) && e != Some(libc::EAGAIN) {
                        closed = true;
                    }
                }
            }
            if closed {
                open.remove(i);
                pfds.remove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// Everything after the request is sent: responses, pty relay, signals.
fn relay(conn: &UnixStream, session: &str, master: Option<OwnedFd>) -> Result<Finish> {
    let handled = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGWINCH];
    sig::install(&handled)?;
    let old = sig::block(&handled)?;
    let _raw = master.as_ref().and_then(|_| RawTerm::enter(0));
    let mut stdin_open = master.is_some();
    let mut lines = Lines::default();
    let mut buf = vec![0u8; 16384];
    let mut pid: Option<i32> = None;
    let mut exec_id: Option<String> = None;
    let mut queued: Vec<i32> = Vec::new();
    let mut finish: Option<Finish> = None;
    let mut master_open = master.is_some();

    while finish.is_none() {
        for s in sig::take_pending() {
            match s {
                libc::SIGWINCH => {
                    if let Some(m) = &master {
                        resize_to(0, m.as_raw_fd());
                    }
                }
                libc::SIGTERM | libc::SIGINT | libc::SIGHUP => queued.push(s),
                _ => {}
            }
        }
        if let Some(eid) = &exec_id {
            for s in queued.drain(..) {
                // A second connection: this one is busy delivering the exit line.
                let _ = control::request(
                    &supervisor::socket_for(session)?,
                    &json!({"op":"signal","exec_id":eid,"signal":control::signal_name(s)}),
                );
            }
        } else if let Some(p) = pid {
            for s in queued.drain(..) {
                // Deprecated 0.2 path: signal by pid.
                let _ = control::request(
                    &supervisor::socket_for(session)?,
                    &json!({"op":"signal","pid":p,"signal":control::signal_name(s)}),
                );
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: conn.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: match (&master, master_open) {
                    (Some(m), true) => m.as_raw_fd(),
                    _ => -1,
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stdin_open { 0 } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        match sys::ppoll(&mut fds, &old) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => bail!("poll: {e}"),
        }
        if fds[0].revents != 0 {
            let n = read_some(conn.as_raw_fd(), &mut buf).unwrap_or(0);
            if n == 0 {
                finish = Some(Finish::Lost);
            } else {
                lines.push(&buf[..n]);
                while let Some(l) = lines.pop_line() {
                    match parse_reply(&l) {
                        Some(Reply::Started(p, eid)) => {
                            pid = Some(p);
                            exec_id = eid;
                        }
                        Some(Reply::Exit(f)) => finish = Some(f),
                        Some(Reply::Error { code, message }) => {
                            eprintln!("hisn: exec: {code}: {message}");
                            return Ok(match code.as_str() {
                                control::E_EXEC if message.contains("No such file") => {
                                    Finish::Code(EXIT_NOT_FOUND)
                                }
                                control::E_EXEC => Finish::Code(EXIT_CANNOT_EXEC),
                                _ => Finish::Code(EXIT_INTERNAL),
                            });
                        }
                        None => bail!("unparsable response {l:?}"),
                    }
                }
            }
        }
        if let Some(m) = &master {
            if master_open && fds[1].revents != 0 {
                // SAFETY: reading into our buffer from an fd we own.
                let n = unsafe { libc::read(m.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    write_all_fd(1, &buf[..n as usize]);
                } else {
                    master_open = false; // EIO/EOF: the program's side is closed
                }
            }
            if stdin_open && fds[2].revents != 0 {
                // SAFETY: reading stdin into our buffer.
                let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    write_all_fd(m.as_raw_fd(), &buf[..n as usize]);
                } else {
                    stdin_open = false;
                }
            }
        }
    }
    // Output the program wrote just before exiting may still sit in the pty.
    if let Some(m) = &master {
        set_nonblocking(m.as_raw_fd());
        loop {
            // SAFETY: reading into our buffer from an fd we own.
            let n = unsafe { libc::read(m.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            write_all_fd(1, &buf[..n as usize]);
        }
    }
    let _ = io::stdout().flush();
    Ok(finish.expect("loop ends with a result"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn exec_args(argv: &[&str]) -> ExecArgs {
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Exec(e) => e,
            _ => panic!("not exec"),
        }
    }

    #[test]
    fn exec_request_omits_detach_when_false() {
        let a = exec_args(&["hisn", "exec", "--session", "s", "--", "ls"]);
        let req = build_request(&a).unwrap();
        assert!(req.get("detach").is_none(), "{req}");
        assert_eq!(
            req.to_string(),
            r#"{"argv":["ls"],"client":null,"cwd":null,"env":{},"op":"exec","tty":false}"#
        );
    }

    #[test]
    fn oversized_request_is_refused_before_sending() {
        // 0.6.5: the client refuses a request line over MAX_LINE (excluding
        // the newline) without sending; exactly at the limit passes.
        let a = exec_args(&["hisn", "exec", "--session", "s", "--", "ls"]);
        let small = build_request(&a).unwrap();
        assert!(!refuse_oversized_request(&small));
        // pad the serialized request to exactly MAX_LINE: add a long argv
        // element. The base request for ["ls"] is short; grow argv[0].
        let mut req = small.clone();
        let base_len = req.to_string().len();
        let need = control::MAX_LINE - base_len;
        // base_len includes "ls" (2 chars); replace argv with one long string
        req["argv"] = json!(["x".repeat(need)]);
        // len now = base_len - 2 + need + quotes adjust: compute directly
        let len = req.to_string().len();
        assert!(len <= control::MAX_LINE, "len {len}");
        // adjust to exactly the limit by trimming/padding one char at a time
        while req.to_string().len() < control::MAX_LINE {
            let cur = req["argv"][0].as_str().unwrap().to_owned();
            req["argv"] = json!([format!("{cur}x")]);
        }
        assert_eq!(req.to_string().len(), control::MAX_LINE);
        assert!(
            !refuse_oversized_request(&req),
            "exactly at the limit passes"
        );
        let cur = req["argv"][0].as_str().unwrap().to_owned();
        req["argv"] = json!([format!("{cur}x")]);
        assert_eq!(req.to_string().len(), control::MAX_LINE + 1);
        assert!(refuse_oversized_request(&req), "one byte over is refused");
    }

    #[test]
    fn stdin_limit_resolution() {
        // None = no passthrough (byte-identical to 0.6.4); 1..=1GiB ok; 0 and
        // 1GiB+ are usage errors.
        assert_eq!(effective_stdin_limit(None).unwrap(), None);
        assert_eq!(effective_stdin_limit(Some(1)).unwrap(), Some(1));
        assert_eq!(
            effective_stdin_limit(Some(64 * 1024 * 1024)).unwrap(),
            Some(64 * 1024 * 1024)
        );
        assert_eq!(
            effective_stdin_limit(Some(MAX_STDIN_LIMIT)).unwrap(),
            Some(MAX_STDIN_LIMIT)
        );
        assert!(effective_stdin_limit(Some(0)).is_err());
        assert!(effective_stdin_limit(Some(MAX_STDIN_LIMIT + 1)).is_err());
    }

    #[test]
    fn stdin_limit_requires_no_tty_and_conflicts() {
        // clap: --stdin-limit requires --no-tty; conflicts with --tty/--detach.
        assert!(
            Cli::try_parse_from([
                "hisn",
                "exec",
                "--session",
                "s",
                "--stdin-limit",
                "10",
                "--",
                "ls"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hisn",
                "exec",
                "--session",
                "s",
                "--no-tty",
                "--tty",
                "--stdin-limit",
                "10",
                "--",
                "ls"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hisn",
                "exec",
                "--session",
                "s",
                "--detach",
                "--stdin-limit",
                "10",
                "--",
                "ls"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hisn",
                "exec",
                "--session",
                "s",
                "--no-tty",
                "--stdin-limit",
                "10",
                "--",
                "ls"
            ])
            .is_ok()
        );
    }

    /// Run one relay: `input` on a pipe as src, collect what lands on the dst
    /// pipe. Returns (outcome, bytes received).
    fn run_relay(input: &[u8], cap: u64) -> (StdinRelayOutcome, Vec<u8>) {
        let (src_r, src_w) = open_pipe().unwrap();
        let (dst_r, dst_w) = open_pipe().unwrap();
        let (wake_r, wake_w) = open_pipe().unwrap();
        // prefill the source pipe (input is small in tests)
        let w = src_w;
        let mut data = input;
        while !data.is_empty() {
            // SAFETY: blocking write into our own pipe.
            let n = unsafe { libc::write(w.as_raw_fd(), data.as_ptr() as *const _, data.len()) };
            assert!(n > 0);
            data = &data[n as usize..];
        }
        drop(w); // EOF after the input
        drop(wake_w); // no stop: run to EOF/cap
        let stop = std::sync::atomic::AtomicBool::new(false);
        let out = relay_stdin(src_r.as_raw_fd(), dst_w, cap, &stop, &wake_r);
        drop(src_r);
        // collect dst
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: blocking read of our own pipe.
            let n = unsafe { libc::read(dst_r.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
        (out, got)
    }

    #[test]
    fn relay_small_input_passes_through() {
        let (out, got) = run_relay(b"hello world", 1024);
        assert!(!out.exceeded);
        assert_eq!(got, b"hello world");
        assert_eq!(out.bytes, 11);
    }

    #[test]
    fn relay_exactly_at_cap_is_normal() {
        let (out, got) = run_relay(&[7u8; 100], 100);
        assert!(!out.exceeded, "exactly at the cap must not flag");
        assert_eq!(got.len(), 100);
    }

    #[test]
    fn relay_one_byte_over_flags_and_delivers_cap() {
        let (out, got) = run_relay(&[9u8; 101], 100);
        assert!(out.exceeded, "cap+1 must flag");
        assert_eq!(got.len(), 100, "exactly the cap is delivered");
    }

    #[test]
    fn relay_binary_with_nul_round_trips() {
        let input: Vec<u8> = (0u8..=255).cycle().take(300).collect();
        let (out, got) = run_relay(&input, 1024);
        assert!(!out.exceeded);
        assert_eq!(got, input);
    }

    #[test]
    fn relay_stop_ends_without_hanging() {
        // src pipe never gets EOF (write end kept): stop must end the relay.
        let (src_r, src_w) = open_pipe().unwrap();
        let (dst_r, dst_w) = open_pipe().unwrap();
        let (wake_r, wake_w) = open_pipe().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let t = std::thread::spawn(move || {
            relay_stdin(src_r.as_raw_fd(), dst_w, 1 << 20, &stop2, &wake_r)
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let byte = [0u8; 1];
        // SAFETY: one byte into our own wakeup pipe.
        unsafe { libc::write(wake_w.as_raw_fd(), byte.as_ptr() as *const _, 1) };
        let out = t.join().unwrap();
        assert!(!out.exceeded);
        drop((src_w, dst_r));
    }

    #[test]
    fn relay_epipe_is_normal_end() {
        // dst read end closed: the relay must end, no exceeded flag.
        let (src_r, src_w) = open_pipe().unwrap();
        let (_dst_r, dst_w) = open_pipe().unwrap();
        let (wake_r, _wake_w) = open_pipe().unwrap();
        // write a lot to src so the relay tries to write to a dead dst
        let w = src_w;
        let blob = [4u8; 8192];
        // SAFETY: blocking write into our own pipe (fills until relay drains).
        let n = unsafe { libc::write(w.as_raw_fd(), blob.as_ptr() as *const _, blob.len()) };
        assert!(n > 0);
        drop(w);
        drop(_dst_r); // close dst read end so the relay's writes hit EPIPE
        let stop = std::sync::atomic::AtomicBool::new(false);
        let out = relay_stdin(src_r.as_raw_fd(), dst_w, 1 << 20, &stop, &wake_r);
        assert!(!out.exceeded, "EPIPE is a normal end");
    }

    #[test]
    fn detach_request_roundtrip() {
        let a = exec_args(&["hisn", "exec", "--session", "s", "--detach", "--", "ls"]);
        assert!(a.detach);
        let req = build_request_with(&a, None, Some(4)).unwrap();
        assert_eq!(req["detach"], json!(true));
        assert_eq!(req["client"]["protocol_version"], json!(4));
        let parsed = control::parse_request(&req.to_string()).unwrap();
        assert!(matches!(
            parsed,
            control::Request::Exec {
                detach: true,
                tty: false,
                attach: false,
                ..
            }
        ));
    }

    #[test]
    fn detach_conflicts_with_tty_and_attach() {
        for flag in ["--tty", "--no-tty"] {
            assert!(
                Cli::try_parse_from([
                    "hisn",
                    "exec",
                    "--session",
                    "s",
                    "--detach",
                    flag,
                    "--",
                    "ls"
                ])
                .is_err(),
                "{flag}"
            );
        }
        // The supervisor refuses the combination too (a hand-built request).
        let req = control::parse_request(
            r#"{"op":"exec","argv":["x"],"tty":true,"detach":true,"client":{"protocol_version":4}}"#,
        )
        .unwrap();
        let (code, _) = control::check_detach(&req, 0).unwrap();
        assert_eq!(code, control::E_BAD_REQUEST);
        let req = control::parse_request(
            r#"{"op":"exec","argv":["x"],"attach":true,"detach":true,"client":{"protocol_version":4}}"#,
        )
        .unwrap();
        assert_eq!(
            control::check_detach(&req, 0).unwrap().0,
            control::E_BAD_REQUEST
        );
    }

    #[test]
    fn new_commands_refused_below_revision_4_exit_125_unsupported() {
        let e = require_revision("s", Some(3), 4).unwrap_err();
        assert_eq!(e.0, control::E_UNSUPPORTED);
        assert_eq!(e.1, "requires protocol revision 4, session has 3");
        let obj = error_object(e.0, &e.1);
        assert_eq!(obj["schema"], "hisn-error/v1");
        assert_eq!(obj["code"], "E_UNSUPPORTED");
        assert!(require_revision("s", Some(4), 4).is_ok());
        assert!(require_revision("s", Some(5), 4).is_ok());
        // An unresolvable session is "not found", not "too old".
        assert_eq!(
            require_revision("s", None, 4).unwrap_err().0,
            control::E_NOT_FOUND
        );
        assert_eq!(EXIT_INTERNAL, 125);
    }

    /// 0.6.4 B3: the exec requests equal the lines recorded from a v0.6.3
    /// build (`tests/fixtures/v063-wire.json`, plan section 10.4), byte for byte.
    #[test]
    fn request_bytes_unchanged_exec_matches_v063_fixture() {
        let fx: Value = serde_json::from_str(include_str!("../tests/fixtures/v063-wire.json"))
            .expect("fixture parses");
        let want = |k: &str| {
            fx[k][0]
                .as_str()
                .unwrap_or_else(|| panic!("no {k}"))
                .to_owned()
        };
        let a = exec_args(&["hisn", "exec", "--session", "s", "--", "echo", "hi"]);
        assert_eq!(
            build_request_with(&a, None, Some(3)).unwrap().to_string(),
            want("exec")
        );
        let a = exec_args(&[
            "hisn",
            "exec",
            "--session",
            "s",
            "--cwd",
            "/w",
            "--env",
            "A=1",
            "--env",
            "B=two",
            "--client",
            "lbl",
            "--",
            "sh",
            "-c",
            "x y",
        ]);
        assert_eq!(
            build_request_with(&a, None, Some(3)).unwrap().to_string(),
            want("exec_env_cwd_client")
        );
        let a = exec_args(&["hisn", "exec", "--session", "s", "--", "id"]);
        assert_eq!(
            build_request_with(&a, Some("tok-compat-0123456789"), Some(3))
                .unwrap()
                .to_string(),
            want("exec_seat_token")
        );
    }

    #[test]
    fn declared_version_stays_3_revision_is_4() {
        assert_eq!(crate::sessionmeta::PROTOCOL_VERSION, 3);
        assert_eq!(crate::sessionmeta::PROTOCOL_REVISION, 4);
        assert_eq!(crate::sessionmeta::DETACH_REVISION, 4);
        // An existing command declares 3 against a session of revision >= 3.
        let _ = seat_material; // (reads the live session dir; covered by the byte tests in A4)
        assert_eq!(
            client_field(None, None, Some(crate::sessionmeta::PROTOCOL_VERSION)),
            Some(json!({"protocol_version": 3}))
        );
    }

    /// 0.5.1: the seat credential and the revision ride in `client`, and a
    /// client without a credential is byte-identical to 0.5.0.
    #[test]
    fn seat_credential_and_revision_ride_in_client() {
        let a = exec_args(&["hisn", "exec", "--session", "s", "--", "ls"]);
        // No credential, no revision: the request is exactly the 0.5.0 shape.
        assert_eq!(
            build_request(&a).unwrap(),
            json!({"op":"exec","argv":["ls"],"cwd":null,"env":{},"tty":false,"client":null})
        );
        // With a credential and revision 3: only `client` gains fields.
        let req = build_request_with(&a, Some("TOK"), Some(3)).unwrap();
        assert_eq!(
            req["client"],
            json!({"protocol_version":3,"seat_token":"TOK"})
        );
        // With a label too: both ride, and the credential is never in env.
        let c = exec_args(&[
            "hisn",
            "exec",
            "--session",
            "s",
            "--client",
            "host-wakil",
            "--",
            "ls",
        ]);
        let req = build_request_with(&c, Some("TOK"), Some(3)).unwrap();
        assert_eq!(
            req["client"],
            json!({"label":"host-wakil","label_source":"flag","protocol_version":3,"seat_token":"TOK"})
        );
        assert!(!req["env"].to_string().contains("TOK"));
    }

    #[test]
    fn request_json_matches_the_contract() {
        let a = exec_args(&[
            "hisn",
            "exec",
            "--session",
            "s",
            "--cwd",
            "/w",
            "--env",
            "A=1",
            "--tty",
            "--",
            "sh",
            "-c",
            "x y",
        ]);
        assert_eq!(
            build_request(&a).unwrap(),
            json!({"op":"exec","argv":["sh","-c","x y"],"cwd":"/w","env":{"A":"1"},"tty":true,"client":null})
        );
        let b = exec_args(&["hisn", "exec", "--session", "s", "--", "ls"]);
        assert_eq!(
            build_request(&b).unwrap(),
            json!({"op":"exec","argv":["ls"],"cwd":null,"env":{},"tty":false,"client":null})
        );
        let bad = exec_args(&[
            "hisn",
            "exec",
            "--session",
            "s",
            "--env",
            "novalue",
            "--",
            "ls",
        ]);
        assert!(build_request(&bad).is_err());

        // 0.4.1 step 6: `exec --client LABEL` sets the client record in the
        // request (same shape as attach).
        let c = exec_args(&[
            "hisn",
            "exec",
            "--session",
            "s",
            "--client",
            "host-wakil",
            "--",
            "ls",
        ]);
        assert_eq!(
            build_request(&c).unwrap(),
            json!({"op":"exec","argv":["ls"],"cwd":null,"env":{},"tty":false,
                   "client":{"label":"host-wakil","label_source":"flag"}})
        );
    }

    #[test]
    fn replies_parse() {
        assert_eq!(
            parse_reply(r#"{"ok":true,"pid":9}"#),
            Some(Reply::Started(9, None))
        );
        assert_eq!(
            parse_reply(r#"{"exit":{"code":3}}"#),
            Some(Reply::Exit(Finish::Code(3)))
        );
        assert_eq!(
            parse_reply(r#"{"exit":{"signal":"TERM"}}"#),
            Some(Reply::Exit(Finish::Signal(libc::SIGTERM)))
        );
        assert_eq!(
            parse_reply(r#"{"exit":{"lost":true}}"#),
            Some(Reply::Exit(Finish::Lost))
        );
        assert_eq!(
            parse_reply(r#"{"ok":false,"error":"E_BAD_REQUEST","message":"env keys"}"#),
            Some(Reply::Error {
                code: "E_BAD_REQUEST".into(),
                message: "env keys".into()
            })
        );
        assert_eq!(parse_reply("not json"), None);
        assert_eq!(parse_reply(r#"{"exit":{"signal":"BOGUS"}}"#), None);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&Finish::Code(0)), 0);
        assert_eq!(exit_code(&Finish::Code(42)), 42);
        assert_eq!(exit_code(&Finish::Signal(libc::SIGTERM)), 128 + 15);
        assert_eq!(exit_code(&Finish::Lost), 125);
    }

    #[test]
    fn a_real_terminal_is_refused_unless_tty_is_requested() {
        assert!(refuse_real_terminal(false, false, |_| false).is_ok());
        assert!(refuse_real_terminal(true, false, |_| true).is_ok());
        let e = refuse_real_terminal(false, false, |fd| fd == 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("stdout") && e.contains("--tty"), "{e}");
        assert!(
            e.contains("--no-tty"),
            "refusal must name both options: {e}"
        );
        let e = refuse_real_terminal(false, false, |fd| fd != 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("stdin and stderr"), "{e}");
    }

    #[test]
    fn no_tty_accepts_terminals_on_every_descriptor() {
        // --no-tty never inspects the caller's descriptors: all three being
        // terminals is fine (stdin becomes /dev/null, stdout/stderr pass through).
        assert!(refuse_real_terminal(false, true, |_| true).is_ok());
    }

    #[test]
    fn tty_and_no_tty_together_is_a_usage_error() {
        let r = Cli::try_parse_from([
            "hisn",
            "exec",
            "--session",
            "s",
            "--tty",
            "--no-tty",
            "--",
            "ls",
        ]);
        let err = match r {
            Ok(_) => panic!("--tty with --no-tty must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn no_tty_parses_and_is_not_sent_as_a_tty_request() {
        let a = exec_args(&["hisn", "exec", "--session", "s", "--no-tty", "--", "ls"]);
        assert!(a.no_tty && !a.tty);
        assert_eq!(
            build_request(&a).unwrap(),
            json!({"op":"exec","argv":["ls"],"cwd":null,"env":{},"tty":false,"client":null})
        );
    }

    #[test]
    fn pump_delivers_exact_backlog_written_before_stop() {
        // Regression (0.4.0 L4): output the program wrote before exiting can
        // still sit in the pipe when the exit line arrives and `stop` is set.
        // Here the writer has finished and closed its end BEFORE `stop` is
        // set, so the whole ~256 KiB (well above one 16 KiB read and above a
        // typical 64 KiB pipe buffer) is pre-exit backlog. Every byte must
        // reach the destination, on both streams, exactly.
        //
        // The destinations are temp files passed by fd, so the test never
        // touches the process's fd 1 (the harness writes there).
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let out_payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let err_payload: Vec<u8> = b"stderr line\n".repeat(1000);
        let out_write = out_payload.clone();
        let err_write = err_payload.clone();
        let (out_r, out_w) = open_pipe().unwrap();
        let (err_r, err_w) = open_pipe().unwrap();
        // The writer runs on its own thread: 256 KiB cannot fit in the pipe
        // until the pump drains it. When the writer finishes and closes its
        // end — the program "exits" — it sets `stop`, as the exit line does in
        // production. The pump therefore runs while data is still flowing.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let writer = std::thread::spawn(move || {
            let mut w = std::fs::File::from(out_w);
            w.write_all(&out_write).unwrap();
            let mut w = std::fs::File::from(err_w);
            w.write_all(&err_write).unwrap();
            stop_w.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let dir = tempfile::tempdir().unwrap();
        // Open read+write: the test reads the sink back to assert exact bytes.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        let mut out_sink = opts.open(dir.path().join("out")).unwrap();
        let mut err_sink = opts.open(dir.path().join("err")).unwrap();
        pump_pipes(
            [(out_r, out_sink.as_raw_fd()), (err_r, err_sink.as_raw_fd())],
            &stop,
        );
        writer.join().unwrap();
        out_sink.seek(SeekFrom::Start(0)).unwrap();
        err_sink.seek(SeekFrom::Start(0)).unwrap();
        let mut got_out = Vec::new();
        out_sink.read_to_end(&mut got_out).unwrap();
        let mut got_err = Vec::new();
        err_sink.read_to_end(&mut got_err).unwrap();
        assert_eq!(got_out.len(), out_payload.len(), "stdout length");
        assert!(got_out == out_payload, "stdout bytes differ");
        assert_eq!(got_err, err_payload, "stderr bytes differ");
    }

    #[test]
    fn a_host_pty_can_be_allocated_and_carries_data() {
        let (m, s) = open_host_pty().unwrap();
        // SAFETY: writing/reading small buffers on the pty ends we own.
        unsafe {
            assert_eq!(libc::write(s.as_raw_fd(), b"hi".as_ptr().cast(), 2), 2);
            let mut b = [0u8; 8];
            let n = libc::read(m.as_raw_fd(), b.as_mut_ptr().cast(), 8);
            assert!(n >= 2 && &b[..2] == b"hi");
        }
    }

    #[test]
    fn seat_token_dash_requires_no_tty() {
        let dash = Some(std::path::Path::new("-"));
        assert!(refuse_stdin_token_unless_no_tty(dash, false).is_err());
        assert!(refuse_stdin_token_unless_no_tty(dash, true).is_ok());
        // a real file, or no file, is never affected
        let f = Some(std::path::Path::new("/tmp/t"));
        assert!(refuse_stdin_token_unless_no_tty(f, false).is_ok());
        assert!(refuse_stdin_token_unless_no_tty(None, false).is_ok());
    }

    #[test]
    fn seat_token_stdin_reads_one_line_only() {
        let mut r = std::io::Cursor::new(b"tok-123\nrest of stdin\n".to_vec());
        assert_eq!(read_token_line(&mut r, 4096).unwrap(), "tok-123");
        // Nothing after the newline was consumed.
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut r, &mut rest).unwrap();
        assert_eq!(rest, "rest of stdin\n");
        // No trailing newline: EOF ends the line; CRLF is trimmed.
        let mut r = std::io::Cursor::new(b"tok\r".to_vec());
        assert_eq!(read_token_line(&mut r, 4096).unwrap(), "tok");
    }

    #[test]
    fn seat_token_stdin_empty_is_error() {
        let mut r = std::io::Cursor::new(Vec::new());
        assert_eq!(read_token_line(&mut r, 4096).unwrap(), "");
        let mut r = std::io::Cursor::new(b"\n".to_vec());
        assert_eq!(read_token_line(&mut r, 4096).unwrap(), "");
        // seat_token maps an empty line to an error; here the reader's
        // limit and encoding checks.
        let mut r = std::io::Cursor::new(vec![b'a'; 10]);
        assert!(read_token_line(&mut r, 5).is_err());
        let mut r = std::io::Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert!(read_token_line(&mut r, 5).is_err());
    }

    #[test]
    fn seat_token_stdin_with_env_is_error() {
        // The "both sources" error comes first, before stdin is touched.
        // SAFETY-free: the variable is set and removed within this test
        // under the crate's env lock-free tests (no other test reads it).
        let key = "HISN_SEAT_TOKEN";
        let old = std::env::var(key).ok();
        unsafe { std::env::set_var(key, "x") };
        let e = seat_token(Some(std::path::Path::new("-")));
        match old {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
        assert!(e.unwrap_err().to_string().contains("both"));
    }

    #[test]
    fn exec_query_requests_are_minimal() {
        let c = client_field(None, None, Some(4));
        let r = exec_query_request("execstatus", "e-3", None, json!({}), c.clone());
        assert_eq!(
            r.to_string(),
            r#"{"client":{"protocol_version":4},"exec_id":"e-3","op":"execstatus"}"#
        );
        let r = exec_query_request(
            "execoutput",
            "e-3",
            Some("20261122T101500Z-9f3a"),
            json!({"stream":"stderr","offset":5}),
            c,
        );
        assert_eq!(r["incarnation"], "20261122T101500Z-9f3a");
        assert_eq!(
            (r["stream"].as_str(), r["offset"].as_u64()),
            (Some("stderr"), Some(5))
        );
        assert!(control::parse_request(&r.to_string()).is_ok());
    }

    #[test]
    fn exec_status_text_names_the_essentials() {
        let st = json!({
            "exec_id":"e-2","incarnation":"I","state":"exited","argv0":"sh","seat":null,
            "started":"S","ended":"E","exit_code":3,"cause":"exit",
            "stdout":{"total":10,"base":0},"stderr":{"total":0,"base":0},"output_open":false
        });
        let t = status_text(&st);
        for want in ["e-2", "exited", "exit     3", "cause    exit", "total 10"] {
            assert!(t.contains(want), "{want} in {t}");
        }
        assert!(!t.contains("still open"));
    }
}

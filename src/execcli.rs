//! Client side of `exec` (DESIGN §14): `hisn exec`.
//!
//! Sends the request with the caller's stdio descriptors (or the slave of a
//! *fresh* pty with `--tty`), relays the pty, forwards termination signals
//! through a second connection and turns the final `{"exit":…}` line into the
//! process exit status. Prints nothing of its own on stdout.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::cli::{ExecArgs, parse_env_spec};
use crate::exec::{Lines, read_some};
use crate::init::{EXIT_CANNOT_EXEC, EXIT_INTERNAL, EXIT_NOT_FOUND};
use crate::supervisor::{self, RawTerm, resize_to};
use crate::{control, sig, sys};

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
    let mut env = BTreeMap::new();
    for spec in &args.env {
        let (k, v) = parse_env_spec(spec).map_err(|e| anyhow!(e))?;
        env.insert(k, v);
    }
    Ok(json!({
        "op": "exec",
        "argv": args.command,
        "cwd": args.cwd,
        "env": env,
        "tty": args.tty,
    }))
}

/// One parsed response line from the supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Started(i32),
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
        return Some(Reply::Started(v["pid"].as_i64()? as i32));
    }
    Some(Reply::Error {
        code: v["error"].as_str().unwrap_or("E_INTERNAL").to_owned(),
        message: v["message"].as_str().unwrap_or("").to_owned(),
    })
}

/// Allocate a fresh pty on the *host*. Returns `(master, slave)`.
fn open_host_pty() -> io::Result<(OwnedFd, OwnedFd)> {
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
pub fn refuse_real_terminal(tty_flag: bool, is_tty: impl Fn(RawFd) -> bool) -> Result<()> {
    if tty_flag {
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
         Use --tty to run on a pty, or redirect it",
        ttys.join(" and ")
    )
}

/// Run `hisn exec`; returns the process exit code.
pub fn run(args: ExecArgs) -> Result<i32> {
    let req = build_request(&args)?;
    refuse_real_terminal(args.tty, sys::isatty)?;
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

    // The request line and its descriptors travel in one sendmsg.
    let line = format!("{req}\n");
    let fds: Vec<RawFd> = match &slave {
        Some(s) => vec![s.as_raw_fd()],
        None => vec![0, 1, 2],
    };
    sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), &fds).context("sending request")?;
    drop(slave); // the master sees EOF/EIO once the program's side closes

    let finish = relay(&conn, &args.session, master)?;
    Ok(exit_code(&finish))
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
        if let Some(p) = pid {
            for s in queued.drain(..) {
                // A second connection: this one is busy delivering the exit line.
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
                        Some(Reply::Started(p)) => pid = Some(p),
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
            json!({"op":"exec","argv":["sh","-c","x y"],"cwd":"/w","env":{"A":"1"},"tty":true})
        );
        let b = exec_args(&["hisn", "exec", "--session", "s", "--", "ls"]);
        assert_eq!(
            build_request(&b).unwrap(),
            json!({"op":"exec","argv":["ls"],"cwd":null,"env":{},"tty":false})
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
    }

    #[test]
    fn replies_parse() {
        assert_eq!(
            parse_reply(r#"{"ok":true,"pid":9}"#),
            Some(Reply::Started(9))
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
        assert!(refuse_real_terminal(false, |_| false).is_ok());
        assert!(refuse_real_terminal(true, |_| true).is_ok());
        let e = refuse_real_terminal(false, |fd| fd == 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("stdout") && e.contains("--tty"), "{e}");
        let e = refuse_real_terminal(false, |fd| fd != 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("stdin and stderr"), "{e}");
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
}

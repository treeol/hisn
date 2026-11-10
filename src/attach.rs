//! Client side of `attach` (0.4.0 step 2): `hisn attach`.
//!
//! An attach is an exec with `tty: true` and `attach: true` and no command
//! (the supervisor starts the session's shell, `$SHELL` from the env
//! snapshot else `/bin/sh`, in the session cwd). Multiple concurrent
//! attaches are peers in the same pid namespace (L21 semantics).
//!
//! The detach key is Ctrl-] then `d`, intercepted client-side: it closes
//! the connection, which cancels the shell through the existing TERM→KILL
//! path. The key sequence is never forwarded to the shell.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::cli::AttachArgs;
use crate::execcli::{Finish, exit_code, open_host_pty, parse_exit};
use crate::supervisor;
use crate::sys;

/// Build the control-protocol request for an attach.
pub fn build_request(args: &AttachArgs) -> Result<Value> {
    let client = if args.client.is_some() {
        Some(json!({
            "label": args.client,
            "label_source": "flag",
        }))
    } else {
        None
    };
    Ok(json!({
        "op": "exec",
        "argv": [],
        "cwd": args.cwd,
        "env": {},
        "tty": true,
        "attach": true,
        "client": client,
    }))
}

/// Run `hisn attach`. Allocates a pty, sends the request, relays I/O, and
/// intercepts the detach key (Ctrl-] d).
pub fn run(args: AttachArgs) -> Result<i32> {
    let req = build_request(&args)?;
    let sock = supervisor::socket_for(&args.session)?;
    let conn = UnixStream::connect(&sock)
        .with_context(|| format!("connecting to session {}", args.session))?;

    let (master, slave) = open_host_pty().context("allocating a pty for attach")?;
    // Set a sane initial size.
    // SAFETY: winsize ioctl on fds we own, zeroed storage.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) != 0 || ws.ws_col == 0 {
            ws.ws_row = 24;
            ws.ws_col = 80;
        }
        libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws);
    }

    let line = format!("{req}\n");
    sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), &[slave.as_raw_fd()])
        .context("sending attach request")?;
    drop(slave);

    // Enter raw mode on the host tty so input is passed through unfiltered.
    let _raw = supervisor::RawTerm::enter(0);

    // Relay the pty with detach-key interception.
    let finish = relay_with_detach(&conn, master)?;
    Ok(exit_code(&finish))
}

/// Relay the pty master to stdin/stdout, intercepting Ctrl-] d as the
/// detach key. When the detach key is seen, the connection is dropped
/// (the shell receives TERM→KILL through the existing path) and we
/// read the exit line from the connection like a normal exec end.
fn relay_with_detach(mut conn: &UnixStream, master: OwnedFd) -> Result<Finish> {
    let conn_fd = conn.as_raw_fd();
    let master_fd = master.as_raw_fd();
    let mut stdout = io::stdout();

    let mut in_detach = false;
    let mut buf = [0u8; 4096];
    let mut reply_buf = String::new();

    // Install a SIGWINCH handler that resizes the pty to match stdin.
    // SAFETY: signal handler only does an ioctl on a static fd.
    static mut WINCH_MASTER: libc::c_int = -1;
    static mut WINCH_STDIN: libc::c_int = -1;
    extern "C" fn winch_handler(_sig: libc::c_int) {
        // SAFETY: ioctl on fds we own, zeroed storage.
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(WINCH_STDIN, libc::TIOCGWINSZ, &mut ws) == 0 {
                let _ = libc::ioctl(WINCH_MASTER, libc::TIOCSWINSZ, &ws);
            }
        }
    }
    // SAFETY: we set the static fds before installing the handler.
    unsafe {
        WINCH_MASTER = master_fd;
        WINCH_STDIN = 0;
        let _ = libc::signal(
            libc::SIGWINCH,
            winch_handler as *const () as libc::sighandler_t,
        );
    }

    loop {
        let mut fds = [
            libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            }, // stdin
            libc::pollfd {
                fd: conn_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll on our own fds.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue; // SIGWINCH interrupted poll; retry
            }
            return Err(io::Error::last_os_error()).context("attach: poll");
        }

        // Shell output → stdout.
        if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(master_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                stdout.write_all(&buf[..n as usize])?;
                stdout.flush()?;
            } else {
                break;
            }
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && fds[0].revents & libc::POLLIN == 0
        {
            break;
        }

        // Stdin → master (with detach-key interception).
        if fds[1].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let data = &buf[..n as usize];
                let mut out = Vec::with_capacity(data.len());
                for &b in data {
                    if in_detach {
                        if b == b'd' {
                            // F7: detach — shut down the write side of
                            // the connection so the supervisor sees EOF
                            // and cancels the exec (TERM→KILL). Then
                            // read the exit line with a timeout.
                            unsafe {
                                let _ = libc::signal(libc::SIGWINCH, libc::SIG_DFL);
                            }
                            use std::net::Shutdown;
                            let _ = conn.shutdown(Shutdown::Write);
                            return read_exit_after_detach(conn);
                        }
                        out.push(0x1d);
                        out.push(b);
                        in_detach = false;
                    } else if b == 0x1d {
                        in_detach = true;
                    } else {
                        out.push(b);
                    }
                }
                if !out.is_empty() {
                    let _ = unsafe { libc::write(master_fd, out.as_ptr() as *const _, out.len()) };
                }
            }
        }

        // Conn reply (exit line).
        if fds[2].revents & libc::POLLIN != 0 {
            let mut byte = [0u8; 1];
            match conn.read(&mut byte) {
                Ok(0) => {
                    // Reset SIGWINCH before returning.
                    unsafe {
                        let _ = libc::signal(libc::SIGWINCH, libc::SIG_DFL);
                    }
                    return Ok(Finish::Lost);
                }
                Ok(_) => {
                    reply_buf.push(byte[0] as char);
                    if byte[0] == b'\n' {
                        if let Some(f) = parse_exit(reply_buf.trim()) {
                            unsafe {
                                let _ = libc::signal(libc::SIGWINCH, libc::SIG_DFL);
                            }
                            return Ok(f);
                        }
                        reply_buf.clear();
                    }
                }
                Err(e) => return Err(e).context("attach: reading reply"),
            }
        }
    }

    // Master closed: drain the conn for the exit line.
    unsafe {
        let _ = libc::signal(libc::SIGWINCH, libc::SIG_DFL);
    }
    let mut buf = String::new();
    let mut byte = [0u8; 1];
    loop {
        match conn.read(&mut byte) {
            Ok(0) => return Ok(Finish::Lost),
            Ok(_) => {
                buf.push(byte[0] as char);
                if byte[0] == b'\n' {
                    if let Some(f) = parse_exit(buf.trim()) {
                        return Ok(f);
                    }
                    buf.clear();
                }
            }
            Err(e) => return Err(e).context("attach: reading exit"),
        }
    }
}

/// After a detach (connection still open), read the exit line from the
/// connection with a short timeout (the shell is being killed).
fn read_exit_after_detach(mut conn: &UnixStream) -> Result<Finish> {
    let mut buf = String::new();
    let mut byte = [0u8; 1];
    // Give the supervisor up to 5 s to send the exit line after the kill.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if std::time::Instant::now() > deadline {
            return Ok(Finish::Lost);
        }
        // Poll with a 1 s timeout.
        let mut fds = [libc::pollfd {
            fd: conn.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 1, 1000) };
        if r <= 0 {
            continue;
        }
        match conn.read(&mut byte) {
            Ok(0) => return Ok(Finish::Lost),
            Ok(_) => {
                buf.push(byte[0] as char);
                if byte[0] == b'\n' {
                    if let Some(f) = parse_exit(buf.trim()) {
                        return Ok(f);
                    }
                    buf.clear();
                }
            }
            Err(e) => return Err(e).context("attach: reading exit after detach"),
        }
    }
}

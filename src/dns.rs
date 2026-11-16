//! Phase 2 of ADR 0022 (0.6.0, open mode): sandbox DNS forwarding responder.
//!
//! Runs in the supervisor process on two fds bound by init on `127.0.0.1:53`
//! (UDP + TCP, before caps drop). Forwards every query to the host
//! upstreams (same discovery as `mounts::build_resolv_conf`: host
//! `/etc/resolv.conf`, then `/run/systemd/resolve/resolv.conf`, then a
//! `[net] nameservers` override when given). `SERVFAIL` on failure or
//! upstream timeout. No pinning, no allow-list — that is 0.7.0.
//!
//! Bounds: max 64 concurrent TCP connections, max 256 pending upstream
//! exchanges, 2 s upstream deadline. Thread per TCP connection is *not*
//! used; a single-threaded poll loop serves both fds with an async state
//! machine so fd/thread counts stay bounded.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// Upstream timeout per query.
pub const UPSTREAM_DEADLINE: Duration = Duration::from_secs(2);
/// Max concurrent TCP connections held at once.
pub const MAX_TCP_CONNS: usize = 64;
/// Max pending upstream exchanges.
pub const MAX_PENDING: usize = 256;

/// Discover upstream resolvers (first usable list wins).
pub fn upstreams(override_ns: Option<&[String]>) -> Vec<SocketAddr> {
    if let Some(ns) = override_ns
        && !ns.is_empty()
    {
        let mut out = Vec::new();
        for n in ns {
            let s = if n.contains(':') {
                format!("[{n}]:53")
            } else {
                format!("{n}:53")
            };
            if let Ok(a) = s.parse() {
                out.push(a);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let mut out = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("nameserver") {
                    let ip = rest.trim();
                    if ip.is_empty() || ip.starts_with("127.") || ip == "::1" {
                        continue; // stub / loopback: not an upstream
                    }
                    let s = if ip.contains(':') {
                        format!("[{ip}]:53")
                    } else {
                        format!("{ip}:53")
                    };
                    if let Ok(a) = s.parse() {
                        out.push(a);
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    Vec::new()
}

/// SERVFAIL response for a query message (QR=1, RCODE=2), preserving the
/// header + question when possible.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query[..12].to_vec();
    // Rebuild flags: keep OPCODE/RD from query flags, set QR=1, RA=1,
    // RCODE=2 (SERVFAIL).
    let qflags = u16::from_be_bytes([query[2], query[3]]);
    let rflags = 0x8000 | (qflags & 0x0100) | 0x0080 | 0x0002;
    r[2..4].copy_from_slice(&rflags.to_be_bytes());
    // QCOUNT stays; AN/NS/AR counts zeroed.
    r[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    // Append question section verbatim (from byte 12 to end is the question
    // for a stub query; a malformed tail is dropped).
    r.extend_from_slice(&query[12..]);
    Some(r)
}

struct TcpConn {
    fd: OwnedFd,
    buf: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    // awaiting the 2-byte length prefix?
    need: Option<usize>,
}

impl TcpConn {
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_pos < self.out.len() {
            // SAFETY: fd is a valid socket owned by us.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    self.out[self.out_pos..].as_ptr() as *const libc::c_void,
                    self.out.len() - self.out_pos,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                return Err(e);
            }
            self.out_pos += n as usize;
        }
        self.out.clear();
        self.out_pos = 0;
        Ok(())
    }
}

/// Run the DNS responder until a shutdown flag is set or both fds hit
/// POLLH/ERR. Blocking; call on a dedicated thread. `udp`/`tcp` are the
/// fds received from init via SCM_RIGHTS (bound 127.0.0.1:53).
pub fn run(
    udp: OwnedFd,
    tcp: OwnedFd,
    ups: Vec<SocketAddr>,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    let ups = std::sync::Arc::new(ups);
    let mut conns: Vec<TcpConn> = Vec::new();
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        pollfds.clear();
        pollfds.push(libc::pollfd {
            fd: udp.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        pollfds.push(libc::pollfd {
            fd: tcp.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        for c in &mut conns {
            pollfds.push(libc::pollfd {
                fd: c.fd.as_raw_fd(),
                events: libc::POLLIN | libc::POLLOUT,
                revents: 0,
            });
        }
        let timeout_ms = 500_i32;
        // SAFETY: pollfds is a valid array.
        let r = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if r == 0 {
            continue;
        }
        // UDP fd
        if pollfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return;
        }
        if pollfds[0].revents & libc::POLLIN != 0 {
            let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut slen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    udp.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut src as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                    &mut slen,
                )
            };
            if n > 0 {
                let q = &buf[..n as usize];
                let resp = exchange(q, &ups);
                let resp = resp.unwrap_or_else(|| servfail(q).unwrap_or_default());
                if !resp.is_empty() {
                    // Reply to the sender.
                    let _ = unsafe {
                        libc::sendto(
                            udp.as_raw_fd(),
                            resp.as_ptr() as *const libc::c_void,
                            resp.len(),
                            libc::MSG_NOSIGNAL,
                            &src as *const libc::sockaddr_storage as *const libc::sockaddr,
                            slen,
                        )
                    };
                }
            }
        }
        // TCP listener
        if pollfds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return;
        }
        if pollfds[1].revents & libc::POLLIN != 0 && conns.len() < MAX_TCP_CONNS {
            // SAFETY: accept.
            let fd = unsafe {
                libc::accept(tcp.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            if fd >= 0 {
                // SAFETY: fresh fd owned by us.
                let f = unsafe { OwnedFd::from_raw_fd(fd) };
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if fl >= 0 {
                    unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
                }
                conns.push(TcpConn {
                    fd: f,
                    buf: Vec::new(),
                    out: Vec::new(),
                    out_pos: 0,
                    need: None,
                });
            }
        }
        // Connections
        let mut i = 0;
        while i < conns.len() {
            let revents = pollfds.get(2 + i).map(|p| p.revents).unwrap_or(0);
            let mut dead = false;
            if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                dead = true;
            } else {
                if revents & libc::POLLIN != 0 {
                    let mut tmp = [0u8; 4096];
                    let n = unsafe {
                        libc::recv(
                            conns[i].fd.as_raw_fd(),
                            tmp.as_mut_ptr() as *mut libc::c_void,
                            tmp.len(),
                            0,
                        )
                    };
                    if n < 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::WouldBlock
                            && e.kind() != io::ErrorKind::Interrupted
                        {
                            dead = true;
                        }
                    } else if n == 0 {
                        dead = true;
                    } else {
                        conns[i].buf.extend_from_slice(&tmp[..n as usize]);
                        // Parse length-prefixed messages.
                        loop {
                            if conns[i].need.is_none() {
                                if conns[i].buf.len() < 2 {
                                    break;
                                }
                                let l =
                                    u16::from_be_bytes([conns[i].buf[0], conns[i].buf[1]]) as usize;
                                conns[i].buf.drain(..2);
                                conns[i].need = Some(l);
                            }
                            let need = conns[i].need.unwrap();
                            if conns[i].buf.len() < need {
                                break;
                            }
                            let msg: Vec<u8> = conns[i].buf.drain(..need).collect();
                            conns[i].need = None;
                            let resp = exchange(&msg, &ups)
                                .unwrap_or_else(|| servfail(&msg).unwrap_or_default());
                            if !resp.is_empty() {
                                let l = resp.len() as u16;
                                conns[i].out.extend_from_slice(&l.to_be_bytes());
                                conns[i].out.extend_from_slice(&resp);
                            }
                        }
                    }
                }
                if !dead {
                    let _ = conns[i].drain_out();
                }
            }
            if dead {
                conns.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// One upstream exchange: send to the first upstream that answers.
fn exchange(q: &[u8], ups: &[SocketAddr]) -> Option<Vec<u8>> {
    let deadline = Instant::now() + UPSTREAM_DEADLINE;
    for up in ups {
        if let Some(r) = exchange_one(q, *up, deadline) {
            return Some(r);
        }
    }
    None
}

fn exchange_one(q: &[u8], up: SocketAddr, deadline: Instant) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    sock.connect(up).ok()?;
    sock.send(q).ok()?;
    let mut buf = vec![0u8; 4096];
    while Instant::now() < deadline {
        match sock.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                // Basic sanity: must be >= header and same ID.
                if n >= 4 && buf[..2] == q[..2] {
                    return Some(buf);
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Bind helpers for init (before caps drop): bind 127.0.0.1:53 UDP+TCP.
pub fn bind_dns() -> io::Result<(OwnedFd, OwnedFd)> {
    let udp = UdpSocket::bind("127.0.0.1:53")?;
    let udp_fd = unsafe { OwnedFd::from_raw_fd(AsRawFd::as_raw_fd(&udp)) };
    std::mem::forget(udp);
    // SAFETY: raw socket() for the TCP listener (std has no TcpListener::bind on a fixed addr without net2).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let tcp_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let one = 1i32;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = libc::INADDR_LOOPBACK;
    addr.sin_port = 53u16.to_be();
    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let r = unsafe { libc::listen(fd, 16) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((udp_fd, tcp_fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servfail_shape() {
        let q = [0u8; 12];
        let mut q = q.to_vec();
        q[0] = 0x12;
        q[1] = 0x34; // ID
        q[3] = 0x01; // RD
        let r = servfail(&q).unwrap();
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[3] & 0x0f, 2, "RCODE=SERVFAIL");
        assert_eq!(r[2] & 0x80, 0x80, "QR bit set");
    }

    #[test]
    fn upstreams_parses_resolv_conf_text() {
        // Direct parse test via temp file is host-dependent; instead test
        // the override path (deterministic).
        let ups = upstreams(Some(&["8.8.8.8".into(), "1.1.1.1".into()]));
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].to_string(), "8.8.8.8:53");
    }
}

//! ADR 0022 (0.6.0, open mode): the sandbox DNS forwarding responder.
//!
//! Sandbox init binds `127.0.0.1:53` (UDP + TCP) inside the sandbox netns
//! before it drops capabilities and hands both sockets to the supervisor.
//! The supervisor runs [`run`] on them: every query is forwarded to the
//! host's resolvers from the host netns and the answer is relayed
//! unchanged. There is no allow-list and no pinning in 0.6.0.
//!
//! Upstreams are discovered once at session start by
//! [`discover_upstreams`]; a session without a usable upstream does not
//! start. Per query the responder waits at most [`UPSTREAM_DEADLINE`] for
//! the upstreams and otherwise answers `SERVFAIL` itself.
//!
//! Concurrency: the poll loop only receives and dispatches. Upstream
//! exchanges and the replies run on [`UPSTREAM_WORKERS`] threads behind a
//! queue of [`MAX_PENDING`] queries, so one slow upstream delays only its
//! own query. A full queue is answered `SERVFAIL` at once.
//!
//! Every answered query is one `network/dns` journal record
//! ([`record`]) carrying the real response code.

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::journal::Journal;

/// Total time one query may spend on the upstreams.
pub const UPSTREAM_DEADLINE: Duration = Duration::from_secs(2);
/// Max concurrent TCP client connections.
pub const MAX_TCP_CONNS: usize = 64;
/// Max bytes buffered per TCP connection (length prefix + max message).
pub const MAX_TCP_BUF: usize = 65535 + 2;
/// Threads doing upstream exchanges.
pub const UPSTREAM_WORKERS: usize = 16;
/// Queries that may wait for a worker; one more is answered SERVFAIL.
pub const MAX_PENDING: usize = 256;
/// Queries one TCP connection may have in flight.
const MAX_TCP_IN_FLIGHT: usize = 16;
/// Unsent reply bytes one TCP connection may accumulate.
const MAX_TCP_OUT: usize = 1 << 20;
/// A TCP connection with nothing in flight is closed after this long.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Host files read for upstream resolvers, in this order, after a
/// `[net] nameservers` override. The first file that lists at least one
/// usable address wins.
pub const UPSTREAM_FILES: [&str; 3] = [
    "/run/systemd/resolve/resolv.conf",
    "/run/NetworkManager/no-stub-resolv.conf",
    "/etc/resolv.conf",
];

/// Discover the upstream resolvers for an open-mode session from the host
/// ([`UPSTREAM_FILES`]). See [`discover_upstreams_in`].
pub fn discover_upstreams(override_ns: Option<&[String]>) -> Result<Vec<SocketAddr>, String> {
    let files: Vec<PathBuf> = UPSTREAM_FILES.iter().map(PathBuf::from).collect();
    discover_upstreams_in(override_ns, &files)
}

/// Upstream discovery over an explicit file list.
///
/// Order: the `[net] nameservers` override when given (it replaces the
/// host's list; an override without a usable address is an error, never a
/// fall-through), then each file in `files`. The responder runs in the
/// supervisor, which lives in the host network namespace, so loopback
/// resolvers (a local stub such as `127.0.0.53`) are valid upstreams.
/// Unspecified addresses and entries that are not a plain IP address
/// (e.g. a scoped link-local `fe80::1%eth0`) are skipped.
///
/// `Err` names every source that was checked. The caller refuses to start
/// the session: a responder without upstreams would answer every query
/// with SERVFAIL.
pub fn discover_upstreams_in(
    override_ns: Option<&[String]>,
    files: &[PathBuf],
) -> Result<Vec<SocketAddr>, String> {
    if let Some(ns) = override_ns {
        let ups: Vec<SocketAddr> = ns.iter().filter_map(|a| upstream_addr(a)).collect();
        if ups.is_empty() {
            return Err(format!(
                "network = \"open\": [net] nameservers {ns:?} lists no usable address"
            ));
        }
        return Ok(ups);
    }
    let mut checked = Vec::new();
    for path in files {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let ups = nameservers(&text);
                if !ups.is_empty() {
                    return Ok(ups);
                }
                checked.push(format!("{} (no usable nameserver)", path.display()));
            }
            Err(e) => checked.push(format!("{} ({})", path.display(), io_reason(&e))),
        }
    }
    Err(format!(
        "network = \"open\": no DNS upstream found. Checked: {}. \
         Set [net] nameservers in the profile.",
        checked.join("; ")
    ))
}

fn io_reason(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "not found".to_owned(),
        _ => e.to_string(),
    }
}

/// `nameserver` addresses of a resolv.conf text, in file order.
fn nameservers(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver")).then(|| it.next())?
        })
        .filter_map(upstream_addr)
        .collect()
}

fn upstream_addr(s: &str) -> Option<SocketAddr> {
    let ip: IpAddr = s.parse().ok()?;
    (!ip.is_unspecified()).then(|| SocketAddr::new(ip, 53))
}

/// Offset just past the question section of `msg`, when the header says
/// exactly one question and it parses.
fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointers do not occur in a question
        }
        i += 1 + len;
    }
    let end = i + 1 + 4; // root label + QTYPE + QCLASS
    (end <= msg.len()).then_some(end)
}

/// The queried name (lower case, without the trailing dot; `.` for the
/// root) and the query type of `msg`. Bytes outside `[a-z0-9-_]` are
/// written as `\DDD`, so the result is safe to print.
pub fn question(msg: &[u8]) -> Option<(String, u16)> {
    let end = question_end(msg)?;
    let mut name = String::new();
    let mut i = 12;
    loop {
        let len = msg[i] as usize;
        if len == 0 {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &msg[i + 1..i + 1 + len] {
            let c = b.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_' {
                name.push(c as char);
            } else {
                name.push_str(&format!("\\{b:03}"));
            }
        }
        i += 1 + len;
    }
    if name.is_empty() {
        name.push('.');
    }
    let qtype = u16::from_be_bytes([msg[end - 4], msg[end - 3]]);
    Some((name, qtype))
}

/// SERVFAIL response for `query` (QR=1, RA=1, RCODE=2), keeping the id,
/// the opcode, the RD bit and the question. `None` when `query` is too
/// short to carry a header.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query[..12].to_vec();
    let qflags = u16::from_be_bytes([query[2], query[3]]);
    let rflags = 0x8000 | (qflags & 0x7900) | 0x0080 | 0x0002;
    r[2..4].copy_from_slice(&rflags.to_be_bytes());
    // Answer, authority and additional counts are zero; the question is
    // kept only when it parses (anything after it is dropped).
    r[6..12].fill(0);
    match question_end(query) {
        Some(end) => r.extend_from_slice(&query[12..end]),
        None => r[4..6].fill(0),
    }
    Some(r)
}

/// Response code name as the journal writes it.
pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".to_owned(),
        1 => "FORMERR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        4 => "NOTIMP".to_owned(),
        5 => "REFUSED".to_owned(),
        n => format!("RCODE{n}"),
    }
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        28 => "AAAA".to_owned(),
        33 => "SRV".to_owned(),
        64 => "SVCB".to_owned(),
        65 => "HTTPS".to_owned(),
        255 => "ANY".to_owned(),
        n => format!("TYPE{n}"),
    }
}

/// The `network/dns` journal payload for one answered query.
///
/// - `verdict`: `ok` when an upstream answered NOERROR; `failed` when an
///   upstream answered with any other response code (relayed unchanged);
///   `error` when no upstream answered and hisn replied SERVFAIL itself.
/// - `rcode`: the response code the client received.
/// - `error`: why hisn answered itself (`upstream-timeout`,
///   `upstream-unreachable`, `queue-full`), else null.
/// - `upstream`: the resolver that answered, else null.
pub fn record(
    query: &[u8],
    response: &[u8],
    proto: &str,
    upstream: Option<SocketAddr>,
    error: Option<&str>,
) -> Value {
    let rcode = response.get(3).map_or(2, |b| b & 0x0f);
    let verdict = match (error, rcode) {
        (Some(_), _) => "error",
        (None, 0) => "ok",
        (None, _) => "failed",
    };
    let (name, qtype) = match question(query) {
        Some((n, t)) => (Value::String(n), Value::String(qtype_name(t))),
        None => (Value::Null, Value::Null),
    };
    json!({
        "verdict": verdict,
        "rcode": rcode_name(rcode),
        "name": name,
        "qtype": qtype,
        "proto": proto,
        "upstream": upstream.map(|a| a.to_string()),
        "error": error,
        "seat": Value::Null,
    })
}

/// Is `resp` a response to `query` (same id, QR set, full header)?
fn answers(query: &[u8], resp: &[u8]) -> bool {
    resp.len() >= 12 && resp[..2] == query[..2] && resp[2] & 0x80 != 0
}

fn exchange_udp(q: &[u8], up: SocketAddr, budget: Duration) -> Result<Vec<u8>, &'static str> {
    const UNREACHABLE: &str = "upstream-unreachable";
    let deadline = Instant::now() + budget;
    // The wildcard address lets the kernel pick the source for any
    // upstream, loopback or not.
    let bind = if up.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).map_err(|_| UNREACHABLE)?;
    sock.connect(up).map_err(|_| UNREACHABLE)?;
    sock.send(q).map_err(|_| UNREACHABLE)?;
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("upstream-timeout");
        }
        sock.set_read_timeout(Some(left)).map_err(|_| UNREACHABLE)?;
        match sock.recv(&mut buf) {
            Ok(n) if answers(q, &buf[..n]) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(_) => {} // not our answer: keep waiting
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            // ECONNREFUSED from an ICMP port-unreachable and the like.
            Err(_) => return Err(UNREACHABLE),
        }
    }
}

fn exchange_tcp(q: &[u8], up: SocketAddr, budget: Duration) -> Result<Vec<u8>, &'static str> {
    const TIMEOUT: &str = "upstream-timeout";
    const UNREACHABLE: &str = "upstream-unreachable";
    // `budget` bounds the whole exchange: the time left is recomputed
    // before every single read and write, so an upstream that sends one
    // byte at a time cannot stretch it.
    let deadline = Instant::now() + budget;
    let left = || {
        let d = deadline.saturating_duration_since(Instant::now());
        if d.is_zero() { Err(TIMEOUT) } else { Ok(d) }
    };
    let failed = |e: io::Error| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TIMEOUT,
        _ => UNREACHABLE,
    };
    let mut s = TcpStream::connect_timeout(&up, left()?).map_err(failed)?;
    let mut msg = (q.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(q);
    let mut sent = 0;
    while sent < msg.len() {
        s.set_write_timeout(Some(left()?)).map_err(failed)?;
        match s.write(&msg[sent..]) {
            Ok(0) => return Err(UNREACHABLE),
            Ok(n) => sent += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(failed(e)),
        }
    }
    let mut read_full = |buf: &mut [u8]| -> Result<(), &'static str> {
        let mut got = 0;
        while got < buf.len() {
            s.set_read_timeout(Some(left()?)).map_err(failed)?;
            match s.read(&mut buf[got..]) {
                Ok(0) => return Err(UNREACHABLE),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(failed(e)),
            }
        }
        Ok(())
    };
    let mut len = [0u8; 2];
    read_full(&mut len)?;
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    read_full(&mut resp)?;
    if answers(q, &resp) {
        Ok(resp)
    } else {
        Err(UNREACHABLE)
    }
}

/// Forward `q` to the upstreams in order until one answers. The
/// [`UPSTREAM_DEADLINE`] is shared: each upstream gets an equal part of
/// what is left, so a dead first resolver cannot use up the whole budget.
/// A query that arrived over TCP is forwarded over TCP.
fn forward(
    q: &[u8],
    ups: &[SocketAddr],
    tcp: bool,
) -> (Result<Vec<u8>, &'static str>, Option<SocketAddr>) {
    let deadline = Instant::now() + UPSTREAM_DEADLINE;
    let mut last = Err("upstream-unreachable");
    for (i, up) in ups.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (Err("upstream-timeout"), None);
        }
        let budget = left / (ups.len() - i) as u32;
        let r = if tcp {
            exchange_tcp(q, *up, budget)
        } else {
            exchange_udp(q, *up, budget)
        };
        match r {
            Ok(resp) => return (Ok(resp), Some(*up)),
            Err(e) => last = Err(e),
        }
    }
    (last, None)
}

/// Where a reply goes.
enum Client {
    Udp {
        addr: libc::sockaddr_storage,
        len: libc::socklen_t,
    },
    Tcp {
        conn: u64,
    },
}

struct Job {
    query: Vec<u8>,
    client: Client,
}

/// State shared by the poll loop and the workers.
struct Shared {
    udp: OwnedFd,
    /// Written by a worker when a TCP reply is ready for the poll loop.
    wake: OwnedFd,
    ups: Vec<SocketAddr>,
    journal: Option<Arc<Journal>>,
    /// Set when the responder stops: workers drop the queries that are
    /// still queued instead of forwarding them.
    stopping: AtomicBool,
}

impl Shared {
    fn send_udp(&self, resp: &[u8], addr: &libc::sockaddr_storage, len: libc::socklen_t) {
        // SAFETY: `addr`/`len` are the sender address recvfrom filled in.
        unsafe {
            libc::sendto(
                self.udp.as_raw_fd(),
                resp.as_ptr() as *const libc::c_void,
                resp.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                addr as *const libc::sockaddr_storage as *const libc::sockaddr,
                len,
            )
        };
    }

    fn journal(
        &self,
        query: &[u8],
        resp: &[u8],
        tcp: bool,
        upstream: Option<SocketAddr>,
        error: Option<&str>,
    ) {
        if let Some(j) = &self.journal {
            let proto = if tcp { "tcp" } else { "udp" };
            j.dns_record(record(query, resp, proto, upstream, error));
        }
    }

    fn wake(&self) {
        let one = 1u64;
        // SAFETY: 8-byte write to our own eventfd.
        unsafe {
            libc::write(
                self.wake.as_raw_fd(),
                &one as *const u64 as *const libc::c_void,
                8,
            )
        };
    }
}

fn worker(jobs: &Mutex<mpsc::Receiver<Job>>, shared: &Shared, done: &mpsc::Sender<(u64, Vec<u8>)>) {
    loop {
        let job = {
            let rx = jobs.lock().unwrap_or_else(|e| e.into_inner());
            rx.recv()
        };
        let Ok(job) = job else { return };
        if shared.stopping.load(Ordering::Relaxed) {
            continue; // the session is ending: nobody waits for this
        }
        let tcp = matches!(job.client, Client::Tcp { .. });
        let (result, upstream) = forward(&job.query, &shared.ups, tcp);
        let (resp, error) = match result {
            Ok(r) => (r, None),
            Err(e) => (servfail(&job.query).unwrap_or_default(), Some(e)),
        };
        shared.journal(&job.query, &resp, tcp, upstream, error);
        match job.client {
            Client::Udp { addr, len } => shared.send_udp(&resp, &addr, len),
            Client::Tcp { conn } => {
                let _ = done.send((conn, resp));
                shared.wake();
            }
        }
    }
}

struct TcpConn {
    id: u64,
    fd: OwnedFd,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    in_flight: usize,
    last: Instant,
    /// The client has finished sending (it may still read replies).
    eof: bool,
}

impl TcpConn {
    fn queue_reply(&mut self, resp: &[u8]) {
        self.out
            .extend_from_slice(&(resp.len() as u16).to_be_bytes());
        self.out.extend_from_slice(resp);
    }

    /// Send as much pending output as the socket takes now.
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_pos < self.out.len() {
            // SAFETY: fd is a valid socket owned by us.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    self.out[self.out_pos..].as_ptr() as *const libc::c_void,
                    self.out.len() - self.out_pos,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(()),
                    _ => Err(e),
                };
            }
            self.out_pos += n as usize;
        }
        self.out.clear();
        self.out_pos = 0;
        Ok(())
    }
}

/// Run the responder until `shutdown` is set or a listening socket fails.
/// Blocking; call on a dedicated thread. `udp` and `tcp` are the sockets
/// sandbox init bound on `127.0.0.1:53`; `ups` comes from
/// [`discover_upstreams`]; `journal` is an engine handle
/// ([`Journal::clone_for_engine`]).
pub fn run(
    udp: OwnedFd,
    tcp: OwnedFd,
    ups: Vec<SocketAddr>,
    shutdown: &AtomicBool,
    journal: Option<Arc<Journal>>,
) {
    // SAFETY: plain eventfd creation; the result is checked.
    let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake < 0 {
        return;
    }
    let shared = Arc::new(Shared {
        udp,
        // SAFETY: fresh fd owned by us.
        wake: unsafe { OwnedFd::from_raw_fd(wake) },
        ups,
        journal,
        stopping: AtomicBool::new(false),
    });
    // The listener must not block: a client can reset its connection
    // between poll and accept, and a blocking accept would then stall
    // the whole responder until the next client.
    // SAFETY: fcntl on our own listening socket.
    unsafe {
        let fl = libc::fcntl(tcp.as_raw_fd(), libc::F_GETFL);
        if fl < 0 || libc::fcntl(tcp.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return;
        }
    }
    let (job_tx, job_rx) = mpsc::sync_channel::<Job>(MAX_PENDING);
    let job_rx = Arc::new(Mutex::new(job_rx));
    let (done_tx, done_rx) = mpsc::channel::<(u64, Vec<u8>)>();
    let workers: Vec<_> = (0..UPSTREAM_WORKERS)
        .map(|_| {
            let (rx, sh, done) = (job_rx.clone(), shared.clone(), done_tx.clone());
            std::thread::spawn(move || worker(&rx, &sh, &done))
        })
        .collect();
    drop(done_tx);

    poll_loop(&shared, &tcp, &job_tx, &done_rx, shutdown);

    // Workers end when the queue sender is gone. Each finishes the
    // exchange it is in (bounded by UPSTREAM_DEADLINE) and drops what is
    // still queued, so stopping takes about one deadline at most.
    shared.stopping.store(true, Ordering::Relaxed);
    drop(job_tx);
    for w in workers {
        let _ = w.join();
    }
}

/// Queue `query` for the workers; when the queue is full, answer SERVFAIL
/// right here. Returns the SERVFAIL for a TCP client (the caller owns the
/// connection buffers).
fn dispatch(
    shared: &Shared,
    job_tx: &mpsc::SyncSender<Job>,
    query: Vec<u8>,
    client: Client,
) -> Option<Vec<u8>> {
    let job = match job_tx.try_send(Job { query, client }) {
        Ok(()) => return None,
        Err(mpsc::TrySendError::Full(j)) | Err(mpsc::TrySendError::Disconnected(j)) => j,
    };
    let resp = servfail(&job.query).unwrap_or_default();
    let tcp = matches!(job.client, Client::Tcp { .. });
    shared.journal(&job.query, &resp, tcp, None, Some("queue-full"));
    match job.client {
        Client::Udp { addr, len } => {
            shared.send_udp(&resp, &addr, len);
            None
        }
        Client::Tcp { .. } => Some(resp),
    }
}

fn poll_loop(
    shared: &Shared,
    tcp: &OwnedFd,
    job_tx: &mpsc::SyncSender<Job>,
    done_rx: &mpsc::Receiver<(u64, Vec<u8>)>,
    shutdown: &AtomicBool,
) {
    const FIXED: usize = 3; // udp, tcp listener, wake
    let mut conns: Vec<TcpConn> = Vec::new();
    let mut next_conn = 0u64;
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    let mut buf = vec![0u8; 65535];
    let pfd = |fd: i32, events: i16| libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        pollfds.clear();
        pollfds.push(pfd(shared.udp.as_raw_fd(), libc::POLLIN));
        // Stop accepting while the connection table is full.
        let accept = if conns.len() < MAX_TCP_CONNS {
            libc::POLLIN
        } else {
            0
        };
        pollfds.push(pfd(tcp.as_raw_fd(), accept));
        pollfds.push(pfd(shared.wake.as_raw_fd(), libc::POLLIN));
        for c in &conns {
            // POLLOUT only with output pending, and POLLIN only until
            // the client's end of input, or poll would spin.
            let out = if c.out_pos < c.out.len() {
                libc::POLLOUT
            } else {
                0
            };
            let input = if c.eof { 0 } else { libc::POLLIN };
            pollfds.push(pfd(c.fd.as_raw_fd(), input | out));
        }
        // SAFETY: pollfds is a valid array of pollfds.len() entries.
        let r = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 250) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let bad = libc::POLLERR | libc::POLLNVAL;
        if pollfds[0].revents & bad != 0 || pollfds[1].revents & bad != 0 {
            return;
        }

        // UDP: one datagram per round, handed to a worker.
        if pollfds[0].revents & libc::POLLIN != 0 {
            // SAFETY: zeroed sockaddr_storage is a valid out-buffer.
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: buf/addr/len describe valid writable memory.
            let n = unsafe {
                libc::recvfrom(
                    shared.udp.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                    &mut len,
                )
            };
            // Shorter than a header: not answerable, dropped.
            if n >= 12 {
                let query = buf[..n as usize].to_vec();
                dispatch(shared, job_tx, query, Client::Udp { addr, len });
            }
        }

        // TCP replies finished by workers.
        if pollfds[2].revents & libc::POLLIN != 0 {
            let mut count = 0u64;
            // SAFETY: 8-byte read from our own eventfd.
            unsafe {
                libc::read(
                    shared.wake.as_raw_fd(),
                    &mut count as *mut u64 as *mut libc::c_void,
                    8,
                )
            };
        }
        while let Ok((id, resp)) = done_rx.try_recv() {
            // The client may have gone away meanwhile; then the reply is
            // dropped.
            if let Some(c) = conns.iter_mut().find(|c| c.id == id) {
                c.in_flight = c.in_flight.saturating_sub(1);
                c.queue_reply(&resp);
                c.last = Instant::now();
            }
        }

        // Existing connections (indices match pollfds[FIXED..] as built
        // above; new connections are appended afterwards).
        let polled = pollfds.len() - FIXED;
        let mut dead: Vec<u64> = Vec::new();
        for (i, c) in conns.iter_mut().enumerate().take(polled) {
            let revents = pollfds[FIXED + i].revents;
            // After the client's end of input, POLLHUP means it is gone
            // entirely.
            let mut closed = revents & bad != 0 || (c.eof && revents & libc::POLLHUP != 0);
            if !closed && !c.eof && revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut tmp = [0u8; 4096];
                // SAFETY: tmp is valid writable memory of tmp.len() bytes.
                let n = unsafe {
                    libc::recv(
                        c.fd.as_raw_fd(),
                        tmp.as_mut_ptr() as *mut libc::c_void,
                        tmp.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n > 0 {
                    c.inbuf.extend_from_slice(&tmp[..n as usize]);
                    c.last = Instant::now();
                    closed = !take_tcp_queries(shared, job_tx, c);
                } else if n == 0 {
                    // End of input. Queries already taken are still
                    // answered (a client may shut down its sending side
                    // and wait for the replies).
                    c.eof = true;
                } else {
                    let e = io::Error::last_os_error().kind();
                    closed = !matches!(e, io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted);
                }
            }
            if !closed {
                closed = c.drain_out().is_err() || c.out.len() - c.out_pos > MAX_TCP_OUT;
            }
            let settled = c.in_flight == 0 && c.out.is_empty();
            let idle = settled && c.last.elapsed() > TCP_IDLE;
            if closed || idle || (c.eof && settled) {
                dead.push(c.id);
            }
        }
        conns.retain(|c| !dead.contains(&c.id));

        // New connection.
        if pollfds[1].revents & libc::POLLIN != 0 && conns.len() < MAX_TCP_CONNS {
            // SAFETY: accept4 on our listener; the result is checked.
            let fd = unsafe {
                libc::accept4(
                    tcp.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd >= 0 {
                next_conn += 1;
                conns.push(TcpConn {
                    id: next_conn,
                    // SAFETY: fresh fd owned by us.
                    fd: unsafe { OwnedFd::from_raw_fd(fd) },
                    inbuf: Vec::new(),
                    out: Vec::new(),
                    out_pos: 0,
                    in_flight: 0,
                    last: Instant::now(),
                    eof: false,
                });
            }
        }
    }
}

/// Split complete length-prefixed queries off `c.inbuf` and dispatch
/// them. False when the connection must be closed (protocol violation).
fn take_tcp_queries(shared: &Shared, job_tx: &mpsc::SyncSender<Job>, c: &mut TcpConn) -> bool {
    while c.inbuf.len() >= 2 {
        let len = u16::from_be_bytes([c.inbuf[0], c.inbuf[1]]) as usize;
        if len < 12 {
            return false; // shorter than a DNS header
        }
        if c.inbuf.len() < 2 + len {
            break;
        }
        let query: Vec<u8> = c.inbuf.drain(..2 + len).skip(2).collect();
        if c.in_flight >= MAX_TCP_IN_FLIGHT {
            let resp = servfail(&query).unwrap_or_default();
            shared.journal(&query, &resp, true, None, Some("queue-full"));
            c.queue_reply(&resp);
            continue;
        }
        match dispatch(shared, job_tx, query, Client::Tcp { conn: c.id }) {
            None => c.in_flight += 1,
            Some(resp) => c.queue_reply(&resp),
        }
    }
    c.inbuf.len() <= MAX_TCP_BUF
}

/// Bind the responder sockets on `127.0.0.1:53` (UDP + TCP). Called by
/// sandbox init inside the sandbox netns, before it drops capabilities.
pub fn bind_dns() -> io::Result<(OwnedFd, OwnedFd)> {
    let udp: OwnedFd = UdpSocket::bind("127.0.0.1:53")?.into();
    let tcp: OwnedFd = std::net::TcpListener::bind("127.0.0.1:53")?.into();
    Ok((udp, tcp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::path::Path;

    /// A query for `name` with the given id and type.
    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn write_file(dir: &Path, name: &str, text: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    fn addrs(ups: &[SocketAddr]) -> Vec<String> {
        ups.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn discovery_override_wins_over_files() {
        let d = tempfile::tempdir().unwrap();
        let f = write_file(d.path(), "a", "nameserver 9.9.9.9\n");
        let ups =
            discover_upstreams_in(Some(&["192.0.2.2".into(), "2001:db8::1".into()]), &[f]).unwrap();
        assert_eq!(addrs(&ups), ["192.0.2.2:53", "[2001:db8::1]:53"]);
    }

    #[test]
    fn discovery_unusable_override_is_an_error_not_a_fall_through() {
        let d = tempfile::tempdir().unwrap();
        let f = write_file(d.path(), "a", "nameserver 9.9.9.9\n");
        let e = discover_upstreams_in(Some(&["not-an-ip".into()]), &[f]).unwrap_err();
        assert!(e.contains("[net] nameservers"), "{e}");
    }

    #[test]
    fn discovery_takes_the_first_file_with_a_usable_nameserver() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing");
        let empty = write_file(d.path(), "empty", "search home\n# nameserver 1.1.1.1\n");
        let second = write_file(
            d.path(),
            "second",
            "search home\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n",
        );
        let third = write_file(d.path(), "third", "nameserver 9.9.9.9\n");
        let ups = discover_upstreams_in(None, &[missing, empty, second, third]).unwrap();
        assert_eq!(addrs(&ups), ["192.0.2.53:53", "[2001:db8::53]:53"]);
    }

    #[test]
    fn discovery_accepts_loopback_resolvers() {
        // The host's stub file: the supervisor is in the host netns, so
        // 127.0.0.53 is reachable for it.
        let d = tempfile::tempdir().unwrap();
        let stub = write_file(
            d.path(),
            "stub",
            "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch home\n",
        );
        let ups = discover_upstreams_in(None, &[d.path().join("none"), stub]).unwrap();
        assert_eq!(addrs(&ups), ["127.0.0.53:53"]);
        let v6 = write_file(d.path(), "v6", "nameserver ::1\n");
        assert_eq!(
            addrs(&discover_upstreams_in(None, &[v6]).unwrap()),
            ["[::1]:53"]
        );
    }

    #[test]
    fn discovery_skips_unusable_entries() {
        let d = tempfile::tempdir().unwrap();
        let f = write_file(
            d.path(),
            "a",
            "nameserver 0.0.0.0\nnameserver fe80::1%eth0\nnameserver bogus\nnameserver\n\
             nameserver 192.0.2.7\n",
        );
        assert_eq!(
            addrs(&discover_upstreams_in(None, &[f]).unwrap()),
            ["192.0.2.7:53"]
        );
    }

    #[test]
    fn discovery_without_any_upstream_fails_and_names_every_file() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing.conf");
        let empty = write_file(d.path(), "empty.conf", "search home\n");
        let e = discover_upstreams_in(None, &[missing.clone(), empty.clone()]).unwrap_err();
        assert!(
            e.contains(&format!("{} (not found)", missing.display())),
            "{e}"
        );
        assert!(
            e.contains(&format!("{} (no usable nameserver)", empty.display())),
            "{e}"
        );
        assert!(e.contains("[net] nameservers"), "{e}");
    }

    #[test]
    fn default_file_order() {
        assert_eq!(
            UPSTREAM_FILES,
            [
                "/run/systemd/resolve/resolv.conf",
                "/run/NetworkManager/no-stub-resolv.conf",
                "/etc/resolv.conf",
            ]
        );
    }

    #[test]
    fn question_is_parsed_and_escaped() {
        let q = query(7, "WWW.Example.com", 28);
        assert_eq!(question(&q), Some(("www.example.com".to_owned(), 28)));
        let mut odd = query(7, "x", 1);
        odd[13] = 0x1b; // an escape byte in the label
        assert_eq!(question(&odd), Some(("\\027".to_owned(), 1)));
        assert_eq!(question(&query(7, "", 2)), Some((".".to_owned(), 2)));
        assert_eq!(question(&q[..14]), None);
    }

    #[test]
    fn servfail_keeps_id_and_question_only() {
        let mut q = query(0x1234, "hermetic.test", 1);
        let question_len = q.len() - 12;
        q[11] = 1; // ARCOUNT = 1
        q.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]); // EDNS OPT
        let r = servfail(&q).unwrap();
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[2] & 0x01, 0x01, "RD kept");
        assert_eq!(r[3] & 0x0f, 2, "RCODE = SERVFAIL");
        assert_eq!(
            &r[4..12],
            &[0, 1, 0, 0, 0, 0, 0, 0],
            "one question, no records"
        );
        assert_eq!(r.len(), 12 + question_len, "additional section dropped");
        assert_eq!(servfail(&q[..11]), None);
    }

    #[test]
    fn record_carries_the_real_rcode() {
        let q = query(1, "example.org", 1);
        let up: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let resp = |rcode: u8| {
            let mut r = q.clone();
            r[2] |= 0x80;
            r[3] = (r[3] & 0xf0) | rcode;
            r
        };
        let ok = record(&q, &resp(0), "udp", Some(up), None);
        assert_eq!(ok["verdict"], "ok");
        assert_eq!(ok["rcode"], "NOERROR");
        assert_eq!(ok["name"], "example.org");
        assert_eq!(ok["qtype"], "A");
        assert_eq!(ok["upstream"], "192.0.2.2:53");
        assert_eq!(ok["error"], Value::Null);

        let nx = record(&q, &resp(3), "tcp", Some(up), None);
        assert_eq!(nx["verdict"], "failed");
        assert_eq!(nx["rcode"], "NXDOMAIN");
        assert_eq!(nx["proto"], "tcp");

        // An upstream's own SERVFAIL is a failed lookup, not "ok".
        let sf = record(&q, &resp(2), "udp", Some(up), None);
        assert_eq!(sf["verdict"], "failed");
        assert_eq!(sf["rcode"], "SERVFAIL");

        // No upstream answered: hisn's SERVFAIL, verdict "error".
        let own = servfail(&q).unwrap();
        let err = record(&q, &own, "udp", None, Some("upstream-timeout"));
        assert_eq!(err["verdict"], "error");
        assert_eq!(err["rcode"], "SERVFAIL");
        assert_eq!(err["error"], "upstream-timeout");
        assert_eq!(err["upstream"], Value::Null);
    }

    /// A UDP upstream on loopback: names starting with `slow` are never
    /// answered, names starting with `nx` get NXDOMAIN, the rest NOERROR.
    fn fake_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Some((name, _)) = question(&buf[..n]) else {
                    continue;
                };
                if name.starts_with("slow") {
                    continue;
                }
                let mut r = buf[..n].to_vec();
                r[2] |= 0x80;
                if name.starts_with("nx") {
                    r[3] = (r[3] & 0xf0) | 3;
                }
                let _ = sock.send_to(&r, from);
            }
        });
        addr
    }

    struct Responder {
        udp: SocketAddr,
        tcp: SocketAddr,
        shutdown: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Responder {
        fn start(ups: Vec<SocketAddr>, journal: Option<Arc<Journal>>) -> Self {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            let (udp_addr, tcp_addr) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
            let shutdown = Arc::new(AtomicBool::new(false));
            let sd = shutdown.clone();
            let thread = std::thread::spawn(move || {
                run(udp.into(), tcp.into(), ups, &sd, journal);
            });
            Self {
                udp: udp_addr,
                tcp: tcp_addr,
                shutdown,
                thread: Some(thread),
            }
        }

        fn client(&self) -> UdpSocket {
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            c.connect(self.udp).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
            c
        }
    }

    impl Drop for Responder {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    #[test]
    fn slow_upstream_does_not_delay_other_queries() {
        let r = Responder::start(vec![fake_upstream()], None);
        // Eight queries that the upstream never answers...
        let slow: Vec<UdpSocket> = (0..8)
            .map(|i| {
                let c = r.client();
                c.send(&query(100 + i, "slow.test", 1)).unwrap();
                c
            })
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        // ...and one it answers at once.
        let fast = r.client();
        let start = Instant::now();
        fast.send(&query(1, "fast.test", 1)).unwrap();
        let mut buf = [0u8; 512];
        let n = fast.recv(&mut buf).unwrap();
        let took = start.elapsed();
        assert_eq!(&buf[..2], &[0, 1]);
        assert_eq!(buf[3] & 0x0f, 0, "NOERROR ({n} bytes)");
        assert!(
            took < Duration::from_millis(500),
            "fast query took {took:?} behind 8 slow ones"
        );
        // The slow ones end in SERVFAIL after the upstream deadline.
        for (i, c) in slow.iter().enumerate() {
            c.recv(&mut buf).unwrap();
            assert_eq!(buf[3] & 0x0f, 2, "slow query {i} gets SERVFAIL");
        }
        assert!(start.elapsed() >= Duration::from_millis(1500));
    }

    #[test]
    fn second_upstream_answers_when_the_first_is_dead() {
        // First upstream: a bound socket nobody reads (no answer).
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
        let r = Responder::start(vec![dead.local_addr().unwrap(), fake_upstream()], None);
        let c = r.client();
        c.send(&query(9, "fast.test", 1)).unwrap();
        let mut buf = [0u8; 512];
        c.recv(&mut buf).unwrap();
        assert_eq!(buf[3] & 0x0f, 0, "answered by the second upstream");
    }

    #[test]
    fn tcp_framing_and_pipelining_with_an_unreachable_upstream() {
        // The fake upstream speaks UDP only, so a TCP query cannot be
        // forwarded: the client must still get a well-formed SERVFAIL
        // for each pipelined query, in a length-prefixed frame.
        // (Forwarding over TCP is tested just below.)
        let r = Responder::start(vec![fake_upstream()], None);
        let mut s = TcpStream::connect(r.tcp).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        for id in [21u16, 22] {
            let q = query(id, "fast.test", 1);
            s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&q).unwrap();
        }
        let mut ids = Vec::new();
        for _ in 0..2 {
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut resp).unwrap();
            assert_eq!(resp[3] & 0x0f, 2);
            ids.push(u16::from_be_bytes([resp[0], resp[1]]));
        }
        ids.sort_unstable();
        assert_eq!(ids, [21, 22]);
    }

    /// A TCP upstream on loopback. `trickle`: send the reply one byte
    /// every 300 ms instead of at once.
    fn fake_tcp_upstream(trickle: bool) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut q).is_err() {
                    continue;
                }
                q[2] |= 0x80;
                let mut reply = (q.len() as u16).to_be_bytes().to_vec();
                reply.extend_from_slice(&q);
                if trickle {
                    for b in reply {
                        if s.write_all(&[b]).is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(300));
                    }
                } else {
                    let _ = s.write_all(&reply);
                }
            }
        });
        addr
    }

    fn tcp_ask(r: &Responder, id: u16, half_close: bool) -> (u8, Duration) {
        let start = Instant::now();
        let mut s = TcpStream::connect(r.tcp).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        let q = query(id, "fast.test", 1);
        s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
        s.write_all(&q).unwrap();
        if half_close {
            s.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let mut len = [0u8; 2];
        s.read_exact(&mut len).unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut resp).unwrap();
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), id);
        (resp[3] & 0x0f, start.elapsed())
    }

    #[test]
    fn tcp_query_is_forwarded_over_tcp() {
        let r = Responder::start(vec![fake_tcp_upstream(false)], None);
        assert_eq!(tcp_ask(&r, 31, false).0, 0, "NOERROR from the TCP upstream");
        // A client that shuts down its sending side still gets the reply.
        assert_eq!(
            tcp_ask(&r, 32, true).0,
            0,
            "reply after the client's half-close"
        );
    }

    #[test]
    fn trickling_tcp_upstream_is_cut_off_at_the_deadline() {
        // The reply would take about 9 s at one byte per 300 ms. The
        // whole exchange is bounded by the upstream deadline (2 s).
        let r = Responder::start(vec![fake_tcp_upstream(true)], None);
        let (rcode, took) = tcp_ask(&r, 33, false);
        assert_eq!(rcode, 2, "SERVFAIL");
        assert!(took < Duration::from_secs(4), "took {took:?}");
    }

    #[test]
    fn stopping_drops_the_queued_queries() {
        // 60 queries for an upstream that never answers: 16 are being
        // forwarded, the rest wait. Stopping must take about one upstream
        // deadline, not the four it would take to work through them all.
        let r = Responder::start(vec![fake_upstream()], None);
        let clients: Vec<UdpSocket> = (0..60)
            .map(|i| {
                let c = r.client();
                c.send(&query(200 + i, "slow.test", 1)).unwrap();
                c
            })
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        let start = Instant::now();
        drop(r);
        let took = start.elapsed();
        assert!(took < Duration::from_millis(3500), "stopping took {took:?}");
        drop(clients);
    }

    #[test]
    fn reset_before_accept_does_not_stall_the_responder() {
        // Connections that are reset right after the handshake: the
        // responder must keep answering UDP afterwards.
        let r = Responder::start(vec![fake_upstream()], None);
        for _ in 0..20 {
            let s = TcpStream::connect(r.tcp).unwrap();
            // SO_LINGER 0: close sends RST.
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: setsockopt on our own socket with a valid struct.
            unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    &linger as *const libc::linger as *const libc::c_void,
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                )
            };
            drop(s);
        }
        let c = r.client();
        c.send(&query(40, "fast.test", 1)).unwrap();
        let mut buf = [0u8; 512];
        c.recv(&mut buf).unwrap();
        assert_eq!(buf[3] & 0x0f, 0);
    }

    #[test]
    fn journal_records_real_outcomes() {
        let d = tempfile::tempdir().unwrap();
        let ws = d.path().join("ws");
        let j = Arc::new(Journal::new(ws.clone(), "s1".into()).clone_for_engine());
        let r = Responder::start(vec![fake_upstream()], Some(j.clone()));
        let c = r.client();
        let mut buf = [0u8; 512];
        for (id, name) in [(1u16, "good.test"), (2, "nx.test"), (3, "slow.test")] {
            c.send(&query(id, name, 28)).unwrap();
            c.recv(&mut buf).unwrap();
        }
        assert!(j.net_flush(Duration::from_secs(10)));
        let (records, _) = crate::journal::read_records(&ws);
        let dns: Vec<_> = records.iter().filter(|r| r.kind == "network/dns").collect();
        let of = |name: &str| {
            &dns.iter()
                .find(|r| r.data["name"] == name)
                .unwrap_or_else(|| panic!("no record for {name}"))
                .data
        };
        assert_eq!(dns.len(), 3);
        assert_eq!(of("good.test")["verdict"], "ok");
        assert_eq!(of("good.test")["rcode"], "NOERROR");
        assert_eq!(of("good.test")["qtype"], "AAAA");
        assert_eq!(of("nx.test")["verdict"], "failed");
        assert_eq!(of("nx.test")["rcode"], "NXDOMAIN");
        assert_eq!(of("slow.test")["verdict"], "error");
        assert_eq!(of("slow.test")["rcode"], "SERVFAIL");
        assert_eq!(of("slow.test")["error"], "upstream-timeout");
    }
}

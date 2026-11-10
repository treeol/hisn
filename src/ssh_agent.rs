//! SSH agent T1 proxy (0.3.2, ADR 0011).
//!
//! A filtering proxy for the ssh-agent protocol. The proxy connects to the
//! host `SSH_AUTH_SOCK` and listens on a unix socket inside the hisn runtime
//! dir. It forwards ONLY `SSH_AGENTC_REQUEST_IDENTITIES` (11) and
//! `SSH_AGENTC_SIGN_REQUEST` (13); everything else (`ADD_IDENTITY`,
//! `REMOVE_ALL_IDENTITIES`, `LOCK`, `UNLOCK`, `EXTENSION`, constrained adds)
//! is answered with `SSH_AGENT_FAILURE` (5) and logged.
//!
//! With `keys` set (a fingerprint allowlist), `REQUEST_IDENTITIES` responses
//! are filtered to the allowlisted fingerprints, and `SIGN_REQUEST` for a
//! non-listed key fails.
//!
//! The proxy runs as a thread in the supervisor process. The proxy socket is
//! forwarded into the sandbox by the supervisor (using the same `do_forward`
//! mechanism as `[[forward]]`), and `SSH_AUTH_SOCK` is set in the scrubbed env
//! to point at the forwarded path. The host `SSH_AUTH_SOCK` is never mounted.
//!
//! T1 means "sign but never add/remove/extract": the session can produce
//! signatures with the listed keys, but cannot mutate the host agent's key
//! set or extract key material.

use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use anyhow::{Context, Result, bail};
use sha2::Digest;

/// SSH agent protocol message types (draft-miller-ssh-agent / OpenSSH).
/// These are stable byte values, not an API that changes.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

/// The maximum message size the proxy will accept (256 KiB — large enough
/// for key blobs and signatures, small enough to prevent memory exhaustion).
const MAX_MSG_SIZE: u32 = 256 * 1024;

/// Read a complete ssh-agent message: 4-byte big-endian length + payload.
/// Returns the payload bytes (not including the length prefix).
fn read_msg(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent message too large: {len}"),
        ));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write a complete ssh-agent message: 4-byte big-endian length + payload.
///
/// The host agent socket gets a write timeout (see `HOST_WRITE_TIMEOUT`):
/// a host agent that accepts a connection but never reads must not pin
/// the worker thread forever.
fn write_msg(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Write timeout on the host agent socket. The client side already has
/// `CLIENT_IDLE_TIMEOUT` on reads; without a write bound a wedged host
/// agent wedges the worker (and its client counter slot) indefinitely.
const HOST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read timeout on the host agent socket: symmetric with the write timeout
/// (a host agent that accepts but never replies pins the worker and the
/// client's counter slot). Chosen identical to `HOST_WRITE_TIMEOUT` so both
/// directions have the same bound.
const HOST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// RAII guard for one proxy client: decrements the active-clients counter
/// on *every* exit path, including a panic unwinding through
/// `handle_client`. Replaces the manual `fetch_sub` after the call.
struct ClientGuard {
    counter: Arc<AtomicUsize>,
}
impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Build a `SSH_AGENT_FAILURE` message (1 byte payload).
fn failure_msg() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Parse a 4-byte big-endian length from a byte slice.
fn parse_u32(data: &[u8]) -> Option<(u32, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Some((val, &data[4..]))
}

/// Parse a length-prefixed byte string (SSH wire format: 4-byte length + data).
fn parse_string(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = parse_u32(data)?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// Compute the SHA-256 fingerprint of a public key blob: `SHA256:base64(sha256(blob))`.
/// Matches OpenSSH format: base64 with padding (`=`) stripped, as `ssh-keygen -lf` prints.
fn ssh_fingerprint(blob: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(blob);
    let hash = hasher.finalize();
    let b64 = base64_encode(&hash);
    format!("SHA256:{}", b64.trim_end_matches('='))
}

/// Standard base64 encoding (RFC 4648).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

/// Parse the `REQUEST_IDENTITIES` response from the host agent and filter
/// the identities to the allowlisted fingerprints.
///
/// Response format (after type byte `SSH_AGENT_IDENTITIES_ANSWER`, 12):
///   uint32 num_keys
///   for each key: string key_blob, string comment
fn filter_identities_response(response: &[u8], allowed: &[String]) -> Result<Vec<u8>> {
    if response.is_empty() {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    if response[0] != SSH_AGENT_IDENTITIES_ANSWER {
        // Not an identities answer; pass through (e.g. failure).
        return Ok(response.to_vec());
    }
    let (num_keys, mut rest) = match parse_u32(&response[1..]) {
        Some(v) => v,
        None => return Ok(vec![SSH_AGENT_FAILURE]),
    };
    let mut filtered: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for _ in 0..num_keys {
        let (blob, r1) = match parse_string(rest) {
            Some(v) => v,
            None => return Ok(vec![SSH_AGENT_FAILURE]),
        };
        let (comment, r2) = match parse_string(r1) {
            Some(v) => v,
            None => return Ok(vec![SSH_AGENT_FAILURE]),
        };
        rest = r2;
        if allowed.is_empty() {
            filtered.push((blob.to_vec(), comment.to_vec()));
        } else {
            let fp = ssh_fingerprint(blob);
            if allowed.iter().any(|a| a == &fp) {
                filtered.push((blob.to_vec(), comment.to_vec()));
            }
        }
    }
    let mut out = Vec::new();
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    out.extend_from_slice(&(filtered.len() as u32).to_be_bytes());
    for (blob, comment) in &filtered {
        out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        out.extend_from_slice(blob);
        out.extend_from_slice(&(comment.len() as u32).to_be_bytes());
        out.extend_from_slice(comment);
    }
    Ok(out)
}

/// Parse a `SIGN_REQUEST` to extract the key blob for fingerprinting.
/// Request format (after type byte `SSH_AGENTC_SIGN_REQUEST`, 13):
///   string key_blob, string data, uint32 flags
///
/// The whole envelope is validated (blob, data, flags, no trailing bytes) so a
/// request the proxy cannot fully parse is never forwarded.
fn extract_sign_key_blob(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let (blob, rest) = parse_string(&payload[1..])?;
    let (_data, rest) = parse_string(rest)?;
    let (_flags, rest) = parse_u32(rest)?;
    if !rest.is_empty() || blob.is_empty() {
        return None;
    }
    Some(blob.to_vec())
}

/// Is the message type one we forward? Only 11 (REQUEST_IDENTITIES) and 13
/// (SIGN_REQUEST).
fn is_forwarded(msg_type: u8) -> bool {
    matches!(
        msg_type,
        SSH_AGENTC_REQUEST_IDENTITIES | SSH_AGENTC_SIGN_REQUEST
    )
}

/// Handle one client connection: read messages, forward the allowed ones
/// to the host agent, filter responses. Disallowed messages get FAILURE.
fn handle_client(mut client: UnixStream, host_agent: &str, allowed: Vec<String>, session_id: &str) {
    let mut host = match UnixStream::connect(host_agent) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("ssh-agent proxy: connect to {host_agent}: {e}");
            let _ = write_msg(&mut client, &failure_msg());
            return;
        }
    };
    // Bound every write to the host agent: without it a host agent that
    // stops reading pins this worker (and the client's counter slot).
    // The read side gets the symmetric bound from `HOST_READ_TIMEOUT`
    // (Part 2.5): a host agent that accepts but never replies would
    // otherwise block `read_msg` forever.
    if let Err(e) = host.set_write_timeout(Some(HOST_WRITE_TIMEOUT)) {
        tracing::warn!("ssh-agent proxy [{session_id}]: host write timeout: {e}");
    }
    if let Err(e) = host.set_read_timeout(Some(HOST_READ_TIMEOUT)) {
        tracing::warn!("ssh-agent proxy [{session_id}]: host read timeout: {e}");
    }
    loop {
        let payload = match read_msg(&mut client) {
            Ok(p) => p,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::debug!("ssh-agent proxy [{session_id}]: client read: {e}");
                break;
            }
        };
        if payload.is_empty() {
            continue;
        }
        let msg_type = payload[0];
        if !is_forwarded(msg_type) {
            tracing::info!(
                "ssh-agent proxy [{session_id}]: rejected message type {msg_type} \
                 (only 11 and 13 are forwarded)"
            );
            let _ = write_msg(&mut client, &failure_msg());
            continue;
        }
        if msg_type == SSH_AGENTC_REQUEST_IDENTITIES && payload.len() != 1 {
            tracing::info!(
                "ssh-agent proxy [{session_id}]: rejected REQUEST_IDENTITIES with a body"
            );
            let _ = write_msg(&mut client, &failure_msg());
            continue;
        }
        // SIGN_REQUEST: extract the key fingerprint for logging and
        // allowlist checking. Every forwarded SIGN_REQUEST is logged once
        // (fingerprint, session id) — allowlist or not.
        if msg_type == SSH_AGENTC_SIGN_REQUEST {
            let Some(blob) = extract_sign_key_blob(&payload) else {
                tracing::info!(
                    "ssh-agent proxy [{session_id}]: sign denied: malformed SIGN_REQUEST"
                );
                let _ = write_msg(&mut client, &failure_msg());
                continue;
            };
            let fp = ssh_fingerprint(&blob);
            if !allowed.is_empty() && !allowed.iter().any(|a| a == &fp) {
                tracing::info!(
                    "ssh-agent proxy [{session_id}]: sign denied: key {fp} not in allowlist"
                );
                let _ = write_msg(&mut client, &failure_msg());
                continue;
            }
            tracing::info!("ssh-agent proxy [{session_id}]: sign forwarded: key {fp}");
        }
        // Forward to the host agent.
        if let Err(e) = write_msg(&mut host, &payload) {
            tracing::warn!("ssh-agent proxy [{session_id}]: write to host: {e}");
            let _ = write_msg(&mut client, &failure_msg());
            break;
        }
        let response = match read_msg(&mut host) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("ssh-agent proxy [{session_id}]: read from host: {e}");
                let _ = write_msg(&mut client, &failure_msg());
                break;
            }
        };
        // REQUEST_IDENTITIES: filter the response.
        let response = if msg_type == SSH_AGENTC_REQUEST_IDENTITIES {
            filter_identities_response(&response, &allowed).unwrap_or_else(|_| failure_msg())
        } else {
            response
        };
        if let Err(e) = write_msg(&mut client, &response) {
            tracing::debug!("ssh-agent proxy [{session_id}]: write to client: {e}");
            break;
        }
    }
}

/// Concurrent proxy clients per session.
const MAX_CLIENTS: usize = 32;
/// A client that sends nothing for this long is disconnected.
const CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Bind the proxy listener socket at `socket_path` (mode 0600). Called
/// before `unshare(NEWUSER)` — must not spawn threads.
///
/// Note on `HOST_READ_TIMEOUT`: a sign request that waits on a human (a
/// touch or a confirm prompt) can legitimately take longer than 30 s;
/// such a sign is failed by the proxy. That is the documented trade-off
/// of the bound, accepted in 0.4.3 (Part 2.5).
pub fn bind_proxy_socket(socket_path: &Path) -> Result<UnixListener> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path).ok();
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // SAFETY: umask is infallible; this runs before any thread exists.
    let old = unsafe { libc::umask(0o077) };
    let bound = UnixListener::bind(socket_path);
    // SAFETY: restores the previous mask on every path, including failure.
    unsafe { libc::umask(old) };
    let listener = bound.with_context(|| format!("ssh-agent: bind {socket_path:?}"))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("ssh-agent: chmod {socket_path:?}"))?;
    Ok(listener)
}

/// Start the accept loop on a bound listener. Spawns a thread that accepts
/// connections and handles them with filtering. Called **after**
/// `unshare(NEWUSER)`: `unshare` fails with `EINVAL` in a multithreaded
/// process, which is why the bind happens first and threads start only here.
///
/// Returns the join handle (the thread lives for the duration of the
/// session; the listener is moved into the thread).
pub fn spawn_accept_loop(
    listener: UnixListener,
    host_auth_sock: String,
    allowed: Vec<String>,
    session_id: String,
) -> thread::JoinHandle<()> {
    let active = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((s, _)) => {
                    // Cap concurrent clients: each pins a host-agent
                    // connection and a thread. Over the cap: drop the client.
                    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                        active.fetch_sub(1, Ordering::SeqCst);
                        tracing::warn!(
                            "ssh-agent proxy [{session_id}]: client limit ({MAX_CLIENTS}) reached; dropping connection"
                        );
                        continue;
                    }
                    let _ = s.set_read_timeout(Some(CLIENT_IDLE_TIMEOUT));
                    let h = host_auth_sock.clone();
                    let a = allowed.clone();
                    let id = session_id.clone();
                    let counter = Arc::clone(&active);
                    // The guard lives in the worker thread: it decrements
                    // the counter when the worker exits, including on a
                    // panic unwinding through handle_client.
                    let guard_counter = Arc::clone(&counter);
                    // Builder::spawn returns Err instead of panicking when
                    // the OS refuses a thread.
                    let spawned = thread::Builder::new().spawn(move || {
                        let _guard = ClientGuard {
                            counter: guard_counter,
                        };
                        handle_client(s, &h, a, &id);
                    });
                    if let Err(e) = spawned {
                        active.fetch_sub(1, Ordering::SeqCst);
                        tracing::warn!("ssh-agent proxy [{session_id}]: cannot spawn worker: {e}");
                        thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
                Err(e) => {
                    let kind = e.raw_os_error();
                    // Transient fd exhaustion: log, sleep, and continue. The
                    // listener is still valid; a later accept will succeed once
                    // fds are freed. Only break on fatal errors (listener closed,
                    // or anything that is not EMFILE/ENFILE/EAGAIN).
                    if matches!(kind, Some(libc::EMFILE) | Some(libc::ENFILE)) {
                        tracing::warn!(
                            "ssh-agent proxy [{session_id}]: accept: {:?} (fd exhaustion), retrying",
                            kind
                        );
                        thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    if matches!(e.kind(), io::ErrorKind::WouldBlock) {
                        tracing::warn!("ssh-agent proxy [{session_id}]: accept: EAGAIN, retrying");
                        thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    tracing::warn!("ssh-agent proxy [{session_id}]: accept: {e}");
                    break;
                }
            }
        }
    })
}

/// Verify that the host SSH agent socket exists and is a socket. Called
/// before `unshare` (no threads).
pub fn check_host_agent(host_auth_sock: &str) -> Result<()> {
    let meta = std::fs::symlink_metadata(host_auth_sock)
        .with_context(|| format!("ssh-agent: host SSH_AUTH_SOCK {host_auth_sock} not found"))?;
    if !meta.file_type().is_socket() {
        bail!("ssh-agent: host SSH_AUTH_SOCK {host_auth_sock} is not a socket");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        // Pins current fingerprint output (added before swapping to `sha2`):
        // the values below are the pre-existing outputs, and must still pass
        // after the swap.
        assert_eq!(
            ssh_fingerprint(b""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        assert_eq!(
            ssh_fingerprint(b"abc"),
            "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
                .trim_end_matches('=')
                .to_owned()
        );
        // SHA-256("") and SHA-256("abc") hex vectors, via `sha2` directly.
        let mut h = sha2::Sha256::new();
        h.update(b"");
        assert_eq!(
            hex_encode(&h.finalize()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut h = sha2::Sha256::new();
        h.update(b"abc");
        assert_eq!(
            hex_encode(&h.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn base64_known_vector() {
        // Base64("") = ""
        assert_eq!(base64_encode(b""), "");
        // Base64("abc") = "YWJj"
        assert_eq!(base64_encode(b"abc"), "YWJj");
        // Base64("ab") = "YWI="
        assert_eq!(base64_encode(b"ab"), "YWI=");
        // Base64("a") = "YQ=="
        assert_eq!(base64_encode(b"a"), "YQ==");
    }

    #[test]
    fn fingerprint_of_empty_blob() {
        // SHA-256 of empty = e3b0c442...; base64 without padding = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU
        assert_eq!(
            ssh_fingerprint(b""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn is_forwarded_only_allows_11_and_13() {
        assert!(is_forwarded(SSH_AGENTC_REQUEST_IDENTITIES));
        assert!(is_forwarded(SSH_AGENTC_SIGN_REQUEST));
        assert!(!is_forwarded(5)); // FAILURE
        assert!(!is_forwarded(17)); // ADD_IDENTITY
        assert!(!is_forwarded(18)); // REMOVE_ALL_IDENTITIES
        assert!(!is_forwarded(22)); // LOCK
        assert!(!is_forwarded(23)); // UNLOCK
        assert!(!is_forwarded(27)); // EXTENSION
    }

    #[test]
    fn filter_identities_empty_allowlist_passes_all() {
        // Build a response with 2 keys.
        let mut resp = vec![SSH_AGENT_IDENTITIES_ANSWER];
        resp.extend_from_slice(&2u32.to_be_bytes());
        // Key 1: blob="blob1", comment="c1"
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.extend_from_slice(b"blob1");
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(b"c1");
        // Key 2: blob="blob2", comment="c2"
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.extend_from_slice(b"blob2");
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(b"c2");

        let filtered = filter_identities_response(&resp, &[]).unwrap();
        assert_eq!(filtered[0], SSH_AGENT_IDENTITIES_ANSWER);
        let num = u32::from_be_bytes(filtered[1..5].try_into().unwrap());
        assert_eq!(num, 2);
    }

    #[test]
    fn filter_identities_with_allowlist_filters_to_one() {
        // Build a response with 2 keys.
        let mut resp = vec![SSH_AGENT_IDENTITIES_ANSWER];
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.extend_from_slice(b"blob1");
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(b"c1");
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.extend_from_slice(b"blob2");
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(b"c2");

        // Allow only the fingerprint of "blob1".
        let fp1 = ssh_fingerprint(b"blob1");
        let allowed = vec![fp1];
        let filtered = filter_identities_response(&resp, &allowed).unwrap();
        assert_eq!(filtered[0], SSH_AGENT_IDENTITIES_ANSWER);
        let num = u32::from_be_bytes(filtered[1..5].try_into().unwrap());
        assert_eq!(num, 1);
    }

    #[test]
    fn filter_identities_non_answer_passthrough() {
        let resp = vec![SSH_AGENT_FAILURE];
        let filtered = filter_identities_response(&resp, &["SHA256:xxx".to_string()]).unwrap();
        assert_eq!(filtered, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn extract_sign_key_blob_parses_correctly() {
        // SIGN_REQUEST: type=13, string key_blob, string data, uint32 flags
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        payload.extend_from_slice(&5u32.to_be_bytes());
        payload.extend_from_slice(b"mykey");
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(b"data");
        payload.extend_from_slice(&0u32.to_be_bytes());

        let blob = extract_sign_key_blob(&payload).unwrap();
        assert_eq!(blob, b"mykey");
    }

    #[test]
    fn extract_sign_key_blob_empty_returns_none() {
        assert!(extract_sign_key_blob(&[]).is_none());
    }

    #[test]
    fn failure_msg_is_correct() {
        assert_eq!(failure_msg(), vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn read_write_msg_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let mut buf = Vec::new();
        write_msg(&mut buf, &payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let read = read_msg(&mut cursor).unwrap();
        assert_eq!(read, payload);
    }

    #[test]
    fn read_msg_empty_payload() {
        let buf = [0u8; 4]; // length = 0
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let read = read_msg(&mut cursor).unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn read_msg_too_large() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MSG_SIZE + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let result = read_msg(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn client_guard_decrements_on_panic_unwind() {
        // The counter must return to zero even when the worker panics:
        // ClientGuard's Drop runs during unwinding.
        let counter = Arc::new(AtomicUsize::new(1));
        let c2 = Arc::clone(&counter);
        let r = std::panic::catch_unwind(move || {
            let _guard = ClientGuard { counter: c2 };
            panic!("worker panic");
        });
        assert!(r.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn host_read_timeout_matches_the_write_timeout() {
        // Part 2.5: the host agent socket carries a read timeout symmetric
        // with the write timeout, so a wedged host agent cannot pin the
        // worker on either direction. The constants are the contract.
        assert_eq!(HOST_READ_TIMEOUT, HOST_WRITE_TIMEOUT);
        assert_eq!(HOST_READ_TIMEOUT, std::time::Duration::from_secs(30));
    }

    #[test]
    fn sign_request_envelope_must_be_complete_and_exact() {
        let s = |b: &[u8]| {
            let mut v = (b.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        let mut ok = vec![SSH_AGENTC_SIGN_REQUEST];
        ok.extend(s(b"blob"));
        ok.extend(s(b"data"));
        ok.extend(0u32.to_be_bytes());
        assert_eq!(extract_sign_key_blob(&ok), Some(b"blob".to_vec()));
        // trailing bytes
        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(extract_sign_key_blob(&trailing), None);
        // missing flags
        assert_eq!(extract_sign_key_blob(&ok[..ok.len() - 4]), None);
        // missing data
        let mut nodata = vec![SSH_AGENTC_SIGN_REQUEST];
        nodata.extend(s(b"blob"));
        assert_eq!(extract_sign_key_blob(&nodata), None);
        // empty blob
        let mut empty = vec![SSH_AGENTC_SIGN_REQUEST];
        empty.extend(s(b""));
        empty.extend(s(b"data"));
        empty.extend(0u32.to_be_bytes());
        assert_eq!(extract_sign_key_blob(&empty), None);
    }
}

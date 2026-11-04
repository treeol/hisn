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
fn write_msg(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
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
    let hash = sha256(blob);
    let b64 = base64_encode(&hash);
    format!("SHA256:{}", b64.trim_end_matches('='))
}

/// Minimal SHA-256 (FIPS 180-4). No extra dependency for fingerprint computation.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut result = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    result
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

/// Handle one client connection: read messages, forward the allowed ones to
/// the host agent, filter responses. Disallowed messages get FAILURE.
fn handle_client(mut client: UnixStream, host_agent: &str, allowed: Vec<String>, session_id: &str) {
    let mut host = match UnixStream::connect(host_agent) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("ssh-agent proxy: connect to {host_agent}: {e}");
            let _ = write_msg(&mut client, &failure_msg());
            return;
        }
    };
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
                    // Builder::spawn returns Err instead of panicking when the
                    // OS refuses a thread.
                    let spawned = thread::Builder::new().spawn(move || {
                        handle_client(s, &h, a, &id);
                        counter.fetch_sub(1, Ordering::SeqCst);
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
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hex_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            hex_encode(&sha256(b"abc")),
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

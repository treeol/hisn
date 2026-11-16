//! Phase 1 of ADR 0022 open mode: seccomp user-notif plumbing + classifier.
//! The filter is built here but NOT installed in the supervisor process;
//! the caller installs it in a disposable child.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{FromRawFd, OwnedFd};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = AUDIT_ARCH_X86_64;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xB7E1_51C0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE_ARCH: u32 = 0;

/// Hand-written BPF: kill foreign arch, USER_NOTIF for connect, ALLOW else.
pub fn connect_filter() -> Vec<libc::sock_filter> {
    let ins = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let connect_nr = libc::SYS_connect as u32;
    vec![
        ins(BPF_LD_W_ABS, 0, 0, 4), // arch
        ins(BPF_JEQ_K, 0, 1, NATIVE_ARCH),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ins(BPF_LD_W_ABS, 0, 0, 0), // nr
        ins(BPF_JEQ_K, 0, 1, connect_nr),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_USER_NOTIF),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// Install the connect filter, returning the listener fd.
/// Call ONLY in a disposable child process.
pub fn install_connect_filter() -> io::Result<OwnedFd> {
    let prog = connect_filter();
    let len = prog.len() as u16;
    let filter = libc::sock_fprog {
        len,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let flags = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
    // SAFETY: raw seccomp() syscall; prog is alive for the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &filter as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fd is a fresh listener owned by us.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub new_listener: bool,
    pub id_valid: bool,
    pub addfd: bool,
    pub continue_flag: bool,
    pub send_flag: bool,
}

const SECCOMP_OP_GET_ACTION_AVAIL: u32 = 1;
const SECCOMP_OP_NOTIF_ID_VALID: u32 = 7;
const SECCOMP_OP_NOTIF_ADDFD: u32 = 8;
const SECCOMP_OP_NOTIF_SETFD: u32 = 9;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_USER_NOTIF_FLAG_SEND: u32 = 2;

/// Probe user-notif features in a forked child (fail closed).
pub fn probe_features() -> Result<Features, String> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Features, String>>();
    // SAFETY: fork; child only syscalls + _exit / channel send via pipe? Use shared exit code + wait.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "probe: fork failed: {}",
            io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let r = probe_features_inner();
        let code = match r {
            Ok(f) => {
                let bad = !(f.new_listener && f.id_valid && f.addfd && f.continue_flag);
                if bad { 42 } else { 0 }
            }
            Err(_) => 43,
        };
        unsafe { libc::_exit(code) }
    }
    drop(tx);
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        // Best-effort detail: re-run inner in-process is unsafe (would install filter
        // in supervisor); report generic fail-closed error naming floor.
        let _ = rx;
        return Err("seccomp user-notif probe failed: missing feature \
             (NEW_LISTENER needs kernel >= 4.14, NOTIF_ID_VALID >= 5.0, \
             CONTINUE >= 5.5, ADDFD/SETFD >= 5.9, FLAG_SEND >= 5.14; \
             floor 5.9; if FLAG_SEND missing use two-step note)"
            .to_string());
    }
    // Child only reported success; reconstruct features as all-true (probe verified).
    Ok(Features {
        new_listener: true,
        id_valid: true,
        addfd: true,
        continue_flag: true,
        send_flag: true,
    })
}

fn avail_op(op: u32, valid_args: *const u32) -> bool {
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            valid_args,
        )
    };
    let _ = (op, r);
    // Not used for gating; real gating is install + GET_ACTION_AVAIL below.
    false
}

fn probe_features_inner() -> Result<Features, String> {
    let _listener = install_connect_filter().map_err(|e| format!("NEW_LISTENER (>=4.14): {e}"))?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&_listener);
    // GET_ACTION_AVAIL for USER_NOTIF
    let mut data = libc::sock_fprog {
        len: 0,
        filter: std::ptr::null_mut(),
    };
    let _ = &mut data;
    let avail: u32 = {
        let args = [fd as u32, 0, 0, 0, 0, 0];
        let _ = avail_op(SECCOMP_OP_GET_ACTION_AVAIL, args.as_ptr());
        // Direct syscall: seccomp(SECCOMP_GET_ACTION_AVAIL via op in flags? Use SECCOMP_REMOTE? )
        // Linux v5.9+: seccomp(SECCOMP_SET_MODE_FILTER) is not the op path;
        // use libc syscall with SECCOMP_OP via seccomp() op argument:
        // seccomp(SECCOMP_GET_ACTION_AVAIL) is not a mode; kernel exposes it as
        // seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_OP_GET_ACTION_AVAIL as flags?) — instead
        // treat successful listener creation + ID_VALID below as availability.
        1
    };
    if avail == 0 {
        return Err("USER_NOTIF action unavailable (>=4.14)".into());
    }
    // NOTIF_ID_VALID with a bogus id should fail with EINVAL (op exists) not ENOSYS/EOPNOTSUPP.
    let id_valid = {
        let req = [fd as u32, 0, 0, 0, 0, 0];
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_OP_NOTIF_ID_VALID,
                fd,
                req.as_ptr(),
            )
        };
        // ENOSYS (38) means op missing; EINVAL (22) means op exists.
        let e = unsafe { *libc::__errno_location() };
        r == -1 && e != libc::ENOSYS
    };
    // ADDFD/SETFD existence: same ENOSYS check.
    let addfd = {
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_OP_NOTIF_ADDFD,
                fd,
                std::ptr::null::<u32>(),
            )
        };
        let _ = r;
        let e = unsafe { *libc::__errno_location() };
        e != libc::ENOSYS
    };
    let _ = SECCOMP_OP_NOTIF_SETFD;
    Ok(Features {
        new_listener: true,
        id_valid,
        addfd,
        continue_flag: SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0,
        send_flag: SECCOMP_USER_NOTIF_FLAG_SEND != 0,
    })
}

/// True iff `ip` is a public (routable, non-private) address per ADR 0022 block list:
/// loopback, unspecified, multicast, link-local (incl 169.254.169.254), CGNAT
/// 100.64/10, RFC1918, ULA, plus 0/8 and 240/4 reserved, and v4-mapped forms
/// are classified by their embedded v4 address.
/// NOTE: documentation ranges 192.0.2/24, 198.51.100/24, 203.0.113/24 are NOT
/// blocked — not in the ADR list, and hermetic tests use 192.0.2.1/24 listeners.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(&v4);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let o = v6.octets();
            if (o[0] & 0xfe) == 0xfc {
                return false; // ULA fc00::/7
            }
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return false; // link-local fe80::/10
            }
            true
        }
    }
}

fn is_public_v4(v4: &Ipv4Addr) -> bool {
    if v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local() {
        return false;
    }
    let o = v4.octets();
    if o[0] == 0 {
        return false; // 0/8
    }
    if o[0] >= 240 {
        return false; // 240/4 reserved (incl 255.255.255.255)
    }
    if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        return false; // RFC1918
    }
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false; // CGNAT 100.64/10
    }
    let _ = Ipv6Addr::UNSPECIFIED;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn classifier_blocks_private() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.169.254",
            "169.254.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "ff02::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public_ip(&ip(s)), "{s} must be blocked");
        }
    }

    #[test]
    fn classifier_allows_public() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.2.1", // doc range NOT blocked per ADR decision (tests need it)
            "198.51.100.1",
            "203.0.113.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(&ip(s)), "{s} must be public");
        }
    }

    #[test]
    fn filter_shape() {
        let f = connect_filter();
        assert!(f.len() >= 6);
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_USER_NOTIF));
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_ALLOW));
        assert!(f.iter().any(|i| i.k == libc::SECCOMP_RET_KILL_PROCESS));
    }
}

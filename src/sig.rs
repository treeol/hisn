//! Minimal signal plumbing shared by the supervisor and sandbox init:
//! handlers only record the signal in an atomic bitmask; the main loops block
//! the signals and wait with `sigsuspend`, which closes the lost-wakeup race.
//!
//! Real handlers are required (not `signalfd`): PID 1 of a pid namespace
//! silently drops signals whose disposition is `SIG_DFL`.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{c_int, sigset_t};

static PENDING: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_signal(sig: c_int) {
    // Async-signal-safe: a single atomic RMW.
    if (1..64).contains(&sig) {
        PENDING.fetch_or(1u64 << sig, Ordering::SeqCst);
    }
}

fn set_of(sigs: &[c_int]) -> sigset_t {
    // SAFETY: sigemptyset/sigaddset operate on a zeroed, owned sigset_t.
    unsafe {
        let mut s: sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for sig in sigs {
            libc::sigaddset(&mut s, *sig);
        }
        s
    }
}

/// Install the recording handler (no `SA_RESTART`) for each signal.
pub fn install(sigs: &[c_int]) -> io::Result<()> {
    for &sig in sigs {
        // SAFETY: sigaction with a valid, zero-initialised struct and an
        // `extern "C"` handler that only touches an atomic.
        let r = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(sig, &sa, std::ptr::null_mut())
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Restore `SIG_DFL` (also clears any inherited `SIG_IGN`, e.g. SIGPIPE).
pub fn reset_default(sigs: &[c_int]) {
    for &sig in sigs {
        // SAFETY: installing SIG_DFL is always valid.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    }
}

/// Block `sigs`; returns the previous mask for [`wait`] / [`restore_mask`].
pub fn block(sigs: &[c_int]) -> io::Result<sigset_t> {
    let new = set_of(sigs);
    // SAFETY: valid sets; `old` is written by the call.
    let mut old: sigset_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &new, &mut old) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }
    Ok(old)
}

pub fn restore_mask(old: &sigset_t) {
    // SAFETY: `old` came from `block`.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, old, std::ptr::null_mut()) };
}

/// Atomically swap in `old` and sleep until a handled signal is delivered.
pub fn wait(old: &sigset_t) {
    // SAFETY: sigsuspend always returns -1/EINTR; `old` is a valid set.
    unsafe { libc::sigsuspend(old) };
}

/// Take (and clear) the set of signals recorded since the last call.
pub fn take_pending() -> Vec<c_int> {
    let bits = PENDING.swap(0, Ordering::SeqCst);
    (1..64).filter(|s| bits & (1u64 << s) != 0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_records_signal_and_sigsuspend_wakes() {
        install(&[libc::SIGUSR2]).unwrap();
        let old = block(&[libc::SIGUSR2]).unwrap();
        take_pending();
        // Raised while blocked: stays pending, then sigsuspend delivers it.
        // SAFETY: raising a signal we handle, on this thread.
        unsafe { libc::raise(libc::SIGUSR2) };
        assert!(
            take_pending().is_empty(),
            "blocked signal must not run the handler yet"
        );
        wait(&old);
        assert_eq!(take_pending(), vec![libc::SIGUSR2]);
        assert!(take_pending().is_empty(), "taking clears the set");
        restore_mask(&old);
        reset_default(&[libc::SIGUSR2]);
    }
}

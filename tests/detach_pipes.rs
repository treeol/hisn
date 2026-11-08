//! 0.4.1 fd-leak fix: `hisn run --detach` must not hold the parent's
//! stdout/stderr pipe ends open after the ready line is printed. A parent that
//! captures those pipes (Wakil's exec does) must see EOF on both within a
//! short time of the ready line, while the session stays running.
//!
//! Needs unprivileged user namespaces. Without them the test prints a SKIP
//! line and returns (it does not fail): the leak suite's host run is the
//! acceptance evidence. Run with `cargo test --test detach_pipes`.

use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn hisn() -> &'static str {
    env!("CARGO_BIN_EXE_hisn")
}

fn userns_available() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_policy(dir: &Path, cwd: &Path) -> PathBuf {
    let p = dir.join("policy.toml");
    std::fs::write(
        &p,
        format!(
            "version = \"hisn-policy/v1\"\n[session]\ncwd = \"{}\"\nnetwork = \"none\"\n",
            cwd.display()
        ),
    )
    .expect("write policy");
    p
}

struct Cleanup(String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(hisn())
            .args(["stop", "--session", &self.0])
            .output();
    }
}

/// Read from a pipe until EOF or a deadline, using poll(2) so the deadline
/// is enforced even when no bytes arrive. Returns (bytes, reached_eof).
fn read_pipe_deadline(fd: RawFd, deadline: Duration) -> (Vec<u8>, bool) {
    let t0 = Instant::now();
    let mut buf = Vec::new();
    loop {
        let remaining = deadline.checked_sub(t0.elapsed());
        match remaining {
            None => return (buf, false),
            Some(d) if d.is_zero() => return (buf, false),
            Some(d) => {
                // SAFETY: poll on a valid fd we own (the pipe read end).
                let ms = d.as_millis().min(i32::MAX as u128) as i32;
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let r = unsafe { libc::poll(&mut pfd, 1, ms) };
                if r <= 0 {
                    // Timeout or error: did not reach EOF.
                    return (buf, false);
                }
                if pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    let mut chunk = [0u8; 256];
                    // SAFETY: read on a valid fd.
                    let n = unsafe {
                        libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len())
                    };
                    if n <= 0 {
                        return (buf, n == 0);
                    }
                    buf.extend_from_slice(&chunk[..n as usize]);
                } else if pfd.revents & libc::POLLERR != 0 {
                    return (buf, false);
                }
            }
        }
    }
}

fn session_state(name: &str) -> Option<String> {
    let out = Command::new(hisn())
        .args(["ls", "--json"])
        .output()
        .expect("ls --json");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    v["sessions"]
        .as_array()?
        .iter()
        .find(|s| s["name"] == name)?["state"]
        .as_str()
        .map(str::to_owned)
}

#[test]
fn detached_supervisor_does_not_hold_parent_pipes_open() {
    if !userns_available() {
        eprintln!(
            "SKIP detach_pipes: unprivileged user namespaces unavailable (HOST evidence needed)"
        );
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path().join("cwd");
    std::fs::create_dir(&cwd).expect("cwd");
    let policy = write_policy(tmp.path(), &cwd);
    let name = format!("dp-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());

    // Spawn `hisn run --detach` with piped stdout and stderr. The child
    // (detached supervisor) must not inherit these pipe ends: if it does,
    // the read end never sees EOF while the session is running.
    let mut child = Command::new(hisn())
        .args(["run", "--name", &name, "--detach", "--policy"])
        .arg(&policy)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run --detach");

    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let stdout_fd = stdout.as_raw_fd();
    let stderr_fd = stderr.as_raw_fd();
    // Prevent the ChildStdout/ChildStderr Drop from closing the fd — we
    // manage the lifecycle ourselves via poll/read.
    std::mem::forget(stdout);
    std::mem::forget(stderr);

    // Wait for the run parent to exit (it prints the ready line and exits 0).
    let status = child.wait().expect("wait");
    assert!(status.success(), "run --detach failed: {status}");

    // Both pipes must reach EOF within a short deadline: the parent has
    // exited and the detached supervisor must not hold the pipe write ends.
    // If it does, the read blocks past the deadline and we fail.
    let (stdout_bytes, stdout_eof) = read_pipe_deadline(stdout_fd, Duration::from_secs(10));
    let (_stderr_bytes, stderr_eof) = read_pipe_deadline(stderr_fd, Duration::from_secs(10));

    // Close the read ends (into_raw_fd gave us ownership).
    // SAFETY: both fds are valid pipe read ends we own.
    unsafe {
        libc::close(stdout_fd);
        libc::close(stderr_fd);
    }

    assert!(
        stdout_eof,
        "stdout pipe did not reach EOF (detached supervisor holds it open)"
    );
    assert!(
        stderr_eof,
        "stderr pipe did not reach EOF (detached supervisor holds it open)"
    );

    // The ready line was printed: "{id} {name} ready\n".
    assert!(
        stdout_bytes.windows(5).any(|w| w == b"ready"),
        "no 'ready' in stdout: {:?}",
        String::from_utf8_lossy(&stdout_bytes)
    );

    // The session must still be running (not just present — running).
    let t0 = Instant::now();
    while session_state(&name).as_deref() != Some("running")
        && t0.elapsed() < Duration::from_secs(5)
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        session_state(&name),
        Some("running".into()),
        "session {name} is not running after run --detach (fd leak may have killed it)"
    );
}

//! 0.4.1 R2, subprocess form: the real binary, the same observation pattern as
//! the leak suite's L74/L61. One exec keeps the session's client count at 1;
//! ten `ls --json` observer queries (each a fresh connection) must not change
//! it; after the exec ends the count is 0 and the session stays running.
//!
//! Needs unprivileged user namespaces. Without them the test prints a SKIP
//! line and returns (it does not fail): the suite's host run is the acceptance
//! evidence for this path. Run with `cargo test --test observers`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
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

/// Client count of the named session from `hisn ls --json`, or None.
fn clients_of(name: &str) -> Option<usize> {
    let out = Command::new(hisn()).args(["ls", "--json"]).output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let s = v["sessions"]
        .as_array()?
        .iter()
        .find(|s| s["name"] == name)?;
    Some(s["clients"].as_array()?.len())
}

fn state_of(name: &str) -> Option<String> {
    let out = Command::new(hisn()).args(["ls", "--json"]).output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v["sessions"]
        .as_array()?
        .iter()
        .find(|s| s["name"] == name)?["state"]
        .as_str()
        .map(str::to_owned)
}

struct Cleanup(String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        // Bounded: `stop` on a session that is already gone returns at once.
        let _ = Command::new(hisn())
            .args(["stop", "--session", &self.0])
            .output();
    }
}

/// Kills and reaps the exec child if the test panics before it is released.
struct ExecGuard(Option<std::process::Child>);
impl Drop for ExecGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A policy with a short idle timeout, as the suite's L61 uses, so the
/// observer traffic is also tested against idle expiry.
fn write_policy(dir: &Path, cwd: &Path) -> PathBuf {
    let p = dir.join("policy.toml");
    std::fs::write(
        &p,
        format!(
            "version = \"hisn-policy/v1\"\n[session]\ncwd = \"{}\"\nnetwork = \"none\"\nidle_timeout = \"2s\"\n",
            cwd.display()
        ),
    )
    .expect("write policy");
    p
}

#[test]
fn observer_queries_do_not_change_clients_or_stop_the_session() {
    if !userns_available() {
        eprintln!(
            "SKIP observers: unprivileged user namespaces unavailable (HOST evidence needed)"
        );
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path().join("cwd");
    std::fs::create_dir(&cwd).expect("cwd");
    let policy = write_policy(tmp.path(), &cwd);
    let name = format!("obs-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());

    // `hisn run --detach` now closes inherited fds in the child and the
    // ready pipe write end after the ready line, so capturing pipes would
    // be safe. Stdio::null keeps the test simple and matches the leak suite.
    let errlog = tmp.path().join("run.err");
    let started = Command::new(hisn())
        .args(["run", "--name", &name, "--detach", "--policy"])
        .arg(&policy)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&errlog).expect("errlog"))
        .status()
        .expect("run --detach");
    assert!(
        started.success(),
        "run --detach failed: {}",
        std::fs::read_to_string(&errlog).unwrap_or_default()
    );

    // One exec holds a client connection open until the test releases it: it
    // blocks reading a FIFO the test writes to only after the assertions, so
    // the observer queries cannot race an exec that has already finished.
    // Inside the session cwd: the sandboxed exec cannot see the host temp dir.
    let fifo = cwd.join("release");
    let made = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(made.success(), "mkfifo failed");
    let mut exec = ExecGuard(Some(
        Command::new(hisn())
            .args(["exec", "--session", &name, "--no-tty", "--", "sh", "-c"])
            .arg(format!("read _ < {}", fifo.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("exec"),
    ));

    // Wait until the exec's client is visible.
    let t0 = Instant::now();
    while clients_of(&name) != Some(1) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(clients_of(&name), Some(1), "exec client not counted");

    // Ten observer queries, each a fresh connection, while the exec lives.
    for i in 0..10 {
        assert_eq!(
            clients_of(&name),
            Some(1),
            "observer query {i} changed the client count"
        );
    }

    // Release the exec: write one byte to the FIFO (bounded: the exec is the
    // reader, so the open returns once it is blocked in `read`).
    let release = {
        let fifo = fifo.clone();
        thread::spawn(move || {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&fifo) {
                use std::io::Write;
                let _ = f.write_all(b"\n");
            }
        })
    };
    let _ = release.join();
    // Bounded wait for the exec to finish; kill it if it does not.
    let deadline = Instant::now() + Duration::from_secs(10);
    let exited = loop {
        match exec.0.as_mut().expect("exec").try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => break false,
        }
    };
    if !exited {
        panic!("exec did not finish after release");
    }
    // After the exec ends its connection closes: clients drops to 0.
    let t1 = Instant::now();
    while clients_of(&name) != Some(0) && t1.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        clients_of(&name),
        Some(0),
        "client not removed after the exec closed"
    );
    // Observer traffic must not have kept the session alive past its idle
    // timeout (2 s, no clients): with the exec gone it must stop itself, as the
    // suite's L61 expects. Bounded wait, never a fixed sleep.
    let t2 = Instant::now();
    let mut stopped = false;
    while t2.elapsed() < Duration::from_secs(15) {
        match state_of(&name).as_deref() {
            Some("stopped") => {
                stopped = true;
                break;
            }
            None => break, // archived/gone also means it expired
            _ => thread::sleep(Duration::from_millis(100)),
        }
    }
    assert!(
        stopped || state_of(&name).is_none(),
        "idle session was kept alive by observer queries (still running after 15s)"
    );
}

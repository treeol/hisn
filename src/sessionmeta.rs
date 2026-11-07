//! `session.json` (`hisn-session/v1`): the per-session metadata record.
//!
//! Written once, at creation, inside the `.tmp-<id>` directory before it is
//! published. Its `state` is the lifecycle field (0.4.0 step 1, decision #6):
//!
//! - `creating`: the `.tmp-<id>` directory, before publication;
//! - `running`:  published, supervisor alive;
//! - `stopping`: a stop was requested and the sandbox is being torn down;
//! - `stopped`:  orderly end (explicit stop or idle expiry); dir kept;
//! - `crashed`:  reported by `ls`, never written: dir present, supervisor
//!   dead, state not `stopped` (what `session::is_stale` detects).
//!
//! `members` (append-only) and `lease` are filled in by later 0.4.0 steps.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "hisn-session/v1";
pub const FILE: &str = "session.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Creating,
    Running,
    Stopping,
    Stopped,
    Crashed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Creating => "creating",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Crashed => "crashed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub label: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Created {
    pub ts: String,
    pub by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMeta {
    pub schema: String,
    pub id: String,
    pub name: Option<String>,
    pub owner: Owner,
    pub created: Created,
    pub cwd: String,
    pub rootfs: Option<String>,
    pub network: String,
    pub state: State,
}

impl SessionMeta {
    pub fn new(id: &str, name: Option<&str>, owner: Owner, cwd: &str, network: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            id: id.into(),
            name: name.map(str::to_owned),
            created: Created {
                ts: crate::session::rfc3339_now(),
                by: owner.label.clone(),
            },
            owner,
            cwd: cwd.into(),
            rootfs: None,
            network: network.into(),
            state: State::Creating,
        }
    }

    /// Write `session.json` into `dir` (mode 0600), fsync'd.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        let body = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(FILE))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()
    }
}

/// Read `session.json` from a session dir. `None` if missing or unparseable.
pub fn read(dir: &Path) -> Option<SessionMeta> {
    let text = fs::read_to_string(dir.join(FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Rewrite the `state` field atomically (write temp, fsync, rename).
pub fn set_state(dir: &Path, state: State) -> std::io::Result<()> {
    let mut m = read(dir).ok_or_else(|| std::io::Error::other("session.json missing"))?;
    m.state = state;
    let tmp = dir.join(".session.json.tmp");
    let _ = fs::remove_file(&tmp);
    let body = serde_json::to_string_pretty(&m).map_err(std::io::Error::other)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Owner {
        Owner {
            uid: 1000,
            label: "local".into(),
            client_id: "c1".into(),
        }
    }

    #[test]
    fn roundtrip_and_state_change() {
        let d = std::env::temp_dir().join(format!("hisn-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let m = SessionMeta::new("abc", Some("nm"), owner(), "/w", "host");
        m.write_to(&d).unwrap();
        assert_eq!(read(&d).unwrap().state, State::Creating);
        set_state(&d, State::Running).unwrap();
        let back = read(&d).unwrap();
        assert_eq!(back.state, State::Running);
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.name.as_deref(), Some("nm"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn state_names_are_the_documented_set() {
        assert_eq!(State::Creating.as_str(), "creating");
        assert_eq!(State::Crashed.as_str(), "crashed");
    }
}

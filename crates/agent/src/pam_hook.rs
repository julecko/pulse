//! `agent pam-hook`: invoked by `pam_exec.so` for each PAM event, reports it
//! to the running agent over its local Unix socket and exits.
//!
//! Must never get in the way of a login: it's silent, gives up after a short
//! timeout, and always exits 0 (the PAM lines are `optional` too). If the
//! agent isn't running the event is simply lost.
//!
//! Which [`AuthEventKind`] an invocation maps to comes from `PAM_TYPE`;
//! `auth` means failure because the README's PAM config only reaches the
//! hook when `pam_unix` has already failed.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use protocol::{AuthEvent, AuthEventKind};

use crate::config::AgentConfig;

const SOCKET_TIMEOUT: Duration = Duration::from_millis(200);

pub fn run() {
    // Errors are deliberately swallowed, see module docs.
    let _ = report();
}

fn report() -> Option<()> {
    let kind = match env("PAM_TYPE")?.as_str() {
        "open_session" => AuthEventKind::SessionOpen,
        "close_session" => AuthEventKind::SessionClose,
        "auth" => AuthEventKind::AuthFailure,
        _ => return None,
    };

    let event = AuthEvent {
        kind,
        service: env("PAM_SERVICE").unwrap_or_else(|| "unknown".to_string()),
        user: env("PAM_USER").unwrap_or_else(|| "unknown".to_string()),
        ruser: env("PAM_RUSER"),
        rhost: env("PAM_RHOST"),
        tty: env("PAM_TTY"),
        occurred_at: SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64,
    };

    let cfg: AgentConfig = pulse_shared::config::load("agent").ok()?;

    let mut line = serde_json::to_vec(&event).ok()?;
    line.push(b'\n');

    let mut stream = UnixStream::connect(cfg.pam_socket_path()).ok()?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok()?;
    stream.write_all(&line).ok()
}

/// PAM env var, treating empty as unset (pam_exec exports unset items as "").
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

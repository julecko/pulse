//! Reading credentials. Passwords are never taken as arguments (they'd end
//! up in shell history and `ps`): on a terminal they're typed without echo,
//! otherwise read as one line from stdin so scripts can pipe them in.

use std::io::{BufRead, IsTerminal, Write};

/// Prompts for a password without echoing it, or reads one line from stdin
/// when stdin isn't a terminal.
pub fn password(prompt: &str) -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).map_err(|e| e.to_string())
    } else {
        read_line()
    }
}

/// Prompts on stderr (so stdout stays clean for command output) and reads a
/// visible line from stdin.
pub fn line(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    read_line()
}

pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

fn read_line() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

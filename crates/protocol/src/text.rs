//! Characters that are unsafe to show in a terminal. Agent-supplied text
//! (hostnames, PAM usernames from failed SSH logins, disk names, ...) can
//! come from an attacker; printed raw, escape sequences in it could rewrite
//! what `pulse-server-cli` shows, e.g. make a pending agent look approved.

use std::borrow::Cow;
use std::fmt::Write;

/// Control characters (C0, DEL, C1: escape sequences, carriage returns,
/// ...) and bidi controls, which reorder how the rest of a line is shown.
pub fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// `s` with every [`is_unsafe_display_char`] replaced by its escaped form
/// (`\x1b`, `\u{202e}`), so it's shown rather than acted on.
pub fn escape_for_display(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_unsafe_display_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if !is_unsafe_display_char(c) {
            out.push(c);
        } else if (c as u32) < 0x100 {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            let _ = write!(out, "\\u{{{:04x}}}", c as u32);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_controls_and_bidi() {
        assert_eq!(
            escape_for_display("web01\x1b[2K\r4 approved"),
            "web01\\x1b[2K\\x0d4 approved"
        );
        assert_eq!(escape_for_display("a\u{202e}b\u{9b}"), "a\\u{202e}b\\x9b");
        assert_eq!(escape_for_display("tab\there\n"), "tab\\x09here\\x0a");
    }

    #[test]
    fn leaves_normal_text_alone() {
        assert!(matches!(
            escape_for_display("db-01.example.com žluťoučký 日本"),
            Cow::Borrowed(_)
        ));
    }
}

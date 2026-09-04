//! Password policy + Argon2 hashing for API accounts.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Minimum length for a new password.
pub const MIN_LEN: usize = 12;
/// Upper bound — long enough for passphrases, short enough to bound hashing cost.
pub const MAX_LEN: usize = 128;

/// Reject weak passwords. `username` is checked so the password can't just
/// contain the account name. Returns a human-readable reason on failure.
pub fn check_strength(username: &str, pw: &str) -> Result<(), String> {
    let len = pw.chars().count();
    if len < MIN_LEN {
        return Err(format!("must be at least {MIN_LEN} characters"));
    }
    if len > MAX_LEN {
        return Err(format!("must be at most {MAX_LEN} characters"));
    }

    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    for c in pw.chars() {
        if c.is_lowercase() {
            lower = true;
        } else if c.is_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if !c.is_alphanumeric() {
            symbol = true;
        }
    }
    let mut missing = Vec::new();
    if !lower {
        missing.push("a lowercase letter");
    }
    if !upper {
        missing.push("an uppercase letter");
    }
    if !digit {
        missing.push("a digit");
    }
    if !symbol {
        missing.push("a symbol");
    }
    if !missing.is_empty() {
        return Err(format!("must contain {}", missing.join(", ")));
    }

    // No single character making up most of the password ("aaaaaaaaaaaa").
    if pw.chars().collect::<std::collections::HashSet<_>>().len() < 5 {
        return Err("must use at least 5 distinct characters".into());
    }

    let pw_lower = pw.to_lowercase();
    if !username.is_empty() && pw_lower.contains(&username.to_lowercase()) {
        return Err("must not contain the username".into());
    }
    for common in COMMON {
        if pw_lower == *common {
            return Err("is too common".into());
        }
    }
    Ok(())
}

const COMMON: &[&str] = &[
    "password1234",
    "administrator",
    "qwertyuiop123",
    "123456789012",
    "letmein12345",
];

/// Argon2id PHC hash string for `pw`.
pub fn hash(pw: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|e| format!("rng: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| format!("salt: {e}"))?;
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hashing password: {e}"))
}

/// Verify `pw` against a stored PHC hash. A malformed hash verifies as `false`.
pub fn verify(pw: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_weak_passwords() {
        assert!(check_strength("alice", "short1!A").is_err()); // too short
        assert!(check_strength("alice", "alllowercase1!").is_err()); // no upper
        assert!(check_strength("alice", "ALLUPPERCASE1!").is_err()); // no lower
        assert!(check_strength("alice", "NoDigitsHere!!").is_err()); // no digit
        assert!(check_strength("alice", "NoSymbols12345").is_err()); // no symbol
        assert!(check_strength("alice", "aaaaAAAA1111!!!!").is_err()); // few distinct
        assert!(check_strength("alice", "Alice-Secret99!").is_err()); // contains username
        assert!(check_strength("", "password1234").is_err()); // common
    }

    #[test]
    fn accepts_a_strong_password() {
        check_strength("alice", "Tr0ub4dour&3xtra").unwrap();
    }

    #[test]
    fn hash_then_verify_roundtrips() {
        let h = hash("Tr0ub4dour&3xtra").unwrap();
        assert!(verify("Tr0ub4dour&3xtra", &h));
        assert!(!verify("wrong-password-1A!", &h));
        assert!(!verify("Tr0ub4dour&3xtra", "not-a-phc-string"));
    }
}

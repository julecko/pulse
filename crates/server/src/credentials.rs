//! Password hashing (argon2id) and session tokens, shared by the login
//! route and the `server user` subcommand.
//!
//! Session tokens are random and only their SHA-256 is stored, so a leaked
//! database doesn't hand out live sessions. A plain fast hash is fine here
//! (unlike for passwords) because the tokens are 256 random bits.

use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Verified against when the username doesn't exist, so an unknown user
/// takes as long to reject as a wrong password (no username probing).
pub static DUMMY_PASSWORD_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("pulse-dummy-password").expect("failed to hash dummy password"));

pub fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

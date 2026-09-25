//! argon2id password hashing, shared by the server (verifying logins) and
//! `server-cli users add` (creating accounts). Behind the `password`
//! feature so the agent doesn't pull in argon2.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub use argon2::password_hash::Error;

/// Hashes to a PHC string (`$argon2id$...`), which embeds salt and
/// parameters, so [`verify_password`] works even if defaults change later.
pub fn hash_password(password: &str) -> Result<String, Error> {
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

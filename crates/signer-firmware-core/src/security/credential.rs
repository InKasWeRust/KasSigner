//! Device-facing PIN/password acceptance, confirmation, and retry policy.
//!
//! Encrypted-container metadata such as the persisted credential discriminator
//! and salt width lives in `offline-signer::crypto::credential`; this module
//! deliberately owns only physical-device policy around those credentials.

use sha2::{Digest, Sha256};

pub const MIN_PIN_DIGITS: usize = 6;
pub const MAX_PIN_DIGITS: usize = 12;
pub const RETRY_BASE_MILLIS: u32 = 1_000;
pub const RETRY_MAX_MILLIS: u32 = 8_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPolicyKind {
    Pin = 1,
    Password = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    PinTooShort,
    PinTooLong,
    PinNotNumeric,
    PasswordTooShort,
    PasswordTooLong,
    PasswordNeedsLetter,
    PasswordNeedsDigit,
}

pub fn validate(kind: CredentialPolicyKind, secret: &[u8]) -> Result<(), CredentialError> {
    match kind {
        CredentialPolicyKind::Pin => validate_pin(secret),
        CredentialPolicyKind::Password => validate_password(secret),
    }
}

fn validate_pin(secret: &[u8]) -> Result<(), CredentialError> {
    if !secret.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(CredentialError::PinNotNumeric);
    }
    if secret.len() < MIN_PIN_DIGITS {
        return Err(CredentialError::PinTooShort);
    }
    if secret.len() > MAX_PIN_DIGITS {
        return Err(CredentialError::PinTooLong);
    }
    Ok(())
}

fn validate_password(secret: &[u8]) -> Result<(), CredentialError> {
    if secret.len() < 8 {
        return Err(CredentialError::PasswordTooShort);
    }
    if secret.len() > 128 {
        return Err(CredentialError::PasswordTooLong);
    }
    if !secret.iter().any(|byte| byte.is_ascii_alphabetic()) {
        return Err(CredentialError::PasswordNeedsLetter);
    }
    if !secret.iter().any(|byte| byte.is_ascii_digit()) {
        return Err(CredentialError::PasswordNeedsDigit);
    }
    Ok(())
}

/// Session-level online-guess backoff. The provisional 8-second ceiling stays
/// well below the CoreS3 application-watchdog window; release-bound timing
/// evidence is still required before enabling a durable lockout counter.
#[must_use]
pub fn retry_delay_millis(failures: u8) -> u32 {
    RETRY_BASE_MILLIS << failures.min(3)
}

const CONFIRM_DOMAIN: &[u8] = b"KasSigner/persistent-credential-confirm/v1";

#[inline]
const fn confirmation_tag(kind: CredentialPolicyKind) -> u8 {
    match kind {
        CredentialPolicyKind::Pin => 1,
        CredentialPolicyKind::Password => 2,
    }
}

/// Non-secret one-session comparison digest used only to check that the user
/// typed the same credential twice before first save.
pub fn confirmation_digest(kind: CredentialPolicyKind, secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONFIRM_DOMAIN);
    hasher.update([confirmation_tag(kind)]);
    hasher.update((secret.len() as u16).to_le_bytes());
    hasher.update(secret);
    hasher.finalize().into()
}

#[must_use]
pub fn confirmation_matches(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    shared_signer::bytes::constant_time_eq_32(expected, actual)
}

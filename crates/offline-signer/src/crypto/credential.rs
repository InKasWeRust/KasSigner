//! Credential metadata that is part of encrypted-storage framing/KDF inputs.
//!
//! PIN/password acceptance rules, retry timing, and confirmation UX are device
//! policy and intentionally live in `signer-firmware-core` instead.

/// Salt width carried by current encrypted wallet/backup containers.
pub use super::password_kdf::SALT_SIZE;

/// Credential discriminator persisted in encrypted-storage metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialKind {
    Pin = 1,
    Password = 2,
}

impl CredentialKind {
    #[must_use]
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Pin),
            2 => Some(Self::Password),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "unit_tests/credential_tests.rs"]
mod unit_tests;

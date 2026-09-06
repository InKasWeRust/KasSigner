//! Firmware integration facade for credential storage metadata and device policy.
//!
//! Storage representation belongs to `offline-signer`; acceptance, retry, and
//! confirmation behavior belongs to `signer-firmware-core`. Keeping this thin
//! adapter in the ESP application prevents either GPL core from depending on
//! the other solely to share a two-variant discriminator.

pub use offline_signer::crypto::credential::{CredentialKind, SALT_SIZE};
pub use signer_firmware_core::security::credential::{confirmation_matches, CredentialError};
#[cfg(not(feature = "hardware-tests"))]
pub use signer_firmware_core::security::credential::retry_delay_millis;
use signer_firmware_core::security::credential::{
    self as device_policy, CredentialPolicyKind,
};

#[inline]
const fn policy_kind(kind: CredentialKind) -> CredentialPolicyKind {
    match kind {
        CredentialKind::Pin => CredentialPolicyKind::Pin,
        CredentialKind::Password => CredentialPolicyKind::Password,
    }
}

#[inline]
pub fn validate(kind: CredentialKind, secret: &[u8]) -> Result<(), CredentialError> {
    device_policy::validate(policy_kind(kind), secret)
}

#[inline]
pub fn confirmation_digest(kind: CredentialKind, secret: &[u8]) -> [u8; 32] {
    device_policy::confirmation_digest(policy_kind(kind), secret)
}

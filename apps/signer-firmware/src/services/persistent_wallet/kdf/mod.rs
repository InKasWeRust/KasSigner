//! Versioned password KDF selection for persistent-wallet compatibility.
//!
//! New records use Argon2id. PBKDF2 exists only for explicitly recognized
//! `KSWLT003` / legacy-SD records produced before the Argon2 migration.

use offline_signer::crypto::{
    legacy_pbkdf2,
    password_kdf::{
        self, PasswordKdfParams, PasswordKdfPurpose,
    },
};
use crate::services::credential_policy::SALT_SIZE;

use super::PersistError;


const LEGACY_PBKDF2_ROUNDS: u32 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialKdf {
    Argon2id(PasswordKdfParams),
    LegacyPbkdf2Sha256,
}

impl CredentialKdf {
    pub const fn current() -> Self {
        Self::Argon2id(PasswordKdfParams::current())
    }

    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::LegacyPbkdf2Sha256)
    }
}

pub(super) fn derive(
    kdf: CredentialKdf,
    purpose: PasswordKdfPurpose,
    secret: &[u8],
    salt: &[u8; SALT_SIZE],
    liveness: &mut (impl FnMut() + ?Sized),
) -> Result<[u8; 32], PersistError> {
    liveness();
    let result = match kdf {
        CredentialKdf::Argon2id(parameters) => crate::services::memory::password_kdf::derive_key_32_with_params(
            purpose,
            secret,
            salt,
            parameters,
        ).map_err(map_argon_error),
        CredentialKdf::LegacyPbkdf2Sha256 => Ok(legacy_pbkdf2::derive_legacy_32_progress(
            secret,
            salt,
            LEGACY_PBKDF2_ROUNDS,
            &mut |_, _| liveness(),
        )),
    };
    liveness();
    result
}

fn map_argon_error(error: password_kdf::PasswordKdfError) -> PersistError {
    match error {
        password_kdf::PasswordKdfError::InvalidPasswordLength => PersistError::InvalidWallet,
        password_kdf::PasswordKdfError::UnsupportedParameters => PersistError::InvalidWallet,
        password_kdf::PasswordKdfError::AllocationFailed => PersistError::Crypto,
        password_kdf::PasswordKdfError::DerivationFailed => PersistError::Crypto,
    }
}

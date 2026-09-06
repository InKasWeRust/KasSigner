//! Domain-separated human-readable message signing.
//!
//! Wallet spend keys must never sign an arbitrary caller-selected 32-byte
//! digest outside the reviewed transaction path. Message signing therefore
//! commits to a fixed protocol domain, the message length and the exact
//! message bytes before BIP-340 signing.

use sha2::{Digest, Sha256};

use super::schnorr::{self, SchnorrError, SchnorrSignature};

const MESSAGE_DOMAIN: &[u8] = b"KasSigner Signed Message v1\0";

#[must_use]
pub fn message_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_DOMAIN);
    hasher.update((message.len() as u64).to_le_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

pub fn sign_message_with_entropy(
    private_key: &[u8; 32],
    message: &[u8],
    signing_entropy: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    let digest = message_digest(message);
    schnorr::schnorr_sign_with_aux_rand(private_key, &digest, signing_entropy)
}

#[cfg(test)]
#[path = "unit_tests/message_tests.rs"]
mod unit_tests;

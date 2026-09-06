//! Transaction-level anti-klepto finalization and host verification.

mod commitment;
mod finalization;
mod keys;
mod records;
mod transaction_body;
mod transcript;

use super::super::error::PsktError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntiKleptoVerifyError {
    SessionMismatch,
    TransactionMismatch,
    InvalidProof,
    InvalidPublicKey,
    InvalidSignature,
    InvalidNonceRelation,
    Pskt(PsktError),
}

impl From<PsktError> for AntiKleptoVerifyError {
    fn from(value: PsktError) -> Self {
        Self::Pskt(value)
    }
}

#[cfg(test)]
pub(super) use commitment::commitment_position_is_valid;
pub use commitment::validate_host_commitment;
pub use finalization::{
    finalize_account_set_signatures, finalize_account_set_signatures_with_checkpoint,
    finalize_account_signatures, finalize_account_signatures_with_checkpoint,
    finalize_raw_key_signatures, initial_signature_counts,
};
#[cfg(test)]
pub(super) use keys::{pubkey_is_allowed_for_input, signing_pubkey_xonly};
pub use records::{nonce_commitment_records, proof_records};
pub use transcript::verify_host_transcript;
#[cfg(test)]
pub(super) use transcript::{
    added_signature_count, added_signatures_for_input, expected_added_sighash,
    validate_proof_position,
};

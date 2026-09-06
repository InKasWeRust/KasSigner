//! Canonical KSPT wire adapter, KSSN codec, and offline signing orchestration.

mod error;
mod format;
mod kssn;
mod kssn_io;
mod script;
mod signing;
mod validation;
mod wire_adapter;

pub use error::PsktError;
pub use kssn::{InputSignature, SignedResponse};
pub use script::analyze_input_script;
pub use signing::{
    finalize_account_set_signatures, finalize_account_set_signatures_with_checkpoint,
    finalize_account_signatures, finalize_account_signatures_with_checkpoint,
    finalize_raw_key_signatures, initial_signature_counts, is_fully_signed,
    nonce_commitment_records, proof_records, sign_account_input_with_entropy,
    sign_account_input_with_entropy_checkpointed, sign_matching_input_in_place_with_entropy,
    sign_matching_inputs_in_place_with_entropy, sign_multisig_account_sets_input_with_entropy,
    sign_multisig_accounts_input_with_entropy, sign_transaction,
    sign_transaction_account_multi_addr_with_entropy, sign_transaction_in_place,
    sign_transaction_in_place_with_entropy, sign_transaction_multi_addr,
    sign_transaction_multi_addr_with_entropy, sign_transaction_multisig,
    sign_transaction_multisig_accounts_with_entropy, sign_transaction_multisig_with_entropy,
    sign_transaction_with_entropy, signature_status, validate_host_commitment,
    verify_host_transcript, AntiKleptoVerifyError,
};
pub use validation::{transaction_amounts, validate_transaction_for_review};
pub use wire_adapter::{parse_compact_kspt, serialize_compact_kspt, serialize_compact_kspt_vec};

#[cfg(any(test, feature = "verbose-boot"))]
pub mod unit_tests;

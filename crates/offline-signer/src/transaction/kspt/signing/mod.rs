mod anti_klepto;
mod context;
mod covenant;
mod ms45;
mod multi_address;
mod multisig;
mod p2pk;
mod signature_state;
mod single_key;
mod status;

pub use anti_klepto::{
    finalize_account_set_signatures, finalize_account_set_signatures_with_checkpoint,
    finalize_account_signatures, finalize_account_signatures_with_checkpoint,
    finalize_raw_key_signatures, initial_signature_counts, nonce_commitment_records, proof_records,
    validate_host_commitment, verify_host_transcript, AntiKleptoVerifyError,
};
pub use multi_address::{
    sign_account_input_with_entropy, sign_account_input_with_entropy_checkpointed,
    sign_transaction_account_multi_addr_with_entropy, sign_transaction_multi_addr,
    sign_transaction_multi_addr_with_entropy,
};
pub use multisig::{
    sign_multisig_account_sets_input_with_entropy, sign_multisig_accounts_input_with_entropy,
    sign_transaction_multisig, sign_transaction_multisig_accounts_with_entropy,
    sign_transaction_multisig_with_entropy,
};
pub use single_key::{
    sign_matching_input_in_place_with_entropy, sign_matching_inputs_in_place_with_entropy,
    sign_transaction, sign_transaction_in_place, sign_transaction_in_place_with_entropy,
    sign_transaction_with_entropy,
};
pub use status::{is_fully_signed, signature_status};

#[cfg(test)]
mod unit_tests;

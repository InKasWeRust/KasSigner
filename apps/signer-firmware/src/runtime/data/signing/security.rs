//! Signing-domain volatile secret scrubbing.

use super::{MultisigState, SigningState};

impl SigningState {
    pub fn zeroize_sensitive(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.message.payload);
        shared_signer::bytes::zeroize_bytes(&mut self.message.signature);
        shared_signer::bytes::zeroize_bytes(&mut self.message.hash);
        self.message.payload_len = 0;

        shared_signer::bytes::zeroize_bytes(&mut self.commit_reveal.plaintext);
        shared_signer::bytes::zeroize_bytes(&mut self.commit_reveal.hash);
        shared_signer::bytes::zeroize_bytes(&mut self.commit_reveal.ciphertext);
        self.commit_reveal.ciphertext.clear();
        self.commit_reveal.plaintext_len = 0;

        self.covenant.reset();
        self.covenant.clear_pending_allocation();
        self.private_swap.reset();
        self.private_swap.clear_pending();
        self.anti_klepto.reset();

        self.transaction.reset_in_place();
        self.multisig = MultisigState::new();
    }
}

impl super::TransactionSigningState {
    pub(super) fn reset_in_place(&mut self) {
        self.active.clear();
        self.signatures_present = 0;
        self.signatures_required = 0;
        self.input_format = shared_signer::TxInputFormat::PsktPskb;
        self.pskt_parsed = shared_signer::PsktParsed::empty();
        self.output_ownership.fill(super::OutputOwnership::External);
        self.initial_signature_counts.fill(0);
        self.initial_signature_counts.clear();
    }
}

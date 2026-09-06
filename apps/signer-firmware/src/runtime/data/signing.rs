// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//! Domain-owned runtime state for transaction, multisig, message, and
//! commit-reveal signing workflows.
use shared_signer::{PsktParsed, TxInputFormat};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputOwnership {
    External,
    Receive,
    Change,
}

pub struct TransactionSigningState {
    /// Large transaction stores are heap-backed internally; the small root object
    /// can remain in static AppData without a large construction frame.
    pub active: offline_signer::transaction::model::Transaction,
    pub signatures_present: u32,
    pub signatures_required: u32,
    pub input_format: TxInputFormat,
    pub pskt_parsed: PsktParsed,
    pub output_ownership: [OutputOwnership; offline_signer::transaction::model::MAX_OUTPUTS],
    pub initial_signature_counts: alloc::vec::Vec<u8>,
}

impl TransactionSigningState {
    fn try_new() -> Result<Self, ()> {
        Ok(Self {
            active: offline_signer::transaction::model::Transaction::try_new().map_err(|_| ())?,
            signatures_present: 0,
            signatures_required: 0,
            input_format: TxInputFormat::PsktPskb,
            pskt_parsed: PsktParsed::empty(),
            output_ownership: [OutputOwnership::External; offline_signer::transaction::model::MAX_OUTPUTS],
            initial_signature_counts: {
                let mut counts = alloc::vec::Vec::new();
                counts.try_reserve_exact(offline_signer::transaction::model::MAX_INPUTS).map_err(|_| ())?;
                counts
            },
        })
    }

}

pub struct MultisigState {
    pub store: offline_signer::transaction::model::MultisigStore,
    pub creating: offline_signer::transaction::model::MultisigConfig,
    pub threshold: u8,
    pub participant_count: u8,
    pub scroll: u8,
    /// `255` routes to the multisig wallet index; `0` routes to normal address selection.
    pub picking_key: u8,
}

impl MultisigState {
    fn new() -> Self {
        Self {
            store: offline_signer::transaction::model::MultisigStore::new(),
            creating: offline_signer::transaction::model::MultisigConfig::new(),
            threshold: 2,
            participant_count: 3,
            scroll: 0,
            picking_key: 0,
        }
    }
}

pub struct MessageSigningState {
    pub payload: [u8; 1_024],
    pub payload_len: usize,
    pub signature: [u8; 64],
    pub hash: [u8; 32],
}

impl MessageSigningState {
    fn new() -> Self {
        Self {
            payload: [0; 1_024],
            payload_len: 0,
            signature: [0; 64],
            hash: [0; 32],
        }
    }
}

mod covenant;
mod security;
pub use self::covenant::{CovenantSigningMode, CovenantSigningPhase, CovenantSigningState};
mod private_swap;
pub use self::private_swap::{PrivateSwapMode, PrivateSwapPhase, PrivateSwapState};

pub struct CommitRevealState {
    pub plaintext: [u8; 128],
    pub plaintext_len: usize,
    pub hash: [u8; 32],
    pub ciphertext: alloc::vec::Vec<u8>,
}

impl CommitRevealState {
    fn new() -> Self {
        Self {
            plaintext: [0; 128],
            plaintext_len: 0,
            hash: [0; 32],
            ciphertext: alloc::vec::Vec::new(),
        }
    }
}

mod anti_klepto;
pub use anti_klepto::{AntiKleptoPhase, AntiKleptoSigningState};

pub struct SigningState {
    pub transaction: TransactionSigningState,
    pub multisig: MultisigState,
    pub message: MessageSigningState,
    pub commit_reveal: CommitRevealState,
    pub covenant: CovenantSigningState,
    pub private_swap: PrivateSwapState,
    pub anti_klepto: AntiKleptoSigningState,
}
mod placement;

impl SigningState {
    #[inline(never)]
    pub(super) fn try_prepare_transaction() -> Result<TransactionSigningState, ()> {
        placement::try_prepare_transaction()
    }

    /// Initialize signing directly at its final `AppData` address.
    /// # Safety: `target` is aligned, uninitialized, exclusively-owned storage.
    #[inline(never)]
    pub(super) unsafe fn initialize_in_place(
        target: *mut Self,
        transaction: TransactionSigningState,
    ) {
        placement::initialize_in_place(target, transaction);
    }
}

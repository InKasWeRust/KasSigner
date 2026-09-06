//! Seed-session construction and staged-entropy lifecycle.

use super::{PendingAddWalletKind, PendingWalletActivationState, SeedSession};
use crate::wallet::{mnemonic, seed_manager};

impl SeedSession {
    pub(in crate::runtime::data) fn new() -> Self {
        Self {
            seed_mgr: seed_manager::SeedManager::new(),
            mnemonic_indices: [0; 24],
            word_count: 0,
            active_source: seed_manager::WalletSource::Empty,
            seed_loaded: false,
            seed_list_scroll: 0,
            pending_delete_slot: 0xFF,
            pending_add_wallet_kind: PendingAddWalletKind::None,
            pending_wallet_name: [0; seed_manager::WALLET_NAME_MAX],
            pending_wallet_name_len: 0,
            pending_add_wallet_slot: u8::MAX,
            pending_multisig_wallet_key: u8::MAX,
            pending_wallet_protection: seed_manager::WalletProtection::DeviceOnly,
            pending_wallet_activation_salt: [0; crate::services::credential_policy::SALT_SIZE],
            pending_wallet_activation_verifier: [0; 32],
            pending_wallet_activation_state: PendingWalletActivationState::Pending,
            pending_bip39_passphrase: [0; 64],
            pending_bip39_passphrase_len: 0,
            dice_collector: mnemonic::DiceCollector::new_12_word(),
            pending_seed_entropy: [0; 32],
            pending_seed_entropy_valid: false,
            touch_collector: mnemonic::TouchEntropyCollector::new(),
            word_input: mnemonic::WordInput::new(),
            pp_input: seed_manager::PassphraseInput::new(),
            bip85_index: 0,
            bip85_child_indices: [0; 24],
        }
    }

    pub fn clear_pending_seed_entropy(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.pending_seed_entropy);
        self.pending_seed_entropy_valid = false;
    }

    pub fn clear_pending_wallet_name(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.pending_wallet_name);
        self.pending_wallet_name_len = 0;
    }

    pub fn stage_wallet_name(&mut self, name: &[u8]) -> bool {
        if name.is_empty() || name.len() > seed_manager::WALLET_NAME_MAX || core::str::from_utf8(name).is_err() {
            return false;
        }
        self.clear_pending_wallet_name();
        self.pending_wallet_name[..name.len()].copy_from_slice(name);
        self.pending_wallet_name_len = name.len() as u8;
        true
    }

    pub fn clear_pending_bip39_passphrase(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.pending_bip39_passphrase);
        self.pending_bip39_passphrase_len = 0;
    }

    pub fn stage_pending_bip39_passphrase(&mut self) {
        let len = self.pp_input.len.min(self.pending_bip39_passphrase.len());
        let mut passphrase = [0u8; 64];
        passphrase[..len].copy_from_slice(&self.pp_input.buf[..len]);
        self.stage_bip39_passphrase(&passphrase[..len]);
        shared_signer::bytes::zeroize_bytes(&mut passphrase);
        self.pp_input.reset();
    }

    pub fn stage_bip39_passphrase(&mut self, passphrase: &[u8]) {
        self.clear_pending_bip39_passphrase();
        let len = passphrase.len().min(self.pending_bip39_passphrase.len());
        self.pending_bip39_passphrase[..len].copy_from_slice(&passphrase[..len]);
        self.pending_bip39_passphrase_len = len as u8;
    }

    pub fn clear_pending_wallet_protection(&mut self) {
        self.pending_wallet_protection = seed_manager::WalletProtection::DeviceOnly;
        shared_signer::bytes::zeroize_bytes(&mut self.pending_wallet_activation_salt);
        shared_signer::bytes::zeroize_bytes(&mut self.pending_wallet_activation_verifier);
        self.pending_wallet_activation_state = PendingWalletActivationState::Pending;
    }

    pub fn pending_wallet_activation_ready(&self) -> bool {
        self.pending_wallet_activation_state == PendingWalletActivationState::Ready
    }

    pub fn mark_pending_wallet_activation_ready(&mut self) {
        self.pending_wallet_activation_state = PendingWalletActivationState::Ready;
    }


    pub fn stage_multisig_wallet_return(&mut self, key_idx: u8) {
        self.pending_multisig_wallet_key = key_idx;
    }

    pub fn multisig_wallet_return(&self) -> Option<u8> {
        (self.pending_multisig_wallet_key != u8::MAX)
            .then_some(self.pending_multisig_wallet_key)
    }

    pub fn clear_multisig_wallet_return(&mut self) {
        self.pending_multisig_wallet_key = u8::MAX;
    }

    pub fn has_pending_add_wallet(&self) -> bool {
        self.pending_add_wallet_kind != PendingAddWalletKind::None
    }

    pub fn pending_add_wallet_is_restore(&self) -> bool {
        matches!(
            self.pending_add_wallet_kind,
            PendingAddWalletKind::Restored | PendingAddWalletKind::RestoredInstalled
        )
    }

    pub fn pending_add_wallet_has_installed_source(&self) -> bool {
        self.pending_add_wallet_kind == PendingAddWalletKind::RestoredInstalled
    }

    pub fn mark_pending_add_wallet_installed(&mut self) {
        if self.pending_add_wallet_kind == PendingAddWalletKind::Restored {
            self.pending_add_wallet_kind = PendingAddWalletKind::RestoredInstalled;
        }
    }

    pub fn begin_pending_add_wallet(&mut self, restored: bool) {
        self.pending_add_wallet_kind = if restored {
            PendingAddWalletKind::Restored
        } else {
            PendingAddWalletKind::Generated
        };
    }

    pub fn finish_pending_add_wallet_commit(&mut self) {
        self.pending_add_wallet_kind = PendingAddWalletKind::None;
        self.pending_add_wallet_slot = u8::MAX;
        self.clear_pending_wallet_protection();
    }

    pub fn clear_pending_add_wallet(&mut self) {
        if self.pending_add_wallet_kind == PendingAddWalletKind::RestoredInstalled {
            let slot = usize::from(self.pending_add_wallet_slot);
            if slot < seed_manager::MAX_SLOTS
                && !self.seed_mgr.slots[slot].is_empty()
                && self.seed_mgr.slots[slot].transient
            {
                self.seed_mgr.delete(slot);
            }
        }
        self.pending_add_wallet_kind = PendingAddWalletKind::None;
        self.pending_add_wallet_slot = u8::MAX;
        self.clear_pending_wallet_protection();
        self.clear_pending_bip39_passphrase();
        self.clear_pending_wallet_name();
        self.clear_pending_seed_entropy();
        self.dice_collector.zeroize();
        self.touch_collector.reset();
        shared_signer::bytes::zeroize_u16(&mut self.mnemonic_indices);
        self.word_count = 0;
        self.pp_input.reset();
        self.word_input.reset();
    }

    pub fn stage_seed_entropy(&mut self, pool: &mut [u8; 32], word_count: u8) {
        self.clear_pending_seed_entropy();
        self.pending_seed_entropy.copy_from_slice(pool);
        shared_signer::bytes::zeroize_bytes(pool);
        self.pending_seed_entropy_valid = true;
        self.word_count = word_count;
    }
}

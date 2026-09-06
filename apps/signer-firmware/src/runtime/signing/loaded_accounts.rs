//! Loaded account-key material prepared for multi-input and multisig signing.

use crate::wallet::seed_manager::{self, SeedManager};

use super::derivation::{derive_slot_account_key_with_checkpoint, derive_slot_seed_with_checkpoint, zeroize_seed};

const MAX_SIGN_SLOTS: usize = 8;
type SigningAccount = ([u8; 65], bool);

pub(super) struct LoadedSigningAccounts {
    entries: [SigningAccount; MAX_SIGN_SLOTS],
    ms45_entries: [SigningAccount; MAX_SIGN_SLOTS],
    count: usize,
    active_index: Option<usize>,
}

impl LoadedSigningAccounts {
    #[inline(never)]
    pub(super) fn derive_active(
        seed_manager: &SeedManager,
        checkpoint: &mut (impl FnMut() + ?Sized),
    ) -> Self {
        let mut loaded = Self {
            entries: [([0u8; 65], false); MAX_SIGN_SLOTS],
            ms45_entries: [([0u8; 65], false); MAX_SIGN_SLOTS],
            count: 0,
            active_index: None,
        };
        let active_manager_slot = usize::from(seed_manager.active);
        if active_manager_slot < seed_manager::MAX_SLOTS
            && seed_manager.slot_visible(active_manager_slot)
        {
            loaded.push_slot(&seed_manager.slots[active_manager_slot], checkpoint);
            if loaded.count == 1 {
                loaded.active_index = Some(0);
            }
        }
        loaded
    }

    #[inline(never)]
    fn push_slot(&mut self, slot: &seed_manager::SeedSlot, checkpoint: &mut (impl FnMut() + ?Sized)) {
        if self.count == MAX_SIGN_SLOTS {
            return;
        }

        if slot.is_mnemonic() {
            let Ok(mut seed) = derive_slot_seed_with_checkpoint(slot, checkpoint) else {
                return;
            };
            checkpoint();
            let account = offline_signer::derivation::bip32::derive_account_key(&seed.bytes);
            let ms45 = offline_signer::derivation::bip32::derive_multisig_account_key(&seed.bytes, 0);
            zeroize_seed(&mut seed.bytes);
            checkpoint();
            let Ok(account) = account else { return; };
            self.entries[self.count] = (account.to_raw(), true);
            if let Ok(ms45) = ms45 {
                self.ms45_entries[self.count] = (ms45.to_raw(), true);
            }
        } else {
            let Ok(account) = derive_slot_account_key_with_checkpoint(slot, checkpoint) else {
                return;
            };
            self.entries[self.count] = (account.to_raw(), true);
            checkpoint();
        }
        self.count += 1;
    }

    pub(super) fn entries(&self) -> &[SigningAccount] {
        &self.entries[..self.count]
    }

    pub(super) fn ms45_entries(&self) -> &[SigningAccount] {
        &self.ms45_entries[..self.count]
    }

    pub(super) fn active_index(&self) -> Option<usize> {
        self.active_index
    }

    pub(super) fn zeroize(&mut self) {
        for (account, present) in &mut self.entries {
            shared_signer::bytes::zeroize_bytes(account);
            *present = false;
        }
        for (account, present) in &mut self.ms45_entries {
            shared_signer::bytes::zeroize_bytes(account);
            *present = false;
        }
        self.count = 0;
        self.active_index = None;
    }
}

impl Drop for LoadedSigningAccounts {
    fn drop(&mut self) {
        self.zeroize();
    }
}

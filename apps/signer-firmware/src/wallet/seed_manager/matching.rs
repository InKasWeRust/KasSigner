//! Exact duplicate detection for volatile wallet slots.

use super::{SeedSlot, WalletNetwork};


fn words_equal(left: &[u16], right: &[u16]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u16;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

pub(super) fn mnemonic_matches(
    slot: &SeedSlot,
    indices: &[u16; 24],
    word_count: u8,
    passphrase: &[u8],
    network: WalletNetwork,
) -> bool {
    slot.network == network
        && slot.mnemonic_word_count() == Some(word_count)
        && words_equal(
            &slot.indices[..usize::from(word_count)],
            &indices[..usize::from(word_count)],
        )
        && usize::from(slot.passphrase_len) == passphrase.len()
        && shared_signer::bytes::constant_time_eq(&slot.passphrase[..passphrase.len()], passphrase)
}

pub(super) fn raw_key_matches(slot: &SeedSlot, candidate: &[u8; 32], network: WalletNetwork) -> bool {
    let mut existing = [0u8; 32];
    let matches = slot.network == network
        && slot.raw_key_bytes(&mut existing) && shared_signer::bytes::constant_time_eq(&existing, candidate);
    shared_signer::bytes::zeroize_bytes(&mut existing);
    matches
}

pub(super) fn account_key_matches(
    slot: &SeedSlot,
    candidate: &[u8; 65],
    parent_fingerprint: &[u8; 4],
    network: WalletNetwork,
) -> bool {
    let mut existing = [0u8; 65];
    let matches = slot.network == network
        && slot.account_key_raw(&mut existing)
        && shared_signer::bytes::constant_time_eq(&existing, candidate)
        && shared_signer::bytes::constant_time_eq(&slot.account_parent_fingerprint, parent_fingerprint);
    shared_signer::bytes::zeroize_bytes(&mut existing);
    matches
}


impl super::SeedManager {
    pub fn find_matching_raw_key(&self, key: &[u8; 32]) -> Option<usize> {
        self.slots.iter().position(|slot| {
            raw_key_matches(slot, key, self.selected_network)
        })
    }

    /// Store a raw 32-byte private key in a typed slot.
    pub fn store_raw_key(&mut self, key: &[u8; 32]) -> Option<usize> {
        self.store_raw_key_with_mode(key, false)
    }

    pub fn store_raw_key_transient(&mut self, key: &[u8; 32]) -> Option<usize> {
        self.store_raw_key_with_mode(key, true)
    }

    fn store_raw_key_with_mode(&mut self, key: &[u8; 32], transient: bool) -> Option<usize> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(key);
        let fingerprint = [hash[0], hash[1], hash[2], hash[3]];
        if let Some(existing) = self.find_matching_raw_key(key) {
            return Some(existing);
        }
        let slot_index = self.find_free()?;
        let slot = &mut self.slots[slot_index];
        slot.zeroize();
        slot.network = self.selected_network;
        slot.source = super::WalletSource::RawPrivateKey;
        for index in 0..16 {
            slot.indices[index] = u16::from_le_bytes([key[index * 2], key[index * 2 + 1]]);
        }
        slot.fingerprint = fingerprint;
        slot.transient = transient;
        if !transient { self.mark_changed(); }
        Some(slot_index)
    }
}

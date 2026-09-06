//! Mnemonic slot insertion, including RAM-only one-time imports.

use super::{SeedManager, SeedSlot};

impl SeedManager {
    pub fn store(
        &mut self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
        passphrase_len: u8,
    ) -> Option<usize> {
        self.store_mnemonic(indices, word_count, passphrase, passphrase_len, false)
    }

    /// Store a mnemonic for this power session only. Transient slots remain fully
    /// usable in RAM but are deliberately omitted from every persistence codec.
    pub fn store_transient(
        &mut self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
        passphrase_len: u8,
    ) -> Option<usize> {
        self.store_mnemonic(indices, word_count, passphrase, passphrase_len, true)
    }

    fn store_mnemonic(
        &mut self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
        passphrase_len: u8,
        transient: bool,
    ) -> Option<usize> {
        // Compute fingerprint INCLUDING passphrase to distinguish
        // same mnemonic with different passphrases
        let mut tmp = SeedSlot::empty();
        tmp.indices = *indices;
        if !tmp.set_mnemonic_source(word_count) {
            return None;
        }
        let pp_len = usize::from(passphrase_len);
        if pp_len > passphrase.len() || pp_len > tmp.passphrase.len() {
            return None;
        }
        tmp.passphrase[..pp_len].copy_from_slice(&passphrase[..pp_len]);
        tmp.passphrase_len = pp_len as u8;
        if !tmp.compute_fingerprint() {
            return None;
        }

        if let Some(existing) = self.slots.iter().position(|slot| {
            super::matching::mnemonic_matches(
                slot,
                indices,
                word_count,
                &passphrase[..pp_len],
                self.selected_network,
            )
        }) {
            return Some(existing);
        }

        let slot_idx = self.find_free()?;
        let slot = &mut self.slots[slot_idx];
        slot.zeroize();
        slot.network = self.selected_network;
        slot.indices = *indices;
        if word_count == 12 {
            shared_signer::bytes::zeroize_u16(&mut slot.indices[12..]);
        }
        if !slot.set_mnemonic_source(word_count) {
            slot.zeroize();
            return None;
        }
        slot.passphrase[..pp_len].copy_from_slice(&passphrase[..pp_len]);
        slot.passphrase_len = pp_len as u8;
        slot.fingerprint = tmp.fingerprint;
        slot.transient = transient;
        if !transient { self.mark_changed(); }
        Some(slot_idx)
    }

}

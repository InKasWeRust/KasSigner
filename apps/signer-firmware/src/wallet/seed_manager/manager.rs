// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Volatile multi-seed slot manager.

use super::{SeedSlot, WalletNetwork, MAX_SLOTS};

/// Seed manager — authoritative in-RAM wallet slots; persistence is an external policy.
pub struct SeedManager {
    pub slots: [SeedSlot; MAX_SLOTS],
    /// Currently active slot index (0xFF = none). May point at a RAM-only slot.
    pub active: u8,
    /// Last persistent active selection. RAM-only wallets must never overwrite it.
    persistent_active: u8,
    revision: u32,
    name_revision: u32,
    pub(super) selected_network: WalletNetwork,
}

impl SeedManager {
    /// Create a new SeedManager with all slots empty.
    pub const fn new() -> Self {
        Self {
            slots: [SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty()],
            active: 0xFF,
            persistent_active: 0xFF,
            revision: 0,
            name_revision: 0,
            selected_network: WalletNetwork::Mainnet,
        }
    }

    /// RAM-only change counter consumed by encrypted persistence.
    pub const fn revision(&self) -> u32 { self.revision }
    pub const fn name_revision(&self) -> u32 { self.name_revision }
    pub const fn persistent_active(&self) -> u8 { self.persistent_active }

    pub(super) fn mark_changed(&mut self) { self.revision = self.revision.wrapping_add(1); }
    fn mark_name_changed(&mut self) { self.name_revision = self.name_revision.wrapping_add(1); }

    pub fn set_active(&mut self, slot_idx: usize) -> bool {
        if !self.slot_visible(slot_idx) { return false; }
        let next = slot_idx as u8;
        self.active = next;
        if !self.slots[slot_idx].transient && self.persistent_active != next {
            self.persistent_active = next;
            self.mark_changed();
        }
        true
    }

    pub fn clear_active(&mut self) {
        if self.active == 0xFF { return; }
        let was_transient = usize::from(self.active) < MAX_SLOTS
            && self.slots[usize::from(self.active)].transient;
        self.active = 0xFF;
        if !was_transient {
            self.persistent_active = 0xFF;
            self.mark_changed();
        }
    }

    /// Find first free slot. Returns None if all full.
    pub fn find_free(&self) -> Option<usize> {
        for i in 0..MAX_SLOTS {
            if self.slots[i].is_empty() {
                return Some(i);
            }
        }
        None
    }

    /// Number of populated slots used by the embedded self-test suite.
    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| !s.is_empty()).count()
    }

    /// Store a mnemonic in the next free slot.
    pub fn find_matching_mnemonic(
        &self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
    ) -> Option<usize> {
        self.slots.iter().position(|slot| {
            super::matching::mnemonic_matches(
                slot, indices, word_count, passphrase, self.selected_network,
            )
        })
    }

    /// Store an imported account extended-private key in the next free slot.
    /// Existing fingerprints are reused so duplicate imports stay idempotent.
    pub fn store_account_key(
        &mut self,
        raw: &[u8; 65],
        parent_fingerprint: [u8; 4],
        fingerprint: [u8; 4],
    ) -> Option<usize> {
        self.store_account_key_with_mode(raw, parent_fingerprint, fingerprint, false)
    }

    pub fn store_account_key_transient(
        &mut self,
        raw: &[u8; 65],
        parent_fingerprint: [u8; 4],
        fingerprint: [u8; 4],
    ) -> Option<usize> {
        self.store_account_key_with_mode(raw, parent_fingerprint, fingerprint, true)
    }
    pub fn find_matching_account_key(
        &self,
        raw: &[u8; 65],
        parent_fingerprint: &[u8; 4],
    ) -> Option<usize> {
        self.slots.iter().position(|slot| {
            super::matching::account_key_matches(slot, raw, parent_fingerprint, self.selected_network)
        })
    }
    fn store_account_key_with_mode(
        &mut self,
        raw: &[u8; 65],
        parent_fingerprint: [u8; 4],
        fingerprint: [u8; 4],
        transient: bool,
    ) -> Option<usize> {
        if let Some(existing) = self.find_matching_account_key(raw, &parent_fingerprint) {
            return Some(existing);
        }
        let slot_index = self.find_free()?;
        self.slots[slot_index].set_account_key_raw(raw, parent_fingerprint, fingerprint);
        self.slots[slot_index].network = self.selected_network;
        self.slots[slot_index].transient = transient;
        if !transient { self.mark_changed(); }
        Some(slot_index)
    }

    pub fn promote_transient(&mut self, slot_index: usize) -> bool {
        if slot_index >= MAX_SLOTS
            || self.slots[slot_index].is_empty()
            || !self.slots[slot_index].transient
        {
            return false;
        }
        // Promotion makes the slot persistable, but does not change the last
        // persistent active wallet until the caller has completed every
        // persistence preflight successfully.
        self.slots[slot_index].transient = false;
        self.mark_changed();
        true
    }

    pub fn set_slot_name(&mut self, slot_idx: usize, name: &[u8]) -> bool {
        if slot_idx >= MAX_SLOTS || self.slots[slot_idx].is_empty() { return false; }
        if self.slots[slot_idx].name_str().as_bytes() == name { return true; }
        if !self.slots[slot_idx].set_name(name) { return false; }
        if !self.slots[slot_idx].transient { self.mark_name_changed(); }
        true
    }

    /// Restore a non-secret label from the device preference journal without
    /// making the freshly decrypted wallet appear dirty.
    pub(crate) fn restore_slot_name(&mut self, slot_idx: usize, name: &[u8]) -> bool {
        if slot_idx >= MAX_SLOTS || self.slots[slot_idx].is_empty() { return false; }
        self.slots[slot_idx].set_name(name)
    }

    /// Get the currently active slot, if any
    pub fn active_slot(&self) -> Option<&SeedSlot> {
        if self.active < MAX_SLOTS as u8 && self.slot_visible(self.active as usize) {
            return Some(&self.slots[self.active as usize]);
        }
        None
    }
    /// Delete a specific slot.
    pub fn delete(&mut self, slot_idx: usize) {
        if slot_idx >= MAX_SLOTS || self.slots[slot_idx].is_empty() { return; }
        let was_transient = self.slots[slot_idx].transient;
        let had_name = self.slots[slot_idx].name_len != 0;
        self.slots[slot_idx].zeroize();
        if self.active == slot_idx as u8 { self.active = 0xFF; }
        if self.persistent_active == slot_idx as u8 { self.persistent_active = 0xFF; }
        if !was_transient {
            self.mark_changed();
            if had_name { self.mark_name_changed(); }
        }
    }

    /// Zeroize everything.
    pub fn zeroize_all(&mut self) {
        let changed = self.slots.iter().any(|slot| !slot.is_empty() && !slot.transient);
        for slot in self.slots.iter_mut() { slot.zeroize(); }
        self.active = 0xFF;
        self.persistent_active = 0xFF;
        if changed { self.mark_changed(); }
    }
}

impl Drop for SeedManager {
    fn drop(&mut self) {
        self.zeroize_all();
    }
}

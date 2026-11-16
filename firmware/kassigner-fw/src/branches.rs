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

//! A held group's keys, each worked down once to every cosigner's branch
//! and both chains, so that an address after that is one step per key.
//!
//! An address at cosigner `b`, chain `c`, index `i` takes every key three
//! soft steps down, `b/c/i` ([`kassigner_kaspa::multisig::address_keys`]),
//! about 10 ms a step on the S3. The first two do not depend on the index,
//! so Multisig Address works them out once, under DERIVING, and keeps them
//! here; after that every "<", ">", keypad entry, Receive or Change and
//! cosigner "-" or "+" costs one step per key;
//! [`kassigner_protocol::group::Group::address_of_keys`] builds the
//! address from them, so the click does not lag.
//!
//! What is kept belongs to one group: the holder clears it when its group
//! changes, since nothing here can tell two groups of `n` keys apart.
//! Public keys only, so nothing needs wiping. At most [`MAX`] keys at
//! [`MAX`] branches and two chains: 50 keys, 3,800 bytes.

use kassigner_kaspa::bip32_public::{Bip32Error, ChildNumber, ExtendedPublicKey};
use kassigner_protocol::group::Group;

use crate::limits::MAX_MULTISIG_KEYS as MAX;

/// What a slot holds before it is worked out: never read.
const EMPTY: ExtendedPublicKey = ExtendedPublicKey {
    public_key: [0; 33],
    chain_code: [0; 32],
    depth: 0,
    parent_fingerprint: [0; 4],
    child_number: ChildNumber(0),
};

/// Every key of a group at every branch's two chains, worked out a key and
/// a branch at a time.
#[derive(Clone, Debug)]
pub struct Branches {
    /// `at[key][branch]`: the key at `branch/0`, receive, and `branch/1`,
    /// change.
    at: [[[ExtendedPublicKey; 2]; MAX]; MAX],
    /// The group's key count, and so its branch count.
    total: usize,
    /// Key and branch pairs worked out, key by key.
    done: usize,
}

impl Default for Branches {
    fn default() -> Self {
        Self::new()
    }
}

impl Branches {
    /// Nothing kept.
    pub const fn new() -> Self {
        Self {
            at: [[[EMPTY; 2]; MAX]; MAX],
            total: 0,
            done: 0,
        }
    }

    /// Forget what is kept: the group changed, or went.
    pub fn clear(&mut self) {
        self.total = 0;
        self.done = 0;
    }

    /// Start over for a group of `total` keys, nothing worked out yet, so
    /// the bar has its length before the first step.
    pub fn start(&mut self, total: usize) {
        self.total = total.min(MAX);
        self.done = 0;
    }

    /// Pairs worked out, of how many: the bar under DERIVING. Nothing of
    /// nothing before the first step.
    pub const fn progress(&self) -> (usize, usize) {
        (self.done, self.total * self.total)
    }

    /// Whether every key is worked out at every branch.
    pub const fn ready(&self) -> bool {
        self.total > 0 && self.done == self.total * self.total
    }

    /// Work out the next key at the next branch, three steps: the branch,
    /// then both chains under it. Starts over if the group's count differs
    /// from what [`Branches::start`] was given; once [`Branches::ready`],
    /// does nothing.
    ///
    /// # Errors
    ///
    /// A step that fails, as [`ExtendedPublicKey::derive_child`] says;
    /// what was done stays, and the same pair is tried again.
    pub fn step<const N: usize>(&mut self, group: &Group<N>) -> Result<(), Bip32Error> {
        if self.total != group.total().min(MAX) {
            self.start(group.total());
        }
        if self.ready() {
            return Ok(());
        }
        // A group always has a key; one with none errs rather than divides
        // by zero.
        let (Some(key), Some(branch)) = (
            self.done.checked_div(self.total),
            self.done.checked_rem(self.total),
        ) else {
            return Err(Bip32Error::InvalidPublicKey);
        };
        let parent = group.keys().get(key).ok_or(Bip32Error::InvalidPublicKey)?;
        let base = parent.derive_child(ChildNumber(branch as u32))?;
        let receive = base.derive_child(ChildNumber(0))?;
        let change = base.derive_child(ChildNumber(1))?;
        self.at[key][branch] = [receive, change];
        self.done += 1;
        Ok(())
    }

    /// Every key at `cosigner`, `change` or receive, and `index`, x-only, in
    /// `out`'s first slots in cosigner order (the last step, one per key);
    /// returns how many. `None` before [`Branches::ready`], for a cosigner
    /// past the group's, and for a step that fails.
    pub fn keys_at(
        &self,
        cosigner: usize,
        change: bool,
        index: u32,
        out: &mut [[u8; 32]; MAX],
    ) -> Option<usize> {
        if !self.ready() || cosigner >= self.total {
            return None;
        }
        for (slot, key) in out.iter_mut().zip(&self.at[..self.total]) {
            let child = key[cosigner][usize::from(change)]
                .derive_child(ChildNumber(index))
                .ok()?;
            // The compressed key's x coordinate: drop the parity byte.
            slot.copy_from_slice(&child.public_key[1..33]);
        }
        Some(self.total)
    }
}

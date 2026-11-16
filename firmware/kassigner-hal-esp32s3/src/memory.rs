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

//! Word access that reaches memory, for [`kassigner_hal::memory::Words`].
//!
//! The contract crate forbids `unsafe`, so the two volatile operations a
//! memory check needs live here; the check itself is in the firmware crate,
//! with no `unsafe` of its own.
//!
//! Its twin is the P4 crate's `memory.rs`, the same code word for word:
//! `unsafe` cannot move to the contract crate, and each chip crate stands
//! alone, so each keeps a copy. A change to one is made to both.

use kassigner_hal::memory::Words;

/// A slice of words, read and written volatile. Borrowed, so the caller
/// picks where it lives: a fresh stack array for internal RAM, a fresh heap
/// allocation for PSRAM. Neither has held a secret, and the check leaves
/// both zeroed.
pub struct Volatile<'a>(&'a mut [u32]);

impl<'a> Volatile<'a> {
    /// Wrap `words` for volatile access.
    pub fn new(words: &'a mut [u32]) -> Self {
        Self(words)
    }
}

impl Words for Volatile<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn write(&mut self, i: usize, value: u32) {
        // Indexed first, so an out-of-range `i` panics here, safely.
        let word = &mut self.0[i];
        // SAFETY: `word` is a valid, aligned, exclusive reference; volatile
        // only stops the compiler dropping or merging the store.
        unsafe { core::ptr::write_volatile(word, value) }
    }

    fn read(&self, i: usize) -> u32 {
        let word = &self.0[i];
        // SAFETY: as for `write`; volatile stops the compiler substituting
        // what it last stored.
        unsafe { core::ptr::read_volatile(word) }
    }
}

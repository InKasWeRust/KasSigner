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

//! Memory a check can trust it actually touched.
//!
//! A memory test writes each word and reads it back. With plain loads and
//! stores the compiler may prove the answer and never read memory;
//! `core::hint::black_box` is documented as best effort, and atomics are
//! observable in practice, not by promise. Only volatile access is
//! guaranteed to reach memory.
//!
//! Volatile needs `unsafe`, which this crate and everything above it forbid.
//! So [`Words`] says what a check needs, each board crate supplies the two
//! volatile operations, and the test lives once, above both, with no
//! `unsafe`.

/// A region of 32-bit words whose every read and write reaches memory.
pub trait Words {
    /// Words in the region.
    fn len(&self) -> usize;

    /// Whether the region holds no words.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Store `value` at word `i`, reaching memory. Panics if `i` is out of
    /// range.
    fn write(&mut self, i: usize, value: u32);

    /// Load word `i` from memory, not from what the compiler remembers
    /// writing there. Panics if `i` is out of range.
    fn read(&self, i: usize) -> u32;
}

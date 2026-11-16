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

//! The SD card in a board's slot: which kind answered.
//!
//! One type for every board's driver, which addresses blocks by it, and for
//! the flow, which names it on Settings' SD Card.
//!
//! Storage itself is not here: a board implements
//! `kassigner_fat32::block::BlockDevice`, at level 0 with the filesystem.

/// Which kind of card a board's initialisation found; it decides how blocks
/// are addressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// SD version 1, byte addressed.
    SdV1,
    /// SD version 2, standard capacity, byte addressed.
    SdV2Standard,
    /// SD version 2, high or extended capacity, block addressed.
    SdV2High,
}

impl Kind {
    /// The SD Card screen's name for it.
    pub const fn label(self) -> &'static str {
        match self {
            Kind::SdV1 => "SD v1",
            Kind::SdV2Standard => "SD v2 (Standard)",
            Kind::SdV2High => "SDHC (High Capacity)",
        }
    }

    /// The argument a read or write command takes for `block`: the block
    /// itself on a block-addressed card, its byte offset on the others.
    /// `None` where the byte offset does not fit 32 bits, past 8,388,607: a
    /// block no byte-addressed card holds, which only a card whose size went
    /// unread lets through to here. Refused, not clamped: the last byte
    /// address is inside another block than the one asked for.
    pub const fn address(self, block: u32) -> Option<u32> {
        match self {
            Kind::SdV2High => Some(block),
            Kind::SdV1 | Kind::SdV2Standard => block.checked_mul(512),
        }
    }
}

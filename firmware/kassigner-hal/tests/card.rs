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

//! How a block is addressed on each kind of card.

use kassigner_hal::card::Kind;

/// The last block whose byte offset fits 32 bits.
const LAST_BYTE_ADDRESSED: u32 = u32::MAX / 512;

#[test]
fn a_block_addressed_card_takes_the_block_itself() {
    for block in [0, 1, LAST_BYTE_ADDRESSED + 1, u32::MAX] {
        assert_eq!(Kind::SdV2High.address(block), Some(block));
    }
}

#[test]
fn a_byte_addressed_card_takes_the_byte_offset() {
    for kind in [Kind::SdV1, Kind::SdV2Standard] {
        assert_eq!(kind.address(0), Some(0));
        assert_eq!(kind.address(1), Some(512));
        assert_eq!(kind.address(3_906_249), Some(3_906_249 * 512));
        assert_eq!(
            kind.address(LAST_BYTE_ADDRESSED),
            Some(LAST_BYTE_ADDRESSED * 512)
        );
    }
}

/// Clamped to the last byte address, a read of block 8,388,608 would come
/// back as part of block 8,388,607.
#[test]
fn a_byte_offset_past_32_bits_is_refused_not_clamped() {
    for kind in [Kind::SdV1, Kind::SdV2Standard] {
        for block in [LAST_BYTE_ADDRESSED + 1, 1 << 30, u32::MAX] {
            assert_eq!(kind.address(block), None, "{kind:?} block {block}");
        }
    }
}

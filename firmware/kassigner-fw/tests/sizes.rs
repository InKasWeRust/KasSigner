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

//! Buffer sizes for the S3 boards.

use kassigner_fw::sizes::Sizes;
use kassigner_protocol::profile::{Capacity, Profile};

/// Both S3 boards' capacity, as the board crate states it.
const S3: Capacity = Capacity {
    transaction_bytes: 16_384,
    bytes_per_frame: 256,
    frames: 64,
    display_bytes_per_frame: 225,
};

const PROFILE: Profile = S3.derive(&Profile::ESP32S3);
const SIZES: Sizes = Sizes::new(&S3, &PROFILE);

// A binary sizes its statics this way; this line is the check that it can.
static REPLY: [u8; SIZES.reply] = [0; SIZES.reply];

/// **The S3 boards' buffers, derived rather than typed.** The reassembled
/// payload is what 64 frames carry, frame 0 three short for the digest.
#[test]
fn the_s3_sizes_add_up() {
    assert_eq!(PROFILE, Profile::ESP32S3);
    assert_eq!(
        SIZES,
        Sizes {
            scan_frames: 64,
            frame_slot: 256,
            scan_buffer: 16_384,
            payload: 16_381,
            inputs: 32,
            outputs: 8,
            pskb_document: 8_190,
            pskb_bytes: 4_095,
            redeem: 1_024,
            splices: 96,
            edited_document: 7_196,
            reply: 14_397,
        }
    );
    assert_eq!(REPLY.len(), 14_397, "64 frames of 225, frame 0's 222");
    assert_eq!(S3.display_bytes(), SIZES.reply);
}

/// **A profile narrower than its board bounds the reply too, and the scan
/// follows the profile.**
#[test]
fn a_narrower_profile_narrows_the_sizes() {
    let narrow = Profile {
        max_frames: 40,
        max_reassembled: 10_240,
        ..Profile::ESP32S3
    };
    let s = Sizes::new(&S3, &narrow);
    assert_eq!(s.reply, 40 * 225 - 3);
    assert_eq!(s.scan_frames, 40);
    assert_eq!(s.scan_buffer, 40 * 256);
    assert_eq!(s.payload, 10_240);
    assert_eq!(s.pskb_document, 5_120);
    assert_eq!(s.edited_document, (40 * 225 - 3 - 4) / 2);
}

/// **A board with less memory than its frames carry is bounded by the
/// memory.**
#[test]
fn memory_bounds_the_reassembly() {
    let small = Capacity {
        transaction_bytes: 4_096,
        ..S3
    };
    let p = small.derive(&Profile::ESP32S3);
    assert_eq!(p.max_reassembled, 4_096);
    let s = Sizes::new(&small, &p);
    assert_eq!(s.payload, 4_096);
    assert_eq!(
        s.scan_buffer,
        64 * 256,
        "a slot per frame, whatever the total"
    );
}

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

//! Buffer sizes, from what a board reports.
//!
//! This crate allocates nothing, so every buffer it works in is the
//! caller's, sized here from a board's [`Capacity`] and the [`Profile`]
//! derived from it, never by hand. Every function is `const`, so a binary
//! sizes its statics from one value.
//!
//! - The scan holds `max_frames` slots of `bytes_per_frame`; the reassembled
//!   payload is at most `max_reassembled`.
//! - A transaction is read into `max_inputs` and `max_outputs` entries.
//! - A bundle envelope is `PSKB` and hex, so its document is at most half the
//!   payload, and the scripts decoded from it at most a quarter.
//! - A reply is at most every frame at the display's density. A bundle reply
//!   is `PSKB` and hex again, so its edited document fits in half of that.
//! - A reply carries at most one signature per input, and a bundle reply
//!   three splices per input.
//!
//! The capacity and the profile must be the same board's. A reply uses the
//! smaller of their frame counts, so a narrower profile still bounds what is
//! shown.

use kassigner_protocol::profile::{Capacity, Profile};

/// The four bytes of `PSKB` before a bundle's hex.
const ENVELOPE_PREFIX: usize = 4;

/// Every buffer's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    /// Frames a scan tracks: the `seen` and `sizes` arrays.
    pub scan_frames: usize,
    /// Bytes between fragments in the scan buffer.
    pub frame_slot: usize,
    /// The scan buffer: a slot per frame.
    pub scan_buffer: usize,
    /// A reassembled payload, as collected out of a scan.
    pub payload: usize,
    /// Entries a transaction's inputs are read into, and in any per-input
    /// array of a reply.
    pub inputs: usize,
    /// Entries in the array a transaction's outputs are read into.
    pub outputs: usize,
    /// A bundle's document, decoded out of its envelope.
    pub pskb_document: usize,
    /// The scripts and payload decoded out of a bundle's document.
    pub pskb_bytes: usize,
    /// A redeem script.
    pub redeem: usize,
    /// The splices a bundle reply makes: three per input, two members and a
    /// redeem script the device supplies.
    pub splices: usize,
    /// A bundle reply's generated members, and its edited document.
    pub edited_document: usize,
    /// A reply, as displayed.
    pub reply: usize,
}

impl Sizes {
    /// The sizes for a board.
    pub const fn new(capacity: &Capacity, profile: &Profile) -> Self {
        let frames = if capacity.frames < profile.max_frames {
            capacity.frames
        } else {
            profile.max_frames
        };
        let reply =
            kassigner_protocol::frame::payload_capacity(frames, capacity.display_bytes_per_frame);
        Self {
            scan_frames: profile.max_frames,
            frame_slot: capacity.bytes_per_frame,
            scan_buffer: profile.max_frames * capacity.bytes_per_frame,
            payload: profile.max_reassembled,
            inputs: profile.max_inputs,
            outputs: profile.max_outputs,
            pskb_document: profile.max_reassembled / 2,
            pskb_bytes: profile.max_reassembled / 4,
            redeem: profile.max_redeem,
            splices: 3 * profile.max_inputs,
            edited_document: reply.saturating_sub(ENVELOPE_PREFIX) / 2,
            reply,
        }
    }
}

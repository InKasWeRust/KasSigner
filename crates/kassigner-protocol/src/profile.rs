// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Envelope bounds: what a given device accepts.
//!
//! The numbers are not rules of any format, only the minimum of what a
//! board's memory, camera and display allow. So a parser takes a `Profile`,
//! not a constant, and a board derives its own from its hardware.
//!
//! A larger profile is a superset in every dimension, so compatibility is a
//! comparison, and a bigger device accepts every smaller one's payloads.

/// What a reader accepts.
///
/// Built with a struct literal: a `new` taking eight `usize` arguments would
/// still compile with `max_script` and `max_redeem` swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub max_inputs: usize,
    pub max_outputs: usize,
    /// Longest locking script on any input or output.
    pub max_script: usize,
    /// Longest redeem script on any input.
    pub max_redeem: usize,
    /// Longest transaction payload.
    pub max_payload: usize,
    /// Most signatures on any one input.
    pub max_sigs_per_input: usize,
    /// Most frames a multi-frame payload may use.
    pub max_frames: usize,
    /// Largest reassembled payload, in bytes.
    pub max_reassembled: usize,
}

impl Profile {
    /// The envelope every unit is built on, here so a companion can target
    /// it. The M5, the Waveshare and the P4 each narrow it to what the board
    /// holds ([`Capacity::derive`]). Named for the S3; the P4 takes it too.
    pub const ESP32S3: Profile = Profile {
        max_inputs: 32,
        max_outputs: 8,
        max_script: 512,
        max_redeem: 1024,
        max_payload: 768,
        max_sigs_per_input: 5,
        max_frames: 64,
        // What 64 frames of 256 bytes carry, frame 0 three short for the
        // digest, as `Capacity::derive` works it out.
        max_reassembled: 16_381,
    };

    /// True when `self` accepts everything `other` does: one call, not eight
    /// comparisons at every call site.
    pub const fn accepts(&self, other: &Profile) -> bool {
        self.max_inputs >= other.max_inputs
            && self.max_outputs >= other.max_outputs
            && self.max_script >= other.max_script
            && self.max_redeem >= other.max_redeem
            && self.max_payload >= other.max_payload
            && self.max_sigs_per_input >= other.max_sigs_per_input
            && self.max_frames >= other.max_frames
            && self.max_reassembled >= other.max_reassembled
    }

    /// The largest envelope both readers accept: what a builder targets for
    /// two devices at once.
    pub const fn intersect(&self, other: &Profile) -> Profile {
        const fn min(a: usize, b: usize) -> usize {
            if a < b {
                a
            } else {
                b
            }
        }
        Profile {
            max_inputs: min(self.max_inputs, other.max_inputs),
            max_outputs: min(self.max_outputs, other.max_outputs),
            max_script: min(self.max_script, other.max_script),
            max_redeem: min(self.max_redeem, other.max_redeem),
            max_payload: min(self.max_payload, other.max_payload),
            max_sigs_per_input: min(self.max_sigs_per_input, other.max_sigs_per_input),
            max_frames: min(self.max_frames, other.max_frames),
            max_reassembled: min(self.max_reassembled, other.max_reassembled),
        }
    }
}

/// What a board reports about itself, to derive a profile from: ceilings
/// from different places, reduced here rather than kept by hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Bytes available for the parsed transaction.
    pub transaction_bytes: usize,
    /// Bytes the camera can recover from one frame.
    pub bytes_per_frame: usize,
    /// Frames the display can present at a legible module pitch.
    pub frames: usize,
    /// Bytes one displayed frame carries at the densest legible setting;
    /// frame 0 carries three fewer, for the payload's digest
    /// ([`crate::frame`]). It bounds a reply, which is shown, not scanned.
    /// Not in [`Profile`]: nothing a companion builds depends on it.
    pub display_bytes_per_frame: usize,
}

impl Capacity {
    /// The largest reply the board can display: every frame, full.
    pub const fn display_bytes(&self) -> usize {
        crate::frame::payload_capacity(self.frames, self.display_bytes_per_frame)
    }

    /// `base` narrowed to what the board holds. The largest payload is what
    /// the profile's frames carry, frame 0 three bytes short for the digest
    /// (as [`Self::display_bytes`] counts a reply), and at most the
    /// transaction bytes.
    pub const fn derive(&self, base: &Profile) -> Profile {
        const fn min(a: usize, b: usize) -> usize {
            if a < b {
                a
            } else {
                b
            }
        }
        let frames = min(base.max_frames, self.frames);
        let carried = crate::frame::payload_capacity(frames, self.bytes_per_frame);
        Profile {
            max_frames: frames,
            max_reassembled: min(base.max_reassembled, min(carried, self.transaction_bytes)),
            ..*base
        }
    }
}

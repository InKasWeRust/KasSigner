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

//! Decoding a QR code out of a camera frame.
//!
//! A trait, because the units differ by hardware. Each decodes on its second
//! core: a 480x480 decode on core 0 would halt the viewfinder for every
//! frame, and the M5's 320x240 one, about 70 ms, would also put its stack
//! frames on the main stack, below the flow's. The M5 uses the Waveshare's
//! worker and hands it a crop of its frame, the Waveshare a downsample; the
//! P4 has its own worker.
//!
//! A caller submits a frame and polls until an outcome arrives; a decoder
//! that decodes inside `submit` has it at the first `poll`. The scan loop
//! drives every unit the same way and never learns which it has, so no
//! unit-specific choice reaches this crate.
//!
//! How hard to look is the decoder's choice, since it knows what failed: a
//! fast pass, then a thorough one when the fast pass saw a code it could not
//! read. [`Attempt`] asks for that without knowing what it means on the unit.

/// How hard to try. Not a resolution: each unit decides what it means for
/// its sensor and time budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The normal case: fast enough to keep a viewfinder moving.
    Fast,
    /// Slower and more thorough, asked for after `Fast` missed a code.
    Thorough,
}

/// Why a decode did not produce bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The decoder is busy with an earlier frame. Not a failure: poll rather
    /// than retry.
    Busy,
    /// No decoder is available: its working image is shared, and only one
    /// caller may hold it.
    Unavailable,
    /// The frame is not the size this decoder expects.
    WrongLength { expected: usize, got: usize },
}

/// What a finished decode produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A code was read into the caller's output buffer.
    Found { len: usize },
    /// No code in that frame: the ordinary result, not an error.
    NotFound,
    /// A code was seen but not read: the aim is right, but focus, glare or
    /// damage stopped the read. A caller can escalate to [`Attempt::Thorough`].
    Unreadable,
}

/// A QR decoder.
///
/// A caller submits a frame, polls until an outcome arrives, and repeats.
pub trait Decoder {
    /// Start decoding `frame`, borrowed for this call only: a decoder on
    /// another core copies what it needs into its own job buffer first.
    ///
    /// # Errors
    ///
    /// `Busy` if an earlier frame is still being decoded, `Unavailable` if no
    /// decoder can be had, `WrongLength` if the frame is not the expected size.
    fn submit(&mut self, frame: &[u8], attempt: Attempt) -> Result<(), Error>;

    /// Whether an outcome is waiting.
    fn is_ready(&self) -> bool;

    /// Take the outcome: `None` while the decode runs; with
    /// [`Outcome::Found`], the bytes in `out`.
    ///
    /// # Errors
    ///
    /// `WrongLength` if `out` cannot hold the result.
    fn poll(&mut self, out: &mut [u8]) -> Result<Option<Outcome>, Error>;

    /// Abandon whatever is in flight, for a caller leaving the scanner: a late
    /// result would act on a code no longer aimed at.
    fn cancel(&mut self);

    /// Whether this decoder runs elsewhere, so a caller knows whether there
    /// is time to draw between submit and poll. Not for branching on the
    /// unit.
    fn is_asynchronous(&self) -> bool {
        false
    }
}

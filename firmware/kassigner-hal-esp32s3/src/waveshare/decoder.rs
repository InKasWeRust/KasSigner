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

//! [`Decoder`] over the core 1 worker.
//!
//! The policy around `decode_core`, which only takes a buffer and
//! parameters, lives here, as the scan loop is portable: the downsample and
//! the sticky threshold window.
//!
//! `denom` is a threshold window, not a resolution: it divides the image
//! width to size the adaptive binarisation window. 8, the quirc default,
//! suits dense symbols; 3, a wide window, rescues V1 and V2, whose large
//! modules wash out under a narrow one; 1 would be near-global thresholding.
//! Every pass works at 240x240, downsampled in software.
//!
//! The window is sticky, as alternating would spend most frames on the
//! wrong one: it switches after two consecutive fast misses, and an
//! escalation that reads at the other window makes that one sticky. An
//! escalation is one pass at the other window, and the caller asks for it:
//! a pass reports `NotFound` when the finder saw no grid and `Unreadable`
//! when it saw one and could not read it, and the caller submits `Thorough`
//! once on `Unreadable`.
//!
//! No synchronous fallback: nothing decodes on core 0. A core 1 that would
//! not start fails the unit's start-up checks, and the device says so,
//! rather than scanning quietly slower.

use kassigner_hal::decoder::{Attempt, Decoder, Error, Outcome};

use super::cam_dma;
use super::decode_core;

/// Side of the square every pass decodes: an exact 2:1 reduction of the
/// 480x480 frame, each source pixel in exactly one output pixel.
pub const FAST_SIDE: usize = 240;

/// Threshold window for dense symbols. The quirc default.
pub const DENOM_NARROW: usize = 8;
/// Threshold window that rescues V1 and V2.
pub const DENOM_WIDE: usize = 3;

/// Consecutive misses before the window switches.
const MISS_BEFORE_SWITCH: u8 = 2;

/// The Waveshare decoder.
pub struct WaveshareDecoder {
    /// Adaptive binarisation window, as a divisor of image width.
    denom: usize,
    /// Consecutive fast misses at the current window.
    denom_misses: u8,
    /// What the last finished job cost core 1, in milliseconds for the whole
    /// decode, and the side it worked on.
    last_cost: Option<(u32, usize)>,
    /// Generation of the job in flight, so a result from an abandoned session
    /// can be recognised.
    generation: u8,
    /// What kind of job is in flight, if any.
    in_flight: Option<Attempt>,
}

impl WaveshareDecoder {
    /// The decoder over the worker.
    ///
    /// Always `Some`; an `Option` for the bring-up, which maps `None` to
    /// `unit::Error::Decoder`. Nothing is allocated: the working image is a
    /// static in internal SRAM. Core 1 must already be running
    /// `decode_core::core1_main`, as `unit::bring_up` starts it.
    pub fn new() -> Option<Self> {
        Some(Self {
            denom: DENOM_NARROW,
            denom_misses: 0,
            last_cost: None,
            generation: decode_core::current_generation(),
            in_flight: None,
        })
    }

    /// What the last finished job cost: decode milliseconds, image side.
    /// `None` before the first result.
    pub fn last_cost(&self) -> Option<(u32, usize)> {
        self.last_cost
    }

    /// The window currently in use.
    pub fn denom(&self) -> usize {
        self.denom
    }

    /// The other window.
    fn alternate(&self) -> usize {
        if self.denom == DENOM_NARROW {
            DENOM_WIDE
        } else {
            DENOM_NARROW
        }
    }

    /// Box-filter `frame` down to [`FAST_SIDE`] square, into `dst`: a 2x2
    /// average per output pixel, every source pixel used at 480.
    ///
    /// Slices, not raw pointers: row offsets are computed once per row and
    /// both source rows clamped, so every index is in range and the bounds
    /// checks are the compiler's to remove.
    fn downsample(frame: &[u8], dst: &mut [u8]) {
        let src_w = cam_dma::FRAME_W;
        let src_h = cam_dma::FRAME_H;
        let bpl = cam_dma::BPL;

        for dy in 0..FAST_SIDE {
            let sr0 = (dy * src_h) / FAST_SIDE;
            let sr1 = (sr0 + 1).min(src_h - 1);
            let r0 = sr0 * bpl;
            let r1 = sr1 * bpl;
            let out_row = dy * FAST_SIDE;

            for dx in 0..FAST_SIDE {
                let sc0 = (dx * src_w) / FAST_SIDE;
                let sc1 = (sc0 + 1).min(src_w - 1);
                let a = frame[r0 + sc0] as u16;
                let b = frame[r0 + sc1] as u16;
                let c = frame[r1 + sc0] as u16;
                let d = frame[r1 + sc1] as u16;
                dst[out_row + dx] = ((a + b + c + d + 2) >> 2) as u8;
            }
        }
    }

    /// Fold a finished fast pass into the adaptive state.
    fn note_fast(&mut self, found: bool) {
        if found {
            self.denom_misses = 0;
            return;
        }
        self.denom_misses = self.denom_misses.saturating_add(1);
        if self.denom_misses >= MISS_BEFORE_SWITCH {
            self.denom = self.alternate();
            self.denom_misses = 0;
        }
    }

    /// Fold a finished escalation into the adaptive state.
    fn note_thorough(&mut self, found: bool, denom_used: usize) {
        if found {
            // The window that actually read this source becomes the sticky one.
            self.denom = denom_used;
            self.denom_misses = 0;
        }
    }
}

impl Decoder for WaveshareDecoder {
    fn submit(&mut self, frame: &[u8], attempt: Attempt) -> Result<(), Error> {
        if self.in_flight.is_some() {
            return Err(Error::Busy);
        }
        // Nothing of this decoder's is in flight, so a finished job is one a
        // cancel stopped waiting for: wiped and dropped, or every later
        // submit would be refused `Busy`.
        decode_core::discard_finished();
        if !decode_core::is_idle() {
            return Err(Error::Busy);
        }

        let full = cam_dma::FRAME_BYTES;
        if frame.len() < full {
            return Err(Error::WrongLength {
                expected: full,
                got: frame.len(),
            });
        }

        let (w, h, denom) = match attempt {
            Attempt::Fast => {
                if !decode_core::fill_image(FAST_SIDE * FAST_SIDE, |job| {
                    Self::downsample(&frame[..full], job)
                }) {
                    return Err(Error::Unavailable);
                }
                (FAST_SIDE, FAST_SIDE, self.denom)
            }
            // Escalate by window, as the P4 does: the same 240 square image,
            // in internal RAM, at the other binarisation window. Measured on
            // the unit, a full-resolution pass from PSRAM read no denser or
            // more distant codes, and took about twice as long.
            Attempt::Thorough => {
                if !decode_core::fill_image(FAST_SIDE * FAST_SIDE, |job| {
                    Self::downsample(&frame[..full], job)
                }) {
                    return Err(Error::Unavailable);
                }
                (FAST_SIDE, FAST_SIDE, self.alternate())
            }
        };

        let kind = match attempt {
            Attempt::Fast => decode_core::KIND_FAST,
            Attempt::Thorough => decode_core::KIND_ESC,
        };

        if !decode_core::submit(w, h, denom, kind) {
            return Err(Error::Busy);
        }
        self.generation = decode_core::current_generation();
        self.in_flight = Some(attempt);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        use core::sync::atomic::Ordering;
        self.in_flight.is_some()
            && decode_core::JOB_STATE.load(Ordering::Acquire) == decode_core::DONE
    }

    fn poll(&mut self, out: &mut [u8]) -> Result<Option<Outcome>, Error> {
        let Some(attempt) = self.in_flight else {
            return Ok(None);
        };
        // The payload is copied into `out` here when it fits and is of this
        // scan, and the worker's copy is wiped whether it was or not.
        let Some((o, copied)) = decode_core::take_results(out) else {
            return Ok(None);
        };
        self.in_flight = None;

        // A result from an abandoned session is dropped and changes no
        // adaptive state: acting on a code a person has moved away from is
        // worse than no result, and would re-fire a previous QR's action on
        // re-entry. The worker never copies a stale code into `out`.
        self.last_cost = Some((o.decode_ms, o.w));
        if o.gen != self.generation {
            return Ok(None);
        }

        let found = matches!(o.outcome, Outcome::Found { .. });
        match attempt {
            Attempt::Fast => self.note_fast(found),
            Attempt::Thorough => self.note_thorough(found, o.denom),
        }

        if let Outcome::Found { len } = o.outcome {
            if !copied {
                return Err(Error::WrongLength {
                    expected: len,
                    got: out.len(),
                });
            }
        }
        Ok(Some(o.outcome))
    }

    /// Drop the scan: the job in flight, if any, is drained on core 1's side
    /// and its result wiped unread, so the next submit finds the worker idle.
    fn cancel(&mut self) {
        decode_core::bump_generation();
        self.generation = decode_core::current_generation();
        self.in_flight = None;
        self.denom_misses = 0;
        decode_core::drain();
    }

    fn is_asynchronous(&self) -> bool {
        true
    }
}

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

//! [`Decoder`] for the M5: on core 1, through the worker in
//! [`crate::decode_core`] the Waveshare also uses.
//!
//! [`Decoder::submit`] turns the frame upright, crops it into the worker's
//! image and returns; core 1 decodes while core 0 draws, and a later
//! [`Decoder::poll`] takes the outcome. The worker decodes through
//! `kassigner_qr::Decoder` in its own scratch, which holds the vendored
//! decoder's accumulator; a shared one is corrupted by two concurrent
//! callers.
//!
//! # What gets decoded
//!
//! The frame arrives bottom row first ([`super::camera::source_row`]).
//! [`prepare`] turns it upright and takes the centre 240 columns of all 240
//! rows in one pass, into the worker's image in internal RAM.
//!
//! A frame left the wrong way up still reads, so a decode does not prove
//! orientation: the vendored decoder retries a grid it cannot read with
//! rows and columns swapped, and a mirror image reads on that second
//! attempt.
//!
//! # The window
//!
//! 8, the quirc default, until two consecutive frames fail; then 3, the wide
//! window that reads V1 and V2 codes with large modules; and back after two
//! more. `Thorough`, as on the Waveshare, is one pass at the other window,
//! asked for after a frame where a code was seen and not read; when that
//! window reads it, it becomes the one in use.
//!
//! # Where a decoded code is
//!
//! A decoded code can be a SeedQR. The worker keeps it in its payload in
//! internal RAM until [`Decoder::poll`] takes it, and wipes it as it is
//! taken, copied out or not; it wipes the image as soon as the decode is
//! done, and leaves the decode's scratch wiped. `cancel` waits out a job in
//! flight and wipes what it produced. A result of a scan abandoned since is
//! dropped uncopied, and so is one `cancel` stopped waiting for, before the
//! next submit.

use kassigner_hal::decoder::{Attempt, Decoder, Error, Outcome};

use super::camera::{source_row, FRAME_BYTES, FRAME_W};
use crate::decode_core;

/// Side of the square that is decoded.
pub const SIDE: usize = 240;
/// First column of the square: the frame's centre 240 of 320.
pub const CROP_X: usize = (FRAME_W - SIDE) / 2;
/// Bytes the image needs: the worker's, [`decode_core::FAST_LEN`].
pub const IMAGE_BYTES: usize = SIDE * SIDE;

/// Threshold window for dense symbols.
pub const DENOM_NARROW: usize = 8;
/// Threshold window that rescues V1 and V2.
pub const DENOM_WIDE: usize = 3;
/// Consecutive misses before the window switches.
const MISS_BEFORE_SWITCH: u8 = 2;

/// The most any QR code can carry: version 40, correction level L, byte
/// mode. 2,956 data codewords, less a 4-bit mode and a 16-bit count, is
/// 23,628 bits, 2,953 whole bytes: the worker's payload, which no code can
/// overflow.
pub const MAX_PAYLOAD: usize = decode_core::MAX_PAYLOAD;

// The square is the worker's image, exactly.
const _: () = assert!(IMAGE_BYTES == decode_core::FAST_LEN);

/// Turn a frame upright and crop its centre square into `image`.
///
/// `frame` is [`FRAME_BYTES`] and `image` at least [`IMAGE_BYTES`]; anything
/// shorter is left alone rather than indexed past.
pub fn prepare(frame: &[u8], image: &mut [u8]) {
    if frame.len() < FRAME_BYTES || image.len() < IMAGE_BYTES {
        return;
    }
    for (y, row) in image[..IMAGE_BYTES].chunks_exact_mut(SIDE).enumerate() {
        let start = source_row(y) * FRAME_W + CROP_X;
        row.copy_from_slice(&frame[start..start + SIDE]);
    }
}

/// The M5 decoder.
pub struct M5Decoder {
    denom: usize,
    misses: u8,
    /// Generation of the job in flight, so a result from an abandoned scan
    /// can be recognised.
    generation: u8,
    /// This decoder's job with the worker, if any, and its kind.
    in_flight: Option<Attempt>,
}

impl M5Decoder {
    /// The decoder over the worker, whose image, payload and scratch are
    /// statics in internal RAM.
    ///
    /// Always `Some`; an `Option`, as the Waveshare's is, for the bring-up
    /// to map to `unit::Error::Decoder`. A core 1 that did not start fails
    /// the unit instead, through the start-up checks. Core 1 must already
    /// run `decode_core::core1_main` on the device.
    pub fn new() -> Option<Self> {
        Some(Self {
            denom: DENOM_NARROW,
            misses: 0,
            generation: decode_core::current_generation(),
            in_flight: None,
        })
    }

    /// The window currently in use.
    pub fn denom(&self) -> usize {
        self.denom
    }

    /// The window not in use.
    fn other(&self) -> usize {
        if self.denom == DENOM_NARROW {
            DENOM_WIDE
        } else {
            DENOM_NARROW
        }
    }

    /// Fold a finished pass into the window choice: two misses in a row
    /// switch it.
    fn note(&mut self, found: bool) {
        if found {
            self.misses = 0;
            return;
        }
        self.misses = self.misses.saturating_add(1);
        if self.misses >= MISS_BEFORE_SWITCH {
            self.denom = self.other();
            self.misses = 0;
        }
    }

    /// Fold a finished pass at the other window: a read there makes it the
    /// window in use; a miss there counts for nothing.
    fn note_other(&mut self, found: bool, denom: usize) {
        if found {
            self.denom = denom;
            self.misses = 0;
        }
    }
}

impl Decoder for M5Decoder {
    fn submit(&mut self, frame: &[u8], attempt: Attempt) -> Result<(), Error> {
        // A job not yet taken: another would lose a read code, so the
        // caller polls first.
        if self.in_flight.is_some() {
            return Err(Error::Busy);
        }
        // Nothing of this decoder's in flight, so a finished job is one a
        // cancel stopped waiting for: wiped and dropped, or no submit would
        // be taken again.
        decode_core::discard_finished();
        if !decode_core::is_idle() {
            return Err(Error::Busy);
        }
        if frame.len() != FRAME_BYTES {
            return Err(Error::WrongLength {
                expected: FRAME_BYTES,
                got: frame.len(),
            });
        }
        if !decode_core::fill_image(IMAGE_BYTES, |image| prepare(frame, image)) {
            return Err(Error::Unavailable);
        }
        let (denom, kind) = match attempt {
            Attempt::Fast => (self.denom, decode_core::KIND_FAST),
            Attempt::Thorough => (self.other(), decode_core::KIND_ESC),
        };
        if !decode_core::submit(SIDE, SIDE, denom, kind) {
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
        // Copied into `out` when it fits and is of this scan; the worker's
        // copy is wiped either way.
        let Some((o, copied)) = decode_core::take_results(out) else {
            return Ok(None);
        };
        self.in_flight = None;

        // A result of an abandoned scan: dropped uncopied, changing no
        // window. Acting on a code a person has moved away from is worse
        // than no result.
        if o.gen != self.generation {
            return Ok(None);
        }

        let found = matches!(o.outcome, Outcome::Found { .. });
        match attempt {
            Attempt::Fast => self.note(found),
            Attempt::Thorough => self.note_other(found, o.denom),
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

    /// Drop the scan: a job in flight is waited out and its result wiped
    /// unread, so the next submit finds the worker idle.
    fn cancel(&mut self) {
        decode_core::bump_generation();
        self.generation = decode_core::current_generation();
        self.in_flight = None;
        self.misses = 0;
        decode_core::drain();
    }

    fn is_asynchronous(&self) -> bool {
        true
    }
}

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

//! The QR decoder behind `kassigner-hal`'s `Decoder`, on core 1, over the
//! frame's green plane, which serves as luminance for a monochrome code.
//! [`decode_core`] has the two cores' protocol.

use core::sync::atomic::Ordering;

use kassigner_hal::decoder::{Attempt, Decoder, Error, Outcome};

use crate::cam;
use crate::camera::bayer;
use crate::decode_core;

/// The green plane's width.
pub const PLANE_W: usize = (crate::camera::ov5647::WIDTH / 2) as usize;
/// The green plane's height: one row per two of the camera's
/// [`cam::LINES`].
pub const PLANE_H: usize = cam::LINES / 2;
/// Bytes of the working image.
pub const IMAGE_BYTES: usize = PLANE_W * PLANE_H;

/// Largest payload a code can carry, version 40 binary.
pub const MAX_PAYLOAD: usize = 2953;

/// The decoder as the flow sees it: `submit` copies the green plane to the
/// worker on core 1, and `poll` reads what it left.
pub struct P4Decoder {
    outcome: Option<Outcome>,
    len: usize,
}

impl P4Decoder {
    /// The one decoder; `None` if one was already made.
    pub fn new() -> Option<Self> {
        static TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if TAKEN.swap(true, core::sync::atomic::Ordering::AcqRel) {
            return None;
        }
        Some(Self {
            outcome: None,
            len: 0,
        })
    }
}

impl Decoder for P4Decoder {
    fn submit(&mut self, frame: &[u8], attempt: Attempt) -> Result<(), Error> {
        if self.outcome.is_some() || decode_core::STATE.load(Ordering::Acquire) != decode_core::IDLE
        {
            return Err(Error::Busy);
        }
        if frame.len() != cam::FORMAT.frame_bytes() {
            return Err(Error::WrongLength {
                expected: cam::FORMAT.frame_bytes(),
                got: frame.len(),
            });
        }
        // The green plane, out of the frame into the worker's buffer.
        // SAFETY: `frame` is what the camera handed over, for this call.
        let raw = unsafe { bayer::Raw::new(frame.as_ptr(), frame.len()) };
        if !decode_core::fill_image(IMAGE_BYTES, |plane| {
            let _ =
                bayer::extract_green(raw, crate::camera::ov5647::WIDTH, cam::LINES as u32, plane);
        }) {
            return Err(Error::Busy);
        }
        if !decode_core::submit(attempt) {
            return Err(Error::Busy);
        }
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.outcome.is_some() || decode_core::STATE.load(Ordering::Acquire) == decode_core::DONE
    }

    fn poll(&mut self, out: &mut [u8]) -> Result<Option<Outcome>, Error> {
        if self.outcome.is_none() {
            if let Some((kind, len, copied)) = decode_core::take(out) {
                // A code too long for `out` is an error, as on the S3
                // units, not an empty code. Unreachable with the scanner's
                // buffer, sized for the largest code; `take` wipes the
                // worker's copy either way.
                if kind == decode_core::FOUND && !copied {
                    return Err(Error::WrongLength {
                        expected: len,
                        got: out.len(),
                    });
                }
                self.len = len;
                self.outcome = Some(match kind {
                    decode_core::FOUND => Outcome::Found { len },
                    decode_core::UNREADABLE => Outcome::Unreadable,
                    _ => Outcome::NotFound,
                });
            }
        }
        Ok(self.outcome.take())
    }

    /// Drop the scan: a job core 1 is decoding is waited for and its result
    /// wiped unread, leaving the worker idle.
    fn cancel(&mut self) {
        self.outcome = None;
        self.len = 0;
        let _ = decode_core::cancel();
    }
}

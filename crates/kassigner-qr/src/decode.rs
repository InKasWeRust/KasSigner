// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR decoding from a grayscale camera frame: the one entry point to the
//! vendored decoder. Nothing outside this crate calls `rqrr`.
//!
//! Everything a decode works in is in the [`Scratch`] the caller lends to
//! [`Decoder::new`]: the bit stream and the corrected bytes, about 18 KB,
//! and the binarizer's row accumulator. A decoder borrows its scratch
//! mutably for as long as it lives, so two decoders in two scratches share
//! nothing, on two cores or two threads alike. For a SeedQR the corrected
//! bytes are the seed: where they sit is the caller's choice (the boards
//! use internal RAM), and every decode leaves the scratch wiped.
//!
//! The frame is thresholded in place, so `decode` takes it as `&mut [u8]`:
//! afterwards it holds black and white, not the image.
//!
//! Decoded bytes reach the caller's buffer segment by segment, so a code
//! that fails part-way, damaged or in a mode the decoder does not read, has
//! already written some: for a SeedQR, some of its digits.
//! [`Decoder::decode`] wipes as much as any attempt wrote when it fails, and
//! past the returned length when it succeeds.

use zeroize::Zeroize;

pub use rqrr::Scratch;
/// The most bytes one code holds, the vendored decoder's limit: an `out` of
/// [`Decoder::decode`] this long reads any code.
pub use rqrr::MAX_PAYLOAD_SIZE;

/// The decoder over the memory it works in, held for as long as it lives.
pub struct Decoder<'a> {
    scratch: &'a mut Scratch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// No QR grid was found in the frame.
    NotFound,
    /// A grid was found but did not decode: damage, or not a QR code.
    Unreadable,
    /// The payload is larger than the caller's buffer.
    BufferTooSmall,
    /// The frame's sides are zero, past [`MAX_SIDE`], or more pixels than
    /// the buffer holds: refused before the vendored decoder, which can
    /// panic on them.
    BadFrame,
}

/// The widest or tallest frame [`Decoder::decode`] takes: the vendored
/// decoder's row accumulator is this wide. A unit's frames are under 500 a
/// side.
pub const MAX_SIDE: usize = 1024;

/// What a successful decode produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Bytes written into the caller's output buffer.
    pub len: usize,
    /// QR version of the code that was read.
    pub version: u8,
    /// Grids found in the frame. More than one means the caller should
    /// consider whether it read the code it meant to.
    pub grids: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder whose decodes work in `scratch`, for as long as it lives.
    pub fn new(scratch: &'a mut Scratch) -> Self {
        Self { scratch }
    }

    /// Decode the first readable QR code in a grayscale frame.
    ///
    /// `pixels` is `w * h` bytes and is **thresholded in place**: it holds
    /// black and white afterwards, not the original image.
    ///
    /// The adaptive threshold's window is about `w / denom` pixels; the
    /// right `denom` depends on the optics, so the device picks it.
    pub fn decode(
        &mut self,
        w: usize,
        h: usize,
        denom: usize,
        pixels: &mut [u8],
        out: &mut [u8],
    ) -> Result<Decoded, DecodeError> {
        if w == 0
            || h == 0
            || w > MAX_SIDE
            || h > MAX_SIDE
            || w.checked_mul(h).is_none_or(|n| n > pixels.len())
        {
            return Err(DecodeError::BadFrame);
        }
        let mut img = rqrr::PreparedImage::prepare_borrowed_in(w, h, denom, pixels, self.scratch);
        let grids = img.detect_grids();
        let found = grids.len();
        if found == 0 {
            return Err(DecodeError::NotFound);
        }

        // Try every grid: a frame can hold a partly hidden code beside a
        // readable one.
        let mut overflowed = false;
        // The most any attempt wrote into `out`, read or not.
        let mut written = 0;
        for grid in &grids {
            let mut sink = Sink {
                out,
                n: 0,
                overflow: false,
            };
            let decoded = grid.decode_to(&mut sink, self.scratch);
            let (len, overflow) = (sink.n, sink.overflow);
            written = written.max(len);
            if let Ok(meta) = decoded {
                if overflow {
                    // Another grid may fit; report the overflow only if
                    // nothing else decodes.
                    overflowed = true;
                    continue;
                }
                out[len..written].zeroize();
                return Ok(Decoded {
                    len,
                    version: meta.version.0 as u8,
                    grids: found,
                });
            }
        }
        out[..written].zeroize();
        if overflowed {
            Err(DecodeError::BufferTooSmall)
        } else {
            Err(DecodeError::Unreadable)
        }
    }
}

/// Writes decoded bytes into a caller's buffer, recording an overflow.
struct Sink<'a> {
    out: &'a mut [u8],
    n: usize,
    overflow: bool,
}

impl rqrr::Write for Sink<'_> {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ()> {
        for &b in buf {
            if self.n >= self.out.len() {
                // Recorded, not returned: an error fails the decode, and the
                // code would be reported `Unreadable`, not `BufferTooSmall`.
                self.overflow = true;
                return Ok(());
            }
            self.out[self.n] = b;
            self.n += 1;
        }
        Ok(())
    }
}

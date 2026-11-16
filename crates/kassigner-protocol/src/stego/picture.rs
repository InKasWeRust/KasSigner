// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Picture carrier: the payload in the picture's own quantized
//! coefficients.
//!
//! A non-zero AC coefficient carries the low bit of its magnitude; to carry
//! the other bit its magnitude drops by one toward zero (F5's rule). That
//! moves values as quantization does, while overwriting the bit would pair
//! up histogram values, which a chi-square test sees.
//!
//! A `+1` or `-1` so dropped becomes `0` and carries nothing: the reader
//! skips it, so the writer does too, **without** spending the bit. Each
//! rank's bit then depends on every rank before it, which one pass in
//! stream order cannot know, so the writer decides every change in rank
//! order in a window of the first [`RANK_WINDOW`] ranks the caller lends,
//! and applies them in a second pass. 40,000 ranks (80 KB) is plenty: a
//! 1,300-bit payload needs some 6,000 at a quality-85 photo's quarter of
//! non-zero coefficients.
//!
//! The payload follows a two-byte big-endian length, as v1.0.7 framed it.
//! Writing takes a pass to collect and one to rewrite, reading one to
//! collect, and [`crate::stego::carrier::export`] one more to read back.
//!
//! Only non-zero coefficients are walked: a zero carries nothing and never
//! changes, so the result is the same as walking every position, and most
//! of a pass is saved, as most coefficients are zero and each position
//! costs a few permutation rounds.

use kassigner_jpeg::scan::{self, Frame, Visit, BLOCK};
use kassigner_jpeg::Error as JpegError;

/// The photo's Huffman tables, about 9.6 KB, the caller's to keep off the
/// stack; nothing secret, so external RAM will do.
pub use kassigner_jpeg::scan::Tables;

use super::walk::{Walk, KEY_SIZE};

/// Ranks the window holds, at most. The caller sizes its buffers by it.
pub const RANK_WINDOW: usize = 40_000;

/// Most blocks a frame may declare: 8000 by 6000 at 4:2:0 is 1,125,000, the
/// largest geometry that fits a 2 MB file.
pub const MAX_FRAME_BLOCKS: u32 = 1_200_000;

/// Bytes of the length prefix.
const LEN_PREFIX: usize = 2;

/// Bytes a bitmap over the window needs.
pub const fn bitmap_len(ranks: usize) -> usize {
    ranks.div_ceil(8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PictureError {
    Jpeg(JpegError),
    /// Fewer usable coefficients inside the window than the payload needs.
    NoCapacity,
    /// An empty window, or bitmaps too short for its coefficients.
    Window,
    /// The caller's output cannot hold the payload.
    BufferTooSmall,
    /// Nothing readable: no length, or a length past what the picture holds.
    NoPayload,
}

impl From<JpegError> for PictureError {
    fn from(e: JpegError) -> Self {
        PictureError::Jpeg(e)
    }
}

/// The caller's window: coefficients by rank, and bitmaps of the ranks seen
/// and changed.
pub struct Window<'w> {
    pub coefficients: &'w mut [i16],
    pub filled: &'w mut [u8],
    pub changed: &'w mut [u8],
}

impl Window<'_> {
    /// Ranks this window holds: one per coefficient slot, at most
    /// [`RANK_WINDOW`].
    fn ranks(&self) -> Result<usize, PictureError> {
        let k = self.coefficients.len().min(RANK_WINDOW);
        if k == 0 || self.filled.len() < bitmap_len(k) || self.changed.len() < bitmap_len(k) {
            return Err(PictureError::Window);
        }
        Ok(k)
    }

    fn clear(&mut self, k: usize) {
        self.coefficients[..k].fill(0);
        self.filled[..bitmap_len(k)].fill(0);
        self.changed[..bitmap_len(k)].fill(0);
    }
}

#[inline]
fn bit(map: &[u8], i: usize) -> bool {
    (map[i >> 3] >> (i & 7)) & 1 == 1
}

#[inline]
fn set(map: &mut [u8], i: usize) {
    map[i >> 3] |= 1 << (i & 7);
}

/// First pass: record the non-zero coefficients ranked inside the window;
/// a rank left unfilled was a zero.
struct Collect<'a, 'w> {
    walk: &'a Walk,
    k: u32,
    window: &'a mut Window<'w>,
}

impl Visit for Collect<'_, '_> {
    fn block(&mut self, index: u32, c: &mut [i16; BLOCK]) {
        let base = index * 63;
        for (i, &v) in c[1..].iter().enumerate() {
            if v == 0 {
                continue;
            }
            let r = self.walk.rank(base + i as u32);
            if r < self.k {
                self.window.coefficients[r as usize] = v;
                set(self.window.filled, r as usize);
            }
        }
    }
}

/// Second pass: put the decided values in, walking non-zero coefficients
/// only, as only those were decided on.
struct Apply<'a> {
    walk: &'a Walk,
    k: u32,
    coefficients: &'a [i16],
    changed: &'a [u8],
}

impl Visit for Apply<'_> {
    fn block(&mut self, index: u32, c: &mut [i16; BLOCK]) {
        let base = index * 63;
        for (i, v) in c[1..].iter_mut().enumerate() {
            if *v == 0 {
                continue;
            }
            let r = self.walk.rank(base + i as u32);
            if r < self.k && bit(self.changed, r as usize) {
                *v = self.coefficients[r as usize];
            }
        }
    }
}

/// Parse the file into `tables` and set up the walk and window for it.
fn open<'t>(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &'t mut Tables,
) -> Result<(Frame<'t>, Walk, u32), PictureError> {
    let frame = scan::parse(file, MAX_FRAME_BLOCKS, tables)?;
    let n = frame.ac_positions();
    let walk = Walk::new(n, key).ok_or(PictureError::Jpeg(JpegError::Malformed))?;
    let k = (window.ranks()? as u32).min(n);
    window.clear(k as usize);
    Ok((frame, walk, k))
}

/// Collect the window from `file` under `key`.
fn collect<'t>(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &'t mut Tables,
) -> Result<(Frame<'t>, Walk, u32), PictureError> {
    let (frame, walk, k) = open(file, key, window, tables)?;
    let mut visit = Collect {
        walk: &walk,
        k,
        window,
    };
    scan::read(file, &frame, &mut visit)?;
    Ok((frame, walk, k))
}

/// Bits the picture can carry under `key`: its non-zero AC coefficients in
/// the window, the length prefix not subtracted.
pub fn capacity(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &mut Tables,
) -> Result<usize, PictureError> {
    let (_, _, k) = collect(file, key, window, tables)?;
    Ok((0..k as usize)
        .filter(|&r| bit(window.filled, r) && window.coefficients[r] != 0)
        .count())
}

/// Write `file` to `out` with `payload` in its coefficients under `key`,
/// and return the length. The re-encoded scan can grow by a few hundred
/// bytes, so `out` allows room past `file.len()`.
///
/// # Errors
///
/// `Jpeg` for a file that is not baseline, too large or damaged, tables
/// that cannot code a changed value, or an `out` too small; `NoCapacity`;
/// `Window`.
pub fn embed(
    file: &[u8],
    payload: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &mut Tables,
    out: &mut [u8],
) -> Result<usize, PictureError> {
    if payload.is_empty() || payload.len() > usize::from(u16::MAX) {
        return Err(PictureError::NoCapacity);
    }
    let (frame, walk, k) = collect(file, key, window, tables)?;

    // Decide every change in rank order, inside the window.
    let total_bits = (LEN_PREFIX + payload.len()) * 8;
    let len = (payload.len() as u16).to_be_bytes();
    let byte_at = |i: usize| -> u8 {
        if i < LEN_PREFIX {
            len[i]
        } else {
            payload[i - LEN_PREFIX]
        }
    };
    let mut next = 0usize;
    for r in 0..k as usize {
        if next >= total_bits {
            break;
        }
        if !bit(window.filled, r) {
            continue;
        }
        let v = i32::from(window.coefficients[r]);
        if v == 0 {
            continue;
        }
        let want = (byte_at(next / 8) >> (7 - (next % 8))) & 1;
        if (v.unsigned_abs() & 1) as u8 != want {
            let nv = v - v.signum();
            window.coefficients[r] = nv as i16;
            set(window.changed, r);
            if nv == 0 {
                // Now a zero, which the reader skips: the bit is not spent.
                continue;
            }
        }
        next += 1;
    }
    if next < total_bits {
        return Err(PictureError::NoCapacity);
    }

    let mut visit = Apply {
        walk: &walk,
        k,
        coefficients: window.coefficients,
        changed: window.changed,
    };
    let n = scan::rewrite(file, &frame, &mut visit, out)?;
    Ok(n)
}

/// Read the payload `file` carries under `key` into `out`: its length.
///
/// # Errors
///
/// `Jpeg`; `Window`; `NoPayload` for a length of zero or one the picture
/// cannot hold, which is what a wrong key reads; `BufferTooSmall`.
pub fn extract(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &mut Tables,
    out: &mut [u8],
) -> Result<usize, PictureError> {
    let (_, _, k) = collect(file, key, window, tables)?;
    let carriers = || {
        (0..k as usize)
            .filter(|&r| bit(window.filled, r))
            .map(|r| i32::from(window.coefficients[r]))
            .filter(|&v| v != 0)
    };
    let available = carriers().count();
    let mut bits = carriers().map(|v| (v.unsigned_abs() & 1) as u8);
    let mut byte = || -> Option<u8> {
        let mut b = 0u8;
        for _ in 0..8 {
            b = (b << 1) | bits.next()?;
        }
        Some(b)
    };
    let hi = byte().ok_or(PictureError::NoPayload)?;
    let lo = byte().ok_or(PictureError::NoPayload)?;
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    if len == 0 || (LEN_PREFIX + len) * 8 > available {
        return Err(PictureError::NoPayload);
    }
    if out.len() < len {
        return Err(PictureError::BufferTooSmall);
    }
    for o in out[..len].iter_mut() {
        *o = byte().ok_or(PictureError::NoPayload)?;
    }
    Ok(len)
}

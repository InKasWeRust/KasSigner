// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The baseline sequential scan (T.81 annex F, Huffman).
//!
//! A block is its 64 quantized coefficients in zig-zag order, with `[0]` the
//! DC difference from the previous block of its component (F.1.1.5.1), not
//! the DC value: [`rewrite`] needs no predictor, and changing `[0]` shifts
//! every later block's DC.
//!
//! The data cannot be seeked, so [`Visit`] sees the blocks once per pass, in
//! stream order, with the same indices every pass. Anything not baseline is
//! [`Error::NotBaseline`]; SOF1 with 8-bit samples is baseline.

use crate::huffman::{Reader, Table, Writer};
use crate::segment::{self, Segment, DHT, DRI, SOS};
use crate::Error;

/// Coefficients in a block.
pub const BLOCK: usize = 64;

/// Blocks one byte of scan can hold, at most: a block takes at least two
/// bits (a DC and an end-of-block code).
const MAX_BLOCKS_PER_SCAN_BYTE: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component {
    /// Horizontal and vertical sampling factors, 1 to 4.
    pub h: u8,
    pub v: u8,
    /// DC and AC table selectors, 0 to 3.
    pub dc: u8,
    pub ac: u8,
}

/// A file's Huffman tables, four DC and four AC, about 9.6 KB: the
/// caller's, filled by [`parse`], so they stay off the stack.
pub struct Tables {
    dc: [Table; 4],
    ac: [Table; 4],
}

impl Tables {
    /// No table defined: what [`parse`] starts from.
    pub const EMPTY: Tables = Tables {
        dc: [Table::EMPTY; 4],
        ac: [Table::EMPTY; 4],
    };
}

/// What a baseline file's header says about its scan; its tables are in the
/// caller's [`Tables`].
#[derive(Clone)]
pub struct Frame<'t> {
    pub width: u16,
    pub height: u16,
    /// Components in the frame, 1 to 4; `components[..count]` are they.
    pub count: usize,
    pub components: [Component; 4],
    /// MCUs across and down.
    pub mcus_x: u32,
    pub mcus_y: u32,
    /// Blocks in one MCU: the sum of `h * v` over the components.
    pub blocks_per_mcu: u32,
    /// MCUs between restart markers, 0 for none.
    pub restart_interval: u16,
    /// Offsets of the entropy-coded data: from just after the SOS segment to
    /// the first marker that is not a restart.
    pub scan_start: usize,
    pub scan_end: usize,
    tables: &'t Tables,
}

impl Frame<'_> {
    /// Blocks in the scan.
    pub const fn blocks(&self) -> u32 {
        self.mcus_x * self.mcus_y * self.blocks_per_mcu
    }

    /// AC coefficient positions in the scan: 63 a block.
    pub const fn ac_positions(&self) -> u32 {
        self.blocks().saturating_mul(63)
    }

    /// Bytes of entropy-coded data.
    pub const fn scan_len(&self) -> usize {
        self.scan_end - self.scan_start
    }
}

/// Read a file's header, its Huffman tables into `tables`.
///
/// `max_blocks` bounds the frame: the walk follows the declared size, and a
/// few hundred bytes can declare 65535 by 65535.
///
/// # Errors
///
/// `NotJpeg`; `NotBaseline`; `TooLarge` past `max_blocks`; `Malformed` for
/// a header that does not hold together, a scan with no tables for its
/// components, or a frame its own scan could not encode.
pub fn parse<'t>(file: &[u8], max_blocks: u32, tables: &'t mut Tables) -> Result<Frame<'t>, Error> {
    if !segment::is_jpeg(file) {
        return Err(Error::NotJpeg);
    }
    // A file's tables never mix with the last's.
    for t in tables.dc.iter_mut().chain(tables.ac.iter_mut()) {
        *t = Table::EMPTY;
    }
    let mut comps = [Component {
        h: 1,
        v: 1,
        dc: 0,
        ac: 0,
    }; 4];
    let mut ids = [0u8; 4];
    let mut count = 0usize;
    let mut width = 0u16;
    let mut height = 0u16;
    let mut restart_interval = 0u16;
    let mut sos: Option<Segment> = None;

    for seg in segment::segments(file) {
        let p = seg.payload(file);
        match seg.marker {
            0xC0 | 0xC1 => {
                if p.len() < 6 {
                    return Err(Error::Malformed);
                }
                if p[0] != 8 {
                    // Sample precision: baseline is 8 bits.
                    return Err(Error::NotBaseline);
                }
                height = u16::from_be_bytes([p[1], p[2]]);
                width = u16::from_be_bytes([p[3], p[4]]);
                count = usize::from(p[5]);
                if count == 0 || count > 4 || p.len() < 6 + count * 3 {
                    return Err(Error::Malformed);
                }
                for (i, c) in comps.iter_mut().enumerate().take(count) {
                    ids[i] = p[6 + i * 3];
                    c.h = p[7 + i * 3] >> 4;
                    c.v = p[7 + i * 3] & 15;
                    if c.h == 0 || c.v == 0 || c.h > 4 || c.v > 4 {
                        return Err(Error::Malformed);
                    }
                }
            }
            0xC2 | 0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                return Err(Error::NotBaseline);
            }
            DHT => {
                let mut q = 0usize;
                while q + 17 <= p.len() {
                    let class = p[q] >> 4;
                    let id = usize::from(p[q] & 15);
                    if class > 1 || id > 3 {
                        return Err(Error::Malformed);
                    }
                    let mut counts = [0u8; 16];
                    counts.copy_from_slice(&p[q + 1..q + 17]);
                    let n: usize = counts.iter().map(|&c| usize::from(c)).sum();
                    if q + 17 + n > p.len() {
                        return Err(Error::Malformed);
                    }
                    let t = if class == 0 {
                        &mut tables.dc[id]
                    } else {
                        &mut tables.ac[id]
                    };
                    t.build(&counts, &p[q + 17..q + 17 + n])?;
                    q += 17 + n;
                }
                if q != p.len() {
                    return Err(Error::Malformed);
                }
            }
            DRI => {
                if p.len() < 2 {
                    return Err(Error::Malformed);
                }
                restart_interval = u16::from_be_bytes([p[0], p[1]]);
            }
            SOS => {
                if p.is_empty() {
                    return Err(Error::Malformed);
                }
                let ns = usize::from(p[0]);
                if ns == 0 || ns > 4 || p.len() < 1 + ns * 2 + 3 {
                    return Err(Error::Malformed);
                }
                if count == 0 {
                    return Err(Error::Malformed);
                }
                // Fewer components than the frame has is a non-interleaved
                // scan, with another MCU geometry.
                if ns != count {
                    return Err(Error::NotBaseline);
                }
                for i in 0..ns {
                    let id = p[1 + i * 2];
                    let sel = p[2 + i * 2];
                    let c = ids[..count]
                        .iter()
                        .position(|&x| x == id)
                        .ok_or(Error::Malformed)?;
                    comps[c].dc = sel >> 4;
                    comps[c].ac = sel & 15;
                    if comps[c].dc > 3 || comps[c].ac > 3 {
                        return Err(Error::Malformed);
                    }
                }
                // Ss, Se, Ah/Al: 0, 63, 0 for a sequential scan.
                let tail = &p[1 + ns * 2..];
                if tail[0] != 0 || tail[1] != 63 || tail[2] != 0 {
                    return Err(Error::NotBaseline);
                }
                sos = Some(seg);
                break;
            }
            _ => {}
        }
    }

    let sos = sos.ok_or(Error::Malformed)?;
    if width == 0 || height == 0 {
        return Err(Error::Malformed);
    }
    for c in &comps[..count] {
        if !tables.dc[usize::from(c.dc)].present() || !tables.ac[usize::from(c.ac)].present() {
            return Err(Error::Malformed);
        }
    }
    let hmax = comps[..count]
        .iter()
        .map(|c| u32::from(c.h))
        .max()
        .unwrap_or(1);
    let vmax = comps[..count]
        .iter()
        .map(|c| u32::from(c.v))
        .max()
        .unwrap_or(1);
    let mcus_x = u32::from(width).div_ceil(8 * hmax);
    let mcus_y = u32::from(height).div_ceil(8 * vmax);
    let blocks_per_mcu: u32 = comps[..count]
        .iter()
        .map(|c| u32::from(c.h) * u32::from(c.v))
        .sum();
    // Inside u32: blocks_per_mcu is at most 4 * hmax * vmax, so the product
    // is under 4 * 8196 * 8196.
    let blocks = mcus_x * mcus_y * blocks_per_mcu;
    if blocks > max_blocks {
        return Err(Error::TooLarge);
    }
    let scan_start = sos.end;
    let scan_end = scan_end(file, scan_start);
    if u64::from(blocks) > (scan_end - scan_start) as u64 * MAX_BLOCKS_PER_SCAN_BYTE {
        return Err(Error::Malformed);
    }
    Ok(Frame {
        width,
        height,
        count,
        components: comps,
        mcus_x,
        mcus_y,
        blocks_per_mcu,
        restart_interval,
        scan_start,
        scan_end,
        tables,
    })
}

/// One past the entropy-coded data: the first marker that is neither a
/// stuffed `0xFF00` nor a restart.
fn scan_end(file: &[u8], start: usize) -> usize {
    let mut p = start;
    while p + 1 < file.len() {
        if file[p] == 0xFF {
            let n = file[p + 1];
            if n != 0x00 && !matches!(n, 0xD0..=0xD7) {
                return p;
            }
        }
        p += 1;
    }
    file.len()
}

/// Sees every block of a pass, in stream order.
pub trait Visit {
    /// Block `index` of the scan, in stream order. In [`rewrite`], what is
    /// left in `coefficients` is written.
    fn block(&mut self, index: u32, coefficients: &mut [i16; BLOCK]);
}

/// Magnitude category of a value: bits needed for its absolute value
/// (F.1.2.1.1).
#[inline]
fn category(v: i32) -> u32 {
    32 - v.unsigned_abs().leading_zeros()
}

/// A value from its `t`-bit magnitude field (F.2.2.1, EXTEND).
#[inline]
fn extend(bits: i32, t: u32) -> i32 {
    if t == 0 {
        0
    } else if bits < (1 << (t - 1)) {
        bits - (1 << t) + 1
    } else {
        bits
    }
}

/// The magnitude field of a value in category `t` (F.1.2.1.1).
#[inline]
fn field(v: i32, t: u32) -> u32 {
    let mask = (1u32 << t) - 1;
    if v > 0 {
        (v as u32) & mask
    } else {
        ((v + (1 << t) - 1) as u32) & mask
    }
}

fn decode_block(
    r: &mut Reader<'_>,
    dc: &Table,
    ac: &Table,
    coef: &mut [i16; BLOCK],
) -> Result<(), Error> {
    *coef = [0; BLOCK];
    let t = u32::from(dc.decode(r)?);
    if t > 11 {
        return Err(Error::Malformed);
    }
    coef[0] = extend(r.bits(t), t) as i16;
    let mut k = 1usize;
    while k < BLOCK {
        let rs = ac.decode(r)?;
        let run = usize::from(rs >> 4);
        let size = u32::from(rs & 15);
        if size == 0 {
            if run == 15 {
                k += 16;
                continue;
            }
            break;
        }
        if size > 10 {
            return Err(Error::Malformed);
        }
        k += run;
        if k >= BLOCK {
            return Err(Error::Malformed);
        }
        coef[k] = extend(r.bits(size), size) as i16;
        k += 1;
    }
    Ok(())
}

fn encode_block(
    w: &mut Writer<'_>,
    dc: &Table,
    ac: &Table,
    coef: &[i16; BLOCK],
) -> Result<(), Error> {
    let d = i32::from(coef[0]);
    let t = category(d);
    dc.encode(w, t as u8)?;
    if t != 0 {
        w.bits(field(d, t), t);
    }
    let mut run = 0u32;
    for &c in &coef[1..] {
        let v = i32::from(c);
        if v == 0 {
            run += 1;
            continue;
        }
        while run > 15 {
            ac.encode(w, 0xF0)?;
            run -= 16;
        }
        let s = category(v);
        ac.encode(w, ((run << 4) | s) as u8)?;
        w.bits(field(v, s), s);
        run = 0;
    }
    if run > 0 {
        ac.encode(w, 0x00)?;
    }
    Ok(())
}

/// Walk the scan once. With `out`, a new scan is written to it.
fn walk(
    file: &[u8],
    f: &Frame,
    visit: &mut dyn Visit,
    mut out: Option<&mut [u8]>,
) -> Result<usize, Error> {
    // A frame from another file can point past this one.
    let data = file.get(f.scan_start..f.scan_end).ok_or(Error::Malformed)?;
    let mut r = Reader::new(data);
    let mut none: [u8; 0] = [];
    let writing = out.is_some();
    let mut w = Writer::new(match out {
        Some(ref mut o) => &mut o[..],
        None => &mut none,
    });
    let mcus = f.mcus_x * f.mcus_y;
    let restart = u32::from(f.restart_interval);
    let mut index = 0u32;
    let mut coef = [0i16; BLOCK];
    for m in 0..mcus {
        if restart != 0 && m != 0 && m % restart == 0 {
            r.restart();
            if writing {
                w.restart(((m / restart - 1) % 8) as u8);
            }
        }
        for c in &f.components[..f.count] {
            let dc = &f.tables.dc[usize::from(c.dc)];
            let ac = &f.tables.ac[usize::from(c.ac)];
            for _ in 0..(u32::from(c.h) * u32::from(c.v)) {
                decode_block(&mut r, dc, ac, &mut coef)?;
                visit.block(index, &mut coef);
                if writing {
                    encode_block(&mut w, dc, ac, &coef)?;
                }
                index += 1;
            }
        }
    }
    if r.overran() {
        return Err(Error::Truncated);
    }
    if writing {
        w.flush();
        if w.overflowed() {
            return Err(Error::BufferTooSmall);
        }
    }
    Ok(w.written())
}

/// Visit every block of `file`'s scan; nothing is written.
///
/// # Errors
///
/// `Malformed` for data that does not decode or a frame from another file;
/// `Truncated` for a scan that ends before its blocks do.
pub fn read(file: &[u8], frame: &Frame, visit: &mut dyn Visit) -> Result<(), Error> {
    walk(file, frame, visit, None).map(|_| ())
}

/// Write `file` to `out` with its scan re-encoded from what the visitor
/// leaves in each block, and return the length; the rest is copied. The new
/// scan can be a little longer, so leave room past `file.len()`.
///
/// # Errors
///
/// As [`read`]; `BufferTooSmall`; `Unencodable` for a coefficient the
/// file's tables cannot code.
pub fn rewrite(
    file: &[u8],
    frame: &Frame,
    visit: &mut dyn Visit,
    out: &mut [u8],
) -> Result<usize, Error> {
    if frame.scan_start > frame.scan_end || frame.scan_end > file.len() {
        return Err(Error::Malformed);
    }
    let head = frame.scan_start;
    let tail = file.len() - frame.scan_end;
    if out.len() < head + tail {
        return Err(Error::BufferTooSmall);
    }
    out[..head].copy_from_slice(&file[..head]);
    let room = out.len() - head - tail;
    let scan_len = walk(file, frame, visit, Some(&mut out[head..head + room]))?;
    let total = head + scan_len + tail;
    out[head + scan_len..total].copy_from_slice(&file[frame.scan_end..]);
    Ok(total)
}

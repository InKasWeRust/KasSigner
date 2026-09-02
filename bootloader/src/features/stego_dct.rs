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

// features/stego_dct.rs — JPEG entropy-layer codec for coefficient-domain
// steganography (F5-style).
//
// ─── What this is for ───────────────────────────────────────────────
//
// The EXIF codec in `stego.rs` hides the payload in metadata. Metadata is
// stripped by every messaging app and most social platforms, so that artifact
// does not survive a trip through them. This one hides the payload in the
// image's own quantized DCT coefficients, which survives metadata stripping
// untouched and dies on recompression instead. The two fail on OPPOSITE
// operations, which is the reason to have both.
//
// ─── What it does NOT do ────────────────────────────────────────────
//
// It never touches pixels and never runs an IDCT. It decodes the Huffman
// layer to coefficients, alters a few of them, and re-encodes. Pixel-domain
// LSB embedding was measured and discarded: it survives PNG perfectly and is
// destroyed by even quality-95 JPEG (recovery 0.496, i.e. coin flips), so it
// cannot survive being stored as a JPEG at all, let alone photographed.
//
// Baseline sequential only (SOF0/SOF1). Progressive JPEGs are refused rather
// than mishandled: their coefficients are split across multiple scans with
// successive-approximation, and treating one like a baseline scan would
// corrupt the image.
//
// ─── Embedding rule ─────────────────────────────────────────────────
//
// F5-style magnitude decrement, not LSB replacement. A coefficient carries
// `|v| & 1`. To make it carry bit b when it does not, |v| is decremented by
// one, toward zero. Decrement rather than replacement because replacement
// creates the value-pair histogram anomaly that chi-square attacks on JSteg
// detect.
//
// SHRINKAGE is the subtle part. A +1 or -1 decremented becomes 0, and a zero
// coefficient carries nothing: the embedder skips it WITHOUT consuming a
// message bit, and the extractor skips it too because it reads zero there.
// The two stay in step only because both walk the same fixed position list in
// the same permuted order. This is why the embedding cannot be decided
// locally, and why there is a window array rather than a single pass — see
// `stego_perm.rs` for the full argument.
//
// ─── Structure ──────────────────────────────────────────────────────
//
//   pass 1  stream the scan, and for every AC position whose permuted rank
//           falls inside the window, record its coefficient
//   sim     walk the window in RANK order and decide every change, which is
//           the only place the sequential shrinkage logic lives
//   pass 2  stream the scan again, applying the recorded changes, writing a
//           new entropy-coded scan
//
// Two Huffman decodes of the scan. The alternative, holding every coefficient
// in RAM, is megabytes on a phone-sized photo.
//
// Verified in a reference implementation before this was written: the
// decode/re-encode identity round trip is BYTE-IDENTICAL on a real JPEG, a
// 202-byte payload embeds and extracts byte-identically, a wrong key recovers
// nothing, PSNR 45.7 dB, and file size moves by a couple of hundred bytes.

extern crate alloc;
use alloc::vec::Vec;
use crate::log;

use super::stego_perm::PosPerm;

/// Coefficients kept in the rank window. 40,000 entries is 78 KB and is
/// generous: a 1,632-bit payload needs roughly 7,000 ranks at the ~25%
/// non-zero coefficient density typical of a quality-85 photo.
pub const RANK_WINDOW: u32 = 40_000;

/// Ceiling on a frame's 8x8 block count, independent of file size.
///
/// SOF width and height are 16-bit with no upper bound of their own, so a few
/// hundred bytes on the SD card can declare 65535 x 65535. With four
/// components at sampling factor 1 that is 8192 x 8192 MCUs of 4 blocks each,
/// 268,435,456 blocks, and nothing stops the walk early: once the entropy data
/// runs out `BitReader::bit` returns zeros forever and a zero decodes to a
/// valid symbol, so every block past the real end of the data decodes as an
/// empty block. The walk is driven by the DECLARED geometry and never by how
/// much data exists.
///
/// 1,200,000 covers 8000 x 6000 at 4:2:0, which is 1,125,000 blocks and the
/// largest geometry that realistically fits inside the 2 MB import cap in
/// `handlers/stego.rs`. Sized to any camera a user might own rather than to
/// the on-board OV5640: these photos arrive from the SD card, not from the
/// device's own capture path.
pub const MAX_FRAME_BLOCKS: u32 = 1_200_000;

/// Blocks one byte of entropy-coded data can encode, at most.
///
/// A block costs at least one DC code and one end-of-block code. A 1-bit
/// Huffman code is legal, so two bits per block is a floor no valid file goes
/// under, and four blocks per byte rejects nothing a real encoder produces.
/// This is the bound that catches the small file: a 500-byte scan cannot
/// honestly claim more than 2,000 blocks.
const MAX_BLOCKS_PER_SCAN_BYTE: u64 = 4;

/// Payload is framed with a 2-byte big-endian length so the extractor knows
/// where to stop. Inside high-entropy coefficient noise there is nothing to
/// grep for, unlike the EXIF path where a fixed header was the whole problem.
const LEN_PREFIX: usize = 2;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DctError {
    /// Not a JPEG, or truncated.
    Malformed,
    /// Progressive or arithmetic-coded: not handled, deliberately.
    NotBaseline,
    /// Not enough usable coefficients for this payload.
    NoCapacity,
    /// Caller's output buffer is too small.
    BufferTooSmall,
    /// Declared frame geometry exceeds `MAX_FRAME_BLOCKS`. Distinct from
    /// `Malformed` on purpose: such a file can be perfectly well formed and
    /// simply larger than this device walks, and the user is owed that
    /// difference.
    TooLarge,
    /// A code the file's own Huffman table cannot express. Only reachable
    /// with optimized tables that omit run/size combinations we need after a
    /// coefficient changed magnitude category.
    Unencodable,
}

// ─── Huffman ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct HuffTable {
    present: bool,
    // Canonical decode, JPEG spec F.2.2.3.
    mincode: [i32; 17],
    maxcode: [i32; 17],
    valptr: [i32; 17],
    vals: [u8; 256],
    // Encode side.
    ehufco: [u16; 256],
    ehufsi: [u8; 256],
}

impl HuffTable {
    const fn empty() -> Self {
        Self {
            present: false,
            mincode: [0; 17],
            maxcode: [-1; 17],
            valptr: [0; 17],
            vals: [0; 256],
            ehufco: [0; 256],
            ehufsi: [0; 256],
        }
    }

    fn build(counts: &[u8; 16], vals: &[u8]) -> Self {
        let mut t = Self::empty();
        t.present = true;
        let n = vals.len().min(256);
        t.vals[..n].copy_from_slice(&vals[..n]);

        let mut code: i32 = 0;
        let mut k: usize = 0;
        for l in 1..=16usize {
            let c = counts[l - 1] as i32;
            if c == 0 {
                t.maxcode[l] = -1;
            } else {
                t.valptr[l] = k as i32;
                t.mincode[l] = code;
                // Assign encode-side codes for this length as we go.
                for i in 0..c {
                    let v = t.vals[k + i as usize] as usize;
                    t.ehufco[v] = (code + i) as u16;
                    t.ehufsi[v] = l as u8;
                }
                k += c as usize;
                code += c;
                t.maxcode[l] = code - 1;
            }
            code <<= 1;
        }
        t
    }
}

// ─── Bit I/O ────────────────────────────────────────────────────────

struct BitReader<'a> {
    d: &'a [u8],
    p: usize,
    b: u32,
    n: u32,
    /// Set the first time a bit is asked for past the end of the scan.
    ///
    /// `bit` fabricates zeros when the data runs out, and says nothing. A
    /// canonical Huffman table has an all-zeros shortest code, so `decode`
    /// returns a valid symbol rather than an error, `decode_block` returns
    /// `Ok` with an empty block, and `walk` completes normally. A TRUNCATED
    /// photo therefore decodes as a run of empty blocks and reports success:
    /// on extract that is a wrong answer instead of `Malformed`, and on embed
    /// the output is not the input.
    ///
    /// [E25] removed the dangerous half of this. A tiny file claiming a huge
    /// frame is now refused at `parse` by the geometry bounds before any walk
    /// happens. What is left is a file whose geometry passes both bounds and
    /// whose scan is genuinely short, which is a photo damaged in transit
    /// rather than a crafted one.
    ///
    /// Checked once after the walk, which then returns `Malformed`. Same shape
    /// as `BitWriter::overflow`, which is checked in the same place.
    ///
    /// Shipped observe-only first and promoted to a refusal only after
    /// measurement: four real photos across twelve reader passes never set it,
    /// and a photo truncated by 800 bytes set it on every pass. The evidence is
    /// recorded at the check site.
    over: bool,
}

impl<'a> BitReader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, p: 0, b: 0, n: 0, over: false }
    }

    #[inline]
    fn bit(&mut self) -> u32 {
        if self.n == 0 {
            if self.p >= self.d.len() {
                self.over = true;
                return 0;
            }
            let c = self.d[self.p];
            self.p += 1;
            // 0xFF00 is a stuffed 0xFF data byte; anything else after 0xFF is
            // a marker and the caller is responsible for resyncing.
            if c == 0xFF && self.p < self.d.len() && self.d[self.p] == 0x00 {
                self.p += 1;
            }
            self.b = c as u32;
            self.n = 8;
        }
        self.n -= 1;
        (self.b >> self.n) & 1
    }

    #[inline]
    fn bits(&mut self, k: u32) -> i32 {
        let mut v: i32 = 0;
        for _ in 0..k {
            v = (v << 1) | self.bit() as i32;
        }
        v
    }

    fn decode(&mut self, t: &HuffTable) -> Result<u8, DctError> {
        let mut code: i32 = self.bit() as i32;
        let mut l: usize = 1;
        while l <= 16 {
            if t.maxcode[l] >= 0 && code <= t.maxcode[l] {
                let idx = t.valptr[l] + code - t.mincode[l];
                if idx < 0 || idx as usize >= 256 {
                    return Err(DctError::Malformed);
                }
                return Ok(t.vals[idx as usize]);
            }
            code = (code << 1) | self.bit() as i32;
            l += 1;
        }
        Err(DctError::Malformed)
    }

    /// Skip forward to just past the next restart marker.
    fn resync(&mut self) {
        self.n = 0;
        while self.p + 1 < self.d.len() {
            if self.d[self.p] == 0xFF
                && (0xD0..=0xD7).contains(&self.d[self.p + 1])
            {
                self.p += 2;
                return;
            }
            self.p += 1;
        }
        self.p = self.d.len();
    }
}

struct BitWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    b: u32,
    n: u32,
    overflow: bool,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0, b: 0, n: 0, overflow: false }
    }

    #[inline]
    fn put(&mut self, byte: u8) {
        if self.pos < self.out.len() {
            self.out[self.pos] = byte;
            self.pos += 1;
        } else {
            self.overflow = true;
        }
    }

    #[inline]
    fn bit(&mut self, v: u32) {
        self.b = (self.b << 1) | (v & 1);
        self.n += 1;
        if self.n == 8 {
            let byte = self.b as u8;
            self.put(byte);
            // Stuff a zero after a literal 0xFF so it is not read as a marker.
            if byte == 0xFF {
                self.put(0x00);
            }
            self.b = 0;
            self.n = 0;
        }
    }

    #[inline]
    fn bits(&mut self, v: u32, k: u32) {
        for i in (0..k).rev() {
            self.bit((v >> i) & 1);
        }
    }

    fn code(&mut self, t: &HuffTable, sym: u8) -> Result<(), DctError> {
        let l = t.ehufsi[sym as usize];
        if l == 0 {
            return Err(DctError::Unencodable);
        }
        self.bits(t.ehufco[sym as usize] as u32, l as u32);
        Ok(())
    }

    /// Pad the partial byte with 1-bits, as the JPEG spec requires.
    fn flush(&mut self) {
        while self.n != 0 {
            self.bit(1);
        }
    }
}

/// Magnitude category: number of bits needed for |v|.
#[inline]
fn magcat(v: i32) -> u32 {
    let mut a = v.unsigned_abs();
    let mut t = 0u32;
    while a != 0 {
        t += 1;
        a >>= 1;
    }
    t
}

/// Sign-extend a raw `t`-bit magnitude field.
#[inline]
fn extend(v: i32, t: u32) -> i32 {
    if t == 0 {
        0
    } else if v < (1 << (t - 1)) {
        v - (1 << t) + 1
    } else {
        v
    }
}

/// The raw bits a value is written as, for a given category.
#[inline]
fn magbits(v: i32, t: u32) -> u32 {
    let m = (1u32 << t) - 1;
    if v > 0 { (v as u32) & m } else { ((v + (1 << t) - 1) as u32) & m }
}

// ─── Frame parsing ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Comp {
    h: u32,
    v: u32,
    td: usize,
    ta: usize,
}

struct Frame {
    scan_start: usize,
    scan_end: usize,
    comps: [Comp; 4],
    ncomp: usize,
    mcux: u32,
    mcuy: u32,
    restart: u32,
    dc: [HuffTable; 4],
    ac: [HuffTable; 4],
    blocks_per_mcu: u32,
}

impl Frame {
    fn total_blocks(&self) -> u32 {
        self.mcux * self.mcuy * self.blocks_per_mcu
    }
    /// Number of AC coefficient positions: 63 per block.
    fn positions(&self) -> u32 {
        self.total_blocks().saturating_mul(63)
    }
}

fn parse(jpeg: &[u8]) -> Result<Frame, DctError> {
    if jpeg.len() < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
        return Err(DctError::Malformed);
    }
    let mut dc = [HuffTable::empty(); 4];
    let mut ac = [HuffTable::empty(); 4];
    let mut comps = [Comp { h: 1, v: 1, td: 0, ta: 0 }; 4];
    let mut ncomp = 0usize;
    let mut ids = [0u8; 4];
    let mut restart = 0u32;
    let mut w = 0u32;
    let mut h = 0u32;

    let mut p = 2usize;
    while p + 3 < jpeg.len() {
        if jpeg[p] != 0xFF {
            p += 1;
            continue;
        }
        let m = jpeg[p + 1];
        if m == 0xD8 || m == 0x01 || (0xD0..=0xD7).contains(&m) {
            p += 2;
            continue;
        }
        if m == 0xD9 {
            break;
        }
        let seg_len = ((jpeg[p + 2] as usize) << 8) | jpeg[p + 3] as usize;
        if seg_len < 2 || p + 2 + seg_len > jpeg.len() {
            return Err(DctError::Malformed);
        }
        let seg = &jpeg[p + 4..p + 2 + seg_len];

        match m {
            // Baseline / extended sequential Huffman.
            0xC0 | 0xC1 => {
                if seg.len() < 6 {
                    return Err(DctError::Malformed);
                }
                h = ((seg[1] as u32) << 8) | seg[2] as u32;
                w = ((seg[3] as u32) << 8) | seg[4] as u32;
                ncomp = seg[5] as usize;
                if ncomp == 0 || ncomp > 4 || seg.len() < 6 + ncomp * 3 {
                    return Err(DctError::Malformed);
                }
                for i in 0..ncomp {
                    ids[i] = seg[6 + i * 3];
                    comps[i].h = (seg[7 + i * 3] >> 4) as u32;
                    comps[i].v = (seg[7 + i * 3] & 15) as u32;
                    if comps[i].h == 0 || comps[i].v == 0 || comps[i].h > 4 || comps[i].v > 4 {
                        return Err(DctError::Malformed);
                    }
                }
            }
            // Progressive, lossless, arithmetic, hierarchical: all refused.
            0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF => {
                return Err(DctError::NotBaseline);
            }
            0xC4 => {
                let mut q = 0usize;
                while q + 17 <= seg.len() {
                    let tc = seg[q] >> 4;
                    let th = (seg[q] & 15) as usize;
                    if th >= 4 {
                        return Err(DctError::Malformed);
                    }
                    let mut counts = [0u8; 16];
                    counts.copy_from_slice(&seg[q + 1..q + 17]);
                    let n: usize = counts.iter().map(|&c| c as usize).sum();
                    if q + 17 + n > seg.len() || n > 256 {
                        return Err(DctError::Malformed);
                    }
                    let t = HuffTable::build(&counts, &seg[q + 17..q + 17 + n]);
                    if tc == 0 { dc[th] = t; } else { ac[th] = t; }
                    q += 17 + n;
                }
            }
            0xDD => {
                if seg.len() < 2 {
                    return Err(DctError::Malformed);
                }
                restart = ((seg[0] as u32) << 8) | seg[1] as u32;
            }
            0xDA => {
                if seg.is_empty() {
                    return Err(DctError::Malformed);
                }
                let ns = seg[0] as usize;
                if ns == 0 || ns > 4 || seg.len() < 1 + ns * 2 {
                    return Err(DctError::Malformed);
                }
                // A scan covering fewer components than the frame is
                // non-interleaved, which changes the MCU geometry. Refuse.
                if ns != ncomp {
                    return Err(DctError::NotBaseline);
                }
                for i in 0..ns {
                    let cs = seg[1 + i * 2];
                    let t = seg[2 + i * 2];
                    for c in 0..ncomp {
                        if ids[c] == cs {
                            comps[c].td = (t >> 4) as usize & 3;
                            comps[c].ta = (t & 15) as usize & 3;
                        }
                    }
                }
                if w == 0 || h == 0 {
                    return Err(DctError::Malformed);
                }
                let hmax = comps[..ncomp].iter().map(|c| c.h).max().unwrap_or(1);
                let vmax = comps[..ncomp].iter().map(|c| c.v).max().unwrap_or(1);
                let mcux = (w + 8 * hmax - 1) / (8 * hmax);
                let mcuy = (h + 8 * vmax - 1) / (8 * vmax);
                let blocks_per_mcu: u32 = comps[..ncomp].iter().map(|c| c.h * c.v).sum();

                let scan_start = p + 2 + seg_len;
                let scan_end = find_scan_end(jpeg, scan_start);
                for c in 0..ncomp {
                    if !dc[comps[c].td].present || !ac[comps[c].ta].present {
                        return Err(DctError::Malformed);
                    }
                }

                // Geometry is DECLARED, not measured. Bound it twice here, in
                // the one place that builds a Frame, so `capacity_bits`,
                // `embed` and `extract` all inherit both bounds.
                //
                // The product cannot overflow before it is tested: w and h are
                // 16-bit, so mcux <= 8192 + hmax and mcuy <= 8192 + vmax,
                // while blocks_per_mcu <= 4 * hmax * vmax. That gives a
                // ceiling of 4 * (8192 + hmax) * (8192 + vmax), at most
                // 268,697,664, well inside u32. `Frame::total_blocks`
                // recomputes this same product and is bounded by the test
                // below from here on.
                let total_blocks = mcux * mcuy * blocks_per_mcu;
                if total_blocks > MAX_FRAME_BLOCKS {
                    return Err(DctError::TooLarge);
                }
                // A frame claiming more blocks than its own scan could
                // possibly encode is malformed rather than large. The two
                // bounds are loose in opposite places and neither replaces the
                // other: this one leaves a full 2 MB scan able to claim eight
                // million blocks, and the ceiling above leaves a few hundred
                // bytes able to claim 1,200,000.
                let scan_len = scan_end - scan_start;
                if u64::from(total_blocks) > scan_len as u64 * MAX_BLOCKS_PER_SCAN_BYTE {
                    return Err(DctError::Malformed);
                }

                return Ok(Frame {
                    scan_start,
                    scan_end,
                    comps,
                    ncomp,
                    mcux,
                    mcuy,
                    restart,
                    dc,
                    ac,
                    blocks_per_mcu,
                });
            }
            _ => {}
        }
        p += 2 + seg_len;
    }
    Err(DctError::Malformed)
}

/// End of entropy-coded data: the first marker that is neither a stuffed
/// 0xFF00 nor a restart.
fn find_scan_end(jpeg: &[u8], start: usize) -> usize {
    let mut p = start;
    while p + 1 < jpeg.len() {
        if jpeg[p] == 0xFF {
            let n = jpeg[p + 1];
            if n != 0x00 && !(0xD0..=0xD7).contains(&n) {
                return p;
            }
        }
        p += 1;
    }
    jpeg.len()
}

// ─── Block codec ────────────────────────────────────────────────────

/// Decode one block's coefficients. `coef[0]` is the DC DIFFERENCE, kept as
/// decoded: this codec never alters DC, so re-encoding the same difference
/// reproduces the original bits exactly without tracking the DC predictor.
fn decode_block(
    br: &mut BitReader,
    dc: &HuffTable,
    ac: &HuffTable,
    coef: &mut [i16; 64],
) -> Result<(), DctError> {
    *coef = [0i16; 64];
    let t = br.decode(dc)? as u32;
    if t > 15 {
        return Err(DctError::Malformed);
    }
    let diff = if t == 0 { 0 } else { extend(br.bits(t), t) };
    coef[0] = diff as i16;

    let mut k = 1usize;
    while k < 64 {
        let rs = br.decode(ac)?;
        let r = (rs >> 4) as usize;
        let s = (rs & 15) as u32;
        if s == 0 {
            if r == 15 {
                k += 16; // ZRL
                continue;
            }
            break; // EOB
        }
        k += r;
        if k > 63 {
            return Err(DctError::Malformed);
        }
        coef[k] = extend(br.bits(s), s) as i16;
        k += 1;
    }
    Ok(())
}

/// Re-encode a block from its coefficients. Run lengths and magnitude
/// categories are recomputed, which is required: a changed coefficient can
/// move to a different category, and a coefficient driven to zero lengthens
/// the run that follows it.
fn encode_block(
    bw: &mut BitWriter,
    dc: &HuffTable,
    ac: &HuffTable,
    coef: &[i16; 64],
) -> Result<(), DctError> {
    let d = coef[0] as i32;
    let t = magcat(d);
    bw.code(dc, t as u8)?;
    if t != 0 {
        bw.bits(magbits(d, t), t);
    }

    let mut run = 0u32;
    for k in 1..64usize {
        let v = coef[k] as i32;
        if v == 0 {
            run += 1;
            continue;
        }
        while run > 15 {
            bw.code(ac, 0xF0)?; // ZRL
            run -= 16;
        }
        let s = magcat(v);
        bw.code(ac, ((run << 4) | s) as u8)?;
        bw.bits(magbits(v, s), s);
        run = 0;
    }
    if run > 0 {
        bw.code(ac, 0x00)?; // EOB
    }
    Ok(())
}

// ─── Scan walking ───────────────────────────────────────────────────

/// What to do with each block as the scan streams past.
enum Mode<'m> {
    /// Record coefficients whose permuted rank is inside the window.
    Collect { window: &'m mut [i16], filled: &'m mut [u8] },
    /// Apply recorded changes and re-encode.
    Apply { window: &'m [i16], changed: &'m [u8] },
}

#[inline]
fn bit_get(bs: &[u8], i: u32) -> bool {
    let idx = (i >> 3) as usize;
    idx < bs.len() && (bs[idx] >> (i & 7)) & 1 == 1
}

#[inline]
fn bit_set(bs: &mut [u8], i: u32) {
    let idx = (i >> 3) as usize;
    if idx < bs.len() {
        bs[idx] |= 1 << (i & 7);
    }
}

/// Stream the entropy-coded scan once. If `out` is `Some`, a new scan is
/// written to it and its length returned.
fn walk(
    jpeg: &[u8],
    f: &Frame,
    perm: &PosPerm,
    k_window: u32,
    mode: &mut Mode,
    mut out: Option<&mut [u8]>,
) -> Result<usize, DctError> {
    let data = &jpeg[f.scan_start..f.scan_end];
    let mut br = BitReader::new(data);

    let mut scratch: [u8; 0] = [];
    let writing = out.is_some();
    let obuf: &mut [u8] = match out {
        Some(ref mut b) => &mut b[..],
        None => &mut scratch,
    };
    let mut bw = BitWriter::new(obuf);

    let nmcu = f.mcux * f.mcuy;
    let mut block_index: u32 = 0;

    for m in 0..nmcu {
        if f.restart != 0 && m != 0 && m % f.restart == 0 {
            br.resync();
            if writing {
                bw.flush();
                let rst = 0xD0 + (((m / f.restart) - 1) % 8) as u8;
                bw.put(0xFF);
                bw.put(rst);
                bw.b = 0;
                bw.n = 0;
            }
        }
        for c in 0..f.ncomp {
            let comp = f.comps[c];
            for _ in 0..(comp.h * comp.v) {
                let mut coef = [0i16; 64];
                decode_block(&mut br, &f.dc[comp.td], &f.ac[comp.ta], &mut coef)?;

                let base = block_index * 63;
                match mode {
                    Mode::Collect { window, filled } => {
                        for kk in 1..64usize {
                            let r = perm.rank(base + kk as u32 - 1);
                            if r < k_window {
                                window[r as usize] = coef[kk];
                                bit_set(filled, r);
                            }
                        }
                    }
                    Mode::Apply { window, changed } => {
                        for kk in 1..64usize {
                            let r = perm.rank(base + kk as u32 - 1);
                            if r < k_window && bit_get(changed, r) {
                                coef[kk] = window[r as usize];
                            }
                        }
                    }
                }

                if writing {
                    encode_block(&mut bw, &f.dc[comp.td], &f.ac[comp.ta], &coef)?;
                }
                block_index += 1;
            }
        }
    }

    // ENFORCED as of 2026-09-02, after measuring. See `BitReader::over` for
    // what fabricating zeros past the end of the scan does.
    //
    // Refusing rather than reporting, because the failure is silent and the
    // output is wrong in a way that looks like success. Measured on hardware
    // with a photo truncated by 800 bytes, which E25's geometry bounds admit
    // (30,000 blocks against a cap of 1,200,000 and a scan bound of
    // 3,244,364): the decoder invented empty blocks for the missing tail, the
    // encoder wrote real Huffman codes for them, and embed returned Ok with an
    // output 249 bytes LARGER than its input. Every undamaged photo in the
    // same session shrank by 89 to 158 bytes.
    //
    // Held back one delivery on purpose. In principle a well-formed file never
    // reads past the end, since the encoder pads the final byte with 1-bits and
    // `find_scan_end` puts the boundary just after it, but "in principle" is
    // what turning this into a refusal would have rested on. Four real photos,
    // grayscale and 4:2:0, 250 KB to 812 KB, went through export and import
    // across twelve reader passes without setting the flag, and the truncated
    // one set it on every pass. No false positives, and a true positive.
    if br.over {
        log!("   [dct] scan exhausted before {} blocks decoded ({} B scan)",
            block_index, data.len());
        return Err(DctError::Malformed);
    }

    if writing {
        bw.flush();
        if bw.overflow {
            return Err(DctError::BufferTooSmall);
        }
        return Ok(bw.pos);
    }
    Ok(0)
}

// ─── Public API ─────────────────────────────────────────────────────

/// Usable capacity in bits: non-zero AC coefficients inside the rank window.
pub fn capacity_bits(jpeg: &[u8], key: &[u8]) -> Result<u32, DctError> {
    let f = parse(jpeg)?;
    let n = f.positions();
    let perm = PosPerm::new(n, key).ok_or(DctError::Malformed)?;
    let k = k_window_for(n);

    let mut window = alloc::vec![0i16; k as usize];
    let mut filled = alloc::vec![0u8; (k as usize + 7) / 8];
    let mut mode = Mode::Collect { window: &mut window, filled: &mut filled };
    walk(jpeg, &f, &perm, k, &mut mode, None)?;

    let mut usable = 0u32;
    for r in 0..k {
        if bit_get(&filled, r) && window[r as usize] != 0 {
            usable += 1;
        }
    }
    Ok(usable)
}

#[inline]
fn k_window_for(n: u32) -> u32 {
    if n < RANK_WINDOW { n } else { RANK_WINDOW }
}

/// Embed `payload` into the JPEG's coefficients, writing a complete new JPEG
/// to `out`. Returns the output length.
pub fn embed(
    jpeg: &[u8],
    payload: &[u8],
    key: &[u8],
    out: &mut [u8],
) -> Result<usize, DctError> {
    if payload.is_empty() || payload.len() > 0xFFFF {
        return Err(DctError::NoCapacity);
    }
    let f = parse(jpeg)?;
    let n = f.positions();
    let perm = PosPerm::new(n, key).ok_or(DctError::Malformed)?;
    let k = k_window_for(n);

    // ── pass 1: collect the window ──
    let mut window = alloc::vec![0i16; k as usize];
    let mut filled = alloc::vec![0u8; (k as usize + 7) / 8];
    {
        let mut mode = Mode::Collect { window: &mut window, filled: &mut filled };
        walk(jpeg, &f, &perm, k, &mut mode, None)?;
    }

    // ── simulate in RANK order: the one place shrinkage is handled ──
    let nbits = (LEN_PREFIX + payload.len()) * 8;
    let mut changed = alloc::vec![0u8; (k as usize + 7) / 8];
    let mut bit_i = 0usize;
    for r in 0..k {
        if bit_i >= nbits {
            break;
        }
        if !bit_get(&filled, r) {
            continue;
        }
        let v = window[r as usize] as i32;
        if v == 0 {
            continue;
        }
        // Bit this rank must carry.
        let byte = if bit_i < LEN_PREFIX * 8 {
            let l = payload.len() as u32;
            if bit_i < 8 { (l >> 8) as u8 } else { (l & 0xFF) as u8 }
        } else {
            payload[(bit_i / 8) - LEN_PREFIX]
        };
        let want = (byte >> (7 - (bit_i % 8))) & 1;

        if (v.unsigned_abs() & 1) as u8 != want {
            let nv = if v > 0 { v - 1 } else { v + 1 };
            window[r as usize] = nv as i16;
            bit_set(&mut changed, r);
            if nv == 0 {
                // Shrinkage: this rank now carries nothing. The extractor
                // will see a zero and skip it too, so the message pointer
                // must NOT advance.
                continue;
            }
        }
        bit_i += 1;
    }
    if bit_i < nbits {
        return Err(DctError::NoCapacity);
    }

    // ── pass 2: apply and re-encode ──
    let head = f.scan_start;
    let tail = jpeg.len() - f.scan_end;
    if out.len() < head + tail {
        return Err(DctError::BufferTooSmall);
    }
    out[..head].copy_from_slice(&jpeg[..head]);

    let scan_len = {
        let mut mode = Mode::Apply { window: &window, changed: &changed };
        let avail = out.len() - head - tail;
        let (_, rest) = out.split_at_mut(head);
        let (scan_area, _) = rest.split_at_mut(avail);
        walk(jpeg, &f, &perm, k, &mut mode, Some(scan_area))?
    };

    // The tail (EOI and any trailing markers) goes directly after the new
    // scan, which is shorter or longer than the original by a few hundred
    // bytes depending on how the changed coefficients re-encode.
    let total = head + scan_len + tail;
    if out.len() < total {
        return Err(DctError::BufferTooSmall);
    }
    out[head + scan_len..total].copy_from_slice(&jpeg[f.scan_end..]);
    Ok(total)
}

/// Recover a payload previously embedded with the same key.
pub fn extract(jpeg: &[u8], key: &[u8], out: &mut [u8]) -> Result<usize, DctError> {
    let f = parse(jpeg)?;
    let n = f.positions();
    let perm = PosPerm::new(n, key).ok_or(DctError::Malformed)?;
    let k = k_window_for(n);

    let mut window = alloc::vec![0i16; k as usize];
    let mut filled = alloc::vec![0u8; (k as usize + 7) / 8];
    {
        let mut mode = Mode::Collect { window: &mut window, filled: &mut filled };
        walk(jpeg, &f, &perm, k, &mut mode, None)?;
    }

    // Read LSBs in rank order, skipping zeros exactly as the embedder did.
    let mut bits: Vec<u8> = Vec::with_capacity(k as usize);
    for r in 0..k {
        if !bit_get(&filled, r) {
            continue;
        }
        let v = window[r as usize] as i32;
        if v == 0 {
            continue;
        }
        bits.push((v.unsigned_abs() & 1) as u8);
    }
    if bits.len() < LEN_PREFIX * 8 {
        return Err(DctError::Malformed);
    }

    let byte_at = |i: usize| -> u8 {
        let mut b = 0u8;
        for j in 0..8 {
            b = (b << 1) | bits[i * 8 + j];
        }
        b
    };
    let len = ((byte_at(0) as usize) << 8) | byte_at(1) as usize;
    if len == 0 || (LEN_PREFIX + len) * 8 > bits.len() {
        return Err(DctError::Malformed);
    }
    if out.len() < len {
        return Err(DctError::BufferTooSmall);
    }
    for i in 0..len {
        out[i] = byte_at(LEN_PREFIX + i);
    }
    Ok(len)
}

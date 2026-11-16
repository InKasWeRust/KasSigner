// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR encoding, ISO/IEC 18004: byte and numeric modes, versions 1 to 9,
//! error correction level L (7% recovery), no allocator.
//!
//! An encode builds the data codewords, adds Reed-Solomon error correction,
//! places the function patterns and the data, then applies whichever of the
//! eight masks scores the lowest penalty and writes its format information.
//! [`QrMatrix`] is a grid of modules, not a code: the bytes it carries are
//! the caller's and nothing here interprets them.

use crate::capacity::{byte_capacity, select_version, select_version_numeric};
use zeroize::{Zeroize, Zeroizing};

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Modules per side at version 9.
const MAX_SIZE: usize = 53;
const MAX_MODULES: usize = MAX_SIZE * MAX_SIZE; // 2809
/// A bitmap of every module, 352 bytes.
const BITMAP_BYTES: usize = MAX_MODULES.div_ceil(8);

/// Each version at error correction level L.
const VERSION_TABLE: [(u8, u8, u16, u16, u8); 9] = [
    // version, side, data codewords, EC codewords, EC blocks
    (1, 21, 19, 7, 1),
    (2, 25, 34, 10, 1),
    (3, 29, 55, 15, 1),
    (4, 33, 80, 20, 1),
    (5, 37, 108, 26, 1),
    (6, 41, 136, 36, 2), // two equal blocks from here
    (7, 45, 156, 40, 2), // version information from here
    (8, 49, 194, 48, 2),
    (9, 53, 232, 60, 2),
];

// ═══════════════════════════════════════════════════════════════════
// Reed-Solomon GF(256) with primitive polynomial 0x11D
// ═══════════════════════════════════════════════════════════════════

/// GF(256) multiplication.
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let mut result: u16 = 0;
    let mut aa = a as u16;
    let mut bb = b;
    for _ in 0..8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let carry = aa & 0x80 != 0;
        aa <<= 1;
        if carry {
            aa ^= 0x11D; // primitive polynomial
        }
        bb >>= 1;
    }
    result as u8
}

/// The `ec_count` Reed-Solomon error correction codewords of `data`, into
/// `ec_out`.
fn rs_encode(data: &[u8], ec_count: usize, ec_out: &mut [u8]) {
    // The generator g(x) = (x + α^0)(x + α^1)...(x + α^(n-1)) (minus is
    // plus in GF(2)), coefficients in descending powers: gen[0] is x^n's,
    // always 1, gen[n] the constant. Built from [1] one factor at a time.
    let mut gen2 = [0u8; 37];
    gen2[0] = 1;

    for i in 0..ec_count {
        // `gen2` holds the product of the first `i` factors, `i + 1`
        // coefficients.
        let glen = i + 1;
        let mut alpha_i = 1u8;
        for _ in 0..i {
            alpha_i = gf_mul(alpha_i, 2);
        }
        // Times (x + r): new[0] = g[0], new[j] = g[j] + g[j-1]*r, and the
        // new constant g[n]*r.
        let mut new_gen = [0u8; 37];
        new_gen[0] = gen2[0];
        for j in 1..glen {
            new_gen[j] = gen2[j] ^ gf_mul(gen2[j - 1], alpha_i);
        }
        new_gen[glen] = gf_mul(gen2[glen - 1], alpha_i);
        gen2[..=glen].copy_from_slice(&new_gen[..=glen]);
    }

    // D(x)*x^n mod g(x). The remainder starts as the data codewords, a
    // SeedQR's seed among them, so it is wiped like the encode's other
    // buffers.
    let mut remainder = Zeroizing::new([0u8; 180]);
    remainder[..data.len()].copy_from_slice(data);

    for i in 0..data.len() {
        let coef = remainder[i];
        if coef != 0 {
            for j in 1..=ec_count {
                remainder[i + j] ^= gf_mul(gen2[j], coef);
            }
        }
    }

    ec_out[..ec_count].copy_from_slice(&remainder[data.len()..data.len() + ec_count]);
}

// ═══════════════════════════════════════════════════════════════════
// QR Code bitmap
// ═══════════════════════════════════════════════════════════════════

/// A QR code's modules, in fixed-size storage.
///
/// Wipes its modules on drop: a SeedQR's matrix is the seed. The crate
/// header says what that does not cover.
pub struct QrMatrix {
    /// Module data (dark = true)
    modules: [u8; BITMAP_BYTES],
    /// Which modules are "function patterns" (not data)
    is_function: [u8; BITMAP_BYTES],
    /// Size (modules per side)
    pub size: u8,
    /// Version (1-9)
    version: u8,
}

/// The wipe its drop runs, for a caller done with a code before it goes.
impl Zeroize for QrMatrix {
    fn zeroize(&mut self) {
        self.modules.zeroize();
        self.is_function.zeroize();
    }
}

impl Drop for QrMatrix {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl QrMatrix {
    fn new(version: u8) -> Self {
        Self {
            modules: [0u8; BITMAP_BYTES],
            is_function: [0u8; BITMAP_BYTES],
            size: 17 + version * 4,
            version,
        }
    }

    #[inline]
    fn idx(&self, x: u8, y: u8) -> usize {
        (y as usize) * (self.size as usize) + (x as usize)
    }

    #[inline]
    /// Whether the module at (x, y) is dark. Outside the matrix is light, as
    /// its quiet zone is.
    pub fn get(&self, x: u8, y: u8) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        let i = self.idx(x, y);
        (self.modules[i / 8] >> (i % 8)) & 1 != 0
    }

    #[inline]
    fn set(&mut self, x: u8, y: u8, dark: bool) {
        let i = self.idx(x, y);
        if dark {
            self.modules[i / 8] |= 1 << (i % 8);
        } else {
            self.modules[i / 8] &= !(1 << (i % 8));
        }
    }

    #[inline]
    fn is_func(&self, x: u8, y: u8) -> bool {
        let i = self.idx(x, y);
        (self.is_function[i / 8] >> (i % 8)) & 1 != 0
    }

    #[inline]
    fn set_func(&mut self, x: u8, y: u8, dark: bool) {
        let i = self.idx(x, y);
        self.is_function[i / 8] |= 1 << (i % 8);
        if dark {
            self.modules[i / 8] |= 1 << (i % 8);
        } else {
            self.modules[i / 8] &= !(1 << (i % 8));
        }
    }

    // ─── Function patterns ──────────────────────────────────────

    /// Draw a finder pattern (7x7) and its light separator, centred at
    /// (cx, cy).
    fn draw_finder(&mut self, cx: i16, cy: i16) {
        for dy in -4i16..=4 {
            for dx in -4i16..=4 {
                let x = cx + dx;
                let y = cy + dy;
                if x < 0 || y < 0 || x >= self.size as i16 || y >= self.size as i16 {
                    continue;
                }
                let dist = dx.abs().max(dy.abs());
                let dark = dist != 2 && dist != 4;
                self.set_func(x as u8, y as u8, dark);
            }
        }
    }

    /// Draw all function patterns
    fn draw_function_patterns(&mut self) {
        let s = self.size;

        // Finder patterns (top-left, top-right, bottom-left)
        self.draw_finder(3, 3);
        self.draw_finder(s as i16 - 4, 3);
        self.draw_finder(3, s as i16 - 4);

        // Timing patterns
        for i in 8..s - 8 {
            self.set_func(i, 6, i % 2 == 0);
            self.set_func(6, i, i % 2 == 0);
        }

        // Dark module (always present)
        self.set_func(8, 4 * self.version + 9, true);

        // Alignment patterns (V2+)
        if self.version >= 2 {
            let positions = alignment_positions(self.version);
            let n = positions.0;
            for i in 0..n {
                for j in 0..n {
                    // Skip the three corners the finder patterns occupy.
                    let last = n - 1;
                    if matches!((i, j), (0, 0)) || (i, j) == (0, last) || (i, j) == (last, 0) {
                        continue;
                    }
                    self.draw_alignment(positions.1[i], positions.1[j]);
                }
            }
        }

        // Version information, from version 7: the 18-bit BCH-coded version
        // in two 3 by 6 areas beside the finders. The mask does not touch
        // it, so the final bits go in here; the standard's values.
        if self.version >= 7 {
            const VERSION_INFO_BITS: [u32; 3] = [0x07C94, 0x085BC, 0x09A99]; // V7, V8, V9
            let bits = VERSION_INFO_BITS[(self.version - 7) as usize];
            for i in 0..18u32 {
                let dark = (bits >> i) & 1 == 1;
                let a = s - 11 + (i % 3) as u8;
                let b = (i / 3) as u8;
                self.set_func(a, b, dark); // top-right block
                self.set_func(b, a, dark); // bottom-left block (transposed)
            }
        }

        // Reserve format info areas (will be written later)
        // Around top-left finder
        for i in 0..9u8 {
            // (6,8) and (8,6) are the timing patterns' first modules, not
            // format positions: the standard and `write_format_info` skip
            // them.
            if i == 6 {
                continue;
            }
            if i < s {
                self.set_func(i, 8, false); // horizontal
                self.set_func(8, i, false); // vertical
            }
        }
        // Around top-right finder
        for i in 0..8u8 {
            self.set_func(s - 1 - i, 8, false);
        }
        // Around bottom-left finder
        for i in 0..7u8 {
            self.set_func(8, s - 1 - i, false);
        }
    }

    /// Draw 5x5 alignment pattern centered at (cx, cy)
    fn draw_alignment(&mut self, cx: u8, cy: u8) {
        for dy in -2i8..=2 {
            for dx in -2i8..=2 {
                let x = (cx as i8 + dx) as u8;
                let y = (cy as i8 + dy) as u8;
                let dark = dx.abs().max(dy.abs()) != 1;
                self.set_func(x, y, dark);
            }
        }
    }

    // ─── Data placement ─────────────────────────────────────────

    /// Place data bits into QR code following the zigzag pattern
    fn place_data(&mut self, data: &[u8]) {
        let s = self.size as i16;
        let mut bit_idx: usize = 0;
        let total_bits = data.len() * 8;

        // Right-to-left column pairs, skipping column 6
        let mut right = s - 1;
        while right >= 0 {
            if right == 6 {
                right -= 1;
                continue;
            }

            // Upward then downward alternating
            let upward = ((s - 1 - right) / 2) % 2 == 0;

            for row_i in 0..s {
                let y = if upward { s - 1 - row_i } else { row_i };

                for dx in 0..2i16 {
                    let x = right - dx;
                    if x < 0 || x >= s || y < 0 || y >= s {
                        continue;
                    }

                    if self.is_func(x as u8, y as u8) {
                        continue;
                    }

                    let dark = if bit_idx < total_bits {
                        let byte = data[bit_idx / 8];
                        let bit = 7 - (bit_idx % 8);
                        bit_idx += 1;
                        (byte >> bit) & 1 != 0
                    } else {
                        false
                    };

                    self.set(x as u8, y as u8, dark);
                }
            }

            right -= 2;
        }
    }

    // ─── Masking ────────────────────────────────────────────────

    /// Apply mask pattern to data modules
    fn apply_mask(&mut self, mask: u8) {
        let s = self.size;
        for y in 0..s {
            for x in 0..s {
                if self.is_func(x, y) {
                    continue;
                }
                let invert = match mask {
                    0 => (y + x) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (y + x) % 3 == 0,
                    4 => (y / 2 + x / 3) % 2 == 0,
                    5 => (y as u16 * x as u16) % 2 + (y as u16 * x as u16) % 3 == 0,
                    6 => ((y as u16 * x as u16) % 2 + (y as u16 * x as u16) % 3).is_multiple_of(2),
                    7 => ((y + x) as u16 % 2 + (y as u16 * x as u16) % 3).is_multiple_of(2),
                    _ => false,
                };
                if invert {
                    let i = self.idx(x, y);
                    self.modules[i / 8] ^= 1 << (i % 8);
                }
            }
        }
    }

    /// Calculate penalty score for mask evaluation
    fn penalty_score(&self) -> u32 {
        let s = self.size as usize;
        let mut penalty = 0u32;

        // Rule 1: runs of same color (horizontal + vertical)
        for y in 0..s {
            let mut run_color = false;
            let mut run_len = 0u32;
            for x in 0..s {
                let dark = self.get(x as u8, y as u8);
                if x == 0 || dark != run_color {
                    run_color = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                    if run_len == 5 {
                        penalty += 3;
                    } else if run_len > 5 {
                        penalty += 1;
                    }
                }
            }
        }
        for x in 0..s {
            let mut run_color = false;
            let mut run_len = 0u32;
            for y in 0..s {
                let dark = self.get(x as u8, y as u8);
                if y == 0 || dark != run_color {
                    run_color = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                    if run_len == 5 {
                        penalty += 3;
                    } else if run_len > 5 {
                        penalty += 1;
                    }
                }
            }
        }

        // Rule 2: 2x2 blocks of same color
        for y in 0..s - 1 {
            for x in 0..s - 1 {
                let c = self.get(x as u8, y as u8);
                if c == self.get(x as u8 + 1, y as u8)
                    && c == self.get(x as u8, y as u8 + 1)
                    && c == self.get(x as u8 + 1, y as u8 + 1)
                {
                    penalty += 3;
                }
            }
        }

        // Rule 3: finder-like patterns in a row or a column, 40 each.
        for line in 0..s {
            for horizontal in [true, false] {
                penalty += 40 * self.finder_like(line, horizontal);
            }
        }

        // Rule 4: proportion of dark modules
        let mut dark_count = 0u32;
        let total = (s * s) as u32;
        for y in 0..s {
            for x in 0..s {
                if self.get(x as u8, y as u8) {
                    dark_count += 1;
                }
            }
        }
        let pct = (dark_count * 100) / total;
        let dev = pct.abs_diff(50);
        penalty += (dev / 5) * 10;

        penalty
    }

    /// How many finder-like patterns row `line` holds, or column `line`:
    /// rule 3's dark `1:1:3:1:1` with four light modules on one side or the
    /// other, past the edge counting as light (the quiet zone).
    fn finder_like(&self, line: usize, horizontal: bool) -> u32 {
        const PATTERN: [bool; 7] = [true, false, true, true, true, false, true];
        const LIGHT: [bool; 4] = [false; 4];
        let s = usize::from(self.size);
        let mut cells = [false; MAX_SIZE + 8];
        for (k, cell) in cells[4..4 + s].iter_mut().enumerate() {
            let (x, y) = if horizontal { (k, line) } else { (line, k) };
            *cell = self.get(x as u8, y as u8);
        }
        let mut found = 0;
        for j in 4..=s.saturating_sub(3) {
            if cells[j..j + 7] == PATTERN
                && (cells[j - 4..j] == LIGHT || cells[j + 7..j + 11] == LIGHT)
            {
                found += 1;
            }
        }
        found
    }

    // ─── Format information ─────────────────────────────────────

    /// Write format info bits (ECC level + mask pattern)
    fn write_format_info(&mut self, mask: u8) {
        // Format info = 5 bits (ECC L = 01, mask 3 bits) + 10 bits BCH ECC
        let format_data = (0b01 << 3) | (mask as u16 & 7);
        let format_bits = format_info_bits(format_data);

        let s = self.size;

        // Place format bits around top-left finder
        let coords_h: [(u8, u8); 15] = [
            (0, 8),
            (1, 8),
            (2, 8),
            (3, 8),
            (4, 8),
            (5, 8),
            (7, 8),
            (8, 8),
            (8, 7),
            (8, 5),
            (8, 4),
            (8, 3),
            (8, 2),
            (8, 1),
            (8, 0),
        ];

        for (i, &(x, y)) in coords_h.iter().enumerate() {
            let bit = (format_bits >> (14 - i)) & 1 != 0;
            self.set(x, y, bit);
        }

        // Place format bits around other finders
        let coords_v: [(u8, u8); 15] = [
            (8, s - 1),
            (8, s - 2),
            (8, s - 3),
            (8, s - 4),
            (8, s - 5),
            (8, s - 6),
            (8, s - 7),
            (s - 8, 8),
            (s - 7, 8),
            (s - 6, 8),
            (s - 5, 8),
            (s - 4, 8),
            (s - 3, 8),
            (s - 2, 8),
            (s - 1, 8),
        ];

        for (i, &(x, y)) in coords_v.iter().enumerate() {
            let bit = (format_bits >> (14 - i)) & 1 != 0;
            self.set(x, y, bit);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// BCH(15,5) encoding for format information
/// Uses generator polynomial x^10 + x^8 + x^5 + x^4 + x^2 + x + 1
fn format_info_bits(data: u16) -> u16 {
    let mut bits = data << 10;
    let gen = 0b10100110111u16; // generator polynomial

    for i in (0..5).rev() {
        if bits & (1 << (i + 10)) != 0 {
            bits ^= gen << i;
        }
    }

    let result = (data << 10) | bits;
    // XOR with mask pattern
    result ^ 0b101010000010010
}

/// Alignment pattern positions for each version
fn alignment_positions(version: u8) -> (usize, [u8; 7]) {
    let positions: [u8; 7];
    let n: usize;

    match version {
        2 => {
            n = 2;
            positions = [6, 18, 0, 0, 0, 0, 0];
        }
        3 => {
            n = 2;
            positions = [6, 22, 0, 0, 0, 0, 0];
        }
        4 => {
            n = 2;
            positions = [6, 26, 0, 0, 0, 0, 0];
        }
        5 => {
            n = 2;
            positions = [6, 30, 0, 0, 0, 0, 0];
        }
        6 => {
            n = 2;
            positions = [6, 34, 0, 0, 0, 0, 0];
        }
        7 => {
            n = 3;
            positions = [6, 22, 38, 0, 0, 0, 0];
        }
        8 => {
            n = 3;
            positions = [6, 24, 42, 0, 0, 0, 0];
        }
        9 => {
            n = 3;
            positions = [6, 26, 46, 0, 0, 0, 0];
        }
        _ => {
            n = 0;
            positions = [0; 7];
        }
    }

    (n, positions)
}

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Error type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrError {
    DataTooLong,
    InternalError,
    /// [`encode_numeric`] was given a byte that is not an ASCII digit.
    NotNumeric,
}

/// Encode data into QR code, at the smallest version that holds it.
pub fn encode(data: &[u8]) -> Result<QrMatrix, QrError> {
    let version = select_version(data.len()).ok_or(QrError::DataTooLong)?;
    encode_at(data, version)
}

/// Encode data into a QR code of `version` exactly, the room the data
/// leaves filled with the standard's pad codewords. A unit draws every
/// frame for a wallet this way, at version 9.
///
/// # Errors
///
/// `DataTooLong` for data `version` cannot hold, and for a version that is
/// not 1 to [`MAX_VERSION`](crate::MAX_VERSION).
pub fn encode_at(data: &[u8], version: u8) -> Result<QrMatrix, QrError> {
    match byte_capacity(version) {
        Some(room) if data.len() <= room => {}
        _ => return Err(QrError::DataTooLong),
    }
    let vi = (version - 1) as usize;
    let (_, _, data_cw, ec_cw, ec_blocks) = VERSION_TABLE[vi];

    // ─── Data codewords ─────────────────────────────────────
    let mut codewords = Zeroizing::new([0u8; 240]); // max data codewords (V9 = 232)
    let mut bit_buf = BitWriter::new(&mut codewords[..]);

    // Mode indicator: 0100 (byte mode)
    bit_buf.write_bits(0b0100, 4);

    // Character count (8 bits for V1-9 byte mode)
    bit_buf.write_bits(data.len() as u32, 8);

    // Data bytes
    for &b in data {
        bit_buf.write_bits(b as u32, 8);
    }

    // Terminator (up to 4 zero bits)
    let total_data_bits = data_cw as usize * 8;
    let bits_used = bit_buf.bit_pos;
    let terminator_len = 4.min(total_data_bits.saturating_sub(bits_used));
    bit_buf.write_bits(0, terminator_len);

    // Pad to byte boundary
    while !bit_buf.bit_pos.is_multiple_of(8) {
        bit_buf.write_bits(0, 1);
    }

    // Pad with alternating 0xEC, 0x11
    let mut pad_byte = 0;
    while bit_buf.bit_pos / 8 < data_cw as usize {
        bit_buf.write_bits(if pad_byte % 2 == 0 { 0xEC } else { 0x11 }, 8);
        pad_byte += 1;
    }

    // ─── Error correction ───────────────────────────────────
    let data_bytes = data_cw as usize;
    let ec_bytes = ec_cw as usize;

    // One block up to version 5, two equal blocks from version 6
    let mut all_codewords = Zeroizing::new([0u8; 300]); // max total codewords (V9 = 292)

    if ec_blocks == 1 {
        // Single block: data codewords + EC codewords
        all_codewords[..data_bytes].copy_from_slice(&codewords[..data_bytes]);
        let mut ec = Zeroizing::new([0u8; 37]);
        rs_encode(&codewords[..data_bytes], ec_bytes, &mut ec[..]);
        all_codewords[data_bytes..data_bytes + ec_bytes].copy_from_slice(&ec[..ec_bytes]);
    } else {
        // Each block half the data codewords and half the EC
        let block1_data = data_bytes / 2;
        let block2_data = data_bytes - block1_data;
        let block_ec = ec_bytes / 2;

        let mut ec1 = Zeroizing::new([0u8; 37]);
        let mut ec2 = Zeroizing::new([0u8; 37]);
        rs_encode(&codewords[..block1_data], block_ec, &mut ec1[..]);
        rs_encode(&codewords[block1_data..data_bytes], block_ec, &mut ec2[..]);

        // Interleave data codewords
        let mut pos = 0;
        let max_block = block1_data.max(block2_data);
        for i in 0..max_block {
            if i < block1_data {
                all_codewords[pos] = codewords[i];
                pos += 1;
            }
            if i < block2_data {
                all_codewords[pos] = codewords[block1_data + i];
                pos += 1;
            }
        }
        // Interleave EC codewords
        for i in 0..block_ec {
            all_codewords[pos] = ec1[i];
            pos += 1;
            all_codewords[pos] = ec2[i];
            pos += 1;
        }
    }

    let total_cw = data_bytes + ec_bytes;

    // ─── Matrix ─────────────────────────────────────────────
    let mut qr = QrMatrix::new(version);

    qr.draw_function_patterns();

    qr.place_data(&all_codewords[..total_cw]);

    // ─── Best mask ──────────────────────────────────────────
    let mut best_mask = 0u8;
    let mut best_penalty = u32::MAX;

    // Save unmasked data modules
    let saved_modules = Zeroizing::new(qr.modules);

    for mask in 0..8u8 {
        qr.modules = *saved_modules;
        qr.apply_mask(mask);
        qr.write_format_info(mask);

        let penalty = qr.penalty_score();
        if penalty < best_penalty {
            best_penalty = penalty;
            best_mask = mask;
        }
    }

    // Apply best mask
    qr.modules = *saved_modules;
    qr.apply_mask(best_mask);
    qr.write_format_info(best_mask);

    Ok(qr)
}

// ═══════════════════════════════════════════════════════════════════
// Numeric mode encoding
// ═══════════════════════════════════════════════════════════════════

/// Encode ASCII digits into a QR code in numeric mode (mode indicator 0001),
/// at the smallest version that holds them. Any byte not '0' to '9' is
/// `NotNumeric`.
pub fn encode_numeric(digits: &[u8]) -> Result<QrMatrix, QrError> {
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(QrError::NotNumeric);
    }
    let digit_count = digits.len();
    let version = select_version_numeric(digit_count).ok_or(QrError::DataTooLong)?;
    let vi = (version - 1) as usize;
    let (_, _, data_cw, ec_cw, ec_blocks) = VERSION_TABLE[vi];

    let mut codewords = Zeroizing::new([0u8; 240]); // max data codewords (V9 = 232)
    let mut bit_buf = BitWriter::new(&mut codewords[..]);

    // Mode indicator: 0001 (numeric)
    bit_buf.write_bits(0b0001, 4);

    // Character count: 10 bits for V1-9
    bit_buf.write_bits(digit_count as u32, 10);

    // Encode digits in groups of 3 → 10 bits, 2 → 7 bits, 1 → 4 bits
    let mut i = 0;
    while i + 2 < digit_count {
        let d0 = (digits[i] - b'0') as u32;
        let d1 = (digits[i + 1] - b'0') as u32;
        let d2 = (digits[i + 2] - b'0') as u32;
        bit_buf.write_bits(d0 * 100 + d1 * 10 + d2, 10);
        i += 3;
    }
    let remaining = digit_count - i;
    if remaining == 2 {
        let d0 = (digits[i] - b'0') as u32;
        let d1 = (digits[i + 1] - b'0') as u32;
        bit_buf.write_bits(d0 * 10 + d1, 7);
    } else if remaining == 1 {
        let d0 = (digits[i] - b'0') as u32;
        bit_buf.write_bits(d0, 4);
    }

    // Terminator
    let total_data_bits = data_cw as usize * 8;
    let bits_used = bit_buf.bit_pos;
    let terminator_len = 4.min(total_data_bits.saturating_sub(bits_used));
    bit_buf.write_bits(0, terminator_len);

    // Pad to byte boundary
    while !bit_buf.bit_pos.is_multiple_of(8) {
        bit_buf.write_bits(0, 1);
    }

    // Pad with alternating 0xEC, 0x11
    let mut pad_byte = 0;
    while bit_buf.bit_pos / 8 < data_cw as usize {
        bit_buf.write_bits(if pad_byte % 2 == 0 { 0xEC } else { 0x11 }, 8);
        pad_byte += 1;
    }

    // Error correction (same as byte mode)
    let data_bytes = data_cw as usize;
    let ec_bytes = ec_cw as usize;
    let mut all_codewords = Zeroizing::new([0u8; 300]); // max total codewords (V9 = 292)

    if ec_blocks == 1 {
        all_codewords[..data_bytes].copy_from_slice(&codewords[..data_bytes]);
        let mut ec = Zeroizing::new([0u8; 37]);
        rs_encode(&codewords[..data_bytes], ec_bytes, &mut ec[..]);
        all_codewords[data_bytes..data_bytes + ec_bytes].copy_from_slice(&ec[..ec_bytes]);
    } else {
        let block1_data = data_bytes / 2;
        let block2_data = data_bytes - block1_data;
        let block_ec = ec_bytes / 2;

        let mut ec1 = Zeroizing::new([0u8; 37]);
        let mut ec2 = Zeroizing::new([0u8; 37]);
        rs_encode(&codewords[..block1_data], block_ec, &mut ec1[..]);
        rs_encode(&codewords[block1_data..data_bytes], block_ec, &mut ec2[..]);

        let mut pos = 0;
        let max_block = block1_data.max(block2_data);
        for j in 0..max_block {
            if j < block1_data {
                all_codewords[pos] = codewords[j];
                pos += 1;
            }
            if j < block2_data {
                all_codewords[pos] = codewords[block1_data + j];
                pos += 1;
            }
        }
        for j in 0..block_ec {
            all_codewords[pos] = ec1[j];
            pos += 1;
            all_codewords[pos] = ec2[j];
            pos += 1;
        }
    }

    let total_cw = data_bytes + ec_bytes;

    // Build QR code (same matrix logic as byte mode)
    let mut qr = QrMatrix::new(version);
    qr.draw_function_patterns();
    qr.place_data(&all_codewords[..total_cw]);

    // Apply best mask
    let mut best_mask = 0u8;
    let mut best_penalty = u32::MAX;
    let saved_modules = Zeroizing::new(qr.modules);

    for mask in 0..8u8 {
        qr.modules = *saved_modules;
        qr.apply_mask(mask);
        qr.write_format_info(mask);

        let penalty = qr.penalty_score();
        if penalty < best_penalty {
            best_penalty = penalty;
            best_mask = mask;
        }
    }

    qr.modules = *saved_modules;
    qr.apply_mask(best_mask);
    qr.write_format_info(best_mask);

    Ok(qr)
}

// ═══════════════════════════════════════════════════════════════════
// BitWriter helper (no-alloc)
// ═══════════════════════════════════════════════════════════════════

struct BitWriter<'a> {
    buf: &'a mut [u8],
    bit_pos: usize,
}

impl<'a> BitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        // Zero the buffer
        for b in buf.iter_mut() {
            *b = 0;
        }
        Self { buf, bit_pos: 0 }
    }

    /// Write `count` low bits of `value`, most significant first.
    ///
    /// A bit past the buffer's end is dropped, though `bit_pos` advances, so
    /// sizing is the caller's. Both callers' 240 bytes hold version 9's 232
    /// data codewords, and no larger version gets this far: adding one to
    /// the capacity tables means growing those buffers too.
    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = (value >> i) & 1;
            let byte_idx = self.bit_pos / 8;
            let bit_idx = 7 - (self.bit_pos % 8);
            if byte_idx < self.buf.len() && bit != 0 {
                self.buf[byte_idx] |= 1 << bit_idx;
            }
            self.bit_pos += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::QrMatrix;

    /// Rule 3 finds `1:1:3:1:1` with four light modules on one side, the
    /// edge counting as light, and nothing else.
    #[test]
    fn rule_three_finds_finder_like_patterns() {
        let row = |cells: &[u8], at: u8| {
            let mut m = QrMatrix::new(1);
            for (i, &c) in cells.iter().enumerate() {
                m.set(at + i as u8, 10, c == 1);
            }
            m
        };
        let finder = [1, 0, 1, 1, 1, 0, 1];
        // In the middle of an empty row: light both sides.
        assert_eq!(row(&finder, 7).finder_like(10, true), 1);
        // Against the left edge: light past the edge.
        assert_eq!(row(&finder, 0).finder_like(10, true), 1);
        // Dark on both sides within four: not one.
        let boxed = [1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1];
        assert_eq!(row(&boxed, 5).finder_like(10, true), 0);
        // Light on one side is enough.
        let left_dark = [1, 0, 1, 0, 1, 1, 1, 0, 1];
        assert_eq!(row(&left_dark, 5).finder_like(10, true), 1);
        // Not the pattern.
        assert_eq!(row(&[1, 0, 1, 1, 0, 0, 1], 7).finder_like(10, true), 0);
        // The column through the same cells holds one dark module at most.
        assert_eq!(row(&finder, 7).finder_like(9, false), 0);
    }
}

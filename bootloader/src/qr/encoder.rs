// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// qr/encoder.rs — QR code generation (V1-V6)

// KasSigner — Minimal QR Code Encoder
// 100% Rust, no-std, no-alloc
//
// Generates QR codes for displaying signed transaction responses
// on the OLED display. Only supports what we need:
//
//   - Versions 1-4 (21x21 to 33x33 modules)
//   - Byte mode encoding
//   - Error correction level L (7% recovery)
//   - Automatic version selection based on data length
//
// Version capacities (Byte mode, ECC Level L):
//   V1: 17 bytes  (21x21)  — too small for us
//   V2: 32 bytes  (25x25)  — minimal single sig
//   V3: 53 bytes  (29x29)  — 1 signature (72 bytes needs V4)
//   V4: 78 bytes  (33x33)  — 1 signature comfortably
//   V5: 106 bytes (37x37)  — 2 signatures
//   V6: 134 bytes (41x41)  — 2+ signatures
//
// For KSSN response: 72 bytes = V4 (33x33)
// On 128x64 OLED: 33 modules * 1px = 33px, centered. Readable but tight.
// With 2px/module: 66px > 64px height. So V4 needs 1px/module.
// V3 at 2px/module = 58px, fits in 64px height nicely.
//
// Strategy: Use V4 at 1px/module for single sigs (72 bytes).
//
// QR Code structure (simplified):
// 1. Data encoding (byte mode)
// 2. Error correction (Reed-Solomon)
// 3. Module placement (finder patterns, timing, format info, data)
// 4. Masking (8 patterns evaluated, best selected)
// 5. Format information
// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

#![allow(dead_code)]
/// Maximum QR version we support
const MAX_VERSION: usize = 6;
/// Maximum modules per side (V6 = 41)
const MAX_SIZE: usize = 41;
/// Maximum total modules in bitmap
const MAX_MODULES: usize = MAX_SIZE * MAX_SIZE; // 1681
/// Bitmap stored as bytes (ceil(1681/8) = 211)
const BITMAP_BYTES: usize = (MAX_MODULES + 7) / 8;

/// Version info table: (version, size, data_codewords, ec_codewords, ec_blocks)
/// All for ECC Level L
const VERSION_TABLE: [(u8, u8, u16, u16, u8); 6] = [
    // ver, size, data_cw, ec_cw, ec_blocks
    (1, 21, 19, 7, 1),
    (2, 25, 34, 10, 1),
    (3, 29, 55, 15, 1),
    (4, 33, 80, 20, 1),
    (5, 37, 108, 26, 1),
    (6, 41, 136, 36, 2), // 2 blocks for V6
];

/// Byte mode capacity (ECC Level L) per version
const BYTE_CAPACITY: [usize; 6] = [17, 32, 53, 78, 106, 134];

// ═══════════════════════════════════════════════════════════════════
// Reed-Solomon GF(256) with primitive polynomial 0x11D
// ═══════════════════════════════════════════════════════════════════

/// GF(256) multiplication
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

/// Generate Reed-Solomon error correction codewords
/// generator polynomial for n EC codewords
fn rs_encode(data: &[u8], ec_count: usize, ec_out: &mut [u8]) {
    // Build generator polynomial in DESCENDING power order:
    // gen[0] = coefficient of x^n (always 1)
    // gen[1] = coefficient of x^(n-1)
    // ...
    // gen[n] = constant term
    //
    // g(x) = (x - α^0)(x - α^1)...(x - α^(n-1))
    // In GF(2), (x - α^i) = (x + α^i) since -1 = +1
    let mut gen = [0u8; 37]; // max 36 EC codewords + 1
    gen[0] = 1; // start with g(x) = 1 (leading coeff)

    for i in 0..ec_count {
        // Multiply current gen by (x + α^i)
        // New poly: gen[j]*x + gen[j]*α^i for each term
        // In descending order: new[j] = gen[j-1] + gen[j]*α^i
        let mut alpha_i = 1u8;
        for _ in 0..i {
            alpha_i = gf_mul(alpha_i, 2);
        }

        // Multiply from right to left to avoid overwriting
        let deg = i + 1; // new degree after multiplication
        gen[deg] = gf_mul(gen[deg - 1], alpha_i); // constant term
        for j in (1..deg).rev() {
            gen[j] = gen[j - 1] ^ gf_mul(gen[j], alpha_i);
        }
        gen[0] = gf_mul(gen[0], alpha_i); // Wait, gen[0] is x^n coeff
        // Actually: new[0] = old[0] * 1 (from x term) = old[0] 
        // No — multiplying by (x + α^i):
        // For coefficient of x^(deg): it comes from old x^(deg-1) * x = gen[0]
        // For coefficient of x^j where 0 < j < deg: gen[j-1] + gen[j]*α^i
        // For constant (x^0): gen[deg-1]*α^i

        // Let me redo this properly:
        // Save old gen
        // new[0] = gen[0]  (from gen[0]*x^deg term, the x factor raises power by 1)
        // Actually no. Let me think step by step.
    }

    // Ugh, let me just use the straightforward approach:
    // Start with gen = [1], build up by convolution
    let mut gen2 = [0u8; 37];
    gen2[0] = 1;
    let mut glen = 1usize; // current length of gen

    for i in 0..ec_count {
        let mut alpha_i = 1u8;
        for _ in 0..i {
            alpha_i = gf_mul(alpha_i, 2);
        }
        // Multiply gen by [1, α^i] representing (x + α^i) in descending power
        // g(x)*(x+r) where g = [g0,g1,...,gn] descending:
        //   new[0] = g[0]                   (from x * g0*x^n)
        //   new[j] = g[j] + g[j-1]*r       (for 1 <= j <= n)
        //   new[n+1] = g[n]*r              (constant term)
        let mut new_gen = [0u8; 37];
        new_gen[0] = gen2[0]; // leading coefficient unchanged
        for j in 1..glen {
            new_gen[j] = gen2[j] ^ gf_mul(gen2[j - 1], alpha_i);
        }
        new_gen[glen] = gf_mul(gen2[glen - 1], alpha_i); // new constant term
        glen += 1;
        gen2[..glen].copy_from_slice(&new_gen[..glen]);
    }

    // gen2[0..=ec_count] is now the generator in descending power
    // gen2[0] = 1 (x^ec_count), gen2[ec_count] = constant term

    // Polynomial division: D(x)*x^n mod g(x)
    let mut remainder = [0u8; 180];
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

/// QR Code bitmap with fixed-size storage
pub struct QrCode {
    /// Module data (dark = true)
    modules: [u8; BITMAP_BYTES],
    /// Which modules are "function patterns" (not data)
    is_function: [u8; BITMAP_BYTES],
    /// Size (modules per side)
    pub size: u8,
    /// Version (1-6)
    version: u8,
}

impl QrCode {
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
        /// Get the module (pixel) value at position (x, y).
pub fn get(&self, x: u8, y: u8) -> bool {
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

    /// Draw finder pattern (7x7) at given corner
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
        self.set_func(8, (4 * self.version + 9) as u8, true);

        // Alignment patterns (V2+)
        if self.version >= 2 {
            let positions = alignment_positions(self.version);
            let n = positions.0;
            for i in 0..n {
                for j in 0..n {
                    // Skip if overlaps with finder patterns
                    if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                        continue;
                    }
                    self.draw_alignment(positions.1[i] as u8, positions.1[j] as u8);
                }
            }
        }

        // Reserve format info areas (will be written later)
        // Around top-left finder
        for i in 0..9u8 {
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
                    6 => ((y as u16 * x as u16) % 2 + (y as u16 * x as u16) % 3) % 2 == 0,
                    7 => ((y + x) as u16 % 2 + (y as u16 * x as u16) % 3) % 2 == 0,
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

        // Rule 3: finder-like patterns (simplified)
        // Skip for performance on embedded - rules 1+2 are sufficient
        // for reasonable mask selection

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
        let dev = if pct >= 50 { pct - 50 } else { 50 - pct };
        penalty += (dev / 5) * 10;

        penalty
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
            (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8),
            (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0),
        ];

        for (i, &(x, y)) in coords_h.iter().enumerate() {
            let bit = (format_bits >> (14 - i)) & 1 != 0;
            self.set(x, y, bit);
        }

        // Place format bits around other finders
        let coords_v: [(u8, u8); 15] = [
            (8, s - 1), (8, s - 2), (8, s - 3), (8, s - 4), (8, s - 5), (8, s - 6), (8, s - 7),
            (s - 8, 8), (s - 7, 8), (s - 6, 8), (s - 5, 8), (s - 4, 8), (s - 3, 8), (s - 2, 8), (s - 1, 8),
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
        2 => { n = 2; positions = [6, 18, 0, 0, 0, 0, 0]; }
        3 => { n = 2; positions = [6, 22, 0, 0, 0, 0, 0]; }
        4 => { n = 2; positions = [6, 26, 0, 0, 0, 0, 0]; }
        5 => { n = 2; positions = [6, 30, 0, 0, 0, 0, 0]; }
        6 => { n = 2; positions = [6, 34, 0, 0, 0, 0, 0]; }
        _ => { n = 0; positions = [0; 7]; }
    }

    (n, positions)
}

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Error type
#[derive(Debug, PartialEq)]
pub enum QrError {
    DataTooLong,
    InternalError,
}

/// Select minimum QR version for given data length (byte mode, ECC L)
pub fn select_version(data_len: usize) -> Result<u8, QrError> {
    for (i, &cap) in BYTE_CAPACITY.iter().enumerate() {
        if data_len <= cap {
            return Ok((i + 1) as u8);
        }
    }
    Err(QrError::DataTooLong)
}

/// Encode data into QR code
pub fn encode(data: &[u8]) -> Result<QrCode, QrError> {
    let version = select_version(data.len())?;
    let vi = (version - 1) as usize;
    let (_, _, data_cw, ec_cw, ec_blocks) = VERSION_TABLE[vi];

    // ─── Step 1: Build data codewords ───────────────────────
    // Byte mode indicator (0100) + character count + data + terminator + padding
    let mut codewords = [0u8; 160]; // max data + EC for V6
    let mut bit_buf = BitWriter::new(&mut codewords);

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
    while bit_buf.bit_pos % 8 != 0 {
        bit_buf.write_bits(0, 1);
    }

    // Pad with alternating 0xEC, 0x11
    let mut pad_byte = 0;
    while bit_buf.bit_pos / 8 < data_cw as usize {
        bit_buf.write_bits(if pad_byte % 2 == 0 { 0xEC } else { 0x11 }, 8);
        pad_byte += 1;
    }

    // ─── Step 2: Error correction ───────────────────────────
    let data_bytes = data_cw as usize;
    let ec_bytes = ec_cw as usize;

    // For V1-5 (1 block): simple
    // For V6 (2 blocks): split data into 2 blocks
    let mut all_codewords = [0u8; 180];

    if ec_blocks == 1 {
        // Single block: data codewords + EC codewords
        all_codewords[..data_bytes].copy_from_slice(&codewords[..data_bytes]);
        let mut ec = [0u8; 37];
        rs_encode(&codewords[..data_bytes], ec_bytes, &mut ec);
        all_codewords[data_bytes..data_bytes + ec_bytes].copy_from_slice(&ec[..ec_bytes]);
    } else {
        // 2 blocks for V6
        // Block 1: data_bytes/2 data codewords, ec_bytes/2 EC
        // Block 2: remaining data codewords, ec_bytes/2 EC
        let block1_data = data_bytes / 2;
        let block2_data = data_bytes - block1_data;
        let block_ec = ec_bytes / 2;

        let mut ec1 = [0u8; 37];
        let mut ec2 = [0u8; 37];
        rs_encode(&codewords[..block1_data], block_ec, &mut ec1);
        rs_encode(&codewords[block1_data..data_bytes], block_ec, &mut ec2);

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

    // ─── Step 3: Build QR code ──────────────────────────────
    let mut qr = QrCode::new(version);

    // Draw function patterns
    qr.draw_function_patterns();

    // Place data
    qr.place_data(&all_codewords[..total_cw]);

    // ─── Step 4: Apply best mask ────────────────────────────
    let mut best_mask = 0u8;
    let mut best_penalty = u32::MAX;

    // Save unmasked data modules
    let saved_modules = qr.modules;

    for mask in 0..8u8 {
        qr.modules = saved_modules;
        qr.apply_mask(mask);
        qr.write_format_info(mask);

        let penalty = qr.penalty_score();
        if penalty < best_penalty {
            best_penalty = penalty;
            best_mask = mask;
        }
    }

    // Apply best mask
    qr.modules = saved_modules;
    qr.apply_mask(best_mask);
    qr.write_format_info(best_mask);

    Ok(qr)
}

// ═══════════════════════════════════════════════════════════════════
// Rendering to OLED
// ═══════════════════════════════════════════════════════════════════

use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
};

/// Render QR code onto an embedded_graphics display
/// scale: pixels per module (1 or 2)
/// ox, oy: offset from top-left corner of display
pub fn draw_qr<D>(
    display: &mut D,
    qr: &QrCode,
    scale: u8,
    ox: i32,
    oy: i32,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = BinaryColor>,
{
    let s = qr.size;
    let sc = scale as u32;

    // Quiet zone (1 module white border)
    // The display background is already black/off, so we draw white for "light" modules
    // QR standard: dark module = black, light module = white
    // On OLED: BinaryColor::On = white pixel

    // Draw quiet zone + QR
    let total = (s as u32 + 2) * sc; // +2 for quiet zone
    Rectangle::new(
        Point::new(ox - sc as i32, oy - sc as i32),
        Size::new(total, total),
    )
    .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
    .draw(display)?;

    // Draw dark modules as black pixels on top of white background
    for y in 0..s {
        for x in 0..s {
            if qr.get(x, y) {
                Rectangle::new(
                    Point::new(ox + x as i32 * sc as i32, oy + y as i32 * sc as i32),
                    Size::new(sc, sc),
                )
                .into_styled(PrimitiveStyle::with_fill(BinaryColor::Off))
                .draw(display)?;
            }
        }
    }

    Ok(())
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

    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = (value >> i) & 1;
            let byte_idx = self.bit_pos / 8;
            let bit_idx = 7 - (self.bit_pos % 8);
            if byte_idx < self.buf.len() {
                if bit != 0 {
                    self.buf[byte_idx] |= 1 << bit_idx;
                }
            }
            self.bit_pos += 1;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Self-tests
// ═══════════════════════════════════════════════════════════════════

/// Run QR encoder self-tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    // Test 1: Version selection
    {
        if select_version(17) == Ok(1)
            && select_version(32) == Ok(2)
            && select_version(72) == Ok(4)
            && select_version(200).is_err()
        {
            passed += 1;
        }
    }

    // Test 2: GF(256) multiplication sanity
    {
        // gf_mul(2, 2) = 4 (no reduction)
        // gf_mul(0, anything) = 0
        // gf_mul(1, x) = x
        let ok = gf_mul(0, 42) == 0
            && gf_mul(1, 42) == 42
            && gf_mul(2, 2) == 4
            && gf_mul(2, 128) != 0; // should trigger reduction
        if ok {
            passed += 1;
        }
    }

    // Test 3: Encode small data, verify QR dimensions
    {
        let data = b"KSSN"; // 4 bytes -> V1 (21x21)
        if let Ok(qr) = encode(data) {
            if qr.size == 21 && qr.version == 1 {
                // Verify finder pattern top-left corner
                // Module (0,0) should be dark (finder pattern)
                if qr.get(0, 0) && qr.get(6, 0) && qr.get(0, 6) {
                    passed += 1;
                }
            }
        }
    }

    // Test 4: Encode 72 bytes (typical KSSN response), verify V4
    {
        let mut data = [0u8; 72];
        // Simulate KSSN header
        data[0] = b'K';
        data[1] = b'S';
        data[2] = b'S';
        data[3] = b'N';
        data[4] = 0x01; // version
        data[5] = 0x01; // 1 signature
        // Fill rest with test pattern
        for i in 6..72 {
            data[i] = (i & 0xFF) as u8;
        }

        if let Ok(qr) = encode(&data) {
            if qr.size == 33 && qr.version == 4 {
                // Basic structure check: finders should be present
                let tl = qr.get(0, 0) && qr.get(6, 0) && qr.get(0, 6);
                let tr = qr.get(32, 0) && qr.get(26, 0) && qr.get(32, 6);
                let bl = qr.get(0, 32) && qr.get(6, 32) && qr.get(0, 26);
                if tl && tr && bl {
                    passed += 1;
                }
            }
        }
    }

    (passed, total)
}

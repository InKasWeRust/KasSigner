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

// qr/decoder.rs — QR code detection and decoding

// ═══════════════════════════════════════════════════════════════
// KasSigner — QR Code Decoder (no_std, no_alloc, pure Rust)
// ═══════════════════════════════════════════════════════════════
//
// Decodes QR codes V1-V8 (21×21 to 49×49) from 8-bit grayscale
// camera frames. Supports byte-mode payloads with ECC levels L/M.
//
// Pipeline:
//   1. Adaptive binarization (block-mean threshold)
//   2. Finder pattern detection (1:1:3:1:1 ratio scan)
//   3. Corner identification (TL / TR / BL via geometry)
//   4. Version estimation from finder spacing
//   5. Grid sampling via affine transform
//   6. Format info decode (BCH-15,5 with lookup)
//   7. Unmask data modules
//   8. Read codewords in QR zigzag order
//   9. De-interleave blocks (V6-V8)
//  10. Reed-Solomon error correction (Berlekamp-Massey)
//  11. Byte-mode payload extraction
//
// Memory: ~4KB stack (bit matrix + scratch), zero heap.
//
// Multi-frame: The caller accumulates frames externally. This
// module decodes one QR code from one grayscale image at a time.

/// Max QR version we decode
const MAX_VER: usize = 8;
/// Max modules per side (V8 = 49)
const MAX_SIDE: usize = 49;
/// Bitmap bytes for MAX_SIDE×MAX_SIDE
const BM_BYTES: usize = (MAX_SIDE * MAX_SIDE + 7) / 8;
/// Max payload we can return
pub const MAX_PAYLOAD: usize = 256;
/// Max finder candidates during scan
const MAX_FINDERS: usize = 24;

// ═══════════════════════════════════════════════════════════════
// Public types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq)]
/// QR decode errors.
pub enum DecodeError {
    NoFinders,
    BadGeometry,
    BadVersion,
    BadFormat,
    EccFailed,
    UnsupportedMode,
    DataOverflow,
}

/// Successfully decoded QR payload.
pub struct DecodeResult {
    pub data: [u8; MAX_PAYLOAD],
    pub len: usize,
}

// ═══════════════════════════════════════════════════════════════
// Version tables — ECC Level L and M, versions 1-8
// ═══════════════════════════════════════════════════════════════
//
// (total_codewords, data_codewords, ec_per_block, blocks_g1,
//  data_per_block_g1, blocks_g2, data_per_block_g2)

#[derive(Clone, Copy)]
struct VerInfo {
    total: u16,
    data: u16,
    ec_per_blk: u8,
    bg1: u8,
    dpb1: u8,
    bg2: u8,
    dpb2: u8,
}

// Level L
const VL: [VerInfo; 8] = [
    VerInfo { total: 26,  data: 19,  ec_per_blk: 7,  bg1: 1, dpb1: 19,  bg2: 0, dpb2: 0 },  // V1
    VerInfo { total: 44,  data: 34,  ec_per_blk: 10, bg1: 1, dpb1: 34,  bg2: 0, dpb2: 0 },  // V2
    VerInfo { total: 70,  data: 55,  ec_per_blk: 15, bg1: 1, dpb1: 55,  bg2: 0, dpb2: 0 },  // V3
    VerInfo { total: 100, data: 80,  ec_per_blk: 20, bg1: 1, dpb1: 80,  bg2: 0, dpb2: 0 },  // V4
    VerInfo { total: 134, data: 108, ec_per_blk: 26, bg1: 1, dpb1: 108, bg2: 0, dpb2: 0 },  // V5
    VerInfo { total: 172, data: 136, ec_per_blk: 18, bg1: 2, dpb1: 68,  bg2: 0, dpb2: 0 },  // V6
    VerInfo { total: 196, data: 156, ec_per_blk: 20, bg1: 2, dpb1: 78,  bg2: 0, dpb2: 0 },  // V7
    VerInfo { total: 242, data: 192, ec_per_blk: 24, bg1: 2, dpb1: 97,  bg2: 0, dpb2: 0 },  // V8
];

// Level M
const VM: [VerInfo; 8] = [
    VerInfo { total: 26,  data: 16, ec_per_blk: 10, bg1: 1, dpb1: 16, bg2: 0, dpb2: 0 },
    VerInfo { total: 44,  data: 28, ec_per_blk: 16, bg1: 1, dpb1: 28, bg2: 0, dpb2: 0 },
    VerInfo { total: 70,  data: 44, ec_per_blk: 26, bg1: 1, dpb1: 44, bg2: 0, dpb2: 0 },
    VerInfo { total: 100, data: 64, ec_per_blk: 18, bg1: 2, dpb1: 32, bg2: 0, dpb2: 0 },
    VerInfo { total: 134, data: 86, ec_per_blk: 24, bg1: 2, dpb1: 43, bg2: 0, dpb2: 0 },
    VerInfo { total: 172, data: 108,ec_per_blk: 16, bg1: 4, dpb1: 27, bg2: 0, dpb2: 0 },
    VerInfo { total: 196, data: 124,ec_per_blk: 18, bg1: 4, dpb1: 31, bg2: 0, dpb2: 0 },
    VerInfo { total: 242, data: 154,ec_per_blk: 22, bg1: 2, dpb1: 38, bg2: 2, dpb2: 39 },
];

// Level Q
const VQ: [VerInfo; 8] = [
    VerInfo { total: 26,  data: 13, ec_per_blk: 13, bg1: 1, dpb1: 13, bg2: 0, dpb2: 0 },  // V1
    VerInfo { total: 44,  data: 22, ec_per_blk: 22, bg1: 1, dpb1: 22, bg2: 0, dpb2: 0 },  // V2
    VerInfo { total: 70,  data: 34, ec_per_blk: 18, bg1: 2, dpb1: 17, bg2: 0, dpb2: 0 },  // V3
    VerInfo { total: 100, data: 48, ec_per_blk: 26, bg1: 2, dpb1: 24, bg2: 0, dpb2: 0 },  // V4
    VerInfo { total: 134, data: 62, ec_per_blk: 18, bg1: 2, dpb1: 15, bg2: 2, dpb2: 16 }, // V5
    VerInfo { total: 172, data: 76, ec_per_blk: 24, bg1: 4, dpb1: 19, bg2: 0, dpb2: 0 },  // V6
    VerInfo { total: 196, data: 88, ec_per_blk: 18, bg1: 2, dpb1: 14, bg2: 4, dpb2: 15 }, // V7
    VerInfo { total: 242, data: 110,ec_per_blk: 22, bg1: 4, dpb1: 14, bg2: 2, dpb2: 15 }, // V8
];

// Level H
const VH: [VerInfo; 8] = [
    VerInfo { total: 26,  data: 9,  ec_per_blk: 17, bg1: 1, dpb1: 9,  bg2: 0, dpb2: 0 },  // V1
    VerInfo { total: 44,  data: 16, ec_per_blk: 28, bg1: 1, dpb1: 16, bg2: 0, dpb2: 0 },  // V2
    VerInfo { total: 70,  data: 24, ec_per_blk: 22, bg1: 2, dpb1: 12, bg2: 0, dpb2: 0 },  // V3
    VerInfo { total: 100, data: 36, ec_per_blk: 16, bg1: 4, dpb1: 9,  bg2: 0, dpb2: 0 },  // V4
    VerInfo { total: 134, data: 46, ec_per_blk: 22, bg1: 2, dpb1: 11, bg2: 2, dpb2: 12 }, // V5
    VerInfo { total: 172, data: 60, ec_per_blk: 28, bg1: 4, dpb1: 15, bg2: 0, dpb2: 0 },  // V6
    VerInfo { total: 196, data: 66, ec_per_blk: 26, bg1: 4, dpb1: 13, bg2: 1, dpb2: 14 }, // V7
    VerInfo { total: 242, data: 86, ec_per_blk: 26, bg1: 4, dpb1: 14, bg2: 2, dpb2: 15 }, // V8
];

// Alignment pattern positions V1-V8
const ALIGN: [&[u8]; 8] = [
    &[],           // V1
    &[6, 18],      // V2
    &[6, 22],      // V3
    &[6, 26],      // V4
    &[6, 30],      // V5
    &[6, 34],      // V6
    &[6, 22, 38],  // V7
    &[6, 24, 42],  // V8
];

// ═══════════════════════════════════════════════════════════════
// Bit matrix (compact, stack-allocated)
// ═══════════════════════════════════════════════════════════════

struct BitMat {
    bits: [u8; BM_BYTES],
    side: usize,
}

impl BitMat {
    fn new(side: usize) -> Self {
        Self { bits: [0u8; BM_BYTES], side }
    }
    #[inline(always)]
    fn get(&self, x: usize, y: usize) -> bool {
        let i = y * self.side + x;
        (self.bits[i >> 3] >> (i & 7)) & 1 != 0
    }
    #[inline(always)]
    fn set(&mut self, x: usize, y: usize, v: bool) {
        let i = y * self.side + x;
        if v { self.bits[i >> 3] |= 1 << (i & 7); }
        else  { self.bits[i >> 3] &= !(1 << (i & 7)); }
    }
    #[inline(always)]
    fn flip(&mut self, x: usize, y: usize) {
        let i = y * self.side + x;
        self.bits[i >> 3] ^= 1 << (i & 7);
    }
}

// ═══════════════════════════════════════════════════════════════
// GF(256) arithmetic — shared with encoder (primitive poly 0x11D)
// ═══════════════════════════════════════════════════════════════

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { return 0; }
    let (mut r, mut aa, mut bb) = (0u16, a as u16, b);
    for _ in 0..8 {
        if bb & 1 != 0 { r ^= aa; }
        let hi = aa & 0x80 != 0;
        aa <<= 1;
        if hi { aa ^= 0x11D; }
        bb >>= 1;
    }
    r as u8
}

/// GF(256) power: a^n
fn gf_pow(mut a: u8, mut n: u8) -> u8 {
    if n == 0 { return 1; }
    let mut r = 1u8;
    loop {
        if n & 1 != 0 { r = gf_mul(r, a); }
        n >>= 1;
        if n == 0 { break; }
        a = gf_mul(a, a);
    }
    r
}

/// GF(256) inverse via Fermat's little theorem: a^254 = a^(-1)
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    gf_pow(a, 254)
}

// ═══════════════════════════════════════════════════════════════
// Reed-Solomon syndrome + error correction (Berlekamp-Massey)
// ═══════════════════════════════════════════════════════════════

/// Compute syndromes S_1..S_nsym for received message.
/// Evaluates r(α^i) for i = 0..nsym-1 (generator roots α^0..α^(nsym-1)).
fn rs_syndromes(msg: &[u8], nsym: usize, syn: &mut [u8]) {
    for i in 0..nsym {
        let alpha_i = gf_pow(2, i as u8);
        let mut val = 0u8;
        for &b in msg.iter() {
            val = gf_mul(val, alpha_i) ^ b;
        }
        syn[i] = val;
    }
}

/// Check if all syndromes are zero → no errors.
fn rs_check(syn: &[u8], nsym: usize) -> bool {
    for i in 0..nsym { if syn[i] != 0 { return false; } }
    true
}

/// Berlekamp-Massey to find error locator polynomial.
/// Returns degree of locator (= number of errors).
fn rs_berlekamp_massey(syn: &[u8], nsym: usize, sigma: &mut [u8; 64]) -> usize {
    // sigma = error locator polynomial, sigma[0]=1
    let mut old = [0u8; 64];
    for b in sigma.iter_mut() { *b = 0; }
    for b in old.iter_mut() { *b = 0; }
    sigma[0] = 1;
    old[0] = 1;

    let mut l = 0usize; // current degree
    let mut m = 1usize; // step

    for n in 0..nsym {
        // Compute discrepancy
        let mut delta = syn[n];
        for i in 1..=l {
            delta ^= gf_mul(sigma[i], syn[n.wrapping_sub(i)]);
        }

        if delta == 0 {
            m += 1;
        } else {
            let mut tmp = [0u8; 64];
            tmp[..nsym + 1].copy_from_slice(&sigma[..nsym + 1]);

            // sigma = sigma - delta * x^m * old
            let delta_inv_old = delta; // we multiply old by delta
            for i in 0..nsym + 1 - m {
                sigma[i + m] ^= gf_mul(delta_inv_old, old[i]);
            }

            if 2 * l <= n {
                l = n + 1 - l;
                // old = tmp / delta
                let inv = gf_inv(delta);
                for i in 0..nsym + 1 {
                    old[i] = gf_mul(tmp[i], inv);
                }
                m = 1;
            } else {
                m += 1;
            }
        }
    }
    l
}

/// Chien search: find error positions from locator polynomial.
fn rs_chien_search(sigma: &[u8; 64], n_errors: usize, msg_len: usize, positions: &mut [usize; 32]) -> usize {
    let mut found = 0usize;
    for i in 0..msg_len {
        // Evaluate sigma(α^(-i)) = sigma(α^(255-i))
        let x_inv = gf_pow(2, (255 - i as u16 % 255) as u8);
        let mut val = 1u8; // sigma[0] = 1
        let mut x_pow = 1u8;
        for j in 1..=n_errors {
            x_pow = gf_mul(x_pow, x_inv);
            val ^= gf_mul(sigma[j], x_pow);
        }
        if val == 0 {
            positions[found] = msg_len - 1 - i;
            found += 1;
            if found >= n_errors { break; }
        }
    }
    found
}

/// Compute error magnitudes directly from syndromes and error positions.
/// Solves the linear system: S_i = sum(e_j * α^(i*p_j)) for each syndrome i.
/// For small numbers of errors (1-3), this is fast and avoids Forney complexity.
fn rs_error_magnitudes(syn: &[u8], n_errors: usize, positions: &[usize; 32], msg: &mut [u8]) {
    if n_errors == 0 { return; }
    if n_errors > 16 { return; } // safety limit

    // Build N×(N+1) matrix: M[i][j] = α^(i * (msg_len-1-p_j)), augmented with S[i]
    // Syndrome S_i = Σ e_j · α^(i · (msg_len-1-p_j))
    // because the polynomial is evaluated as msg[0]*x^(n-1) + ... + msg[n-1]*x^0
    let n = n_errors;
    let msg_len = msg.len();
    let mut m = [[0u8; 17]; 16]; // max 16 errors × 17 columns

    for i in 0..n {
        for j in 0..n {
            let power = (i * (msg_len - 1 - positions[j])) % 255;
            m[i][j] = gf_pow(2, power as u8);
        }
        m[i][n] = syn[i]; // augmented column
    }

    // Gaussian elimination in GF(256)
    for col in 0..n {
        // Find pivot
        if m[col][col] == 0 {
            let mut found = false;
            for row in (col+1)..n {
                if m[row][col] != 0 {
                    // Swap rows
                    for k in 0..=n { let tmp = m[col][k]; m[col][k] = m[row][k]; m[row][k] = tmp; }
                    found = true;
                    break;
                }
            }
            if !found { return; } // singular
        }

        let inv = gf_inv(m[col][col]);
        for j in col..=n { m[col][j] = gf_mul(m[col][j], inv); }

        for row in 0..n {
            if row != col && m[row][col] != 0 {
                let f = m[row][col];
                for j in col..=n { m[row][j] ^= gf_mul(f, m[col][j]); }
            }
        }
    }

    // Apply corrections
    for i in 0..n {
        msg[positions[i]] ^= m[i][n];
    }
}

/// Full RS error correction on a codeword block (data + ec).
/// Corrects in-place. Returns Ok if corrected, Err if uncorrectable.
fn rs_correct(block: &mut [u8], ec_len: usize) -> Result<(), DecodeError> {
    rs_correct_with_erasures(block, ec_len, &[])
}

/// RS error correction with known erasure positions.
/// Erasures are byte positions in the block where the value is known to be unreliable.
/// RS can correct `e` errors and `f` erasures if `2e + f <= ec_len`.
fn rs_correct_with_erasures(block: &mut [u8], ec_len: usize, erasures: &[usize]) -> Result<(), DecodeError> {
    let nsym = ec_len;
    let n_erasures = erasures.len();

    // Quick check: if too many erasures alone, impossible
    if n_erasures > nsym {
        return Err(DecodeError::EccFailed);
    }

    let mut syn = [0u8; 48];
    rs_syndromes(block, nsym, &mut syn);

    if rs_check(&syn, nsym) {
        return Ok(()); // no errors at all
    }

    if n_erasures == 0 {
        // No erasures — standard error-only correction
        let mut sigma = [0u8; 64];
        let n_errors = rs_berlekamp_massey(&syn, nsym, &mut sigma);

        if n_errors == 0 || n_errors > nsym / 2 {
            return Err(DecodeError::EccFailed);
        }

        let mut positions = [0usize; 32];
        let found = rs_chien_search(&sigma, n_errors, block.len(), &mut positions);

        if found != n_errors {
            return Err(DecodeError::EccFailed);
        }

        rs_error_magnitudes(&syn, n_errors, &positions, block);
    } else {
        // Erasure + error correction
        // Step 1: Copy erasure positions into the right format
        let mut erase_pos = [0usize; 32];
        for i in 0..n_erasures.min(32) { erase_pos[i] = erasures[i]; }

        // Step 2: Solve erasure magnitudes directly (we know WHERE errors are)
        if n_erasures <= nsym {
            rs_error_magnitudes(&syn, n_erasures, &erase_pos, block);
            
            // Recheck syndromes after erasure correction
            rs_syndromes(block, nsym, &mut syn);
            if !rs_check(&syn, nsym) {
                // Still errors remaining — run standard BM+Chien for residual
                let mut sigma = [0u8; 64];
                let n_errors = rs_berlekamp_massey(&syn, nsym, &mut sigma);
                
                if n_errors == 0 || n_errors > (nsym - n_erasures) / 2 {
                    return Err(DecodeError::EccFailed);
                }
                
                let mut err_positions = [0usize; 32];
                let found = rs_chien_search(&sigma, n_errors, block.len(), &mut err_positions);
                
                if found != n_errors {
                    return Err(DecodeError::EccFailed);
                }
                
                rs_error_magnitudes(&syn, n_errors, &err_positions, block);
            }
        } else {
            return Err(DecodeError::EccFailed);
        }
    }

    // Verify
    rs_syndromes(block, nsym, &mut syn);
    if rs_check(&syn, nsym) { Ok(()) } else { Err(DecodeError::EccFailed) }
}

// ═══════════════════════════════════════════════════════════════
// Binarization — global Otsu threshold, computed once per frame
// ═══════════════════════════════════════════════════════════════
/// Compute optimal binary threshold using simplified Otsu's method.
/// Ignores pixels == 0 (zero-padded rows from camera crop).
fn compute_threshold(img: &[u8]) -> u8 {
    // Build histogram, skipping 0 (padding)
    let mut hist = [0u32; 256];
    let mut total = 0u32;
    for &p in img {
        if p > 0 {
            hist[p as usize] += 1;
            total += 1;
        }
    }
    if total == 0 { return 128; }

    // Compute total weighted sum
    let mut sum_all = 0u64;
    for i in 1..256u32 { sum_all += i as u64 * hist[i as usize] as u64; }

    // Otsu: iterate thresholds, find max inter-class variance
    let mut sum_bg = 0u64;
    let mut w_bg = 0u32;
    let mut best_thr = 128u8;
    let mut best_var = 0u64;

    for t in 1..255u32 {
        // Include bin t in background class FIRST
        w_bg += hist[t as usize];
        sum_bg += t as u64 * hist[t as usize] as u64;

        if w_bg == 0 { continue; }
        let w_fg = total - w_bg;
        if w_fg == 0 { break; }

        let sum_fg = sum_all - sum_bg;

        // Means (integer)
        let mean_bg = sum_bg / w_bg as u64;
        let mean_fg = sum_fg / w_fg as u64;
        let diff = mean_bg.abs_diff(mean_fg);

        // Variance = w_bg * w_fg * diff^2 (fits u64 for our image sizes)
        let var = (w_bg as u64) * (w_fg as u64) * diff * diff;
        if var > best_var {
            best_var = var;
            best_thr = t as u8;
        }
    }

    // best_thr is the last value in the "dark" class.
    // Place threshold at midpoint to the next occupied bin.
    let mut next = best_thr as usize + 1;
    while next < 256 && hist[next] == 0 {
        next += 1;
    }
    if next < 256 && next > best_thr as usize + 1 {
        ((best_thr as usize + next) / 2) as u8
    } else {
        // No gap — just add 1 so pixels AT best_thr are classified dark
        best_thr.saturating_add(1)
    }
}

/// Binarize pixel using pre-computed threshold.
#[inline(always)]
fn is_dark(img: &[u8], w: usize, x: usize, y: usize, thr: u8) -> bool {
    img[y * w + x] < thr
}

// ═══════════════════════════════════════════════════════════════
// Finder pattern detection
// ═══════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Default)]
struct Finder {
    cx: i32,  // center x ×256 (sub-pixel)
    cy: i32,  // center y ×256
    ms: u32,  // module size ×256
}

/// Check 5-element run-length for 1:1:3:1:1 ratio. Returns module_size×256 or 0.
/// 80% tolerance (slightly more generous than M5Stack's 75% for the noisier OV2640)
fn check_ratio(r: &[u32; 5]) -> u32 {
    let tot: u32 = r[0] + r[1] + r[2] + r[3] + r[4];
    if tot < 7 { return 0; }
    let m = (tot << 8) / 7; // module×256
    let tol = m * 4 / 5; // 80% tolerance
    for &v in &[r[0], r[1], r[3], r[4]] {
        let v256 = v << 8;
        if v256 + tol < m || v256 > m + tol { return 0; }
    }
    let c256 = r[2] << 8;
    let m3 = m * 3;
    if c256 + tol < m3 || c256 > m3 + tol { return 0; }
    m
}

/// Verify horizontal candidate with a vertical cross-scan.
/// Returns the true vertical center (pixel Y) or None.
#[inline(never)]
fn verify_vert(img: &[u8], w: usize, h: usize, px: usize, py: usize, thr: u8) -> Option<usize> {
    if px >= w || py >= h { return None; }
    if !is_dark(img, w, px, py, thr) { return None; }

    let mut r = [0u32; 5];
    // up from center (inclusive of py)
    let mut y = py as i32;
    while y >= 0 && is_dark(img, w, px, y as usize, thr) { r[2] += 1; y -= 1; }
    // y is now one above the top of the center dark region (or -1)
    while y >= 0 && !is_dark(img, w, px, y as usize, thr) { r[1] += 1; y -= 1; }
    while y >= 0 && is_dark(img, w, px, y as usize, thr) { r[0] += 1; y -= 1; }
    let top_edge = (y + 1) as u32; // top of outer dark ring

    // down from center (py was already counted above, start at py+1)
    y = py as i32 + 1;
    while (y as usize) < h && is_dark(img, w, px, y as usize, thr) { r[2] += 1; y += 1; }
    while (y as usize) < h && !is_dark(img, w, px, y as usize, thr) { r[3] += 1; y += 1; }
    while (y as usize) < h && is_dark(img, w, px, y as usize, thr) { r[4] += 1; y += 1; }

    if check_ratio(&r) > 0 {
        // True vertical center: top_edge + r[0] + r[1] + r[2]/2
        // This places the center at the middle of the central dark region
        let vc = top_edge + r[0] + r[1] + r[2] / 2;
        Some(vc as usize)
    } else {
        None
    }
}

/// Merge candidate with nearby existing one, or return false.
fn merge(finders: &mut [Finder; MAX_FINDERS], cnt: usize, f: Finder) -> bool {
    let thr = (f.ms as i32) * 2;
    for i in 0..cnt {
        if (finders[i].cx - f.cx).abs() < thr && (finders[i].cy - f.cy).abs() < thr {
            finders[i].cx = (finders[i].cx + f.cx) / 2;
            finders[i].cy = (finders[i].cy + f.cy) / 2;
            finders[i].ms = (finders[i].ms + f.ms) / 2;
            return true;
        }
    }
    false
}

/// Scan image for finder patterns. Returns number found.
#[inline(never)]
fn find_finders(img: &[u8], w: usize, h: usize, thr: u8, out: &mut [Finder; MAX_FINDERS]) -> usize {
    let mut cnt = 0usize;
    let step = 1usize; // 120 lines is small, scan all
    let mut y = 2;
    while y < h.saturating_sub(2) && cnt < MAX_FINDERS {
        let mut r = [0u32; 5];
        let mut ri = 0usize;
        let mut last = is_dark(img, w, 0, y, thr);
        r[0] = 1;

        for x in 1..w {
            let blk = is_dark(img, w, x, y, thr);
            if blk == last {
                r[ri] += 1;
            } else {
                if ri == 4 {
                    let ms = check_ratio(&r);
                    if ms > 0 {
                        let tot: u32 = r.iter().sum();
                        // x is at the START of the new run (just past end of r[4])
                        // Pattern starts at x - tot
                        // Center of central dark (r[2]): x - tot + r[0] + r[1] + r[2]/2
                        let cx_px = x as i32 - tot as i32 + r[0] as i32 + r[1] as i32 + (r[2] as i32) / 2;
                        if let Some(vy) = verify_vert(img, w, h, cx_px.max(0) as usize, y, thr) {
                            let f = Finder { cx: cx_px << 8, cy: (vy as i32) << 8, ms };
                            if !merge(out, cnt, f) && cnt < MAX_FINDERS {
                                out[cnt] = f;
                                cnt += 1;
                            }
                        }
                    }
                    // Shift by 1 run — standard approach to not miss overlapping patterns
                    r[0] = r[1];
                    r[1] = r[2];
                    r[2] = r[3];
                    r[3] = r[4];
                    r[4] = 1;
                    // ri stays at 4
                } else {
                    ri += 1;
                    r[ri] = 1;
                }
                last = blk;
            }
        }
        y += step;
    }
    cnt
}

// ═══════════════════════════════════════════════════════════════
// Corner identification
// ═══════════════════════════════════════════════════════════════

fn dist_sq(a: Finder, b: Finder) -> u64 {
    let dx = (a.cx - b.cx) as i64;
    let dy = (a.cy - b.cy) as i64;
    (dx * dx + dy * dy) as u64
}

fn isqrt64(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = 1u64 << ((64 - n.leading_zeros()) / 2);
    loop { let x1 = (x + n / x) / 2; if x1 >= x { return x; } x = x1; }
}

/// Pick best 3 finder triples and assign TL, TR, BL for each.
/// Returns up to 3 ranked triples (best geometry first).
#[inline(never)]
fn identify_corners_multi(f: &[Finder; MAX_FINDERS], cnt: usize, 
    results: &mut [(Finder, Finder, Finder); 3]) -> usize {
    if cnt < 3 { return 0; }

    // Score all triples
    #[derive(Clone, Copy)]
    struct Triple { a: usize, b: usize, c: usize, score: u64 }
    let mut triples = [Triple { a: 0, b: 0, c: 0, score: u64::MAX }; 3];
    let mut n_found = 0usize;

    let n = cnt.min(8);
    for a in 0..n {
        for b in (a + 1)..n {
            for c in (b + 1)..n {
                let ms_min = f[a].ms.min(f[b].ms).min(f[c].ms);
                let ms_max = f[a].ms.max(f[b].ms).max(f[c].ms);
                // Allow 3x module size variation
                if ms_min == 0 || ms_max > ms_min * 3 { continue; }

                let d = [dist_sq(f[a], f[b]), dist_sq(f[b], f[c]), dist_sq(f[a], f[c])];
                let mx = d[0].max(d[1]).max(d[2]);
                let mn = d[0].min(d[1]).min(d[2]);
                if mn == 0 { continue; }

                let score = mx.abs_diff(mn * 2);

                // Insert into top-3 if better than worst
                if n_found < 3 {
                    triples[n_found] = Triple { a, b, c, score };
                    n_found += 1;
                } else if score < triples[2].score {
                    triples[2] = Triple { a, b, c, score };
                }
                // Keep sorted (simple bubble for 3 elements)
                if n_found >= 2 && triples[1].score > triples[n_found - 1].score {
                    triples.swap(1, n_found - 1);
                }
                if n_found >= 2 && triples[0].score > triples[1].score {
                    triples.swap(0, 1);
                }
            }
        }
    }

    // Convert to (TL, TR, BL) triples
    for i in 0..n_found {
        let fa = f[triples[i].a]; let fb = f[triples[i].b]; let fc = f[triples[i].c];
        let d_ab = dist_sq(fa, fb);
        let d_bc = dist_sq(fb, fc);
        let d_ac = dist_sq(fa, fc);

        let (tl, mut tr, mut bl) = if d_ab >= d_bc && d_ab >= d_ac { (fc, fa, fb) }
            else if d_bc >= d_ab && d_bc >= d_ac { (fa, fb, fc) }
            else { (fb, fa, fc) };

        let ax = (tr.cx - tl.cx) as i64;
        let ay = (tr.cy - tl.cy) as i64;
        let bx = (bl.cx - tl.cx) as i64;
        let by = (bl.cy - tl.cy) as i64;
        let cross = ax * by - ay * bx;
        if cross < 0 {
            core::mem::swap(&mut tr, &mut bl);
        }

        // Sanity check: BL should not be nearly collinear with TL-TR
        // If |cross| is very small relative to distances, BL is likely wrong
        // In that case, estimate BL by rotating TL→TR by 90° clockwise
        let cross_abs = if cross < 0 { -cross } else { cross };
        let tl_tr_dist = dist_sq(tl, tr);
        let tl_bl_dist = dist_sq(tl, bl);
        // cross² / (|TL-TR| * |TL-BL|) should be ~1 for right angle
        // If < 0.25, it's nearly collinear → synthesize BL
        if tl_tr_dist > 0 && tl_bl_dist > 0 {
            let cross_sq = (cross_abs as u64).saturating_mul(cross_abs as u64);
            let dist_prod = tl_tr_dist.saturating_mul(tl_bl_dist);
            // cross_sq / dist_prod < 0.25 means nearly collinear
            if cross_sq.saturating_mul(4) < dist_prod {
                // Synthesize BL: rotate TL→TR by 90° CW: (dx,dy) → (dy,-dx)
                let dx = tr.cx - tl.cx;
                let dy = tr.cy - tl.cy;
                bl = Finder {
                    cx: tl.cx + dy,
                    cy: tl.cy - dx,
                    ms: (tl.ms + tr.ms) / 2,
                };
                // Recheck cross product orientation
                let bx2 = (bl.cx - tl.cx) as i64;
                let by2 = (bl.cy - tl.cy) as i64;
                if ax * by2 - ay * bx2 < 0 {
                    bl = Finder {
                        cx: tl.cx - dy,
                        cy: tl.cy + dx,
                        ms: (tl.ms + tr.ms) / 2,
                    };
                }
            }
        }

        results[i] = (tl, tr, bl);
    }
    n_found
}

// ═══════════════════════════════════════════════════════════════
// Version estimation + grid sampling
// ═══════════════════════════════════════════════════════════════

fn estimate_version(tl: Finder, tr: Finder, bl: Finder) -> Result<usize, DecodeError> {
    let d1 = isqrt64(dist_sq(tl, tr));
    let d2 = isqrt64(dist_sq(tl, bl));
    let avg_d = (d1 + d2) / 2; // pixels×256
    let avg_ms = (tl.ms as u64 + tr.ms as u64 + bl.ms as u64) / 3;
    if avg_ms == 0 { return Err(DecodeError::BadGeometry); }

    // Distance between finder centers = (side - 7) modules
    // side = 4*v + 17  →  v = (modules_between + 7 - 17) / 4 = (mb - 10) / 4
    let mb = avg_d / avg_ms; // modules between centers
    let v = ((mb as i32 - 10) + 2) / 4; // +2 = rounding
    if !(1..=MAX_VER as i32).contains(&v) { return Err(DecodeError::BadVersion); }
    Ok(v as usize)
}

/// Sample the QR grid from image using bilinear interpolation from 4 corners.
/// TL, TR, BL are from finder patterns. BR is estimated with optional offset.
#[inline(never)]
fn sample_grid(
    img: &[u8], w: usize, h: usize,
    tl: Finder, tr: Finder, bl: Finder,
    br_dx: i32, br_dy: i32,
    ver: usize, thr: u8, mat: &mut BitMat,
) -> Result<(), DecodeError> {
    let side = 4 * ver + 17;
    if side > MAX_SIDE { return Err(DecodeError::BadVersion); }
    mat.side = side;
    for b in mat.bits.iter_mut() { *b = 0; }

    let br_cx = tr.cx + bl.cx - tl.cx + br_dx;
    let br_cy = tr.cy + bl.cy - tl.cy + br_dy;

    let span = (side as i64 - 7) * 1024;
    let half = 3i64 * 1024 + 512;
    let span_sq_div = span * span / 256;

    for my in 0..side {
        let v = my as i64 * 1024 + 512 - half;
        for mx in 0..side {
            let u = mx as i64 * 1024 + 512 - half;
            let su = span - u;
            let sv = span - v;

            let px = (su * sv * (tl.cx as i64)
                    + u  * sv * (tr.cx as i64)
                    + su * v  * (bl.cx as i64)
                    + u  * v  * (br_cx as i64)) / span_sq_div;
            let py = (su * sv * (tl.cy as i64)
                    + u  * sv * (tr.cy as i64)
                    + su * v  * (bl.cy as i64)
                    + u  * v  * (br_cy as i64)) / span_sq_div;

            if px < 0 || py < 0 {
                mat.set(mx, my, false);
                continue;
            }
            let pxu = px as u64;
            let pyu = py as u64;
            let ix = (pxu >> 16) as usize;
            let iy = (pyu >> 16) as usize;
            let fx = (pxu & 0xFFFF) as i64;
            let fy = (pyu & 0xFFFF) as i64;

            let dark = if ix + 1 < w && iy + 1 < h {
                let p00 = img[iy * w + ix] as i64;
                let p10 = img[iy * w + ix + 1] as i64;
                let p01 = img[(iy + 1) * w + ix] as i64;
                let p11 = img[(iy + 1) * w + ix + 1] as i64;
                let s = 65536i64;
                let val = ((s - fx) * (s - fy) * p00
                         + fx * (s - fy) * p10
                         + (s - fx) * fy * p01
                         + fx * fy * p11) / (s * s);
                (val as u8) < thr
            } else if ix < w && iy < h {
                is_dark(img, w, ix, iy, thr)
            } else { false };
            mat.set(mx, my, dark);
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Format info reading
// ═══════════════════════════════════════════════════════════════

const FORMAT_MASK: u16 = 0b101010000010010;

/// Read format bits from around the top-left finder, decode BCH(15,5).
/// Returns (ecc_level, mask_pattern). ecc_level: 0=M, 1=L, 2=H, 3=Q
#[inline(never)]
fn read_format(mat: &BitMat) -> Result<(u8, u8), DecodeError> {
    let s = mat.side;
    if s < 21 { return Err(DecodeError::BadFormat); }

    // Read 15 format bits from around TL finder
    // Positions match the encoder's write_format_info coords_h
    let coords: [(usize, usize); 15] = [
        (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8),
        (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0),
    ];

    let mut raw = 0u16;
    for (i, &(x, y)) in coords.iter().enumerate() {
        if mat.get(x, y) {
            raw |= 1 << (14 - i);
        }
    }

    let bits = raw ^ FORMAT_MASK;

    // BCH(15,5) decoding — brute force (only 32 valid codewords)
    // Check all 32 valid format info values and pick closest Hamming distance
    let mut best_data = 0u8;
    let mut best_dist = 16u32;
    for d in 0u8..32 {
        let encoded = format_encode(d as u16);
        let dist = (bits ^ encoded).count_ones();
        if dist < best_dist {
            best_dist = dist;
            best_data = d;
        }
    }

    if best_dist > 3 {
        // Try reading from the other two format info locations
        // Around TR finder (horizontal) and BL finder (vertical)
        let mut raw2 = 0u16;
        let coords2: [(usize, usize); 15] = [
            (8, s - 1), (8, s - 2), (8, s - 3), (8, s - 4),
            (8, s - 5), (8, s - 6), (8, s - 7),
            (s - 8, 8), (s - 7, 8), (s - 6, 8), (s - 5, 8),
            (s - 4, 8), (s - 3, 8), (s - 2, 8), (s - 1, 8),
        ];
        for (i, &(x, y)) in coords2.iter().enumerate() {
            if mat.get(x, y) { raw2 |= 1 << (14 - i); }
        }
        let bits2 = raw2 ^ FORMAT_MASK;
        for d in 0u8..32 {
            let encoded = format_encode(d as u16);
            let dist = (bits2 ^ encoded).count_ones();
            if dist < best_dist { best_dist = dist; best_data = d; }
        }

        if best_dist > 3 { return Err(DecodeError::BadFormat); }
    }

    let ecc_level = (best_data >> 3) & 3; // bits 4-3
    let mask = best_data & 7;             // bits 2-0
    Ok((ecc_level, mask))
}

/// BCH(15,5) encode a 5-bit value (same as encoder).
fn format_encode(data: u16) -> u16 {
    let mut bits = data << 10;
    let gen = 0b10100110111u16;
    for i in (0..5).rev() {
        if bits & (1 << (i + 10)) != 0 { bits ^= gen << i; }
    }
    (data << 10) | bits
}

// ═══════════════════════════════════════════════════════════════
// Unmasking
// ═══════════════════════════════════════════════════════════════

/// Build function-pattern mask (finder, timing, alignment, format, dark module).
#[inline(never)]
fn build_func_mask(ver: usize, func: &mut BitMat) {
    let s = ver * 4 + 17;
    func.side = s;
    for b in func.bits.iter_mut() { *b = 0; }

    // Finders + separators (9×9 area at each corner)
    // TL: cols 0..8 × rows 0..8
    for y in 0..9usize { for x in 0..9usize { if x < s && y < s { func.set(x, y, true); } } }
    // TR: cols (s-8)..s × rows 0..8
    for y in 0..9usize { for x in (s.saturating_sub(8))..s { func.set(x, y, true); } }
    // BL: cols 0..8 × rows (s-8)..s
    for x in 0..9usize { for y in (s.saturating_sub(8))..s { func.set(x, y, true); } }

    // Format info reserved areas (must match encoder exactly)
    // Horizontal strip around TL: row 8, cols 0..8 — already covered by TL 9×9
    // Vertical strip around TL: col 8, rows 0..8 — already covered by TL 9×9
    // Horizontal strip around TR: row 8, cols (s-8)..s-1
    for i in 0..8usize {
        if s > i { func.set(s - 1 - i, 8, true); }
    }
    // Vertical strip around BL: col 8, rows (s-7)..s-1
    for i in 0..7usize {
        func.set(8, s - 1 - i, true);
    }

    // Timing patterns
    for i in 8..s.saturating_sub(8) {
        func.set(6, i, true);
        func.set(i, 6, true);
    }

    // Dark module
    func.set(8, (4 * ver + 9).min(s - 1), true);

    // Alignment patterns (V2+)
    if ver >= 2 && (ver - 1) < ALIGN.len() {
        let coords = ALIGN[ver - 1];
        let n = coords.len();
        for i in 0..n {
            for j in 0..n {
                // Skip overlap with finders
                if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                    continue;
                }
                let cx = coords[i] as usize;
                let cy = coords[j] as usize;
                for dy in 0..5usize {
                    for dx in 0..5usize {
                        let ax = cx + dx - 2;
                        let ay = cy + dy - 2;
                        if ax < s && ay < s { func.set(ax, ay, true); }
                    }
                }
            }
        }
    }

    // Version info (V7+) — two 6×3 blocks
    if ver >= 7 {
        for i in 0..6usize {
            for j in 0..3usize {
                func.set(i, s - 11 + j, true);
                func.set(s - 11 + j, i, true);
            }
        }
    }
}

/// Apply data mask (undo masking) to non-function modules.
#[inline(never)]
fn unmask(mat: &mut BitMat, func: &BitMat, mask: u8) {
    let s = mat.side;
    for y in 0..s {
        for x in 0..s {
            if func.get(x, y) { continue; }
            let invert = match mask {
                0 => (y + x) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (y + x) % 3 == 0,
                4 => (y / 2 + x / 3) % 2 == 0,
                5 => { let p = y * x; p % 2 + p % 3 == 0 },
                6 => { let p = y * x; (p % 2 + p % 3) % 2 == 0 },
                7 => { ((y + x) % 2 + (y * x) % 3) % 2 == 0 },
                _ => false,
            };
            if invert { mat.flip(x, y); }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Read codewords in QR zigzag order
// ═══════════════════════════════════════════════════════════════

/// Read all data+EC codewords from the matrix in the standard zigzag order.
/// Also marks codeword bytes that have modules in the center logo region as erasures.
/// `erasure_mask[i]` is true if codeword byte `i` has ≥4 bits in the logo region.
#[inline(never)]
fn read_codewords(mat: &BitMat, func: &BitMat, out: &mut [u8; 256], erasure_mask: &mut [bool; 256]) -> usize {
    let s = mat.side as i32;
    let mut bit_idx = 0usize;
    let mut byte_idx = 0usize;
    for b in out.iter_mut() { *b = 0; }
    for b in erasure_mask.iter_mut() { *b = false; }

    // Logo region: center ±3 modules (7×7 block in the middle)
    let center = s / 2;
    let logo_r = 6; // modules from center that a logo might cover

    let mut logo_bits_in_byte = 0u8;

    let mut right = s - 1;
    while right >= 0 {
        if right == 6 { right -= 1; continue; }
        let upward = ((s - 1 - right) / 2) % 2 == 0;

        for row_i in 0..s {
            let y = if upward { s - 1 - row_i } else { row_i };
            for dx in 0..2i32 {
                let x = right - dx;
                if x < 0 || x >= s || y < 0 || y >= s { continue; }
                let (xu, yu) = (x as usize, y as usize);
                if func.get(xu, yu) { continue; }

                if mat.get(xu, yu) {
                    out[byte_idx] |= 1 << (7 - (bit_idx & 7));
                }

                // Check if this module is in the logo region
                if (x - center).abs() <= logo_r && (y - center).abs() <= logo_r {
                    logo_bits_in_byte += 1;
                }

                bit_idx += 1;
                if bit_idx & 7 == 0 {
                    // Mark as erasure if any bits are in logo region
                    if logo_bits_in_byte >= 1 {
                        erasure_mask[byte_idx] = true;
                    }
                    logo_bits_in_byte = 0;
                    byte_idx += 1;
                    if byte_idx >= 256 { return byte_idx; }
                }
            }
        }
        right -= 2;
    }
    if bit_idx & 7 != 0 { byte_idx + 1 } else { byte_idx }
}

// ═══════════════════════════════════════════════════════════════
// De-interleave and error-correct
// ═══════════════════════════════════════════════════════════════

/// De-interleave codewords into blocks, RS-correct each block,
/// then reassemble the data codewords.
#[inline(never)]
fn deinterleave_and_correct(
    raw: &[u8; 256], vi: &VerInfo,
) -> Result<([u8; 256], usize), DecodeError> {
    let total_blocks = (vi.bg1 + vi.bg2) as usize;
    let ec_per = vi.ec_per_blk as usize;

    if total_blocks == 0 || total_blocks > 8 {
        return Err(DecodeError::EccFailed);
    }

    if total_blocks == 1 {
        // Simple: first data codewords, then EC codewords
        let data_len = vi.dpb1 as usize;
        let block_len = data_len + ec_per;
        let mut block = [0u8; 256];
        block[..block_len].copy_from_slice(&raw[..block_len]);
        rs_correct(&mut block[..block_len], ec_per)?;
        let mut out = [0u8; 256];
        out[..data_len].copy_from_slice(&block[..data_len]);
        return Ok((out, vi.data as usize));
    }

    // Multi-block: need to de-interleave data codewords and EC codewords
    // Data codewords are interleaved: block0[0], block1[0], ..., block0[1], block1[1], ...
    // If blocks have different lengths (bg2 > 0), shorter blocks come first
    let b1 = vi.bg1 as usize;
    let d1 = vi.dpb1 as usize;
    let _b2 = vi.bg2 as usize;
    let d2 = vi.dpb2 as usize;
    let max_d = d1.max(d2);

    // Extract data codewords per block
    let mut blocks: [[u8; 128]; 8] = [[0u8; 128]; 8]; // max 8 blocks (ECC-Q/H)
    let mut pos = 0usize;
    for col in 0..max_d {
        for blk in 0..total_blocks {
            let blk_data_len = if blk < b1 { d1 } else { d2 };
            if col < blk_data_len {
                blocks[blk][col] = raw[pos];
                pos += 1;
            }
        }
    }

    // Extract EC codewords per block (also interleaved)
    for col in 0..ec_per {
        for blk in 0..total_blocks {
            let blk_data_len = if blk < b1 { d1 } else { d2 };
            blocks[blk][blk_data_len + col] = raw[pos];
            pos += 1;
        }
    }

    // RS-correct each block
    for blk in 0..total_blocks {
        let blk_data_len = if blk < b1 { d1 } else { d2 };
        let blk_total = blk_data_len + ec_per;
        rs_correct(&mut blocks[blk][..blk_total], ec_per)?;
    }

    // Reassemble data codewords in order
    let mut out = [0u8; 256];
    let mut op = 0usize;
    for blk in 0..total_blocks {
        let blk_data_len = if blk < b1 { d1 } else { d2 };
        out[op..op + blk_data_len].copy_from_slice(&blocks[blk][..blk_data_len]);
        op += blk_data_len;
    }
    Ok((out, vi.data as usize))
}

/// De-interleave with erasure tracking from logo detection.
/// Maps the raw erasure_mask through the interleaving to per-block erasure positions.
#[inline(never)]
fn deinterleave_and_correct_erasures(
    raw: &[u8; 256], erasure_mask: &[bool; 256], vi: &VerInfo,
) -> Result<([u8; 256], usize), DecodeError> {
    let total_blocks = (vi.bg1 + vi.bg2) as usize;
    let ec_per = vi.ec_per_blk as usize;

    if total_blocks == 0 || total_blocks > 8 {
        return Err(DecodeError::EccFailed);
    }

    // Use erasure-aware correction if any erasures detected
    let has_erasures = erasure_mask.iter().any(|&e| e);
    if !has_erasures {
        return deinterleave_and_correct(raw, vi);
    }

    if total_blocks == 1 {
        let data_len = vi.dpb1 as usize;
        let block_len = data_len + ec_per;
        let mut block = [0u8; 256];
        block[..block_len].copy_from_slice(&raw[..block_len]);
        // Collect erasure positions for this block
        let mut erasures = [0usize; 32];
        let mut ne = 0usize;
        for i in 0..block_len {
            if erasure_mask[i] && ne < 32 {
                erasures[ne] = i;
                ne += 1;
            }
        }
        rs_correct_with_erasures(&mut block[..block_len], ec_per, &erasures[..ne])?;
        let mut out = [0u8; 256];
        out[..data_len].copy_from_slice(&block[..data_len]);
        return Ok((out, vi.data as usize));
    }

    // Multi-block with erasure tracking
    let b1 = vi.bg1 as usize;
    let d1 = vi.dpb1 as usize;
    let _b2 = vi.bg2 as usize;
    let d2 = vi.dpb2 as usize;
    let max_d = d1.max(d2);

    let mut blocks: [[u8; 128]; 8] = [[0u8; 128]; 8];
    let mut block_erasures: [[usize; 32]; 8] = [[0usize; 32]; 8];
    let mut block_ne: [usize; 8] = [0usize; 8];

    // Extract data codewords per block with erasure tracking
    let mut pos = 0usize;
    for col in 0..max_d {
        for blk in 0..total_blocks {
            let blk_data_len = if blk < b1 { d1 } else { d2 };
            if col < blk_data_len {
                blocks[blk][col] = raw[pos];
                if erasure_mask[pos] && block_ne[blk] < 32 {
                    block_erasures[blk][block_ne[blk]] = col;
                    block_ne[blk] += 1;
                }
                pos += 1;
            }
        }
    }

    // Extract EC codewords per block with erasure tracking
    for col in 0..ec_per {
        for blk in 0..total_blocks {
            let blk_data_len = if blk < b1 { d1 } else { d2 };
            blocks[blk][blk_data_len + col] = raw[pos];
            if erasure_mask[pos] && block_ne[blk] < 32 {
                block_erasures[blk][block_ne[blk]] = blk_data_len + col;
                block_ne[blk] += 1;
            }
            pos += 1;
        }
    }

    // RS-correct each block with erasures
    for blk in 0..total_blocks {
        let blk_data_len = if blk < b1 { d1 } else { d2 };
        let blk_total = blk_data_len + ec_per;
        rs_correct_with_erasures(
            &mut blocks[blk][..blk_total], ec_per,
            &block_erasures[blk][..block_ne[blk]]
        )?;
    }

    // Reassemble
    let mut out = [0u8; 256];
    let mut op = 0usize;
    for blk in 0..total_blocks {
        let blk_data_len = if blk < b1 { d1 } else { d2 };
        out[op..op + blk_data_len].copy_from_slice(&blocks[blk][..blk_data_len]);
        op += blk_data_len;
    }
    Ok((out, vi.data as usize))
}

// ═══════════════════════════════════════════════════════════════
// Payload extraction (byte mode + alphanumeric mode)
// ═══════════════════════════════════════════════════════════════

fn extract_payload(data_cw: &[u8], data_len: usize, result: &mut DecodeResult) -> Result<(), DecodeError> {
    if data_len < 2 { return Err(DecodeError::DataOverflow); }

    // Read mode indicator (4 bits)
    let mode = (data_cw[0] >> 4) & 0x0F;

    if mode == 0b0001 {
        // ── Numeric mode ──
        // Character count: 10 bits for V1-9
        let count = read_bits(data_cw, 4, 10) as usize;

        if count > MAX_PAYLOAD {
            return Err(DecodeError::DataOverflow);
        }

        // Data starts at bit 14 (4 mode + 10 count)
        // Digits in groups of 3: each group = 10 bits → value 0-999
        // Remainder 2 digits = 7 bits, 1 digit = 4 bits
        let mut bit_pos = 14usize;
        let mut out_pos = 0usize;
        let full_groups = count / 3;
        let remainder = count % 3;

        for _ in 0..full_groups {
            let val = read_bits(data_cw, bit_pos, 10) as usize;
            bit_pos += 10;
            let d0 = (val / 100) as u8;
            let d1 = ((val / 10) % 10) as u8;
            let d2 = (val % 10) as u8;
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + d0; out_pos += 1; }
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + d1; out_pos += 1; }
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + d2; out_pos += 1; }
        }
        if remainder == 2 {
            let val = read_bits(data_cw, bit_pos, 7) as usize;
            let d0 = (val / 10) as u8;
            let d1 = (val % 10) as u8;
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + d0; out_pos += 1; }
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + d1; out_pos += 1; }
        } else if remainder == 1 {
            let val = read_bits(data_cw, bit_pos, 4) as usize;
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = b'0' + val as u8; out_pos += 1; }
        }
        result.len = out_pos;
        Ok(())
    } else if mode == 0b0100 {
        // ── Byte mode ──
        // Character count: 8 bits for V1-9
        let char_count = ((data_cw[0] & 0x0F) << 4) | (data_cw[1] >> 4);
        let count = char_count as usize;

        if count > MAX_PAYLOAD || count > data_len - 1 {
            return Err(DecodeError::DataOverflow);
        }

        // Data starts at bit position 12 (4 mode + 8 count)
        for i in 0..count {
            let bit_off = 12 + i * 8;
            let byte_off = bit_off / 8;
            let shift = bit_off % 8;

            if byte_off + 1 < data_len {
                result.data[i] = (data_cw[byte_off] << shift) | (data_cw[byte_off + 1] >> (8 - shift));
            } else if byte_off < data_len {
                result.data[i] = data_cw[byte_off] << shift;
            }
        }
        result.len = count;
        Ok(())
    } else if mode == 0b0010 {
        // ── Alphanumeric mode ──
        // Character count: 9 bits for V1-9
        // Bits 4..12 = count (9 bits)
        let count = (read_bits(data_cw, 4, 9)) as usize;

        if count > MAX_PAYLOAD {
            return Err(DecodeError::DataOverflow);
        }

        // Data starts at bit position 13 (4 mode + 9 count)
        // Characters encoded in pairs: each pair = 11 bits → val = c1*45 + c2
        // Last odd character = 6 bits
        let mut bit_pos = 13usize;
        let mut out_pos = 0usize;
        let pairs = count / 2;
        for _ in 0..pairs {
            let val = read_bits(data_cw, bit_pos, 11) as usize;
            bit_pos += 11;
            let c1 = val / 45;
            let c2 = val % 45;
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = alphanumeric_char(c1); out_pos += 1; }
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = alphanumeric_char(c2); out_pos += 1; }
        }
        if count & 1 != 0 {
            let val = read_bits(data_cw, bit_pos, 6) as usize;
            if out_pos < MAX_PAYLOAD { result.data[out_pos] = alphanumeric_char(val); out_pos += 1; }
        }
        result.len = out_pos;
        Ok(())
    } else {
        Err(DecodeError::UnsupportedMode)
    }
}

/// Read `nbits` (1-16) from codeword array starting at `bit_offset`.
fn read_bits(data: &[u8], bit_offset: usize, nbits: usize) -> u16 {
    let mut val = 0u16;
    for i in 0..nbits {
        let pos = bit_offset + i;
        let byte_idx = pos / 8;
        let bit_idx = 7 - (pos % 8);
        if byte_idx < data.len() && (data[byte_idx] >> bit_idx) & 1 != 0 {
            val |= 1 << (nbits - 1 - i);
        }
    }
    val
}

/// Map alphanumeric mode index to ASCII character.
/// 0-9 → '0'-'9', 10-35 → 'A'-'Z', 36-44 → SP,$,%,*,+,-,.,/,:
fn alphanumeric_char(idx: usize) -> u8 {
    const ALPHA_TABLE: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    if idx < 45 { ALPHA_TABLE[idx] } else { b'?' }
}

// ═══════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// Alignment pattern search for BR corner refinement (V2+)
// ═══════════════════════════════════════════════════════════════

/// Check if position (cx, cy) in the image looks like an alignment pattern center.
/// An alignment pattern is a 5×5 module region: dark ring, white ring, dark center.
/// Returns a quality score (lower = better match), or u32::MAX if not a match.
fn alignment_score(img: &[u8], w: usize, h: usize, cx: i32, cy: i32, ms: i32, thr: u8) -> u32 {
    // Check 5 points along horizontal and vertical: center, ±1 module, ±2 modules
    // Pattern: dark(±2), white(±1), dark(0), white(±1), dark(±2)
    // ms is module size in ×256 fixed point; we work in pixels
    let ms_px = (ms + 128) >> 8; // module size in pixels, rounded
    if ms_px < 1 { return u32::MAX; }

    let checks: [(i32, i32, bool); 9] = [
        (0, 0, true),           // center: dark
        (ms_px, 0, false),      // right 1 mod: white
        (-ms_px, 0, false),     // left 1 mod: white
        (0, ms_px, false),      // down 1 mod: white
        (0, -ms_px, false),     // up 1 mod: white
        (2*ms_px, 0, true),     // right 2 mod: dark
        (-2*ms_px, 0, true),    // left 2 mod: dark
        (0, 2*ms_px, true),     // down 2 mod: dark
        (0, -2*ms_px, true),    // up 2 mod: dark
    ];

    let mut score = 0u32;
    for &(dx, dy, expect_dark) in &checks {
        let px = cx + dx;
        let py = cy + dy;
        if px < 0 || py < 0 || px as usize >= w || py as usize >= h {
            return u32::MAX;
        }
        let val = img[py as usize * w + px as usize];
        let dark = val < thr;
        if dark != expect_dark {
            score += 100; // penalty per wrong polarity
        }
        // Also add distance from threshold as a tie-breaker
        if expect_dark {
            if val >= thr { score += (val - thr) as u32; }
        } else {
            if val < thr { score += (thr - val) as u32; }
        }
    }
    score
}

/// Compute pixel position of a module center using the bilinear model.
/// Returns (px, py) in ×256 fixed point.
fn module_to_pixel(
    tl: Finder, tr: Finder, bl: Finder,
    br_cx: i32, br_cy: i32,
    mx: usize, my: usize, side: usize,
) -> (i32, i32) {
    let span = (side as i64 - 7) * 1024;
    let half = 3i64 * 1024 + 512; // 3.5 modules in ×1024
    let u = mx as i64 * 1024 + 512 - half;
    let v = my as i64 * 1024 + 512 - half;
    let su = span - u;
    let sv = span - v;

    let px = (su * sv * (tl.cx as i64)
            + u  * sv * (tr.cx as i64)
            + su * v  * (bl.cx as i64)
            + u  * v  * (br_cx as i64)) / (span * span / 256);
    let py = (su * sv * (tl.cy as i64)
            + u  * sv * (tr.cy as i64)
            + su * v  * (bl.cy as i64)
            + u  * v  * (br_cy as i64)) / (span * span / 256);
    // Result is in ×65536 (×256 from coords × ×256 from division).
    // Convert to ×256: divide by 256
    ((px / 256) as i32, (py / 256) as i32)
}

/// Search for alignment pattern near predicted position and compute BR correction.
/// Returns (br_dx, br_dy) offset in ×256 fixed point, or (0,0) if not found.
#[inline(never)]
fn find_alignment_correction(
    img: &[u8], w: usize, h: usize, thr: u8,
    tl: Finder, tr: Finder, bl: Finder,
    ver: usize,
) -> (i32, i32) {
    if !(2..=MAX_VER).contains(&ver) { return (0, 0); }
    let side = 4 * ver + 17;
    let coords = ALIGN[ver - 1];
    if coords.len() < 2 { return (0, 0); }

    // For V2-V6 (2 alignment coords), the single alignment pattern is at
    // (coords[last], coords[last]) — the bottom-right one (skip finder overlaps).
    // For V7-V8 (3 coords), there are multiple alignment patterns; use the BR-most.
    let n = coords.len();
    let ax = coords[n - 1] as usize; // e.g., V4: 26
    let ay = coords[n - 1] as usize;

    // Parallelogram BR estimate (no offset)
    let br_cx0 = tr.cx + bl.cx - tl.cx;
    let br_cy0 = tr.cy + bl.cy - tl.cy;

    // Predict alignment center in pixel space using parallelogram model
    let (pred_px, pred_py) = module_to_pixel(tl, tr, bl, br_cx0, br_cy0, ax, ay, side);
    // pred_px, pred_py are in ×256

    // Module size (average of finders) in ×256
    let ms = ((tl.ms as i32) + (tr.ms as i32) + (bl.ms as i32)) / 3;
    let ms_px = (ms + 128) >> 8; // pixels

    // Search window: ±3 modules around prediction
    let search = (ms_px * 3).max(6);
    let pred_x = (pred_px + 128) >> 8; // pixel coords
    let pred_y = (pred_py + 128) >> 8;

    let mut best_score = u32::MAX;
    let mut best_x = pred_x;
    let mut best_y = pred_y;

    // Search in integer pixel steps
    let x0 = (pred_x - search).max(2);
    let x1 = (pred_x + search).min(w as i32 - 3);
    let y0 = (pred_y - search).max(2);
    let y1 = (pred_y + search).min(h as i32 - 3);

    let mut y = y0;
    while y <= y1 {
        let mut x = x0;
        while x <= x1 {
            let s = alignment_score(img, w, h, x, y, ms, thr);
            if s < best_score {
                best_score = s;
                best_x = x;
                best_y = y;
            }
            x += 1;
        }
        y += 1;
    }

    // Only use correction if we found a reasonable alignment pattern
    // Score of 0 = perfect match; anything > 400 is probably noise
    if best_score > 400 {
        return (0, 0);
    }

    // Found alignment at (best_x, best_y) in integer pixels.
    // Predicted was at (pred_px, pred_py) in ×256 fixed point.
    // Use ×256 displacement for sub-pixel precision in BR correction.
    let dx_256 = (best_x << 8) - pred_px; // displacement in ×256
    let dy_256 = (best_y << 8) - pred_py;

    // Compute BR correction from alignment displacement.
    // delta_BR (×256) = delta_pixel (×256) * span^2 / (u * v)
    // delta_pixel is already in ×256, result is also in ×256
    let span = (side as i64 - 7) * 1024;
    let half = 3i64 * 1024 + 512;
    let u_align = ax as i64 * 1024 + 512 - half;
    let v_align = ay as i64 * 1024 + 512 - half;

    if u_align == 0 || v_align == 0 { return (0, 0); }

    let br_dx = ((dx_256 as i64) * span * span / (u_align * v_align)) as i32;
    let br_dy = ((dy_256 as i64) * span * span / (u_align * v_align)) as i32;

    // Sanity: if correction is huge (> 5 modules), reject it
    let max_corr = ms * 5;
    if br_dx.abs() > max_corr || br_dy.abs() > max_corr {
        return (0, 0);
    }

    (br_dx, br_dy)
}

/// Try to decode a QR from a sampled grid at a given version.
/// Tries both ECC levels L and M.
#[inline(never)]
fn try_decode_grid(
    img: &[u8], w: usize, h: usize,
    tl: Finder, tr: Finder, bl: Finder,
    ver: usize, thr: u8,
) -> Result<DecodeResult, DecodeError> {
    let side = 4 * ver + 17;
    if side > MAX_SIDE || !(1..=MAX_VER).contains(&ver) { return Err(DecodeError::BadVersion); }

    // Try normal corners and swapped TR/BL (for mirrored camera image)
    let corner_sets: [(Finder, Finder, Finder); 2] = [
        (tl, tr, bl),  // normal
        (tl, bl, tr),  // swapped TR/BL (mirrored image)
    ];

    let last_err = DecodeError::EccFailed;

    // BR estimated as parallelogram: BR = TR + BL - TL
    // For V2+, alignment pattern search refines the BR estimate to correct
    // perspective distortion that causes grid errors at higher versions.

    for &(c_tl, c_tr, c_bl) in &corner_sets {
        // Build offset list: (0,0) first, then alignment-corrected, then BR nudges
        // The parallelogram BR estimate can be off by ~0.5 modules due to perspective.
        // Try small offsets to find the sweet spot.
        let avg_ms = ((c_tl.ms as i32 + c_tr.ms as i32 + c_bl.ms as i32) / 3).max(128);
        let half_mod = avg_ms / 2; // half module in ×256 fixed point

        let mut offsets: [(i32, i32); 6] = [(0, 0); 6];
        let mut n_offsets = 1usize;
        // Alignment pattern correction (V2+)
        if ver >= 2 {
            let (adx, ady) = find_alignment_correction(img, w, h, thr, c_tl, c_tr, c_bl, ver);
            if adx != 0 || ady != 0 {
                offsets[n_offsets] = (adx, ady);
                n_offsets += 1;
            }
        }
        // Single BR nudge: inward diagonal (most common perspective error direction)
        offsets[n_offsets] = (half_mod, half_mod); n_offsets += 1;

        let mut oi = 0usize;
        while oi < n_offsets {
            let (br_dx, br_dy) = offsets[oi];
            oi += 1;

            let mut mat = BitMat::new(side);
            if sample_grid(img, w, h, c_tl, c_tr, c_bl, br_dx, br_dy, ver, thr, &mut mat).is_err() {
                continue;
            }

        let _saved = mat.bits;

        // No flip loop — camera image is consistent orientation
        {
            if let Ok((ecc_level, mask)) = read_format(&mat) {
                let mut func = BitMat::new(side);
                build_func_mask(ver, &mut func);

                let mat_before_unmask = mat.bits;
                unmask(&mut mat, &func, mask);

                let mut raw_cw = [0u8; 256];
                let mut erasure_mask = [false; 256];
                let _ = read_codewords(&mat, &func, &mut raw_cw, &mut erasure_mask);

                // Store diagnostics
                unsafe {
                    LAST_RAW0 = raw_cw[0];
                    LAST_RAW1 = raw_cw[1];
                    LAST_ECC = ecc_level;
                    LAST_MASK = mask;
                    LAST_VER = ver as u8;
                    LAST_ERASURES = erasure_mask.iter().filter(|&&e| e).count() as u8;
                }

                // ecc_level from format info: 0=M, 1=L, 2=H, 3=Q
                // Try detected level first, then L as fallback (most common)
                let tbl_detected: &[VerInfo; 8] = match ecc_level {
                    1 => &VL, 0 => &VM, 3 => &VQ, _ => &VH,
                };
                let tables: [&[VerInfo; 8]; 2] = if ecc_level == 1 {
                    [&VL, &VM] // L detected, try M as fallback
                } else {
                    [tbl_detected, &VL] // Other detected, try L as fallback
                };

                for tbl in &tables {
                    let vi = &tbl[ver - 1];
                    if let Ok((data_cw, data_len)) = deinterleave_and_correct_erasures(&raw_cw, &erasure_mask, vi) {
                        let mut result = DecodeResult { data: [0u8; MAX_PAYLOAD], len: 0 };
                        if extract_payload(&data_cw, data_len, &mut result).is_ok() && result.len > 0 {
                            // Validate: either printable ASCII or known binary format
                            let check_len = result.len.min(8);
                            let is_ascii = result.data[..check_len].iter()
                                .all(|&b| (0x20..0x7F).contains(&b));
                            // Known binary: KSPT at byte 0 or at byte 3 (multi-frame)
                            let is_kspt = result.len >= 4 && &result.data[..4] == b"KSPT";
                            let is_multiframe_kspt = result.len >= 7
                                && result.data[1] >= 2 && result.data[1] <= 8
                                && result.data[0] < result.data[1]
                                && (result.data[0] > 0 || &result.data[3..7] == b"KSPT");
                            let is_kssn = result.len >= 4 && &result.data[..4] == b"KSSN";
                            if is_ascii || is_kspt || is_multiframe_kspt || is_kssn {
                                return Ok(result);
                            }
                        }
                    }
                }

                // RS failed — try direct extraction (only on first offset, byte mode only)
                // Bypass validates that result looks like printable ASCII to avoid
                // returning garbage from alphanumeric-encoded QRs
                if oi <= 1 {
                    let vi_table: &[VerInfo; 8] = match ecc_level {
                        1 => &VL, 0 => &VM, 3 => &VQ, _ => &VH,
                    };
                    let vi = &vi_table[ver - 1];
                    let data_len = vi.data as usize;
                    let first_nibble = (raw_cw[0] >> 4) & 0x0F;
                    // Only bypass for byte mode (0100) or numeric mode (0001)
                    if first_nibble == 0b0100 || first_nibble == 0b0001 {
                        let mut result = DecodeResult { data: [0u8; MAX_PAYLOAD], len: 0 };
                        if extract_payload(&raw_cw, data_len, &mut result).is_ok() && result.len > 0 {
                            // Validate: printable ASCII, known binary prefix, all digits, or CompactSeedQR
                            let valid_ascii = result.len >= 4
                                && result.data[..4].iter().all(|&b| (0x20..0x7F).contains(&b));
                            let valid_numeric = (result.len == 48 || result.len == 96)
                                && result.data[..result.len].iter().all(|&b| b.is_ascii_digit());
                            let valid_compact_seedqr = result.len == 16 || result.len == 32;
                            let valid_bin = result.len >= 4
                                && (&result.data[..4] == b"KSPT" || &result.data[..4] == b"KSSN"
                                    || (result.len >= 7 && result.data[1] >= 2 && result.data[1] <= 8
                                        && result.data[0] < result.data[1]));
                            if valid_ascii || valid_numeric || valid_compact_seedqr || valid_bin {
                                return Ok(result);
                            }
                        }
                    }
                }

                mat.bits = mat_before_unmask;
            }
        }
        } // end offsets loop
    } // end corner_sets loop

    Err(last_err)
}

/// Decode a QR code from a grayscale image buffer.
///
/// `img`: 8-bit grayscale pixels, row-major, `w`×`h`.
///
/// Returns decoded byte payload or error.
#[inline(never)]
pub fn decode(img: &[u8], w: usize, h: usize) -> Result<DecodeResult, DecodeError> {
    // Step 0: Compute global threshold for finder detection
    let thr = compute_threshold(img);

    // Step 1: Find finder patterns — try multiple thresholds for robustness
    let mut finders = [Finder::default(); MAX_FINDERS];
    let mut cnt = find_finders(img, w, h, thr, &mut finders);
    if cnt < 3 {
        let c2 = find_finders(img, w, h, thr.saturating_sub(15), &mut finders);
        if c2 > cnt { cnt = c2; }
    }
    if cnt < 3 {
        let c3 = find_finders(img, w, h, thr.saturating_add(15), &mut finders);
        if c3 > cnt { cnt = c3; }
    }
    unsafe {
        LAST_FINDER_CNT = cnt as u8;
        if cnt < 3 {
            LAST_QR_X0 = 0; LAST_QR_Y0 = 0;
            LAST_QR_X1 = 0; LAST_QR_Y1 = 0;
        }
    }
    if cnt < 3 { return Err(DecodeError::NoFinders); }

    // Step 2: Identify up to 3 corner triples (ranked by geometry quality)
    let mut corner_triples = [(Finder::default(), Finder::default(), Finder::default()); 3];
    let n_triples = identify_corners_multi(&finders, cnt, &mut corner_triples);
    if n_triples == 0 {
        unsafe {
            for i in 0..cnt.min(6) {
                GEO_DEBUG[i] = (finders[i].cx >> 8, finders[i].cy >> 8, finders[i].ms);
            }
            GEO_DEBUG_CNT = cnt as u8;
        }
        return Err(DecodeError::BadGeometry);
    }

    // Always store finder info for diagnostics
    unsafe {
        for i in 0..cnt.min(6) {
            GEO_DEBUG[i] = (finders[i].cx >> 8, finders[i].cy >> 8, finders[i].ms);
        }
        GEO_DEBUG_CNT = cnt as u8;
    }

    let mut last_err = DecodeError::BadGeometry;

    // Store QR bounding box from best triple for guide overlay
    {
        let (tl, tr, bl) = corner_triples[0];
        // BR estimated as parallelogram
        let br_cx = tr.cx + bl.cx - tl.cx;
        let br_cy = tr.cy + bl.cy - tl.cy;
        // Module size (average)
        let ms = ((tl.ms as i32 + tr.ms as i32 + bl.ms as i32) / 3).max(1);
        // Expand by 4 modules for quiet zone + finder extent
        let expand = ms * 4;
        let all_x = [tl.cx, tr.cx, bl.cx, br_cx];
        let all_y = [tl.cy, tr.cy, bl.cy, br_cy];
        let min_x = all_x.iter().copied().min().unwrap_or(0);
        let max_x = all_x.iter().copied().max().unwrap_or(0);
        let min_y = all_y.iter().copied().min().unwrap_or(0);
        let max_y = all_y.iter().copied().max().unwrap_or(0);
        unsafe {
            LAST_QR_X0 = ((min_x - expand).max(0) >> 8) as u16;
            LAST_QR_Y0 = ((min_y - expand).max(0) >> 8) as u16;
            LAST_QR_X1 = (((max_x + expand) >> 8) as u16).min(w as u16);
            LAST_QR_Y1 = (((max_y + expand) >> 8) as u16).min(h as u16);
        }
    }

    // Use best triple only — additional triples rarely help and cost 3× compute
    let (tl, tr, bl) = corner_triples[0];

    // Recompute threshold over QR region only (removes background bias)
    let qr_thr = {
        let min_x = ((tl.cx.min(tr.cx).min(bl.cx) >> 8) - 10).max(0) as usize;
        let max_x = ((tl.cx.max(tr.cx).max(bl.cx) >> 8) + 10).min(w as i32 - 1) as usize;
        let min_y = ((tl.cy.min(tr.cy).min(bl.cy) >> 8) - 10).max(0) as usize;
        let max_y = ((tl.cy.max(tr.cy).max(bl.cy) >> 8) + 10).min(h as i32 - 1) as usize;

        if max_x > min_x + 10 && max_y > min_y + 10 {
            let mut hist = [0u32; 256];
            let mut total = 0u32;
            for y in min_y..=max_y {
                for x in min_x..=max_x {
                    let p = img[y * w + x];
                    if p > 0 {
                        hist[p as usize] += 1;
                        total += 1;
                    }
                }
            }
            if total > 100 {
                let mut sum_all = 0u64;
                for i in 1..256u32 { sum_all += i as u64 * hist[i as usize] as u64; }
                let mut sum_bg = 0u64;
                let mut w_bg = 0u32;
                let mut best_t = thr;
                let mut best_v = 0u64;
                for t in 1..255u32 {
                    w_bg += hist[t as usize];
                    sum_bg += t as u64 * hist[t as usize] as u64;
                    if w_bg == 0 { continue; }
                    let w_fg = total - w_bg;
                    if w_fg == 0 { break; }
                    let mean_bg = sum_bg / w_bg as u64;
                    let mean_fg = (sum_all - sum_bg) / w_fg as u64;
                    let diff = mean_bg.abs_diff(mean_fg);
                    let var = (w_bg as u64) * (w_fg as u64) * diff * diff;
                    if var > best_v { best_v = var; best_t = t as u8; }
                }
                let mut next = best_t as usize + 1;
                while next < 256 && hist[next] == 0 { next += 1; }
                if next < 256 && next > best_t as usize + 1 {
                    ((best_t as usize + next) / 2) as u8
                } else {
                    best_t.saturating_add(1)
                }
            } else { thr }
        } else { thr }
    };

    // Estimate version from finder spacing
    let ver_est = estimate_version(tl, tr, bl);
    unsafe {
        GEO_DEBUG_VER = ver_est.unwrap_or(0) as u8;
    }

    // Build version list: estimated ±1 (covers estimation jitter)
    // Fallback: try V1, V2, V3 if estimate fails
    let mut versions_to_try = [0i32; 3];
    let mut nv = 0usize;
    if let Ok(v) = ver_est {
        versions_to_try[nv] = v as i32; nv += 1;
        let lo = v as i32 - 1;
        let hi = v as i32 + 1;
        if lo >= 1 { versions_to_try[nv] = lo; nv += 1; }
        if hi <= MAX_VER as i32 { versions_to_try[nv] = hi; nv += 1; }
    } else {
        versions_to_try = [1, 2, 3];
        nv = 3;
    }

    let mut _last_err = DecodeError::BadVersion;

    // 2 thresholds: QR-region Otsu + slightly lower (dark modules more forgiving)
    let thresholds = [
        qr_thr,
        qr_thr.saturating_sub(10),
    ];

    for &t in &thresholds {
        for i in 0..nv {
            let v = versions_to_try[i];
            if v >= 1 && v <= MAX_VER as i32 {
                match try_decode_grid(img, w, h, tl, tr, bl, v as usize, t) {
                    Ok(result) => return Ok(result),
                    Err(e) => { _last_err = e; last_err = e; }
                }
            }
        }
    }

    Err(last_err)
}

// ═══════════════════════════════════════════════════════════════
// Self-tests
// ═══════════════════════════════════════════════════════════════
/// Get raw codeword diagnostic: (raw_cw[0], raw_cw[1], ecc_level, mask, version_est)
pub fn last_raw_info() -> (u8, u8, u8, u8, u8) {
    unsafe { (LAST_RAW0, LAST_RAW1, LAST_ECC, LAST_MASK, LAST_VER) }
}
static mut LAST_FINDER_CNT: u8 = 0;
static mut GEO_DEBUG: [(i32, i32, u32); 6] = [(0,0,0); 6];
static mut GEO_DEBUG_CNT: u8 = 0;
static mut GEO_DEBUG_VER: u8 = 0;
static mut LAST_QR_X0: u16 = 0;
static mut LAST_QR_Y0: u16 = 0;
static mut LAST_QR_X1: u16 = 0;
static mut LAST_QR_Y1: u16 = 0;
static mut LAST_RAW0: u8 = 0;
static mut LAST_RAW1: u8 = 0;
static mut LAST_ECC: u8 = 0;
static mut LAST_MASK: u8 = 0;
static mut LAST_VER: u8 = 0;
static mut LAST_ERASURES: u8 = 0;

/// Run QR decoder test suite. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 6u32;

    // Test 1: GF(256) inverse
    {
        let a = 42u8;
        let inv_a = gf_inv(a);
        if gf_mul(a, inv_a) == 1 {
            // Also test another value
            let b = 200u8;
            let inv_b = gf_inv(b);
            if gf_mul(b, inv_b) == 1 { passed += 1; }
        }
    }

    // Test 2: RS syndromes on clean data should be all zero
    {
        // Build correct generator (descending power order)
        let mut gen = [0u8; 8];
        gen[0] = 1;
        let mut glen = 1usize;
        for i in 0..7usize {
            let mut alpha_i = 1u8;
            for _ in 0..i { alpha_i = gf_mul(alpha_i, 2); }
            let mut new_gen = [0u8; 8];
            new_gen[0] = gen[0];
            for j in 1..glen { new_gen[j] = gen[j] ^ gf_mul(gen[j-1], alpha_i); }
            new_gen[glen] = gf_mul(gen[glen-1], alpha_i);
            glen += 1;
            gen[..glen].copy_from_slice(&new_gen[..glen]);
        }

        let data: [u8; 5] = [0x40, 0x56, 0x86, 0x57, 0x26];
        let mut remainder = [0u8; 12];
        remainder[..5].copy_from_slice(&data);
        for i in 0..5 {
            let coef = remainder[i];
            if coef != 0 {
                for j in 1..=7 { remainder[i + j] ^= gf_mul(gen[j], coef); }
            }
        }

        let mut encoded = [0u8; 12];
        encoded[..5].copy_from_slice(&data);
        encoded[5..12].copy_from_slice(&remainder[5..12]);

        let mut syn = [0u8; 48];
        rs_syndromes(&encoded, 7, &mut syn);
        if rs_check(&syn, 7) { passed += 1; }
    }

    // Test 3: RS correction with 1 error
    {
        let mut gen = [0u8; 8];
        gen[0] = 1;
        let mut glen = 1usize;
        for i in 0..7usize {
            let mut alpha_i = 1u8;
            for _ in 0..i { alpha_i = gf_mul(alpha_i, 2); }
            let mut new_gen = [0u8; 8];
            new_gen[0] = gen[0];
            for j in 1..glen { new_gen[j] = gen[j] ^ gf_mul(gen[j-1], alpha_i); }
            new_gen[glen] = gf_mul(gen[glen-1], alpha_i);
            glen += 1;
            gen[..glen].copy_from_slice(&new_gen[..glen]);
        }

        let data: [u8; 5] = [0x40, 0x56, 0x86, 0x57, 0x26];
        let mut remainder = [0u8; 12];
        remainder[..5].copy_from_slice(&data);
        for i in 0..5 {
            let coef = remainder[i];
            if coef != 0 {
                for j in 1..=7 { remainder[i + j] ^= gf_mul(gen[j], coef); }
            }
        }
        let mut encoded = [0u8; 12];
        encoded[..5].copy_from_slice(&data);
        encoded[5..12].copy_from_slice(&remainder[5..12]);

        // Inject 1 error
        encoded[2] ^= 0xAB;
        let original_2 = data[2]; // 0x86
        let result = rs_correct(&mut encoded, 7);
        if result.is_ok() && encoded[2] == original_2 { passed += 1; }
    }

    // Test 4: Format encode/decode round-trip
    {
        // ECC-L(01) + mask 3 = 0b01_011 = 11
        let data = 0b01_011u16;
        let encoded = format_encode(data);
        // Decode via brute-force
        let bits = encoded; // no errors
        let mut best_d = 0u8;
        let mut best_dist = 16u32;
        for d in 0u8..32 {
            let e = format_encode(d as u16);
            let dist = (bits ^ e).count_ones();
            if dist < best_dist { best_dist = dist; best_d = d; }
        }
        if best_d == data as u8 && best_dist == 0 { passed += 1; }
    }

    // Test 5: Synthetic round-trip — encode "Hello" with our encoder,
    // render to 160×120 grayscale image, decode back.
    {

        let test_data = b"Hello";
        if let Ok(qr) = crate::qr::encoder::encode(test_data) {
            // Render QR into a 160×120 grayscale buffer
            // QR V1 = 21×21 modules. At scale=4, that's 84×84 pixels + quiet zone
            let scale = 4usize;
            let qr_size = qr.size as usize;
            let total_px = (qr_size + 2) * scale; // +2 for quiet zone
            let img_w = 160usize;
            let img_h = 120usize;
            static mut TEST_IMG: [u8; 160 * 120] = [128u8; 160 * 120];

            unsafe {
                // Fill with mid-gray background
                let ptr = core::ptr::addr_of_mut!(TEST_IMG) as *mut u8;
                for i in 0..(160 * 120) { *ptr.add(i) = 128; }

                // Center the QR in the image
                let ox = (img_w - total_px) / 2;
                let oy = (img_h - total_px) / 2;

                // Draw quiet zone (white)
                for dy in 0..total_px {
                    for dx in 0..total_px {
                        *ptr.add((oy + dy) * img_w + (ox + dx)) = 220;
                    }
                }

                // Draw QR modules
                for my in 0..qr_size {
                    for mx in 0..qr_size {
                        let val = if qr.get(mx as u8, my as u8) { 20u8 } else { 220u8 };
                        let px = ox + (mx + 1) * scale; // +1 for quiet zone
                        let py = oy + (my + 1) * scale;
                        for dy in 0..scale {
                            for dx in 0..scale {
                                *ptr.add((py + dy) * img_w + (px + dx)) = val;
                            }
                        }
                    }
                }

                // Now decode
                let slice = core::slice::from_raw_parts(ptr as *const u8, 160 * 120);
                match decode(slice, img_w, img_h) {
                    Ok(result) => {
                        if result.len == 5
                            && result.data[0] == b'H'
                            && result.data[1] == b'e'
                            && result.data[2] == b'l'
                            && result.data[3] == b'l'
                            && result.data[4] == b'o'
                        {
                            passed += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Test 6: RS correction with erasures (known error positions)
    {
        // Build valid codeword: 5 data + 7 EC = 12 bytes (same as tests 2-3)
        let mut gen = [0u8; 8];
        gen[0] = 1;
        let mut glen = 1usize;
        for i in 0..7usize {
            let mut alpha_i = 1u8;
            for _ in 0..i { alpha_i = gf_mul(alpha_i, 2); }
            let mut new_gen = [0u8; 8];
            new_gen[0] = gen[0];
            for j in 1..glen { new_gen[j] = gen[j] ^ gf_mul(gen[j-1], alpha_i); }
            new_gen[glen] = gf_mul(gen[glen-1], alpha_i);
            glen += 1;
            gen[..glen].copy_from_slice(&new_gen[..glen]);
        }

        let data: [u8; 5] = [0x40, 0x56, 0x86, 0x57, 0x26];
        let mut remainder = [0u8; 12];
        remainder[..5].copy_from_slice(&data);
        for i in 0..5 {
            let coef = remainder[i];
            if coef != 0 {
                for j in 1..=7 { remainder[i + j] ^= gf_mul(gen[j], coef); }
            }
        }
        let mut encoded = [0u8; 12];
        encoded[..5].copy_from_slice(&data);
        encoded[5..12].copy_from_slice(&remainder[5..12]);
        let original = encoded;

        // Inject 3 erasures (known positions) — max for 7 EC is 7 erasures
        encoded[1] ^= 0x55;
        encoded[3] ^= 0xAA;
        encoded[4] ^= 0x33;

        let erasure_positions: [usize; 3] = [1, 3, 4];
        let result = rs_correct_with_erasures(&mut encoded, 7, &erasure_positions);
        if result.is_ok() && encoded == original {
            passed += 1;
        }
    }

    (passed, total)
}

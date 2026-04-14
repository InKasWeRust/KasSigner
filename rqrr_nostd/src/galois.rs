// galois.rs — GF(2^4) and GF(2^8) arithmetic for QR code Reed-Solomon
//
// Replaces the g2p proc macro which requires std at build time.
// Pre-computed exp/log tables for both fields.

use core::ops::{Add, AddAssign, Mul, MulAssign, Div};

/// Trait for Galois field elements (replaces g2p::GaloisField)
pub trait GaloisField:
    Copy + Clone + PartialEq + Eq +
    Add<Output = Self> + AddAssign +
    Mul<Output = Self> + MulAssign +
    Div<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;
    const GENERATOR: Self;
    fn pow(self, exp: usize) -> Self;
}

// ═══════════════════════════════════════════════════════════════
// GF(2^8) with modulus 0x11D = x^8 + x^4 + x^3 + x^2 + 1
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GF256(pub u8);

// Exp table: GENERATOR^i for i=0..254, with GENERATOR=2
// EXP[255] = EXP[0] = 1 for wrap-around
const GF256_EXP: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = val as u8;
        exp[i + 255] = val as u8;
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= 0x11D; // modulus
        }
        i += 1;
    }
    exp
};

// Log table: inverse of exp. LOG[0] is undefined (set to 0).
const GF256_LOG: [u8; 256] = {
    let mut log = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        log[GF256_EXP[i] as usize] = i as u8;
        i += 1;
    }
    log
};

impl Add for GF256 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self { GF256(self.0 ^ rhs.0) }
}

impl AddAssign for GF256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) { self.0 ^= rhs.0; }
}

impl Mul for GF256 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 { return GF256(0); }
        let log_sum = GF256_LOG[self.0 as usize] as usize + GF256_LOG[rhs.0 as usize] as usize;
        GF256(GF256_EXP[log_sum])
    }
}

impl MulAssign for GF256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Div for GF256 {
    type Output = Self;
    #[inline(always)]
    fn div(self, rhs: Self) -> Self {
        if self.0 == 0 { return GF256(0); }
        // rhs must not be zero (caller's responsibility — matches g2p behavior)
        let log_diff = GF256_LOG[self.0 as usize] as usize + 255 - GF256_LOG[rhs.0 as usize] as usize;
        GF256(GF256_EXP[log_diff])
    }
}

impl GaloisField for GF256 {
    const ZERO: Self = GF256(0);
    const ONE: Self = GF256(1);
    const GENERATOR: Self = GF256(2);

    #[inline]
    fn pow(self, exp: usize) -> Self {
        if self.0 == 0 { return GF256(0); }
        let log_val = GF256_LOG[self.0 as usize] as usize;
        let log_result = (log_val * exp) % 255;
        GF256(GF256_EXP[log_result])
    }
}

// ═══════════════════════════════════════════════════════════════
// GF(2^4) with modulus 0x13 = x^4 + x + 1
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GF16(pub u8);

// Exp table: GENERATOR^i for i=0..14
const GF16_EXP: [u8; 30] = {
    let mut exp = [0u8; 30];
    let mut val: u16 = 1;
    let mut i = 0;
    while i < 15 {
        exp[i] = val as u8;
        exp[i + 15] = val as u8;
        val <<= 1;
        if val & 0x10 != 0 {
            val ^= 0x13; // modulus
        }
        i += 1;
    }
    exp
};

const GF16_LOG: [u8; 16] = {
    let mut log = [0u8; 16];
    let mut i = 0;
    while i < 15 {
        log[GF16_EXP[i] as usize] = i as u8;
        i += 1;
    }
    log
};

impl Add for GF16 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self { GF16(self.0 ^ rhs.0) }
}

impl AddAssign for GF16 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) { self.0 ^= rhs.0; }
}

impl Mul for GF16 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 { return GF16(0); }
        let log_sum = GF16_LOG[self.0 as usize] as usize + GF16_LOG[rhs.0 as usize] as usize;
        GF16(GF16_EXP[log_sum])
    }
}

impl MulAssign for GF16 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Div for GF16 {
    type Output = Self;
    #[inline(always)]
    fn div(self, rhs: Self) -> Self {
        if self.0 == 0 { return GF16(0); }
        let log_diff = GF16_LOG[self.0 as usize] as usize + 15 - GF16_LOG[rhs.0 as usize] as usize;
        GF16(GF16_EXP[log_diff])
    }
}

impl GaloisField for GF16 {
    const ZERO: Self = GF16(0);
    const ONE: Self = GF16(1);
    const GENERATOR: Self = GF16(2);

    #[inline]
    fn pow(self, exp: usize) -> Self {
        if self.0 == 0 { return GF16(0); }
        let log_val = GF16_LOG[self.0 as usize] as usize;
        let log_result = (log_val * exp) % 15;
        GF16(GF16_EXP[log_result])
    }
}

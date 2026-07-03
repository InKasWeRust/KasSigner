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

// crypto/entropy.rs — Shared hardware entropy collector
//
// Single source of truth for gathering randomness on the ESP32-S3.
// Every consumer (ECIES ephemeral keys, AES-GCM nonces, future needs)
// calls fill(), so no code path can silently use a weaker sampler.
//
// Sources mixed via SHA-256:
//   1. WDEV RNG (0x6003_5144) — 32 reads, spaced. Fed by RC_FAST_CLK
//      jitter, which fill() enables first (DIG_CLK8M_EN, bit 10 of
//      RTC_CNTL CLK_CONF 0x6000_8074 — verified against the esp32s3
//      PAC; bit 8 is DIG_XTAL32K_EN and does NOT feed the RNG).
//   2. SYSTIMER 52-bit counter, latched before and after the WDEV
//      sampling loop (interrupt/loop timing jitter).
//   3. eFuse MAC (chip-unique, low entropy but device-binding).
//   4. Camera DMA write buffer — sensor thermal noise (Waveshare).
//      Passive read: uses whatever the last capture left in PSRAM.
//
// Output expansion: seed = SHA256(pool); out[i] = SHA256(seed || i).
// The seed is zeroized before returning.

use sha2::{Sha256, Digest};
use crate::wallet::hmac::zeroize_buf;

/// RTC_CNTL CLK_CONF register.
const RTC_CNTL_CLK_CONF: u32 = 0x6000_8074;
/// DIG_CLK8M_EN — enable CK8M (RC_FAST) for the digital core.
const DIG_CLK8M_EN: u32 = 1 << 10;
/// WDEV RNG data register.
const WDEV_RND: u32 = 0x6003_5144;
/// SYSTIMER unit0: operation (latch) and value registers.
const SYSTIMER_OP: u32 = 0x6002_3004;
const SYSTIMER_LO: u32 = 0x6002_3044;
const SYSTIMER_HI: u32 = 0x6002_3040;
/// eFuse MAC words.
const EFUSE_MAC0: u32 = 0x6000_7044;
const EFUSE_MAC1: u32 = 0x6000_7048;

/// Enable RC_FAST_CLK so the WDEV RNG receives clock-jitter entropy.
/// Idempotent; safe to call before every collection.
fn enable_rc_fast() {
    unsafe {
        let clk_conf = core::ptr::read_volatile(RTC_CNTL_CLK_CONF as *const u32);
        core::ptr::write_volatile(RTC_CNTL_CLK_CONF as *mut u32, clk_conf | DIG_CLK8M_EN);
    }
    // Let the RC oscillator feed stabilize (~a few hundred µs is ample;
    // no Delay handle here, so burn cycles).
    for _ in 0..50_000u32 {
        core::hint::spin_loop();
    }
}

/// Latch and hash the SYSTIMER 52-bit counter.
fn mix_systimer(hasher: &mut Sha256) {
    unsafe {
        core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
        for _ in 0..20u32 {
            core::hint::spin_loop();
        }
        let lo = core::ptr::read_volatile(SYSTIMER_LO as *const u32);
        let hi = core::ptr::read_volatile(SYSTIMER_HI as *const u32);
        hasher.update(lo.to_le_bytes());
        hasher.update(hi.to_le_bytes());
    }
}

/// Fill `out` with hardware-derived randomness. Any length.
///
/// This is the ONLY approved randomness source for cryptographic
/// material (ephemeral EC keys, AES nonces). Do not sample WDEV
/// directly elsewhere.
pub fn fill(out: &mut [u8]) {
    enable_rc_fast();

    let mut hasher = Sha256::new();

    // SYSTIMER snapshot before sampling
    mix_systimer(&mut hasher);

    // eFuse MAC (chip-unique)
    unsafe {
        let mac0 = core::ptr::read_volatile(EFUSE_MAC0 as *const u32);
        let mac1 = core::ptr::read_volatile(EFUSE_MAC1 as *const u32);
        hasher.update(mac0.to_le_bytes());
        hasher.update(mac1.to_le_bytes());
    }

    // 32 WDEV reads, spaced so the RNG accumulates fresh jitter
    for _ in 0..32u32 {
        let rng_val = unsafe { core::ptr::read_volatile(WDEV_RND as *const u32) };
        hasher.update(rng_val.to_le_bytes());
        for _ in 0..160u32 {
            core::hint::spin_loop();
        }
    }

    // SYSTIMER snapshot after sampling (loop-duration jitter)
    mix_systimer(&mut hasher);

    // Camera DMA write buffer — sensor noise left by the last capture
    // (Waveshare only; passive, does not start or stop the camera)
    #[cfg(feature = "waveshare")]
    if let Some(pixels) = crate::hw::cam_dma::get_entropy_bytes() {
        let len = pixels.len().min(4096);
        hasher.update(&pixels[..len]);
    }

    // Domain separator for this module
    hasher.update([0xE7, 0x21]);

    let mut seed: [u8; 32] = hasher.finalize().into();

    // Counter-mode expansion: out chunk i = SHA256(seed || i)
    let mut counter: u32 = 0;
    for chunk in out.chunks_mut(32) {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(counter.to_le_bytes());
        let block = h.finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);
        counter = counter.wrapping_add(1);
    }

    zeroize_buf(&mut seed);
}

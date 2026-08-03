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
//   1. WDEV RNG (0x6003_507C) — 32 reads, spaced. Fed by RC_FAST_CLK
//      jitter, which fill() enables first (DIG_CLK8M_EN, bit 10 of
//      RTC_CNTL CLK_CONF 0x6000_8074 — verified against the esp32s3
//      PAC; bit 8 is DIG_XTAL32K_EN and does NOT feed the RNG).
//   2. SYSTIMER 52-bit counter, latched before and after the WDEV
//      sampling loop (interrupt/loop timing jitter).
//   3. eFuse MAC (chip-unique, low entropy but device-binding).
//   4. Camera DMA write buffer — sensor thermal noise (Waveshare).
//      Passive read: uses whatever the last capture left in PSRAM.
//   5. MEMS gyro noise staged by the main loop (Waveshare). See the
//      IMU staging section below for why it arrives this way.
//
// Output expansion: seed = SHA256(pool); out[i] = SHA256(seed || i).
// The seed is zeroized before returning.

use sha2::{Sha256, Digest};
use crate::wallet::hmac::zeroize_buf;
// `AtomicU32` and `Ordering` are needed on BOTH boards for the WDEV health
// figures. `AtomicBool` is only used by the Waveshare IMU staging, so it stays
// gated to avoid an unused-import warning on M5Stack.
use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(feature = "waveshare")]
use core::sync::atomic::AtomicBool;

/// RTC_CNTL CLK_CONF register.
const RTC_CNTL_CLK_CONF: u32 = 0x6000_8074;
/// DIG_CLK8M_EN — enable CK8M (RC_FAST) for the digital core.
const DIG_CLK8M_EN: u32 = 1 << 10;

/// `APB_CTRL_WIFI_CLK_EN`. Aggregates modem-domain clock enables, and bit 15 is
/// the one that clocks the RNG.
///
/// ADDRESS VERIFIED against the PAC, not assumed. `esp32s3` 0.30.0,
/// `lib.rs`: `APB_CTRL::PTR = 0x6002_6000`, and `wifi_clk_en` is the sixth u32
/// in `apb_ctrl::RegisterBlock` (sysclk_conf, tick_conf, clk_out_en,
/// wifi_bb_cfg, wifi_bb_cfg_2, wifi_clk_en), so offset 0x14.
///
/// `hw/lockdown.rs` calls this register `SYSTEM_WIFI_CLK_EN` at `0x600C_0090`.
/// That address is in the SYSTEM peripheral, a different block. The first
/// attempt at this fix reused it and the probe then reported the register still
/// reading 0x00000000 immediately after the write, which is what exposed the
/// mistake. esp-hal reaches it via `APB_CTRL::regs()`, not `SYSTEM::regs()`.
const APB_CTRL_WIFI_CLK_EN: u32 = 0x6002_6014;
/// `SYSTEM_WIFI_CLK_RNG_EN`, bit 15. WITHOUT THIS THE RNG PRODUCES NOTHING.
///
/// Measured 2026-08-02 on both boards: `WDEV_RND` read 0x00000000 for 256
/// consecutive samples at three points in boot, with `DIG_CLK8M_EN` set. 8192
/// bits, all zero. So every one of the 32 WDEV reads in `fill()` contributed
/// nothing, on every device, for the life of the project.
///
/// The name of the register is why it was missed: it looks like a WiFi thing on
/// a device with no radios, and `hw::lockdown::early_lockdown` zeroes the whole
/// register precisely to kill the radios. But `early_lockdown` is Waveshare-only
/// and M5Stack measured identically, so the lockdown was never the cause: the
/// bit was simply never set. esp-hal does not set it either unless a
/// `TrngSource` is constructed.
///
/// Authority: `esp-hal-1.0.0/src/soc/esp32s3/trng.rs`, `ensure_randomness()`,
/// which sets exactly this bit first and comments that the 8 MHz clock alone
/// "is actually enough to produce strong random results", with the SAR ADC as
/// "some insurance".
const SYSTEM_WIFI_CLK_RNG_EN: u32 = 1 << 15;
/// WDEV RNG data register.
const WDEV_RND: u32 = 0x6003_507C;

// ADDRESS CORRECTED 2026-08-02. This was `0x6003_5144` for the life of the
// project, which is the ESP32's address, not the ESP32-S3's. Nothing is mapped
// there on this chip, so it read 0x00000000 always, and every one of the 32
// reads in `fill()` contributed exactly nothing on every device.
//
// Measured before the fix: 256 consecutive samples at three points in boot, on
// BOTH boards, 8192 bits, all zero. M5Stack never calls `early_lockdown`, so
// the lockdown was never the cause and M-13 as written is wrong.
//
// Verified from the PAC rather than assumed, after two wrong guesses (the
// lockdown register, then the modem clock bit) that the probe disproved in
// turn: `esp32s3` 0.30.0, `lib.rs` gives `RNG::PTR = 0x6003_4F6C`, and
// `rng::RegisterBlock` places `data` at offset 0x110 behind
// `_reserved0: [u8; 0x110]`. 0x6003_4F6C + 0x110 = 0x6003_507C.
//
// esp-hal reads exactly this via `RNG::regs().data().read().bits()`.

/// Sample the WDEV RNG and report crude health figures (M-13).
///
/// `hw::lockdown::early_lockdown` writes 0 to the whole of
/// `SYSTEM_WIFI_CLK_EN` (`0x600C_0090`), a register that aggregates clock
/// enables well beyond the radios. The audit's concern is that it may gate the
/// very clock this RNG is fed from, in which case every nonce and ephemeral key
/// produced afterwards would draw from a degraded source with nothing reporting
/// it.
///
/// The finding says this must be measured rather than argued, so this measures
/// it. Called either side of `early_lockdown` under the `rng-probe` feature.
///
/// Returns `(distinct, ones, zero_words, repeats)` over `N` samples:
/// - `distinct`  count of distinct 32-bit words
/// - `ones`      total set bits; expect close to `N * 16`
/// - `zero_words` words that read back 0, the classic dead-clock signature
/// - `repeats`   consecutive identical reads, the other dead-clock signature
///
/// Crude on purpose. It is not a randomness test, it is a "is this source
/// alive" test, and a gated clock fails it unmistakably.
/// Read `SYSTEM_WIFI_CLK_EN` so its state can be reported alongside a probe.
#[cfg(feature = "rng-probe")]
pub fn read_wifi_clk_en() -> u32 {
    unsafe { core::ptr::read_volatile(APB_CTRL_WIFI_CLK_EN as *const u32) }
}

/// Sample the WDEV RNG with the modem clocks temporarily enabled, then restore.
///
/// Measured 2026-08-02: `WDEV_RND` reads zero at every point in boot on BOTH
/// boards, before and after `early_lockdown` and after full initialisation,
/// with `DIG_CLK8M_EN` set and the SAR ADC forced on. M5Stack never calls
/// `early_lockdown` and reads the same, so the lockdown is not the cause and
/// M-13 as written is wrong.
///
/// The remaining hypothesis is that this register is fed from the modem clock
/// domain in `SYSTEM_WIFI_CLK_EN` (`0x600C_0090`), which nothing in this build
/// ever enables: esp-hal has no reason to without the wifi feature, and
/// `enable_rc_fast` sets `DIG_CLK8M_EN` in an RTC register, which is a
/// different clock entirely.
///
/// This turns those bits on, samples, and restores the previous value. If the
/// source comes alive, the requirement is confirmed and the decision is whether
/// to enable it deliberately or to drop the WDEV source and say so plainly.
/// Diagnostic only; it enables radio clocks and must never ship.
#[cfg(feature = "rng-probe")]
pub fn probe_wdev_with_modem_clk(samples: usize) -> (usize, u32, usize, usize, u32) {
    let saved = unsafe { core::ptr::read_volatile(APB_CTRL_WIFI_CLK_EN as *const u32) };
    unsafe {
        core::ptr::write_volatile(APB_CTRL_WIFI_CLK_EN as *mut u32, 0xFFFF_FFFF);
    }
    for _ in 0..50_000u32 {
        core::hint::spin_loop();
    }
    let (d, o, z, r) = probe_wdev(samples);
    unsafe {
        core::ptr::write_volatile(APB_CTRL_WIFI_CLK_EN as *mut u32, saved);
    }
    (d, o, z, r, saved)
}

#[cfg(feature = "rng-probe")]
pub fn probe_wdev(samples: usize) -> (usize, u32, usize, usize) {
    // Enable the sources first. Without this the register reads zero, because
    // `fill()` is what normally turns them on and it has not run yet at boot.
    //
    // The first version of this probe omitted these two calls and reported
    // all-zero BEFORE and AFTER, which looked like a catastrophic finding and
    // was a broken measurement. Recorded so the same mistake is not repeated:
    // a probe that reports a dead source must first prove the source was alive.
    enable_rc_fast();
    enable_sar_adc_noise();

    let mut seen = [0u32; 256];
    let n = samples.min(256);
    let mut ones = 0u32;
    let mut zero_words = 0usize;
    let mut repeats = 0usize;
    let mut prev: u32 = 0;
    for i in 0..n {
        let v = unsafe { core::ptr::read_volatile(WDEV_RND as *const u32) };
        seen[i] = v;
        ones += v.count_ones();
        if v == 0 { zero_words += 1; }
        if i > 0 && v == prev { repeats += 1; }
        prev = v;
        // Space the reads: the TRM rate-limits the RNG, and back-to-back reads
        // return the same word even when the source is healthy.
        for _ in 0..64 { core::hint::spin_loop(); }
    }
    let mut distinct = 0usize;
    for i in 0..n {
        let mut dup = false;
        for j in 0..i {
            if seen[i] == seen[j] { dup = true; break; }
        }
        if !dup { distinct += 1; }
    }
    (distinct, ones, zero_words, repeats)
}
/// SYSTIMER unit0: operation (latch) and value registers.
const SYSTIMER_OP: u32 = 0x6002_3004;
const SYSTIMER_LO: u32 = 0x6002_3044;
const SYSTIMER_HI: u32 = 0x6002_3040;
/// eFuse MAC words.
const EFUSE_MAC0: u32 = 0x6000_7044;
const EFUSE_MAC1: u32 = 0x6000_7048;

/// SENS (on-chip sensors) base and the registers needed to hold the SAR ADC
/// powered on as an RNG noise source.
const SENS_BASE: u32 = 0x6000_8800;
/// SENS_SAR_POWER_XPD_SAR_REG, TRM Register 39.18.
const SENS_SAR_POWER_XPD_SAR: u32 = SENS_BASE + 0x003C;
/// SENS_SAR_PERI_CLK_GATE_REG.
const SENS_SAR_PERI_CLK_GATE: u32 = SENS_BASE + 0x0104;
/// SYSTEM_PERIP_CLK_EN0, bit 28 = SARADC peripheral clock.
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;
const SARADC_CLK_EN: u32 = 1 << 28;
/// SENS_FORCE_XPD_SAR occupies bits 30:29. Value 2 = force power up.
/// TRM Register 39.18: "0/1: Disable force power up/down function,
/// 2: Enable force power up, 3: Enable force power down".
const FORCE_XPD_SAR_MASK: u32 = 0x3 << 29;
const FORCE_XPD_SAR_ON: u32 = 0x2 << 29;

/// Hold the SAR ADC powered on so it feeds the RNG as a thermal noise source.
///
/// TRM 25.3: thermal noise reaches the RNG from the high-speed ADC or the SAR
/// ADC. The high-speed ADC is enabled only with Wi-Fi or Bluetooth, which this
/// device deliberately never starts, so the SAR ADC is the only available
/// source. TRM 25.3 again: RC_FAST_CLK alone gives true random numbers, but
/// "to ensure maximum entropy, it's recommended to always enable an ADC source
/// as well".
///
/// Powering the peripheral is not enough. With SENS_FORCE_XPD_SAR left at its
/// reset value the ADC is controller-managed: it powers up for a conversion
/// and back down afterwards, so it is not a continuous noise source. Value 2
/// forces it on.
///
/// NOTE on hw/battery_ws.rs: that file writes bits 0:1 of this register with
/// the comment "XPD_SAR_FORCE + XPD_SAR", which is the ESP32 layout. On S3
/// those bits are reserved (TRM Register 39.18 defines only bits 30:29), so
/// that write has no effect and the ADC has never been held on for the RNG.
///
/// Idempotent; safe to call before every collection.
pub(crate) fn enable_sar_adc_noise() {
    unsafe {
        let clk = core::ptr::read_volatile(SYSTEM_PERIP_CLK_EN0 as *const u32);
        core::ptr::write_volatile(SYSTEM_PERIP_CLK_EN0 as *mut u32, clk | SARADC_CLK_EN);

        let gate = core::ptr::read_volatile(SENS_SAR_PERI_CLK_GATE as *const u32);
        core::ptr::write_volatile(SENS_SAR_PERI_CLK_GATE as *mut u32, gate | 0x3F);

        let pwr = core::ptr::read_volatile(SENS_SAR_POWER_XPD_SAR as *const u32);
        core::ptr::write_volatile(
            SENS_SAR_POWER_XPD_SAR as *mut u32,
            (pwr & !FORCE_XPD_SAR_MASK) | FORCE_XPD_SAR_ON,
        );
    }
}

/// Busy-wait roughly `us` microseconds using SYSTIMER.
///
/// Replaces a spin_loop count. TRM 25.3 caps RNG_DATA_REG reads at 500 kHz,
/// i.e. one read per 2 us, and a spin_loop count cannot express that: what
/// spin_loop compiles to on Xtensa, and how LTO schedules the loop, both move
/// the real delay. SYSTIMER runs at 16 MHz regardless of either.
pub(crate) fn delay_us_systimer(us: u32) {
    let ticks = us.saturating_mul(16); // SYSTIMER counts at 16 MHz
    unsafe {
        core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
        let start = core::ptr::read_volatile(SYSTIMER_LO as *const u32);
        loop {
            core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
            let now = core::ptr::read_volatile(SYSTIMER_LO as *const u32);
            if now.wrapping_sub(start) >= ticks { return; }
        }
    }
}

/// Enable RC_FAST_CLK so the WDEV RNG receives clock-jitter entropy.
/// Idempotent; safe to call before every collection.
pub(crate) fn enable_rc_fast() {
    unsafe {
        // The RNG's own clock enable. Read-modify-write, never a bare store:
        // this register is shared, and writing the whole word is what
        // `early_lockdown` does to kill the radios.
        let wifi_clk = core::ptr::read_volatile(APB_CTRL_WIFI_CLK_EN as *const u32);
        core::ptr::write_volatile(
            APB_CTRL_WIFI_CLK_EN as *mut u32,
            wifi_clk | SYSTEM_WIFI_CLK_RNG_EN,
        );

        let clk_conf = core::ptr::read_volatile(RTC_CNTL_CLK_CONF as *const u32);
        core::ptr::write_volatile(RTC_CNTL_CLK_CONF as *mut u32, clk_conf | DIG_CLK8M_EN);
    }
    // Let the RC oscillator feed stabilize (~a few hundred µs is ample;
    // no Delay handle here, so burn cycles).
    for _ in 0..50_000u32 {
        core::hint::spin_loop();
    }
}

/// Why a `fill()` refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntropyError {
    /// The hardware RNG failed its continuous health tests this call.
    SourceDegraded,
}

/// Result of the continuous health tests run over each `fill()` WDEV window.
///
/// Recorded, not enforced. Whether a failure should refuse the operation is a
/// product decision that has not been taken yet; this measures first so the
/// decision can be made against real numbers rather than against a guess.
#[derive(Clone, Copy)]
pub struct WdevHealth {
    /// Consecutive identical words. Expect 0. A dead source scores 31.
    pub repeats: u32,
    /// Distinct words of 32. Expect 32.
    pub distinct: u32,
    /// Set bits of 1024. Expect near 512.
    pub ones: u32,
    /// Bit positions (of 32) that never changed across the whole window.
    /// Expect 0. A stuck half-word scores 16; a counter with a fixed stride
    /// scores the low bits it never touches plus the high bits it never
    /// reaches.
    pub stuck_bits: u32,
    /// The window was monotonic: 30 or more of its 31 steps went the same
    /// direction. Expect false. A free-running timer read in place of the RNG
    /// scores true.
    pub monotonic: bool,
    /// All tests within tolerance.
    pub healthy: bool,
}

impl WdevHealth {
    fn pack(self) -> u32 {
        (self.repeats & 0x3F)
            | ((self.distinct & 0x3F) << 6)
            | ((self.ones & 0x7FF) << 12)
            | ((self.healthy as u32) << 23)
            | ((self.stuck_bits & 0x3F) << 24)
            | ((self.monotonic as u32) << 30)
    }

    fn unpack(v: u32) -> Self {
        Self {
            repeats: v & 0x3F,
            distinct: (v >> 6) & 0x3F,
            ones: (v >> 12) & 0x7FF,
            healthy: (v >> 23) & 1 == 1,
            stuck_bits: (v >> 24) & 0x3F,
            monotonic: (v >> 30) & 1 == 1,
        }
    }
}

/// Health of the most recent `fill()` WDEV window, or `None` if `fill` has not
/// run yet. An atomic, so a caller can read it without a lock and without
/// changing `fill`'s signature.
static LAST_WDEV_HEALTH: AtomicU32 = AtomicU32::new(u32::MAX);

/// Health figures from the last `fill()`. `None` before the first call.
pub fn last_wdev_health() -> Option<WdevHealth> {
    let v = LAST_WDEV_HEALTH.load(Ordering::Relaxed);
    if v == u32::MAX {
        None
    } else {
        Some(WdevHealth::unpack(v))
    }
}

/// Read one word from the hardware RNG.
///
/// The single place this address appears. It was hardcoded as `0x6003_5144` in
/// five places, `crypto/entropy.rs` plus four sites in `handlers/menu.rs`, and
/// all five were the ESP32 address rather than the ESP32-S3's, so all five read
/// zero forever. One constant, one function, so a wrong address can only ever
/// be wrong once.
///
/// Callers must have called `enable_rc_fast` first, and should space their
/// reads: the RNG is rate-limited and back-to-back reads return the same word.
#[inline]
pub(crate) fn read_wdev() -> u32 {
    unsafe { core::ptr::read_volatile(WDEV_RND as *const u32) }
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

// ── IMU staging ──────────────────────────────────────────────────────
//
// `fill` is a free function with no I2C handle and cannot grow one: its
// most important caller is `wallet::schnorr`, which generates BIP340
// aux-rand for nonce derivation and has no hardware handles anywhere in
// its call graph. A weak nonce does not degrade a signature, it leaks the
// private key, so that call site is exactly the one the MEMS source most
// needs to reach.
//
// So the bytes come to `fill` instead of `fill` going to get them. The main
// loop, which does hold the I2C handle, calls `stage_imu` while idle; `fill`
// mixes whatever is staged.
//
// Held as 8 AtomicU32 rather than a `static mut [u8; 32]`. Lock-free, no
// unsafe, and sound if a future change ever calls `fill` from the Core 1
// worker. A torn read across the eight words is harmless here: this is
// entropy being fed to a hash, not a structure with invariants.
#[cfg(feature = "waveshare")]
static IMU_STAGE: [AtomicU32; 8] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
#[cfg(feature = "waveshare")]
static IMU_STAGED: AtomicBool = AtomicBool::new(false);

/// Successful restagings since boot. Drives the log lines below, and is the
/// only externally visible evidence that the main-loop path is alive.
#[cfg(feature = "waveshare")]
static IMU_STAGE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Collections rejected by the point-of-use health check. A non-zero value
/// here alongside a healthy boot line means the part is degrading in service,
/// which is the failure the boot check alone cannot see.
#[cfg(feature = "waveshare")]
static IMU_SKIP_COUNT: AtomicU32 = AtomicU32::new(0);

/// One-shot latch so the "reached fill" line prints once, not on every nonce.
#[cfg(all(feature = "waveshare", not(feature = "silent")))]
static IMU_FILL_LOGGED: AtomicBool = AtomicBool::new(false);

/// Restagings between heartbeat log lines. Compiled out entirely in a silent
/// or production build.
#[cfg(all(feature = "waveshare", not(feature = "silent")))]
const IMU_STAGE_LOG_EVERY: u32 = 64;

/// SYSTIMER low word at the previous heartbeat, so the heartbeat can report
/// its own interval instead of anyone timing it by hand.
///
/// SYSTIMER runs at 16 MHz, so the low 32 bits wrap every 268 s. wrapping_sub
/// is correct for any interval shorter than that; a longer one would be
/// indistinguishable from a short one, and if the heartbeat ever takes 4.5
/// minutes the cadence is wrong by so much that the exact figure is moot.
#[cfg(all(feature = "waveshare", not(feature = "silent")))]
static IMU_LAST_LOG_TICK: AtomicU32 = AtomicU32::new(0);

/// Latch and read the SYSTIMER low word (16 MHz).
#[cfg(all(feature = "waveshare", not(feature = "silent")))]
fn systimer_lo() -> u32 {
    unsafe {
        core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
        for _ in 0..20u32 {
            core::hint::spin_loop();
        }
        core::ptr::read_volatile(SYSTIMER_LO as *const u32)
    }
}

/// Bytes drawn per restaging. 24 is 8 whole passes of 3 axes, about 3 ms of
/// I2C. Small on purpose: this runs from the main loop, not once at boot.
#[cfg(feature = "waveshare")]
const IMU_STAGE_DRAW: usize = 24;

/// Collect MEMS gyro noise and fold it into the staging buffer.
///
/// Returns the number of raw bytes collected, 0 if the IMU is absent or the
/// bus errored. Call from anywhere that holds the I2C handle and is not in a
/// hurry; the main loop does it while idle.
///
/// ACCUMULATES, it does not overwrite. The new digest is taken over the
/// previous stage AND the new samples, so a later short or failed collection
/// can never reduce what is already staged. Once good bytes are in, they stay
/// mixed in.
#[cfg(feature = "waveshare")]
pub fn stage_imu(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> usize {
    let mut buf = [0u8; IMU_STAGE_DRAW];
    let n = crate::hw::imu::collect(i2c, delay, &mut buf);
    if n == 0 {
        return 0;
    }

    // Same point-of-use check the seed path applies. A frozen axis cannot
    // reduce the pool, but it must not be allowed to set IMU_STAGED and have
    // fill() report MEMS noise it never received.
    if !crate::hw::imu::buffer_is_healthy(&buf[..n]) {
        let _s = IMU_SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        #[cfg(not(feature = "silent"))]
        if _s == 1 || _s % IMU_STAGE_LOG_EVERY == 0 {
            let d = crate::hw::imu::axis_distinct(&buf[..n]);
            crate::log!(
                "   [imu] stage SKIPPED x{}: distinct X{} Y{} Z{} of {}",
                _s, d[0], d[1], d[2], n / 3
            );
        }
        zeroize_buf(&mut buf);
        return 0;
    }

    let mut h = Sha256::new();
    for w in IMU_STAGE.iter() {
        h.update(w.load(Ordering::Relaxed).to_le_bytes());
    }
    h.update(&buf[..n]);
    h.update((n as u32).to_le_bytes());
    h.update([0xE7, 0x22]); // domain separator, distinct from fill's 0xE7 0x21
    let d: [u8; 32] = h.finalize().into();

    for (i, w) in IMU_STAGE.iter().enumerate() {
        w.store(
            u32::from_le_bytes([d[i * 4], d[i * 4 + 1], d[i * 4 + 2], d[i * 4 + 3]]),
            Ordering::Relaxed,
        );
    }
    IMU_STAGED.store(true, Ordering::Relaxed);
    let _c = IMU_STAGE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    #[cfg(not(feature = "silent"))]
    {
        if _c == 1 {
            // The one line that proves the whole main-loop path works:
            // loop -> collect -> stage. Everything downstream of here is
            // arithmetic.
            IMU_LAST_LOG_TICK.store(systimer_lo(), Ordering::Relaxed);
            crate::log!(
                "   [imu] entropy stage primed: {} bytes, fill() now carries MEMS noise",
                n
            );
        } else if _c % IMU_STAGE_LOG_EVERY == 0 {
            // Report the interval rather than leaving it to a stopwatch.
            // ms/stage x IMU_RESTAGE_TICKS gives the real main-loop period,
            // which is the number IMU_RESTAGE_TICKS was guessed from.
            let now = systimer_lo();
            let prev = IMU_LAST_LOG_TICK.swap(now, Ordering::Relaxed);
            let ms = now.wrapping_sub(prev) / 16_000; // SYSTIMER = 16 MHz
            crate::log!(
                "   [imu] entropy restaged x{} ({} bytes, {} ms for {}, {} ms/stage)",
                _c,
                n,
                ms,
                IMU_STAGE_LOG_EVERY,
                ms / IMU_STAGE_LOG_EVERY
            );
        }
    }

    zeroize_buf(&mut buf);
    n
}

/// Successful IMU restagings since boot. 0 means `fill` has never carried
/// MEMS noise, which is a different question from whether the part answered
/// at boot.
///
/// Nothing calls this yet; it is here for a self-test or an about screen.
#[allow(dead_code)]
#[cfg(feature = "waveshare")]
pub fn imu_stage_count() -> u32 {
    IMU_STAGE_COUNT.load(Ordering::Relaxed)
}

/// Fill `out` with hardware-derived randomness. Any length.
///
/// This is the ONLY approved randomness source for cryptographic
/// material (ephemeral EC keys, AES nonces). Do not sample WDEV
/// directly elsewhere.
/// Fill `out` with entropy, or fail closed.
///
/// Returns `Err(EntropyError::SourceDegraded)` when the hardware RNG fails its
/// continuous tests over this call's window: any repeated consecutive word, any
/// duplicate in 32, or a bit balance outside 25%..75%.
///
/// **Fail closed is deliberate.** This function produces signing nonces, AES-GCM
/// nonces, PBKDF2 salts and ECIES ephemeral keys. A refused operation is
/// recoverable; a signature made with a predictable nonce leaks the private key
/// and cannot be taken back. C-04 is the argument for having the check at all:
/// this source returned 0x00000000 on every read on both boards for the life of
/// the project, and every consumer used it without noticing.
///
/// False positives are not a practical concern: for a live 32-bit source, a
/// repeated consecutive word is a 2^-32 event per pair, so the whole test fails
/// at roughly 2^-27 per call. Measured on healthy hardware: 505/1024 and
/// 510/1024 ones, 0 repeats, 32/32 distinct.
///
/// `out` is left ZEROED on failure, not partially filled, so a caller that
/// ignores the result cannot proceed with half-random material.
pub fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
    enable_rc_fast();
    enable_sar_adc_noise();

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

    // 32 WDEV reads, spaced at the TRM's 500 kHz ceiling (one per 2 us) so
    // consecutive reads do not share entropy.
    //
    // Health-tested as they are drawn, on the SP 800-90B continuous-test model
    // and for the same reason the camera path gates on `MIN_AC_FOR_ENTROPY`:
    // a source that has stopped must be detectable, not merely hashed. C-04 is
    // the argument. This register returned 0x00000000 on every read on both
    // boards for the life of the project and nothing noticed, because 32 zero
    // words hash to a perfectly respectable-looking digest.
    //
    // Two tests, both effectively free over 32 words:
    //
    // REPETITION COUNT — any two consecutive identical words. For a live 32-bit
    // source that is a 2^-32 event per pair, so one repeat means the source
    // stalled. A dead register scores 31.
    //
    // ADAPTIVE PROPORTION — all 32 words distinct, and the bit balance inside a
    // loose band. Catches stuck patterns with a period longer than one, which
    // the repetition test alone would miss.
    //
    // The band is deliberately wide. This is a "has the source died" test, not
    // a randomness test: 32 words is far too small a sample to say anything
    // about quality, and a narrow band would produce false alarms on healthy
    // hardware. Measured on both boards after the C-04 fix, 256-sample windows
    // ran 4065..4142 ones out of 8192, i.e. 49.6%..50.6%.
    //
    // STUCK-BIT and MONOTONIC, added after an external review observed that
    // the three tests above all answer the same question — is the source
    // stuck? — and none of them detects STRUCTURE. Measured against the gate
    // as it stood, all of these passed it:
    //
    //   a SYSTIMER-like counter (+0x40 stride)   304 ones, PASSED
    //   a slow +1 counter                        464 ones, PASSED
    //   a source with the upper 16 bits stuck    607 ones, PASSED
    //   a 35%-biased source                      346 ones, PASSED
    //
    // The first three have little or no entropy. This matters here more than
    // it would elsewhere because of C-04: the RNG was read from the ESP32's
    // address on an S3 and returned a constant, which `distinct` catches. The
    // same class of mistake pointing at a free-running timer instead of a dead
    // register produces exactly the counter pattern above, and the gate would
    // have called it healthy.
    //
    // STUCK-BIT counts bit positions that never changed across all 32 words.
    // For a live source each position is a fair coin per word, so a constant
    // position is a 2^-31 event; over 32 positions the false-alarm rate is
    // about 1.5e-8. It catches stuck halves and, incidentally, counters,
    // whose low bits below the stride and high bits above the range never
    // move.
    //
    // MONOTONIC fails a window whose steps nearly all go the same direction.
    // 30 of 31 rather than all 31, so a counter that wraps once inside the
    // window is still caught. False-alarm rate about 3e-8.
    //
    // Both are cheap and neither tightens the ones band, which was left alone
    // deliberately: it catches gross bias, it produces no false alarms, and
    // narrowing it would have caught none of the four cases above.
    let mut prev: u32 = 0;
    let mut seen = [0u32; 32];
    let mut repeats: u32 = 0;
    let mut ones: u32 = 0;
    for i in 0..32usize {
        let rng_val = read_wdev();
        hasher.update(rng_val.to_le_bytes());
        if i > 0 && rng_val == prev {
            repeats += 1;
        }
        prev = rng_val;
        seen[i] = rng_val;
        ones += rng_val.count_ones();
        delay_us_systimer(2);
    }
    let mut distinct = 0u32;
    for i in 0..32usize {
        let mut dup = false;
        for j in 0..i {
            if seen[i] == seen[j] {
                dup = true;
                break;
            }
        }
        if !dup {
            distinct += 1;
        }
    }
    // Bit positions that never changed across the window.
    let mut stuck_bits = 0u32;
    for bit in 0..32u32 {
        let first = (seen[0] >> bit) & 1;
        let mut constant = true;
        for w in seen.iter() {
            if (w >> bit) & 1 != first {
                constant = false;
                break;
            }
        }
        if constant {
            stuck_bits += 1;
        }
    }

    // Direction of each step. A window that nearly always moves the same way
    // is a counter, not a random source.
    let mut ascending = 0u32;
    let mut descending = 0u32;
    for i in 1..32usize {
        if seen[i] > seen[i - 1] {
            ascending += 1;
        } else if seen[i] < seen[i - 1] {
            descending += 1;
        }
    }
    let monotonic = ascending >= 30 || descending >= 30;

    // 32 words = 1024 bits. Band 25%..75% -> 256..768 ones.
    let balance_ok = (256..=768).contains(&ones);
    let health = WdevHealth {
        repeats,
        distinct,
        ones,
        stuck_bits,
        monotonic,
        healthy: repeats == 0
            && distinct == 32
            && balance_ok
            && stuck_bits == 0
            && !monotonic,
    };
    LAST_WDEV_HEALTH.store(health.pack(), Ordering::Relaxed);
    for w in seen.iter_mut() {
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    if !health.healthy {
        // Fail closed. `out` is left as the caller gave it rather than filled
        // with the other sources: SYSTIMER and the eFuse MAC alone are not a
        // basis for a signing nonce, and returning something plausible is how
        // a degraded source goes unnoticed.
        for b in out.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        crate::log!(
            "   [rng-health] REFUSED: repeats {} distinct {}/32 ones {}/1024 stuck {} mono {}",
            health.repeats, health.distinct, health.ones,
            health.stuck_bits, health.monotonic
        );
        return Err(EntropyError::SourceDegraded);
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

    // MEMS gyro noise staged by the main loop (Waveshare). The only input to
    // this function that is not the SoC describing itself.
    //
    // NOT consumed on read. Clearing it would mean that only the first `fill`
    // after each restaging got any MEMS contribution and every other call got
    // none. Re-mixing the same 32 bytes adds nothing beyond the first call but
    // costs nothing and cannot hurt: every other input here varies per call.
    #[cfg(feature = "waveshare")]
    if IMU_STAGED.load(Ordering::Relaxed) {
        for w in IMU_STAGE.iter() {
            hasher.update(w.load(Ordering::Relaxed).to_le_bytes());
        }
        // Once only. This function runs per signature nonce and per AES nonce;
        // a line per call would bury the log it is meant to inform.
        #[cfg(not(feature = "silent"))]
        if !IMU_FILL_LOGGED.swap(true, Ordering::Relaxed) {
            crate::log!(
                "   [imu] MEMS noise consumed by entropy::fill (first use, stage #{})",
                IMU_STAGE_COUNT.load(Ordering::Relaxed)
            );
        }
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
    Ok(())
}

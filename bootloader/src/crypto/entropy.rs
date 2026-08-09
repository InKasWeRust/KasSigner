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
// All three are needed on BOTH boards: `AtomicU32` and `Ordering` for the WDEV
// health figures, and `AtomicBool` for `AMB_STAGED`. It was Waveshare-gated
// when only the IMU staging used it.
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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
/// ─── Ambient entropy stage, both boards ──────────────────────────────────
///
/// `fill()` cannot reach the sources that carry real entropy on this device.
/// Every caller is mid-operation - a signature nonce a second after a QR
/// scan, an AES-GCM nonce during an SD write - so it cannot power up the
/// camera for eight frames or ask the user to draw for thirty seconds.
///
/// MEASURED THIS SESSION (NIST SP 800-90B `ea_non_iid`, all ten estimators):
///
///   touch   3.89 bits per movement scribbling, 0.76 at a deliberately slow
///           worst effort. Both channels anti-correlate, so the conservative
///           floor over 2,048 events is 1,558 bits.
///   camera  0 to 24,813 bits per 8-frame capture, depending on light and
///           motion. A static grey subject in low light measured ZERO.
///
/// So the sources are harvested WHEN THEY ARE ALREADY RUNNING - touch from
/// the main loop, camera when a QR scan has powered it - and staged here for
/// `fill()` to mix.
///
/// WHY THIS MATTERS MOST ON M5STACK. Before this stage, `fill()`'s inputs on
/// that board were SYSTIMER, the eFuse MAC and the WDEV: a counter, a
/// constant, and one register. `cam_dma` is Waveshare-only and M5Stack has no
/// IMU, so it had NO input that was not the SoC describing itself. Touch is
/// the first, and it needs no hardware that board lacks.
///
/// POPULATED BEFORE ANY SIGNATURE, by construction. `fill()`'s callers are
/// the signature nonce, the ECIES ephemeral key, the commit-reveal salt and
/// the SD nonce and salt - and every one of them is downstream of a LOADED
/// SEED. Reaching a loaded seed means navigating Seed Tools, choosing a slot,
/// importing from SD or camera, and passphrase entry: all touch, dozens of
/// contacts, every one of them staged here. There is no physical confirm
/// button on the CoreS3 and no path from boot to signing that avoids the
/// touchscreen.
///
/// So this is not "usually populated". The only `fill()` that can run with an
/// empty stage is the boot self-test, which signs nothing. That is why there
/// is no "only the WDEV varied" warning below: the condition it would report
/// cannot arise on a path that matters.
///
/// Same discipline as `IMU_STAGE`, and for the same reasons:
///   ACCUMULATES, never overwrites. The new digest covers the previous stage
///   AND the new samples, so a later short or failed collection can never
///   reduce what is already staged.
///   NOT CONSUMED ON READ by `fill()`. Clearing would mean only the first
///   nonce after each staging got any contribution and every later one got
///   none.
static AMB_STAGE: [AtomicU32; 8] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static AMB_STAGED: AtomicBool = AtomicBool::new(false);

/// Successful stagings since boot, per source. The only externally visible
/// evidence that each harvest path is alive.
static AMB_TOUCH_COUNT: AtomicU32 = AtomicU32::new(0);
static AMB_CAM_COUNT: AtomicU32 = AtomicU32::new(0);

/// One-shot latch so the "reached fill" line prints once, not per nonce.
#[cfg(not(feature = "silent"))]
static AMB_FILL_LOGGED: AtomicBool = AtomicBool::new(false);


/// Fold `data` into the ambient stage under a caller-supplied domain tag.
///
/// The tag keeps sources distinct: the same bytes arriving from touch and
/// from the camera must not produce the same stage. Tags are allocated at the
/// call sites below and share the 0xE7 prefix with this module's other
/// separators (`fill` 0x21, `stage_imu` 0x22).
fn amb_stage_bytes(data: &[u8], tag: u8) {
    if data.is_empty() {
        return;
    }
    let mut h = Sha256::new();
    for w in AMB_STAGE.iter() {
        h.update(w.load(Ordering::Relaxed).to_le_bytes());
    }
    h.update(data);
    h.update((data.len() as u32).to_le_bytes());
    h.update([0xE7, tag]);
    let d: [u8; 32] = h.finalize().into();
    for (i, w) in AMB_STAGE.iter().enumerate() {
        w.store(
            u32::from_le_bytes([d[i * 4], d[i * 4 + 1], d[i * 4 + 2], d[i * 4 + 3]]),
            Ordering::Relaxed,
        );
    }
    AMB_STAGED.store(true, Ordering::Relaxed);
}

/// Stage one touch point. Call from the main loop for every reported contact.
///
/// GATED ON MOVEMENT, for the same reason the touch seed path is: `read_touch`
/// returns the controller's current state on every poll, so a finger held
/// still yields the same coordinate repeatedly. Measured, only 9% of polls
/// during continuous drawing were actual movement; the other 91% were
/// re-samples carrying nothing. Staging them would inflate the count while
/// adding no entropy, which is precisely the self-deception the health checks
/// elsewhere in this module exist to prevent.
///
/// Cheap by construction: one comparison, and on movement a SHA-256 over 40
/// bytes. No I2C, no allocation. Safe to call at the main loop's rate.
pub fn stage_touch(x: u16, y: u16) {
    static LAST_X: AtomicU32 = AtomicU32::new(u32::MAX);
    static LAST_Y: AtomicU32 = AtomicU32::new(u32::MAX);
    let (lx, ly) = (
        LAST_X.load(Ordering::Relaxed),
        LAST_Y.load(Ordering::Relaxed),
    );
    if lx == x as u32 && ly == y as u32 {
        return;
    }
    LAST_X.store(x as u32, Ordering::Relaxed);
    LAST_Y.store(y as u32, Ordering::Relaxed);

    // Position and arrival time. Coordinates carry 3.89 bits per movement
    // measured; timing 0.22, and they anti-correlate, so both go in.
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&systimer_lo().to_le_bytes());
    buf[4..6].copy_from_slice(&x.to_le_bytes());
    buf[6..8].copy_from_slice(&y.to_le_bytes());
    amb_stage_bytes(&buf, 0x23);
    AMB_TOUCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Stage camera sensor noise from a frame the caller already has.
///
/// PASSIVE: takes a slice the caller is holding, never starts or stops the
/// camera. Call it where a frame is already in hand - the QR scan loop has one
/// every capture, and `frame_noise::measure` already runs there.
///
/// GATED ON `is_live`, the same per-delta check the seed path uses. A frozen
/// sensor still returns frames and looks busy: one 8-frame capture measured
/// ZERO min-entropy under the full SP 800-90B suite while four of its seven
/// deltas were bit-identical. Staging that would let `fill()` report camera
/// noise it never received.
pub fn stage_camera_frame(pixels: &[u8]) {
    let Some(fm) = crate::hw::frame_noise::measure(pixels) else {
        return;
    };
    if !crate::hw::frame_noise::is_live(&fm) {
        return;
    }
    // A bounded slice, not the whole frame: this runs inside a scan loop and
    // 76,800 bytes through SHA-256 per frame would be felt. The measurement
    // above already established that this frame carries per-pixel variation.
    let len = pixels.len().min(1024);
    amb_stage_bytes(&pixels[..len], 0x24);
    AMB_CAM_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Stagings so far, as (touch, camera). For the boot and diagnostic lines.
pub fn ambient_counts() -> (u32, u32) {
    (
        AMB_TOUCH_COUNT.load(Ordering::Relaxed),
        AMB_CAM_COUNT.load(Ordering::Relaxed),
    )
}

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
///
/// The latch write is MANDATORY, not overhead: reading SYSTIMER_LO without it
/// returns a frozen value. Measured, 255 of 255 zero-deltas in a back-to-back
/// no-latch loop, against 2.64 ticks mean with the latch.
///
/// Ungated: `stage_touch` timestamps every movement with this on both boards
/// and in every build. It was Waveshare-and-verbose-only when the IMU
/// heartbeat was its only caller.
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
/// Evaluate a 32-word WDEV window against the five continuous health tests.
///
/// EXTRACTED SO THE SEED PATH CAN USE IT. `fill` has always run these; the
/// seed generator sampled the same register, the same 32 words, at the same
/// 2 us spacing, and then hashed them without evaluating anything. That is not
/// a different source used carelessly, it is the SAME source sampled the SAME
/// way with the gate removed.
///
/// The tests are worth having, measured rather than assumed. Four degraded
/// sources recorded in the comments below pass a naive bit-balance check and
/// fail this one:
///
/// ```text
///   a SYSTIMER-like counter (+0x40 stride)   304 ones, PASSED balance alone
///   a slow +1 counter                        464 ones, PASSED
///   upper 16 bits stuck                      607 ones, PASSED
///   a 35%-biased source                      346 ones, PASSED
/// ```
///
/// So `distinct`, `stuck_bits` and `!monotonic` are precisely the tests that
/// catch what a ones-band misses.
///
/// All five are pure functions of the window, so this recomputes `repeats` and
/// `ones` rather than taking them from the sampling loop. That costs 32
/// comparisons and 32 `count_ones` and lets any caller holding 32 words
/// evaluate them.
pub fn evaluate_window(seen: &[u32; 32]) -> WdevHealth {
    let mut repeats = 0u32;
    let mut ones = 0u32;
    for i in 0..32usize {
        ones += seen[i].count_ones();
        if i > 0 && seen[i] == seen[i - 1] {
            repeats += 1;
        }
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

    WdevHealth {
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
    }
}

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
    // and for the same reason the camera path gates each frame delta with
    // `frame_noise::is_live`:
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
    let health = evaluate_window(&seen);
    let _ = (repeats, ones); // recomputed inside evaluate_window
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

    // The passive `cam_dma::get_entropy_bytes()` read that used to sit here is
    // GONE. It mixed 4 KB of whatever was left in the DMA buffer with no
    // health check, so if the camera had not run, or had run frozen, that was
    // 4 KB of constant presented as "sensor noise left by the last capture".
    // Constant input cannot reduce entropy, but it made this function look as
    // though it had a camera contribution when it may have had none - the one
    // input that skipped the gating every other source here now has.
    //
    // `stage_camera_frame` replaces it: same sensor, taken from the QR scan
    // loop where a frame is genuinely in hand, gated on `frame_noise::is_live`
    // at the point of use, and folded into AMB_STAGE below.

    // MEMS gyro noise staged by the main loop (Waveshare).
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

    // Ambient stage: touch movements and camera frame noise harvested by the
    // main loop and the scan loop. BOTH BOARDS, unlike the two above.
    //
    // Before this, M5Stack's inputs here were SYSTIMER, the eFuse MAC and the
    // WDEV: a counter, a constant, and one register. `cam_dma` is
    // Waveshare-only and that board has no IMU, so it had nothing that was not
    // the SoC describing itself.
    //
    // Not consumed on read, same reasoning as the IMU stage.
    if AMB_STAGED.load(Ordering::Relaxed) {
        for w in AMB_STAGE.iter() {
            hasher.update(w.load(Ordering::Relaxed).to_le_bytes());
        }
        #[cfg(not(feature = "silent"))]
        if !AMB_FILL_LOGGED.swap(true, Ordering::Relaxed) {
            let (t, c) = ambient_counts();
            crate::log!(
                "   [amb] ambient noise consumed by entropy::fill (first use, touch {} cam {})",
                t, c
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

// Stage-zero probe for touch-entropy timing credit.
//
// Question: SYSTIMER resolves at 62.5 ns/tick (16 MHz) and `delay_us_systimer`
// already depends on that, so the counter is not the concern. What is unknown
// is the COST of reading it: latch (volatile write) + volatile read. If that
// costs more than the interval being measured, inter-event deltas come back as
// multiples of the read cost and look exactly like I2C polling quantization.
//
// This measures the read cost with no touch involved. Drop into
// crypto/entropy.rs (it uses the same SYSTIMER_OP / SYSTIMER_LO constants) and
// call once from a menu action or after boot tests.

/// Measurement only: its single caller in `main.rs` is behind the same
/// feature. Ungated it linked into a production build that can never call it.
#[cfg(feature = "rng-probe")]
pub fn probe_systimer_read_cost() {
    const N: usize = 256;
    let mut samples = [0u32; N];

    // Back-to-back latch+read, nothing between them.
    unsafe {
        for s in samples.iter_mut() {
            core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
            *s = core::ptr::read_volatile(SYSTIMER_LO as *const u32);
        }
    }

    // Deltas between consecutive reads = the cost of one latch+read.
    let mut min = u32::MAX;
    let mut max = 0u32;
    let mut sum = 0u64;
    let mut zero = 0u32;
    for i in 1..N {
        let d = samples[i].wrapping_sub(samples[i - 1]);
        if d == 0 { zero += 1; }
        if d < min { min = d; }
        if d > max { max = d; }
        sum += d as u64;
    }
    let mean_x100 = (sum * 100) / (N as u64 - 1);

    // How many DISTINCT delta values? A tight cluster means the read cost
    // dominates; a spread means there is jitter to harvest.
    let mut distinct = 0u32;
    for i in 1..N {
        let d = samples[i].wrapping_sub(samples[i - 1]);
        let mut seen = false;
        for j in 1..i {
            if samples[j].wrapping_sub(samples[j - 1]) == d { seen = true; break; }
        }
        if !seen { distinct += 1; }
    }

    // ns = ticks * 62.5, reported as x10 to stay integer.
    crate::log!(
        "[SYSTIMER] read cost over {} samples: min {} max {} mean {}.{:02} ticks, {} distinct, {} zero-deltas",
        N, min, max, mean_x100 / 100, mean_x100 % 100, distinct, zero
    );
    crate::log!(
        "[SYSTIMER] min {} ns, mean {} ns  (62.5 ns/tick)",
        (min as u64 * 625) / 10,
        (mean_x100 * 625) / 1000
    );

    // First 16 raw deltas, so quantization is visible rather than inferred.
    let mut line = [0u32; 16];
    for i in 0..16 { line[i] = samples[i + 1].wrapping_sub(samples[i]); }
    crate::log!(
        "[SYSTIMER] first 16 deltas: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7],
        line[8], line[9], line[10], line[11], line[12], line[13], line[14], line[15]
    );

    // Control: the same loop WITHOUT the latch write. If the latch is what
    // costs, these deltas will be materially smaller.
    unsafe {
        for s in samples.iter_mut() {
            *s = core::ptr::read_volatile(SYSTIMER_LO as *const u32);
        }
    }
    let mut nmin = u32::MAX;
    let mut nsum = 0u64;
    let mut nzero = 0u32;
    for i in 1..N {
        let d = samples[i].wrapping_sub(samples[i - 1]);
        if d == 0 { nzero += 1; }
        if d < nmin { nmin = d; }
        nsum += d as u64;
    }
    crate::log!(
        "[SYSTIMER] no-latch control: min {} mean {}.{:02} ticks, {} zero-deltas",
        nmin, (nsum * 100 / (N as u64 - 1)) / 100, (nsum * 100 / (N as u64 - 1)) % 100, nzero
    );
}

// // Stage one for touch entropy. Stage zero is done and answered:
//
//     [SYSTIMER] read cost over 256 samples: min 0 max 17 mean 2.64 ticks
//     [SYSTIMER] mean 165 ns  (62.5 ns/tick)
//
// 165 ns against a touch interval of 10-100 ms is five orders of magnitude
// of headroom, so the clock and the cost of reading it are not the limit.
//
// The remaining question is the TOUCH CONTROLLER's cadence. If it reports on
// a fixed I2C poll, every timestamp lands in the same bucket and the timing
// contribution collapses regardless of SYSTIMER, leaving only the low-order
// coordinate bits. That is measured here, not assumed.
//
// Two collection shapes are logged so they can be compared directly:
//   - drag: continuous finger movement, the bitaddress.org analogue
//   - keys: discrete taps, which inherit the same polling floor but carry a
//           landing coordinate inside each key rectangle
//
// Call from a menu action with the touch I2C bus. Runs until the sample
// buffer fills or the caller stops polling.

/// Events captured per run. 2,048 x 8 bytes = 16 KB in .bss.
///
/// SIZED FROM MEASUREMENT, not guessed. Recording every poll gave 256 samples
/// in 321 ms at a fixed 1.255 ms cadence, which was the main loop
/// (`delay_millis(1)` plus the I2C read), not the finger: 8 distinct deltas
/// across 254 samples, spread 0.46%. Recording on coordinate CHANGE instead
/// means each entry is a real movement, so 2,048 is roughly 20-40 seconds of
/// continuous drawing rather than 2.5 seconds of the loop ticking.
///
/// SRAM COST: 2,048 x 8 bytes = 16 KB of `.bss`, which raises the stack floor
/// by the same amount (`_stack_end` "rises with static RWDATA"). M5Stack has
/// the tighter budget and has previously died on a stack-guard violation from
/// static growth. Boot reported 112,488 B usable with a deepest use of
/// 35,904 B, so 16 KB should fit - but CHECK THE `[stack]` LINE after
/// flashing. If it is tight, halve this to 1,024: the buffer is a
/// measurement, and a shorter run that completes beats a longer one that
/// trips the guard.
pub const TOUCH_PROBE_MAX: usize = 2048;

/// Running digest over the movement stream, folded in as events arrive.
///
/// THE STREAM IS NOT STORED. `SHA256(domain || e1 || .. || eN || count)` is
/// identical whether the events are fed one at a time or from a buffer, so
/// keeping 2,048 x 8 bytes only to hash them once at the end cost 16 KB of
/// `.bss` for nothing. That raised the stack floor by the same amount -
/// measured, M5Stack went from 112,488 to 96,036 bytes usable - on the board
/// with the tighter budget and a recorded history of stack-guard violations
/// from static growth.
///
/// The count is folded at FINALISE rather than first, since it is not known
/// until collection ends. It binds the length either way.
static mut TP_HASH: Option<Sha256> = None;
static mut TP_N: usize = 0;

/// Raw stream, MEASUREMENT BUILDS ONLY. Needed by `touch_probe_report` and
/// `touch_probe_dump`, which exist to characterise the source, not to run it.
/// A production build carries the 112-byte hash state instead of 16 KB.
#[cfg(feature = "rng-probe")]
static mut TP_TICKS: [u32; TOUCH_PROBE_MAX] = [0; TOUCH_PROBE_MAX];
#[cfg(feature = "rng-probe")]
static mut TP_X: [u16; TOUCH_PROBE_MAX] = [0; TOUCH_PROBE_MAX];
#[cfg(feature = "rng-probe")]
static mut TP_Y: [u16; TOUCH_PROBE_MAX] = [0; TOUCH_PROBE_MAX];
/// Last recorded position, so a stationary finger is not sampled repeatedly.
static mut TP_LAST_X: u16 = u16::MAX;
static mut TP_LAST_Y: u16 = u16::MAX;
/// Polls seen while the finger was down, recorded or not. The ratio against
/// TP_N is how much of the poll stream was actually movement.
static mut TP_POLLS: u32 = 0;

/// Record one touch event. Call from the poll loop for every reported point.
///
/// Timestamped with the same latch+read `delay_us_systimer` uses, because
/// reading SYSTIMER_LO without the SYSTIMER_OP latch returns a frozen value
/// (measured: 255 of 255 zero-deltas in the no-latch control).
pub fn touch_probe_record(x: u16, y: u16) {
    unsafe {
        TP_POLLS = TP_POLLS.saturating_add(1);
        if TP_N >= TOUCH_PROBE_MAX {
            return;
        }
        // ONLY ON MOVEMENT. `read_touch` returns the controller's current
        // state on every poll, so a finger held still yields the same point
        // over and over. The first run recorded those and measured its own
        // loop period: 20,076 ticks, 8 distinct values, and y low bits stuck
        // at 0/256 and 256/256 because the finger had not moved in y at all.
        // An unmoved sample adds a row and no entropy.
        if x == TP_LAST_X && y == TP_LAST_Y {
            return;
        }
        TP_LAST_X = x;
        TP_LAST_Y = y;
        core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
        core::ptr::write_volatile(SYSTIMER_OP as *mut u32, 1 << 30);
        let t = core::ptr::read_volatile(SYSTIMER_LO as *const u32);

        // Raw pointer rather than `&mut TP_HASH`: taking a reference to a
        // `static mut` trips `static_mut_refs`, warn-by-default in edition
        // 2021 and deny in 2024. The rest of this module uses `addr_of!` for
        // the same reason.
        let hp = core::ptr::addr_of_mut!(TP_HASH);
        if (*hp).is_none() {
            let mut h = Sha256::new();
            h.update(b"KasSigner-touch-entropy-v1:");
            *hp = Some(h);
        }
        if let Some(h) = (*hp).as_mut() {
            h.update(t.to_le_bytes());
            h.update(x.to_le_bytes());
            h.update(y.to_le_bytes());
        }

        #[cfg(feature = "rng-probe")]
        {
            TP_TICKS[TP_N] = t;
            TP_X[TP_N] = x;
            TP_Y[TP_N] = y;
        }
        TP_N += 1;
    }
}

/// Discard the buffer so a second run does not mix collection shapes.
pub fn touch_probe_reset() {
    unsafe {
        TP_HASH = None;
        TP_N = 0;
        TP_POLLS = 0;
        TP_LAST_X = u16::MAX;
        TP_LAST_Y = u16::MAX;
    }
}

/// Number of events captured so far, for a progress line on screen.
pub fn touch_probe_count() -> usize {
    unsafe { TP_N }
}

/// Report. `label` distinguishes runs: "drag", "keys".
#[cfg(feature = "rng-probe")]
pub fn touch_probe_report(label: &str) {
    let (n, ticks, xs, ys) = unsafe {
        (
            TP_N,
            &*core::ptr::addr_of!(TP_TICKS),
            &*core::ptr::addr_of!(TP_X),
            &*core::ptr::addr_of!(TP_Y),
        )
    };
    if n < 8 {
        crate::log!("   [touch-probe/{}] only {} events, need >= 8", label, n);
        return;
    }

    // ─── inter-event timing ───
    //
    // From index 2, not 1: the first delta spans screen entry to first
    // contact (measured ~508,000 ticks, 32 ms) and is not an inter-event
    // interval. Leaving it in moved the mean by ~2,000 ticks and dominated
    // `max`.
    let mut min = u32::MAX;
    let mut max = 0u32;
    let mut sum = 0u64;
    for i in 2..n {
        let d = ticks[i].wrapping_sub(ticks[i - 1]);
        if d < min { min = d; }
        if d > max { max = d; }
        sum += d as u64;
    }
    let mean = sum / (n as u64 - 2);

    // Distinct delta values. THE DISCRIMINATOR: if the controller reports on
    // a fixed poll, the deltas collapse onto a handful of multiples of that
    // period and the timing credit is near zero however wide the range looks.
    let mut distinct = 0u32;
    for i in 2..n {
        let d = ticks[i].wrapping_sub(ticks[i - 1]);
        let mut seen = false;
        for j in 2..i {
            if ticks[j].wrapping_sub(ticks[j - 1]) == d { seen = true; break; }
        }
        if !seen { distinct += 1; }
    }

    // Greatest common divisor of the deltas. A polling floor shows up here as
    // a GCD equal to the poll period in ticks; jitter drives it to 1.
    let mut g = 0u32;
    for i in 2..n {
        let mut a = ticks[i].wrapping_sub(ticks[i - 1]);
        let mut b = g;
        while b != 0 { let t = b; b = a % b; a = t; }
        g = a;
    }

    let polls = unsafe { TP_POLLS };
    crate::log!(
        "   [touch-probe/{}] {} movements from {} polls ({}% moved)",
        label, n, polls, if polls > 0 { n as u32 * 100 / polls } else { 0 }
    );
    crate::log!(
        "   [touch-probe/{}] delta min {} mean {} max {} ticks ({} us mean), {} distinct, gcd {}",
        label, min, mean, max, mean / 16, distinct, g
    );

    // ─── coordinate low bits ───
    // Where inside a key rectangle the finger lands is uncorrelated between
    // presses even when the timing is quantized. Counted per bit so a stuck
    // or unused low bit is visible rather than averaged away.
    let mut xb = [0u32; 4];
    let mut yb = [0u32; 4];
    for i in 0..n {
        for b in 0..4 {
            xb[b] += ((xs[i] >> b) & 1) as u32;
            yb[b] += ((ys[i] >> b) & 1) as u32;
        }
    }
    crate::log!(
        "   [touch-probe/{}] x low bits ones: b0 {}/{} b1 {}/{} b2 {}/{} b3 {}/{}",
        label, xb[0], n, xb[1], n, xb[2], n, xb[3], n
    );
    crate::log!(
        "   [touch-probe/{}] y low bits ones: b0 {}/{} b1 {}/{} b2 {}/{} b3 {}/{}",
        label, yb[0], n, yb[1], n, yb[2], n, yb[3], n
    );

    // First 12 raw deltas, so quantization is visible rather than inferred.
    crate::log!(
        "   [touch-probe/{}] first 12 deltas: {} {} {} {} {} {} {} {} {} {} {} {}",
        label,
        ticks[1].wrapping_sub(ticks[0]), ticks[2].wrapping_sub(ticks[1]),
        ticks[3].wrapping_sub(ticks[2]), ticks[4].wrapping_sub(ticks[3]),
        ticks[5].wrapping_sub(ticks[4]), ticks[6].wrapping_sub(ticks[5]),
        ticks[7].wrapping_sub(ticks[6]), ticks[8].wrapping_sub(ticks[7]),
        ticks[9].wrapping_sub(ticks[8]), ticks[10].wrapping_sub(ticks[9]),
        ticks[11].wrapping_sub(ticks[10]), ticks[12].wrapping_sub(ticks[11])
    );
}

/// Extract 32 bytes of seed entropy from the collected touch stream.
///
/// MEASURED, not assumed. NIST SP 800-90B `ea_non_iid`, all ten estimators,
/// over two runs on M5Stack:
///
///   run                        coords bits/event   timing bits/event
///   27 s of scribbling                    3.8916              0.2152
///   122 s of deliberately slow,           0.0830              0.7610
///     straight, predictable motion
///
/// The channels ANTI-CORRELATE: slow motion makes position predictable and
/// intervals varied, fast motion the reverse. Taking the conservative bound
/// (the larger single channel, not the sum, since one hand drives both), the
/// worse of those two runs still yields 0.761 x 2048 = 1,558 bits against a
/// 256-bit target. Six times over, at the floor of what a user can produce
/// while still filling the bar.
///
/// The genuinely degenerate case - a finger held still, or tapping one pixel -
/// records NOTHING, because `touch_probe_record` skips an unchanged
/// coordinate. The bar never fills and no seed is produced. That is why this
/// path needs no health gate where the camera does: a frozen camera still
/// returns frames and looks busy, a frozen finger returns nothing.
///
/// Both channels are hashed: ticks carry the timing, x and y the position,
/// and the domain string keeps this distinct from the dice extractor.
pub fn touch_extract_entropy_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        let hp = core::ptr::addr_of_mut!(TP_HASH);
        let Some(h) = (*hp).take() else {
            // No movements collected. Returning a digest of nothing would be a
            // constant, and a constant seed is the failure this whole path
            // exists to avoid. The caller cannot reach here - the canvas only
            // completes at TOUCH_PROBE_MAX - but an all-zero return is at
            // least visibly wrong rather than plausibly right.
            return out;
        };
        let mut h = h;
        // Length last: it is not known until collection ends. Binds the count
        // either way, so a short collection cannot collide with a longer one
        // that shares a prefix.
        h.update((TP_N as u32).to_le_bytes());
        out.copy_from_slice(&h.finalize());
    }
    out
}

/// Wipe the capture. Call after extraction: the stream is the seed preimage.
pub fn touch_probe_zeroize() {
    unsafe {
        // Dropping the hash state discards the only copy of the stream in a
        // production build. The raw arrays exist only under `rng-probe`.
        TP_HASH = None;
        #[cfg(feature = "rng-probe")]
        {
            for v in TP_TICKS.iter_mut() { core::ptr::write_volatile(v, 0); }
            for v in TP_X.iter_mut() { core::ptr::write_volatile(v, 0); }
            for v in TP_Y.iter_mut() { core::ptr::write_volatile(v, 0); }
        }
        TP_N = 0;
        TP_POLLS = 0;
        TP_LAST_X = u16::MAX;
        TP_LAST_Y = u16::MAX;
    }
}

/// Dump the raw capture for offline analysis.
///
/// LOG, NOT SD: it works identically on both boards, needs no FAT32 path, and
/// the file-capture workflow is already proven. 2,048 records x 8 bytes is
/// 32,768 hex characters, about four times the PSKB dumps this log already
/// carries. Redirect the serial output to a file rather than copying from a
/// terminal, which has corrupted a paste in this project before.
///
/// Record layout, little-endian, 8 bytes each:
///     tick u32 | x u16 | y u16
///
/// Deltas are computed offline rather than here: the absolute stamps let the
/// analysis reconstruct both the inter-event intervals and the total duration,
/// and a u32 tick wraps every 268 s at 16 MHz, which one run can cross.
#[cfg(feature = "rng-probe")]
pub fn touch_probe_dump() {
    let (n, ticks, xs, ys) = unsafe {
        (
            TP_N,
            &*core::ptr::addr_of!(TP_TICKS),
            &*core::ptr::addr_of!(TP_X),
            &*core::ptr::addr_of!(TP_Y),
        )
    };
    if n == 0 {
        crate::log!("   [touch-probe] nothing to dump");
        return;
    }
    crate::log!("   TOUCH_HEX_START");
    // 16 records per line = 256 hex chars, in a buffer of 288.
    //
    // SIZED, NOT GUESSED. The first version wrote 32 records (512 chars) into
    // a String<300> and dropped every char past 300, because `push` returns
    // Err when full and the result was discarded. 300/16 = 18.75 records per
    // line, 64 lines, 1,200 of 2,048 records delivered: a silent 41% loss that
    // showed up only as impossible timing (max 0xFFFFFFFF) from records read
    // across the cut. The push result is checked below so a size mistake
    // cannot be silent again.
    const RECS_PER_LINE: usize = 16;
    let mut line: heapless::String<288> = heapless::String::new();
    let mut overflow = false;
    for i in 0..n {
        let t = ticks[i];
        let x = xs[i];
        let y = ys[i];
        let bytes = [
            (t & 0xFF) as u8, ((t >> 8) & 0xFF) as u8,
            ((t >> 16) & 0xFF) as u8, ((t >> 24) & 0xFF) as u8,
            (x & 0xFF) as u8, ((x >> 8) & 0xFF) as u8,
            (y & 0xFF) as u8, ((y >> 8) & 0xFF) as u8,
        ];
        for b in bytes.iter() {
            const HX: &[u8; 16] = b"0123456789abcdef";
            if line.push(HX[(b >> 4) as usize] as char).is_err() { overflow = true; }
            if line.push(HX[(b & 0x0F) as usize] as char).is_err() { overflow = true; }
        }
        if (i + 1) % RECS_PER_LINE == 0 || i + 1 == n {
            crate::log!("{}", line.as_str());
            line.clear();
        }
    }
    crate::log!("   TOUCH_HEX_END");
    if overflow {
        crate::log!("   [touch-probe] LINE BUFFER OVERFLOW - dump is incomplete");
    }
    crate::log!("   [touch-probe] dumped {} records, 8 B each, {} hex chars",
        n, n * 16);
}

// ─── WIRING ──────────────────────────────────────────────────────────────
//
// In the touch poll loop, wherever `read_touch` returns a point:
//
//     #[cfg(feature = "rng-probe")]
//     if let crate::hw::touch::TouchState::One(p) = state {
//         crate::crypto::entropy::touch_probe_record(p.x, p.y);
//     }
//
// Then, from a menu action or after a fixed number of events:
//
//     #[cfg(feature = "rng-probe")]
//     crate::crypto::entropy::touch_probe_report("drag");
//     #[cfg(feature = "rng-probe")]
//     crate::crypto::entropy::touch_probe_reset();
//
// HOW TO READ THE RESULT
//
//   gcd 1, distinct near the event count
//       Real jitter. Timing is worth crediting; measure per-event min-entropy
//       from the delta stream before assigning a number.
//
//   gcd equal to the poll period, distinct in single figures
//       The controller's cadence dominates. Timing contributes ~nothing and
//       the credit comes from coordinate low bits alone, which raises the
//       event count a seed would need.
//
//   x/y low bits near n/2
//       Uncorrelated landing position, the useful part. A bit stuck at 0 or n
//       is a controller reporting on a coarser grid than the coordinate range
//       suggests, and that bit carries nothing.
//
// Run BOTH shapes. If keyboard deltas are wider than drag deltas, that is the
// user hesitating between characters and it is worth extra credit; if they
// match, the polling floor dominates both and they get identical treatment.

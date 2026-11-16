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

// QMI8658C 6-axis IMU, entropy source only.
//
// WHY THIS EXISTS
//
// A firmware can believe it has a TRNG and not have one. The generator's
// health tests (`crate::entropy`) catch a dead or stuck one, but a
// deterministic fallback (Yasmarang-style) gives varying, non-zero output
// and would pass them. What protects against that is a source the SoC
// cannot fake: the camera, and MEMS gyro noise, thermal and Brownian motion
// of a proof mass on separate silicon.
//
// The camera's share depends on the sensor. Inter-frame delta over the
// captured region, measured:
//
//   OV5640, lens covered, cold        451/1024 bytes changed, MAD 2.44 LSB
//   OV5640, lens covered, AGC high    841/1024                MAD 4.02 LSB
//   OV5640, pointed at a light       1017/1024                MAD 90.87 LSB
//   GC0308 (M5Stack), dark room         0/1024                MAD 0.00 LSB
//
// The GC0308's black-level clamp gives bit-identical frames in the dark. So
// the case for this source has two legs: independence (camera and IMU fail
// for unrelated reasons on separate dies) and availability (MEMS thermal
// noise does not depend on the lighting, and a signer is used in safes and
// windowless rooms).
//
// NOT a fingerprint. PRNU, FPN and the chip's USID are stable per device:
// characterised once, they are a constant. Only per-sample noise is mixed
// here, never an identifier.
//
// CONFIGURED FOR NOISE, NOT FOR MOTION
//
//   - low-pass filter OFF   (filtering removes the noise)
//   - highest ODR           (most independent samples per unit time)
//   - full scale for CLIP HEADROOM, not resolution (see CTRL3 below)
//
// Datasheet noise (Rev 0.6 Tables 8 and 12): 15 mdps/sqrt(Hz) over 4000 Hz
// (filter off, 8000 Hz ODR) is 0.949 dps RMS. Measured on a stationary board,
// readings swing over +/-9000 LSB at 2048 LSB/dps, about 4.4 dps. At the
// +/-256 dps scale used (128 LSB/dps) that is about 563 LSB, against the
// low byte's 256 counts. So all 8 bits of the low byte are noise on a device
// sitting still; the high byte carries the angular rate, near zero and
// constant, and is discarded.
//
// HARDWARE, Waveshare ESP32-S3-Touch-LCD-2 schematic, U3:
//   SA0  (pin 1)  -> GND   see ADDRESS below
//   SDx  (pin 2)  -> 3V3   Mode 1 requires VDDIO or GND: not floating
//   SCx  (pin 3)  -> 3V3   same
//   INT1 (pin 4)  -> IO3   unused, polling only
//   CS   (pin 12) -> 3V3   I2C mode, not SPI
//   SCL  (pin 13) -> IO47  shared with the touch controller
//   SDA  (pin 14) -> IO48  shared with the touch controller
//   pins 9, 10, 11 unconnected, as specified
//
// Datasheet: QMI8658C Rev 0.6, QST Corporation.

// # It does not implement `Entropy`
//
// `kassigner_hal::entropy::Entropy::fill` either fills the buffer or fails.
// `collect` returns how many bytes it managed, maybe none, for a caller to
// stir into a pool. "These bytes are good entropy" and "here are some bytes
// that might help" must not be one method: a fail-closed gate reading the
// second as the first would pass on nothing. The camera stays the gate; this
// is additive.

use embedded_hal::i2c::I2c;
use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

// ── Address ──────────────────────────────────────────────────────────
//
// The datasheet revisions disagree:
//
//   Rev 0.6 section 12.2:  SA0 unconnected (weak pull-DOWN) -> 0x6A
//                          SA0 pulled up externally         -> 0x6B
//   Rev A   section 1.6:   SA0 High -> 0x6A,  SA0 Low -> 0x6B
//   Rev 0.6 Table 2 note 1: pin 1 has an internal 200k pull-UP,
//                          against its own 12.2.
//
// The netlist in ESP32S3TouchLCD2SchDoc.pdf puts U3 pin 1 on GND and the part
// answers at 0x6B: Rev A is right. Both addresses are still probed, at the
// cost of one transaction.
const ADDR_CANDIDATES: [u8; 2] = [0x6B, 0x6A];

// ── Registers (Rev 0.6 Table 20) ─────────────────────────────────────
const REG_WHO_AM_I: u8 = 0x00;
const REG_CTRL1: u8 = 0x02;
const REG_CTRL3: u8 = 0x04;
const REG_CTRL5: u8 = 0x06;
const REG_CTRL7: u8 = 0x08;
const REG_STATUS0: u8 = 0x2E;

/// Low bytes of the three gyro axes. Read individually, NOT as a burst; see
/// the note on CTRL1_ADDR_AUTO_INC below.
const REG_GX_L: u8 = 0x3B;
const REG_GY_L: u8 = 0x3D;
const REG_GZ_L: u8 = 0x3F;

/// High bytes: the angular rate, near zero and constant on a still device.
/// Read only by the boot health check, for the DC level; never by `collect`.
const REG_GX_H: u8 = 0x3C;
const REG_GY_H: u8 = 0x3E;
const REG_GZ_H: u8 = 0x40;

/// (low, high) register pair per axis, in X Y Z order.
const AXIS_REGS: [(u8, u8); 3] = [
    (REG_GX_L, REG_GX_H),
    (REG_GY_L, REG_GY_H),
    (REG_GZ_L, REG_GZ_H),
];

const WHO_AM_I_VALUE: u8 = 0x05;

/// CTRL1 bit 6, SPI_AI: address auto-increment. Set, but NOT relied upon:
/// the datasheet describes two mechanisms and does not reconcile them.
///
///   Table 24, CTRL1 bit 6: "Serial interface (SPI or I2C) address auto
///                           increment"
///   Section 12.2:          on I2C, "bit-7 of the \[register\] address is used
///                           to enable auto-increment of the target address"
///
/// Under 12.2 a burst from GX_L with the address MSB clear returns GX_L
/// repeated: plausible data that cuts this source to a third. So `collect`
/// reads one register per axis, about 180 us a pass at 400 kHz against 110 us
/// for a burst.
const CTRL1_ADDR_AUTO_INC: u8 = 1 << 6;

/// CTRL3: gFS = 100 (+/-256 dps, 128 LSB/dps) and gODR = 0000 (8000 Hz).
///
/// Not the finest scale: +/-16 dps is 2.7 RPM, so a finger press that tilts
/// the board clips the axis at 0x7FFF or 0x8000, and its low byte is a
/// constant 0xFF or 0x00 that looks like data. At +/-256 dps the
/// measured 4.4 dps of noise is still about 563 LSB, over twice the low
/// byte's range, and the clip point is 43 RPM, beyond normal handling.
///
/// The 6DOF-only restriction on 8000/4000/2000 Hz (Rev 0.6 notes 9 and 11)
/// is for the ACCELEROMETER ODR table; Table 12 lists 8000 Hz for the
/// gyroscope without it.
const CTRL3_GYRO_CFG: u8 = 0x40;

/// Magnitude counted as rail-pinned in the boot health check (full scale is
/// 32767).
const CLIP_THRESHOLD: i32 = 32_000;

/// CTRL5: gLPF_EN = 0. Filter OFF, deliberately.
const CTRL5_NO_FILTER: u8 = 0x00;

/// CTRL7 bit 1, gEN: gyroscope only. The accelerometer stays off: a constant
/// 1 g dominates it on a device lying still.
const CTRL7_GYRO_ENABLE: u8 = 1 << 1;

/// STATUS0 bit 1, gDA. New gyroscope data available since the last read.
const STATUS0_GYRO_DATA_READY: u8 = 1 << 1;

/// Gyro turn-on, 60 ms plus 3/ODR (Rev 0.6 Table 8): 60.4 ms at 8000 Hz,
/// rounded up. Once at boot.
const GYRO_TURNON_MS: u32 = 70;

/// The part's System Turn On Time, t0: from no power, a software reset or
/// power down to its Power-On Default state (datasheet Tables 7 and 8),
/// counted once VDD and VDDIO are within 1% of final. Inside it the part
/// does not answer, and a cold boot would find the IMU absent.
const TURN_ON_MS: u32 = 1750;
/// On top of [`TURN_ON_MS`], for rails that take their time to settle.
const TURN_ON_MARGIN_MS: u32 = 250;
/// How often to ask while waiting for it.
const PROBE_EVERY_MS: u32 = 10;

/// Passes for the boot health check. A pass is one sample of each axis, so
/// this is the per-axis sample count: 33 bytes, about 3 ms.
const HEALTH_PASSES: usize = 11;

/// Distinct low-byte values required PER AXIS: summed, two working axes and
/// a dead one still give 22 or so of 33, which hides the dead one.
///
/// With the measured noise a low byte is effectively uniform, so 11 samples
/// of one axis are 11 uniform draws from 256 values:
///
///   expected     10.79
///   P(< 9)       0.00065
///   P(< 3)       vanishing
///
/// A dead axis yields exactly 1. REJECT under 3 catches a stuck register, a
/// bus stuck at 0x00 or 0xFF, or a gyro that never started, on any axis.
/// WARN under 9 fires by chance about once in 1500 per axis, roughly once in
/// 500 boots: too often to reject on a good board.
const HEALTH_MIN_DISTINCT: u32 = 3;
const HEALTH_WARN_DISTINCT: u32 = 9;

/// 0 = not probed, 1 = absent, otherwise the confirmed I2C address. Absent
/// is sticky: a missing, unresponsive or STUCK IMU contributes NOTHING, not
/// zeros.
static IMU_ADDR: AtomicU8 = AtomicU8::new(0);
const ADDR_ABSENT: u8 = 1;

/// Why the last [`init`] gave up. The driver's log lines expand to nothing
/// in this crate, so this is how a caller learns which step refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Neither address answered `WHO_AM_I` with the QMI8658's value.
    NotFound,
    /// The part answered but refused a configuration write.
    ConfigRefused,
    /// The gyro ran but its samples did not vary enough, after one retry:
    /// the passes that read as ready, out of `HEALTH_PASSES`, and the
    /// distinct low-byte values seen per axis.
    Stuck { passes: u32, distinct: [u32; 3] },
}

/// Which failure, as a small integer; zero is none. The health figures are
/// in the four words after it.
static FAILED_AT: AtomicU8 = AtomicU8::new(0);
static FAILED_PASSES: AtomicU32 = AtomicU32::new(0);
static FAILED_DISTINCT: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

/// Why the last [`init`] failed, or `None` if it did not.
pub fn failure() -> Option<Failure> {
    match FAILED_AT.load(Ordering::Relaxed) {
        1 => Some(Failure::NotFound),
        2 => Some(Failure::ConfigRefused),
        3 => Some(Failure::Stuck {
            passes: FAILED_PASSES.load(Ordering::Relaxed),
            distinct: [
                FAILED_DISTINCT[0].load(Ordering::Relaxed),
                FAILED_DISTINCT[1].load(Ordering::Relaxed),
                FAILED_DISTINCT[2].load(Ordering::Relaxed),
            ],
        }),
        _ => None,
    }
}

/// How many health passes [`init`] takes, for a caller reading [`Failure`].
pub const HEALTH_PASSES_TAKEN: u32 = HEALTH_PASSES as u32;

fn write_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8, val: u8) -> bool {
    i2c.write(addr, &[reg, val]).is_ok()
}

fn read_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8) -> Option<u8> {
    let mut buf = [0u8; 1];
    if i2c.write_read(addr, &[reg], &mut buf).is_ok() {
        Some(buf[0])
    } else {
        None
    }
}

/// Mark `b` in a 256-bit bitmap (32 bytes of stack per axis). Returns true
/// if it had not been seen.
fn mark_seen(seen: &mut [u32; 8], b: u8) -> bool {
    let word = (b >> 5) as usize;
    let bit = 1u32 << (b & 0x1F);
    if seen[word] & bit == 0 {
        seen[word] |= bit;
        true
    } else {
        false
    }
}

/// Distinct low-byte values per axis over a buffer from `collect`, which
/// writes X, Y, Z, X, Y, Z...: axis k is every third byte from k. A trailing
/// partial pass counts for the axes it reached, so compare against
/// `buf.len() / 3`.
pub fn axis_distinct(buf: &[u8]) -> [u32; 3] {
    let mut seen = [[0u32; 8]; 3];
    let mut n = [0u32; 3];
    for (i, &b) in buf.iter().enumerate() {
        let ax = i % 3;
        if mark_seen(&mut seen[ax], b) {
            n[ax] += 1;
        }
    }
    n
}

/// First sample of each axis in a buffer from `collect`. On an axis with one
/// distinct value this is the stuck value: 0xFF or 0x00 is a full-scale
/// clip, anything else a frozen register or a bus fault.
pub fn axis_first_byte(buf: &[u8]) -> [u8; 3] {
    let mut f = [0u8; 3];
    for ax in 0..3usize {
        if ax < buf.len() {
            f[ax] = buf[ax];
        }
    }
    f
}

/// Boot health measurement. `distinct` says whether an axis is NOISY, which
/// the entropy claim rests on; `mean` whether it is ALIVE at DC (it moves
/// when the board tilts). An axis can be alive and not noisy (a filter left
/// on), or noisy garbage and not alive, so both are logged.
struct Health {
    passes: u32,
    distinct: [u32; 3],
    /// Mean of the signed 16-bit reading, in LSB (128 LSB = 1 dps here).
    mean: [i32; 3],
    /// Samples at or past CLIP_THRESHOLD: an axis hitting the rail, whose low
    /// byte is then a constant.
    clipped: [u32; 3],
}

fn measure_health<I: I2c>(i2c: &mut I, delay: &mut SysTimer, addr: u8, passes: usize) -> Health {
    let mut seen = [[0u32; 8]; 3];
    let mut distinct = [0u32; 3];
    let mut sum = [0i32; 3];
    let mut clipped = [0u32; 3];
    let mut done = 0u32;

    for _ in 0..passes {
        // Wait for a sample the sensor reports as new, bounded.
        let mut waited = 0u32;
        loop {
            match read_reg(i2c, addr, REG_STATUS0) {
                Some(s) if s & STATUS0_GYRO_DATA_READY != 0 => break,
                Some(_) => {
                    delay.delay_us(150);
                    waited += 1;
                    if waited > 200 {
                        break;
                    }
                }
                None => {
                    return Health {
                        passes: done,
                        distinct,
                        mean: axis_mean(&sum, done),
                        clipped,
                    };
                }
            }
        }

        for ax in 0..3usize {
            let lo = read_reg(i2c, addr, AXIS_REGS[ax].0);
            let hi = read_reg(i2c, addr, AXIS_REGS[ax].1);
            match (lo, hi) {
                (Some(l), Some(h)) => {
                    if mark_seen(&mut seen[ax], l) {
                        distinct[ax] += 1;
                    }
                    let v = i16::from_le_bytes([l, h]) as i32;
                    if v >= CLIP_THRESHOLD || v <= -CLIP_THRESHOLD {
                        clipped[ax] += 1;
                    }
                    sum[ax] += v;
                }
                _ => {
                    return Health {
                        passes: done,
                        distinct,
                        mean: axis_mean(&sum, done),
                        clipped,
                    };
                }
            }
        }
        done += 1;
    }

    Health {
        passes: done,
        distinct,
        mean: axis_mean(&sum, done),
        clipped,
    }
}

fn axis_mean(sum: &[i32; 3], n: u32) -> [i32; 3] {
    if n == 0 {
        return [0; 3];
    }
    [sum[0] / n as i32, sum[1] / n as i32, sum[2] / n as i32]
}

/// Probe and configure, after I2C is up and before the seed screen. Later
/// calls return the first call's answer.
///
/// True if the part answered WHO_AM_I, accepted its configuration, AND passed
/// a live health check of varying samples. Never panics; a missing part costs
/// the turn-on wait once, then is marked absent and `collect` contributes
/// nothing.
pub fn init<I: I2c>(i2c: &mut I, delay: &mut SysTimer) -> bool {
    let prev = IMU_ADDR.load(Ordering::Relaxed);
    if prev == ADDR_ABSENT {
        return false;
    }
    if prev != 0 {
        return true;
    }

    // Ask until it answers, up to its turn-on time: a warm boot finds it at
    // once, a cold one waits only while it is turning on.
    let mut waited_ms = 0;
    let found = loop {
        let hit = ADDR_CANDIDATES
            .iter()
            .copied()
            .find(|&addr| read_reg(i2c, addr, REG_WHO_AM_I) == Some(WHO_AM_I_VALUE));
        if hit.is_some() || waited_ms >= TURN_ON_MS + TURN_ON_MARGIN_MS {
            break hit;
        }
        delay.delay_ms(PROBE_EVERY_MS);
        waited_ms += PROBE_EVERY_MS;
    };

    let addr = match found {
        Some(a) => a,
        None => {
            IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
            FAILED_AT.store(1, Ordering::Relaxed);
            crate::log!("   [imu] QMI8658C not found, entropy source unavailable");
            return false;
        }
    };

    // Enable last, so the gyro starts with its final settings.
    let ok = write_reg(i2c, addr, REG_CTRL1, CTRL1_ADDR_AUTO_INC)
        && write_reg(i2c, addr, REG_CTRL3, CTRL3_GYRO_CFG)
        && write_reg(i2c, addr, REG_CTRL5, CTRL5_NO_FILTER)
        && write_reg(i2c, addr, REG_CTRL7, CTRL7_GYRO_ENABLE);

    if !ok {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        FAILED_AT.store(2, Ordering::Relaxed);
        crate::log!("   [imu] QMI8658C config write failed, entropy source unavailable");
        return false;
    }

    delay.delay_ms(GYRO_TURNON_MS);

    // A failed health check below overwrites this with ADDR_ABSENT.
    IMU_ADDR.store(addr, Ordering::Relaxed);

    // ── Health check ─────────────────────────────────────────────────
    //
    // WHO_AM_I proves the part is on the bus, not that the gyro runs or its
    // output registers are anything but zero: real samples must vary.
    let mut h = measure_health(i2c, delay, addr, HEALTH_PASSES);
    if h.passes < HEALTH_PASSES as u32 {
        // One retry: the drive loop may still be settling on a cold part.
        delay.delay_ms(50);
        h = measure_health(i2c, delay, addr, HEALTH_PASSES);
    }

    let worst = h.distinct[0].min(h.distinct[1]).min(h.distinct[2]);

    if h.passes < HEALTH_PASSES as u32 || worst < HEALTH_MIN_DISTINCT {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        FAILED_AT.store(3, Ordering::Relaxed);
        FAILED_PASSES.store(h.passes, Ordering::Relaxed);
        for (slot, &n) in FAILED_DISTINCT.iter().zip(h.distinct.iter()) {
            slot.store(n, Ordering::Relaxed);
        }
        crate::log!(
            "   [imu] QMI8658C stuck: {} of {} passes, distinct X{} Y{} Z{} — entropy source rejected",
            h.passes,
            HEALTH_PASSES,
            h.distinct[0],
            h.distinct[1],
            h.distinct[2]
        );
        return false;
    }

    {
        // LOW: passed, but an axis is under HEALTH_WARN_DISTINCT. Once is
        // chance; the same axis on every boot is dead or filtered.
        let flag = if worst < HEALTH_WARN_DISTINCT {
            "  LOW"
        } else {
            ""
        };
        crate::log!(
            "   [imu] QMI8658C 0x{:02X}, 8kHz +/-256dps, filter off | distinct X{} Y{} Z{} of {} | mean X{} Y{} Z{} LSB | clipped X{} Y{} Z{}{}",
            addr,
            h.distinct[0],
            h.distinct[1],
            h.distinct[2],
            h.passes,
            h.mean[0],
            h.mean[1],
            h.mean[2],
            h.clipped[0],
            h.clipped[1],
            h.clipped[2],
            flag
        );
    }

    true
}

/// Collect gyro noise into `out`. Returns the number of bytes written.
///
/// One byte per axis per sample: the LOW byte, where the noise is. Each axis
/// is its own single-register read (see CTRL1_ADDR_AUTO_INC), so a pass may
/// straddle two ODR periods, which does no harm here.
///
/// Returns 0 if the IMU is absent or never initialised: the source
/// contributed nothing, and `out` must not be mixed.
pub fn collect<I: I2c>(i2c: &mut I, delay: &mut SysTimer, out: &mut [u8]) -> usize {
    let addr = IMU_ADDR.load(Ordering::Relaxed);
    if addr == 0 || addr == ADDR_ABSENT {
        return 0;
    }

    let mut written = 0usize;
    // Bounded so a wedged bus cannot spin here. A ready pass yields 3 bytes;
    // the rest of the bound is for passes that find no new sample.
    let max_passes = out.len() * 2 + 16;

    for _ in 0..max_passes {
        if written >= out.len() {
            break;
        }

        // Only a sample the sensor reports as new: re-reading faster than the
        // ODR returns the same bytes.
        match read_reg(i2c, addr, REG_STATUS0) {
            Some(s) if s & STATUS0_GYRO_DATA_READY != 0 => {}
            Some(_) => {
                // 8 kHz ODR means a fresh sample every 125 us.
                delay.delay_us(150);
                continue;
            }
            None => break, // bus error: stop, do not fabricate data
        }

        // A bus error mid-pass keeps what was written and stops; never pads.
        for reg in [REG_GX_L, REG_GY_L, REG_GZ_L] {
            if written >= out.len() {
                break;
            }
            match read_reg(i2c, addr, reg) {
                Some(v) => {
                    out[written] = v;
                    written += 1;
                }
                None => return written,
            }
        }
    }

    written
}

/// Minimum distinct low-byte values PER AXIS, as a percentage of the per-axis
/// sample count, for a collection to be healthy at the point of use. A
/// healthy axis gives about 94% (30 of 32, 7.9 of 8); no unlucky draw falls
/// to 60% and no frozen axis reaches it.
pub const HEALTHY_DISTINCT_PCT: u32 = 60;

/// True if every axis of a buffer from `collect` carried real variation. The
/// boot check is not enough: an axis alive at boot can freeze later (a
/// clip), so a source is checked where it is used.
pub fn buffer_is_healthy(buf: &[u8]) -> bool {
    let per_axis = (buf.len() / 3) as u32;
    if per_axis < 4 {
        return false;
    }
    let d = axis_distinct(buf);
    let min_needed = per_axis * HEALTHY_DISTINCT_PCT / 100;
    d[0] >= min_needed && d[1] >= min_needed && d[2] >= min_needed
}

/// True if a QMI8658C was found, configured and passed the boot health check.
pub fn present() -> bool {
    let a = IMU_ADDR.load(Ordering::Relaxed);
    a != 0 && a != ADDR_ABSENT
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 KasSigner contributors
//
// QMI8658C 6-axis IMU, entropy source only.
//
// WHY THIS EXISTS
//
// The seed pool mixes the ESP32-S3 hardware RNG, camera frames, SYSTIMER and
// the eFuse chip ID. The COLDCARD failure of 2026-07-30 was not a weak TRNG,
// it was a firmware that believed it had a TRNG and did not, with nothing
// checking. The boot health check added in the same release catches a dead or
// stuck generator, but a Yasmarang-style deterministic fallback produces
// varying, non-zero, non-constant output and would pass it.
//
// What actually protects against that is a source the SoC cannot fake. The
// camera is one, and MEMS gyro noise is another: thermal and Brownian motion
// in a physical proof mass on separate silicon.
//
// CORRECTION, on measurement. This paragraph used to claim the camera
// "contributes nothing with the lens covered or in a dark room". That is
// false, and it was the stated reason for adding this module. Measured on a
// Waveshare board, inter-frame delta over the captured region:
//
//   lens covered, camera cold   451/1024 bytes changed/frame, MAD 2.44 LSB
//   lens covered, AGC wound up  841/1024                      MAD 4.02 LSB
//   pointed at a light         1017/1024                      MAD 90.87 LSB
//
// CORRECTION TO THE CORRECTION. The above is true of the OV5640 and NOT of the
// M5Stack GC0308. Measured in true darkness on that sensor:
//
//   lens covered, dark room     0/1024 bytes changed, MAD 0.00 LSB
//
// Zero. Bit-identical frames, seven deltas running. Its black-level clamping
// floors the image to a constant and clips the read noise away entirely.
//
// So the original sentence was RIGHT, for this sensor, and generalising one
// board's measurement into a claim about "the camera" was the actual error.
// The honest statement is that it is sensor-dependent: OV5640 keeps ~44% of
// its bytes moving with the lens covered, GC0308 keeps none.
//
// The consequence is not academic. M5Stack has no IMU driver, so the camera is
// its only non-SoC source, and in a dark room that board CANNOT GENERATE A
// SEED. Correct behaviour, since there is genuinely nothing to harvest, but an
// air-gapped signer is used in safes and windowless rooms.
//
// The argument for this module therefore has two legs, not one:
// independence — the camera and the IMU fail for unrelated reasons on separate
// dies — and availability, because MEMS thermal noise does not care about the
// lighting and the camera demonstrably does.
//
// NOT a fingerprint. PRNU, FPN and the chip's own USID are STABLE per device,
// which is what makes them useful for identity and disqualifying as entropy:
// characterise the part once and the contribution becomes a constant. Only the
// per-sample noise is mixed here, never any identifier.
//
// CONFIGURED FOR NOISE, NOT FOR MOTION
//
// The settings below are deliberately the opposite of a motion application:
//   - low-pass filter OFF   (filtering removes exactly what we want)
//   - highest ODR           (most independent samples per unit time)
//   - full scale chosen for CLIP HEADROOM, not resolution (see CTRL3 below)
//
// That last one was originally the opposite, and it was wrong. See CTRL3.
//
// How much noise this actually yields, from Rev 0.6 Table 8 and Table 12:
//   noise density   15 mdps/sqrt(Hz)
//   bandwidth       4000 Hz  (default, filter off, at 8000 Hz ODR)
//   sensitivity     2048 LSB/dps  (+/-16 dps full scale)
//
//   RMS noise = 0.015 * sqrt(4000) = 0.949 dps = 1943 LSB
//
// MEASURED, and the datasheet extrapolation above is pessimistic. A stationary
// Waveshare board dumped 16 passes swinging over +/-9000 LSB on every axis at
// 2048 LSB/dps, about 4.6x the 1943 LSB the numbers predict, so the real
// figure is nearer +/-4.4 dps.
//
// At the +/-256 dps scale now used (128 LSB/dps) that same 4.4 dps is ~563 LSB
// RMS. The low byte needs only +/-128 LSB to be saturated, so there is still
// more than six times the margin, with sixteen times the clip headroom.
//
// So roughly bits 0..12 of every 16-bit reading are noise on a device sitting
// still. Taking the low byte alone is conservative: all 8 of its bits are well
// inside the noise floor. The high byte carries the actual angular rate, which
// is a near-constant close to zero on a stationary device, so it is discarded
// rather than diluting the pool.
//
// HARDWARE, from Waveshare ESP32-S3-Touch-LCD-2 schematic U3:
//   CS   (pin 12) -> 3V3   I2C mode, not SPI
//   SA0  (pin 1)  -> GND   see ADDRESS below
//   SCL  (pin 13) -> IO47  shared with the touch controller
//   SDA  (pin 14) -> IO48  same bus main.rs already opens
//   INT1 (pin 4)  -> IO3   unused here, polling only
//
// Datasheet: QMI8658C Rev 0.6, QST Corporation.

use esp_hal::i2c::master::I2c;
use esp_hal::delay::Delay;
use core::sync::atomic::{AtomicU8, Ordering};

// The `imu-dump` guard MOVED to main.rs, where the rest of the
// diagnostic-feature guards live. Keeping one of them here meant the list in
// main.rs read as complete when it was not, which is the failure mode the
// guards exist to prevent.

// ── Address ──────────────────────────────────────────────────────────
//
// SETTLED, by netlist plus measurement. It was not settled by the datasheet,
// whose revisions contradict each other and one of which contradicts itself:
//
//   Rev 0.6 section 12.2:  SA0 unconnected (weak pull-DOWN) -> 0x6A
//                          SA0 pulled up externally         -> 0x6B
//   Rev A   section 1.6:   SA0 High -> 0x6A,  SA0 Low -> 0x6B
//   Rev 0.6 Table 2 note 1: pin 1 has an internal 200k pull-UP,
//                          directly contradicting its own 12.2.
//
// The Altium netlist inside ESP32S3TouchLCD2SchDoc.pdf puts U3 pin 1 on GND,
// and the part answers at 0x6B on hardware. So SA0 LOW -> 0x6B: Rev A is
// right and Rev 0.6 section 12.2 is wrong.
//
// Both candidates are still probed. The cost is one extra transaction on a
// board where the first guess is right, and the alternative is trusting a
// document that has been demonstrated wrong on exactly this point.
//
// Rest of U3, same netlist, for anyone re-checking this later:
//   pin 2 SDx  -> 3V3   (Mode 1 requires VDDIO or GND; compliant, not floating)
//   pin 3 SCx  -> 3V3   (same)
//   pin 12 CS  -> 3V3   (1 = I2C mode, not SPI)
//   pin 13 SCL -> IO47, shared with TP_SCL
//   pin 14 SDA -> IO48, shared with TP_SDA
//   pin 4 INT1 -> IO3, unused here; pins 9/10/11 unconnected, as specified
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

/// High bytes. Never read by `collect`: on a stationary device they carry the
/// angular rate, a near-constant close to zero, and would dilute the pool.
/// Read by the boot health check and by `imu-dump`, where the DC level is the
/// point rather than the problem.
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

/// CTRL1 bit 6, SPI_AI. Address auto-increment.
///
/// Set, but deliberately NOT relied upon. The datasheet describes two
/// different auto-increment mechanisms and does not reconcile them:
///
///   Table 24, CTRL1 bit 6: "Serial interface (SPI or I2C) address auto
///                           increment"
///   Section 12.2:          on I2C, "bit-7 of the [register] address is used
///                           to enable auto-increment of the target address"
///
// If 12.2 is the operative one, a multi-byte read starting at GX_L with the
/// address MSB clear returns GX_L repeated, which looks like plausible sensor
/// data and would silently cut this source's contribution to a third. That is
/// precisely the class of failure this module was written to defend against,
/// so `collect` issues one single-register read per axis instead. Three
/// transactions at 400 kHz cost about 180 us per pass against 110 us for a
/// burst: irrelevant at 32 passes, and it depends on no contested behaviour.
const CTRL1_ADDR_AUTO_INC: u8 = 1 << 6;

/// CTRL3: gFS = 100 (+/-256 dps, 128 LSB/dps) and gODR = 0000 (8000 Hz).
///
/// THE FULL SCALE WAS +/-16 dps AND THAT WAS A BUG. The original reasoning was
/// "smallest full scale, finest LSB, so noise occupies the most bits". It is
/// true and it is beside the point, because +/-16 dps is 2.7 RPM: a finger
/// press that tilts the board clips the axis, the reading pins at 0x7FFF or
/// 0x8000, and the low byte becomes a CONSTANT 0xFF or 0x00 for the duration.
///
/// Observed in service: a seed-time collection returning distinct X27 Y1 Z25,
/// with a second collection one second later on the same board reading
/// X28 Y30 Z23. One axis frozen, self-clearing, correlated with the touch that
/// started the operation.
///
/// A clipped axis is worse than a coarse one. It contributes nothing while
/// looking like data, which is the failure this whole module exists to
/// prevent, and it was introduced here by over-optimising resolution.
///
/// +/-256 dps at 128 LSB/dps against the MEASURED 4.4 dps noise gives ~563 LSB
/// RMS, so the low byte is still saturated more than six times over, and the
/// clip point moves to 43 RPM which normal handling does not reach. Sixteen
/// times the headroom for resolution that was never needed.
///
/// The 6DOF-only restriction on 8000/4000/2000 Hz (Rev 0.6 notes 9 and 11)
/// applies to the ACCELEROMETER ODR table. Table 12 lists 8000 Hz for the
/// gyroscope with no such condition, so gyro-only at 8 kHz is in spec.
const CTRL3_GYRO_CFG: u8 = 0x40;

/// Magnitude at which a reading is treated as rail-pinned for the boot clip
/// count. Full scale is 32767; anything past this is clipping or about to.
const CLIP_THRESHOLD: i32 = 32_000;

/// CTRL5: gLPF_EN = 0. Filter OFF, deliberately.
const CTRL5_NO_FILTER: u8 = 0x00;

/// CTRL7 bit 1, gEN. Gyroscope only; the accelerometer stays disabled since
/// its LSBs are dominated by a constant 1 g on a device sitting on a table.
const CTRL7_GYRO_ENABLE: u8 = 1 << 1;

/// STATUS0 bit 1, gDA. New gyroscope data available since the last read.
const STATUS0_GYRO_DATA_READY: u8 = 1 << 1;

/// Gyro turn-on is 60 ms plus 3/ODR (Rev 0.6 Table 8). At 8000 Hz that is
/// 60.4 ms. Rounded up; this runs once at boot, not per seed.
const GYRO_TURNON_MS: u32 = 70;

/// Passes drawn for the boot health check. One pass is one sample of each of
/// the three axes, so this is also the per-axis sample count. 11 passes is 33
/// bytes and about 3 ms, once, at boot.
const HEALTH_PASSES: usize = 11;

/// Distinct low-byte values required PER AXIS, not in aggregate.
///
/// Aggregating hides the failure that matters. With ~1943 LSB RMS of noise a
/// low byte is effectively uniform, so 11 samples of one axis are 11 uniform
/// draws from 256 values:
///
///   expected     10.79
///   P(< 9)       0.00065
///   P(< 3)       vanishing
///
/// A dead axis yields exactly 1. Summed across three axes that is 22 or so
/// out of 33, which trips a lenient aggregate warn and no more: two working
/// axes mask the third and two thirds of the source dies quietly. Per axis it
/// is unmistakable.
///
/// REJECT at 3 catches a stuck register, a bus stuck at 0x00 or 0xFF, and a
/// gyro that never started, on any single axis. WARN at 9 fires by chance
/// about once in 1500 per axis, so roughly once in 500 boots across all
/// three; it does not reject, because that rate must not brick seed
/// generation on a good board.
const HEALTH_MIN_DISTINCT: u32 = 3;
const HEALTH_WARN_DISTINCT: u32 = 9;

/// 0 = not probed, 1 = absent, otherwise the confirmed I2C address.
///
/// Absent is sticky. A missing, unresponsive or STUCK IMU must contribute
/// NOTHING rather than contributing zeros, which is the failure this whole
/// module exists to defend against.
static IMU_ADDR: AtomicU8 = AtomicU8::new(0);
const ADDR_ABSENT: u8 = 1;

fn write_reg(i2c: &mut I2c<'_, esp_hal::Blocking>, addr: u8, reg: u8, val: u8) -> bool {
    i2c.write(addr, &[reg, val]).is_ok()
}

fn read_reg(i2c: &mut I2c<'_, esp_hal::Blocking>, addr: u8, reg: u8) -> Option<u8> {
    let mut buf = [0u8; 1];
    if i2c.write_read(addr, &[reg], &mut buf).is_ok() {
        Some(buf[0])
    } else {
        None
    }
}

/// Mark `b` in a 256-bit bitmap. Returns true if it had not been seen.
///
/// No allocator and no sort: 32 bytes of stack per axis, one pass.
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

/// Distinct low-byte values per axis over a buffer produced by `collect`.
///
/// `collect` writes X, Y, Z, X, Y, Z..., so axis k is the stride-3 subsequence
/// starting at k. A trailing partial pass is counted for whichever axes it
/// reached, which is why callers should compare against `buf.len() / 3` rather
/// than assume a fixed denominator.
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

/// First sample of each axis in a buffer produced by `collect`.
///
/// On an axis whose distinct count is 1, this IS the stuck value, and the
/// value names the failure: 0xFF or 0x00 is a rail-pinned axis (full-scale
/// clip), anything else is a frozen register or a bus fault.
pub fn axis_first_byte(buf: &[u8]) -> [u8; 3] {
    let mut f = [0u8; 3];
    for ax in 0..3usize {
        if ax < buf.len() {
            f[ax] = buf[ax];
        }
    }
    f
}

/// Boot health measurement: per-axis noise AND per-axis DC level.
///
/// Two different questions, and the distinct count answers only one of them.
/// `distinct` says whether an axis is NOISY, which is what the entropy claim
/// rests on. `mean` says whether an axis is ALIVE at DC and responds to
/// orientation: tilt the board and the means move, leave it still and they sit
/// near zero while the distinct counts stay high. An axis can be alive and not
/// noisy (a filter left on), or noisy garbage and not alive. Log both.
struct Health {
    passes: u32,
    distinct: [u32; 3],
    /// Mean of the signed 16-bit reading, in LSB. 128 LSB = 1 dps at the
    /// +/-256 dps scale this driver configures.
    mean: [i32; 3],
    /// Samples at or past CLIP_THRESHOLD. Non-zero means the axis is hitting
    /// the rail, which pins its low byte to a constant and is the documented
    /// cause of a distinct count of 1.
    clipped: [u32; 3],
}

fn measure_health(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
    addr: u8,
    passes: usize,
) -> Health {
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
                    delay.delay_micros(150);
                    waited += 1;
                    if waited > 200 {
                        break;
                    }
                }
                None => {
                    return Health { passes: done, distinct, mean: axis_mean(&sum, done), clipped };
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
                    return Health { passes: done, distinct, mean: axis_mean(&sum, done), clipped };
                }
            }
        }
        done += 1;
    }

    Health { passes: done, distinct, mean: axis_mean(&sum, done), clipped }
}

fn axis_mean(sum: &[i32; 3], n: u32) -> [i32; 3] {
    if n == 0 {
        return [0; 3];
    }
    [sum[0] / n as i32, sum[1] / n as i32, sum[2] / n as i32]
}

/// Probe and configure. Call once, after I2C is up, before the seed screen.
///
/// Returns true if the part answered with the expected WHO_AM_I, accepted its
/// configuration, AND passed a live health check proving the gyro is actually
/// producing varying data. Safe to call more than once; later calls are no-ops.
///
/// Never panics and never blocks on a missing device: a failed probe marks the
/// IMU absent and `collect` then contributes nothing.
pub fn init(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) -> bool {
    let prev = IMU_ADDR.load(Ordering::Relaxed);
    if prev == ADDR_ABSENT {
        return false;
    }
    if prev != 0 {
        return true;
    }

    let mut found: Option<u8> = None;
    for &addr in ADDR_CANDIDATES.iter() {
        if read_reg(i2c, addr, REG_WHO_AM_I) == Some(WHO_AM_I_VALUE) {
            found = Some(addr);
            break;
        }
    }

    let addr = match found {
        Some(a) => a,
        None => {
            IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
            #[cfg(not(feature = "silent"))]
            crate::log!("   [imu] QMI8658C not found, entropy source unavailable");
            return false;
        }
    };

    // Order matters: sensor configuration first, enable last, so the gyro
    // starts with its final settings rather than being reconfigured while
    // running.
    let ok = write_reg(i2c, addr, REG_CTRL1, CTRL1_ADDR_AUTO_INC)
        && write_reg(i2c, addr, REG_CTRL3, CTRL3_GYRO_CFG)
        && write_reg(i2c, addr, REG_CTRL5, CTRL5_NO_FILTER)
        && write_reg(i2c, addr, REG_CTRL7, CTRL7_GYRO_ENABLE);

    if !ok {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        #[cfg(not(feature = "silent"))]
        crate::log!("   [imu] QMI8658C config write failed, entropy source unavailable");
        return false;
    }

    delay.delay_millis(GYRO_TURNON_MS);

    // Publish the address BEFORE the health check: collect() needs it, and a
    // failure below overwrites it with ADDR_ABSENT.
    IMU_ADDR.store(addr, Ordering::Relaxed);

    // ── Health check ─────────────────────────────────────────────────
    //
    // An answering WHO_AM_I proves the part is on the bus. It does not prove
    // the gyro is running, that the drive loop started, or that the output
    // registers are anything but zero. Read real samples and require them to
    // vary before this source is allowed to claim it contributes anything.
    let mut h = measure_health(i2c, delay, addr, HEALTH_PASSES);
    if h.passes < HEALTH_PASSES as u32 {
        // One retry: the drive loop may still be settling on a cold part.
        delay.delay_millis(50);
        h = measure_health(i2c, delay, addr, HEALTH_PASSES);
    }

    let worst = h.distinct[0].min(h.distinct[1]).min(h.distinct[2]);

    if h.passes < HEALTH_PASSES as u32 || worst < HEALTH_MIN_DISTINCT {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        #[cfg(not(feature = "silent"))]
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

    #[cfg(not(feature = "silent"))]
    {
        // LOW means it passed but at least one axis is below what a healthy
        // one produces. Expected is ~10.8 of 11 per axis; under 9 happens by
        // chance about once in 1500 per axis. One LOW line is a shrug. The
        // same axis low on every boot is a dead or filtered axis.
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

    #[cfg(feature = "imu-dump")]
    dump(i2c, delay);

    true
}

/// Bench diagnostic. Prints 16 raw gyro samples, full 16-bit per axis, and
/// flags any pass identical to the one before it.
///
/// This answers one question that the distinct count cannot: WHY a low count
/// happened. A repeated pass means the STATUS0 gDA gate let a stale sample
/// through. Low bytes that collide while the 16-bit values keep changing means
/// the sensor is fine and the draw was unlucky.
///
/// Never compiled into a shipped build; see the compile_error at the top of
/// this file. Do not generate a real seed on a board running this feature.
#[cfg(feature = "imu-dump")]
fn dump(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) {
    let addr = IMU_ADDR.load(Ordering::Relaxed);
    if addr == 0 || addr == ADDR_ABSENT {
        crate::log!("   [imu-dump] absent, nothing to dump");
        return;
    }

    crate::log!("   [imu-dump] pass      GX      GY      GZ   low bytes");

    let mut prev = [0i16; 3];
    let mut repeats = 0u32;
    let mut stale_waits = 0u32;

    for pass in 0..16u32 {
        // Wait for a fresh sample, bounded.
        let mut waited = 0u32;
        loop {
            match read_reg(i2c, addr, REG_STATUS0) {
                Some(s) if s & STATUS0_GYRO_DATA_READY != 0 => break,
                Some(_) => {
                    delay.delay_micros(150);
                    waited += 1;
                    if waited > 200 {
                        break;
                    }
                }
                None => {
                    crate::log!("   [imu-dump] bus error at pass {}", pass);
                    return;
                }
            }
        }
        stale_waits += waited;

        let mut v = [0i16; 3];
        for i in 0..3 {
            let lo = read_reg(i2c, addr, AXIS_REGS[i].0);
            let hi = read_reg(i2c, addr, AXIS_REGS[i].1);
            match (lo, hi) {
                (Some(l), Some(h)) => v[i] = i16::from_le_bytes([l, h]),
                _ => {
                    crate::log!("   [imu-dump] read error at pass {}", pass);
                    return;
                }
            }
        }

        let same = pass > 0 && v == prev;
        if same {
            repeats += 1;
        }

        crate::log!(
            "   [imu-dump]  {:2}  {:6}  {:6}  {:6}   {:02X} {:02X} {:02X}{}",
            pass,
            v[0],
            v[1],
            v[2],
            v[0].to_le_bytes()[0],
            v[1].to_le_bytes()[0],
            v[2].to_le_bytes()[0],
            if same { "  <-- REPEATED PASS" } else { "" }
        );

        prev = v;
    }

    crate::log!(
        "   [imu-dump] {} repeated passes of 16, {} gDA waits total",
        repeats,
        stale_waits
    );
}

/// Collect gyro noise into `out`. Returns the number of bytes written.
///
/// Writes one byte per axis per sample, taking only the LOW byte of each
/// 16-bit reading. The high byte carries the actual angular rate, which on a
/// device lying still is a near-constant close to zero and would dilute the
/// pool rather than fill it. The low byte is where the noise lives.
///
/// Each axis is fetched with its own single-register read rather than one
/// burst; see CTRL1_ADDR_AUTO_INC. A side effect is that the three bytes of a
/// pass may straddle two ODR periods, which for an entropy source is neutral
/// at worst and marginally helpful at best.
///
/// Returns 0 if the IMU is absent or never initialised. Callers must treat a
/// 0 return as "this source contributed nothing" and must not mix `out`.
pub fn collect(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
    out: &mut [u8],
) -> usize {
    let addr = IMU_ADDR.load(Ordering::Relaxed);
    if addr == 0 || addr == ADDR_ABSENT {
        return 0;
    }

    let mut written = 0usize;
    // Bounded so a wedged bus cannot spin here. Each pass yields at most 3
    // bytes, so this caps the loop well above any realistic `out` length.
    let max_passes = out.len() * 2 + 16;

    for _ in 0..max_passes {
        if written >= out.len() {
            break;
        }

        // Only take a sample the sensor reports as new. Re-reading the same
        // registers faster than the ODR returns identical bytes, which would
        // inflate the apparent sample count without adding anything.
        match read_reg(i2c, addr, REG_STATUS0) {
            Some(s) if s & STATUS0_GYRO_DATA_READY != 0 => {}
            Some(_) => {
                // 8 kHz ODR means a fresh sample every 125 us.
                delay.delay_micros(150);
                continue;
            }
            None => break, // bus error: stop, do not fabricate data
        }

        // One read per axis. A bus error mid-pass keeps whatever was already
        // written and stops; it never pads.
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

/// Minimum distinct low-byte values PER AXIS, as a fraction of the per-axis
/// sample count, for a collection to be called healthy at the point of use.
///
/// Expressed as a percentage so callers with different buffer sizes share one
/// rule. A healthy axis returns ~94% (30 of 32, 7.9 of 8); the threshold is
/// 60%, which no unlucky draw reaches and no frozen axis clears.
pub const HEALTHY_DISTINCT_PCT: u32 = 60;

/// Verdict on a buffer produced by `collect`: true if every axis carried real
/// variation.
///
/// The boot health check is not enough on its own. It proves the part was
/// alive at boot, and the seed-time evidence is that an axis can be alive at
/// boot and frozen later. A source must be checked where it is used, not only
/// where it is initialised.
pub fn buffer_is_healthy(buf: &[u8]) -> bool {
    let per_axis = (buf.len() / 3) as u32;
    if per_axis < 4 {
        return false;
    }
    let d = axis_distinct(buf);
    let min_needed = per_axis * HEALTHY_DISTINCT_PCT / 100;
    d[0] >= min_needed && d[1] >= min_needed && d[2] >= min_needed
}

/// Print a collected buffer as one row per pass, flagging repeats.
///
/// Dumps exactly the bytes that were mixed, so it costs no extra I2C and
/// cannot perturb what it is measuring. Whole-pass repeats point at the
/// STATUS0 gDA gate; a single column stuck while the others move points at the
/// sensor or the bus.
#[cfg(feature = "imu-dump")]
pub fn dump_buffer(buf: &[u8]) {
    crate::log!("   [imu-dump] pass   X  Y  Z");
    let passes = buf.len() / 3;
    let mut whole_repeats = 0u32;
    for p in 0..passes {
        let x = buf[p * 3];
        let y = buf[p * 3 + 1];
        let z = buf[p * 3 + 2];
        let same = p > 0
            && x == buf[(p - 1) * 3]
            && y == buf[(p - 1) * 3 + 1]
            && z == buf[(p - 1) * 3 + 2];
        if same {
            whole_repeats += 1;
        }
        crate::log!(
            "   [imu-dump]  {:2}   {:02X} {:02X} {:02X}{}",
            p, x, y, z,
            if same { "   <-- WHOLE PASS REPEATED" } else { "" }
        );
    }
    let d = axis_distinct(buf);
    crate::log!(
        "   [imu-dump] {} whole-pass repeats of {}, distinct X{} Y{} Z{}",
        whole_repeats, passes, d[0], d[1], d[2]
    );
}

/// True if a QMI8658C was found, configured and passed the boot health check.
pub fn present() -> bool {
    let a = IMU_ADDR.load(Ordering::Relaxed);
    a != 0 && a != ADDR_ABSENT
}

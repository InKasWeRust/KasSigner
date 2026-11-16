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

//! The M5's BMI270, as an entropy source.
//!
//! A six-axis IMU on the internal bus with the camera, the touch controller
//! and the PMU. It produces nothing until Bosch's 8,192-byte microcode is
//! written into it, at every power-on (`vendor/bmi270`, BSD-3-Clause).
//!
//! It matters most here: the GC0308 clamps its black level so hard that a
//! covered lens gives identical frames, so in the dark the camera credits
//! nothing, and without the gyro, touch alone would carry the seed's 128
//! bits, about 25 seconds of scribbling.
//!
//! Configured for noise, not motion: the fastest output rate, so samples
//! are as independent as possible; the least filtering, since filtering
//! removes what is harvested; and a range narrow enough that thermal noise
//! spans many counts but a hand movement does not saturate it. Only the low
//! byte of each axis is taken, where the thermal noise lives; the high bytes
//! carry orientation, a constant on a desk.
//!
//! Never an identifier: offset and sensitivity are per-part constants,
//! useful for identity and useless as entropy. Nothing here reads a serial
//! number.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use embedded_hal::i2c::I2c;

use kassigner_hal::timer::Timer;

use crate::systimer::SysTimer;

/// The blob, and the reason this module exists.
#[path = "../../../../vendor/bmi270/config.rs"]
mod config;

/// The two addresses a BMI270 answers on: `0x69` with `SDO` high, M5Stack's
/// for the CoreS3, then `0x68` with it low, so a board revision that moved
/// it is found rather than reported missing.
const ADDR_CANDIDATES: [u8; 2] = [0x69, 0x68];

/// Set once [`init`] has found the part, or to [`ADDR_ABSENT`] once it has
/// looked and failed, so a failed probe costs one bus scan per boot.
static IMU_ADDR: AtomicU8 = AtomicU8::new(0);
const ADDR_ABSENT: u8 = 0xFF;

/// Where [`init`] gave up, as an index into [`FAILURES`]; zero is no failure.
/// Log lines expand to nothing in this crate, so this is how a caller learns
/// which of the eight steps refused.
static FAILED_AT: AtomicU8 = AtomicU8::new(0);

/// Why [`init`] gave up, in the order the steps run.
const FAILURES: [&str; 9] = [
    "",
    "no BMI270 chip id at 0x69 or 0x68",
    "soft reset refused",
    "power config refused",
    "loader would not arm",
    "the blob did not go in",
    "loader would not disarm",
    "the part refused its own configuration",
    "gyro config refused",
];

/// How long after the soft reset the part first answered, in microseconds.
static RESET_WAIT_US: AtomicU32 = AtomicU32::new(0);

/// How often the first write after a reset is retried.
const RESET_WAIT_STEP_US: u32 = 2_000;

/// How long a part has to answer after a soft reset before it is called
/// dead: Bosch give 2 ms, a part already running took 4 ms on an M5.
const RESET_WAIT_MAX_US: u32 = 100_000;

/// Microseconds from the soft reset to the part's first answer, on the last
/// successful [`init`]. Zero before one has run.
pub fn reset_wait_us() -> u32 {
    RESET_WAIT_US.load(Ordering::Relaxed)
}

/// Why the last [`init`] failed, or `None` if it did not.
pub fn failure() -> Option<&'static str> {
    match FAILED_AT.load(Ordering::Relaxed) {
        0 => None,
        i => FAILURES.get(usize::from(i)).copied(),
    }
}

const REG_CHIP_ID: u8 = 0x00;
const CHIP_ID_BMI270: u8 = 0x24;
const REG_STATUS: u8 = 0x03;
const STATUS_GYR_DRDY: u8 = 0x40;
/// Gyro data, six bytes from here: X, Y, Z, low byte first.
const REG_GYR_X_LSB: u8 = 0x12;
const REG_INTERNAL_STATUS: u8 = 0x21;
const INTERNAL_STATUS_OK: u8 = 0x01;
const REG_GYR_CONF: u8 = 0x42;
/// Measurement range, the byte after the config.
const REG_GYR_RANGE: u8 = 0x43;
const REG_INIT_CTRL: u8 = 0x59;
const REG_INIT_ADDR_0: u8 = 0x5B;
const REG_INIT_ADDR_1: u8 = 0x5C;
const REG_INIT_DATA: u8 = 0x5E;
const REG_PWR_CONF: u8 = 0x7C;
const REG_PWR_CTRL: u8 = 0x7D;
const REG_CMD: u8 = 0x7E;
const CMD_SOFT_RESET: u8 = 0xB6;

/// Gyro on, accelerometer and temperature off: only the gyro is read, and
/// the rest would only draw current.
const PWR_CTRL_GYR_ONLY: u8 = 0x02;

/// 3,200 Hz, the fastest the gyro offers, with the least filtering.
///
/// `[3:0]` output rate `0x0D`, `[5:4]` filter `0x02` for normal mode, `[6]`
/// noise performance, `[7]` filter performance.
///
/// Normal mode is the least filtered at this rate. OSR4 oversamples by four
/// and is the most filtered: measured on an M5 with OSR4 at ±2,000, the low
/// byte walked one count at a time, lag-1 correlation `+0.86`, 66 distinct
/// values in 32 KB, 1.93 bits a byte.
const GYR_CONF_FAST: u8 = 0xED;

/// ±250 degrees a second: `[2:0]` range `0x03`, the rest clear.
///
/// Measured on an M5, 32 KB captures, the lowest estimator in each posture,
/// in bits a byte:
///
/// | range | still | in a hand | worst |
/// |---|---|---|---|
/// | ±2,000, OSR4 | 1.93 | 5.56 | 1.93 |
/// | ±125, normal | 7.08 | 1.72 | 1.72 |
/// | **±250, normal** | **6.33 / 6.25** | **2.69 / 2.86** | **2.69** |
///
/// The ±2,000 row also had OSR4 filtering. The ±250 row is two runs:
/// hand-held captures vary by 0.17 bits, so a smaller gap is no result.
///
/// **A credit rests on the worst column**, a person holding the device and
/// scribbling, as a seed is collected. At ±2,000 thermal noise spans eight
/// times fewer counts; at ±125 a hand movement pegs the gyro at its limit
/// (lag-1 `+0.70`); at ±250 lag-1 is `+0.43` to `+0.53` in a hand and
/// within `0.04` of zero at rest. The credit, half a bit a byte, sits five
/// times under the worst, 2.69.
const GYR_RANGE_NARROW: u8 = 0x03;

/// Bytes of the blob written per bus transaction. The part may take the
/// 8 KB in any split, provided the address registers are stepped; 64 is a
/// size every ESP32 I2C driver handles in one go, and 128 transactions cost
/// little at 400 kHz beside the 8 KB itself.
const BURST: usize = 64;

fn write_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8, val: u8) -> bool {
    i2c.write(addr, &[reg, val]).is_ok()
}

fn read_reg<I: I2c>(i2c: &mut I, addr: u8, reg: u8) -> Option<u8> {
    let mut buf = [0u8; 1];
    i2c.write_read(addr, &[reg], &mut buf).ok().map(|()| buf[0])
}

/// Find, reset and configure the part, uploading the blob, and return
/// whether the gyro is running. The answer is remembered: a second call
/// costs nothing and a missing part is not probed again.
///
/// The sequence is Bosch's: leave advanced power save, arm the loader, write
/// the blob, disarm, wait, and read `INTERNAL_STATUS` for the part's own
/// verdict, so a corrupted blob reports itself rather than producing quiet
/// nonsense.
pub fn init<I: I2c>(i2c: &mut I, delay: &mut SysTimer) -> bool {
    let prev = IMU_ADDR.load(Ordering::Relaxed);
    if prev == ADDR_ABSENT {
        return false;
    }
    if prev != 0 {
        return true;
    }

    let mut found = None;
    for &addr in ADDR_CANDIDATES.iter() {
        if read_reg(i2c, addr, REG_CHIP_ID) == Some(CHIP_ID_BMI270) {
            found = Some(addr);
            break;
        }
    }
    let Some(addr) = found else {
        return absent(1);
    };

    // A reset first, so a warm boot starts as a cold one does. Bosch give
    // 2 ms after it; a part already running the blob and the gyro took 4 ms
    // on an M5. So the first write after it is retried every 2 ms up to
    // `RESET_WAIT_MAX_US`, and the wait is kept for `reset_wait_us`.
    if !write_reg(i2c, addr, REG_CMD, CMD_SOFT_RESET) {
        return absent(2);
    }
    let mut waited: u32 = 0;
    loop {
        delay.delay_us(RESET_WAIT_STEP_US);
        waited += RESET_WAIT_STEP_US;
        // Advanced power save must be off while the loader runs.
        if write_reg(i2c, addr, REG_PWR_CONF, 0x00) {
            break;
        }
        if waited >= RESET_WAIT_MAX_US {
            return absent(3);
        }
    }
    RESET_WAIT_US.store(waited, Ordering::Relaxed);
    delay.delay_us(500);

    // Arm the loader, write the blob, disarm.
    if !write_reg(i2c, addr, REG_INIT_CTRL, 0x00) {
        return absent(4);
    }
    if !upload(i2c, addr) {
        return absent(5);
    }
    if !write_reg(i2c, addr, REG_INIT_CTRL, 0x01) {
        return absent(6);
    }

    // The part checks the blob and reports in `INTERNAL_STATUS`. Bosch allow
    // 20 ms; this waits up to 50 ms in 5 ms steps, so a slow part is not
    // called dead and a missing one does not hold the boot.
    let mut ok = false;
    for _ in 0..10 {
        delay.delay_us(5_000);
        if read_reg(i2c, addr, REG_INTERNAL_STATUS) == Some(INTERNAL_STATUS_OK) {
            ok = true;
            break;
        }
    }
    if !ok {
        return absent(7);
    }

    // Configure, then enable, so the gyro starts with its final settings.
    if !write_reg(i2c, addr, REG_GYR_CONF, GYR_CONF_FAST)
        || !write_reg(i2c, addr, REG_GYR_RANGE, GYR_RANGE_NARROW)
        || !write_reg(i2c, addr, REG_PWR_CTRL, PWR_CTRL_GYR_ONLY)
    {
        return absent(8);
    }
    // The gyro needs a moment before its first sample is ready.
    delay.delay_us(50_000);

    IMU_ADDR.store(addr, Ordering::Relaxed);
    FAILED_AT.store(0, Ordering::Relaxed);
    crate::log!("   [imu] BMI270 at {:#04x}, gyro running", addr);
    true
}

/// Record where [`init`] gave up and remember the part as absent.
fn absent(step: u8) -> bool {
    IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
    FAILED_AT.store(step, Ordering::Relaxed);
    crate::log!(
        "   [imu] BMI270 init failed: {}",
        FAILURES[usize::from(step)]
    );
    false
}

/// Write the 8 KB blob, stepping the address registers as Bosch require.
///
/// The address is in words, not bytes: `INIT_ADDR_0` holds bits 3:0 of the
/// word address and `INIT_ADDR_1` bits 11:4. Get it wrong and the blob
/// passes every bus check but fails the part's own.
fn upload<I: I2c>(i2c: &mut I, addr: u8) -> bool {
    let mut buf = [0u8; BURST + 1];
    buf[0] = REG_INIT_DATA;
    for (i, chunk) in config::CONFIG.chunks(BURST).enumerate() {
        let word = (i * BURST / 2) as u16;
        if !write_reg(i2c, addr, REG_INIT_ADDR_0, (word & 0x0F) as u8)
            || !write_reg(i2c, addr, REG_INIT_ADDR_1, (word >> 4) as u8)
        {
            return false;
        }
        buf[1..=chunk.len()].copy_from_slice(chunk);
        if i2c.write(addr, &buf[..=chunk.len()]).is_err() {
            return false;
        }
    }
    true
}

/// Fill `out` with gyro low bytes, three at a time, and say how many landed.
///
/// One byte per axis per pass, as on the Waveshare, so `kassigner_fw::seed`'s
/// per-axis health test reads either board's buffer. Only samples the part
/// reports as new are taken: re-reading faster than the output rate returns
/// the same bytes and would inflate the count. A bus error stops it, keeping
/// what was written; it never pads.
pub fn collect<I: I2c>(i2c: &mut I, delay: &mut SysTimer, out: &mut [u8]) -> usize {
    let addr = IMU_ADDR.load(Ordering::Relaxed);
    if addr == 0 || addr == ADDR_ABSENT {
        return 0;
    }

    let mut written = 0usize;
    // Bounded so a wedged bus cannot spin here.
    let max_passes = out.len() * 2 + 16;
    for _ in 0..max_passes {
        if written >= out.len() {
            break;
        }
        match read_reg(i2c, addr, REG_STATUS) {
            Some(s) if s & STATUS_GYR_DRDY != 0 => {}
            Some(_) => {
                // 3,200 Hz is a fresh sample every 312 us.
                delay.delay_us(350);
                continue;
            }
            None => break,
        }

        // Six bytes in one transaction, then keep the low byte of each axis.
        let mut raw = [0u8; 6];
        if i2c.write_read(addr, &[REG_GYR_X_LSB], &mut raw).is_err() {
            return written;
        }
        for axis in 0..3 {
            if written >= out.len() {
                break;
            }
            out[written] = raw[axis * 2];
            written += 1;
        }
    }
    written
}

/// Whether the part is running, for a caller deciding which sources it has.
pub fn is_present() -> bool {
    let a = IMU_ADDR.load(Ordering::Relaxed);
    a != 0 && a != ADDR_ABSENT
}

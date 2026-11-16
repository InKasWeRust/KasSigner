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

//! The ESP32-S3's own temperature sensor, read on the die.
//!
//! esp-hal 1.2 has no driver for it on this chip, so this drives two
//! registers of the RTC's SENS block as the `esp32s3` PAC 0.36 lays them
//! out: `SAR_TSENS_CTRL` at `0x6000_8850` (reading in bits 7:0, ready in 8,
//! clock divider in 21:14, power-up and its force in 22 and 23, "dump out"
//! in 24) and `SAR_PERI_CLK_GATE_CONF` at `0x6000_8904` (the sensor's clock
//! in bit 29). Sequence and conversion are ESP-IDF's
//! (`temperature_sensor_ll.h`): power up, clock divider 6, then per reading
//! set dump-out, wait for ready, read, clear.
//!
//! Degrees use ESP-IDF's default-range formula, 0.4386 a count less 20.52,
//! without the eFuse calibration offset, so they may be a few degrees off:
//! they compare one state of the unit with another (the Waveshare runs
//! hot).

use core::ptr::{read_volatile, write_volatile};

const SAR_TSENS_CTRL: *mut u32 = 0x6000_8850 as *mut u32;
const SAR_PERI_CLK_GATE_CONF: *mut u32 = 0x6000_8904 as *mut u32;

const OUT_MASK: u32 = 0xFF;
const READY: u32 = 1 << 8;
const CLK_DIV_SHIFT: u32 = 14;
const CLK_DIV_MASK: u32 = 0xFF << CLK_DIV_SHIFT;
const POWER_UP: u32 = 1 << 22;
const POWER_UP_FORCE: u32 = 1 << 23;
const DUMP_OUT: u32 = 1 << 24;
const TSENS_CLK_EN: u32 = 1 << 29;

/// Clock and power the sensor, once at bring-up; a reading taken before it
/// settles comes back `None`.
pub fn init() {
    // SAFETY: fixed MMIO words in the RTC's SENS block, always mapped.
    // `SAR_TSENS_CTRL` is this module's alone; the clock gate, shared with
    // the generator and the Waveshare's battery gauge, is read-modify-write.
    unsafe {
        let gate = read_volatile(SAR_PERI_CLK_GATE_CONF);
        write_volatile(SAR_PERI_CLK_GATE_CONF, gate | TSENS_CLK_EN);
        let ctrl = read_volatile(SAR_TSENS_CTRL) & !CLK_DIV_MASK;
        write_volatile(
            SAR_TSENS_CTRL,
            ctrl | (6 << CLK_DIV_SHIFT) | POWER_UP | POWER_UP_FORCE,
        );
    }
}

/// The die's temperature in tenths of a degree, or `None` if the sensor
/// did not answer within about a millisecond.
pub fn tenths() -> Option<i32> {
    // SAFETY: as in `init`.
    unsafe {
        let ctrl = read_volatile(SAR_TSENS_CTRL);
        write_volatile(SAR_TSENS_CTRL, ctrl | DUMP_OUT);
        let mut ready = false;
        for _ in 0..100_000 {
            if read_volatile(SAR_TSENS_CTRL) & READY != 0 {
                ready = true;
                break;
            }
        }
        let raw = (read_volatile(SAR_TSENS_CTRL) & OUT_MASK) as i32;
        write_volatile(SAR_TSENS_CTRL, read_volatile(SAR_TSENS_CTRL) & !DUMP_OUT);
        // 0.4386 a count less 20.52, in tenths.
        ready.then_some((4386 * raw - 205_200) / 1000)
    }
}

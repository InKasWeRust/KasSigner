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

// hw/pmu.rs — Backlight PWM control for Waveshare ESP32-S3-Touch-LCD-2
//
// LEDC Timer1/Channel1 on GPIO1, configured by esp-hal in main.rs.
// set_brightness() updates duty via direct register writes.

#![allow(dead_code)]
use esp_hal::i2c::master::I2c;

const LEDC_BASE: u32 = 0x6001_9000;
const LEDC_LSCH1_CONF0: u32 = LEDC_BASE + 0x14;
const LEDC_LSCH1_DUTY: u32 = LEDC_BASE + 0x1C;
const LEDC_LSCH1_CONF1: u32 = LEDC_BASE + 0x20;

/// Set backlight brightness 0-255 via LEDC PWM duty on Channel1/GPIO1.
pub fn set_brightness(_i2c: &mut I2c<'_, esp_hal::Blocking>, brightness: u8) {
    unsafe {
        core::ptr::write_volatile(LEDC_LSCH1_DUTY as *mut u32, (brightness as u32) << 4);
        core::ptr::write_volatile(LEDC_LSCH1_CONF1 as *mut u32, 1u32 << 31);
        let conf0 = core::ptr::read_volatile(LEDC_LSCH1_CONF0 as *const u32);
        core::ptr::write_volatile(LEDC_LSCH1_CONF0 as *mut u32, conf0 | (1 << 4));
    }
}

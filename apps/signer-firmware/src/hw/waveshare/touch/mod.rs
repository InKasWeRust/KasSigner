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

// hw/touch/touch_cst816d.rs — CST816D driver for Waveshare ESP32-S3-Touch-LCD-2
//
// STATELESS DESIGN: each I2C read is independent.
//   - GestureID is a swipe → return Swipe (once per gesture)
//   - Event is PressDown, no gesture → return Tap
//   - Everything else → None
//
// CST816D gesture rotation (portrait → Deg90 landscape):
//   CST816D SwipeUp(0x01)    = finger moves right on screen
//   CST816D SwipeDown(0x02)  = finger moves left on screen

use esp_hal::i2c::master::I2c;

pub use crate::hw::shared::touch::{TouchState, TouchZone};
#[cfg(test)]
pub use signer_firmware_core::input::touch::TouchEventType;
pub use signer_firmware_core::input::touch::TouchPoint;
pub use signer_firmware_core::input::touch::{HwGesture, TouchAction, TouchTracker};
use signer_firmware_core::input::{
    recovery::run_i2c_recovery,
    touch::{decode_gesture_byte, decode_touch_event_flag},
};

const CST816D_ADDR: u8 = 0x15;
const REG_GESTURE_ID: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════
// I2C bus recovery
// ═══════════════════════════════════════════════════════════════

use core::sync::atomic::{AtomicU8, Ordering};

/// Consecutive I2C error counter. When this reaches BUS_RECOVERY_THRESHOLD,
/// we attempt bus recovery by toggling SCL 9 times to unstick a slave
/// holding SDA LOW (e.g. CST816D clock-stretching after idle wakeup).
static TOUCH_I2C_ERRORS: AtomicU8 = AtomicU8::new(0);
const BUS_RECOVERY_THRESHOLD: u8 = 5;

// GPIO register addresses (same as sdcard_ws.rs)
const GPIO_OUT1_W1TS: u32   = 0x6000_4014;
const GPIO_OUT1_W1TC: u32   = 0x6000_4018;
const GPIO_ENABLE1_W1TS: u32 = 0x6000_4030;
const GPIO_ENABLE1_W1TC: u32 = 0x6000_4034;

// Touch I2C pins (Waveshare)
const PIN_TP_SCL: u8 = 47; // GPIO47 = bit 15 in OUT1 (47-32=15)
const PIN_TP_SDA: u8 = 48; // GPIO48 = bit 16 in OUT1 (48-32=16)

/// Toggle SCL 9 times with SDA held HIGH to unstick a slave holding SDA LOW.
/// Then issue a STOP condition (SDA LOW while SCL HIGH, then SDA HIGH).
/// Uses direct GPIO register writes, bypassing esp-hal's I2C peripheral.
/// After recovery, the I2C peripheral re-takes control on the next
/// i2c.write_read() call because the bus is back in idle state.
fn recover_i2c_bus() {
    #[cfg(not(feature = "silent"))]
    crate::log!("[CST816D] I2C bus recovery: 9 SCL toggles");

    let lines = recovery_line_mask();
    unsafe { core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, lines); }
    run_i2c_recovery(9, set_recovery_scl, set_recovery_sda, recovery_delay);
    unsafe { core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, lines); }
}

const fn recovery_line_mask() -> u32 {
    (1u32 << (PIN_TP_SCL - 32)) | (1u32 << (PIN_TP_SDA - 32))
}

fn set_recovery_scl(high: bool) {
    set_recovery_line(1u32 << (PIN_TP_SCL - 32), high);
}

fn set_recovery_sda(high: bool) {
    set_recovery_line(1u32 << (PIN_TP_SDA - 32), high);
}

fn set_recovery_line(bit: u32, high: bool) {
    let address = if high { GPIO_OUT1_W1TS } else { GPIO_OUT1_W1TC };
    unsafe { core::ptr::write_volatile(address as *mut u32, bit); }
}

fn recovery_delay() {
    for _ in 0..400u32 {
        core::hint::spin_loop();
    }
}

// ═══════════════════════════════════════════════════════════════
// I2C read
// ═══════════════════════════════════════════════════════════════

pub fn read_touch_full(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    configured: &mut bool,
) -> (TouchState, HwGesture) {
    let Some(registers) = read_registers(i2c, configured) else {
        return (TouchState::NoTouch, HwGesture::None);
    };
    configure_controller_once(i2c, configured);
    decode_registers(registers)
}

fn read_registers(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    configured: &mut bool,
) -> Option<[u8; 6]> {
    let mut registers = [0u8; 6];
    if i2c.write_read(CST816D_ADDR, &[REG_GESTURE_ID], &mut registers).is_ok() {
        TOUCH_I2C_ERRORS.store(0, Ordering::Relaxed);
        return Some(registers);
    }
    let errors = TOUCH_I2C_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
    if errors >= BUS_RECOVERY_THRESHOLD {
        recover_i2c_bus();
        TOUCH_I2C_ERRORS.store(0, Ordering::Relaxed);
        *configured = false;
    }
    None
}

fn configure_controller_once(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    configured: &mut bool,
) {
    if *configured {
        return;
    }
    *configured = true;
    let _ = i2c.write(CST816D_ADDR, &[0x05, 0x60]);
    let _ = i2c.write(CST816D_ADDR, &[0x06, 0x30]);
    let _ = i2c.write(CST816D_ADDR, &[0xFE, 0x01]);
    #[cfg(not(feature = "silent"))]
    crate::log!("[CST816D] Configured: sens=0x60 lp=0x30 nosleep");
}

fn decode_registers(registers: [u8; 6]) -> (TouchState, HwGesture) {
    if registers[1] & 0x0F == 0 {
        return (TouchState::NoTouch, HwGesture::None);
    }
    let event = decode_touch_event_flag((registers[2] >> 6) & 0x03);
    let raw_x = ((registers[2] as u16 & 0x0F) << 8) | registers[3] as u16;
    let raw_y = ((registers[4] as u16 & 0x0F) << 8) | registers[5] as u16;
    let point = TouchPoint {
        x: raw_y.min(319),
        y: 239u16.saturating_sub(raw_x),
        event,
    };
    (TouchState::One(point), decode_gesture_byte(registers[0]))
}


pub fn read_touch_with_gesture(i2c: &mut I2c<'_, esp_hal::Blocking>) -> (TouchState, HwGesture) {
    let mut dummy = true;
    read_touch_full(i2c, &mut dummy)
}

// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
pub mod unit_tests;

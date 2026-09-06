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


// hw/touch/touch_ft6336u.rs — FT6336U capacitive touch driver + TouchTracker
// 100% Rust, no-std, no-alloc
//
// The FT6336U is on the same internal I2C bus as AXP2101 and AW9523B
// (GPIO12=SDA, GPIO11=SCL). We borrow the I2C bus, not own it.
//
// Register map (FT6x36 family):
//   0x02: TD_STATUS  — [3:0] number of touch points (0, 1, or 2)
//   0x03: P1_XH      — [7:6] event flag, [3:0] X position high nibble
//   0x04: P1_XL      — [7:0] X position low byte
//   0x05: P1_YH      — [7:4] touch ID, [3:0] Y position high nibble
//   0x06: P1_YL      — [7:0] Y position low byte
//
// Event flags (bits [7:6] of P1_XH):
//   0b00 = Press Down
//   0b01 = Lift Up
//   0b10 = Contact
//   0b11 = No Event
//
// CoreS3 display is 320×240. Touch coordinates match display pixels
// when properly calibrated (x: 0-319, y: 0-239).
//
// With Rotation::Deg180, touch coords need to be flipped:
//   display_x = 319 - raw_x
//   display_y = 239 - raw_y

use esp_hal::i2c::master::I2c;

pub use crate::hw::shared::touch::{TouchState, TouchZone};

/// FT6336U I2C address (fixed, not configurable)
const FT6336U_ADDR: u8 = 0x38;

/// Touch status register — number of active touch points
const REG_TD_STATUS: u8 = 0x02;

// ═══════════════════════════════════════════════════════════════
// High-level touch input for UI
// ═══════════════════════════════════════════════════════════════

pub use signer_firmware_core::input::touch::TouchAction;

/// Board facade name consumed by the shared runtime event loop. The actual
/// contact/release reducer is board-neutral and host-testable.
pub type TouchTracker = signer_firmware_core::input::touch::contact_gate::ContactGate;

// ═══════════════════════════════════════════════════════════════
// Raw I2C communication
// ═══════════════════════════════════════════════════════════════

/// Read touch data from FT6336U.
/// Borrows I2C mutably but does not own it.
/// Applies 180° rotation correction for CoreS3 display orientation.
/// Probe the live FT6336U transport without fabricating a touch event.
/// The connected workflow image requires this to succeed before it may PASS.
#[cfg(feature = "workflow-test-auto")]
pub(crate) fn probe(i2c: &mut I2c<'_, esp_hal::Blocking>) -> bool {
    let mut status = [0u8; 1];
    i2c.write_read(FT6336U_ADDR, &[REG_TD_STATUS], &mut status).is_ok()
}

pub(crate) fn read_touch_checked(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
) -> Result<TouchState, ()> {
    let mut registers = [0u8; 5];
    i2c.write_read(FT6336U_ADDR, &[REG_TD_STATUS], &mut registers)
        .map_err(|_| ())?;
    // FT6336U supports two simultaneous contacts. The application is strictly
    // single-touch: treating TD_STATUS=2 as NoTouch would fabricate a release
    // edge and let a second key slip through the contact gate. Fail this sample
    // closed instead; the event loop preserves the existing gate on Err.
    if registers[0] & 0x0F > 1 {
        return Err(());
    }
    Ok(signer_firmware_core::input::touch::decode_rotated_single_touch(
        registers, 319, 239,
    ))
}

// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
pub mod unit_tests;

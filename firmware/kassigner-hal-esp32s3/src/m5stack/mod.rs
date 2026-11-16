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

//! The M5Stack CoreS3 unit: one module per part, each implementing the
//! `kassigner-hal` trait for it where one exists.
//!
//! From the netlist: GPIO14 is the microphone's data line, not a display
//! reset; the camera has its own oscillator, and GPIO2 carries no clock;
//! expander `P0.4` is the card-detect input, and the expander's four input
//! lines are configured as inputs.
//!
//! Every read-modify-write here returns a failed read's error rather than
//! write a value built from it. Drivers hold no UI: the card driver ticks no
//! buzzer, and the display module holds no screens.
//!
//! # One I2C bus
//!
//! The AXP2101, the AW9523B, the touch controller, the camera's SCCB and the
//! amplifier share it. Every driver is generic over `embedded_hal::i2c::I2c`
//! and owns a handle, an `embedded_hal_bus::i2c::RefCellDevice` each.
//!
//! # esp-hal on the device only
//!
//! The DVP capture and the speaker's I2S stream are esp-hal drivers, built
//! on the device by `unit` with `dvp` and `ring`. They come in through
//! [`camera::Capture`] and the buffer [`speaker::M5Speaker`] takes, so the
//! rest builds on a host.
//!
//! # Decoding
//!
//! On core 1, through the decode worker the Waveshare also uses,
//! `decode_core`. [`decoder`] crops the frame into the worker's image and
//! keeps the M5's own window policy.

pub mod backlight;
pub mod battery;
pub mod camera;
#[cfg(target_arch = "xtensa")]
pub mod dvp;
pub mod imu;
pub mod panel;
pub mod pmu;
#[cfg(target_arch = "xtensa")]
pub mod ring;
pub mod sdspi;
pub mod sensor;
pub mod speaker;
pub mod storage;
pub mod touch;

// The one call that brings the unit up. Device only, since it names
// esp-hal's types, and behind `decode` because it starts the decode worker.
#[cfg(all(target_arch = "xtensa", feature = "decode"))]
pub mod unit;

use kassigner_protocol::profile::{Capacity, Profile};

/// What this board holds.
///
/// - 64 frames, matching the companion's generator; the progress dots are
///   laid out for that many.
/// - 256 bytes a frame: a fragment's length is a byte, so none exceeds 255.
/// - 16,384 bytes for the transaction: 64 slots of 256.
/// - 225 bytes a displayed frame: a version-9 code carries 230 and the frame
///   header takes five, frame 0's eight with the payload's digest. A reply is
///   at most 14,397 bytes.
pub const CAPACITY: Capacity = Capacity {
    transaction_bytes: 16_384,
    bytes_per_frame: 256,
    frames: 64,
    display_bytes_per_frame: 225,
};

/// The envelope this board accepts: its capacity, over the ESP32-S3 base.
pub const PROFILE: Profile = CAPACITY.derive(&Profile::ESP32S3);

// Behind the Waveshare decoder's feature: the worker it hands jobs to pulls
// in the vendored QR decoder, which needs a newer rustc than the rest of
// this crate is checked with.
#[cfg(feature = "decode")]
pub mod decoder;

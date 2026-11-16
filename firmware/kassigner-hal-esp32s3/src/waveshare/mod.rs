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

//! The Waveshare ESP32-S3-Touch-LCD-2 unit.
//!
//! [`cam_dma`] and [`decode_core`] are the capture and decode path: a
//! hand-rolled GDMA feed into double-buffered PSRAM, and a worker parked on
//! core 1 behind a four-state atomic handoff. Their timings, poll intervals
//! and thresholds were set on the hardware; change them only against it.
//!
//! [`camera`] presents `cam_dma` as [`kassigner_hal::camera::Camera`], and
//! [`decoder`] presents `decode_core` as [`kassigner_hal::decoder::Decoder`].
//! One resolution, 480x480; every decode job is a 240x240 square, and
//! `denom` is the binarisation window, not a resolution.
//!
//! Capture and decode are separate traits because they run on different
//! cores: a decode on core 0 would halt the viewfinder for its length. The
//! M5 decodes on its core 1 through the same worker, and the portable scan
//! loop never learns which unit it has.

pub mod backlight;
pub mod battery;
pub mod cam_dma;
pub mod camera;
pub mod imu;
pub mod panel;
pub mod sdhost;
pub mod sensor;
pub mod storage;
pub mod touch;

use kassigner_protocol::profile::{Capacity, Profile};

/// What this board holds.
///
/// - 64 frames, matching the companion's generator; the progress dots are
///   laid out for that many.
/// - 256 bytes a frame: a fragment's length is a byte, so none exceeds 255.
/// - 16,384 bytes for the transaction: 64 slots of 256.
/// - 225 bytes a displayed frame: a version-9 code carries 230 and the frame
///   header takes five (frame 0's, with the payload's digest, eight). A
///   reply is then at most 14,397 bytes.
pub const CAPACITY: Capacity = Capacity {
    transaction_bytes: 16_384,
    bytes_per_frame: 256,
    frames: 64,
    display_bytes_per_frame: 225,
};

/// The envelope this board accepts: its capacity, over the ESP32-S3 base.
pub const PROFILE: Profile = CAPACITY.derive(&Profile::ESP32S3);

// `decode_core` and the `Decoder` over it sit behind `decode`, apart from the
// unit features, so the capture path builds and checks without the decoder.
// It sits at the crate root, shared with the M5, and is named here for this
// unit's callers.
#[cfg(feature = "decode")]
pub use crate::decode_core;
#[cfg(feature = "decode")]
pub mod decoder;

// The one call that brings the unit up: device only, as it names esp-hal's
// types, and behind `decode`, as it starts the decode worker.
#[cfg(all(target_arch = "xtensa", feature = "decode"))]
pub mod unit;

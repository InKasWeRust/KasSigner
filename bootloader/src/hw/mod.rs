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

// hw/mod.rs — Hardware abstraction layer (platform-gated module routing)
// hw/ — Hardware abstraction layer
//
// Platform selection via Cargo features:
//   --features waveshare  → Waveshare ESP32-S3-Touch-LCD-2
//   --features m5stack    → M5Stack CoreS3 / CoreS3 Lite
//
// Each platform module re-exports the same public API so the rest
// of the crate can use `hw::display`, `hw::camera`, etc. unchanged.

// ─── Display ─────────────────────────────────────────────────
#![allow(unused_imports)]
#[cfg(feature = "waveshare")]
#[path = "display_ws.rs"]
pub mod display;

#[cfg(feature = "m5stack")]
#[path = "display_m5.rs"]
pub mod display;

// ─── Camera ──────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "camera_ov5640.rs"]
pub mod camera;

#[cfg(feature = "m5stack")]
#[path = "camera_gc0308.rs"]
pub mod camera;

// ─── Touch ───────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "touch_cst816d.rs"]
pub mod touch;

#[cfg(feature = "m5stack")]
#[path = "touch_ft6336u.rs"]
pub mod touch;

// ─── PMU / Backlight ─────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "pmu_ws.rs"]
pub mod pmu;

#[cfg(feature = "m5stack")]
#[path = "pmu_m5.rs"]
pub mod pmu;

// ─── Sound ───────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "sound_ws.rs"]
pub mod sound;

#[cfg(feature = "m5stack")]
#[path = "sound_m5.rs"]
pub mod sound;

// ─── Battery ─────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "battery_ws.rs"]
pub mod battery;

#[cfg(feature = "m5stack")]
#[path = "battery_m5.rs"]
pub mod battery;

// ─── SD Card ─────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "sdcard_ws.rs"]
pub mod sdcard;

#[cfg(feature = "m5stack")]
#[path = "sdcard_m5.rs"]
pub mod sdcard;

// ─── Shared modules (both platforms) ─────────────────────────
pub mod icon_data;
pub mod sd_backup;

// ─── Waveshare-only modules ──────────────────────────────────
#[cfg(feature = "waveshare")]
pub mod board;
#[cfg(feature = "waveshare")]
pub mod lockdown;
#[cfg(feature = "waveshare")]
pub mod ov5640_af_fw;

// ─── Screenshot (optional feature) ──────────────────────────
#[cfg(feature = "screenshot")]
pub mod screenshot;

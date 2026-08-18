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
#[cfg(feature = "waveshare")]
#[path = "display_ws.rs"]
pub mod display;

#[cfg(feature = "m5stack")]
#[path = "display_m5.rs"]
pub mod display;

// ─── IMU (entropy source) ────────────────────────────────────
// Waveshare only. The M5Stack BMI270 needs an 8 KB config blob uploaded on
// every power-up before it returns anything but zeros, which is a much larger
// change and is deliberately not attempted here.
#[cfg(feature = "waveshare")]
#[path = "imu_ws.rs"]
pub mod imu;

// ─── Camera ──────────────────────────────────────────────────
#[cfg(feature = "waveshare")]
#[path = "camera_ov5640.rs"]
pub mod camera;

#[cfg(feature = "waveshare")]
pub mod camera_ov2640;

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
// Camera entropy measurement. Shared deliberately: it was Waveshare-only when
// it lived in cam_dma.rs, which left the seed-path entropy gate real on one
// board and a null-pointer test on the other (audit E-07).
pub mod frame_noise;

// E-12 raw-frame capture. Board-agnostic on purpose: `cam_dma` is Waveshare
// only and M5Stack captures through DvpCamera, so this module takes the
// pixel slice from the caller rather than reaching for a camera itself.
#[cfg(feature = "e12-capture")]
pub mod entropy_capture;

// E-13 raw WDEV_RND capture, for offline SP 800-90B analysis. Board-agnostic:
// the register is on the SoC, not the board. Same shape as E-12 above, and the
// same rule: never enable for a shipped build.
#[cfg(feature = "wdev-capture")]
pub mod wdev_capture;

// ─── M5Stack-only modules ────────────────────────────────────
// ES7210 audio ADC, identification only. Candidate entropy source for a board
// whose only non-SoC source is a camera that goes bit-identical in darkness.
#[cfg(feature = "m5stack")]
pub mod mic_m5;

// ─── Waveshare-only modules ──────────────────────────────────
#[cfg(feature = "waveshare")]
pub mod board;
// Both boards as of 2026-08-02. Every register in here is SoC-level and
// identical across the two; the gate meant untested, not incompatible.
pub mod lockdown;
/// Runtime read of the eFuse provisioning bits. SoC-level, both boards.
pub mod efuse;
#[cfg(feature = "waveshare")]
pub mod ov5640_af_fw;

#[cfg(feature = "waveshare")]
pub mod decode_core;
#[cfg(feature = "waveshare")]
pub mod cam_dma;

// ─── Screenshot (optional feature) ──────────────────────────
#[cfg(feature = "screenshot")]
pub mod screenshot;

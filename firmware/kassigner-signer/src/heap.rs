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

//! The heap: each unit's PSRAM made the allocator's. `main.rs` and, through
//! `#[path]`, every example use this one copy, so no probe sets PSRAM up
//! differently from the firmware.
//!
//! # The S3 units: the mode stated, not probed
//!
//! esp-hal's default, `Auto`, tries octal first, and on the ESP32-S3 an
//! octal probe takes GPIO 33 to 37 and keeps them when it fails: the M5's
//! panel has SCK on 36 and MOSI on 37.
//!
//! # The P4: 125 MHz
//!
//! The module's PSRAM is hex, the driver's only mode. At esp-hal's default
//! of 250 MHz the boot self-test read 3,408 of 131,072 words back with one
//! byte wrong, every boot; at 125, none, at no measurable cost (the cache
//! and bus fabric set the pace). ESP-IDF offers no 250 MHz on the P4 and
//! tunes the read strobe before it trusts 200; this fork does neither. 80
//! does not divide the fork's bus clock source exactly, and `Psram::new`
//! then maps nothing, saying so only in a log line. Half of 250 divides
//! whatever source produces 250.

/// How this unit's PSRAM is wired. A board fact; the M5Stack CoreS3 is quad,
/// the Waveshare ESP32-S3-Touch-LCD-2 is octal.
#[cfg(feature = "m5stack")]
const PSRAM_MODE: esp_hal::psram::PsramMode = esp_hal::psram::PsramMode::QuadSpi;
#[cfg(feature = "waveshare")]
const PSRAM_MODE: esp_hal::psram::PsramMode = esp_hal::psram::PsramMode::OctalSpi;

/// Make this unit's PSRAM the heap and return its size in bytes. Zero, with
/// nothing added, when the driver found no chip or the clear did not cover
/// all it mapped: the caller then stops rather than run on an empty heap.
///
/// All of PSRAM is zeroed first, every boot, so nothing the last run left
/// can be handed out. PSRAM the board's clear did not reach (mapped outside
/// the window it knows) is not made the heap. The console shows how much
/// was cleared and how long it took.
///
/// A `fn`, so a bring-up takes it as the function pointer it asks for.
pub fn make(psram: esp_hal::peripherals::PSRAM<'static>) -> usize {
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let config = esp_hal::psram::PsramConfig {
        mode: PSRAM_MODE,
        ..Default::default()
    };
    #[cfg(feature = "p4")]
    let config = esp_hal::psram::PsramConfig {
        timing: esp_hal::psram::PsramTimingParams::MHZ_125,
        ..Default::default()
    };
    let psram = esp_hal::psram::Psram::new(psram, config);
    let (_, bytes) = psram.raw_parts();
    let from = esp_hal::time::Instant::now();
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let cleared = kassigner_hal_esp32s3::cache::clear_psram(&psram);
    #[cfg(feature = "p4")]
    let cleared = kassigner_hal_esp32p4::psram::clear(&psram);
    esp_println::println!(
        "PSRAM cleared: {} KB in {} ms",
        cleared / 1024,
        from.elapsed().as_millis()
    );
    if cleared != bytes {
        esp_println::println!(
            "PSRAM mapped {} KB, cleared {} KB: not made the heap",
            bytes / 1024,
            cleared / 1024
        );
        return 0;
    }
    if bytes > 0 {
        esp_alloc::psram_allocator!(&psram);
    }
    bytes
}

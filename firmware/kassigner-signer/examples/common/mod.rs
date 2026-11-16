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

//! What the probes share: the unit's name, and a halt and panic handler. The
//! panic probe takes only the name: it brings its own handler, since a panic
//! is what it tests.

/// Which unit this is; an example does not see the binary's constant.
pub const UNIT: &str = if cfg!(feature = "m5stack") {
    "M5Stack CoreS3"
} else if cfg!(feature = "waveshare") {
    "Waveshare ESP32-S3-Touch-LCD-2"
} else {
    "Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5"
};

/// Stop here, for good.
#[cfg(not(feature = "panicprobe"))]
pub fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Ours: `esp-backtrace`'s is behind a feature left off, and an example does
/// not link the binary's.
#[cfg(not(feature = "panicprobe"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    esp_println::println!("PANIC: {}", info);
    halt();
}

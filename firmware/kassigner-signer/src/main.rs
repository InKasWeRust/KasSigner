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

//! The KasSigner firmware. Level 4: the program.
//!
//! One binary per unit, chosen by feature: it brings the chip up, hands
//! `kassigner-fw`'s flow the board's drivers and buffers, reports events to
//! it (a tick, a finger's lift, a payload, a sample) and draws the screen it
//! names, a band at a time or a code straight to the panel. Nothing is
//! decided here: no Kaspa rule, format, key handling or meaning of a tap.
//!
//! # The console
//!
//! `out!` writes to USB Serial/JTAG on the S3 units, UART0 on the P4. When
//! the flow closes it (a provisioned unit leaving its verification screen,
//! holes or not) the port's pads are switched off: the unit is silent from
//! before it can hold a seed until its next reset. A blank unit is never
//! closed, so it stays watchable and flashable over USB.
//!
//! # The screens
//!
//! The verification screen shows the fuses' verdict and the image's hash;
//! the fuses never halt the unit. A refusal is the ERROR screen; a failed
//! start-up check, or a camera, decoder or generator failing after the
//! panel came up, the PANIC screen. A seed's words, SeedQR and keys appear
//! only on their own screens, never on the console; after one of those
//! (`Screen::shows_secret`) the stack below is scrubbed, with the band they
//! were composed in and the encoder's scratch.

#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_std)]
#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_main)]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "m5stack", feature = "waveshare"),
    all(feature = "m5stack", feature = "p4"),
    all(feature = "waveshare", feature = "p4")
))]
compile_error!("pick one unit: --features m5stack, --features waveshare or --features p4");

#[cfg(all(
    target_arch = "xtensa",
    not(any(feature = "m5stack", feature = "waveshare"))
))]
compile_error!("an S3 build needs a unit: --features m5stack or --features waveshare");

#[cfg(all(target_arch = "riscv32", not(feature = "p4")))]
compile_error!("a RISC-V build is the P4: --features p4");

// The stack probe is the S3 units' alone: the P4's crate has none.
#[cfg(all(feature = "p4", feature = "stackprobe"))]
compile_error!("the stack probe is for the S3 units: m5-stackprobe or ws-stackprobe");

/// Which unit this binary is for.
pub const UNIT: &str = if cfg!(feature = "m5stack") {
    "M5Stack CoreS3"
} else if cfg!(feature = "waveshare") {
    "Waveshare ESP32-S3-Touch-LCD-2"
} else if cfg!(feature = "p4") {
    "Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5"
} else {
    "none"
};

#[cfg(not(any(target_arch = "xtensa", target_arch = "riscv32")))]
fn main() {
    // Keeps the crate in `cargo test --workspace`, so its manifest, features
    // and dependency directions are checked there.
    println!("kassigner-signer, unit: {UNIT}");
}

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod heap;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod device;

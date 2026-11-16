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

//! HAL implementations that belong to the chip, not to a board.
//!
//! SYSTIMER, the WDEV RNG, the GPIO matrix and the eFuse controller are the
//! same on the Waveshare and the M5, so they sit at the crate root with no
//! feature. What hangs off the pins (display, touch, card, sensor) is per
//! unit, in [`waveshare`] and `m5stack` behind features of the same names; a
//! build selects one. A `cfg` here, between two implementations of a trait,
//! is fine; a `cfg` in `kassigner-fw` is not. The P4 has its own crate,
//! `kassigner-hal-esp32p4`: different silicon shares nothing here.
//!
//! `kassigner-hal` and everything above it forbid `unsafe`; the hardware
//! access is here, kept small. Every `unsafe` block has a `// SAFETY:`
//! comment, which the lint below checks is there.
//!
//! The chip's register code needs no HAL. Each unit's bring-up (`unit`)
//! names esp-hal's types, so the crate depends on it for the Xtensa target
//! only: a host build sees none of it, and the tests here run on a laptop.

#![no_std]
// `WAITI`, core 1's clock-gated wait between decode jobs, is inline
// assembly, still behind this feature on Xtensa (esp-hal enables it too).
#![cfg_attr(target_arch = "xtensa", feature(asm_experimental_arch))]
// One of the two firmware crates allowed `unsafe`: every block needs a
// `// SAFETY:` comment saying why it is sound.
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

/// Diagnostic logging, off: the log lines stay in the code, since they are
/// what makes a hand-rolled DMA path debuggable.
///
/// It prints nothing but still uses its arguments, so no unused-variable
/// warning appears. Every call names `crate::log!`, which a binary cannot
/// replace; a bench build that wants the lines changes the body here.
///
/// The arms are `{{ }}`, not `{ }`: the outer pair only delimits the arm,
/// and the inner one makes the expansion a block, so a `log!(...)` where an
/// expression is required still parses.
#[macro_export]
macro_rules! log {
    () => {{}};
    ($($arg:tt)*) => {{ let _ = format_args!($($arg)*); }};
}

#[cfg(target_arch = "xtensa")]
pub mod brownout;
pub mod cache;
#[cfg(feature = "capture")]
pub mod capture;
#[cfg(target_arch = "xtensa")]
pub mod console;
// Both units' core-1 QR worker, behind `decode` (the vendored decoder).
// Each unit's own `decoder` fills its image.
#[cfg(feature = "decode")]
pub mod decode_core;
pub mod efuse;
pub mod entropy;
pub mod gpio_matrix;
pub mod i2c_bus;
#[cfg(target_arch = "xtensa")]
pub mod image;
pub mod memory;
pub mod paint;
pub mod panel;
#[cfg(target_arch = "xtensa")]
pub mod radio;
#[cfg(target_arch = "xtensa")]
pub mod stack;
pub mod systimer;
#[cfg(target_arch = "xtensa")]
pub mod tsens;
#[cfg(target_arch = "xtensa")]
pub mod watchdog;

#[cfg(feature = "m5stack")]
pub mod m5stack;
#[cfg(feature = "waveshare")]
pub mod waveshare;

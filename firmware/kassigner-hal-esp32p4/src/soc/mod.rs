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

//! The silicon layer: what talks to the ESP32-P4 rev1.3 (ROM ECO2) below
//! esp-hal, knowing nothing of the board. It is every place the application
//! side touches the ECO2 patch surface; if esp-hal grows support for any of
//! it, the module to delete is here.
//!
//! - `clocks`: HP_SYS_CLKRST bits esp-hal does not expose for CSI, ISP and
//!   dw_gdma.
//! - `cache`: L1/L2 sync through the CACHE block, not the ROM's `Cache_*`.
//! - `regi2c`: the analog master; esp-hal's is `pub(crate)` three levels
//!   deep.
//! - `watchdog`: the LP watchdog off before `esp_hal::init()`, so a hang
//!   hangs rather than reboots.
//! - `uart`: lock-free UART0 stores, usable before `esp_hal::init()`.
//! - `rom`: the ECO version and the ROM table probe.
//! - `settle`: physical wait times in microseconds, not NOP counts.

//! ## Visibility
//!
//! `clocks`, `cache` and `regi2c` are register-level: `pub` only with the
//! `unstable` feature, which this crate's hardware-test examples turn on,
//! and crate-private otherwise, so an application cannot reprogram an LDO or
//! the analog master by accident. `uart`, `watchdog`, `rom` and `settle` are
//! fixed-function and public.

/// What went wrong on the REGI2C analog master. Always public, so
/// `entropy::Error` can carry it without exposing the master.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegI2cError {
    /// `block` has no master-select bit; nothing was written.
    UnknownBlock,
    /// The busy bit never cleared: a stuck master reports so rather than
    /// return whatever the data register held.
    Busy,
}

#[cfg(feature = "unstable")]
pub mod cache;
#[cfg(not(feature = "unstable"))]
pub(crate) mod cache;

#[cfg(feature = "unstable")]
pub mod clocks;
#[cfg(not(feature = "unstable"))]
pub(crate) mod clocks;

#[cfg(feature = "unstable")]
pub mod regi2c;
#[cfg(not(feature = "unstable"))]
pub(crate) mod regi2c;

pub mod rom;
pub mod settle;
pub mod uart;
pub mod watchdog;

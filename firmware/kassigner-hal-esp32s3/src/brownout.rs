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

//! The brown-out detector, as the bootloader left it.
//!
//! A supply sag can make a chip skip an instruction; the detector's reset
//! turns the sag into a restart. The second-stage bootloader turns the
//! analog reset on (`bootloader_esp32s3.c`, `bootloader_ana_reset_config`);
//! the detector's level and digital reset are set by ESP-IDF's application
//! start-up, which this firmware does not run.
//!
//! Read at boot and printed with the boot lines. A unit without the analog
//! reset fails the signer's self-test; the rest is only reported.
//!
//! `RTC_CNTL_BROWN_OUT_REG`, read only: `brown_out_ena` the detector,
//! `brown_out_rst_ena` its digital reset, `brown_out_ana_rst_en` the analog
//! reset, `det` a brown-out seen now. Device only: it names the peripheral.

use esp_hal::peripherals::LPWR;

/// What the detector is set to, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// The detector on.
    pub enabled: bool,
    /// Its digital reset on.
    pub reset: bool,
    /// The analog reset on, as the bootloader sets it.
    pub analog_reset: bool,
    /// A brown-out seen when read.
    pub detected: bool,
    /// The whole register, for the console.
    pub raw: u32,
}

/// Read the detector's register. Nothing is written.
pub fn read() -> State {
    let r = LPWR::regs().brown_out().read();
    State {
        enabled: r.brown_out_ena().bit_is_set(),
        reset: r.brown_out_rst_ena().bit_is_set(),
        analog_reset: r.brown_out_ana_rst_en().bit_is_set(),
        detected: r.det().bit_is_set(),
        raw: r.bits(),
    }
}

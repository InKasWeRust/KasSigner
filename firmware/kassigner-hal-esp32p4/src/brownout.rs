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
//! A supply sag is one way to make a chip skip an instruction; the
//! detector's reset turns the sag into a restart. Espressif's second-stage
//! bootloader turns on the reset of mode 1, the analog detector
//! (`bootloader_esp32p4.c`, `bootloader_ana_reset_config`); mode 0's reset
//! and level are set by ESP-IDF's application start-up, which this firmware
//! does not run.
//!
//! Read at boot and said on the console with the other boot lines. Mode 1's
//! reset is part of the signer's boot verdict: every unit reads it on, and
//! one without it fails the self-test. The rest is only said.
//!
//! `LP_ANA_PERI.bod_mode0_cntl` and `bod_mode1_cntl`, read only.

use esp32p4::LP_ANA;

/// What the detector is set to, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// Mode 0's reset on: the digital detector's.
    pub mode0_reset: bool,
    /// Mode 0's interrupt on.
    pub mode0_interrupt: bool,
    /// Mode 1's reset on: the analog one the bootloader sets.
    pub mode1_reset: bool,
    /// Both registers whole, mode 0's then mode 1's, for the console.
    pub raw: (u32, u32),
}

/// Read the detector's two registers. Nothing is written.
pub fn read() -> State {
    // SAFETY: `LP_ANA_PERI` is a fixed MMIO block, always mapped; two reads
    // and no write, so nothing another driver set is touched.
    let ana = unsafe { &*LP_ANA::PTR };
    let m0 = ana.bod_mode0_cntl().read();
    let m1 = ana.bod_mode1_cntl().read();
    State {
        mode0_reset: m0.bod_mode0_reset_ena().bit_is_set(),
        mode0_interrupt: m0.bod_mode0_intr_ena().bit_is_set(),
        mode1_reset: m1.bod_mode1_reset_ena().bit_is_set(),
        raw: (m0.bits(), m1.bits()),
    }
}

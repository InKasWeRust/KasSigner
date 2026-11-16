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

//! MIPI D-PHY analog supply.
//!
//! The D-PHY runs from an internal LDO, off by default. Without it the PHY
//! seems to work (registers and the test interface round-trip) while
//! `phy_stopstate` and `phy_rx` never move: the analog receiver has no
//! power. Espressif's LDO channel for it (`esp_video_init_csi_config_t`)
//! maps to this register:
//!
//! ```text
//! chan_id 3 -> ldo_unit 2 -> index_array[] = {0,3,1,4} -> [2] = 1
//!                         -> ext_ldo_p0_0p2a
//! ```
//!
//! Voltage encoding from `ldo_ll_voltage_to_dref_mul()` with uncalibrated
//! constants (K=1000, Vos=0, C=1000):
//!
//! ```text
//! Vref = (dref<9) ? 0.5+dref*0.05 : 1+(dref-9)*0.1
//! Vout = Vref * (1 + 0.25*mul)
//! 2500 mV -> dref = 9, mul = 6   (exact)
//! ```
//!
//! Driven through the `esp32p4` PAC (`PMU.ext_ldo_p0_0p2a` and `_ana`),
//! whose fields match the offsets verified on this silicon. `_ana` resets
//! to 0xa000_0000 (dref = 10); its fields are read-modify-written.

use crate::soc::settle;
use esp32p4::{pmu::RegisterBlock, PMU};
use esp_hal::delay::Delay;

/// `dref = 9, mul = 6` -> 2500 mV, from `esp_video_init_csi_config_t`.
const DREF: u8 = 9;
const MUL: u8 = 6;

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped; esp-hal's PSRAM init writes
    // it too, but before `enable()`.
    unsafe { &*PMU::PTR }
}

/// Turn the LDO on at 2.5 V and let it settle. Runs after any esp-hal PSRAM
/// init, whose `psram_phy_ldo_init()` `.write()`s over this unit.
pub fn enable(delay: &Delay) {
    let r = regs();
    r.ext_ldo_p0_0p2a()
        .modify(|_, w| w._0p2a_force_tieh_sel_0().set_bit()); // software owns it
    r.ext_ldo_p0_0p2a()
        .modify(|_, w| w._0p2a_tieh_0().clear_bit()); // Vref*Mul, not the 3.3V rail
    r.ext_ldo_p0_0p2a_ana()
        // SAFETY: `DREF` 9 and `MUL` 6, 2500 mV, fit their fields.
        .modify(|_, w| unsafe { w.ana_0p2a_dref_0().bits(DREF).ana_0p2a_mul_0().bits(MUL) });
    r.ext_ldo_p0_0p2a().modify(|_, w| w._0p2a_xpd_0().set_bit());
    settle::us(delay, settle::MIPI_LDO_US); // let the rail settle
}

/// Is the LDO on with the expected reference and multiplier?
pub fn is_enabled() -> bool {
    let r = regs();
    let ana = r.ext_ldo_p0_0p2a_ana().read();
    r.ext_ldo_p0_0p2a().read()._0p2a_xpd_0().bit_is_set()
        && ana.ana_0p2a_dref_0().bits() == DREF
        && ana.ana_0p2a_mul_0().bits() == MUL
}

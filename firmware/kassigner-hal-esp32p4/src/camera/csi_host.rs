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

//! Synopsys DesignWare MIPI CSI-2 host, base 0x5009_F000, the standard DWC
//! layout. Version 0x3135302a, ASCII "150*" (v1.50). Driven through the
//! `esp32p4` PAC, whose fields match the offsets verified on this silicon.
//!
//! **PAC rule for every block in this crate:** svd2rust `write()` starts
//! from the register's reset value, not zero, so a write meant as a whole
//! word states every field that word zeroes: `phy_test_ctrl0` resets to
//! 0x01 (testclr), the bridge's `frame_cfg` to 0x011e01e0 (has_hsync_e).
//! `modify()` only for a read-modify-write.

use esp32p4::{mipi_csi_host::RegisterBlock, MIPI_CSI_HOST};

/// Nothing in esp-hal drives the CSI host on P4.
#[inline(always)]
pub(super) fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped, sole owner in this firmware.
    unsafe { &*MIPI_CSI_HOST::PTR }
}

/// `version` on this silicon: "150*". Zero means unclocked or in reset.
pub const VERSION_EXPECTED: u32 = 0x3135_302a;

/// The version register, raw. Prints as four ASCII bytes.
pub fn version() -> u32 {
    regs().version().read().bits()
}

/// True if the version register reads back (clocked and out of reset).
pub fn alive() -> bool {
    version() == VERSION_EXPECTED
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// OR of every error-status register. These latch faults only, so zero
/// with active lanes is clean reception.
pub fn errors() -> u32 {
    let r = regs();
    r.int_st_main().read().bits()
        | r.int_st_phy_fatal().read().bits()
        | r.int_st_pkt_fatal().read().bits()
        | r.int_st_bndry_frame_fatal().read().bits()
        | r.int_st_seq_frame_fatal().read().bits()
        | r.int_st_crc_frame_fatal().read().bits()
        | r.int_st_pld_crc_fatal().read().bits()
        | r.int_st_data_id().read().bits()
        | r.int_st_ecc_corrected().read().bits()
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Data lanes idle in LP-11. Toggling between 0 and 3 while streaming is
/// normal: the lanes go idle between lines.
pub fn stopstate() -> u32 {
    regs().phy_stopstate().read().bits()
}

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

//! MIPI D-PHY bring-up after ESP-IDF's `mipi_csi_hal_init()`
//! (`components/hal/mipi_csi_hal.c`): one PHY register write and the reset
//! order, no PLL or lane calibration. The PHY is reached through a
//! bit-banged test interface that reads back:
//!   phy_test_ctrl0 = clock_level << 1 | clear
//!   phy_test_ctrl1 = (1 << 16) | addr      address phase
//!   phy_test_ctrl1 = value                 data phase
//!   read phy_test_ctrl1 `[15:8]` = testdout

use super::csi_host::regs;

/// hs_freq_range_sel, from ESP-IDF `soc_mipi_csi_phy_pll_ranges[]`
/// (components/soc/esp32p4/mipi_csi_periph.c).
pub fn hs_freq_sel(mbps: u32) -> u8 {
    const T: &[(u32, u32, u8)] = &[
        (90, 99, 0x00),
        (100, 109, 0x10),
        (110, 129, 0x20),
        (130, 139, 0x01),
        (140, 149, 0x11),
        (150, 169, 0x21),
        (170, 179, 0x02),
        (180, 199, 0x12),
        (200, 219, 0x22),
        (220, 239, 0x03),
        (240, 249, 0x13),
        (250, 269, 0x23),
        (270, 299, 0x04),
        (300, 329, 0x14),
        (330, 359, 0x05),
        (360, 399, 0x15),
        (400, 449, 0x25),
        (450, 499, 0x06),
        (500, 549, 0x16),
        (550, 599, 0x07),
        (600, 649, 0x17),
        (650, 699, 0x08),
        (700, 749, 0x18),
        (750, 799, 0x09),
        (800, 849, 0x19),
        (850, 899, 0x29),
        (900, 949, 0x39),
        (950, 999, 0x0A),
        (1000, 1049, 0x1A),
        (1050, 1099, 0x2A),
        (1100, 1149, 0x3A),
        (1150, 1199, 0x0B),
        (1200, 1249, 0x1B),
        (1250, 1299, 0x2B),
        (1300, 1349, 0x3B),
        (1350, 1399, 0x0C),
        (1400, 1449, 0x1C),
        (1450, 1500, 0x2C),
    ];
    let mut i = 0;
    while i < T.len() {
        if mbps >= T[i].0 && mbps <= T[i].1 {
            return T[i].2;
        }
        i += 1;
    }
    0x25
}

/// Every field stated: PAC `write()` starts from `phy_test_ctrl0`'s reset
/// value, 0x01 (`testclr` set), so a bare `write(|w| w)` would reset the
/// test interface.
#[inline(always)]
fn ctrl0(clk: bool) {
    regs()
        .phy_test_ctrl0()
        .write(|w| w.phy_testclr().clear_bit().phy_testclk().bit(clk));
}

/// One test-interface write: the address with testen high, then the data
/// with testen low, each clocked in with testclk.
fn phy_write(reg: u8, val: u8) {
    let r = regs();
    ctrl0(false);
    r.phy_test_ctrl1()
        // SAFETY: `reg`, a `u8`, fits the eight-bit `testdin`; the test
        // interface takes any register number.
        .write(|w| unsafe { w.phy_testen().set_bit().phy_testdin().bits(reg) });
    ctrl0(true);
    ctrl0(false);
    r.phy_test_ctrl1()
        // SAFETY: as above: `val` is a `u8` in an eight-bit field.
        .write(|w| unsafe { w.phy_testen().clear_bit().phy_testdin().bits(val) });
    ctrl0(true);
    ctrl0(false);
}

/// Read a PHY register through phy_testdout; a written value that does not
/// read back means the PHY is not responding.
pub fn phy_read(reg: u8) -> u8 {
    let r = regs();
    ctrl0(false);
    r.phy_test_ctrl1()
        // SAFETY: as above: `reg` is a `u8` in an eight-bit field.
        .write(|w| unsafe { w.phy_testen().set_bit().phy_testdin().bits(reg) });
    ctrl0(true);
    ctrl0(false);
    r.phy_test_ctrl1().read().phy_testdout().bits()
}

/// Bring the D-PHY up for `lanes` data lanes at `lane_rate_mbps`. All
/// three reset signals are active low.
pub fn init(lanes: u32, lane_rate_mbps: u32) {
    debug_assert!((1..=2).contains(&lanes), "P4 CSI has 2 data lanes");
    let sel = hs_freq_sel(lane_rate_mbps);
    let r = regs();

    r.phy_shutdownz().write(|w| w.phy_shutdownz().clear_bit());
    r.dphy_rstz().write(|w| w.dphy_rstz().clear_bit());
    r.csi2_resetn().write(|w| w.csi2_resetn().clear_bit());

    // Reset the test interface: testen high, then a testclr pulse (the one
    // place testclr is meant to be set).
    r.phy_test_ctrl1()
        // SAFETY: zero in the eight-bit data field, as the test clear wants.
        .write(|w| unsafe { w.phy_testen().set_bit().phy_testdin().bits(0) });
    r.phy_test_ctrl0()
        .write(|w| w.phy_testclr().set_bit().phy_testclk().clear_bit());
    ctrl0(false);

    phy_write(0x44, sel << 1);

    r.phy_shutdownz().write(|w| w.phy_shutdownz().set_bit());
    r.dphy_rstz().write(|w| w.dphy_rstz().set_bit());
    r.csi2_resetn().write(|w| w.csi2_resetn().set_bit());

    r.n_lanes()
        // SAFETY: lanes minus one, as the field is defined; one or two fit.
        .write(|w| unsafe { w.n_lanes().bits(lanes.saturating_sub(1) as u8) });
    r.vc_extension().write(|w| w.vcx().set_bit()); // INVERTED: 0 enables VCX, 1 disables
    r.scrambling().write(|w| w.scramble_enable().clear_bit());
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Clock lane in high-speed mode: the sensor is transmitting (stronger
/// evidence than stop-state).
pub fn clock_lane_active() -> bool {
    regs().phy_rx().read().phy_rxclkactivehs().bit_is_set()
}

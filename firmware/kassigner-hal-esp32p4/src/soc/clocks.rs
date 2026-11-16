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

//! Clock and reset control, HP_SYS_CLKRST at 0x500E_6000.
//!
//! Two traps:
//!
//!   * dw_gdma is in the **gdma** group, not `dma2d`; `dma2d` gives a Load
//!     access fault at 0x50081000.
//!   * The ISP functional clock defaults to XTAL, on which the APB read path
//!     still works: version registers read correctly while the register file
//!     silently refuses writes.

//! ## Register access
//!
//! Every address and bit is from the `esp32p4` PAC, whose field names
//! confirm each (`hp_rst_en0` bit 21 is `rst_en_gdma`). Every access is a
//! `modify()`. esp-hal writes other bits of HP_SYS_CLKRST in its driver
//! constructors (I2C, SPI, I2S), never concurrently, as there are no
//! interrupts here; with interrupts these would need a critical section.

use crate::soc::settle;
use esp32p4::{hp_sys_clkrst::RegisterBlock, HP_SYS_CLKRST};
use esp_hal::delay::Delay;

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped. Shared with esp-hal's own
    // drivers only through disjoint bits; see module docs.
    unsafe { &*HP_SYS_CLKRST::PTR }
}

/// PLL_F20M, the D-PHY reference, enabled as ESP-IDF's
/// `esp_clk_tree_enable_src()` does: selecting the source without enabling
/// it leaves the PHY unclocked.
pub fn enable_ref_20m() {
    regs()
        .ref_clk_ctrl2()
        .modify(|_, w| w.ref_20m_clk_en().set_bit());
}

/// MIPI-CSI host + bridge bus clocks.
pub fn enable_csi() {
    regs().soc_clk_ctrl1().modify(|_, w| {
        w.csi_brg_sys_clk_en()
            .set_bit()
            .csi_host_sys_clk_en()
            .set_bit()
    });
}

/// D-PHY config clock. Source select: 0 = PLL_F20M (ESP-IDF's default),
/// 1 = RC_FAST, 2 = PLL_F25M. The enable is pulsed off then on: setting a
/// bit already set does nothing, and the PHY would never get its clock
/// reset.
pub fn enable_dphy_cfg(delay: &Delay) {
    let r = regs();
    r.peri_clk_ctrl03()
        // SAFETY: 0, PLL_F20M, is a defined encoding of the source field.
        .modify(|_, w| unsafe { w.mipi_csi_dphy_clk_src_sel().bits(0) });
    r.peri_clk_ctrl03()
        .modify(|_, w| w.mipi_csi_dphy_cfg_clk_en().clear_bit());
    settle::us(delay, settle::CLOCK_SWITCH_US);
    r.peri_clk_ctrl03()
        .modify(|_, w| w.mipi_csi_dphy_cfg_clk_en().set_bit());
}

/// ISP clock. Source select: 0 = XTAL, 1 = PLL_F240M, 2 = PLL_F160M. XTAL,
/// the reset default, is not enough: writes to ISP.cntl do not latch, while
/// reads work.
pub fn enable_isp(delay: &Delay) {
    let r = regs();
    r.peri_clk_ctrl25()
        // SAFETY: 1, PLL_F240M, is a defined encoding of the source field.
        .modify(|_, w| unsafe { w.isp_clk_src_sel().bits(1) }); // PLL_F240M
    r.peri_clk_ctrl25().modify(|_, w| w.isp_clk_en().set_bit());
    r.peri_clk_ctrl26()
        // SAFETY: zero is a divider of one; the field holds divider minus one.
        .modify(|_, w| unsafe { w.isp_clk_div_num().bits(0) }); // divider - 1
    settle::us(delay, settle::CLOCK_SWITCH_US);
}

/// DesignWare GDMA. Needs both the CPU and SYS clocks.
pub fn enable_dw_gdma(delay: &Delay) {
    let r = regs();
    r.soc_clk_ctrl0()
        .modify(|_, w| w.gdma_cpu_clk_en().set_bit());
    r.soc_clk_ctrl1()
        .modify(|_, w| w.gdma_sys_clk_en().set_bit());
    r.hp_rst_en0().modify(|_, w| w.rst_en_gdma().set_bit()); // reset pulse
    settle::us(delay, settle::DMA_RESET_PULSE_US);
    r.hp_rst_en0().modify(|_, w| w.rst_en_gdma().clear_bit());
    r.hp_force_norst0()
        .modify(|_, w| w.force_norst_gdma().set_bit());
}

/// Release CSI host, CSI bridge and ISP from reset and hold them out.
pub fn release_csi_isp_reset(delay: &Delay) {
    let r = regs();
    r.hp_rst_en0().modify(|_, w| {
        w.rst_en_csi_host()
            .clear_bit()
            .rst_en_csi_brg()
            .clear_bit()
            .rst_en_isp()
            .clear_bit()
    });
    r.hp_force_norst0().modify(|_, w| {
        w.force_norst_csi_host()
            .set_bit()
            .force_norst_csi_brg()
            .set_bit()
            .force_norst_isp()
            .set_bit()
    });
    settle::us(delay, settle::CSI_RESET_RELEASE_US);
}

/// Put the CSI host, the CSI bridge and the ISP back into reset and release
/// them, as a first bring-up finds them. Every camera restart starts here
/// (`P4Camera::set_power`): from the state the last stream left, the bridge
/// can come back empty or stall.
pub fn reset_csi_isp(delay: &Delay) {
    let r = regs();
    r.hp_force_norst0().modify(|_, w| {
        w.force_norst_csi_host()
            .clear_bit()
            .force_norst_csi_brg()
            .clear_bit()
            .force_norst_isp()
            .clear_bit()
    });
    r.hp_rst_en0().modify(|_, w| {
        w.rst_en_csi_host()
            .set_bit()
            .rst_en_csi_brg()
            .set_bit()
            .rst_en_isp()
            .set_bit()
    });
    settle::us(delay, settle::CSI_RESET_RELEASE_US);
    release_csi_isp_reset(delay);
}

/// SAR ADC: reset pulse, then APB + functional clock from XTAL, dividers
/// off. Mirrors `bootloader_random_enable()`. Used by `entropy::enable`.
pub(crate) fn enable_adc(delay: &Delay) {
    let r = regs();
    r.hp_rst_en2().modify(|_, w| w.rst_en_adc().set_bit());
    settle::us(delay, settle::ADC_RESET_PULSE_US);
    r.hp_rst_en2().modify(|_, w| w.rst_en_adc().clear_bit());

    r.soc_clk_ctrl2()
        .modify(|_, w| w.adc_apb_clk_en().set_bit());
    r.peri_clk_ctrl23().modify(|_, w| w.adc_clk_en().set_bit());
    r.peri_clk_ctrl22()
        // SAFETY: 0, XTAL, is a defined encoding of the source field.
        .modify(|_, w| unsafe { w.adc_clk_src_sel().bits(0) }); // XTAL

    // SAFETY: zero in each divider field, values the TRM allows.
    r.peri_clk_ctrl23().modify(|_, w| unsafe {
        w.adc_clk_div_num()
            .bits(0)
            .adc_clk_div_numerator()
            .bits(0)
            .adc_clk_div_denominator()
            .bits(0)
    });
}

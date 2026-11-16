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

//! MIPI CSI bridge, base 0x5009_F800, between the ISP and dw_gdma. Takes
//! raw pixel counts, where the ISP wants count - 1. Driven through the
//! `esp32p4` PAC, whose fields match the offsets verified on this silicon.

use crate::soc::settle;
use esp32p4::{mipi_csi_bridge::RegisterBlock, MIPI_CSI_BRIDGE};
use esp_hal::delay::Delay;

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped, sole owner in this firmware.
    unsafe { &*MIPI_CSI_BRIDGE::PTR }
}

/// The window dw_gdma reads pixel data from; the same in ESP-IDF's hw_ver1
/// and hw_ver3 `reg_base.h`.
pub const MEM_BASE: u32 = 0x5010_4000;

/// Values from ESP-IDF `mipi_csi_hal_init()`.
const AFULL_THRD: u16 = 960;
const BURST_LEN: u16 = 512;
const DATA_TYPE_MIN: u8 = 0x12;
const DATA_TYPE_MAX: u8 = 0x2f; // RAW8 0x2a and RAW10 0x2b both fall inside

/// Configure; `enable()` comes once the sensor streams, as in ESP-IDF's
/// `s_ctlr_csi_start()`.
pub fn configure(width: u32, height: u32, delay: &Delay) {
    let r = regs();
    r.clk_en().modify(|_, w| w.clk_en().set_bit());

    r.csi_en().modify(|_, w| w.csi_brig_rst().set_bit()); // assert bridge reset
    settle::us(delay, settle::BRIDGE_RESET_PULSE_US);
    r.csi_en().modify(|_, w| w.csi_brig_rst().clear_bit());

    // Raw counts here. `has_hsync_e` is set in the reset value, 0x011e01e0,
    // that PAC `write()` starts from, so it is cleared.
    // SAFETY: height and width masked to the fields' twelve bits.
    r.frame_cfg().write(|wr| unsafe {
        wr.vadr_num()
            .bits((height & 0xfff) as u16)
            .hadr_num()
            .bits((width & 0xfff) as u16)
            .has_hsync_e()
            .clear_bit()
            .vadr_num_check()
            .clear_bit()
    });
    r.buf_flow_ctl()
        // SAFETY: `AFULL_THRD` is 960, within the fourteen-bit field.
        .modify(|_, w| unsafe { w.csi_buf_afull_thrd().bits(AFULL_THRD) });
    // SAFETY: CSI-2 data type codes, within the six-bit fields.
    r.data_type_cfg().write(|w| unsafe {
        w.data_type_min()
            .bits(DATA_TYPE_MIN)
            .data_type_max()
            .bits(DATA_TYPE_MAX)
    });
    r.dma_req_cfg()
        // SAFETY: `BURST_LEN` is 512, within the twelve-bit field.
        .modify(|_, w| unsafe { w.dma_burst_len().bits(BURST_LEN) });
    r.endian_mode()
        .modify(|_, w| w.byte_endian_order().clear_bit());
}

/// Start the bridge accepting frames from the ISP.
pub fn enable() {
    regs().csi_en().modify(|_, w| w.csi_brig_en().set_bit());
}

/// Empty the FIFO by disabling and re-enabling the bridge, in vertical
/// blanking so nothing is lost. The bridge fills it whether or not the DMA
/// drains it, and the few hundred stale bytes a DMA would take first shift
/// every line (a roll of about a third of a line).
pub fn flush() {
    disable();
    enable();
}

/// Stop the bridge.
pub fn disable() {
    regs().csi_en().modify(|_, w| w.csi_brig_en().clear_bit());
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Read-only FIFO occupancy, buf_flow_ctl `[29:16]`.
pub fn buf_depth() -> u32 {
    regs().buf_flow_ctl().read().csi_buf_depth().bits() as u32
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Raw status without bit 5, `dma_cfg_has_updated`: a write
/// acknowledgement, not frame activity.
pub fn status() -> u32 {
    let s = regs().int_raw().read();
    s.bits() & !(1 << 5)
}

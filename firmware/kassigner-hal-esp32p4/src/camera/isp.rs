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

//! Image Signal Processor, base 0x500A_1000.
//!
//! The CSI datapath runs through the ISP even with no processing, and two
//! fields of `cntl`'s reset value, 0x4000_2442, are wrong for raw capture
//! ([`init_passthrough`] sets both):
//!
//!   * `mipi_data_en` (bit 0) is clear, gating the CSI path shut.
//!   * `isp_out_type` is 2, RGB888 with demosaic, rgb2yuv and yuv2rgb on:
//!     with no coefficient tables loaded the ISP fills up (`isp_buf_full`)
//!     and stalls.
//!
//! Driven through the `esp32p4` PAC, whose fields match the offsets
//! verified on this silicon.

use esp32p4::{isp::RegisterBlock, ISP};

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped, sole owner in this firmware.
    unsafe { &*ISP::PTR }
}

/// `ver_date` on this silicon.
pub const VER_DATE_EXPECTED: u32 = 0x2021_0608;

#[derive(Copy, Clone, PartialEq)]
/// Bits per raw pixel out of the sensor.
pub enum RawDepth {
    /// 8 bits per pixel.
    Raw8 = 0,
    /// 10 bits per pixel.
    Raw10 = 1,
    /// 12 bits per pixel.
    Raw12 = 2,
}

/// True if the version register reads back (clocked and out of reset).
pub fn alive() -> bool {
    regs().ver_date().read().bits() == VER_DATE_EXPECTED
}

/// Configure for RAW passthrough: gate open, no demosaic, raw in and out.
pub fn init_passthrough(width: u32, height: u32, depth: RawDepth) {
    let r = regs();
    r.clk_en().modify(|_, w| w.clk_en().set_bit());

    // SAFETY: documented encodings: RAW8 out, CSI in, the raw depth, and
    // single bits.
    r.cntl().modify(|_, c| unsafe {
        c.isp_out_type()
            .bits(0) // RAW8 out
            .demosaic_en()
            .clear_bit()
            .rgb2yuv_en()
            .clear_bit()
            .yuv2rgb_en()
            .clear_bit()
            .gamma_en()
            .clear_bit()
            .blc_en()
            .clear_bit()
            .isp_in_src()
            .bits(0) // CSI
            .isp_data_type()
            .bits(depth as u8)
            .mipi_data_en()
            .set_bit()
            .isp_en()
            .set_bit()
    });

    // Counts minus one here; the bridge takes raw counts.
    debug_assert!(width > 0 && height > 0);
    // SAFETY: the counts minus one, as the ISP defines them, masked to the
    // fields' twelve bits.
    r.frame_cfg().modify(|_, f| unsafe {
        f.vadr_num()
            .bits((height.saturating_sub(1) & 0xfff) as u16)
            .hadr_num()
            .bits((width.saturating_sub(1) & 0xfff) as u16)
    });
}

/// Clear every sticky ISP interrupt bit.
pub fn clear_status() {
    // SAFETY: all ones clears every sticky interrupt bit.
    regs().int_clr().write(|w| unsafe { w.bits(0xffff_ffff) });
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Raw ISP interrupt status.
pub fn status() -> u32 {
    regs().int_raw().read().bits()
}

/// A frame ended since the last `clear_status` (`int_raw` bit 14,
/// `frame`): the sensor is in vertical blanking until the next header.
pub fn frame_received() -> bool {
    regs().int_raw().read().bits() & (1 << 14) != 0
}

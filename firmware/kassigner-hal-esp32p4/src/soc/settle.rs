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

//! Physical settle times, in microseconds.
//!
//! Every wait hardware needs (an LDO rail rising, an ADC warming up, a block
//! leaving reset) is a constant here, waited with `Delay`, not a NOP-count
//! loop, which a faster `CpuClock` would shorten. Values are conservative,
//! checked against the ESP-IDF driver each step follows where one exists.

use esp_hal::delay::Delay;

/// MIPI D-PHY LDO rail after `xpd`.
pub const MIPI_LDO_US: u32 = 40_000;
/// CSI host / bridge / ISP after release from reset.
pub const CSI_RESET_RELEASE_US: u32 = 2_000;
/// A clock after its source select: the ISP's, and the D-PHY config
/// clock's off time in its enable pulse.
pub const CLOCK_SWITCH_US: u32 = 100;
/// dw_gdma reset pulse width.
pub const DMA_RESET_PULSE_US: u32 = 100;
/// CSI bridge reset pulse.
pub const BRIDGE_RESET_PULSE_US: u32 = 100;
/// SAR ADC reset pulse.
pub const ADC_RESET_PULSE_US: u32 = 20;
/// The analog I2C's power group held in reset before it is powered: ESP-IDF's
/// `regi2c_ctrl_ll_i2c_sar_periph_enable`, "1us delay is recommended by
/// digital design".
pub const REGI2C_RESET_US: u32 = 1;
/// SAR ADC: first conversions after enable.
pub const ADC_WARMUP_US: u32 = 1_000;
/// Gap between successive `rng_data` reads.
///
/// ESP-IDF's `esp_random` waits at least 14 µs per byte from this chip's
/// generator, the rate its `hw_random.c` says the P4 was tested at ("around
/// 75 KHz bytes"); a read takes four bytes, so four waits. That is far past
/// the ADC's trigger interval (100 cycles of 40 MHz), so no two reads share
/// a conversion.
///
/// The SP 800-90B figure and the health-test cutoffs hold only for the gap
/// the `p4_entropy` capture measured them at: re-assess if this changes.
pub const RNG_READ_GAP_US: u32 = 56;

/// Wait `us` microseconds. Thin wrapper so call sites read as intent.
#[inline]
pub fn us(delay: &Delay, us: u32) {
    delay.delay_micros(us);
}

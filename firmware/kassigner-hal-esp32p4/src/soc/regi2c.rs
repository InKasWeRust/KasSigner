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

//! Analog register interface (REGI2C).
//!
//! The ESP32-P4's analog blocks (PLLs, bias, the SAR ADC calibration this
//! crate needs) sit behind a small I2C-like master, not plain MMIO.
//! `crate::entropy` uses it to program the SAR ADC initial code.
//!
//! esp-hal's `soc/esp32p4/regi2c.rs` is `pub(crate)` three levels deep (in
//! a `mod soc` re-exported only with `ulp_riscv_driver_supported`), and
//! exposing it would take three visibility changes in the fork, each
//! tripping its `#![deny(missing_docs)]`. So its thirty lines are ported,
//! behaving exactly as `regi2c_read`/`regi2c_write`.
//!
//! ```text
//! LP_I2C_ANA_MST @ 0x5012_4000
//!   +0x00 i2c0_ctrl   cmd [24:0], busy b25
//!   +0x20 ana_conf2   master-select bits
//! cmd: slave_id [7:0] | reg_addr [15:8] | data [23:16] | wr_cntl b24
//! ```

//! ## Register access
//!
//! The `esp32p4` PAC gives the block pointer and the busy flag; `i2c0_ctrl`
//! is one 25-bit field there, so the command is packed by hand, in ESP-IDF
//! `regi2c_ctrl.c`'s layout. `ana_conf2` (master select) is a 24-bit field,
//! OR-ed. The master clock enable is `LP_PERI.clk_en` `ck_en_lp_i2cmst` b27.

use esp32p4::{lp_i2c_ana_mst::RegisterBlock, LP_I2C_ANA_MST, LP_PERI};

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped. esp-hal has its own regi2c
    // for its analog init; that runs inside `esp_hal::init()`, never
    // concurrently with these calls.
    unsafe { &*LP_I2C_ANA_MST::PTR }
}

const WR_CNTL_BIT: u32 = 1 << 24;
const DATA_SHIFT: u32 = 16;
const DATA_MASK: u32 = 0xFF;
const ADDR_SHIFT: u32 = 8;
const ADDR_MASK: u32 = 0xFF;
const SLAVE_ID_MASK: u32 = 0xFF;

/// Error type. Defined in `soc` so it stays public when this module is not.
pub use super::RegI2cError as Error;

/// Analog slave ids on the master, from ESP-IDF `regi2c_ctrl.h` (esp32p4).
#[allow(missing_docs)] // id table
pub mod block {
    pub const SDIO_PLL: u8 = 0x62;
    pub const MSPI: u8 = 0x63;
    pub const SYS_PLL: u8 = 0x66;
    pub const CPU_PLL: u8 = 0x67;
    /// The SAR ADC — what the entropy source needs.
    pub const SAR_I2C: u8 = 0x69;
    pub const BIAS: u8 = 0x6a;
    pub const DIG_REG: u8 = 0x6d;
    pub const PLLA: u8 = 0x6f;
}

/// `ana_conf2` master-select bit for a slave id.
fn master_select(block: u8) -> Option<u32> {
    Some(match block {
        block::SYS_PLL => 1 << 5,
        block::SDIO_PLL => 1 << 6,
        block::SAR_I2C => 1 << 7,
        block::PLLA => 1 << 8,
        block::MSPI => 1 << 9,
        block::DIG_REG => 1 << 10,
        block::CPU_PLL => 1 << 11,
        block::BIAS => 1 << 12,
        _ => return None,
    })
}

fn enable_block(block: u8) -> bool {
    // SAFETY: as `regs()`.
    unsafe { &*LP_PERI::PTR }
        .clk_en()
        .modify(|_, w| w.ck_en_lp_i2cmst().set_bit());
    match master_select(block) {
        Some(sel) => {
            regs()
                .ana_conf2()
                // SAFETY: read-modify-write: the bits already set are kept
                // and this block's select bit is added.
                .modify(|r, w| unsafe { w.ana_conf2().bits(r.ana_conf2().bits() | sel) });
            true
        }
        None => false,
    }
}

fn wait_idle() -> Result<(), Error> {
    let mut n = 0u32;
    while regs().i2c0_ctrl().read().i2c0_busy().bit_is_set() {
        n += 1;
        if n > 1_000_000 {
            return Err(Error::Busy);
        }
        core::hint::spin_loop();
    }
    Ok(())
}

/// Read one analog register.
pub fn read(block: u8, reg: u8) -> Result<u8, Error> {
    if !enable_block(block) {
        return Err(Error::UnknownBlock);
    }
    wait_idle()?;
    let cmd = ((block as u32) & SLAVE_ID_MASK) | (((reg as u32) & ADDR_MASK) << ADDR_SHIFT);
    regs()
        .i2c0_ctrl()
        // SAFETY: `cmd` holds the slave id and register at their documented
        // positions, with the write bit clear: a read command.
        .write(|w| unsafe { w.i2c0_ctrl().bits(cmd) });
    wait_idle()?;
    Ok(((regs().i2c0_ctrl().read().bits() >> DATA_SHIFT) & DATA_MASK) as u8)
}

/// Write bits `msb` to `lsb` of one analog register, the others as they
/// read: ESP-IDF's `REGI2C_WRITE_MASK`, a read and a write. `data` is the
/// field's value, cut to its width.
pub fn write_mask(block: u8, reg: u8, msb: u8, lsb: u8, data: u8) -> Result<(), Error> {
    let width = msb.saturating_sub(lsb) + 1;
    let field = if width >= 8 { 0xFF } else { (1u8 << width) - 1 };
    let mask = field << lsb;
    let now = read(block, reg)?;
    write(block, reg, (now & !mask) | ((data & field) << lsb))
}

/// Write one analog register.
pub fn write(block: u8, reg: u8, data: u8) -> Result<(), Error> {
    if !enable_block(block) {
        return Err(Error::UnknownBlock);
    }
    wait_idle()?;
    let cmd = ((block as u32) & SLAVE_ID_MASK)
        | (((reg as u32) & ADDR_MASK) << ADDR_SHIFT)
        | WR_CNTL_BIT
        | (((data as u32) & DATA_MASK) << DATA_SHIFT);
    regs()
        .i2c0_ctrl()
        // SAFETY: as in `read`, plus the data and the write bit.
        .write(|w| unsafe { w.i2c0_ctrl().bits(cmd) });
    wait_idle()
}

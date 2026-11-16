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

//! The S3's provisioning fuses, read into `kassigner-hal`'s [`Reading`].
//!
//! It reads and decodes, and judges nothing: the verdict and the console's
//! lines are `kassigner_hal::provisioning`'s, for every board.
//!
//! # Registers
//!
//! All read-only, in the eFuse controller at `0x6000_7000` (ESP32-S3 TRM
//! v1.2, chapter 5):
//!
//! - `EFUSE_RD_WR_DIS_REG`, `0x002C` (Register 5.12): one bit per
//!   protectable parameter, 1 when it can no longer be programmed. Table
//!   5-1: `RD_DIS` bit 0, `KEY_PURPOSE_0..5` bits 8 to 13. Table 5-3:
//!   `KEY0..5`'s data bits 23 to 28.
//! - `EFUSE_RD_REPEAT_DATA0_REG`, `0x0030` (5.13): `DIS_FORCE_DOWNLOAD`
//!   12, `SOFT_DIS_JTAG` 18:16, `DIS_PAD_JTAG` 19.
//! - `EFUSE_RD_REPEAT_DATA1_REG`, `0x0034` (5.14):
//!   `SECURE_BOOT_KEY_REVOKE0..2` 21 to 23, `KEY_PURPOSE_0` 27:24,
//!   `KEY_PURPOSE_1` 31:28.
//! - `EFUSE_RD_REPEAT_DATA2_REG`, `0x0038` (5.15): `KEY_PURPOSE_2..5` in
//!   the low four nibbles, `SECURE_BOOT_EN` 20,
//!   `SECURE_BOOT_AGGRESSIVE_REVOKE` 21, `DIS_USB_JTAG` 22,
//!   `DIS_USB_SERIAL_JTAG` 23.
//! - `EFUSE_RD_REPEAT_DATA3_REG`, `0x003C` (5.16): `DIS_DOWNLOAD_MODE` 0,
//!   `DIS_LEGACY_SPI_BOOT` 1 (direct boot, `DIS_DIRECT_BOOT` in ESP-IDF),
//!   `ENABLE_SECURITY_DOWNLOAD` 5.
//! - `EFUSE_RD_KEYn_DATA0..7_REG`, `0x009C + 0x20 * n` (5.40 onwards): the
//!   256 bits of `KEYn`, BLOCK4 to BLOCK9, read only to count set bits. A
//!   read-protected block reads as zeros (TRM 5.3.1.2), which the verdict
//!   treats as the safe case (`provisioning::Slot::Open`).
//!
//! The registers are read by address into [`Words`]; [`decode`] turns those
//! into a [`Reading`] with plain arithmetic, so the bit positions above are
//! checked on a host (`tests/efuse.rs`).

use kassigner_hal::provisioning::{KeyBlock, Provisioning, Reading, KEY_BLOCKS};

/// eFuse controller base address (TRM Table 4-3).
const EFUSE_BASE: usize = 0x6000_7000;

/// `EFUSE_RD_WR_DIS_REG`.
const RD_WR_DIS: usize = EFUSE_BASE + 0x002C;

/// `EFUSE_RD_REPEAT_DATA0_REG`; `DATA1` to `DATA3` follow, one word each.
const RD_REPEAT_DATA0: usize = EFUSE_BASE + 0x0030;

/// `EFUSE_RD_KEY0_DATA0_REG`; each key block is eight words, the next one
/// `0x20` on.
const RD_KEY0_DATA0: usize = EFUSE_BASE + 0x009C;

/// Bytes from one key block's first word to the next's.
const KEY_STRIDE: usize = 0x20;

// `EFUSE_WR_DIS` bits, Tables 5-1 and 5-3.
const WR_DIS_RD_DIS: u32 = 1 << 0;
const WR_DIS_KEY_PURPOSE_0: u32 = 8;
const WR_DIS_KEY0: u32 = 23;

// `RD_REPEAT_DATA0`.
const DIS_FORCE_DOWNLOAD: u32 = 1 << 12;
const SOFT_DIS_JTAG_SHIFT: u32 = 16;
const SOFT_DIS_JTAG_MASK: u32 = 0b111;
const DIS_PAD_JTAG: u32 = 1 << 19;

// `RD_REPEAT_DATA1`.
const KEY_REVOKE0_SHIFT: u32 = 21;

// `RD_REPEAT_DATA2`.
const SECURE_BOOT_EN: u32 = 1 << 20;
const SECURE_BOOT_AGGRESSIVE_REVOKE: u32 = 1 << 21;
const DIS_USB_JTAG: u32 = 1 << 22;
const DIS_USB_SERIAL_JTAG: u32 = 1 << 23;

// `RD_REPEAT_DATA3`.
const DIS_DOWNLOAD_MODE: u32 = 1 << 0;
const DIS_DIRECT_BOOT: u32 = 1 << 1;
const ENABLE_SECURITY_DOWNLOAD: u32 = 1 << 5;

/// The registers [`decode`] reads, as read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Words {
    /// `EFUSE_RD_WR_DIS_REG`.
    pub wr_dis: u32,
    /// `EFUSE_RD_REPEAT_DATA0_REG` to `DATA3_REG`.
    pub repeat: [u32; 4],
    /// `EFUSE_RD_KEYn_DATA0..7_REG`, `KEY0` to `KEY5`.
    pub keys: [[u32; 8]; KEY_BLOCKS],
}

/// The fuses, decoded from the registers.
pub fn decode(w: &Words) -> Reading {
    let [d0, d1, d2, d3] = w.repeat;
    // Purposes 0 and 1 in DATA1's top two nibbles, 2 to 5 in DATA2's low
    // four.
    let purposes = [
        (d1 >> 24) & 0xF,
        (d1 >> 28) & 0xF,
        d2 & 0xF,
        (d2 >> 4) & 0xF,
        (d2 >> 8) & 0xF,
        (d2 >> 12) & 0xF,
    ];
    let mut keys = [KeyBlock::default(); KEY_BLOCKS];
    for (i, key) in keys.iter_mut().enumerate() {
        let n = i as u32;
        *key = KeyBlock {
            purpose: purposes[i] as u8,
            purpose_locked: w.wr_dis & (1 << (WR_DIS_KEY_PURPOSE_0 + n)) != 0,
            bits: w.keys[i].iter().map(|word| word.count_ones()).sum(),
            locked: w.wr_dis & (1 << (WR_DIS_KEY0 + n)) != 0,
        };
    }
    let revoked = [0, 1, 2].map(|k| d1 & (1 << (KEY_REVOKE0_SHIFT + k)) != 0);
    Reading {
        secure_boot: d2 & SECURE_BOOT_EN != 0,
        pad_jtag_off: d0 & DIS_PAD_JTAG != 0,
        usb_jtag_off: d2 & DIS_USB_JTAG != 0,
        download_off: d3 & DIS_DOWNLOAD_MODE != 0,
        secure_download: d3 & ENABLE_SECURITY_DOWNLOAD != 0,
        revoked,
        keys,
        direct_boot_off: d3 & DIS_DIRECT_BOOT != 0,
        soft_jtag_off: ((d0 >> SOFT_DIS_JTAG_SHIFT) & SOFT_DIS_JTAG_MASK).count_ones() % 2 == 1,
        aggressive_revoke: d2 & SECURE_BOOT_AGGRESSIVE_REVOKE != 0,
        read_protect_locked: w.wr_dis & WR_DIS_RD_DIS != 0,
        force_download_off: d0 & DIS_FORCE_DOWNLOAD != 0,
        usb_serial_off: Some(d2 & DIS_USB_SERIAL_JTAG != 0),
    }
}

/// One register.
fn reg(address: usize) -> u32 {
    // SAFETY: every address passed here is one of the eFuse controller's
    // read-only 32-bit registers listed above, mapped on every ESP32-S3; a
    // read cannot fault and changes nothing.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// The registers, as they read now.
pub fn words() -> Words {
    let mut w = Words {
        wr_dis: reg(RD_WR_DIS),
        ..Words::default()
    };
    for (n, word) in w.repeat.iter_mut().enumerate() {
        *word = reg(RD_REPEAT_DATA0 + 4 * n);
    }
    for (i, key) in w.keys.iter_mut().enumerate() {
        for (n, word) in key.iter_mut().enumerate() {
            *word = reg(RD_KEY0_DATA0 + KEY_STRIDE * i + 4 * n);
        }
    }
    w
}

/// The fuse reader, behind the trait the flow boots on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fuses;

impl Provisioning for Fuses {
    fn read(&self) -> Reading {
        decode(&words())
    }
}

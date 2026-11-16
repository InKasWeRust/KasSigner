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

//! The P4's provisioning fuses, read into `kassigner-hal`'s [`Reading`].
//!
//! This module only reads; `kassigner_hal::provisioning` judges what the
//! fuses mean, the same for every board.
//!
//! The S3 crate reads its fuses by address, from the TRM. With no P4 TRM in
//! this project, this crate reads esp-hal's generated field constants, each
//! checked against ESP-IDF's P4 eFuse table
//! (`components/efuse/esp32p4/esp_efuse_table.csv`; v6.1's for the
//! download, direct-boot, soft-JTAG, forced-download, read-protect-lock and
//! key-block-lock fields): every bit is where the table puts it.
//!
//! The P4 has no fuse that disables USB Serial/JTAG altogether, only its
//! download function and its ROM printing, so
//! [`Reading::usb_serial_off`] is `None` here.
//!
//! # The key purposes, from the registers
//!
//! The six key purposes are read through the `esp32p4` PAC instead:
//! esp-hal's generated `KEY_PURPOSE_0` to `KEY_PURPOSE_5`
//! (`esp-hal/src/efuse/esp32p4/fields.rs`) are in the wrong place, BLK0
//! bits 155 to 159 and 164, five bits each and overlapping. ESP-IDF's table
//! and the PAC, both Espressif's, put them at BLK0 bits 88 to 111, four
//! bits each: `RD_REPEAT_DATA1` bits 24 to 31 and `RD_REPEAT_DATA2` bits 0
//! to 15. On rev 1.3, bits 155 to 159 are `DCDC_VSET`, a voltage setting;
//! ESP-IDF's rev 3 table keeps the four bits and adds a fifth from bit 155
//! on, where the generator took the whole field from. `bring_up` refuses
//! any ROM but ECO2's, so rev 3 never runs this.
//!
//! # Verified on a locked unit
//!
//! Read on blank fuses (verdict `Blank`) and, since 15 November 2026, on a
//! P4 of rev 1.3 locked from blank by the release's Secure Boot bootloader:
//! verdict `Provisioned`, the screen saying Verified OK. esptool's
//! `get_security_info` on that unit gave the key purposes
//! `(9, 0, 0, 0, 0, 0, 12)`, digest slot 0 in `BLOCK_KEY0`, slots 1 and 2
//! revoked, Secure Download on and JTAG disabled: what this module read.
//!
//! So purpose 9 names digest slot 0 on the P4, as on the S3. Purposes 10
//! and 11, for slots 1 and 2, are still the S3's and what ESP-IDF's
//! `esp_efuse_chip.h` gives for the P4: no P4 has used those slots.

use esp32p4::{efuse::RegisterBlock, EFUSE};
use esp_hal::efuse::{self as ef, EfuseField};
use kassigner_hal::provisioning::{KeyBlock, Provisioning, Reading, KEY_BLOCKS};

/// Each key purpose's write protection.
const WR_DIS_KEY_PURPOSE: [EfuseField; KEY_BLOCKS] = [
    ef::WR_DIS_KEY_PURPOSE_0,
    ef::WR_DIS_KEY_PURPOSE_1,
    ef::WR_DIS_KEY_PURPOSE_2,
    ef::WR_DIS_KEY_PURPOSE_3,
    ef::WR_DIS_KEY_PURPOSE_4,
    ef::WR_DIS_KEY_PURPOSE_5,
];

/// Each key block's data write protection, `WR_DIS` bits 23 to 28.
const WR_DIS_KEY: [EfuseField; KEY_BLOCKS] = [
    ef::WR_DIS_BLOCK_KEY0,
    ef::WR_DIS_BLOCK_KEY1,
    ef::WR_DIS_BLOCK_KEY2,
    ef::WR_DIS_BLOCK_KEY3,
    ef::WR_DIS_BLOCK_KEY4,
    ef::WR_DIS_BLOCK_KEY5,
];

/// Each key block's 256 bits, BLOCK4 to BLOCK9.
const KEY: [EfuseField; KEY_BLOCKS] = [ef::KEY0, ef::KEY1, ef::KEY2, ef::KEY3, ef::KEY4, ef::KEY5];

/// The three digest slots' revoke bits.
const KEY_REVOKE: [EfuseField; 3] = [
    ef::SECURE_BOOT_KEY_REVOKE0,
    ef::SECURE_BOOT_KEY_REVOKE1,
    ef::SECURE_BOOT_KEY_REVOKE2,
];

/// The eFuse controller's registers.
#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: a fixed MMIO block, always mapped; only its read registers are
    // read here, and reading them changes nothing.
    unsafe { &*EFUSE::PTR }
}

/// The six key purposes, from BLK0 bits 88 to 111: see the module's notes.
fn key_purposes() -> [u8; KEY_BLOCKS] {
    let r = regs();
    let low = r.rd_repeat_data1().read();
    let high = r.rd_repeat_data2().read();
    [
        low.key_purpose_0().bits(),
        low.key_purpose_1().bits(),
        high.key_purpose_2().bits(),
        high.key_purpose_3().bits(),
        high.key_purpose_4().bits(),
        high.key_purpose_5().bits(),
    ]
}

/// The fuses, as they read now.
pub fn read() -> Reading {
    let purposes = key_purposes();
    let mut keys = [KeyBlock::default(); KEY_BLOCKS];
    for (i, key) in keys.iter_mut().enumerate() {
        let data: [u32; 8] = ef::read_field_le(KEY[i]);
        *key = KeyBlock {
            purpose: purposes[i],
            purpose_locked: ef::read_bit(WR_DIS_KEY_PURPOSE[i]),
            bits: data.iter().map(|word| word.count_ones()).sum(),
            locked: ef::read_bit(WR_DIS_KEY[i]),
        };
    }
    let soft_jtag: u8 = ef::read_field_le(ef::SOFT_DIS_JTAG);
    Reading {
        secure_boot: ef::read_bit(ef::SECURE_BOOT_EN),
        pad_jtag_off: ef::read_bit(ef::DIS_PAD_JTAG),
        usb_jtag_off: ef::read_bit(ef::DIS_USB_JTAG),
        download_off: ef::read_bit(ef::DIS_DOWNLOAD_MODE),
        secure_download: ef::read_bit(ef::ENABLE_SECURITY_DOWNLOAD),
        revoked: KEY_REVOKE.map(ef::read_bit),
        keys,
        direct_boot_off: ef::read_bit(ef::DIS_DIRECT_BOOT),
        soft_jtag_off: soft_jtag.count_ones() % 2 == 1,
        aggressive_revoke: ef::read_bit(ef::SECURE_BOOT_AGGRESSIVE_REVOKE),
        read_protect_locked: ef::read_bit(ef::WR_DIS_RD_DIS),
        force_download_off: ef::read_bit(ef::DIS_FORCE_DOWNLOAD),
        usb_serial_off: None,
    }
}

/// The fuse reader, behind the trait the flow boots on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fuses;

impl Provisioning for Fuses {
    fn read(&self) -> Reading {
        read()
    }
}

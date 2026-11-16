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

//! ROM identity. Silicon this code has been verified on.

/// Marketing revision.
pub const CHIP_REVISION: &str = "v1.3";
/// ROM build string from the boot banner.
pub const ROM: &str = "esp32p4-eco2-20240710";
/// `rom_eco_version` this tree targets. ECO3 and later are another target:
/// ROM tables, errata workarounds and peripheral defaults all differ.
pub const ROM_ECO_VERSION: u32 = 2;

/// Reads the ROM eco version from the ROM header at 0x4FC0_0014.
pub fn rom_eco_version() -> u32 {
    // SAFETY: fixed ROM address, always mapped, read-only.
    unsafe { core::ptr::read_volatile(0x4FC0_0014 as *const u32) }
}

/// True if the running ROM is the one this tree was verified against.
pub fn is_verified_silicon() -> bool {
    rom_eco_version() == ROM_ECO_VERSION
}

/// Whether the ROM jump table this build linked is this ROM's.
///
/// [`is_verified_silicon`] reads the version word, not the table: ECO5's
/// table moves 237 of the 456 names it shares with ECO2's, yet the few
/// routines `esp-hal` itself calls sit at the same address in both.
///
/// One call each through `crc32_le`, `crc16_le` and `crc8_le`, which
/// `esp-hal` routes to the ROM here and which ECO5's table places twelve
/// bytes early: through a wrong table they return a wrong value or hang.
///
/// Each routine complements the value passed in and the result, so 0 over
/// `"123456789"` gives the catalogue check value: `0xCBF43926`
/// (CRC-32/ISO-HDLC), `0x906E` (CRC-16/IBM-SDLC). CRC-8 in this convention
/// has no catalogue entry; `0x2F` is from the emulation that reproduces the
/// other two.
///
/// Returns `(passed, total)`, like the boot set's other checks.
pub fn table_probe() -> (u32, u32) {
    use esp_hal::rom::crc::{crc16_le, crc32_le, crc8_le};

    let data: &[u8] = core::hint::black_box(b"123456789");
    let results = [
        crc32_le(0, data) == 0xCBF4_3926,
        crc16_le(0, data) == 0x906E,
        crc8_le(0, data) == 0x2F,
    ];
    let passed = results.iter().filter(|&&ok| ok).count() as u32;
    (passed, results.len() as u32)
}

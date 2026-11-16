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

//! Shared-bus I2C helpers.
//!
//! GPIO7/8 carry the PMIC, audio codec, camera SCCB and touch controller.
//! These helpers borrow the bus per call rather than own it, so four devices
//! need no `embedded-hal-bus`.

use esp_hal::{i2c::master::I2c, Blocking};

/// The shared blocking I2C0 bus, as constructed by `board::init`.
pub type Bus<'d> = I2c<'d, Blocking>;

/// 8-bit register address (FT6336, ES8311, AXP2101).
pub fn read8(bus: &mut Bus<'_>, addr: u8, reg: u8) -> Option<u8> {
    let mut b = [0u8; 1];
    bus.write_read(addr, &[reg], &mut b).ok().map(|_| b[0])
}

/// Write one byte to an 8-bit register address.
pub fn write8(bus: &mut Bus<'_>, addr: u8, reg: u8, val: u8) -> bool {
    bus.write(addr, &[reg, val]).is_ok()
}

/// Burst read from an 8-bit register address, in one transaction, so a
/// multi-byte value (an AXP2101 ADC pair, an FT6336 point record) cannot
/// tear between bytes as two `read8` calls can.
pub fn read8_n(bus: &mut Bus<'_>, addr: u8, reg: u8, out: &mut [u8]) -> bool {
    bus.write_read(addr, &[reg], out).is_ok()
}

/// 16-bit register address (OV5647 SCCB, GT911).
pub fn read16(bus: &mut Bus<'_>, addr: u8, reg: u16) -> Option<u8> {
    let mut b = [0u8; 1];
    bus.write_read(addr, &[(reg >> 8) as u8, reg as u8], &mut b)
        .ok()
        .map(|_| b[0])
}

/// Burst read from a 16-bit register address (OV5647, GT911).
pub fn read16_n(bus: &mut Bus<'_>, addr: u8, reg: u16, out: &mut [u8]) -> bool {
    bus.write_read(addr, &[(reg >> 8) as u8, reg as u8], out)
        .is_ok()
}

/// Write one byte to a 16-bit register address.
pub fn write16(bus: &mut Bus<'_>, addr: u8, reg: u16, val: u8) -> bool {
    bus.write(addr, &[(reg >> 8) as u8, reg as u8, val]).is_ok()
}

/// Probe one address by a read, then a zero-length write: some controllers
/// NAK a bare read with no register write before it.
pub fn present(bus: &mut Bus<'_>, addr: u8) -> bool {
    let mut b = [0u8; 1];
    bus.read(addr, &mut b).is_ok() || bus.write(addr, &[]).is_ok()
}

/// Walk the 7-bit address space, calling `f` for every device found.
pub fn scan(bus: &mut Bus<'_>, mut f: impl FnMut(u8)) -> u32 {
    let mut n = 0;
    for addr in 0x08u8..0x78u8 {
        if present(bus, addr) {
            f(addr);
            n += 1;
        }
    }
    n
}

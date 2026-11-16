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

//! Routing peripheral signals to pins through the GPIO matrix.
//!
//! Most drivers route pins through `esp-hal`'s typed pin API. The Waveshare
//! camera does not: it drives `LCD_CAM` over eleven pins in an order the
//! sensor's numbering decides, routed by writing the matrix directly, so
//! those pins never appear as `peripherals.GPIO`.
//!
//! # Registers, from the Technical Reference Manual
//!
//! `GPIO_FUNCy_IN_SEL_CFG_REG`, register 6.19, at `0x0154 + 4y` from the GPIO
//! base. Bit 7 selects the matrix rather than the direct IO MUX path; bits 5:0
//! name the pin. So `0x80 | pin` takes peripheral input `y` from `pin`
//! through the matrix.
//!
//! `IO_MUX_GPIOn_REG`, register 6.36, at `0x0004 + 4n` from the IO MUX base.
//! Bit 9 is `FUN_IE`, the input enable, and bits 14:12 are `MCU_SEL`, the
//! function select. A pin routed through the matrix needs the input buffer on
//! and function 1.
//!
//! No `esp-hal` here, so the module builds on a host and its tests run.

/// GPIO peripheral base. TRM, peripheral address map.
const GPIO_BASE: u32 = 0x6000_4000;
/// IO MUX peripheral base.
const IO_MUX_BASE: u32 = 0x6000_9000;

/// `GPIO_FUNC0_IN_SEL_CFG_REG` offset. Register 6.19.
const FUNC_IN_SEL_CFG: u32 = 0x0154;
/// `IO_MUX_GPIO0_REG` offset. Register 6.36.
const IO_MUX_GPIO: u32 = 0x0004;

/// The highest GPIO with an IO MUX register: the manual documents
/// `IO_MUX_GPIO0_REG` through `IO_MUX_GPIO48_REG`.
///
/// The address functions assert against this and [`MAX_SIGNAL`], so a wrong
/// pin map is a compile error in a `const` context, not a store past the
/// register block.
pub const MAX_GPIO: u8 = 48;

/// The highest peripheral input signal with a matrix register.
///
/// `GPIO_FUNC0_IN_SEL_CFG_REG` through `GPIO_FUNC255_IN_SEL_CFG_REG`. See
/// [`MAX_GPIO`].
pub const MAX_SIGNAL: u16 = 255;

/// Bit 7 of `GPIO_FUNCy_IN_SEL_CFG_REG`: take the signal through the matrix.
pub const SIG_IN_SEL: u32 = 1 << 7;
/// Bits 5:0: which pin, or a constant.
pub const IN_SEL_MASK: u32 = 0x3F;

/// The value that ties a peripheral input to constant zero. Against what the
/// numbers suggest, the manual gives `0x3C` for 0 and `0x38` for 1; swapped,
/// the camera never syncs.
pub const IN_SEL_CONST_ZERO: u32 = 0x3C;
/// The value that ties a peripheral input to constant one.
pub const IN_SEL_CONST_ONE: u32 = 0x38;

/// Bit 9 of `IO_MUX_GPIOn_REG`: input enable.
const FUN_IE: u32 = 1 << 9;
/// Bits 14:12: function select.
const MCU_SEL_MASK: u32 = 0x7 << 12;
/// Function 1, which is what a pin routed through the matrix uses.
const MCU_SEL_GPIO: u32 = 1 << 12;

/// Address of a peripheral input's routing register.
///
/// `signal` is the index from the manual's peripheral signal table: 133 to 140
/// are `CAM_DATA_in0` through `in7`, 149 is `CAM_PCLK`, 150 `CAM_H_ENABLE`,
/// 151 `CAM_H_SYNC`, 152 `CAM_V_SYNC`.
pub const fn func_in_sel_cfg(signal: u16) -> u32 {
    assert!(
        signal <= MAX_SIGNAL,
        "no matrix register for this signal: see MAX_SIGNAL"
    );
    GPIO_BASE + FUNC_IN_SEL_CFG + 4 * signal as u32
}

/// Address of a pin's IO MUX register.
pub const fn io_mux_gpio(pin: u8) -> u32 {
    assert!(
        pin <= MAX_GPIO,
        "no IO MUX register for this pin: see MAX_GPIO"
    );
    IO_MUX_BASE + IO_MUX_GPIO + 4 * pin as u32
}

/// The value that routes a signal from `pin`. Separate from the write so a
/// host test can check it.
pub const fn route_value(pin: u8) -> u32 {
    SIG_IN_SEL | (pin as u32 & IN_SEL_MASK)
}

/// The value that ties a signal to constant one or zero.
pub const fn constant_value(one: bool) -> u32 {
    SIG_IN_SEL
        | if one {
            IN_SEL_CONST_ONE
        } else {
            IN_SEL_CONST_ZERO
        }
}

/// Enable a pin's input buffer and put it on function 1.
///
/// Needed before the matrix can take a signal from it: without `FUN_IE` the
/// pad drives nothing into the chip and the peripheral sees a dead line.
pub fn prepare_pin(pin: u8) {
    let reg = io_mux_gpio(pin) as *mut u32;
    // SAFETY: `IO_MUX_GPIOn_REG`, register 6.36, at the manual's address.
    // Read-modify-write: the register also holds pulls and drive strength
    // something else may have set.
    unsafe {
        let v = core::ptr::read_volatile(reg);
        core::ptr::write_volatile(reg, (v & !MCU_SEL_MASK) | MCU_SEL_GPIO | FUN_IE);
    }
}

/// Take peripheral input `signal` from `pin`.
///
/// The caller must have called [`prepare_pin`] first.
pub fn route(signal: u16, pin: u8) {
    // SAFETY: `GPIO_FUNCy_IN_SEL_CFG_REG`, register 6.19. A bare store: every
    // field in it belongs to this routing.
    unsafe {
        core::ptr::write_volatile(func_in_sel_cfg(signal) as *mut u32, route_value(pin));
    }
}

/// Tie peripheral input `signal` to a constant instead of a pin.
///
/// For a signal the peripheral expects and the board does not drive: the
/// Waveshare camera runs in HREF mode, where `CAM_H_ENABLE` carries the line
/// timing and `CAM_H_SYNC` is tied low.
pub fn route_constant(signal: u16, one: bool) {
    // SAFETY: as [`route`].
    unsafe {
        core::ptr::write_volatile(func_in_sel_cfg(signal) as *mut u32, constant_value(one));
    }
}

/// Apply a routing table from `kassigner_hal::pins`, which is checked there
/// against the manufacturer's netlist and the manual's signal table.
pub fn apply(routes: &[kassigner_hal::pins::MatrixRoute]) {
    for r in routes {
        if let Some(pin) = r.gpio {
            prepare_pin(pin);
        }
    }
    for r in routes {
        match r.gpio {
            Some(pin) => route(r.signal, pin),
            // No pin: tied low, as HREF mode needs for the unused sync.
            None => route_constant(r.signal, false),
        }
    }
}

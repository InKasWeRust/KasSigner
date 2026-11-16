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

//! Register addresses and values, checked against the manual's register
//! diagrams.
//!
//! The writes cannot run on a host; the arithmetic that places them and the
//! values they carry can, and that is where this code goes wrong. A wrong
//! address is not a logic error but a number, and a read there can return
//! zero without complaint.

use kassigner_hal::pins::waveshare;
use kassigner_hal_esp32s3::gpio_matrix::{
    constant_value, func_in_sel_cfg, io_mux_gpio, route_value, IN_SEL_CONST_ONE, IN_SEL_CONST_ZERO,
    IN_SEL_MASK, MAX_GPIO, MAX_SIGNAL, SIG_IN_SEL,
};

/// `GPIO_FUNCy_IN_SEL_CFG_REG`, register 6.19, `0x0154 + 4y` from
/// `0x6000_4000`.
#[test]
fn the_routing_registers_are_where_the_manual_says() {
    assert_eq!(func_in_sel_cfg(0), 0x6000_4154);
    assert_eq!(func_in_sel_cfg(1), 0x6000_4158);

    // The camera signals, from the manual's peripheral signal table.
    assert_eq!(func_in_sel_cfg(133), 0x6000_4154 + 4 * 133, "CAM_DATA_in0");
    assert_eq!(func_in_sel_cfg(149), 0x6000_4154 + 4 * 149, "CAM_PCLK");
    assert_eq!(func_in_sel_cfg(152), 0x6000_4154 + 4 * 152, "CAM_V_SYNC");

    // The register exists for y up to 255 and stays inside the GPIO block.
    assert!(func_in_sel_cfg(255) < 0x6000_5000, "still within GPIO");
}

/// `IO_MUX_GPIOn_REG`, register 6.36, `0x0004 + 4n` from `0x6000_9000`.
#[test]
fn the_pin_registers_are_where_the_manual_says() {
    assert_eq!(io_mux_gpio(0), 0x6000_9004);
    assert_eq!(io_mux_gpio(1), 0x6000_9008);
    assert_eq!(io_mux_gpio(48), 0x6000_9004 + 4 * 48);
    assert!(io_mux_gpio(48) < 0x6000_A000, "still within IO MUX");
}

/// A routed value is the matrix bit plus the pin: bit 7, `SIG_IN_SEL`, takes
/// the signal through the matrix, and bits 5:0 name the pin.
#[test]
fn a_route_is_the_matrix_bit_and_the_pin() {
    assert_eq!(SIG_IN_SEL, 0x80);
    assert_eq!(IN_SEL_MASK, 0x3F);

    for pin in [0u8, 1, 9, 12, 21, 47, 48] {
        let v = route_value(pin);
        assert_eq!(v & SIG_IN_SEL, SIG_IN_SEL, "pin {pin}: matrix bit");
        assert_eq!(v & IN_SEL_MASK, pin as u32, "pin {pin}: pin number");
    }

    // The same as `0x80 | pin`.
    assert_eq!(route_value(9), 0x80 | 9);
    assert_eq!(route_value(2), 0x80 | 2);
}

/// Against what the numbers suggest, the manual gives `GPIO_FUNCy_IN_SEL`
/// `0x3C` for constant 0 and `0x38` for constant 1. Swapped, the camera never
/// syncs, and both values look plausible.
#[test]
fn the_constants_are_the_way_round_the_manual_says() {
    assert_eq!(IN_SEL_CONST_ZERO, 0x3C);
    assert_eq!(IN_SEL_CONST_ONE, 0x38);
    assert_ne!(IN_SEL_CONST_ZERO, IN_SEL_CONST_ONE);

    assert_eq!(
        constant_value(false),
        0x80 | 0x3C,
        "constant zero through the matrix"
    );
    assert_eq!(constant_value(true), 0x80 | 0x38);

    // Both fit the field and neither is a pin number, so a constant is never
    // a route. Checked at compile time.
    const _: () = assert!(IN_SEL_CONST_ZERO <= IN_SEL_MASK);
    const _: () = assert!(IN_SEL_CONST_ONE <= IN_SEL_MASK);
    const _: () = assert!(IN_SEL_CONST_ZERO > 48, "a constant must not be a pin");
    const _: () = assert!(IN_SEL_CONST_ONE > 48, "a constant must not be a pin");
}

/// Every route in the camera pin map gives a sane register write. The table
/// is checked against the netlist and the manual's signal indices in
/// `kassigner-hal`; this checks the step from table to writes.
#[test]
fn the_verified_camera_table_routes_cleanly() {
    let mut tied_off = 0;
    for r in waveshare::CAMERA {
        let addr = func_in_sel_cfg(r.signal);
        assert!(
            (0x6000_4154..0x6000_5000).contains(&addr),
            "{}: address {addr:#010x}",
            r.name
        );

        match r.gpio {
            Some(pin) => {
                assert!(pin <= 48, "{}: GPIO{pin}", r.name);
                let v = route_value(pin);
                assert_eq!(v & IN_SEL_MASK, pin as u32);
                assert_ne!(
                    v & IN_SEL_MASK,
                    IN_SEL_CONST_ZERO,
                    "{}: a pin must not collide with the constant",
                    r.name
                );
            }
            None => {
                tied_off += 1;
                assert_eq!(r.name, "CAM_H_SYNC", "only the unused sync is tied off");
            }
        }
    }
    assert_eq!(tied_off, 1);
}

/// Two signals never share a routing register.
#[test]
fn each_signal_has_its_own_register() {
    let mut addrs: Vec<u32> = waveshare::CAMERA
        .iter()
        .map(|r| func_in_sel_cfg(r.signal))
        .collect();
    let before = addrs.len();
    addrs.sort_unstable();
    addrs.dedup();
    assert_eq!(addrs.len(), before);
}

/// An address is computed only for a register that exists:
/// `IO_MUX_GPIO0_REG` to `IO_MUX_GPIO48_REG` and `GPIO_FUNC0_IN_SEL_CFG_REG`
/// to `GPIO_FUNC255_IN_SEL_CFG_REG`. A `u8` pin reaches 255 and a `u16`
/// signal 65535, so unbounded, either could name a register past its block.
#[test]
fn an_address_is_only_computed_for_a_register_that_exists() {
    // The two ends of each block, against the manual.
    assert_eq!(io_mux_gpio(0), 0x6000_9004);
    assert_eq!(io_mux_gpio(MAX_GPIO), 0x6000_9004 + 4 * 48);
    assert_eq!(func_in_sel_cfg(0), 0x6000_4154);
    assert_eq!(func_in_sel_cfg(MAX_SIGNAL), 0x6000_4154 + 4 * 255);

    assert_eq!(MAX_GPIO, 48, "IO_MUX_GPIO48_REG is the last one");
    assert_eq!(
        MAX_SIGNAL, 255,
        "GPIO_FUNC255_IN_SEL_CFG_REG is the last one"
    );

    // One past each end panics.
    assert!(std::panic::catch_unwind(|| io_mux_gpio(MAX_GPIO + 1)).is_err());
    assert!(std::panic::catch_unwind(|| func_in_sel_cfg(MAX_SIGNAL + 1)).is_err());

    // Every route the board uses is inside the bounds, so neither assert
    // fires on a device.
    for r in waveshare::CAMERA.iter() {
        assert!(r.signal <= MAX_SIGNAL, "{}", r.name);
        if let Some(gpio) = r.gpio {
            assert!(gpio <= MAX_GPIO, "{}", r.name);
        }
    }
}

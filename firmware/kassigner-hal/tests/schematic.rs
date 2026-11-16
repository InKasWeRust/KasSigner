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

//! The Waveshare map against the board.
//!
//! `tests/pins.rs` checks the map against itself and the manual, which a map
//! that is consistent and wrong still passes. The table below is the netlist
//! of `ESP32-S3-Touch-LCD-2-SchDoc.pdf`, the manufacturer's schematic, taken
//! from the drawing's netlist layer rather than read off the picture: each
//! entry is `net name -> GPIO` exactly as the board is wired.

use kassigner_hal::pins::waveshare;

/// `ESP32-S3-Touch-LCD-2-SchDoc.pdf`, netlist layer: net name, then GPIO.
///
/// The camera data lines matter most: their GPIO order looks arbitrary, and
/// a swapped pair gives a wrong picture rather than none, with nothing
/// reporting it.
#[rustfmt::skip]
const SCHEMATIC: &[(&str, u8)] = &[
    ("BOOT",       0), ("LCD_RST",   0),
    ("LCD_BL",     1),
    ("CAM_D7",     2),
    ("IMU_INT1",   3),
    ("CAM_HREF",   4),
    ("BAT_ADC",    5),
    ("CAM_VSYNC",  6),
    ("CAM_D6",     7),
    ("CAM_XCLK",   8),
    ("CAM_PCLK",   9),
    ("CAM_D5",    10),
    ("CAM_D3",    11),
    ("CAM_D0",    12),
    ("CAM_D1",    13),
    ("CAM_D4",    14),
    ("CAM_D2",    15),
    ("TWI_CLK",   16),
    ("CAM_PWDN",  17),
    ("USB_N",     19),
    ("USB_P",     20),
    ("TWI_SDA",   21),
    ("LCD_MOSI",  38), ("SD_MOSI",  38),
    ("LCD_SCLK",  39), ("SD_SCLK",  39),
    ("SD_MISO",   40),
    ("SD_CS",     41),
    ("LCD_DC",    42),
    ("U0_TXD",    43),
    ("U0_RXD",    44),
    ("LCD_CS",    45),
    ("TP_INT",    46),
    ("IMU_SCL",   47), ("TP_SCL",   47),
    ("IMU_SDA",   48), ("TP_SDA",   48),
];

fn schematic(net: &str) -> u8 {
    SCHEMATIC
        .iter()
        .find(|(n, _)| *n == net)
        .unwrap_or_else(|| panic!("{net} is not a net on this board"))
        .1
}

/// The camera data lines are wired where the firmware thinks they are:
/// `CAM_D0` must reach `CAM_DATA_in0`, and so on, or the bytes arrive with
/// their bits permuted.
#[test]
fn the_camera_data_lines_match_the_board() {
    for r in waveshare::CAMERA {
        let Some(gpio) = r.gpio else { continue };
        let Some(n) = r.name.strip_prefix("CAM_DATA_in") else {
            continue;
        };
        assert_eq!(
            gpio,
            schematic(&format!("CAM_D{n}")),
            "CAM_DATA_in{n} is routed from GPIO{gpio}, the board has it elsewhere"
        );
    }
}

/// The camera's clocks and syncs match the board.
#[test]
fn the_camera_control_lines_match_the_board() {
    for (signal, net) in [
        (149u16, "CAM_PCLK"),
        (152, "CAM_VSYNC"),
        (150, "CAM_HREF"), // the manual calls it CAM_H_ENABLE; the board, HREF
    ] {
        let r = waveshare::CAMERA
            .iter()
            .find(|r| r.signal == signal)
            .expect("in the map");
        assert_eq!(r.gpio, Some(schematic(net)), "{net}");
    }

    assert_eq!(waveshare::CAMERA_XCLK.gpio, schematic("CAM_XCLK"));
    assert_eq!(waveshare::CAMERA_PWDN.gpio, schematic("CAM_PWDN"));

    // `CAM_H_SYNC` is tied to a constant, and the board has no net for it: a
    // sensor in HREF mode does not drive HSYNC.
    let hsync = waveshare::CAMERA.iter().find(|r| r.signal == 151).unwrap();
    assert!(hsync.gpio.is_none());
    assert!(
        !SCHEMATIC.iter().any(|(n, _)| n.contains("HSYNC")),
        "the board has an HSYNC net after all; the tie-off would be wrong"
    );
}

/// The two I2C buses are the ones the board wires: `TP_*` is the touch and
/// IMU bus, `TWI_*` the camera's SCCB.
#[test]
fn the_i2c_buses_match_the_board() {
    assert_eq!(waveshare::I2C0[0].gpio, schematic("TP_SDA"), "I2C0 SDA");
    assert_eq!(waveshare::I2C0[1].gpio, schematic("TP_SCL"), "I2C0 SCL");
    assert_eq!(waveshare::I2C0[2].gpio, schematic("TP_INT"), "touch INT");

    assert_eq!(waveshare::I2C1[0].gpio, schematic("TWI_SDA"), "SCCB SDA");
    assert_eq!(waveshare::I2C1[1].gpio, schematic("TWI_CLK"), "SCCB SCL");

    // And the IMU is on the touch bus, not its own.
    assert_eq!(schematic("IMU_SDA"), schematic("TP_SDA"));
    assert_eq!(schematic("IMU_SCL"), schematic("TP_SCL"));
}

/// The display and SD card match the board, including what they share.
#[test]
fn the_display_and_sd_match_the_board() {
    assert_eq!(waveshare::DISPLAY[0].gpio, schematic("LCD_CS"));
    assert_eq!(waveshare::DISPLAY[1].gpio, schematic("LCD_DC"));
    assert_eq!(waveshare::DISPLAY[2].gpio, schematic("LCD_RST"));
    assert_eq!(waveshare::DISPLAY[3].gpio, schematic("LCD_BL"));

    assert_eq!(waveshare::SPI2[0].gpio, schematic("LCD_SCLK"));
    assert_eq!(waveshare::SPI2[1].gpio, schematic("LCD_MOSI"));

    assert_eq!(waveshare::SD[0].gpio, schematic("SD_MISO"));
    assert_eq!(waveshare::SD[1].gpio, schematic("SD_CS"));

    // The sharing is on the board, not a firmware convention.
    assert_eq!(schematic("SD_SCLK"), schematic("LCD_SCLK"));
    assert_eq!(schematic("SD_MOSI"), schematic("LCD_MOSI"));
}

/// The remaining pins match the board.
#[test]
fn the_rest_matches_the_board() {
    assert_eq!(waveshare::BATTERY_ADC.gpio, schematic("BAT_ADC"));
    assert_eq!(waveshare::UART[0].gpio, schematic("U0_TXD"));
    assert_eq!(waveshare::UART[1].gpio, schematic("U0_RXD"));
    assert_eq!(waveshare::USB[0].gpio, schematic("USB_N"));
    assert_eq!(waveshare::USB[1].gpio, schematic("USB_P"));
    assert_eq!(waveshare::IMU_INT.gpio, schematic("IMU_INT1"));
}

/// Nothing in the map is on a pin the board does not wire: driving one would
/// silently do nothing.
#[test]
fn the_map_invents_no_pins() {
    let wired: Vec<u8> = SCHEMATIC.iter().map(|(_, g)| *g).collect();
    for p in waveshare::all() {
        assert!(
            wired.contains(&p.gpio),
            "GPIO{} ('{}') is in the map and carries no net on the board",
            p.gpio,
            p.function
        );
    }
}

/// GPIO0 is the BOOT strap and, on the schematic, the display reset: one
/// net with the BOOT button. The board does not fit the link to the panel
/// (R16), so the firmware leaves GPIO0 alone: a driven GPIO0 would reset
/// nothing, would be shorted to ground by the button, and would also decide
/// whether the chip runs the firmware or the ROM loader.
#[test]
fn the_boot_strap_and_the_display_reset_are_one_net() {
    assert_eq!(schematic("BOOT"), schematic("LCD_RST"));
    assert_eq!(schematic("BOOT"), 0);

    let rst = waveshare::DISPLAY
        .iter()
        .find(|p| p.function.contains("RST"))
        .unwrap();
    assert!(rst.strapping(), "the display reset is on a strapping pin");
}

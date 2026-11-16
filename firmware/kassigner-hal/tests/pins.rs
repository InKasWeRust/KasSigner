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

//! Pin map checks: the properties a wrong pin would break, cheap enough for
//! every build. They check that the map is coherent, that no pin does two
//! incompatible things, and that the signal indices are the manual's. Whether
//! a pin matches the board needs its schematic: `tests/schematic.rs` holds the
//! Waveshare's.

use kassigner_hal::pins::{
    m5stack, waveshare, Pin, IN_SEL_CONST_ONE, IN_SEL_CONST_ZERO, OCTAL_SPI_PINS,
};

/// Every pin is a GPIO the ESP32-S3 has: 0 to 48, without 22 to 25. Any
/// other number is a typo that compiles and fails on hardware.
#[test]
fn every_pin_is_a_real_esp32s3_gpio() {
    for (board, pins) in [
        ("waveshare", waveshare::all().collect::<Vec<_>>()),
        ("m5stack", m5stack::all().collect::<Vec<_>>()),
    ] {
        for p in pins {
            assert!(
                p.gpio <= 48,
                "{board}: GPIO{} is above the highest pin",
                p.gpio
            );
            assert!(
                !(22..=25).contains(&p.gpio),
                "{board}: GPIO{} does not exist on the ESP32-S3",
                p.gpio
            );
        }
    }
}

/// No pin is used twice on one board, except where sharing is the design:
/// the M5 display and SD card share the bus and one data line, muxed at
/// runtime. Anything else twice is two drivers fighting over a pin.
#[test]
fn a_pin_is_used_once_unless_sharing_is_deliberate() {
    // (board, gpio), each with its reason.
    const SHARED: &[(&str, u8)] = &[
        // LCD DC and SD MISO, muxed around each card session.
        ("m5stack", 35),
    ];

    for (board, pins) in [
        ("waveshare", waveshare::all().collect::<Vec<_>>()),
        ("m5stack", m5stack::all().collect::<Vec<_>>()),
    ] {
        let mut seen: Vec<(u8, &str)> = Vec::new();
        for p in &pins {
            if let Some((_, other)) = seen.iter().find(|(g, _)| *g == p.gpio) {
                assert!(
                    SHARED.contains(&(board, p.gpio)),
                    "{board}: GPIO{} is both '{}' and '{}', and is not a declared shared pin",
                    p.gpio,
                    other,
                    p.function
                );
            }
            seen.push((p.gpio, p.function));
        }
    }
}

/// The strapping pins are the manual's four, and each use is accounted for:
/// whatever drives one must not hold the wrong level as the chip leaves
/// reset, and a watchdog reset can come at any time.
#[test]
fn strapping_pins_are_known_and_accounted_for() {
    assert!(Pin::new(0, "", "").strapping());
    assert!(Pin::new(3, "", "").strapping());
    assert!(Pin::new(45, "", "").strapping());
    assert!(Pin::new(46, "", "").strapping());
    for g in [1u8, 2, 4, 44, 47, 48] {
        assert!(
            !Pin::new(g, "", "").strapping(),
            "GPIO{g} is not a strapping pin"
        );
    }

    // Which each board uses: a change here means a strapping pin moved, so
    // think about boot.
    let ws: Vec<u8> = waveshare::all()
        .filter(|p| p.strapping())
        .map(|p| p.gpio)
        .collect();
    let m5: Vec<u8> = m5stack::all()
        .filter(|p| p.strapping())
        .map(|p| p.gpio)
        .collect();

    // Waveshare uses all four. The firmware drives GPIO45 and leaves GPIO0,
    // the BOOT button, alone; the touch controller drives GPIO46, high, which
    // keeps BOOT held through a reset out of USB download; and the IMU GPIO3,
    // the JTAG-source strap: the firmware polls and never configures INT1, so
    // it stays at the sensor's power-on default, but nothing here enforces
    // that.
    assert_eq!(
        ws,
        vec![46, 45, 0, 3],
        "waveshare: touch INT, LCD CS, BOOT, IMU INT1"
    );
    assert_eq!(
        ws.len(),
        4,
        "every ESP32-S3 strapping pin is in use on this board"
    );
    assert_eq!(
        m5,
        vec![3, 45, 46],
        "m5stack: LCD CS, camera PCLK, camera VSYNC"
    );

    // GPIO45, on both boards, selects VDD_SPI, the flash voltage, at reset:
    // LCD chip select on Waveshare, the sensor's pixel clock on M5.
    // `Pin::strapping` says why a cold boot is safe and a watchdog reset
    // needs thought.
    assert!(ws.contains(&45), "waveshare drives VDD_SPI's strap");
    assert!(m5.contains(&45), "m5stack drives VDD_SPI's strap");
}

/// The camera signal indices are the ESP32-S3 TRM's. A wrong one routes a
/// data line to a sync signal and gives a frame that is almost right, a
/// fault hard to debug.
#[test]
fn the_camera_signal_indices_match_the_manual() {
    for r in waveshare::CAMERA {
        let expected = match r.signal {
            133..=140 => {
                // CAM_DATA_in0 counts up from 133.
                let n = r.signal - 133;
                assert_eq!(r.name, format!("CAM_DATA_in{n}"), "signal {}", r.signal);
                continue;
            }
            149 => "CAM_PCLK",
            150 => "CAM_H_ENABLE",
            151 => "CAM_H_SYNC",
            152 => "CAM_V_SYNC",
            other => panic!("signal {other} is not a camera input in the manual's table"),
        };
        assert_eq!(r.name, expected, "signal {}", r.signal);
    }
}

/// Eight data lines, in order, each on its own pin.
#[test]
fn the_camera_has_eight_distinct_data_lines() {
    let data: Vec<_> = waveshare::CAMERA
        .iter()
        .filter(|r| (133..=140).contains(&r.signal))
        .collect();
    assert_eq!(data.len(), 8);

    for (i, r) in data.iter().enumerate() {
        assert_eq!(
            r.signal,
            133 + i as u16,
            "data lines must be in signal order"
        );
        assert!(r.gpio.is_some(), "{} has no pin", r.name);
    }

    let mut pins: Vec<u8> = data.iter().filter_map(|r| r.gpio).collect();
    let before = pins.len();
    pins.sort_unstable();
    pins.dedup();
    assert_eq!(pins.len(), before, "two data lines share a pin");
}

/// `CAM_H_SYNC` is tied to a constant, not to a pin (HREF mode), and the
/// constants are the manual's: `0x3C` is always 0, `0x38` always 1.
#[test]
fn the_unused_sync_signal_is_tied_off() {
    let hsync = waveshare::CAMERA
        .iter()
        .find(|r| r.signal == 151)
        .expect("CAM_H_SYNC is in the map");
    assert!(hsync.gpio.is_none(), "CAM_H_SYNC should not be on a pin");

    assert_eq!(IN_SEL_CONST_ZERO, 0x3C);
    assert_eq!(IN_SEL_CONST_ONE, 0x38);
    assert_ne!(IN_SEL_CONST_ZERO, IN_SEL_CONST_ONE);
}

/// Every entry says where it came from: a map without provenance is a second
/// copy of the truth, and the two drift.
#[test]
fn every_pin_names_its_source() {
    for p in waveshare::all().chain(m5stack::all()) {
        assert!(
            p.source.contains(".rs:"),
            "GPIO{} ('{}') has no source line",
            p.gpio,
            p.function
        );
        assert!(!p.function.is_empty(), "GPIO{} has no function", p.gpio);
    }
}

/// The two boards do not have to agree, and mostly do not: display, camera
/// and buses land on different pins, so one map with exceptions would be
/// wrong far more often than right.
#[test]
fn the_boards_share_almost_nothing() {
    let ws: Vec<u8> = waveshare::all().map(|p| p.gpio).collect();
    let m5: Vec<u8> = m5stack::all().map(|p| p.gpio).collect();

    let common: Vec<u8> = ws.iter().copied().filter(|g| m5.contains(g)).collect();
    // Any overlap is coincidence: the same number doing a different job on
    // each board.
    for g in &common {
        let a = waveshare::all().find(|p| p.gpio == *g).unwrap();
        let b = m5stack::all().find(|p| p.gpio == *g).unwrap();
        assert_ne!(
            (a.function, b.function),
            (a.function, a.function),
            "GPIO{g} happens to match; that is coincidence, not a convention"
        );
    }
}

// ── Bus and device checks ────────────────────────────────────────────────────

/// No two devices share an address on one bus: both would answer at once
/// and the bus would be unusable.
#[test]
fn no_two_devices_share_an_address_on_a_bus() {
    for (bus, devices) in [
        ("waveshare I2C0", &waveshare::I2C0_DEVICES[..]),
        ("waveshare I2C1", &waveshare::I2C1_DEVICES[..]),
    ] {
        let mut addrs: Vec<u8> = devices.iter().map(|(a, _)| *a).collect();
        let before = addrs.len();
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(addrs.len(), before, "{bus}: two devices share an address");
    }
}

/// Every address is a legal 7-bit I2C address outside the ranges the
/// specification reserves, 0x00 to 0x07 and 0x78 to 0x7F (general call,
/// 10-bit prefix and others).
#[test]
fn every_address_is_a_usable_seven_bit_address() {
    for (addr, name) in waveshare::I2C0_DEVICES
        .iter()
        .chain(&waveshare::I2C1_DEVICES)
    {
        assert!(*addr <= 0x7F, "{name}: {addr:#04x} is not a 7-bit address");
        assert!(
            *addr >= 0x08,
            "{name}: {addr:#04x} is in the reserved low range"
        );
        assert!(
            *addr < 0x78,
            "{name}: {addr:#04x} is in the reserved high range"
        );
    }
}

/// The camera bus runs slower than the touch bus, and both are legal: SCCB
/// is not quite I2C and the sensors do not reliably meet 400 kHz, so touch
/// has a bus of its own at full speed.
#[test]
fn the_bus_speeds_are_what_the_parts_need() {
    assert_eq!(waveshare::I2C0_KHZ, 400, "touch and IMU at fast mode");
    assert_eq!(waveshare::I2C1_KHZ, 100, "SCCB at standard mode");

    // Compile-time: both sides are constants.
    const _: () = assert!(
        waveshare::I2C1_KHZ < waveshare::I2C0_KHZ,
        "the sensor bus must not be held to the touch bus's speed"
    );
    const _: () = assert!(
        waveshare::SEPARATE_I2C_BUSES,
        "touch and the camera must be on separate buses"
    );
}

/// The camera data lines follow the sensor's numbering: `CAM_DATA_in0` is
/// the sensor's Y2, and so on to Y9.
#[test]
fn the_camera_data_lines_follow_the_sensor_numbering() {
    let matrix: Vec<u8> = waveshare::CAMERA
        .iter()
        .filter(|r| (133..=140).contains(&r.signal))
        .filter_map(|r| r.gpio)
        .collect();
    let sensor: Vec<u8> = waveshare::CAMERA_SENSOR_PINS
        .iter()
        .map(|(g, _)| *g)
        .collect();

    assert_eq!(
        matrix, sensor,
        "the two tables disagree about the data lines"
    );

    for (i, (_, y)) in waveshare::CAMERA_SENSOR_PINS.iter().enumerate() {
        assert_eq!(
            *y,
            format!("Y{}", i + 2),
            "data line {i} should be Y{}",
            i + 2
        );
    }
}

/// The board's capability flags match its pin map: two statements of one
/// fact can drift apart.
#[test]
fn the_capability_flags_match_the_map() {
    // No speaker, so no I2S pins; no PMU, so the battery is read through an
    // ADC. Constants, so checked when the tests compile.
    const _: () = assert!(!waveshare::HAS_SPEAKER);
    const _: () = assert!(!waveshare::HAS_PMU);
    const _: () = assert!(waveshare::HAS_BATTERY);

    assert!(
        waveshare::all().any(|p| p.gpio == waveshare::BATTERY_ADC.gpio),
        "HAS_BATTERY is set but the ADC pin is not in the map"
    );

    // The M5 has a speaker, so its map has I2S pins.
    assert!(m5stack::all().any(|p| p.function.starts_with("I2S")));
}

/// GPIO33 to 37 follow each board's memory (`OCTAL_SPI_PINS`): unused on the
/// Waveshare's octal-PSRAM `ESP32-S3R8`, all used on the M5. A change here
/// means a module changed.
#[test]
fn the_octal_spi_pins_are_a_module_constraint() {
    let ws_uses: Vec<u8> = waveshare::all()
        .map(|p| p.gpio)
        .filter(|g| OCTAL_SPI_PINS.contains(g))
        .collect();
    assert!(
        ws_uses.is_empty(),
        "waveshare is an ESP32-S3R8 with octal PSRAM; it cannot use {ws_uses:?}"
    );

    let mut m5_uses: Vec<u8> = m5stack::all()
        .map(|p| p.gpio)
        .filter(|g| OCTAL_SPI_PINS.contains(g))
        .collect();
    m5_uses.sort_unstable();
    m5_uses.dedup();
    assert_eq!(
        m5_uses,
        vec![33, 34, 35, 36, 37],
        "m5 uses the whole range, which requires a part without octal PSRAM"
    );
}

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

//! The Waveshare unit's arithmetic, checked without hardware.
//!
//! Registers cannot be written here, but what decides *what* to write can:
//! the backlight duty, the touch rotation, the panel geometry, the pins'
//! register bank, and the touch and camera-tuning writes.

#![cfg(feature = "waveshare")]

use kassigner_hal::display::{Backlight as Level, Size};
use kassigner_hal_esp32s3::waveshare::{backlight, panel, touch};

/// The duty register is Q4, so a level shifts left by four. Without the
/// shift a level gives a sixteenth of the brightness, which looks like a dim
/// panel, not a bug.
#[test]
fn the_duty_is_the_level_shifted_into_the_fractional_field() {
    assert_eq!(backlight::duty_for(Level::Level(1)), 16);
    assert_eq!(backlight::duty_for(Level::Level(255)), 255 * 16);
    assert_eq!(backlight::duty_for(Level::Level(128)), 2048);
}

/// **Off is duty zero, and on this unit that is dark.** On the M5 the lowest
/// rail voltage is still lit and `Off` disables the rail, which is why the
/// level is an enum.
#[test]
fn off_is_dark_here() {
    assert_eq!(backlight::duty_for(Level::Off), 0);
    assert_ne!(
        backlight::duty_for(Level::Level(1)),
        0,
        "and one is not off"
    );
}

/// **A touch lands where the finger is, on a panel mounted turned.** The
/// display is built with a 90 degree rotation; touch reports in the native
/// portrait frame and must make the same turn. Each native corner must map
/// to the landscape corner under the finger.
#[test]
fn the_touch_rotation_matches_the_panel_rotation() {
    let w = panel::SIZE.width;
    let h = panel::SIZE.height;

    // Native origin: top-left in portrait becomes bottom-left in landscape.
    assert_eq!(touch::rotate(0, 0), Some((0, h - 1)));
    // Native far y becomes far x.
    assert_eq!(touch::rotate(0, w - 1), Some((w - 1, h - 1)));
    // Native far x walks up from the bottom.
    assert_eq!(touch::rotate(h - 1, 0), Some((0, 0)));
    assert_eq!(touch::rotate(h - 1, w - 1), Some((w - 1, 0)));

    // Middle stays in the middle.
    assert_eq!(touch::rotate(h / 2, w / 2), Some((w / 2, h - 1 - h / 2)));
}

/// A report off the panel is no point at all. The registers give twelve
/// bits, so a report can exceed the panel; clamped onto the edge it would
/// look like a real touch, and this unit's phantom touches are such reports.
/// Every raw value on the panel lands on it; one past is dropped.
#[test]
fn a_report_off_the_panel_is_dropped() {
    let (w, h) = (panel::SIZE.width, panel::SIZE.height);
    for raw_x in [0u16, 1, 239, 240, 1000, 4095] {
        for raw_y in [0u16, 1, 319, 320, 1000, 4095] {
            match touch::rotate(raw_x, raw_y) {
                Some((x, y)) => {
                    assert!(raw_x < h && raw_y < w, "({raw_x}, {raw_y}) kept");
                    assert!(x < w && y < h, "({x}, {y}) from ({raw_x}, {raw_y})");
                }
                None => assert!(raw_x >= h || raw_y >= w, "({raw_x}, {raw_y}) dropped"),
            }
        }
    }
}

/// The panel is built portrait and drawn landscape.
#[test]
fn the_panel_is_native_portrait_and_drawn_landscape() {
    assert_eq!(panel::NATIVE, Size::new(240, 320));
    assert_eq!(panel::SIZE, Size::new(320, 240));
    assert_eq!(
        panel::NATIVE.pixels(),
        panel::SIZE.pixels(),
        "same panel, turned"
    );
    assert_eq!(panel::SIZE.pixels(), 76_800);
}

/// The I2C0 pins are GPIO48 and 47, in the upper register bank: `i2c_bus`
/// picks the bank from the pin number, and its own tests hold the registers
/// to the manual.
#[test]
fn the_touch_pins_are_in_the_upper_register_bank() {
    use kassigner_hal::pins::waveshare;
    for p in waveshare::I2C0.iter().take(2) {
        assert!(p.gpio >= 32, "{} is GPIO{}", p.function, p.gpio);
        assert!(p.gpio <= 48);
    }
    assert_eq!(waveshare::I2C0[0].gpio, 48, "SDA");
    assert_eq!(waveshare::I2C0[1].gpio, 47, "SCL");
}

/// The touch controller on a bus whose reads go as scripted, then answer
/// with no finger down. It keeps every register write.
#[derive(Default)]
struct TouchBus {
    /// The reads to come, in order: `true` answers, `false` fails.
    reads: std::collections::VecDeque<bool>,
    writes: Vec<Vec<u8>>,
}

impl embedded_hal::i2c::ErrorType for TouchBus {
    type Error = embedded_hal::i2c::ErrorKind;
}

impl embedded_hal::i2c::I2c for TouchBus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [embedded_hal::i2c::Operation<'_>],
    ) -> Result<(), Self::Error> {
        assert_eq!(address, touch::ADDRESS);
        let read = operations
            .iter()
            .any(|op| matches!(op, embedded_hal::i2c::Operation::Read(_)));
        if read && !self.reads.pop_front().unwrap_or(true) {
            return Err(embedded_hal::i2c::ErrorKind::Bus);
        }
        for op in operations {
            match op {
                embedded_hal::i2c::Operation::Write(b) if !read => self.writes.push(b.to_vec()),
                embedded_hal::i2c::Operation::Write(_) => {}
                embedded_hal::i2c::Operation::Read(buf) => buf.fill(0),
            }
        }
        Ok(())
    }
}

/// **After [`touch::RECONFIGURE_AFTER`] failed reads in a row the settings are
/// written again; after one fewer they are not.**
///
/// The bus frees itself (`i2c_bus`); the driver restores the controller's
/// settings, which a controller reset behind the errors loses. Those three
/// are its only writes.
#[test]
fn the_touch_settings_are_written_again_after_failed_reads() {
    use kassigner_hal::input::{Error, State, Touch};
    use touch::WaveshareTouch;

    const SETTINGS: [[u8; 2]; 3] = [[0x05, 0x60], [0x06, 0x30], [0xFE, 0x01]];
    for (failures, times) in [
        (0, 1),
        (touch::RECONFIGURE_AFTER - 1, 1),
        (touch::RECONFIGURE_AFTER, 2),
        (touch::RECONFIGURE_AFTER + 3, 2),
    ] {
        let mut bus = TouchBus::default();
        bus.reads.push_back(true);
        bus.reads
            .extend(std::iter::repeat_n(false, usize::from(failures)));
        let mut t = WaveshareTouch::new(bus);
        assert_eq!(t.read(), Ok(State::Idle), "the first read");
        for n in 0..failures {
            assert_eq!(t.read(), Err(Error::Io), "failed read {n}");
        }
        assert_eq!(
            t.read(),
            Ok(State::Idle),
            "the read after {failures} failures"
        );
        let expect: Vec<Vec<u8>> = SETTINGS
            .iter()
            .cycle()
            .take(SETTINGS.len() * times)
            .map(|s| s.to_vec())
            .collect();
        assert_eq!(t.release().writes, expect, "{failures} failed reads");
    }
}

/// The controller's address is a usable seven-bit one.
#[test]
fn the_address_is_usable() {
    const _: () = assert!(touch::ADDRESS == 0x15);
    const _: () = assert!(touch::ADDRESS >= 0x08);
    const _: () = assert!(touch::ADDRESS < 0x78);
}

/// **The Waveshare holds a 16,384-byte transaction and shows at most
/// 14,397 bytes, and its profile is the S3 profile.**
#[test]
fn the_waveshare_capacity_is_the_firmwares() {
    use kassigner_hal_esp32s3::waveshare::{CAPACITY, PROFILE};
    use kassigner_protocol::profile::Profile;
    assert_eq!(PROFILE, Profile::ESP32S3);
    assert_eq!(CAPACITY.display_bytes(), 14_397);
    assert_eq!(CAPACITY.frames * CAPACITY.bytes_per_frame, 16_384);
}

// ── Tuning ──────────────────────────────────────────────────────────────────

/// An OV5640 on its own bus: sixteen-bit register addresses, a value each.
#[derive(Default)]
struct Sensor {
    regs: std::collections::HashMap<u16, u8>,
    pointer: u16,
}

impl embedded_hal::i2c::ErrorType for Sensor {
    type Error = embedded_hal::i2c::ErrorKind;
}

impl embedded_hal::i2c::I2c for Sensor {
    fn transaction(
        &mut self,
        _address: u8,
        operations: &mut [embedded_hal::i2c::Operation<'_>],
    ) -> Result<(), Self::Error> {
        for op in operations {
            match op {
                embedded_hal::i2c::Operation::Write(b) => {
                    self.pointer = u16::from_be_bytes([b[0], b[1]]);
                    if let Some(&v) = b.get(2) {
                        self.regs.insert(self.pointer, v);
                    }
                }
                embedded_hal::i2c::Operation::Read(buf) => {
                    buf[0] = *self.regs.get(&self.pointer).unwrap_or(&0);
                }
            }
        }
        Ok(())
    }
}

/// The tuner's six knobs on their registers: both halves of each AEC window
/// edge move together, the low edge is held at or under the high one, and
/// there is no exposure switch.
#[test]
fn the_tuner_moves_the_scan_registers() {
    use kassigner_hal::tune::Tune;
    use kassigner_hal_esp32s3::waveshare::sensor;
    let mut s = Sensor::default();
    for &(reg, val) in sensor::INIT_REGS
        .iter()
        .chain(sensor::LCD_QR_TUNING)
        .chain(sensor::SCAN_DEFAULTS)
    {
        s.regs.insert(reg, val);
    }
    let mut t = sensor::Tuner::new(&mut s);
    let labels: Vec<_> = t.knobs().iter().map(|k| k.label).collect();
    assert_eq!(labels, ["AEC-H", "AEC-L", "Contr", "Brite", "AGC", "Sharp"]);
    let mut v = [0u8; 6];
    t.read(&mut v).unwrap();
    assert_eq!(
        v,
        [0x58, 0x48, 0x38, 0x00, 0xB0, 0x30],
        "the starting values the tables leave, the ceiling at 0xB0"
    );
    for (k, &value) in t.knobs().iter().zip(&v) {
        assert_eq!(k.snap(value), value, "{} on its grid", k.label);
    }
    assert_eq!(t.auto(), None);

    t.write(0, 0x30).unwrap();
    t.write(1, 0x50).unwrap();
    t.write(4, 0xF8).unwrap();
    t.read(&mut v).unwrap();
    assert_eq!(
        v[..2],
        [0x30, 0x30],
        "low pulled down to high, and held there"
    );
    assert_eq!(v[4], 0xF8);
    assert_eq!(s.regs[&0x3A1B], 0x30);
    assert_eq!(s.regs[&0x3A1E], 0x30);
}

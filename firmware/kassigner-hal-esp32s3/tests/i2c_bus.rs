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

//! The bus recovery's sequence against a model of a device holding SDA, and
//! its registers against the manual.

use kassigner_hal_esp32s3::i2c_bus::{self, clock_free, Lines, PULSES};

/// A device on the bus, as it drives SDA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Device {
    /// Not driving: between transfers, or after a start or a stop.
    Idle,
    /// Sending `byte`, bit `bit` on SDA; `None` once the byte is done and SDA
    /// let go for the controller's acknowledge, `acked` being what it read.
    Sending {
        byte: u8,
        bit: Option<u8>,
        acked: bool,
        /// What it sends next if the controller acknowledges.
        next: u8,
    },
    /// Holding SDA low to acknowledge a byte it received, until SCL falls.
    Acking,
    /// Holding SDA low whatever happens: a part that has failed.
    Dead,
}

impl Device {
    fn sda(self) -> bool {
        match self {
            Device::Idle | Device::Sending { bit: None, .. } => true,
            Device::Sending {
                byte, bit: Some(b), ..
            } => (byte >> b) & 1 == 1,
            Device::Acking | Device::Dead => false,
        }
    }

    fn scl_rose(&mut self, sda: bool) {
        if let Device::Sending {
            bit: None, acked, ..
        } = self
        {
            *acked = !sda;
        }
    }

    fn scl_fell(&mut self) {
        *self = match *self {
            Device::Sending {
                byte,
                bit: Some(b),
                acked,
                next,
            } => Device::Sending {
                byte,
                bit: b.checked_sub(1),
                acked,
                next,
            },
            Device::Sending {
                bit: None,
                acked: true,
                next,
                ..
            } => Device::Sending {
                byte: next,
                bit: Some(7),
                acked: false,
                next,
            },
            Device::Sending { acked: false, .. } | Device::Acking => Device::Idle,
            other => other,
        };
    }
}

/// The two lines, wired-AND between the controller's pins and the device.
struct Bus {
    scl: bool,
    sda: bool,
    device: Device,
    starts: u32,
    stops: u32,
    falls: u32,
}

impl Bus {
    /// A bus between transfers, SCL high, with `device` holding it.
    fn holding(device: Device) -> Self {
        Self {
            scl: true,
            sda: true,
            device,
            starts: 0,
            stops: 0,
            falls: 0,
        }
    }

    fn line(&self) -> bool {
        self.sda && self.device.sda()
    }
}

impl Lines for Bus {
    fn sda_high(&mut self) -> bool {
        self.line()
    }

    fn set_scl(&mut self, high: bool) {
        if high == self.scl {
            return;
        }
        self.scl = high;
        if high {
            let line = self.line();
            self.device.scl_rose(line);
        } else {
            self.falls += 1;
            self.device.scl_fell();
        }
    }

    fn set_sda(&mut self, high: bool) {
        let before = self.line();
        self.sda = high;
        let after = self.line();
        // SDA moving with SCL high is a start or a stop; either resets any
        // device that still works.
        if self.scl && before != after {
            if after {
                self.stops += 1;
            } else {
                self.starts += 1;
            }
            if self.device != Device::Dead {
                self.device = Device::Idle;
            }
        }
    }

    fn half(&mut self) {}
}

/// A device stopped on any zero bit of any byte is clocked off and sees a
/// stop. Its next byte is all zeros, the worst case; the controller never
/// acknowledges, so the device stops after its byte.
#[test]
fn a_device_held_mid_byte_is_freed() {
    for byte in 0..=u8::MAX {
        for bit in (0..8).filter(|b| (byte >> b) & 1 == 0) {
            let mut bus = Bus::holding(Device::Sending {
                byte,
                bit: Some(bit),
                acked: false,
                next: 0,
            });
            assert!(!bus.line(), "{byte:#04x} bit {bit} holds SDA");
            assert!(clock_free(&mut bus), "{byte:#04x} bit {bit} freed");
            assert_eq!(bus.device, Device::Idle, "{byte:#04x} bit {bit}");
            assert!(bus.line() && bus.scl, "both lines high at the end");
            assert_eq!(bus.stops, 1, "{byte:#04x} bit {bit} ends with a stop");
            assert!(bus.falls <= PULSES, "{} pulses", bus.falls);
        }
    }
}

/// A device acknowledging a byte it received lets go on the first pulse.
#[test]
fn a_device_held_on_its_acknowledge_is_freed() {
    let mut bus = Bus::holding(Device::Acking);
    assert!(clock_free(&mut bus));
    assert_eq!(bus.device, Device::Idle);
    assert_eq!(bus.falls, 1);
    assert_eq!((bus.starts, bus.stops), (1, 1));
}

/// A free bus gets a start and a stop and no clock.
#[test]
fn a_free_bus_is_left_free() {
    let mut bus = Bus::holding(Device::Idle);
    assert!(clock_free(&mut bus));
    assert_eq!(bus.falls, 0);
    assert_eq!((bus.starts, bus.stops), (1, 1));
}

/// A part that never lets go is reported after nine pulses, with no stop.
#[test]
fn a_dead_part_is_reported_after_nine_pulses() {
    let mut bus = Bus::holding(Device::Dead);
    assert!(!clock_free(&mut bus));
    assert_eq!(bus.falls, PULSES);
    assert_eq!((bus.starts, bus.stops), (0, 0));
    assert!(bus.scl, "SCL let go at the end");
}

/// The registers, from the GPIO register summary (TRM 6.14.1) and register
/// 6.20: the Waveshare's pins, GPIO47 and 48, in bank 1, and the M5's,
/// GPIO11 and 12, in bank 0.
#[test]
fn the_registers_are_the_manuals() {
    assert_eq!(i2c_bus::bit(48), 1 << 16);
    assert_eq!(i2c_bus::bit(47), 1 << 15);
    assert_eq!(i2c_bus::out_set(48), 0x6000_4014);
    assert_eq!(i2c_bus::out_clear(48), 0x6000_4018);
    assert_eq!(i2c_bus::enable(48), 0x6000_402C);
    assert_eq!(i2c_bus::enable_set(48), 0x6000_4030);
    assert_eq!(i2c_bus::input(48), 0x6000_4040);
    assert_eq!(i2c_bus::out_sel_cfg(47), 0x6000_4610);
    assert_eq!(i2c_bus::out_sel_cfg(48), 0x6000_4614);

    assert_eq!(i2c_bus::bit(12), 1 << 12);
    assert_eq!(i2c_bus::out_set(12), 0x6000_4008);
    assert_eq!(i2c_bus::out_clear(12), 0x6000_400C);
    assert_eq!(i2c_bus::enable(12), 0x6000_4020);
    assert_eq!(i2c_bus::enable_set(12), 0x6000_4024);
    assert_eq!(i2c_bus::input(12), 0x6000_403C);
    assert_eq!(i2c_bus::out_sel_cfg(0), 0x6000_4554);

    assert_eq!(i2c_bus::OUT_SEL_GPIO, 256);
}

/// The two banks meet at 32.
#[test]
fn the_banks_split_at_thirty_two() {
    assert_eq!(i2c_bus::bit(31), 1 << 31);
    assert_eq!(i2c_bus::bit(32), 1);
    assert_eq!(i2c_bus::out_set(31), 0x6000_4008);
    assert_eq!(i2c_bus::out_set(32), 0x6000_4014);
}

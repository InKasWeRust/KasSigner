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

//! The M5 unit, checked without hardware, against the values the unit runs
//! on (power-up sequences, GC0308 tables, backlight mapping, amplifier
//! registers), restated so any change fails; against the board's netlist
//! (`kassigner_hal::expander`, `kassigner_hal::pins`); and against this
//! crate's own rules (a failed read writes nothing, a capture ends at its
//! deadline, a powered-down camera refuses).
//!
//! A fake bus stands in for the I2C devices: it stores what is written,
//! answers reads from it, models the GC0308's page register, and can refuse
//! a read, answer late or be absent.

#![cfg(feature = "m5stack")]

use std::cell::Cell;
use std::collections::HashMap;

use embedded_hal::i2c::{self, ErrorKind, ErrorType, I2c, NoAcknowledgeSource, Operation};
use kassigner_hal::battery::{Battery, Reading};
use kassigner_hal::camera::{Camera, Error as CamError, Power};
use kassigner_hal::card::Kind;
use kassigner_hal::display::Backlight as Level;
use kassigner_hal::input::{Error as TouchError, Event, State, Touch};
use kassigner_hal::speaker::{Note, Speaker as _};
use kassigner_hal::timer::Timer;
use kassigner_hal_esp32s3::m5stack::backlight::{self, M5Backlight};
use kassigner_hal_esp32s3::m5stack::camera::{self, Capture, M5Camera};
use kassigner_hal_esp32s3::m5stack::pmu::{self, Step};
use kassigner_hal_esp32s3::m5stack::sdspi::{self, SdError};
use kassigner_hal_esp32s3::m5stack::touch::{self, M5Touch};
use kassigner_hal_esp32s3::m5stack::{battery, panel, sensor, speaker};
use kassigner_hal_esp32s3::panel::Backlight as _;

// ── The fake bus ────────────────────────────────────────────────────────────

const AXP: u8 = 0x34;
const AW: u8 = 0x58;
const GC: u8 = 0x21;
const FT: u8 = 0x38;
const AMP: u8 = 0x36;

#[derive(Clone, Copy, Debug, PartialEq)]
struct FakeError(ErrorKind);

impl i2c::Error for FakeError {
    fn kind(&self) -> ErrorKind {
        self.0
    }
}

#[derive(Default)]
struct Bus {
    /// `(address, page, register)` to value. Only the GC0308 has pages.
    regs: HashMap<(u8, u8, u8), u8>,
    page: HashMap<u8, u8>,
    pointer: HashMap<u8, u8>,
    absent: Vec<u8>,
    /// Devices that refuse their first few transactions, as a part still
    /// waking on a cold boot does: `(address, refusals left)`.
    late: Vec<(u8, u32)>,
    fail_reads: Vec<(u8, u8)>,
    writes: Vec<(u8, Vec<u8>)>,
}

impl Bus {
    fn page_of(&self, addr: u8) -> u8 {
        if addr == GC {
            *self.page.get(&addr).unwrap_or(&0)
        } else {
            0
        }
    }

    fn set(&mut self, addr: u8, page: u8, reg: u8, val: u8) {
        self.regs.insert((addr, page, reg), val);
    }

    fn get(&self, addr: u8, page: u8, reg: u8) -> u8 {
        *self.regs.get(&(addr, page, reg)).unwrap_or(&0)
    }

    /// Two-byte register writes to one device, in order.
    fn pairs(&self, addr: u8) -> Vec<(u8, u8)> {
        self.writes
            .iter()
            .filter(|(a, b)| *a == addr && b.len() == 2)
            .map(|(_, b)| (b[0], b[1]))
            .collect()
    }

    /// A board as the boot sequence leaves it: GC0308 answering its ID.
    fn board() -> Self {
        let mut bus = Bus::default();
        bus.set(GC, 0, 0x00, sensor::CHIP_ID);
        bus.set(GC, 1, 0x53, 0x83);
        bus.set(AXP, 0, pmu::REG_LDO_EN, pmu::BOOT_RAILS);
        bus.set(AW, 0, 0x03, 0xFF);
        bus
    }
}

impl ErrorType for Bus {
    type Error = FakeError;
}

impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), FakeError> {
        if self.absent.contains(&address) {
            return Err(FakeError(ErrorKind::NoAcknowledge(
                NoAcknowledgeSource::Address,
            )));
        }
        if let Some((_, left)) = self
            .late
            .iter_mut()
            .find(|(a, left)| *a == address && *left > 0)
        {
            *left -= 1;
            return Err(FakeError(ErrorKind::NoAcknowledge(
                NoAcknowledgeSource::Address,
            )));
        }
        for op in operations {
            match op {
                Operation::Write(bytes) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    self.writes.push((address, bytes.to_vec()));
                    let reg = bytes[0];
                    self.pointer.insert(address, reg);
                    if address == GC && reg == 0xFE && bytes.len() == 2 {
                        let page = if bytes[1] == 0x80 { 0 } else { bytes[1] & 1 };
                        self.page.insert(address, page);
                        continue;
                    }
                    let page = self.page_of(address);
                    for (i, &b) in bytes[1..].iter().enumerate() {
                        self.set(address, page, reg.wrapping_add(i as u8), b);
                    }
                }
                Operation::Read(buf) => {
                    let reg = *self.pointer.get(&address).unwrap_or(&0);
                    if self.fail_reads.contains(&(address, reg)) {
                        return Err(FakeError(ErrorKind::Other));
                    }
                    let page = self.page_of(address);
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = self.get(address, page, reg.wrapping_add(i as u8));
                    }
                }
            }
        }
        Ok(())
    }
}

/// A clock that moves only when something waits on it.
#[derive(Default)]
struct FakeTimer {
    now: u64,
}

impl Timer for FakeTimer {
    fn now_us(&self) -> u64 {
        self.now
    }

    fn delay_us(&mut self, us: u32) {
        self.now += us as u64;
    }
}

// ── Power-up sequences ──────────────────────────────────────────────────────

fn writes(steps: &[Step]) -> Vec<(u8, u8)> {
    steps
        .iter()
        .filter_map(|s| match *s {
            Step::Write { reg, val } => Some((reg, val)),
            Step::Wait(_) => None,
        })
        .collect()
}

fn waited_ms(steps: &[Step]) -> u32 {
    steps
        .iter()
        .map(|s| match *s {
            Step::Wait(ms) => ms,
            Step::Write { .. } => 0,
        })
        .sum()
}

/// **The AXP2101 comes up with the board's values:** eleven voltages and
/// settings, 10 ms, the enable register written whole with the backlight
/// off, 50 ms.
#[test]
fn the_rails_come_up_as_the_firmware_brings_them_up() {
    let firmware = [
        Step::Write {
            reg: 0x99,
            val: 0x1C,
        },
        Step::Write {
            reg: 0x92,
            val: 0x0D,
        },
        Step::Write {
            reg: 0x93,
            val: 0x1C,
        },
        Step::Write {
            reg: 0x96,
            val: 0x17,
        },
        Step::Write {
            reg: 0x97,
            val: 0x0A,
        },
        Step::Write {
            reg: 0x94,
            val: 0x1C,
        },
        Step::Write {
            reg: 0x95,
            val: 0x1C,
        },
        Step::Write {
            reg: 0x27,
            val: 0x00,
        },
        Step::Write {
            reg: 0x69,
            val: 0x11,
        },
        Step::Write {
            reg: 0x10,
            val: 0x30,
        },
        Step::Write {
            reg: 0x30,
            val: 0x0F,
        },
        Step::Wait(10),
        Step::Write {
            reg: 0x90,
            val: 0x3F,
        },
        Step::Wait(50),
    ];
    assert_eq!(pmu::AXP_SEQUENCE, firmware);
    assert_eq!(pmu::BOOT_RAILS, 0xBF);
    assert_eq!(pmu::BOOT_RAILS & !pmu::BACKLIGHT, 0x3F);
}

/// **The expander comes up with the board's values.** The two direction
/// bytes make the input lines inputs, and port 0 is released in one write;
/// the 120 ms after it is the amplifier's time to reach standby.
#[test]
fn the_expander_comes_up_with_the_boards_values() {
    let expected = [
        Step::Write {
            reg: 0x7F,
            val: 0x00,
        },
        Step::Wait(20),
        Step::Write {
            reg: 0x11,
            val: 0x10,
        },
        Step::Write {
            reg: 0x13,
            val: 0xFF,
        },
        Step::Write {
            reg: 0x05,
            val: 0x0C,
        }, // TOUCH_INT and AW_INT inputs
        Step::Write {
            reg: 0x12,
            val: 0xFF,
        },
        Step::Write {
            reg: 0x04,
            val: 0x18,
        }, // ES_INT and TF_SW inputs
        Step::Write {
            reg: 0x03,
            val: 0x00,
        },
        Step::Wait(20),
        Step::Write {
            reg: 0x03,
            val: 0x82,
        },
        Step::Wait(50),
        Step::Write {
            reg: 0x03,
            val: 0xFF,
        },
        Step::Wait(10),
        Step::Write {
            reg: 0x02,
            val: 0x00,
        },
        Step::Wait(20),
        Step::Write {
            reg: 0x02,
            val: 0x05,
        }, // TOUCH_RST and AW_RST released
        Step::Wait(120),
    ];
    assert_eq!(pmu::AW_SEQUENCE, expected);
    assert_eq!(
        waited_ms(&pmu::AW_SEQUENCE),
        20 + 20 + 50 + 10 + 20 + 100 + 20
    );
}

/// **The directions are the netlist's, and M5Stack's:** derived from
/// `kassigner_hal::expander::LINES`, not from the constants under test;
/// M5GFX's CoreS3 initialisation writes the same two bytes.
#[test]
fn the_input_lines_are_the_netlists_and_the_vendors() {
    let mut p0 = 0u8;
    let mut p1 = 0u8;
    for line in kassigner_hal::expander::LINES
        .iter()
        .filter(|l| l.is_input())
    {
        let bytes = line.port.as_bytes();
        let bit = 1u8 << (bytes[3] - b'0');
        match bytes[1] {
            b'0' => p0 |= bit,
            b'1' => p1 |= bit,
            _ => panic!("port {}", line.port),
        }
    }
    assert_eq!((pmu::CONFIG_P0, pmu::CONFIG_P1), (p0, p1));
    assert_eq!((pmu::CONFIG_P0, pmu::CONFIG_P1), (0b0001_1000, 0b0000_1100));
}

/// **Every expander line here is the net the netlist puts there.**
#[test]
fn every_expander_line_is_the_netlists() {
    for s in [
        pmu::TOUCH_RST,
        pmu::AW_RST,
        pmu::ES_INT,
        pmu::TF_SW,
        pmu::CAM_RST,
        pmu::LCD_RST,
        pmu::TOUCH_INT,
        pmu::AW_INT,
        pmu::BOOST_EN,
    ] {
        let port = format!("P{}_{}", s.port, s.bit);
        let line = kassigner_hal::expander::by_port(&port).expect("line on the schematic");
        assert_eq!(line.net, s.net, "{port}");
    }
    // `P0_4` is the card switch, not a camera power-down.
    assert_eq!(
        kassigner_hal::expander::by_port("P0_4").unwrap().net,
        "TF_SW"
    );
}

/// **The rails the driver switches are the ones `kassigner_hal::power` names.**
#[test]
fn the_rail_bits_follow_the_rail_names() {
    use kassigner_hal::power;
    let bit = |name: &str| pmu::rail_bit(name).expect(name);

    assert_eq!(pmu::SD_CARD, bit(power::SD_CARD_RAIL));
    assert_ne!(pmu::CAMERA & bit(power::CAMERA_POWER_RAIL), 0);
    for rail in power::CAMERA_RAILS {
        assert_ne!(pmu::CAMERA & bit(rail), 0, "{rail}");
    }
    let backlight = power::RAILS
        .iter()
        .find(|r| r.load == "display backlight")
        .unwrap();
    assert_eq!(pmu::BACKLIGHT, bit(backlight.name));

    // Each LDO has its own bit; the DC-DC converters are not in this register.
    let mut seen = 0u8;
    for rail in power::RAILS {
        match pmu::rail_bit(rail.name) {
            Some(b) => {
                assert_eq!(seen & b, 0, "{} shares a bit", rail.name);
                seen |= b;
            }
            None => assert!(rail.name.starts_with("DCDC"), "{}", rail.name),
        }
    }
    assert_eq!(seen, pmu::BOOT_RAILS);
}

/// **The sequences run as written, and stop at the first refusal.**
#[test]
fn the_sequences_run_as_written_and_stop_at_a_refusal() {
    let mut bus = Bus::board();
    let mut t = FakeTimer::default();
    pmu::init_axp2101(&mut bus, &mut t).unwrap();
    pmu::init_aw9523b(&mut bus, &mut t).unwrap();
    assert_eq!(bus.pairs(AXP), writes(&pmu::AXP_SEQUENCE));
    assert_eq!(bus.pairs(AW), writes(&pmu::AW_SEQUENCE));
    assert_eq!(
        t.now,
        (waited_ms(&pmu::AXP_SEQUENCE) + waited_ms(&pmu::AW_SEQUENCE)) as u64 * 1000
    );

    let mut gone = Bus {
        absent: vec![AXP],
        ..Bus::default()
    };
    assert_eq!(
        pmu::init_axp2101(&mut gone, &mut t),
        Err(pmu::InitError::Axp2101 { reg: 0x99 })
    );
}

/// **A PMU still waking on a cold boot is waited for:** one that refuses a
/// few times and then answers gets the whole sequence, once. One that never
/// answers fails at `0x99`, the first write, as above.
#[test]
fn a_pmu_that_answers_late_is_waited_for() {
    let mut bus = Bus::board();
    bus.late.push((AXP, 3));
    let mut t = FakeTimer::default();
    pmu::init_axp2101(&mut bus, &mut t).unwrap();
    assert_eq!(bus.pairs(AXP), writes(&pmu::AXP_SEQUENCE));
}

/// **A failed read writes nothing:** a rail value built from it would switch
/// off every other rail.
#[test]
fn a_failed_read_writes_nothing() {
    let mut bus = Bus::board();
    bus.fail_reads.push((AXP, pmu::REG_LDO_EN));
    assert!(pmu::set_rails(&mut bus, pmu::SD_CARD, false).is_err());
    assert!(bus.writes.iter().all(|(a, b)| !(*a == AXP && b.len() == 2)));

    let mut bus = Bus::board();
    bus.fail_reads.push((AW, 0x03));
    assert!(pmu::set_output(&mut bus, pmu::CAM_RST, false).is_err());
    assert!(bus.pairs(AW).is_empty());
}

/// **A rail switch leaves the other rails alone.**
#[test]
fn a_rail_switch_leaves_the_other_rails_alone() {
    let mut bus = Bus::board();
    pmu::set_rails(&mut bus, pmu::SD_CARD, false).unwrap();
    assert_eq!(
        bus.get(AXP, 0, pmu::REG_LDO_EN),
        pmu::BOOT_RAILS & !pmu::ALDO4
    );
    pmu::set_rails(&mut bus, pmu::SD_CARD, true).unwrap();
    assert_eq!(bus.get(AXP, 0, pmu::REG_LDO_EN), pmu::BOOT_RAILS);

    // Already where it was asked to be: nothing written.
    let before = bus.writes.len();
    pmu::set_rails(&mut bus, pmu::SD_CARD, true).unwrap();
    assert_eq!(bus.writes.len(), before + 1, "one read, no write");
}

// ── Backlight ───────────────────────────────────────────────────────────────

/// **The level-to-voltage mapping is the board's, for every level.**
#[test]
fn the_backlight_mapping_is_the_firmwares() {
    for level in 0..=255u8 {
        // The mapping, restated.
        let firmware = if level <= 1 {
            0x11
        } else {
            let step = (level as u16 * 11 / 255) as u8;
            0x11 + step.min(11)
        };
        assert_eq!(backlight::code_for(level), firmware, "level {level}");
    }
    assert_eq!(backlight::code_for(255), 0x1C, "3.3 V");
    assert_eq!(pmu::ldo_code(2200), backlight::CODE_MIN);
    assert_eq!(pmu::ldo_code(3300), backlight::CODE_MAX);
}

/// **Off switches the rail off; a level sets the voltage, then the rail.**
#[test]
fn off_is_the_rail_and_a_level_brings_it_back() {
    let mut bus = Bus::board();
    {
        let mut bl = M5Backlight::new(&mut bus);
        bl.set(Level::Off).unwrap();
    }
    assert_eq!(
        bus.get(AXP, 0, pmu::REG_LDO_EN),
        pmu::BOOT_RAILS & !pmu::DLDO1
    );

    bus.writes.clear();
    {
        let mut bl = M5Backlight::new(&mut bus);
        bl.set(Level::Level(128)).unwrap();
    }
    assert_eq!(
        bus.pairs(AXP),
        vec![
            (pmu::REG_DLDO1_V, backlight::code_for(128)),
            (pmu::REG_LDO_EN, pmu::BOOT_RAILS),
        ],
        "voltage first, then the enable"
    );

    // Lit already: the voltage alone, and a read.
    bus.writes.clear();
    {
        let mut bl = M5Backlight::new(&mut bus);
        bl.set(Level::Level(255)).unwrap();
    }
    assert_eq!(bus.pairs(AXP), vec![(pmu::REG_DLDO1_V, 0x1C)]);
}

// ── Touch ───────────────────────────────────────────────────────────────────

/// **A touch lands where the finger is on a panel turned 180 degrees:**
/// `319 - x` and `239 - y`, from the panel size.
#[test]
fn touch_turns_with_the_panel() {
    assert_eq!(panel::SIZE.width, 320);
    assert_eq!(panel::SIZE.height, 240);
    assert_eq!(touch::rotate(0, 0), Some((319, 239)));
    assert_eq!(touch::rotate(319, 239), Some((0, 0)));
    assert_eq!(touch::rotate(100, 50), Some((219, 189)));
}

/// **A report off the panel is dropped, not moved to its edge**, where one
/// stray report would cancel a held press as if the finger had slid off
/// (seen on the M5).
#[test]
fn a_report_off_the_panel_is_dropped() {
    assert_eq!(touch::rotate(320, 100), None, "x past the edge");
    assert_eq!(touch::rotate(100, 240), None, "y past the edge");
    assert_eq!(touch::rotate(0x0FFF, 0x0FFF), None);

    let mut bus = Bus::board();
    // One finger, contact, raw x 0x0FFF: off the panel.
    report(&mut bus, [0x01, 0x8F, 0xFF, 0x00, 50]);
    assert_eq!(M5Touch::new(&mut bus).read(), Ok(State::Idle));
}

fn report(bus: &mut Bus, bytes: [u8; 5]) {
    for (i, b) in bytes.iter().enumerate() {
        bus.set(FT, 0, 0x02 + i as u8, *b);
    }
}

#[test]
fn touch_reads_the_report() {
    let mut bus = Bus::board();

    report(&mut bus, [0x00, 0, 0, 0, 0]);
    assert_eq!(M5Touch::new(&mut bus).read(), Ok(State::Idle));

    // One finger, press down, raw (100, 50).
    report(&mut bus, [0x01, 0x00, 100, 0x00, 50]);
    let state = M5Touch::new(&mut bus).read().unwrap();
    assert_eq!(
        state.first().map(|p| (p.x, p.y, p.event)),
        Some((219, 189, Event::PressDown))
    );

    // Event code 3, "no event", with a finger counted: read as pressed, which
    // the tracker counts once it stays (how the M5 seems to report a held
    // finger).
    // With no finger counted it is nothing.
    report(&mut bus, [0x01, 0xC0, 100, 0x00, 50]);
    let state = M5Touch::new(&mut bus).read().unwrap();
    assert_eq!(
        state.first().map(|p| (p.x, p.y, p.event)),
        Some((219, 189, Event::PressDown))
    );
    report(&mut bus, [0x00, 0xC0, 100, 0x00, 50]);
    assert_eq!(M5Touch::new(&mut bus).read(), Ok(State::Idle));

    // Two fingers.
    report(&mut bus, [0x02, 0x80, 10, 0x00, 20]);
    for (i, b) in [0x40u8, 30, 0x00, 40].iter().enumerate() {
        bus.set(FT, 0, 0x09 + i as u8, *b);
    }
    match M5Touch::new(&mut bus).read().unwrap() {
        State::Two(a, b) => {
            assert_eq!((a.x, a.y, a.event), (309, 219, Event::Contact));
            assert_eq!((b.x, b.y, b.event), (289, 199, Event::LiftUp));
        }
        other => panic!("{other:?}"),
    }

    // A count the controller cannot produce is a garbled report, not a
    // second finger.
    for garbled in [0x03u8, 0x0F] {
        report(&mut bus, [garbled, 0x80, 10, 0x00, 20]);
        assert_eq!(
            M5Touch::new(&mut bus).read(),
            Ok(State::Idle),
            "count {garbled}"
        );
    }
    report(&mut bus, [0x02, 0x80, 10, 0x00, 20]);

    // The second point unreadable: the first stands.
    bus.fail_reads.push((FT, 0x09));
    assert!(matches!(M5Touch::new(&mut bus).read(), Ok(State::One(_))));

    // An absent controller says so.
    let mut gone = Bus {
        absent: vec![FT],
        ..Bus::default()
    };
    assert_eq!(M5Touch::new(&mut gone).read(), Err(TouchError::NotPresent));
    assert_eq!(M5Touch::new(&mut gone).max_contacts(), 2);
}

// ── Battery ─────────────────────────────────────────────────────────────────

#[test]
fn battery_arithmetic_is_the_firmwares() {
    assert_eq!(
        battery::voltage_of(0xCF, 0xA0),
        0x0FA0,
        "top two bits masked"
    );

    let mut bus = Bus::board();
    bus.set(AXP, 0, 0x00, 0x08);
    bus.set(AXP, 0, 0x01, 0x20);
    bus.set(AXP, 0, 0x34, 0x0F);
    bus.set(AXP, 0, 0x35, 0xA0);
    let s = battery::read(&mut bus).unwrap();
    assert_eq!(s.present, Some(true), "the PMU's own bit, as known");
    assert_eq!(s.voltage_mv, 4000);
    assert_eq!(s.percentage, 88);
    assert_eq!(s.state, battery::ChargeState::Charging);
}

// ── SD card ─────────────────────────────────────────────────────────────────

/// **The CRC computes the values the specification fixes:** CMD0's and
/// CMD8's, which the driver sends as constants, and CMD17's widely published
/// one, an outside check on the function that computes the rest.
#[test]
fn the_crc_computes_the_values_the_specification_fixes() {
    assert_eq!(sdspi::crc7(&[0x40, 0, 0, 0, 0]), 0x95);
    assert_eq!(sdspi::crc7(&[0x48, 0, 0, 0x01, 0xAA]), 0x87);
    assert_eq!(sdspi::crc7(&[0x51, 0, 0, 0, 0]), 0x55);
}

/// **The data CRC-16 is the specification's:** the check value of CCITT's
/// polynomial from zero over `123456789`, and the SD specification's own
/// example, 512 bytes of `0xFF`. A wrong function here fails every write.
#[test]
fn the_data_crc_is_the_specifications() {
    assert_eq!(sdspi::crc16(b"123456789"), 0x31C3);
    assert_eq!(sdspi::crc16(&[0xFF; 512]), 0x7FA1);
    assert_eq!(sdspi::crc16(&[0x00; 512]), 0x0000);
    assert_eq!(sdspi::crc16(&[]), 0x0000);
}

#[test]
fn block_addressing() {
    assert_eq!(sdspi::block_addr(Kind::SdV2High, 5), Ok(5));
    assert_eq!(sdspi::block_addr(Kind::SdV2Standard, 5), Ok(2560));
    assert_eq!(sdspi::block_addr(Kind::SdV1, 1), Ok(512));
    assert_eq!(
        sdspi::block_addr(Kind::SdV2Standard, 0x0080_0000),
        Err(SdError::Address)
    );
    assert_eq!(sdspi::block_addr(Kind::SdV2High, u32::MAX), Ok(u32::MAX));
}

/// **The bus pins are the map's, on their bank 1 bits.**
#[test]
fn the_card_pins_are_the_maps() {
    assert_eq!(
        (
            sdspi::PIN_LCD_CS,
            sdspi::PIN_SD_CS,
            sdspi::PIN_MISO,
            sdspi::PIN_SCK,
            sdspi::PIN_MOSI
        ),
        (3, 4, 35, 36, 37)
    );
    // The bits the fast paths drive and read.
    assert_eq!(sdspi::bank1_bit(sdspi::PIN_SCK), 1 << 4);
    assert_eq!(sdspi::bank1_bit(sdspi::PIN_MISO), 1 << 3);
    assert_eq!(sdspi::bank1_bit(sdspi::PIN_MOSI), 1 << 5);
}

// ── Camera sensor ───────────────────────────────────────────────────────────

/// FNV-1a over the pairs.
fn fnv(pairs: &[(u8, u8)]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &(r, v) in pairs {
        for b in [r, v] {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// **The GC0308 tables are the board's, pair for pair:** FNV-1a
/// fingerprints of the tables the unit runs on, so any change fails here.
#[test]
fn the_sensor_tables_are_the_firmwares() {
    assert_eq!(sensor::DEFAULTS.len(), 240);
    assert_eq!(fnv(sensor::DEFAULTS), 0x4377_a1f5_9d39_fc88);
    assert_eq!(sensor::DEFAULTS[0], sensor::SOFT_RESET);
    assert_eq!(
        *sensor::DEFAULTS.last().unwrap(),
        (0xFE, 0x00),
        "ends on page 0"
    );
    assert!(sensor::DEFAULTS.contains(&(0x24, sensor::OUTPUT_Y8)));

    assert_eq!(sensor::SUBSAMPLE_QVGA.len(), 17);
    assert_eq!(fnv(sensor::SUBSAMPLE_QVGA), 0xa7ca_5d24_00f1_6425);
    assert!(sensor::SUBSAMPLE_QVGA.contains(&(0x54, 0x22)));
    assert_eq!(*sensor::SUBSAMPLE_QVGA.last().unwrap(), (0xFE, 0x00));
}

/// **The first bring-up: reset through the expander, then the whole load.**
#[test]
fn the_sensor_comes_up_through_the_expander_and_the_tables() {
    let mut bus = Bus::board();
    let mut t = FakeTimer::default();
    sensor::init(&mut bus, &mut t).unwrap();

    // The reset: CAM_RST low, then high. Nothing else on the expander.
    assert_eq!(bus.pairs(AW), vec![(0x03, 0xFE), (0x03, 0xFF)]);

    // Every write to the sensor, in order.
    let mut expected = vec![(0xFE, 0x00)];
    expected.extend_from_slice(sensor::DEFAULTS);
    expected.extend_from_slice(&[
        (0xFE, 0x01),
        (0x53, 0x83 | 0x80),
        (0x55, 0x01),
        (0xFE, 0x00),
    ]);
    expected.extend_from_slice(sensor::SUBSAMPLE_QVGA);
    expected.extend_from_slice(&[(0x24, sensor::OUTPUT_Y8), (0x46, 0x00)]);
    // The factory values close the load, so they close this list too.
    expected.extend_from_slice(sensor::FACTORY);
    assert_eq!(bus.pairs(GC), expected);

    // 30 held in reset, 30 after, 30 settle, 20 after the soft reset, 80,
    // 100.
    assert_eq!(t.now, (30 + 30 + 30 + 20 + 80 + 100) * 1000);

    let rb = sensor::read_back(&mut bus).unwrap();
    assert!(rb.is_loaded(), "{rb:?}");
}

/// **A failed read in the subsample step stops the load:** taken as zero,
/// it would write `0x80` and clear the rest of the register.
#[test]
fn a_failed_subsample_read_stops_the_load() {
    let mut bus = Bus::board();
    bus.fail_reads.push((GC, 0x53));
    let mut t = FakeTimer::default();
    assert_eq!(
        sensor::load(&mut bus, &mut t),
        Err(sensor::Error::ReadFailed { reg: 0x53 })
    );
    // The tables went in, then the page select, then nothing.
    let mut expected = sensor::DEFAULTS.to_vec();
    expected.push((0xFE, 0x01));
    assert_eq!(bus.pairs(GC), expected);
}

#[test]
fn a_missing_sensor_is_reported() {
    let mut bus = Bus::board();
    bus.set(GC, 0, 0x00, 0x00);
    let mut t = FakeTimer::default();
    assert_eq!(
        sensor::init(&mut bus, &mut t),
        Err(sensor::Error::NotDetected { id: Some(0x00) })
    );
    let mut gone = Bus::board();
    gone.absent.push(GC);
    assert_eq!(
        sensor::init(&mut gone, &mut t),
        Err(sensor::Error::NotDetected { id: None })
    );
}

// ── Camera ──────────────────────────────────────────────────────────────────

/// **The frame is read bottom row first.**
#[test]
fn the_frame_is_upside_down() {
    assert_eq!(camera::source_row(0), camera::FRAME_H - 1);
    assert_eq!(camera::source_row(camera::FRAME_H - 1), 0);
    assert_eq!(camera::FRAME_BYTES, 76_800);
}

/// **The routes are the netlist-checked pins, on the manual's signals**, as
/// the Waveshare map carries them for the same names.
#[test]
fn the_routes_are_the_maps() {
    use kassigner_hal::pins::{m5stack, waveshare};
    let pin = |function: &str| {
        m5stack::CAMERA
            .iter()
            .find(|p| p.function == function)
            .map(|p| p.gpio)
            .expect(function)
    };
    let expected = [
        ("CAM_PCLK", Some(pin("CAM PCLK"))),
        ("CAM_V_SYNC", Some(pin("CAM VSYNC"))),
        ("CAM_H_SYNC", None),
        ("CAM_H_ENABLE", Some(pin("CAM HREF"))),
        ("CAM_DATA_in0", Some(pin("CAM D0"))),
        ("CAM_DATA_in1", Some(pin("CAM D1"))),
        ("CAM_DATA_in2", Some(pin("CAM D2"))),
        ("CAM_DATA_in3", Some(pin("CAM D3"))),
        ("CAM_DATA_in4", Some(pin("CAM D4"))),
        ("CAM_DATA_in5", Some(pin("CAM D5"))),
        ("CAM_DATA_in6", Some(pin("CAM D6"))),
        ("CAM_DATA_in7", Some(pin("CAM D7"))),
    ];
    for (route, (name, gpio)) in camera::ROUTES.iter().zip(expected) {
        assert_eq!(route.name, name);
        assert_eq!(route.gpio, gpio, "{name}");
        let ws = waveshare::CAMERA
            .iter()
            .find(|r| r.name == name)
            .expect(name);
        assert_eq!(route.signal, ws.signal, "{name}");
    }
}

/// A capture that finishes after a set number of polls, or never.
struct FakeCapture {
    done_after: Option<u32>,
    polls: Cell<u32>,
    started: u32,
    aborted: u32,
    frame: Vec<u8>,
}

impl FakeCapture {
    fn new(done_after: Option<u32>, len: usize) -> Self {
        Self {
            done_after,
            polls: Cell::new(0),
            started: 0,
            aborted: 0,
            frame: vec![0x55; len],
        }
    }
}

impl Capture for FakeCapture {
    fn clear(&mut self) {
        self.frame.fill(0);
    }

    fn start(&mut self) -> bool {
        self.started += 1;
        self.polls.set(0);
        true
    }

    fn is_done(&self) -> bool {
        let n = self.polls.get() + 1;
        self.polls.set(n);
        self.done_after.is_some_and(|d| n > d)
    }

    fn abort(&mut self) {
        self.aborted += 1;
    }

    fn finish(&mut self) -> Option<&[u8]> {
        Some(&self.frame)
    }
}

/// **A frame that arrives is lent; one that never does ends at the deadline.**
/// The bound is time; on expiry the partial frame is discarded.
#[test]
fn the_deadline_ends_a_capture_that_never_finishes() {
    let mut bus = Bus::board();
    let mut cam = M5Camera::with_timer(
        FakeCapture::new(Some(3), 76_800),
        &mut bus,
        FakeTimer::default(),
    );
    assert_eq!(
        cam.frame_within(&FakeTimer::default(), 1_000_000)
            .map(|f| f.len()),
        Ok(76_800)
    );

    let mut bus = Bus::board();
    let mut cam = M5Camera::with_timer(
        FakeCapture::new(None, 76_800),
        &mut bus,
        FakeTimer::default(),
    );
    // The deadline is measured against the camera's own clock, which starts
    // at zero and advances 50 µs a poll.
    let deadline = kassigner_hal::timer::Deadline::after(&FakeTimer::default(), 10_000);
    assert_eq!(cam.frame(deadline).err(), Some(CamError::Timeout));
    let (capture, _) = cam.release();
    assert_eq!(capture.aborted, 1);
    assert_eq!(capture.polls.get(), 10_000 / 50 + 1);
}

/// **A frame of the wrong size is refused rather than lent.**
#[test]
fn a_short_frame_is_refused() {
    let mut bus = Bus::board();
    let mut cam = M5Camera::with_timer(
        FakeCapture::new(Some(0), 1000),
        &mut bus,
        FakeTimer::default(),
    );
    assert_eq!(
        cam.frame_within(&FakeTimer::default(), 1_000_000).err(),
        Some(CamError::WrongLength {
            expected: 76_800,
            got: 1000
        })
    );
}

/// **Off is the rails; on is the rails and the sensor again.**
#[test]
fn power_is_the_rails_and_the_sensor_comes_back() {
    let mut bus = Bus::board();
    {
        let mut cam = M5Camera::with_timer(
            FakeCapture::new(Some(0), 76_800),
            &mut bus,
            FakeTimer::default(),
        );
        cam.set_power(Power::Off).unwrap();
        assert_eq!(cam.power(), Power::Off);
        assert_eq!(
            cam.frame_within(&FakeTimer::default(), 1000).err(),
            Some(CamError::PoweredDown)
        );
    }
    assert_eq!(bus.get(AXP, 0, pmu::REG_LDO_EN) & pmu::CAMERA, 0);
    assert_eq!(
        bus.get(AXP, 0, pmu::REG_LDO_EN),
        pmu::BOOT_RAILS & !pmu::CAMERA
    );

    bus.writes.clear();
    {
        let mut cam = M5Camera::with_timer(
            FakeCapture::new(Some(0), 76_800),
            &mut bus,
            FakeTimer::default(),
        );
        cam.set_power(Power::Off).unwrap();
        cam.set_power(Power::On).unwrap();
        assert_eq!(cam.power(), Power::On);
    }
    assert_eq!(bus.get(AXP, 0, pmu::REG_LDO_EN), pmu::BOOT_RAILS);
    // The whole table went back in.
    assert!(bus.pairs(GC).len() > sensor::DEFAULTS.len());
}

// ── Speaker ─────────────────────────────────────────────────────────────────

/// **The amplifier gets M5Unified's CoreS3 values, in order.**
#[test]
fn the_amplifier_gets_the_firmwares_registers() {
    assert_eq!(
        speaker::INIT,
        [
            (0x61, 0x0673),
            (0x04, 0x4040),
            (0x05, 0x0008),
            (0x06, 0x14C8),
            (0x0C, 0x0064)
        ]
    );
    // 48 kHz is index 8 of M5Unified's rate table, OR'd into 0x14C0.
    assert_eq!(0x14C0 | 8, 0x14C8);

    let mut bus = Bus::board();
    bus.set(AMP, 0, 0x00, 0x18);
    bus.set(AMP, 0, 0x01, 0x52);
    let mut t = FakeTimer::default();
    assert_eq!(speaker::init(&mut bus, &mut t), Ok(0x1852));
    let amp: Vec<Vec<u8>> = bus
        .writes
        .iter()
        .filter(|(a, b)| *a == AMP && b.len() == 3)
        .map(|(_, b)| b.clone())
        .collect();
    let expected: Vec<Vec<u8>> = speaker::INIT
        .iter()
        .map(|&(r, v)| vec![r, (v >> 8) as u8, v as u8])
        .collect();
    assert_eq!(amp, expected);
    assert_eq!(t.now, (100 + 50) * 1000);
    // The reset line was set, and nothing else on port 0 moved.
    assert_eq!(
        bus.get(AW, 0, 0x02) & pmu::AW_RST.mask(),
        pmu::AW_RST.mask()
    );

    let mut gone = Bus::board();
    gone.absent.push(AMP);
    assert_eq!(
        speaker::init(&mut gone, &mut t),
        Err(speaker::Error::NotFound)
    );
}

/// **A tone is the HAL's wave, the P4's, and every tone ends in silence.**
#[test]
fn tones_are_the_hal_wave_and_end_silent() {
    let mut buf = [0u8; 64];
    // 12 kHz at 48 kHz is a four-frame period: a sine read at its quarters.
    speaker::fill_tone(&mut buf, 12_000, 1000);
    let frame = |i: usize| i16::from_le_bytes([buf[i * 4], buf[i * 4 + 1]]);
    let right = |i: usize| i16::from_le_bytes([buf[i * 4 + 2], buf[i * 4 + 3]]);
    assert_eq!(
        (0..8).map(frame).collect::<Vec<_>>(),
        [0, 999, 0, -1000, 0, 999, 0, -1000]
    );
    assert!((0..16).all(|i| frame(i) == right(i)), "both channels");

    // The loop joins with no jump: 4 kHz in the ring's 1023 frames is 85
    // whole cycles (3988 Hz), so 85 rising crossings, the join among them,
    // and the step across the join no bigger than any other.
    let mut looped = vec![0u8; 4092];
    speaker::fill_tone(&mut looped, 4000, 1000);
    let at = |i: usize| i32::from(i16::from_le_bytes([looped[i * 4], looped[i * 4 + 1]]));
    let rising = (0..1023)
        .filter(|&i| at(i) < 0 && at((i + 1) % 1023) >= 0)
        .count();
    assert_eq!(rising, 85, "85 whole cycles");
    let widest = (0..1022).map(|i| (at(i + 1) - at(i)).abs()).max().unwrap();
    assert!(
        (at(0) - at(1022)).abs() <= widest + 1,
        "the join is a step like any other"
    );

    // Below 1 kHz the wave carries its third and fifth harmonics, as the
    // P4's does, and still peaks at the note's height.
    let mut low = vec![0u8; 4 * 1023];
    speaker::fill_tone(&mut low, 300, 1000);
    let peak = low
        .chunks(4)
        .map(|f| i16::from_le_bytes([f[0], f[1]]).unsigned_abs())
        .max()
        .unwrap();
    assert!((990..=1000).contains(&peak), "{peak}");

    // Zero hertz is silence, not a division by zero.
    let mut quiet = [0xAAu8; 64];
    speaker::fill_tone(&mut quiet, 0, 1000);
    assert!(quiet.iter().all(|&b| b == 0), "0 Hz fills silence");

    let stream: &'static mut [u8] = Box::leak(vec![0xAAu8; 4 * 4092].into_boxed_slice());
    let mut spk = speaker::M5Speaker::with_timer(stream, FakeTimer::default());
    assert!(
        spk.buffer().iter().all(|&b| b == 0),
        "silent from the start"
    );
    assert_eq!(spk.volume(), speaker::DEFAULT_VOLUME);
    spk.tone(Note::new(4000, 8000, 30));
    spk.silence();
    assert!(spk.buffer().iter().all(|&b| b == 0), "silence is silence");

    // The camera's tick: 2 kHz for 15 ms is 30 whole cycles, 720 frames,
    // a sine from zero to zero, then silence.
    spk.start_ticking(Note::new(2000, 5000, 15));
    let s = |i: usize| i16::from_le_bytes([spk.buffer()[i * 4], spk.buffer()[i * 4 + 1]]);
    let amp = i32::from((5000i32 * speaker::DEFAULT_VOLUME as i32 / speaker::VOLUME_FULL) as i16);
    let top = ((32767 * amp) >> 15) as i16;
    let bottom = ((-32767 * amp) >> 15) as i16;
    assert_eq!((s(0), s(6), s(12), s(18)), (0, top, 0, bottom));
    assert!((720..4092).all(|i| s(i) == 0), "silence after 15 ms");
    spk.stop_ticking();
    assert!(spk.buffer().iter().all(|&b| b == 0));
}

// ── The HAL traits ──────────────────────────────────────────────────────────

/// **The battery trait reads what the free function reads, and a PMU that
/// does not answer is an I/O error.**
#[test]
fn the_battery_trait_is_the_pmu_reading() {
    let mut bus = Bus::board();
    bus.set(AXP, 0, 0x00, 0x08);
    bus.set(AXP, 0, 0x01, 0x40);
    bus.set(AXP, 0, 0x34, 0x0E);
    bus.set(AXP, 0, 0x35, 0x74);
    let direct = battery::read(&mut bus).unwrap();
    let mut cell = battery::M5Battery::new(&mut bus);
    assert_eq!(cell.read(), Ok(Reading::Battery(direct)));
    assert_eq!(direct.voltage_mv, 3700);
    assert_eq!(direct.state, battery::ChargeState::Discharging);

    let mut gone = Bus {
        absent: vec![AXP],
        ..Bus::board()
    };
    assert_eq!(
        battery::M5Battery::new(&mut gone).read(),
        Err(kassigner_hal::battery::Error::Io)
    );
}

/// **A note takes as long as it says and leaves the stream playing; silence
/// stops it.** Which notes make which cue is `kassigner-fw`'s, tested there.
#[test]
fn a_note_lasts_its_milliseconds() {
    let stream: &'static mut [u8] = Box::leak(vec![0u8; 4 * 1024].into_boxed_slice());
    let mut spk = speaker::M5Speaker::with_timer(stream, FakeTimer::default());

    spk.tone(Note::new(1000, 6000, 40));
    assert_eq!(spk.timer().now_us(), 40_000);
    assert!(
        spk.buffer().iter().any(|&b| b != 0),
        "a tone leaves the stream playing"
    );

    spk.tone(Note::rest(50));
    assert_eq!(spk.timer().now_us(), 90_000, "a rest takes its time too");
    assert!(spk.buffer().iter().all(|&b| b == 0), "a rest is silence");

    spk.tone(Note::new(2000, 6000, 10));
    spk.silence();
    assert_eq!(spk.timer().now_us(), 100_000);
    assert!(spk.buffer().iter().all(|&b| b == 0));

    // A note rises and falls a quarter at a time, and ends on its lowest
    // step: the next note or the silence after it starts from a quarter of
    // the height, not from full.
    spk.tone(Note::new(1000, 6000, 40));
    assert_eq!(spk.timer().now_us(), 140_000, "the ramp is inside the note");
    let peak = spk
        .buffer()
        .chunks(4)
        .map(|f| i16::from_le_bytes([f[0], f[1]]).unsigned_abs())
        .max()
        .unwrap();
    let full = (6000i32 * speaker::DEFAULT_VOLUME as i32 / speaker::VOLUME_FULL) as u16;
    assert!(
        (full / 4 - 1..=full / 4).contains(&peak),
        "left at a quarter: {peak}"
    );
}

/// **The M5 states the capacity `kassigner-fw` is sized for, and its profile
/// is the S3 profile.**
#[test]
fn the_m5_capacity_is_the_firmwares() {
    use kassigner_hal_esp32s3::m5stack::{CAPACITY, PROFILE};
    use kassigner_protocol::profile::Profile;
    assert_eq!(PROFILE, Profile::ESP32S3);
    assert_eq!(CAPACITY.display_bytes(), 14_397);
    assert_eq!(CAPACITY.frames * CAPACITY.bytes_per_frame, 16_384);
}

// ── Tuning ──────────────────────────────────────────────────────────────────

/// The tuner moves the datasheet's page-0 registers, holds exposure's high
/// part and the global gain to their widths, and flips only the exposure
/// loop's switch bit.
#[test]
fn the_tuner_moves_the_datasheet_registers() {
    use kassigner_hal::tune::Tune;
    let mut bus = Bus::board();
    // Page 1 holds something else at the same addresses.
    bus.set(GC, 1, 0xD3, 0x11);
    bus.page.insert(GC, 1);
    // The factory values: the tables' own and, for what they do not write,
    // the datasheet's.
    for (reg, val) in [(0xD3, 0x38), (0x03, 0x00), (0x04, 0x96), (0x50, 0x14)] {
        bus.set(GC, 0, reg, val);
    }
    for (reg, val) in [(0x51, 0x40), (0xB3, 0x50), (0xB5, 0x00), (0x77, 0x38)] {
        bus.set(GC, 0, reg, val);
    }
    bus.set(GC, 0, 0xD2, 0x90);

    let mut t = sensor::Tuner::new(&mut bus);
    let labels: Vec<_> = t.knobs().iter().map(|k| k.label).collect();
    assert_eq!(
        labels,
        ["AEC-Y", "EXPO-H", "EXPO-L", "GAIN", "PREGN", "CONTR", "SHARP"],
        "the luma offset is off the screen"
    );
    let mut v = [0u8; 7];
    t.read(&mut v).unwrap();
    assert_eq!(v, [0x38, 0x00, 0x96, 0x14, 0x40, 0x50, 0x38]);
    // What the tables leave in the settings the loop does not write, AEC-Y,
    // CONTR and SHARP, sits on each knob's grid: minus and plus can always
    // bring it back.
    for i in [0, 5, 6] {
        let k = t.knobs()[i];
        assert_eq!(k.snap(v[i]), v[i], "{}", k.label);
    }
    assert_eq!(t.auto(), Some(true));

    t.write(0, 0x60).unwrap();
    t.write(1, 0xFF).unwrap();
    t.write(3, 0xFF).unwrap();
    t.write(6, 0x55).unwrap();
    t.set_auto(false).unwrap();
    assert_eq!(t.auto(), Some(false));
    assert!(t.write(7, 0).is_err(), "no eighth knob");

    assert_eq!(bus.get(GC, 0, 0xD3), 0x60);
    assert_eq!(bus.get(GC, 0, 0x03), 0x0F, "exposure 11:8 is four bits");
    assert_eq!(bus.get(GC, 0, 0x50), 0x3F, "global gain is six bits");
    assert_eq!(bus.get(GC, 0, 0x77), 0x55);
    assert_eq!(bus.get(GC, 0, 0xD2), 0x10, "only AEC_en cleared");
    assert_eq!(bus.get(GC, 1, 0xD3), 0x11, "page 1 untouched");
}

/// Everything the tuner can write is put back by a load, by the tables or by
/// `sensor::FACTORY`, since the sensor keeps its registers past a soft reset.
#[test]
fn a_load_rewrites_every_tuned_register() {
    use kassigner_hal::tune::Tune;
    let mut bus = Bus::board();
    let mut t = sensor::Tuner::new(&mut bus);
    for k in 0..7 {
        t.write(k, 0xAA).unwrap();
    }
    t.set_auto(false).unwrap();
    let mut timer = FakeTimer::default();
    sensor::load(&mut bus, &mut timer).unwrap();
    // The factory values of what the tables do not write.
    for (reg, val) in [(0x03, 0x00), (0x04, 0x96), (0x51, 0x40), (0xB5, 0x00)] {
        assert_eq!(bus.get(GC, 0, reg), val, "{reg:#04x}");
    }
    // And the tables' own last value for the rest: the exposure target,
    // gain, contrast, edge, and the exposure loop's switch.
    for reg in [0xD3u8, 0x50, 0xB3, 0x77, 0xD2] {
        let mut page = 0;
        let mut want = None;
        for &(r, v) in sensor::DEFAULTS {
            if r == 0xFE {
                page = if v == 0x80 { 0 } else { v & 1 };
            } else if r == reg && page == 0 {
                want = Some(v);
            }
        }
        let want = want.expect("in the tables, on page 0");
        assert_eq!(bus.get(GC, 0, reg), want, "{reg:#04x}");
    }
}

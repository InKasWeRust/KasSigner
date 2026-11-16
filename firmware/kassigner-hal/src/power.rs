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

//! The M5's AXP2101 power rails (`Sch_M5_CoreS3_v1_0.pdf`, page 1): part
//! `U1`, I2C address `0x34`.
//!
//! The table comes from the drawing's rail legend and pin connections, a
//! weaker source than a netlist, whose supply nets are large multi-pin
//! groups that a mechanical parse merges into each other. A netlist read
//! confirmed four entries independently: [`PWROK_NET`], the I2C pins, the
//! charge LED and the power key.
//!
//! # The one piece of sequencing the board enforces
//!
//! `PWROK` drives `AXP_PG`, which drives the AW9523B's `RSTN`: the expander
//! is held in reset, in hardware, until the PMU says the rails are up. The
//! rest of the ordering is the S3 crate's `m5stack::pmu`.

/// I2C address.
pub const ADDRESS: u8 = 0x34;

/// The net `PWROK` drives, to the AW9523B's `RSTN`; confirmed from both ends
/// of the netlist.
pub const PWROK_NET: &str = "AXP_PG";

/// A rail and what it feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rail {
    /// The rail's name in the datasheet and in the S3 crate's `m5stack::pmu`.
    pub name: &'static str,
    /// Its net on the schematic.
    pub net: &'static str,
    /// What it powers: the legend's word, unless its net says otherwise
    /// (`ALDO3`).
    pub load: &'static str,
    /// Millivolts: the legend's, unless the firmware writes another (`BLDO2`).
    pub millivolts: u32,
}

/// Every rail this board uses.
///
/// `DCDC2`, `DCDC4`, `DLDO2/DC4SW`, `CPULDOS` and `GPIO1` are marked
/// unconnected on the drawing and are absent here.
pub const RAILS: &[Rail] = &[
    Rail {
        name: "DCDC1",
        net: "VDD_3V3",
        load: "core VDD",
        millivolts: 3300,
    },
    Rail {
        name: "DCDC3",
        net: "VCC_3V3",
        load: "peripherals VDD",
        millivolts: 3300,
    },
    Rail {
        name: "DLDO1",
        net: "VCC_BL",
        load: "display backlight",
        millivolts: 3300,
    },
    Rail {
        name: "ALDO1",
        net: "VDD_1V8",
        load: "AW88298 amplifier DVDD",
        millivolts: 1800,
    },
    Rail {
        name: "ALDO2",
        net: "VDDA_3V3",
        load: "codec VDDP",
        millivolts: 3300,
    },
    Rail {
        name: "ALDO3",
        net: "VDDCAM_3V3",
        load: "camera 3V3 and its oscillator",
        millivolts: 3300,
    },
    Rail {
        name: "ALDO4",
        net: "VDD_3V3_SD",
        load: "SD card VDD",
        millivolts: 3300,
    },
    Rail {
        name: "BLDO1",
        net: "AVDD",
        load: "camera sensor VDDA",
        millivolts: 2800,
    },
    Rail {
        name: "BLDO2",
        net: "DVDD",
        load: "camera connector DVDD, not a GC0308 supply",
        millivolts: 1500,
    },
];

/// Rails whose legend and net disagree, unresolved: none. `ALDO3`'s legend
/// says codec and microphone analogue supply, but its net, `VDDCAM_3V3`,
/// goes on page 5 to the camera connector `J2` and the 20 MHz oscillator
/// `X2`: the legend is stale, and it is the camera's [`CAMERA_POWER_RAIL`].
pub const AMBIGUOUS: &[&str] = &[];

/// The rail that powers the camera down.
///
/// `CAM_PWDN` reaches only the camera connector and a resistor, out of reach
/// of the ESP32 and the expander. `ALDO3` feeds both the sensor's 3.3 V and
/// `X2`, the oscillator that generates `CAM_MCLK`: gating it removes supply
/// and clock together, a harder stop than `PWDN`. After a scan the camera
/// can be switched off, not merely idled, with one register write.
pub const CAMERA_POWER_RAIL: &str = "ALDO3";

/// Look a rail up by name.
pub fn by_name(name: &str) -> Option<&'static Rail> {
    RAILS.iter().find(|r| r.name == name)
}

/// The rail that powers the SD card, named because the M5's storage driver
/// power-cycles it before each card access.
pub const SD_CARD_RAIL: &str = "ALDO4";

/// The two rails on the camera connector besides `ALDO3`: `BLDO1` at 2.8 V
/// and `BLDO2` at 1.5 V, brought up before the sensor is addressed.
///
/// `BLDO2` is 1.5 V, what the firmware writes and the unit runs on; the
/// legend says 1.2 V. Neither can be a sensor supply: the GC0308 datasheet
/// M5Stack publishes for this board gives one supply pin, `DVDD28`, at 2.7
/// to 3.3 V; the core voltage is made inside. A sensor fed 1.5 V on its only
/// supply would not run, and this one does.
pub const CAMERA_RAILS: [&str; 2] = ["BLDO1", "BLDO2"];

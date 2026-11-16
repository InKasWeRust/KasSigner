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

//! The M5's AW9523B I/O expander, from `Sch_M5_CoreS3_v1_0.pdf`: part
//! `U10`, I2C address `0x58`.
//!
//! On the Waveshare the display reset is a GPIO. Here `LCD_RST`, `CAM_RST`,
//! `TOUCH_RST`, `TOUCH_INT` and the audio amplifier's reset are expander
//! lines, reached only over I2C, so a wrong bit fails unnoticed: it writes
//! to another wire, where a wrong GPIO usually breaks something visibly.
//!
//! Four lines are inputs: the touch and amplifier interrupts, the codec
//! interrupt, and the SD card-detect switch. `P0` is push-pull, so `P0_4`
//! set as an output would drive the same wire as a mechanical switch; see
//! [`Line::is_input`].

/// A line on the expander.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// Package pin.
    pub pin: u8,
    /// Port bit, as the datasheet names it.
    pub port: &'static str,
    /// The net on the schematic.
    pub net: &'static str,
    /// What it does.
    pub function: &'static str,
}

impl Line {
    /// Whether the board drives this line into the expander. An input
    /// configured as an output is two drivers on one wire.
    pub fn is_input(&self) -> bool {
        // Not `const`: a const fn cannot match on `&str`, and comparing bytes
        // would obscure the list.
        matches!(self.net, "TOUCH_INT" | "AW_INT" | "ES_INT" | "TF_SW")
    }
}

/// I2C address, set by the `AD0` and `AD1` strap pins.
pub const ADDRESS: u8 = 0x58;

/// What drives the expander's `RSTN`: `AXP_PG`, the AXP2101's power-good
/// signal, so the part stays in reset until the rails are up. The one piece
/// of power sequencing the board does in hardware.
pub const RESET_SOURCE: &str = "AXP_PG";

/// Every line that resolves to a net in the schematic. `P0_6`, `P0_7`,
/// `P1_4`, `P1_5` and `P1_6` fall in the export's no-connect group and are
/// left out: absent means unknown, not unconnected.
pub const LINES: &[Line] = &[
    Line {
        pin: 1,
        port: "P1_0",
        net: "CAM_RST",
        function: "camera reset",
    },
    Line {
        pin: 2,
        port: "P1_1",
        net: "LCD_RST",
        function: "display reset, active low",
    },
    Line {
        pin: 3,
        port: "P1_2",
        net: "TOUCH_INT",
        function: "touch interrupt, an input",
    },
    Line {
        pin: 4,
        port: "P1_3",
        net: "AW_INT",
        function: "amplifier interrupt, an input",
    },
    Line {
        pin: 5,
        port: "P0_0",
        net: "TOUCH_RST",
        function: "touch reset, active low",
    },
    Line {
        pin: 6,
        port: "P0_1",
        net: "BUS_OUT_EN",
        function: "external bus output enable",
    },
    Line {
        pin: 7,
        port: "P0_2",
        net: "AW_RST",
        function: "AW88298 reset, active low",
    },
    Line {
        pin: 8,
        port: "P0_3",
        net: "ES_INT",
        function: "ES7210 interrupt, an input",
    },
    Line {
        pin: 10,
        port: "P0_4",
        net: "TF_SW",
        function: "SD card detect switch, an input",
    },
    Line {
        pin: 11,
        port: "P0_5",
        net: "USB_OTG_EN",
        function: "USB OTG enable",
    },
    Line {
        pin: 17,
        port: "P1_7",
        net: "BOOST_EN",
        function: "SY7088 boost enable, PVDD",
    },
];

/// Look a line up by its port bit.
pub fn by_port(port: &str) -> Option<&'static Line> {
    LINES.iter().find(|l| l.port == port)
}

/// Nets wrongly attributed to this part. `P0_4` is `TF_SW`, not `CAM_PWDN`,
/// which reaches only the camera connector and a resistor, so neither the
/// expander nor the ESP32 can drive it. The camera is stopped by gating the
/// `ALDO3` rail, which feeds the sensor's 3.3 V and its clock oscillator
/// ([`crate::power::CAMERA_POWER_RAIL`]).
pub const NOT_ON_THIS_PART: &[&str] = &["CAM_PWDN"];

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

//! The M5's expander map against the schematic. An expander bit is a fact
//! like a pin number, but a wrong one fails unnoticed: it writes to another
//! wire.

use kassigner_hal::expander::{by_port, ADDRESS, LINES, NOT_ON_THIS_PART, RESET_SOURCE};

/// The address matches the schematic's note.
#[test]
fn the_address_matches() {
    assert_eq!(ADDRESS, 0x58);

    // A constant, so checked at build time as well.
    const _: () = assert!(
        ADDRESS >= 0x08 && ADDRESS < 0x78,
        "the address must be a usable 7-bit address"
    );
}

/// The output lines the power-on sequence drives are outputs, on the nets
/// it expects. (`BOOST_EN` comes up before the amplifier leaves reset: the
/// `AW88298` needs PVDD stable first.)
#[test]
fn the_output_lines_the_firmware_drives_are_correct() {
    for (port, net) in [
        ("P0_0", "TOUCH_RST"),
        ("P0_2", "AW_RST"),
        ("P0_5", "USB_OTG_EN"),
        ("P1_1", "LCD_RST"),
        ("P1_7", "BOOST_EN"),
    ] {
        let l = by_port(port).unwrap_or_else(|| panic!("{port} is not in the map"));
        assert_eq!(l.net, net, "{port}");
        assert!(!l.is_input(), "{port} is an output");
    }
}

/// `P0_4` is `TF_SW`, the microSD connector's card-detect switch with a 10K
/// pull-up to 3V3, not the camera power-down. It is an input: `GCR = 0x10`
/// makes `P0` push-pull, so as an output it would drive the switch's wire.
/// `CAM_PWDN` reaches only the camera connector and a resistor; the sensor
/// is powered down by gating its rail instead.
#[test]
fn p0_4_is_the_card_detect_switch() {
    let l = by_port("P0_4").expect("in the map");
    assert_eq!(l.net, "TF_SW");
    assert!(l.is_input(), "the board drives this line into the expander");
    assert!(
        NOT_ON_THIS_PART.contains(&"CAM_PWDN"),
        "CAM_PWDN is elsewhere entirely"
    );
}

/// Four lines are inputs: the touch, amplifier and codec interrupts and the
/// card-detect switch. Configured as outputs, each would share its wire with
/// an expander driver.
#[test]
fn four_lines_are_inputs() {
    let inputs: Vec<&str> = LINES
        .iter()
        .filter(|l| l.is_input())
        .map(|l| l.net)
        .collect();
    assert_eq!(inputs, vec!["TOUCH_INT", "AW_INT", "ES_INT", "TF_SW"]);

    // Two are on P0, which is push-pull.
    let p0_inputs: Vec<&str> = LINES
        .iter()
        .filter(|l| l.is_input() && l.port.starts_with("P0"))
        .map(|l| l.net)
        .collect();
    assert_eq!(p0_inputs, vec!["ES_INT", "TF_SW"]);
}

/// The expander is held in reset by the PMU: `RSTN` comes from `AXP_PG`,
/// the AXP2101's power-good output.
#[test]
fn the_expander_is_released_by_the_pmu() {
    assert_eq!(RESET_SOURCE, "AXP_PG");
    assert!(
        !LINES.iter().any(|l| l.net == "AXP_PG"),
        "AXP_PG drives RSTN, it is not one of the port lines"
    );
}

/// Every line names a distinct port bit and a distinct net.
#[test]
fn the_map_is_consistent() {
    let mut ports: Vec<&str> = LINES.iter().map(|l| l.port).collect();
    let n = ports.len();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), n, "two lines claim one port bit");

    let mut nets: Vec<&str> = LINES.iter().map(|l| l.net).collect();
    nets.sort_unstable();
    nets.dedup();
    assert_eq!(nets.len(), n, "two lines claim one net");

    for l in LINES {
        assert!(
            l.port.starts_with("P0_") || l.port.starts_with("P1_"),
            "{}",
            l.port
        );
        assert!((1..=17).contains(&l.pin), "{} is not a port pin", l.pin);
        assert!(!l.function.is_empty(), "{} has no function", l.port);
    }
}

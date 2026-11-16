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

//! The rail map against the firmware: the rails the M5's PMU driver enables
//! by a bit mask, and the one its storage driver power-cycles before each
//! card access.
//!
//! The map comes from the drawing's rail legend, weaker than its netlist:
//! these tests catch a firmware rail name that does not exist and a load on
//! the wrong rail, not a stale legend (one entry is known to be).

use kassigner_hal::power::{
    by_name, ADDRESS, AMBIGUOUS, CAMERA_POWER_RAIL, CAMERA_RAILS, PWROK_NET, RAILS, SD_CARD_RAIL,
};

/// The AXP2101's I2C address.
#[test]
fn the_address_matches() {
    assert_eq!(ADDRESS, 0x34);
}

/// Every rail the firmware enables exists on this board. The boot mask
/// covers `ALDO1` to `ALDO4`, `BLDO1`, `BLDO2` and `DLDO1`; a name in it that
/// is not a rail here would be a bit written at nothing.
#[test]
fn every_rail_the_firmware_enables_exists() {
    for name in [
        "ALDO1", "ALDO2", "ALDO3", "ALDO4", "BLDO1", "BLDO2", "DLDO1",
    ] {
        assert!(
            by_name(name).is_some(),
            "{name} is enabled by m5stack::pmu and is not on the board"
        );
    }
}

/// The SD card rail is `ALDO4`, the one the card driver power-cycles: any
/// other would take down something else and leave the card powered.
#[test]
fn the_sd_rail_is_the_one_the_driver_cycles() {
    let r = by_name(SD_CARD_RAIL).expect("in the map");
    assert_eq!(r.name, "ALDO4");
    assert!(r.load.contains("SD card"), "ALDO4 feeds {}", r.load);
    assert_eq!(r.millivolts, 3300);
}

/// Both camera connector rails are in the table at the voltages the firmware
/// writes, `BLDO1` at 2.8 V and `BLDO2` at 1.5 V (`CAMERA_RAILS` says why
/// not the legend's 1.2 V).
#[test]
fn the_camera_needs_both_of_its_rails() {
    let v: Vec<u32> = CAMERA_RAILS
        .iter()
        .map(|n| by_name(n).unwrap_or_else(|| panic!("{n}")).millivolts)
        .collect();
    assert_eq!(
        v,
        vec![2800, 1500],
        "BLDO1 then BLDO2, as the firmware writes them"
    );

    for n in CAMERA_RAILS {
        assert!(by_name(n).unwrap().load.contains("camera"), "{n}");
    }
}

/// The expander is released by the PMU, in hardware: `PWROK` drives
/// `AXP_PG`, which drives the AW9523B's `RSTN`, so the expander is never
/// addressed before its rails are up.
#[test]
fn the_pmu_releases_the_expander() {
    assert_eq!(PWROK_NET, "AXP_PG");
    assert_eq!(kassigner_hal::expander::RESET_SOURCE, PWROK_NET);
}

/// Rails are distinct, and their voltages are sane.
#[test]
fn the_map_is_consistent() {
    let mut names: Vec<&str> = RAILS.iter().map(|r| r.name).collect();
    let n = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), n, "two entries claim one rail");

    let mut nets: Vec<&str> = RAILS.iter().map(|r| r.net).collect();
    nets.sort_unstable();
    nets.dedup();
    assert_eq!(nets.len(), n, "two rails claim one net");

    for r in RAILS {
        assert!(
            (1000..=3600).contains(&r.millivolts),
            "{}: {} mV",
            r.name,
            r.millivolts
        );
        assert!(!r.load.is_empty(), "{} has no load", r.name);
    }
}

/// The camera powers down over a rail, not a pin (`CAM_PWDN` is out of
/// software's reach): `ALDO3` feeds the sensor's 3.3 V *and* `X2`, the
/// oscillator that generates `CAM_MCLK`. Its legend calls it the codec and
/// microphone analogue supply, which is stale, hence this test names both
/// the rail and what it feeds.
#[test]
fn the_camera_is_powered_down_by_a_rail_not_a_pin() {
    assert!(
        AMBIGUOUS.is_empty(),
        "ALDO3 was the only ambiguity and it is resolved"
    );

    let r = by_name(CAMERA_POWER_RAIL).expect("in the map");
    assert_eq!(r.name, "ALDO3");
    assert_eq!(r.net, "VDDCAM_3V3");
    assert!(r.load.contains("camera"), "ALDO3 feeds {}", r.load);
    assert!(
        r.load.contains("oscillator"),
        "and the clock, which is the point"
    );

    // Distinct from the connector's other two rails, `BLDO1` and `BLDO2`:
    // this is the module's 3.3 V and its clock source.
    assert!(!CAMERA_RAILS.contains(&CAMERA_POWER_RAIL));
}

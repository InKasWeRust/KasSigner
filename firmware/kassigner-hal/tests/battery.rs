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

//! The battery trait, used the way shared code will use it.

use kassigner_hal::battery::{Battery, BatteryStatus, ChargeState, Error, Reading};

struct Fixed(Result<Reading, Error>);

impl Battery for Fixed {
    fn read(&mut self) -> Result<Reading, Error> {
        self.0
    }
}

/// What a screen does with each of the three outcomes.
fn label(b: &mut dyn Battery) -> &'static str {
    match b.read() {
        Ok(Reading::Battery(s)) if s.present == Some(false) => "no battery",
        Ok(Reading::Battery(s)) if s.present.is_none() => "a level, or no battery",
        Ok(Reading::Battery(_)) => "battery",
        Ok(Reading::Implausible { .. }) => "cannot read",
        Err(Error::Io) => "error",
    }
}

/// **A reading, an unreadable converter, and a failed read are three different
/// things, a missing cell is a fourth, and a board that cannot tell whether a
/// cell is there a fifth.**
#[test]
fn the_outcomes_stay_distinct() {
    let cell = |present| BatteryStatus {
        present,
        voltage_mv: 3900,
        percentage: 78,
        state: ChargeState::Unknown,
    };
    assert_eq!(
        label(&mut Fixed(Ok(Reading::Battery(cell(Some(true)))))),
        "battery"
    );
    assert_eq!(
        label(&mut Fixed(Ok(Reading::Battery(cell(Some(false)))))),
        "no battery"
    );
    assert_eq!(
        label(&mut Fixed(Ok(Reading::Battery(cell(None))))),
        "a level, or no battery"
    );
    assert_eq!(
        label(&mut Fixed(Ok(Reading::Implausible { raw: 12 }))),
        "cannot read"
    );
    assert_eq!(label(&mut Fixed(Err(Error::Io))), "error");
}

/// **The AXP2101's percentage is linear between its two ends and held at
/// them outside, and its direction is bits 6:5 alone,** for the M5 and the
/// P4 alike.
#[test]
fn the_axp2101_reading_is_the_firmwares() {
    use kassigner_hal::battery::axp2101::{percent_for, state_of};

    assert_eq!(percent_for(3000), 0);
    assert_eq!(percent_for(3200), 0);
    assert_eq!(percent_for(3650), 50);
    assert_eq!(percent_for(4099), 99);
    assert_eq!(percent_for(4100), 100);
    assert_eq!(percent_for(4200), 100);

    assert_eq!(state_of(0b0010_0000), ChargeState::Charging);
    assert_eq!(state_of(0b0100_0000), ChargeState::Discharging);
    assert_eq!(state_of(0b0110_0000), ChargeState::Unknown);
    assert_eq!(
        state_of(0b1000_0000),
        ChargeState::Unknown,
        "bit 7 is not read"
    );
}

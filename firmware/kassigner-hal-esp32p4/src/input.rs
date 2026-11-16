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

//! The touch controller behind `kassigner-hal`'s `Touch`: polled, it
//! reports the finger while it is there and nothing once it is gone, like
//! the M5's FT6336. A failed read is an error: taken for an idle panel, it
//! would end a touch under a finger.
//!
//! [`Edges`] makes the events from the points: `PressDown` at the first,
//! `Contact` while the finger stays, `LiftUp` at the last on the first read
//! without one, as the S3 units' controllers report them. A tap the loop
//! reads only once, as the P4's often are, is a `PressDown` then its
//! `LiftUp` at the same point, which `kassigner_fw::touch::Tracker`
//! confirms on the second report.

use kassigner_hal::input::{Edges, Error, State, Touch};

use crate::cam::SharedBus;
use crate::drivers::touch;

/// The touch controller as the flow sees it. It borrows the bus on every
/// read, since the sensor and the PMU sit on it too.
pub struct P4Touch {
    driver: touch::Touch<'static>,
    bus: &'static SharedBus,
    /// Makes the press and the lift from the finger's place, read by read.
    edges: Edges,
}

impl P4Touch {
    /// Over a probed driver and the shared bus.
    pub fn new(driver: touch::Touch<'static>, bus: &'static SharedBus) -> Self {
        Self {
            driver,
            bus,
            edges: Edges::new(),
        }
    }
}

impl Touch for P4Touch {
    fn read(&mut self) -> Result<State, Error> {
        let mut bus = self.bus.try_borrow_mut().map_err(|_| Error::Io)?;
        let at = self.driver.read_screen(&mut bus).map_err(|_| Error::Io)?;
        Ok(self.edges.read(at.map(|p| (p.x, p.y))))
    }
}

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

//! The system timer behind `kassigner-hal`'s `Timer`, over esp-hal's clock.

use esp_hal::delay::Delay;
use esp_hal::time::Instant;
use kassigner_hal::timer::Timer;

/// A unit type: the clock is the chip's.
#[derive(Clone, Copy, Debug, Default)]
pub struct SysTimer;

impl Timer for SysTimer {
    fn now_us(&self) -> u64 {
        Instant::now().duration_since_epoch().as_micros()
    }

    fn delay_us(&mut self, us: u32) {
        Delay::new().delay_micros(us);
    }
}

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

//! The LP watchdog, armed for the program's life.
//!
//! `esp_hal::init` turns every watchdog off, so a main loop hung on a stuck
//! bus or a silent camera would hold what it held, a seed included, until
//! the battery ran out. Armed, the LP watchdog (the P4's RTC watchdog)
//! resets the whole chip when the loop has not fed it within its timeout,
//! and the boot after clears PSRAM and the main stack before anything runs
//! (`stack::clear_at_boot`, `psram::clear`).
//!
//! It is the watchdog the second-stage bootloader arms and
//! [`crate::soc::watchdog`] turns off before esp-hal's init, armed again
//! through esp-hal's driver. Stage 0 resets the system, peripherals and
//! cores, from the LP domain's own clock. A panic halts with it counting,
//! so a panicked unit restarts at the timeout, and that boot clears what the
//! panic's wipe leaves.

use esp_hal::peripherals::RTC_TIMER;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::time::Duration;

/// The watchdog, counting. Feed it at least once per timeout.
pub struct Watchdog {
    rtc: Rtc<'static>,
}

impl Watchdog {
    /// Arm the LP watchdog to reset the chip after `seconds` unfed, and feed
    /// it once. Once, after bring-up: a second would take the same timer.
    pub fn arm(seconds: u64) -> Self {
        // SAFETY: `RTC_TIMER` is taken here only: the unit's bring-up does
        // not take it, and esp-hal's init and time driver use other timers.
        // `Rtc` names only the LP timer's registers and the watchdog's.
        let mut rtc = Rtc::new(unsafe { RTC_TIMER::steal() });
        rtc.rwdt
            .set_timeout(RwdtStage::Stage0, Duration::from_secs(seconds));
        rtc.rwdt.enable();
        rtc.rwdt.feed();
        Self { rtc }
    }

    /// Start the timeout again.
    pub fn feed(&mut self) {
        self.rtc.rwdt.feed();
    }
}

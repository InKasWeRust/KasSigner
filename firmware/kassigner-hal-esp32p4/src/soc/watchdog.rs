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

//! Bootloader watchdog.
//!
//! `esp_hal::init()` disables the LP watchdog the second-stage bootloader
//! leaves armed; until it runs, a hang shows as a reboot loop, not a hang.
//! Call this first in `main`, before anything that could block.
//!
//! `config` is `[CONFIG; 4]` in the PAC, so `wprotect` is at +0x18, not the
//! +0x0c a single-register layout would suggest.

//! Through the `esp32p4` PAC: `LP_WDT.config0` `wdt_en` b31 /
//! `wdt_flashboot_mod_en` b12, `wprotect.wdt_wkey`, matching the offsets
//! that ran on this silicon.

use esp32p4::LP_WDT;

/// The unlock key, from the TRM.
const WKEY: u32 = 0x50D8_3AA1;

/// Turn the LP watchdog off. Call BEFORE `esp_hal::init()`.
pub fn disable_lp() {
    // SAFETY: fixed MMIO block, always mapped. Runs before esp-hal's init,
    // which is the point; esp-hal does the same again later.
    let r = unsafe { &*LP_WDT::PTR };
    // SAFETY: `WKEY` is the documented write-protect unlock key.
    r.wprotect().write(|w| unsafe { w.wdt_wkey().bits(WKEY) });
    r.config0()
        .modify(|_, w| w.wdt_en().clear_bit().wdt_flashboot_mod_en().clear_bit());
    // SAFETY: zero re-arms the write protection, as documented.
    r.wprotect().write(|w| unsafe { w.wdt_wkey().bits(0) });
}

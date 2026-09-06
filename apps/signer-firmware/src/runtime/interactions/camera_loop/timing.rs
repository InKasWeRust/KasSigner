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

//! Camera timing and byte conversion helpers.



/// Read SYSTIMER UNIT0 counter for timing (16MHz clock)
/// Returns value in 16MHz ticks. Divide by 16000 for ms.
#[inline(always)]
pub(super) fn systick() -> u32 {
    const SYSTIMER_BASE: u32 = 0x6002_3000;
    unsafe {
        // Trigger UNIT0 value update (bit 30 of UNIT0_OP_REG)
        core::ptr::write_volatile((SYSTIMER_BASE + 0x0004) as *mut u32, 1 << 30);
        // Small delay for value to latch
        let _ = core::ptr::read_volatile((SYSTIMER_BASE + 0x0004) as *const u32);
        // Read UNIT0_VALUE_LO
        core::ptr::read_volatile((SYSTIMER_BASE + 0x0044) as *const u32)
    }
}

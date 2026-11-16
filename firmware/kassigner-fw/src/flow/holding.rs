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

//! Touches held or too soon: a question held for [`HOLD_US`], how far its
//! hold has gone, and a tap too soon after its screen went up.

use super::*;

/// What a question held for [`HOLD_US`] made of an event; a seed's delete,
/// a backup's delete and the card's format ask so.
pub(super) enum Hold {
    Nothing,
    Cancel,
    Home,
    /// The answer that acts was tapped: it must now be held.
    Arm,
    /// A finger went down on it, armed.
    Down,
    /// Held for the time.
    Done,
}

impl<'b, const N: usize> Flow<'b, N> {
    /// A tap on the answer that acts arms it; armed, a finger down on it
    /// starts the hold, done once long enough. A lift or a slide off during
    /// the hold, or a tap on Cancel or Back, is Cancel.
    pub(super) fn hold(&self, event: Event<'_>, armed: bool, held_since: Option<u64>) -> Hold {
        let accept = dialog::zone(self.scale, dialog::Target::Accept);
        let on_accept = |x: u16, y: u16| accept.is_some_and(|z| z.contains(x, y));
        match event {
            Event::Tap { x, y } => {
                if held_since.is_some() {
                    // Lifted before the time.
                    return Hold::Cancel;
                }
                match dialog::target(self.scale, x, y) {
                    Some(dialog::Target::Accept) if !armed => Hold::Arm,
                    Some(dialog::Target::Accept) => Hold::Nothing,
                    Some(dialog::Target::Nav(Nav::Home)) => Hold::Home,
                    Some(_) => Hold::Cancel,
                    None => Hold::Nothing,
                }
            }
            Event::Press { x, y } if armed && held_since.is_none() && on_accept(x, y) => Hold::Down,
            Event::Drag { x, y } if held_since.is_some() && !on_accept(x, y) => Hold::Cancel,
            Event::Tick { now_us }
                if held_since.is_some_and(|t| now_us.saturating_sub(t) >= HOLD_US) =>
            {
                Hold::Done
            }
            _ => Hold::Nothing,
        }
    }

    /// Whether the touch ending now went down within [`SETTLE_US`] of the
    /// screen going up: the second tap of a double tap whose first put the
    /// screen up, which would otherwise answer it.
    pub(super) const fn too_soon(&self) -> bool {
        self.pressed_us.saturating_sub(self.shown_us) < SETTLE_US
    }

    /// How far a hold has gone once armed, 0 to 100: the button's fill.
    pub(super) fn held(&self, armed: bool, held_since: Option<u64>) -> Option<u8> {
        armed.then(|| {
            let held = held_since.map_or(0, |t| self.now_us.saturating_sub(t));
            (held.min(HOLD_US) * 100 / HOLD_US) as u8
        })
    }
}

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

//! Audio: ES8311 codec plus an NS4150B power amplifier.
//!
//! A sound confirms an action without a look at the screen, distinct tones
//! tell "signed" from "rejected", and a compromised display cannot forge one
//! on its own.
//!
//! `es8311` configures the codec over I2C; `player` streams samples to it
//! over I2S. `player` needs the I2S clock-source fix that
//! `esp-hal-fork/fork.sh` applies: without it `I2s::new()` never returns.

pub mod es8311;
pub mod player;
pub mod ring;

pub use es8311::Es8311;
pub use player::Player;

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

//! What the device does, without knowing which device it is: written
//! against `kassigner_hal`'s traits and the level 0 to 2 crates, naming no
//! board, pin or peripheral, so it runs in tests on a laptop.

#![no_std]
#![forbid(unsafe_code)]

pub mod branches;
pub mod card;
pub mod checks;
pub mod cues;
pub mod flow;
pub mod keyring;
pub mod limits;
pub mod paint;
pub mod reply;
pub mod review;
pub mod scan;
pub mod seed;
pub mod selftest;
pub mod session;
pub mod sizes;
pub mod text;
pub mod touch;
pub mod ui;
pub mod wipe;
pub mod words;

/// A kpub as it travels, a cosigner's file, and a signed message's record:
/// the unit's own layouts, from level 1 so a companion reads the same ones.
pub use kassigner_protocol::{kpub, message};

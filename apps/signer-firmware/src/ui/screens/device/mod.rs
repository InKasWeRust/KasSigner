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


// Device settings and camera screens.

mod camera;
pub(crate) mod persistence;
pub(crate) mod advanced_security;
#[cfg(feature = "provisioning-ui")]
pub(crate) mod pop_it;
#[cfg(feature = "provisioning-ui")]
pub(crate) mod owner_firmware;
mod settings;
pub(crate) use settings::{DISPLAY_DIM_ROW_Y, DISPLAY_PIN_ROW_Y};
#[cfg(feature = "m5stack")]
pub(crate) use settings::AUDIO_STARTUP_ROW_Y;

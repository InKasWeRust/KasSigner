// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// hw/ — Hardware drivers for Waveshare ESP32-S3-Touch-LCD-2

pub mod board;
pub mod pmu;
pub mod display;
pub mod icon_data;
pub mod camera;
pub mod touch;
pub mod sound;
pub mod battery;
pub mod sdcard;
pub mod sd_backup;
pub mod lockdown;
#[cfg(feature = "screenshot")]
pub mod screenshot;

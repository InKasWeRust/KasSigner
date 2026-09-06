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

// Stable OV5640 camera facade.

mod autofocus;
mod bus;
mod diagnostics;
mod initialization;
mod peripheral;
mod registers;
mod types;

pub use bus::{detect, read_reg, write_reg};
#[cfg(feature = "cam640")]
pub use diagnostics::init_hires;
pub use diagnostics::log_diagnostics;
#[cfg(not(feature = "cam640"))]
pub use initialization::init_480;
pub use peripheral::{configure_cam_vsync_eof, setup_cam_gpio_routing};
pub use types::CameraStatus;

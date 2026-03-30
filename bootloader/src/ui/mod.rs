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

// ui/mod.rs — User interface module (screens, fonts, keyboard, helpers)
// ui/ — UI logic, screen redraw, fonts, and input wizards

pub mod redraw;
pub mod helpers;
pub mod keyboard;
#[cfg(feature = "icon-browser")]
pub mod icon_browser;
pub mod pin_ui;
pub mod setup_wizard;
pub mod seed_manager;
pub mod prop_fonts;
#[allow(dead_code)]
pub mod logo_data;
pub mod screens;

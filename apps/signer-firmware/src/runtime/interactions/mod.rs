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

// runtime/interactions/mod.rs — Effectful input interaction adapters.
//
// Physical input is normalized/classified by the pure `controllers` module.
// This runtime layer may own display, I2C, delay, storage and service adapters.

pub(crate) use crate::controllers::TouchInput;

pub mod menu;
pub(crate) mod onboarding;
pub(crate) mod persistence;
pub mod stego;
pub mod sd;
pub mod seed;
pub mod export;
pub mod settings;
pub mod tx;
pub(crate) mod multisig_config;
#[cfg(feature = "workflow-tests")]
pub(crate) mod workflow_tests;
pub mod camera_loop;
mod support;
pub(crate) use support::{feedback, keyboard, menu_selection};
mod text_files;

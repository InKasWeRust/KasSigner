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

// runtime/mod.rs — Application state, signing pipeline, and boot tests
// runtime/ — Runtime state and application orchestration

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
pub(crate) mod camera_tuning;
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) mod core_s3;
pub(crate) mod destructive;
pub(crate) mod effects;
#[cfg(not(feature = "hardware-tests"))]
pub(crate) mod event_loop;
pub(crate) mod interactions;
pub(crate) mod touch_service;
pub(crate) mod navigation;
pub(crate) mod power_state;
pub(crate) mod presentation;
pub(crate) mod qr_presentation;
pub(crate) mod touch_dispatch;
#[cfg(feature = "workflow-tests")]
pub(crate) mod workflow_tests;
pub mod data;
pub mod input;
pub mod signing;
pub(crate) mod secret_state;
pub mod unit_tests;

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

//! Camera capture and QR decoding controller.
//!
//! The stable `runtime::interactions::camera_loop::run_camera_cycle` entry point is
//! preserved while capture, decoding, dispatch, touch, and multi-frame state
//! are grouped by responsibility below.

use crate::{
    hw::{camera, display},
    runtime::data::AppData,
    services::audio as sound,
    wallet::seed_manager,
};
use crate::wallet::mnemonic::validate as validate_mnemonic;
use esp_hal::dma::DmaRxBuf;
use esp_hal::lcd_cam::cam::Camera as DvpCamera;

extern crate alloc;
use alloc::vec::Vec;

#[cfg(all(
    not(feature = "hardware-tests"),
    any(
        not(feature = "workflow-test-auto"),
        all(feature = "m5stack", feature = "workflow-runtime-auto")
    )
))]
mod cycle;
mod decoder;
pub(crate) mod dispatch;
mod dvp_capture;
mod multiframe;
mod session;
mod state;
mod timing;
mod touch_input;
#[cfg(feature = "waveshare")]
mod waveshare_capture;

#[cfg(any(
    not(feature = "workflow-test-auto"),
    all(feature = "m5stack", feature = "workflow-runtime-auto")
))]
#[cfg(not(feature = "hardware-tests"))]
pub use cycle::run_camera_cycle;
#[cfg(not(feature = "hardware-tests"))]
pub use state::CameraSessionState;
#[cfg(not(feature = "hardware-tests"))]
pub(crate) use touch_input::route_camera_back;

#[cfg(feature = "workflow-test-auto")]
mod workflow;

#[cfg(feature = "workflow-test-auto")]
pub(crate) use workflow::{
    process_anti_klepto_payload as workflow_process_anti_klepto_payload,
    process_multiframe as workflow_process_multiframe,
    process_pending_payload as workflow_process_pending_payload,
    process_seed_payload as workflow_process_seed_payload,
    process_transaction_payload as workflow_process_transaction_payload,
    validate_stealth_request as workflow_validate_stealth_request,
};

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

// services/mod.rs — Firmware services independent of screen navigation
// services/ — Encrypted backups, steganography, KRC-20, firmware update, and verification

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
pub(crate) mod hardware;
pub(crate) mod memory;
pub(crate) use hardware::{audio, camera_device, storage_device, timing, touch_recovery};
#[cfg(feature = "waveshare")]
pub(crate) use hardware::power;
pub mod backup;
pub mod stego;
pub mod krc20;
pub mod fw_update;
pub mod entropy;
pub mod credential_policy;
pub mod raw_key;
pub mod wallet_session;
pub mod persistent_wallet;
pub mod device_wipe;
pub(crate) mod destructive;
pub mod secure_time;
pub mod signing_policy;
pub mod covenant_sign;
pub mod private_swap;
pub mod storage_files;
pub mod verify;
pub mod unit_tests;

pub(crate) mod wallet_keys;

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

//! Board hardware: the traits a board implements, and the pin maps, one page
//! per board to read beside its schematic (the only way to check a pin).
//!
//! A board implements, one module each:
//!
//! - [`battery::Battery`], [`camera::Camera`], [`decoder::Decoder`],
//!   [`display::Display`], [`entropy::Entropy`], [`input::Touch`],
//!   [`memory::Words`], [`speaker::Speaker`] and [`timer::Timer`].
//! - [`tune::Tune`]: the camera settings a tuning screen moves.
//! - [`provisioning::Provisioning`], the fuse reader, and
//!   [`provisioning::Console`], the host port a provisioned unit closes after
//!   verification.
//! - [`image::Image`]: the running firmware's bytes from flash, which the
//!   verification screen hashes.
//!
//! Shared by every board's driver and the flow, not implemented per board:
//! [`card::Kind`], the kind of SD card a slot answered with,
//! [`drbg::Drbg`], the generator every board wraps its [`entropy::Entropy`]
//! in, so the flow's draws are conditioned the same on any silicon, and
//! [`unit::Failed`], what a board's bring-up returns when it fails.
//!
//! Block storage is `kassigner_fat32::block::BlockDevice`, at level 0 with the
//! filesystem since FAT32 is an outside specification; a board implements it
//! from there.

#![no_std]
#![forbid(unsafe_code)]

pub mod battery;
pub mod camera;
pub mod card;
pub mod decoder;
pub mod display;
pub mod drbg;
pub mod entropy;
pub mod expander;
pub mod image;
pub mod input;
pub mod memory;
pub mod pins;
pub mod power;
pub mod provisioning;
pub mod speaker;
pub mod timer;
pub mod tune;
pub mod unit;

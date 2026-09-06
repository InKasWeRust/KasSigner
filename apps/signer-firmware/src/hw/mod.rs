// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Board selection façade.
//!
//! - `shared/` owns ESP32-S3 and protocol primitives used by all devices.
//! - `waveshare/` owns every Waveshare-specific peripheral implementation.
//! - `m5stack/` owns every M5Stack-specific peripheral implementation.
//!
//! The rest of the firmware imports stable names such as `hw::display`,
//! `hw::camera`, and `hw::sdcard`; only this façade selects their concrete
//! implementation.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
#[cfg(all(feature = "waveshare", feature = "m5stack"))]
compile_error!("select exactly one board feature: waveshare or m5stack");

#[cfg(not(any(feature = "waveshare", feature = "m5stack")))]
compile_error!("select one board feature: waveshare or m5stack");

pub(crate) mod shared;

#[cfg(feature = "waveshare")]
mod waveshare;
#[cfg(feature = "m5stack")]
mod m5stack;

#[cfg(feature = "waveshare")]
use waveshare as active_board;
#[cfg(feature = "m5stack")]
use m5stack as active_board;

pub(crate) use active_board::{battery, camera, display, pmu, sdcard, sound, touch};

#[cfg(feature = "waveshare")]
pub(crate) use active_board::{
    cam_dma, camera_ov2640, camera_power, decode_core, entropy_imu as imu,
};
#[cfg(feature = "m5stack")]
pub(crate) use active_board::{entropy_imu as imu, rtc};
#[cfg(feature = "m5stack")]
pub(crate) use active_board::spi_bus::initialize as initialize_cores3_spi;
#[cfg(all(feature = "waveshare", feature = "af"))]
pub(crate) use active_board::ov5640_af_fw;

pub(crate) use shared::lockdown;
#[cfg(feature = "screenshot")]
pub(crate) use shared::screenshot;

pub(crate) const ACTIVE_BOARD_NAME: &str = active_board::BOARD_NAME;

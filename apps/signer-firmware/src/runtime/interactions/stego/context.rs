// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Shared capabilities for steganography file-selection workflows.

use crate::{
    runtime::interactions::TouchInput,
    hw::{display, touch},
    services::storage_device as sdcard,
    runtime::data::AppData,
};

/// Capabilities supplied by the firmware router to the stego façade.
pub struct StegoTouchContext<'ctx, 'display, 'hal> {
    pub ad: &'ctx mut AppData,
    pub boot_display: &'ctx mut display::BootDisplay<'display>,
    pub delay: &'ctx mut esp_hal::delay::Delay,
    pub liveness: &'ctx mut dyn FnMut(),
    pub i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub sd_card_type: &'ctx Option<sdcard::SdCardType>,
    pub backup_device: &'ctx mut dyn crate::services::backup::BackupDevice,
    pub list_zones: &'ctx [touch::TouchZone; 4],
    pub page_up_zone: &'ctx touch::TouchZone,
    pub page_down_zone: &'ctx touch::TouchZone,
    pub input: TouchInput,
}

pub(super) struct StegoFileContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) boot_display: &'ctx mut display::BootDisplay<'display>,
    pub(super) delay: &'ctx mut esp_hal::delay::Delay,
    pub(super) i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub(super) list_zones: &'ctx [touch::TouchZone; 4],
    pub(super) page_up_zone: &'ctx touch::TouchZone,
    pub(super) page_down_zone: &'ctx touch::TouchZone,
    pub(super) input: TouchInput,
}

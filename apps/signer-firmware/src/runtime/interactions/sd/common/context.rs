// Capability-specific inputs for SD touch workflows.

use crate::{
    runtime::interactions::TouchInput,
    hw::{display, touch},
    services::storage_device as sdcard,
    runtime::data::AppData,
};

pub struct SdTouchContext<'ctx, 'display, 'hal> {
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

pub(crate) struct SdActionContext<'ctx> {
    pub(in crate::runtime::interactions::sd) ad: &'ctx mut AppData,
    pub(in crate::runtime::interactions::sd) x: u16,
    pub(in crate::runtime::interactions::sd) y: u16,
    pub(in crate::runtime::interactions::sd) is_back: bool,
}

pub(crate) struct SdListContext<'ctx> {
    pub(in crate::runtime::interactions::sd) ad: &'ctx mut AppData,
    pub(in crate::runtime::interactions::sd) list_zones: &'ctx [touch::TouchZone; 4],
    pub(in crate::runtime::interactions::sd) x: u16,
    pub(in crate::runtime::interactions::sd) y: u16,
    pub(in crate::runtime::interactions::sd) is_back: bool,
}

pub(crate) struct SdIoContext<'ctx, 'display, 'hal> {
    pub(in crate::runtime::interactions::sd) ad: &'ctx mut AppData,
    pub(in crate::runtime::interactions::sd) boot_display: &'ctx mut display::BootDisplay<'display>,
    pub(in crate::runtime::interactions::sd) delay: &'ctx mut esp_hal::delay::Delay,
    pub(in crate::runtime::interactions::sd) liveness: &'ctx mut dyn FnMut(),
    pub(in crate::runtime::interactions::sd) i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub(in crate::runtime::interactions::sd) backup_device: &'ctx mut dyn crate::services::backup::BackupDevice,
    pub(in crate::runtime::interactions::sd) sd_card_type: &'ctx Option<sdcard::SdCardType>,
    pub(in crate::runtime::interactions::sd) x: u16,
    pub(in crate::runtime::interactions::sd) y: u16,
    pub(in crate::runtime::interactions::sd) is_back: bool,
}

pub(crate) struct SdFileListContext<'ctx, 'display, 'hal> {
    pub(in crate::runtime::interactions::sd) ad: &'ctx mut AppData,
    pub(in crate::runtime::interactions::sd) boot_display: &'ctx mut display::BootDisplay<'display>,
    pub(in crate::runtime::interactions::sd) delay: &'ctx mut esp_hal::delay::Delay,
    pub(in crate::runtime::interactions::sd) liveness: &'ctx mut dyn FnMut(),
    pub(in crate::runtime::interactions::sd) i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub(in crate::runtime::interactions::sd) list_zones: &'ctx [touch::TouchZone; 4],
    pub(in crate::runtime::interactions::sd) x: u16,
    pub(in crate::runtime::interactions::sd) y: u16,
    pub(in crate::runtime::interactions::sd) is_back: bool,
}

pub(crate) struct SdImportMenuContext<'ctx, 'display, 'hal> {
    pub(in crate::runtime::interactions::sd) ad: &'ctx mut AppData,
    pub(in crate::runtime::interactions::sd) boot_display: &'ctx mut display::BootDisplay<'display>,
    pub(in crate::runtime::interactions::sd) delay: &'ctx mut esp_hal::delay::Delay,
    pub(in crate::runtime::interactions::sd) i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub(in crate::runtime::interactions::sd) sd_card_type: &'ctx Option<sdcard::SdCardType>,
    pub(in crate::runtime::interactions::sd) list_zones: &'ctx [touch::TouchZone; 4],
    pub(in crate::runtime::interactions::sd) page_up_zone: &'ctx touch::TouchZone,
    pub(in crate::runtime::interactions::sd) page_down_zone: &'ctx touch::TouchZone,
    pub(in crate::runtime::interactions::sd) x: u16,
    pub(in crate::runtime::interactions::sd) y: u16,
    pub(in crate::runtime::interactions::sd) is_back: bool,
}

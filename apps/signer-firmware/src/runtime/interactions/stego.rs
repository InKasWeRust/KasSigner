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

// controllers/stego.rs — Touch handlers for steganography states
//
use crate::runtime::interactions::feedback::RedrawFlag;
use crate::runtime::interactions::TouchInput;
use crate::{
    hw::{display, touch},
    runtime::data::AppData,
    services::{audio as sound, stego, storage_device as sdcard},
};

use context::StegoFileContext;

mod context;
mod mode;
mod export_description;
mod export_security;
mod export_confirm;
mod import_selection;
mod import_decrypt;
mod import_finish;

pub use context::StegoTouchContext;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use {
    export_description::workflow_accept_description_file,
    import_decrypt::{workflow_open_payload, workflow_stage_portable_payload},
    import_selection::workflow_accept_descriptor_file,
    mode::workflow_select_security_with_jpegs,
};

/// Handle touch events for all steganography workflow screens.
#[inline(never)]
pub fn handle_stego_touch(context: StegoTouchContext<'_, '_, '_>) -> Option<bool> {
    let StegoTouchContext {
        ad,
        boot_display,
        delay,
        liveness,
        i2c,
        sd_card_type,
        backup_device,
        list_zones,
        page_up_zone,
        page_down_zone,
        input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    macro_rules! handled {
        ($expression:expr) => {
            if let Some(result) = $expression {
                return Some(result);
            }
        };
    }
    handled!(mode::handle(ad, boot_display, delay, i2c, sd_card_type, x, y, is_back));
    handled!(export_description::handle(StegoFileContext {
        ad: &mut *ad,
        boot_display: &mut *boot_display,
        delay: &mut *delay,
        i2c: &mut *i2c,
        list_zones,
        page_up_zone,
        page_down_zone,
        input,
    }));
    handled!(export_security::handle(ad, boot_display, delay, x, y, is_back));
    handled!(export_confirm::handle(ad, boot_display, delay, i2c, backup_device, x, y, is_back));
    handled!(import_selection::handle(StegoFileContext {
        ad: &mut *ad,
        boot_display: &mut *boot_display,
        delay: &mut *delay,
        i2c: &mut *i2c,
        list_zones,
        page_up_zone,
        page_down_zone,
        input,
    }));
    handled!(import_decrypt::handle(
        ad, boot_display, delay, liveness, i2c, backup_device, x, y, is_back,
    ));
    handled!(import_finish::handle(ad, boot_display, delay, x, y, is_back));
    None
}

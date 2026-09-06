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
// stego controller — image-description workflow facade.
mod choice;
mod file_picker;
mod image_picker;
mod keyboard;
mod preview;

use crate::{runtime::interactions::text_files::TextFileSelectionContext, runtime::input::AppState};
use super::{context::StegoFileContext, TouchInput};

pub(super) fn handle(context: StegoFileContext<'_, '_, '_>) -> Option<bool> {
    let StegoFileContext {
        ad, boot_display, delay, i2c, list_zones, page_up_zone, page_down_zone, input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    let redraw = match ad.navigation.app.state {
        AppState::StegoJpegPick => image_picker::handle(
            ad,
            list_zones,
            page_up_zone,
            page_down_zone,
            x,
            y,
            is_back,
        ),
        AppState::StegoJpegDescChoice => {
            choice::handle(ad, boot_display, delay, i2c, x, y, is_back)
        }
        AppState::StegoJpegDescFile => {
            file_picker::handle(TextFileSelectionContext {
                ad, boot_display, delay, i2c, list_zones, input,
            })
        }
        AppState::StegoJpegDesc => keyboard::handle(ad, boot_display, x, y, is_back),
        AppState::StegoJpegDescPreview => preview::handle(ad, x, y, is_back),
        _ => return None,
    };
    Some(redraw)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) use file_picker::workflow_accept_content as workflow_accept_description_file;

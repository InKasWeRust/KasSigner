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

//! Screen redraw handlers for steganography workflows.

use super::display;
use crate::runtime::input::AppState;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    redraw_state(ad.navigation.app.state, ad, boot_display)
}

fn redraw_state(
    state: AppState,
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    redraw_stego_export(state, ad, boot_display) || redraw_stego_import(state, ad, boot_display)
}

fn redraw_stego_export(
    state: AppState,
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    if let Some(title) = stego_export_keyboard_title(state) {
        boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, title);
        return true;
    }
    match state {
        AppState::StegoModeSelect => boot_display.draw_stego_carrier_choice(),
        AppState::StegoSecuritySelect => boot_display.draw_stego_security_choice(),
        AppState::StegoResult => draw_stego_result(ad, boot_display),
        AppState::StegoJpegPick => boot_display.draw_stego_jpeg_pick(
            &ad.stego.export_flow.jpeg_display_names,
            &ad.stego.export_flow.jpeg_display_lens,
            ad.stego.export_flow.jpeg_file_count,
            ad.stego.export_flow.jpeg_selected,
        ),
        AppState::StegoJpegDescChoice => boot_display.draw_stego_desc_choice(false),
        AppState::StegoJpegDescFile => boot_display.draw_stego_txt_pick(
            &ad.storage.text_files.display_names,
            &ad.storage.text_files.display_lens,
            ad.storage.text_files.file_count,
        ),
        AppState::StegoJpegDescPreview => draw_stego_description_preview(ad, boot_display),
        AppState::StegoJpegPpAsk => boot_display.draw_stego_pp_ask(),
        AppState::StegoJpegPpInfo => boot_display.draw_stego_hint_picker(),
        AppState::StegoJpegConfirm => draw_stego_confirmation(ad, boot_display),
        _ => return false,
    }
    true
}

fn stego_export_keyboard_title(state: AppState) -> Option<&'static str> {
    match state {
        AppState::StegoJpegDesc => Some("IMAGE DESCRIPTOR"),
        AppState::StegoJpegPpEntry => Some("CUSTOM HINT"),
        AppState::StegoPortablePassword => Some("PORTABLE BACKUP PASSWORD"),
        AppState::StegoPortablePasswordConfirm => Some("CONFIRM PASSWORD"),
        _ => None,
    }
}

fn redraw_stego_import(
    state: AppState,
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match state {
        AppState::StegoImportPick => boot_display.draw_stego_jpeg_pick(
            &ad.stego.import.jpeg_display,
            &ad.stego.import.jpeg_display_lens,
            ad.stego.import.jpeg_count,
            ad.stego.import.jpeg_selected,
        ),
        AppState::StegoImportDescChoice => boot_display.draw_stego_desc_choice(true),
        AppState::StegoImportDescFile => boot_display.draw_stego_txt_pick(
            &ad.storage.text_files.display_names,
            &ad.storage.text_files.display_lens,
            ad.storage.text_files.file_count,
        ),
        AppState::StegoImportPass => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "IMAGE DESCRIPTOR")
        }
        AppState::StegoImportPortablePassword => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "BACKUP PASSWORD")
        }
        AppState::StegoHintReveal => draw_stego_hint(ad, boot_display),
        AppState::StegoHintPassphrase => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "25TH WORD")
        }
        _ => return false,
    }
    true
}


fn draw_stego_result(
    ad: &crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    if ad.stego.session.result_ok {
        boot_display.draw_success_screen("Stego Backup Created");
    } else {
        boot_display.draw_error_back_screen("Stego Failed");
    }
}

fn draw_stego_description_preview(
    ad: &crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    let description = core::str::from_utf8(
        &ad.stego.export_flow.jpeg_desc_buf[..ad.stego.export_flow.jpeg_desc_len],
    )
    .unwrap_or("");
    boot_display.draw_stego_desc_preview(description);
}

fn draw_stego_confirmation(
    ad: &crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    let index = ad.stego.export_flow.jpeg_selected as usize;
    let name_length = ad.stego.export_flow.jpeg_display_lens[index] as usize;
    let name = core::str::from_utf8(
        &ad.stego.export_flow.jpeg_display_names[index][..name_length],
    )
    .unwrap_or("?");
    let description = core::str::from_utf8(
        &ad.stego.export_flow.jpeg_desc_buf[..ad.stego.export_flow.jpeg_desc_len],
    )
    .unwrap_or("");
    boot_display.draw_stego_jpeg_confirm(
        name,
        description,
        ad.stego.hint.length > 0,
        ad.stego.export_flow.security.label(),
    );
}

fn draw_stego_hint(
    ad: &crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    let hint = core::str::from_utf8(
        &ad.stego.import.recovered_hint[..ad.stego.import.recovered_hint_len],
    )
    .unwrap_or("???");
    boot_display.draw_stego_hint_reveal(hint);
}

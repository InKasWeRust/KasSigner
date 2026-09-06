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

//! Screen redraw handlers for message-signing and commit-reveal states.

use super::display;
use crate::runtime::input::AppState;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::SignMsgChoice => boot_display.draw_sign_msg_choice(),
        AppState::SignMsgType => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "MESSAGE");
        }
        AppState::SignMsgScan => {
            // Camera controller owns the live scanner surface.
        }
        AppState::SignMsgFile => {
            boot_display.draw_stego_txt_pick(
                &ad.storage.text_files.display_names,
                &ad.storage.text_files.display_lens,
                ad.storage.text_files.file_count,
            );
        }
        AppState::SignMsgPreview => {
            let message = core::str::from_utf8(
                &ad.signing.message.payload[..ad.signing.message.payload_len],
            )
            .unwrap_or("");
            boot_display.draw_sign_msg_preview(message);
        }
        AppState::SignMsgResult | AppState::SignMsgResultQr => {
            boot_display.draw_sign_msg_result(
                &ad.signing.message.signature,
                &ad.signing.message.hash,
            );
        }
        AppState::CommitRevealType => {
            boot_display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "SECRET");
        }
        AppState::CommitRevealPreview => {
            // Current preimages begin with an eight-byte salt; only the secret is shown.
            let start = 8.min(ad.signing.commit_reveal.plaintext_len);
            let message = core::str::from_utf8(
                &ad.signing.commit_reveal.plaintext
                    [start..ad.signing.commit_reveal.plaintext_len],
            )
            .unwrap_or("");
            boot_display.draw_commit_reveal_preview(
                message,
                &ad.signing.commit_reveal.hash,
            );
        }
        AppState::CommitRevealResult | AppState::CommitRevealResultQr => {
            boot_display.draw_commit_reveal_result(
                &ad.signing.commit_reveal.hash,
                ad.signing.commit_reveal.ciphertext.len(),
            );
        }
        AppState::DecryptSecretScan => {
            // The camera loop owns drawing while the scanner is active.
        }
        AppState::DecryptSecretResult | AppState::DecryptSecretResultQr => {
            let start = 8.min(ad.signing.commit_reveal.plaintext_len);
            let message = core::str::from_utf8(
                &ad.signing.commit_reveal.plaintext
                    [start..ad.signing.commit_reveal.plaintext_len],
            )
            .unwrap_or("");
            boot_display.draw_decrypt_secret_result(message);
        }
        _ => return false,
    }
    true
}

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

//! Commit-reveal result and decrypted-secret result interactions.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::{display, AppData, RedrawFlag};
use crate::runtime::input::AppState;
use shared_signer::bytes::zeroize_bytes;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = RedrawFlag::default();
    match ad.navigation.app.state {
        AppState::CommitRevealResult => {
            if is_back {
                clear_commit_result(ad);
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
                needs_redraw.set(true);
            } else if (150..=186).contains(&y) && (60..=260).contains(&x) {
                show_commit_qr(ad, boot_display, delay, &mut needs_redraw);
            }
        }
        AppState::CommitRevealResultQr => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealResult));
            needs_redraw.set(true);
        }
        AppState::DecryptSecretScan => {
            if is_back {
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
                needs_redraw.set(true);
            }
        }
        AppState::DecryptSecretResult => {
            if is_back {
                clear_plaintext(ad);
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
                needs_redraw.set(true);
            } else if (150..=186).contains(&y) && (70..=250).contains(&x) {
                show_plaintext_qr(ad, boot_display);
            }
        }
        AppState::DecryptSecretResultQr => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DecryptSecretResult));
            needs_redraw.set(true);
        }
        _ => return None,
    }
    Some(needs_redraw.value())
}

fn clear_commit_result(ad: &mut AppData) {
    ad.signing.commit_reveal.ciphertext.clear();
    ad.signing.commit_reveal.hash = [0; 32];
}

fn clear_plaintext(ad: &mut AppData) {
    let length = ad.signing.commit_reveal.plaintext_len;
    zeroize_bytes(&mut ad.signing.commit_reveal.plaintext[..length]);
    ad.signing.commit_reveal.plaintext_len = 0;
}

fn show_commit_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    needs_redraw: &mut RedrawFlag,
) {
    let total = 32 + ad.signing.commit_reveal.ciphertext.len();
    if total > 134 {
        show_rejection(boot_display, delay, "Message too long for QR", 2_000, ErrorSound::Beep);
        needs_redraw.set(true);
        return;
    }

    let mut qr_data = [0u8; 134];
    qr_data[..32].copy_from_slice(&ad.signing.commit_reveal.hash);
    qr_data[32..total].copy_from_slice(&ad.signing.commit_reveal.ciphertext);
    boot_display.draw_qr_fullscreen(&qr_data[..total]);
    zeroize_bytes(&mut qr_data);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealResultQr));
}

fn show_plaintext_qr(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) {
    let plaintext =
        &ad.signing.commit_reveal.plaintext[..ad.signing.commit_reveal.plaintext_len];
    let mut hex = [0u8; 256];
    let hex_len = plaintext.len() * 2;
    for (index, byte) in plaintext.iter().copied().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        hex[index * 2] = HEX[(byte >> 4) as usize];
        hex[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    boot_display.draw_qr_fullscreen(&hex[..hex_len]);
    zeroize_bytes(&mut hex);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DecryptSecretResultQr));
}

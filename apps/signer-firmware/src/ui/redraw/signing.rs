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
// Screen redraw — signing-state facade.
mod qr;
mod transaction;

use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::SignTxGuide => transaction::draw_guide(ad, boot_display),
        AppState::AntiKleptoRevealGuide => boot_display.draw_anti_klepto_reveal_guide(),
        AppState::ReviewTx { page } => transaction::draw_review(ad, boot_display, page),
        AppState::InspectUtxoSummary => transaction::draw_utxo_summary(ad, boot_display),
        AppState::InspectUtxo { index, address_page } => transaction::draw_utxo(ad, boot_display, index, address_page),
        AppState::ConfirmTx => transaction::draw_confirmation(ad, boot_display),
        AppState::ShowQR => qr::draw_payload(ad, boot_display),
        AppState::ShowQrPopup => boot_display.draw_showqr_popup(),
        AppState::ShowQrModeChoice => boot_display.draw_qr_mode_choice(),
        _ => return false,
    }
    true
}

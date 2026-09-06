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


use super::super::{BootDisplay, KASPA_ACCENT};

impl<'a> BootDisplay<'a> {
    /// Draw confirm send screen with big touch-friendly buttons
    pub fn draw_confirm_send_screen(&mut self, amount_str: &str, fee_str: &str, change_str: &str, destination: &str) {
        self.draw_send_confirmation_layout("CONFIRM SEND", amount_str, fee_str, change_str, destination);
    }

    /// Draw confirm send screen with multisig signature status
    pub fn draw_confirm_send_multisig(&mut self, amount_str: &str, fee_str: &str, change_str: &str,
                                       destination: &str, sigs_present: u32, sigs_required: u32) {
        self.draw_send_confirmation_layout("CONFIRM MULTISIG", amount_str, fee_str, change_str, destination);
        let mut sig_buf: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut sig_buf, format_args!("Sigs: {sigs_present}/{sigs_required}")).ok();
        let width = super::super::measure_body(sig_buf.as_str());
        super::super::draw_lato_body(&mut self.display, sig_buf.as_str(), (320 - width) / 2, 181, KASPA_ACCENT);
    }

    /// Draw confirm send screen for covenant P2SH transactions.
    /// Same layout as the standard confirm screen but with a
    /// "CONFIRM COVENANT?" header so the user knows they are
    /// spending from a covenant address.
    pub fn draw_confirm_send_covenant(&mut self, amount_str: &str, fee_str: &str, change_str: &str, destination: &str) {
        self.draw_send_confirmation_layout(
            "CONFIRM COVENANT",
            amount_str,
            fee_str,
            change_str,
            destination,
        );
    }

}

// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::super::BootDisplay;

impl<'a> BootDisplay<'a> {
    /// Draw safe sign-message input choices: typed, message QR, or SD text.
    pub fn draw_sign_msg_choice(&mut self) {
        self.draw_input_source_choice("SIGN MESSAGE", "Domain-separated text signature", true);
    }
}

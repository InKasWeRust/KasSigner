//! Owner-authorized firmware warnings and confirmation screens.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_DANGER, COLOR_TEXT, COLOR_TEXT_DIM, KASPA_TEAL,
    draw_lato_body, draw_lato_hint, draw_oswald_header, measure_body, measure_header,
    measure_hint, truncate_chars,
};
use embedded_graphics::draw_target::DrawTarget;

impl<'a> BootDisplay<'a> {
    pub fn draw_owner_key_warning(&mut self) {
        let lines = if cfg!(feature = "secure-owner-only") {
            [
                "Makes your RSA-3072 key the sole permanent",
                "Secure Boot trust root; no vendor key remains.",
                "Do this BEFORE Pop It. It cannot be undone.",
                "Keep the private key offline and backed up.",
            ]
        } else {
            [
                "Adds your RSA-3072 key as a permanent",
                "Secure Boot trust root beside KasSigner.",
                "Do this BEFORE Pop It. It cannot be undone.",
                "Keep the private key offline and backed up.",
            ]
        };
        self.draw_owner_warning("ENROLL OWNER KEY", lines, true);
    }

    pub fn draw_owner_install_warning(&mut self) {
        self.draw_owner_warning(
            "OWNER FIRMWARE",
            [
                "Installs application firmware signed by your",
                "enrolled owner key from OWNERFW.BIN on SD.",
                "Owner firmware can access wallet secrets.",
                "Only install code you personally trust.",
            ],
            false,
        );
    }

    fn draw_owner_warning(&mut self, title: &str, lines: [&str; 4], irreversible: bool) {
        self.display.clear(COLOR_BG).ok();
        let width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - width) / 2, 32, KASPA_TEAL);
        for (index, line) in lines.iter().enumerate() {
            let y = 72 + index as i32 * 27;
            let line_width = measure_body(line);
            let color = if irreversible && index == 2 { COLOR_DANGER } else { COLOR_TEXT };
            draw_lato_body(&mut self.display, line, ((320 - line_width) / 2).max(2), y, color);
        }
        self.draw_warning_button(16, "CANCEL", false);
        self.draw_warning_button(172, "CONTINUE", true);
    }

    pub fn draw_owner_confirm(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        enroll: bool,
        error: Option<&str>,
    ) {
        let title = if enroll { "TYPE ENROLL OWNER" } else { "TYPE INSTALL OWNER" };
        self.draw_keyboard_screen_full(input, title);
        let hint = if enroll { "Reads OWNERKEY.KAS from SD" } else { "Reads OWNERFW.BIN from SD" };
        let width = measure_hint(hint);
        draw_lato_hint(&mut self.display, hint, ((320 - width) / 2).max(2), 43, COLOR_TEXT_DIM);
        if let Some(message) = error {
            let clipped = truncate_chars(message, 46);
            let error_width = measure_hint(clipped);
            draw_lato_hint(&mut self.display, clipped, ((320 - error_width) / 2).max(2), 78, COLOR_DANGER);
        }
    }

    pub fn draw_owner_firmware_result(&mut self, title: &str, detail: &str, success: bool) {
        self.display.clear(COLOR_BG).ok();
        let width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - width) / 2,
            70,
            if success { KASPA_TEAL } else { COLOR_DANGER },
        );
        let detail_width = measure_body(detail);
        draw_lato_body(&mut self.display, detail, ((320 - detail_width) / 2).max(2), 122, COLOR_TEXT);
    }

    #[cfg(feature = "secure-provisioning-core")]
    pub fn draw_owner_firmware_applying(&mut self, title: &str, enrollment: bool) {
        let detail = if enrollment {
            "Restarting into signed bootloader..."
        } else {
            "Verifying owner signature before activation..."
        };
        self.draw_owner_firmware_result(title, detail, true);
    }
}

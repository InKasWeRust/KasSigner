//! User-controlled Secure Boot v2 eFuse provisioning screens.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_TEXT,
    COLOR_TEXT_DIM, KASPA_TEAL, CornerRadii, Drawable, Line, Point, Primitive,
    PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_body, draw_lato_hint,
    draw_lato_title, draw_oswald_header, measure_body, measure_header, measure_hint,
    measure_title, truncate_chars,
};
use embedded_graphics::draw_target::DrawTarget;

pub(crate) const PROMPT_BUTTON_Y: core::ops::RangeInclusive<u16> = 181..=226;
pub(crate) const YES_BUTTON_X: core::ops::RangeInclusive<u16> = 12..=104;
pub(crate) const NO_BUTTON_X: core::ops::RangeInclusive<u16> = 114..=206;
pub(crate) const EXPLAIN_BUTTON_X: core::ops::RangeInclusive<u16> = 216..=308;
pub(crate) const OWNER_PROMPT_BUTTON_X: core::ops::RangeInclusive<u16> = 12..=308;
pub(crate) const OWNER_SETUP_BUTTON_Y: core::ops::RangeInclusive<u16> = 164..=193;
pub(crate) const CONTINUE_WITHOUT_BUTTON_Y: core::ops::RangeInclusive<u16> = 200..=229;

impl<'a> BootDisplay<'a> {
    pub fn draw_pop_it_prompt(&mut self, owner_authority_enrolled: bool, error: Option<&str>) {
        self.display.clear(COLOR_BG).ok();
        let title = "POP IT!";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 33, KASPA_TEAL);
        Line::new(Point::new(30, 43), Point::new(290, 43))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        self.draw_back_button();

        if !owner_authority_enrolled {
            self.draw_pop_it_owner_warning();
            return;
        }

        let dev_demo = cfg!(all(feature = "m5stack", not(feature = "production")));
        self.draw_pop_centered("Enable hardware Secure Boot v2?", 73, COLOR_TEXT);
        self.draw_pop_centered("Owner firmware key: ENROLLED", 99, KASPA_TEAL);
        if dev_demo {
            self.draw_pop_centered("DEVELOPMENT SIMULATION ONLY", 124, KASPA_TEAL);
            self.draw_pop_centered("No eFuses will be written on this build.", 146, COLOR_TEXT);
        } else {
            self.draw_pop_centered("This permanently burns security eFuses.", 124, COLOR_DANGER);
            self.draw_pop_centered("It cannot be undone or reset later.", 146, COLOR_DANGER);
        }
        if let Some(message) = error {
            let clipped = truncate_chars(message, 46);
            self.draw_pop_centered(clipped, 166, COLOR_DANGER);
        }

        self.draw_pop_button(12, "YES", true);
        self.draw_pop_button(114, "NO", false);
        self.draw_pop_button(216, "EXPLAIN", false);
    }

    fn draw_pop_it_owner_warning(&mut self) {
        let dev_demo = cfg!(all(feature = "m5stack", not(feature = "production")));
        if dev_demo {
            self.draw_pop_centered("DEVELOPMENT SIMULATION ONLY", 62, KASPA_TEAL);
            self.draw_pop_centered("Production Pop It permanently enables", 84, COLOR_TEXT);
            self.draw_pop_centered("hardware Secure Boot v2.", 104, COLOR_TEXT);
        } else {
            self.draw_pop_centered("Pop It permanently enables hardware", 70, COLOR_TEXT);
            self.draw_pop_centered("Secure Boot v2.", 90, COLOR_TEXT);
        }
        self.draw_pop_centered("No owner firmware key is enrolled.", 119, COLOR_DANGER);
        if cfg!(feature = "secure-owner-only") {
            self.draw_pop_centered("Owner-only mode requires your key as", 139, COLOR_TEXT);
            self.draw_pop_centered("the sole permanent Secure Boot authority.", 157, COLOR_TEXT);
            self.draw_pop_wide_button(164, "SET UP OWNER FIRMWARE", true);
        } else {
            self.draw_pop_centered("Continuing permanently closes owner", 139, COLOR_TEXT);
            self.draw_pop_centered("firmware enrollment on this device.", 157, COLOR_TEXT);
            self.draw_pop_wide_button(164, "SET UP OWNER FIRMWARE", true);
            self.draw_pop_wide_button(200, "CONTINUE WITHOUT IT", false);
        }
    }

    pub fn draw_pop_it_explain(&mut self) {
        self.clear_keep_nav();
        let title = "EXPLANATION";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(18, 39), Point::new(302, 39))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let dev_demo = cfg!(all(feature = "m5stack", not(feature = "production")));
        let lines = if dev_demo {
            [
                ("Production Pop It enables ROM-enforced", 70),
                ("Secure Boot v2 with permanent eFuses.", 90),
                ("This development preview performs no", 120),
                ("eFuse write and changes no trust root.", 140),
                ("It only previews the teal Home badge", 160),
                ("until the device is restarted.", 194),
            ]
        } else if cfg!(feature = "secure-owner-only") {
            [
                ("Before Pop It, no vendor key is fused.", 70),
                ("Your enrolled RSA key is prepared as", 90),
                ("the sole Secure Boot v2 authority.", 120),
                ("Pop It permanently enables ROM checks", 140),
                ("for that owner key on every boot.", 160),
                ("No vendor authority remains trusted.", 194),
            ]
        } else {
            [
                ("Before Pop It, signed KasSigner code is", 70),
                ("checked in software by the boot chain.", 90),
                ("After Pop It, the ESP32-S3 ROM also", 120),
                ("enforces the KasSigner signing-key digest", 140),
                ("from permanent eFuse on every boot.", 160),
                ("Owner-key enrollment closes after Pop It.", 194),
            ]
        };
        for (text, y) in lines {
            self.draw_pop_centered(text, y, if !dev_demo && y == 194 { COLOR_DANGER } else { COLOR_TEXT });
        }
        self.draw_pop_centered("Back returns without changing eFuses.", 220, COLOR_TEXT_DIM);
    }

    pub fn draw_pop_it_confirm(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        error: Option<&str>,
    ) {
        self.draw_keyboard_screen_full(input, "FINAL: TYPE POP IT");
        let hint = "Accepts: pop it / POP-IT / pop it!";
        let hw = measure_hint(hint);
        draw_lato_hint(&mut self.display, hint, ((320 - hw) / 2).max(2), 43, COLOR_TEXT_DIM);
        if let Some(message) = error {
            let clipped = truncate_chars(message, 46);
            let mw = measure_hint(clipped);
            draw_lato_hint(&mut self.display, clipped, ((320 - mw) / 2).max(2), 78, COLOR_DANGER);
        }
    }

    #[cfg(feature = "secure-provisioning-core")]
    pub fn draw_pop_it_applying(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let title = "POP IT!";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 55, KASPA_TEAL);
        self.draw_pop_centered("Preflight passed.", 102, COLOR_TEXT);
        self.draw_pop_centered("Restarting into the signed bootloader...", 132, COLOR_TEXT);
        self.draw_pop_centered("Hardware Secure Boot v2 will be enabled", 163, COLOR_DANGER);
        self.draw_pop_centered("only if final boot-chain checks pass.", 184, COLOR_DANGER);
    }

    fn draw_pop_centered(&mut self, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
        let width = measure_body(text);
        draw_lato_body(&mut self.display, text, ((320 - width) / 2).max(2), y, color);
    }

    fn draw_pop_button(&mut self, x: i32, label: &str, primary: bool) {
        let rect = Rectangle::new(Point::new(x, 181), Size::new(92, 45));
        let corners = CornerRadii::new(Size::new(7, 7));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_fill(if primary { KASPA_TEAL } else { COLOR_CARD }))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(if primary { COLOR_TEXT } else { COLOR_CARD_BORDER }, 1))
            .draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, x + (92 - width) / 2, 210, COLOR_TEXT);
    }

    fn draw_pop_wide_button(&mut self, y: i32, label: &str, primary: bool) {
        let rect = Rectangle::new(Point::new(12, y), Size::new(296, 30));
        let corners = CornerRadii::new(Size::new(7, 7));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_fill(if primary { KASPA_TEAL } else { COLOR_CARD }))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(if primary { COLOR_TEXT } else { COLOR_CARD_BORDER }, 1))
            .draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, (320 - width) / 2, y + 21, COLOR_TEXT);
    }
}

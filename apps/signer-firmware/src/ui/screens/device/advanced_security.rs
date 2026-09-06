//! Advanced irreversible security-policy screens.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_TEXT,
    COLOR_TEXT_DIM, KASPA_TEAL, CornerRadii, Drawable, Line, Point, Primitive,
    PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_hint, draw_lato_title,
    draw_oswald_header, measure_header, measure_hint, measure_title,
};
#[cfg(feature = "m5stack")]
use super::super::draw_lato_body;
use embedded_graphics::draw_target::DrawTarget;
use signer_firmware_core::advanced_policy::UtcDateTime;
#[cfg(feature = "m5stack")]
use signer_firmware_core::advanced_policy::SigningWindow;

pub(crate) const ADV_CARD_X: core::ops::RangeInclusive<u16> = 14..=306;
pub(crate) const DURESS_Y: core::ops::RangeInclusive<u16> = 38..=72;
pub(crate) const TIME_LOCK_Y: core::ops::RangeInclusive<u16> = 76..=110;
pub(crate) const WEEKLY_Y: core::ops::RangeInclusive<u16> = 114..=148;
pub(crate) const SD_STORAGE_Y: core::ops::RangeInclusive<u16> = 152..=186;
pub(crate) const RTC_Y: core::ops::RangeInclusive<u16> = 190..=224;
pub(crate) const WARNING_CANCEL_X: core::ops::RangeInclusive<u16> = 16..=148;
pub(crate) const WARNING_ENABLE_X: core::ops::RangeInclusive<u16> = 172..=304;
pub(crate) const WARNING_BUTTON_Y: core::ops::RangeInclusive<u16> = 193..=232;

impl<'a> BootDisplay<'a> {
    pub fn draw_advanced_features(&mut self, ad: &crate::runtime::data::AppData) {
        self.clear_keep_nav();
        let title = "SECURITY";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 26, KASPA_TEAL);
        Line::new(Point::new(18, 34), Point::new(302, 34))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        if !ad.storage.persistence.advanced.availability.is_available() {
            self.draw_unavailable_advanced_features(ad);
            return;
        }

        if !ad.storage.persistence.advanced.policy_integrity.is_valid() {
            self.draw_advanced_integrity_error();
            return;
        }

        self.draw_available_advanced_features(ad);
    }

    fn draw_unavailable_advanced_features(&mut self, ad: &crate::runtime::data::AppData) {
        let requirement = if ad.storage.persistence.advanced.saved_wallet {
            "Requires wallet PIN or password"
        } else {
            "Requires saved wallet"
        };
        self.draw_advanced_card(38, "Duress credential", requirement, false);
        self.draw_advanced_card(76, "No-sign-before", requirement, false);
        self.draw_advanced_card(114, "Weekly signing windows", requirement, false);
        self.draw_advanced_card(152, "Device-bound storage", requirement, false);
        #[cfg(feature = "m5stack")]
        self.draw_advanced_card(190, "Hardware RTC (UTC)", requirement, false);
        #[cfg(feature = "waveshare")]
        self.draw_advanced_card(190, "Time policies", "Unavailable: no hardware RTC", false);
    }

    fn draw_advanced_integrity_error(&mut self) {
        self.draw_advanced_card(38, "POLICY INTEGRITY ERROR", "Transaction signing fails closed", true);
        self.draw_advanced_card(76, "Recovery", "Full flash erase required", true);
    }

    fn draw_available_advanced_features(&mut self, ad: &crate::runtime::data::AppData) {

        let duress_status = if ad.storage.persistence.advanced.duress.is_enabled() {
            match ad.storage.persistence.advanced.credential_kind {
                Some(crate::services::credential_policy::CredentialKind::Pin) => "ENABLED PIN - READ ONLY",
                Some(crate::services::credential_policy::CredentialKind::Password) => "ENABLED PASSWORD - READ ONLY",
                None => "ENABLED - READ ONLY",
            }
        } else {
            "Optional - configure"
        };
        let duress_label = match ad.storage.persistence.advanced.credential_kind {
            Some(crate::services::credential_policy::CredentialKind::Pin) => "Duress PIN",
            Some(crate::services::credential_policy::CredentialKind::Password) => "Duress password",
            None => "Duress",
        };
        self.draw_advanced_card(38, duress_label, duress_status, ad.storage.persistence.advanced.duress.is_enabled());

        let mut time_buf = [0u8; 32];
        let time_status = if ad.storage.persistence.advanced.policy.not_before_unix != 0 {
            let len = format_datetime_unix(ad.storage.persistence.advanced.policy.not_before_unix, &mut time_buf);
            core::str::from_utf8(&time_buf[..len]).unwrap_or("ENABLED - READ ONLY")
        } else {
            "Optional - configure"
        };
        self.draw_advanced_card(76, "No-sign-before (UTC)", time_status, ad.storage.persistence.advanced.policy.not_before_unix != 0);

        let mut weekly_buf = [0u8; 32];
        let weekly_status = if ad.storage.persistence.advanced.policy.weekly_enabled {
            let len = format_window_count(ad.storage.persistence.advanced.policy.weekly_count, &mut weekly_buf);
            core::str::from_utf8(&weekly_buf[..len]).unwrap_or("ENABLED - READ ONLY")
        } else {
            "Optional - configure"
        };
        self.draw_advanced_card(114, "Weekly signing windows", weekly_status, ad.storage.persistence.advanced.policy.weekly_enabled);

        let sd_enabled = ad.storage.persistence.advanced.persistence_backend.is_sd();
        let sd_status = if sd_enabled {
            "SD - this KasSigner Device only"
        } else if ad.storage.persistence.advanced.outer_device_only {
            "Unavailable with per-wallet protection"
        } else {
            "Optional - bind wallet to SD"
        };
        self.draw_advanced_card(152, "Device-bound storage", sd_status, sd_enabled);

        #[cfg(feature = "m5stack")]
        {
            let rtc_status = if ad.storage.persistence.advanced.policy.has_time_policy() {
                "LOCKED - READ ONLY"
            } else if ad.storage.persistence.advanced.rtc_verification.is_verified() {
                "UTC verified for this session"
            } else {
                "Set/verify current UTC time first"
            };
            self.draw_advanced_card(190, "Hardware RTC (UTC)", rtc_status, ad.storage.persistence.advanced.policy.has_time_policy());
        }
        #[cfg(feature = "waveshare")]
        self.draw_advanced_card(190, "Time policies", "Unavailable: no hardware RTC", false);
    }

    pub fn draw_advanced_warning(&mut self, title: &str, line1: &str, line2: &str, line3: &str) {
        self.display.clear(COLOR_DANGER).ok();
        let permanent = "PERMANENT";
        let pw = measure_header(permanent);
        draw_oswald_header(&mut self.display, permanent, (320 - pw) / 2, 31, COLOR_TEXT);
        let tw = measure_title(title);
        draw_lato_title(&mut self.display, title, (320 - tw) / 2, 60, COLOR_TEXT);
        let undo = "CANNOT BE UNDONE";
        let uw = measure_title(undo);
        draw_lato_title(&mut self.display, undo, (320 - uw) / 2, 88, COLOR_TEXT);
        self.draw_warning_line(line1, 116);
        self.draw_warning_line(line2, 137);
        self.draw_warning_line(line3, 158);
        self.draw_warning_button(16, "CANCEL", false);
        self.draw_warning_button(172, "CONTINUE", true);
    }

    pub fn draw_factory_reset_confirmation(&mut self) {
        self.display.clear(COLOR_DANGER).ok();
        let permanent = "FINAL CONFIRMATION";
        let pw = measure_header(permanent);
        draw_oswald_header(&mut self.display, permanent, (320 - pw) / 2, 31, COLOR_TEXT);
        let title = "ERASE ALL USER DATA?";
        let tw = measure_title(title);
        draw_lato_title(&mut self.display, title, (320 - tw) / 2, 67, COLOR_TEXT);
        self.draw_warning_line("Saved wallets and settings are erased.", 112);
        self.draw_warning_line("Recovery requires your external backups.", 137);
        self.draw_warning_line("This action cannot be reversed.", 162);
        self.draw_warning_button(16, "CANCEL", false);
        self.draw_warning_button(172, "ERASE", true);
    }

    #[cfg(feature = "m5stack")]
    pub fn draw_advanced_final_warning(&mut self, title: &str, line1: &str, line2: &str) {
        self.display.clear(COLOR_DANGER).ok();
        let permanent = "FINAL CONFIRMATION";
        let pw = measure_header(permanent);
        draw_oswald_header(&mut self.display, permanent, (320 - pw) / 2, 31, COLOR_TEXT);
        let tw = measure_title(title);
        draw_lato_title(&mut self.display, title, (320 - tw) / 2, 67, COLOR_TEXT);
        self.draw_warning_line(line1, 112);
        self.draw_warning_line(line2, 137);
        self.draw_warning_line("Only full flash erase can remove it.", 162);
        self.draw_warning_button(16, "CANCEL", false);
        self.draw_warning_button(172, "ENABLE", true);
    }

    #[cfg(feature = "m5stack")]
    pub fn draw_advanced_text_entry(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        title: &str,
        hint: &str,
    ) {
        self.draw_keyboard_screen_full(input, title);
        // Keep format guidance inside the existing editable input strip. This
        // avoids painting over either the title separator or the first key row.
        if input.len == 0 {
            let hw = measure_hint(hint);
            draw_lato_hint(
                &mut self.display, hint, ((320 - hw) / 2).max(40), 62, COLOR_TEXT_DIM,
            );
        }
    }

#[cfg(feature = "m5stack")]
    pub fn draw_time_lock_confirmation(&mut self, unix: u64) {
        let mut buf = [0u8; 32];
        let len = format_datetime_unix(unix, &mut buf);
        let value = core::str::from_utf8(&buf[..len]).unwrap_or("INVALID");
        self.draw_advanced_final_warning("ENABLE NO-SIGN-BEFORE?", value, "Transactions stay locked until then.");
    }

#[cfg(feature = "m5stack")]
    pub fn draw_weekly_confirmation(&mut self, count: u8) {
        let mut buf = [0u8; 32];
        let len = format_window_count(count, &mut buf);
        let value = core::str::from_utf8(&buf[..len]).unwrap_or("INVALID");
        self.draw_advanced_final_warning("ENABLE SIGNING WINDOWS?", value, "All other times will be refused.");
    }

#[cfg(feature = "m5stack")]
    pub fn draw_weekly_policy_readonly(&mut self, windows: &[SigningWindow], count: u8) {
        self.clear_keep_nav();
        let title = "WEEKLY WINDOWS";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 24, KASPA_TEAL);
        let readonly = "READ ONLY";
        let rw = measure_hint(readonly);
        draw_lato_hint(&mut self.display, readonly, (320 - rw) / 2, 43, COLOR_TEXT_DIM);
        let mut y = 67i32;
        for window in windows.iter().take(count as usize) {
            let mut buf = [0u8; 32];
            let len = format_window(*window, &mut buf);
            if let Ok(text) = core::str::from_utf8(&buf[..len]) {
                draw_lato_body(&mut self.display, text, 35, y, COLOR_TEXT);
            }
            y += 31;
        }
        let msg = "Immutable until full flash erase";
        let mw = measure_hint(msg);
        draw_lato_hint(&mut self.display, msg, (320 - mw) / 2, 213, COLOR_TEXT_DIM);
    }

    fn draw_advanced_card(&mut self, y: i32, label: &str, status: &str, danger: bool) {
        let rectangle = Rectangle::new(Point::new(14, y), Size::new(292, 34));
        let corners = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_stroke(if danger { COLOR_DANGER } else { COLOR_CARD_BORDER }, 1))
            .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, label, 22, y + 16, COLOR_TEXT);
        draw_lato_hint(&mut self.display, status, 22, y + 31, if danger { COLOR_DANGER } else { COLOR_TEXT_DIM });
    }

    fn draw_warning_line(&mut self, text: &str, y: i32) {
        let width = measure_hint(text);
        draw_lato_hint(&mut self.display, text, ((320 - width) / 2).max(2), y, COLOR_TEXT);
    }

    pub(crate) fn draw_warning_button(&mut self, x: i32, label: &str, strong: bool) {
        let rectangle = Rectangle::new(Point::new(x, 193), Size::new(132, 39));
        let corners = CornerRadii::new(Size::new(6, 6));
        let fill = if strong { COLOR_BG } else { COLOR_DANGER };
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_fill(fill)).draw(&mut self.display).ok();
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 2)).draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, x + (132 - width) / 2, 218, COLOR_TEXT);
    }
}

fn format_datetime_unix(unix: u64, out: &mut [u8; 32]) -> usize {
    let Ok(value) = UtcDateTime::from_unix_seconds(unix) else {
        out[..7].copy_from_slice(b"INVALID");
        return 7;
    };
    let mut cursor = 0usize;
    cursor += write_u4(value.year, &mut out[cursor..]);
    out[cursor] = b'-'; cursor += 1;
    cursor += write_u2(value.month, &mut out[cursor..]);
    out[cursor] = b'-'; cursor += 1;
    cursor += write_u2(value.day, &mut out[cursor..]);
    out[cursor] = b' '; cursor += 1;
    cursor += write_u2(value.hour, &mut out[cursor..]);
    out[cursor] = b':'; cursor += 1;
    cursor += write_u2(value.minute, &mut out[cursor..]);
    out[cursor..cursor + 4].copy_from_slice(b" UTC");
    cursor + 4
}

fn format_window_count(count: u8, out: &mut [u8; 32]) -> usize {
    let prefix = b"ENABLED - ";
    out[..prefix.len()].copy_from_slice(prefix);
    let mut cursor = prefix.len();
    out[cursor] = b'0' + count.min(9); cursor += 1;
    let suffix: &[u8] = if count == 1 { b" window" } else { b" windows" };
    out[cursor..cursor + suffix.len()].copy_from_slice(suffix);
    cursor + suffix.len()
}

#[cfg(feature = "m5stack")]
fn format_window(window: SigningWindow, out: &mut [u8; 32]) -> usize {
    let day = match window.weekday {
        0 => b"MON", 1 => b"TUE", 2 => b"WED", 3 => b"THU", 4 => b"FRI", 5 => b"SAT", _ => b"SUN",
    };
    out[..3].copy_from_slice(day);
    out[3] = b' ';
    write_u2((window.start_minute / 60) as u8, &mut out[4..]);
    out[6] = b':';
    write_u2((window.start_minute % 60) as u8, &mut out[7..]);
    out[9] = b'-';
    write_u2((window.end_minute / 60) as u8, &mut out[10..]);
    out[12] = b':';
    write_u2((window.end_minute % 60) as u8, &mut out[13..]);
    out[15..19].copy_from_slice(b" UTC");
    19
}

fn write_u2(value: u8, out: &mut [u8]) -> usize {
    out[0] = b'0' + value / 10;
    out[1] = b'0' + value % 10;
    2
}

fn write_u4(value: u16, out: &mut [u8]) -> usize {
    out[0] = b'0' + ((value / 1000) % 10) as u8;
    out[1] = b'0' + ((value / 100) % 10) as u8;
    out[2] = b'0' + ((value / 10) % 10) as u8;
    out[3] = b'0' + (value % 10) as u8;
    4
}

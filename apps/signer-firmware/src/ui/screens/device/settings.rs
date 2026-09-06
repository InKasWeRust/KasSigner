// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::super::{
    BootDisplay, COLOR_CARD, COLOR_TEXT, COLOR_TEXT_DIM, CornerRadii, Drawable,
    KASPA_TEAL, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle, Size,
    draw_lato_body, draw_lato_title, measure_body, measure_title,
};

pub(crate) const DISPLAY_DIM_ROW_Y: core::ops::RangeInclusive<u16> = 148..=181;
pub(crate) const DISPLAY_PIN_ROW_Y: core::ops::RangeInclusive<u16> = 188..=221;
#[cfg(feature = "m5stack")]
pub(crate) const AUDIO_STARTUP_ROW_Y: core::ops::RangeInclusive<u16> = 164..=207;

impl<'a> BootDisplay<'a> {
    /// Draw display settings. Brightness is always session-available. Device-
    /// persistent dim/lock controls are deliberately hidden for one-time
    /// mnemonic sessions.
    pub fn draw_display_settings(
        &mut self,
        brightness: u8,
        persistent_controls: bool,
        dim_timeout: crate::runtime::data::ScreenDimTimeout,
        pin_lock_available: bool,
        require_pin: bool,
    ) {
        self.draw_level_settings("DISPLAY", "Brightness:", brightness);
        if !persistent_controls {
            self.draw_session_only_hint();
            return;
        }
        self.draw_setting_row("Dim after", dim_timeout.label(), 148);
        if pin_lock_available {
            self.draw_setting_row("Require PIN", if require_pin { "ON" } else { "OFF" }, 188);
        } else {
            let text = "PIN lock unavailable";
            let width = measure_body(text);
            draw_lato_body(&mut self.display, text, (320 - width) / 2, 214, COLOR_TEXT_DIM);
        }
    }

    /// Partial redraw: only the brightness bar fill + percentage text.
    #[cfg(feature = "waveshare")]
    pub fn update_brightness_bar(&mut self, brightness: u8) {
        self.update_level_bar(brightness);
    }

    /// Draw audio settings. Volume remains session-local; startup sound is a
    /// future-boot preference and is hidden when the active wallet is one-time.
    #[cfg(feature = "m5stack")]
    pub fn draw_audio_settings(
        &mut self,
        volume: u8,
        persistent_controls: bool,
        startup_sound_enabled: bool,
    ) {
        self.draw_level_settings("AUDIO", "Volume:", volume);
        if persistent_controls {
            self.draw_setting_row(
                "Startup sound",
                if startup_sound_enabled { "ON" } else { "OFF" },
                168,
            );
        } else {
            self.draw_session_only_hint();
        }
    }

    fn draw_setting_row(&mut self, label: &str, value: &str, y: i32) {
        let rectangle = Rectangle::new(Point::new(34, y), Size::new(252, 34));
        let corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();
        draw_lato_body(&mut self.display, label, 48, y + 22, COLOR_TEXT);
        let width = measure_title(value);
        draw_lato_title(&mut self.display, value, 272 - width, y + 23, KASPA_TEAL);
    }

    fn draw_session_only_hint(&mut self) {
        let line1 = "One-time wallet session";
        let line2 = "Persistent options hidden";
        let w1 = measure_body(line1);
        let w2 = measure_body(line2);
        draw_lato_body(&mut self.display, line1, (320 - w1) / 2, 174, COLOR_TEXT_DIM);
        draw_lato_body(&mut self.display, line2, (320 - w2) / 2, 198, COLOR_TEXT_DIM);
    }
}

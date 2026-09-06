use super::super::{
    BootDisplay, COLOR_HINT, Drawable, KASPA_TEAL, Point, Rgb565, draw_lato_hint,
    draw_lato_title, measure_hint, measure_title, sound,
};
#[cfg(feature = "m5stack")]
use super::super::{
    COLOR_BG, COLOR_DANGER, COLOR_TEXT_DIM, draw_lato_body, draw_oswald_header,
    measure_body, measure_header,
};

impl<'a> BootDisplay<'a> {
    /// Draw a success screen with a message.
    pub fn draw_success_screen(&mut self, message: &str) {
        sound::stop_ticking();
        use embedded_graphics::image::{Image, ImageRawLE};

        static LOGO_DATA: &[u8] = include_bytes!("../../../../assets/logo_320x240.raw");
        let raw_image: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_image, Point::zero())
            .draw(&mut self.display)
            .ok();

        let mut message_text: heapless::String<64> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut message_text, format_args!("!! {message} !!")).ok();
        let title_width = measure_title(message_text.as_str());
        draw_lato_title(
            &mut self.display,
            message_text.as_str(),
            (320 - title_width) / 2,
            170,
            KASPA_TEAL,
        );

        let hint = "Tap to continue";
        let hint_width = measure_hint(hint);
        draw_lato_hint(
            &mut self.display,
            hint,
            (320 - hint_width) / 2,
            222,
            COLOR_HINT,
        );
    }
    /// Show the previous-reset recovery reason before normal wallet startup.
    #[cfg(feature = "m5stack")]
    pub fn draw_system_recovery_screen(&mut self, title: &str, detail: &str, code: &str) {
        embedded_graphics::draw_target::DrawTarget::clear(&mut self.display, COLOR_BG).ok();
        let title_width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - title_width) / 2, 45, COLOR_DANGER);
        let detail_width = measure_body(detail);
        draw_lato_body(&mut self.display, detail, (320 - detail_width) / 2, 110, COLOR_TEXT_DIM);
        let code_width = measure_title(code);
        draw_lato_title(&mut self.display, code, (320 - code_width) / 2, 155, KASPA_TEAL);
        let hint = "Startup will continue automatically";
        let hint_width = measure_hint(hint);
        draw_lato_hint(&mut self.display, hint, (320 - hint_width) / 2, 215, COLOR_HINT);
    }

}

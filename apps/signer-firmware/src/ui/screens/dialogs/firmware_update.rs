use super::super::{
    BootDisplay, COLOR_HINT, COLOR_TEXT, Drawable, KASPA_TEAL, Line,
    Point, Primitive, PrimitiveStyle, draw_lato_body, draw_lato_hint, draw_lato_title,
    draw_oswald_header, measure_header, measure_hint,
};

impl<'a> BootDisplay<'a> {
    /// Draw host-assisted USB firmware upgrade guidance. The signer never enters
    /// the camera scanner or accepts a QR as the Settings firmware-update path.
    pub fn draw_firmware_update_ready_screen(&mut self) {
        self.clear_keep_nav();
        let title = "READY TO UPDATE";
        let title_width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - title_width) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        draw_lato_title(&mut self.display, "USB FIRMWARE UPDATE", 32, 72, KASPA_TEAL);
        draw_lato_body(&mut self.display, "1. Connect USB-C to computer", 30, 108, COLOR_TEXT);
        draw_lato_body(&mut self.display, "2. Run: make flash BOARD=m5stack", 30, 134, COLOR_TEXT);
        draw_lato_body(&mut self.display, "3. Keep USB connected until done", 30, 160, COLOR_TEXT);
        draw_lato_hint(&mut self.display, "Firmware is verified after reboot", 43, 192, COLOR_HINT);
        let hint = "Back to Advanced";
        let hint_width = measure_hint(hint);
        draw_lato_hint(&mut self.display, hint, (320 - hint_width) / 2, 218, COLOR_HINT);
    }

}

use super::super::{
    BootDisplay, COLOR_BG, COLOR_GREEN_BTN, COLOR_RED_BTN, COLOR_TEXT, COLOR_TEXT_DIM, CornerRadii,
    Drawable, KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle,
    RoundedRectangle, Size, draw_lato_body, draw_lato_title, draw_oswald_header, measure_body,
    measure_header, measure_title,
};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_send_confirmation_layout(
        &mut self,
        header: &str,
        amount: &str,
        fee: &str,
        change: &str,
        destination: &str,
    ) {
        self.clear_keep_nav();

        let title_width = measure_header(header);
        draw_oswald_header(&mut self.display, header, (320 - title_width) / 2, 28, COLOR_TEXT);
        Line::new(Point::new(20, 41), Point::new(300, 41))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        self.draw_confirm_line("Send", amount, 62, COLOR_TEXT);
        self.draw_confirm_line("Fee", fee, 84, COLOR_TEXT);
        self.draw_confirm_line("Change", change, 106, KASPA_ACCENT);
        self.draw_confirm_line("To", destination, 136, KASPA_TEAL);

        let hint = "Inspect for full transaction details";
        let hint_width = measure_body(hint);
        draw_lato_body(
            &mut self.display,
            hint,
            (320 - hint_width) / 2,
            164,
            COLOR_TEXT_DIM,
        );

        self.draw_confirm_action(15, "CONFIRM", ConfirmActionStyle::Confirm);
        self.draw_confirm_action(115, "INSPECT", ConfirmActionStyle::Inspect);
        self.draw_confirm_action(215, "CANCEL", ConfirmActionStyle::Cancel);
    }

    fn draw_confirm_action(&mut self, x: i32, label: &str, style: ConfirmActionStyle) {
        let rect = Rectangle::new(Point::new(x, 188), Size::new(90, 40));
        let corners = CornerRadii::new(Size::new(7, 7));
        let (fill, stroke) = match style {
            ConfirmActionStyle::Confirm => (Some(COLOR_GREEN_BTN), KASPA_TEAL),
            ConfirmActionStyle::Inspect => (Some(COLOR_BG), KASPA_ACCENT),
            ConfirmActionStyle::Cancel => (Some(COLOR_RED_BTN), COLOR_RED_BTN),
        };
        if let Some(fill) = fill {
            RoundedRectangle::new(rect, corners)
                .into_styled(PrimitiveStyle::with_fill(fill))
                .draw(&mut self.display).ok();
        }
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(stroke, 2))
            .draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, x + (90 - width) / 2, 214, COLOR_TEXT);
    }

    fn draw_confirm_line(
        &mut self,
        label: &str,
        value: &str,
        y: i32,
        color: embedded_graphics::pixelcolor::Rgb565,
    ) {
        let mut line: heapless::String<48> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut line, format_args!("{label}: {value}")).ok();
        let width = measure_body(line.as_str());
        draw_lato_body(&mut self.display, line.as_str(), (320 - width) / 2, y, color);
    }
}

enum ConfirmActionStyle {
    Confirm,
    Inspect,
    Cancel,
}

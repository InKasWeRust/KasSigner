use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_TEXT, Drawable, KASPA_ACCENT,
    KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle, Size,
    CornerRadii, draw_lato_body, draw_lato_title, draw_oswald_header, measure_body,
    measure_header, measure_title};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_level_settings(
        &mut self,
        header: &str,
        label: &str,
        value: u8,
    ) {
        self.clear_keep_nav();

        let title_width = measure_header(header);
        draw_oswald_header(
            &mut self.display,
            header,
            (320 - title_width) / 2,
            30,
            COLOR_TEXT,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        let label_width = measure_body(label);
        draw_lato_body(
            &mut self.display,
            label,
            (320 - label_width) / 2,
            65,
            COLOR_TEXT,
        );

        let button_corner = CornerRadii::new(Size::new(6, 6));
        for (x, text, text_x) in [(20, "-", 33), (260, "+", 272)] {
            let button = Rectangle::new(Point::new(x, 80), Size::new(40, 30));
            RoundedRectangle::new(button, button_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display)
                .ok();
            RoundedRectangle::new(button, button_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display)
                .ok();
            draw_lato_title(&mut self.display, text, text_x, 101, COLOR_TEXT);
        }

        self.update_level_bar(value);
    }

    pub(crate) fn update_level_bar(&mut self, value: u8) {
        Rectangle::new(Point::new(70, 85), Size::new(180, 20))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display)
            .ok();
        Rectangle::new(Point::new(70, 85), Size::new(180, 20))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 1))
            .draw(&mut self.display)
            .ok();

        let bar_width = u32::from(value) * 180 / 255;
        if bar_width > 0 {
            Rectangle::new(Point::new(70, 85), Size::new(bar_width, 20))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display)
                .ok();
        }

        Rectangle::new(Point::new(100, 115), Size::new(120, 30))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display)
            .ok();

        let percent = u16::from(value) * 100 / 255;
        let mut percent_text: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut percent_text, format_args!("{percent}%")).ok();
        let width = measure_title(percent_text.as_str());
        draw_lato_title(
            &mut self.display,
            percent_text.as_str(),
            (320 - width) / 2,
            135,
            COLOR_TEXT,
        );
    }
}

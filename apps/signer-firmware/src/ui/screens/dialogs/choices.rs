use super::super::{
    BootDisplay, COLOR_BG, COLOR_HINT, CornerRadii, Drawable, KASPA_TEAL,
    Line, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle, Size,
    draw_lato_hint, draw_lato_title, draw_oswald_header, measure_header, measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    pub fn draw_import_export_choice(&mut self) {
        self.draw_two_option_choice("IMPORT / EXPORT", "Import", "Export", None, None);
    }

    fn draw_two_option_choice(
        &mut self,
        header: &str,
        left_label: &str,
        right_label: &str,
        left_hint: Option<&str>,
        right_hint: Option<&str>,
    ) {
        self.clear_keep_nav();
        let title_width = measure_header(header);
        draw_oswald_header(
            &mut self.display,
            header,
            (320 - title_width) / 2,
            30,
            KASPA_TEAL,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        let button_width = 130i32;
        let button_height = 55i32;
        let button_y = 100i32;
        let gap = 16i32;
        let left_x = (320 - 2 * button_width - gap) / 2;
        let right_x = left_x + button_width + gap;
        let corners = CornerRadii::new(Size::new(6, 6));
        for (x, label) in [(left_x, left_label), (right_x, right_label)] {
            let rectangle = Rectangle::new(
                Point::new(x, button_y),
                Size::new(button_width as u32, button_height as u32),
            );
            RoundedRectangle::new(rectangle, corners)
                .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
                .draw(&mut self.display)
                .ok();
            let label_width = measure_title(label);
            draw_lato_title(
                &mut self.display,
                label,
                x + (button_width - label_width) / 2,
                button_y + 35,
                COLOR_BG,
            );
        }
        for (x, hint) in [(left_x, left_hint), (right_x, right_hint)] {
            if let Some(hint) = hint {
                let hint_width = measure_hint(hint);
                draw_lato_hint(
                    &mut self.display,
                    hint,
                    x + (button_width - hint_width) / 2,
                    button_y + button_height + 14,
                    COLOR_HINT,
                );
            }
        }
    }
}

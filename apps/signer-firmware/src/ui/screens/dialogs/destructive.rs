use super::super::{
    BootDisplay, COLOR_DANGER, COLOR_ORANGE, COLOR_TEXT, CornerRadii, Drawable,
    KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle, Size,
    draw_lato_body, draw_lato_title, draw_oswald_header, measure_body, measure_header,
    measure_title};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_destructive_confirmation(
        &mut self,
        header: &str,
        subject: &str,
        warning_lines: [&str; 3],
    ) {
        self.clear_keep_nav();

        let title_width = measure_header(header);
        draw_oswald_header(
            &mut self.display,
            header,
            (320 - title_width) / 2,
            30,
            COLOR_ORANGE,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
            .draw(&mut self.display)
            .ok();

        let subject_width = measure_body(subject);
        draw_lato_body(
            &mut self.display,
            subject,
            (320 - subject_width) / 2,
            65,
            COLOR_TEXT,
        );
        for (line, y) in warning_lines.into_iter().zip([95, 120, 145]) {
            let width = measure_body(line);
            let color = if y == 95 { COLOR_ORANGE } else { COLOR_TEXT };
            draw_lato_body(&mut self.display, line, (320 - width) / 2, y, color);
        }

        let corner = CornerRadii::new(Size::new(8, 8));
        let cancel = Rectangle::new(Point::new(30, 185), Size::new(120, 40));
        RoundedRectangle::new(cancel, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display)
            .ok();
        let cancel_width = measure_title("CANCEL");
        draw_lato_title(
            &mut self.display,
            "CANCEL",
            30 + (120 - cancel_width) / 2,
            212,
            KASPA_TEAL,
        );

        let delete = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
        RoundedRectangle::new(delete, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_DANGER))
            .draw(&mut self.display)
            .ok();
        let delete_width = measure_title("DELETE");
        draw_lato_title(
            &mut self.display,
            "DELETE",
            170 + (120 - delete_width) / 2,
            212,
            COLOR_TEXT,
        );
    }
}

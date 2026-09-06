use embedded_iconoir::prelude::IconoirNewIcon;
use super::super::{
    BootDisplay, COLOR_CARD, COLOR_TEXT, COLOR_TEXT_DIM, CornerRadii, Drawable,
    Image, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle,
    Size, draw_lato_body, draw_lato_title, draw_oswald_header, measure_body, measure_header,
    size24px};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_input_source_choice(
        &mut self,
        header: &str,
        subtitle: &str,
        include_qr: bool,
    ) {
        self.clear_keep_nav();
        let title_width = measure_header(header);
        draw_oswald_header(&mut self.display, header, (320 - title_width) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let subtitle_width = measure_body(subtitle);
        draw_lato_body(&mut self.display, subtitle, (320 - subtitle_width) / 2, 60, COLOR_TEXT_DIM);

        let rows = if include_qr { 3 } else { 2 };
        for row in 0..rows {
            let y = 70 + row * 46;
            let rect = Rectangle::new(Point::new(44, y), Size::new(232, 42));
            let corner = CornerRadii::new(Size::new(6, 6));
            RoundedRectangle::new(rect, corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(rect, corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            match row {
                0 => {
                    let icon = size24px::editor::EditPencil::new(KASPA_TEAL);
                    Image::new(&icon, Point::new(50, y + 9)).draw(&mut self.display).ok();
                    draw_lato_title(&mut self.display, "Type manually", 86, y + 28, COLOR_TEXT);
                }
                1 => {
                    let icon = size24px::design_tools::Crop::new(KASPA_TEAL);
                    Image::new(&icon, Point::new(50, y + 9)).draw(&mut self.display).ok();
                    draw_lato_title(&mut self.display, "Scan message QR", 86, y + 28, COLOR_TEXT);
                }
                _ => {
                    let icon = size24px::docs::Page::new(KASPA_TEAL);
                    Image::new(&icon, Point::new(50, y + 9)).draw(&mut self.display).ok();
                    draw_lato_title(&mut self.display, "Load .TXT from SD", 86, y + 28, COLOR_TEXT);
                }
            }
        }
    }
}

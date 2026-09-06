//! Transaction review footer with explicit inspection/navigation controls.
use super::{
    BootDisplay, COLOR_TEXT, COLOR_TEXT_DIM, Drawable, KASPA_ACCENT, KASPA_TEAL, Point,
    PrimitiveStyle, draw_lato_body, measure_body,
};
use embedded_graphics::{
    prelude::{Primitive, Size},
    primitives::{CornerRadii, Rectangle, RoundedRectangle},
};
use core::fmt::Write;

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_tx_footer(&mut self, page: u8, total_pages: u8) {
        let mut page_text = heapless::String::<32>::new();
        write!(&mut page_text, "Page {}/{}", page + 1, total_pages).ok();
        let pw = measure_body(page_text.as_str());
        draw_lato_body(
            &mut self.display,
            page_text.as_str(),
            (320 - pw) / 2,
            219,
            COLOR_TEXT_DIM,
        );

        if page == 0 {
            self.draw_review_footer_button(18, "Inspect", true);
        }
        self.draw_review_footer_button(224, "Next", false);
        self.draw_back_button();
    }

    fn draw_review_footer_button(&mut self, x: i32, label: &str, accent: bool) {
        let rect = Rectangle::new(Point::new(x, 194), Size::new(78, 34));
        let corners = CornerRadii::new(Size::new(7, 7));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(if accent { KASPA_ACCENT } else { KASPA_TEAL }, 2))
            .draw(&mut self.display).ok();
        let width = measure_body(label);
        draw_lato_body(
            &mut self.display,
            label,
            x + (78 - width) / 2,
            216,
            COLOR_TEXT,
        );
    }
}

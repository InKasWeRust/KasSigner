use super::super::{
    BootDisplay, COLOR_CARD, COLOR_TEXT, CornerRadii, Drawable, Image, KASPA_TEAL, Point,
    Primitive, PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_title,
    measure_title,
};
use crate::hw::touch::TouchZone;

// Use the full physical right edge. CoreS3 samples can legitimately report
// x=319 for a press on the visible right-most pixel; keeping the scanner
// controls one source of truth prevents rendering/hit-testing drift.
// The brightness glyph sits between the two controls and is intentionally
// non-interactive: only the explicit minus/plus zones change brightness.
pub const QR_BRIGHTNESS_MINUS_ZONE: TouchZone = TouchZone::new(272, 72, 48, 30);
pub const QR_BRIGHTNESS_PLUS_ZONE: TouchZone = TouchZone::new(272, 134, 48, 30);
const QR_BRIGHTNESS_ICON_ORIGIN: Point = Point::new(284, 105);

impl<'a> BootDisplay<'a> {
    /// Shared scanner-assist chrome for every scannable QR presentation. The
    /// right rail stays outside all normal QR render regions and, for signed
    /// multi-frame output, occupies the gap between signer and frame badges.
    pub(in crate::ui::screens) fn draw_qr_brightness_controls(&mut self) {
        // Every scannable QR gets the same explicit Back + scanner brightness
        // chrome. Home remains a global post-Home overlay drawn by redraw.rs.
        self.draw_back_button();
        self.draw_qr_brightness_button(QR_BRIGHTNESS_MINUS_ZONE, "-");
        self.draw_qr_brightness_icon();
        self.draw_qr_brightness_button(QR_BRIGHTNESS_PLUS_ZONE, "+");
    }

    fn draw_qr_brightness_icon(&mut self) {
        use embedded_graphics::image::ImageRawLE;

        static ICON_BRIGHTNESS: &[u8] = include_bytes!("../../../../assets/icon_brightness_24.raw");
        let icon: ImageRawLE<super::super::Rgb565> = ImageRawLE::new(ICON_BRIGHTNESS, 24);
        Image::new(&icon, QR_BRIGHTNESS_ICON_ORIGIN)
            .draw(&mut self.display)
            .ok();
    }

    fn draw_qr_brightness_button(&mut self, zone: TouchZone, label: &str) {
        let x = i32::from(zone.x);
        let y = i32::from(zone.y);
        let rect = Rectangle::new(Point::new(x, y), Size::new(u32::from(zone.w), u32::from(zone.h)));
        let corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(rect, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        RoundedRectangle::new(rect, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, x + (i32::from(zone.w) - width) / 2, y + 21, COLOR_TEXT);
    }
}

use super::super::{
    BootDisplay, COLOR_BG, COLOR_DANGER, COLOR_TEXT, DrawTarget, Drawable, Point, Primitive,
    PrimitiveStyle, Rectangle, Size, draw_lato_title, measure_title, sound,
};

#[derive(Clone, Copy)]
pub(in crate::ui::screens) struct QrRenderOptions {
    pub(in crate::ui::screens) x: i32,
    pub(in crate::ui::screens) y: i32,
    pub(in crate::ui::screens) width: i32,
    pub(in crate::ui::screens) height: i32,
    pub(in crate::ui::screens) quiet_zone: i32,
}

#[derive(Clone, Copy)]
pub(in crate::ui::screens) struct QrScreenOptions {
    pub(in crate::ui::screens) region: QrRenderOptions,
    pub(in crate::ui::screens) max_payload_bytes: Option<usize>,
    pub(in crate::ui::screens) stop_sound: bool,
    pub(in crate::ui::screens) error_title: &'static str,
    pub(in crate::ui::screens) too_large_title: &'static str,
}

impl<'a> BootDisplay<'a> {

    pub(in crate::ui::screens) fn draw_qr_screen_with_options(
        &mut self,
        data: &[u8],
        options: QrScreenOptions,
    ) -> bool {
        if options.stop_sound {
            sound::stop_ticking();
        }
        self.display.clear(COLOR_BG).ok();
        if options
            .max_payload_bytes
            .is_some_and(|maximum| data.len() > maximum)
        {
            self.draw_centered_qr_error(options.too_large_title);
            return false;
        }
        if self.draw_encoded_qr(data, options.region) {
            true
        } else {
            self.draw_centered_qr_error(options.error_title);
            false
        }
    }

    fn draw_centered_qr_error(&mut self, title: &str) {
        let width = measure_title(title);
        draw_lato_title(
            &mut self.display,
            title,
            (320 - width) / 2,
            120,
            COLOR_DANGER,
        );
    }
    pub(in crate::ui::screens) fn draw_encoded_qr(
        &mut self,
        data: &[u8],
        options: QrRenderOptions,
    ) -> bool {
        let Ok(qr) = crate::qr::encoder::encode(data) else { return false; };
        let rendered = self.draw_qr_matrix(&qr, options);
        if rendered { self.draw_qr_brightness_controls(); }
        rendered
    }

    pub(in crate::ui::screens) fn draw_numeric_qr(
        &mut self,
        data: &[u8],
        options: QrRenderOptions,
    ) -> bool {
        let Ok(qr) = crate::qr::encoder::encode_numeric(data) else { return false; };
        let rendered = self.draw_qr_matrix(&qr, options);
        if rendered { self.draw_qr_brightness_controls(); }
        rendered
    }

    fn draw_qr_matrix(
        &mut self,
        qr: &crate::qr::encoder::QrCode,
        options: QrRenderOptions,
    ) -> bool {
        let qr_size = i32::from(qr.size);
        let usable_width = options.width - options.quiet_zone * 2;
        let usable_height = options.height - options.quiet_zone * 2;
        let scale = (usable_width.min(usable_height) / qr_size).max(1);
        let total = qr_size * scale;
        let offset_x = options.x + (options.width - total) / 2;
        let offset_y = options.y + (options.height - total) / 2;

        Rectangle::new(
            Point::new(offset_x - options.quiet_zone, offset_y - options.quiet_zone),
            Size::new(
                (total + options.quiet_zone * 2) as u32,
                (total + options.quiet_zone * 2) as u32,
            ),
        )
        .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
        .draw(&mut self.display)
        .ok();

        for y in 0..qr_size {
            for x in 0..qr_size {
                if qr.get(x as u8, y as u8) {
                    Rectangle::new(
                        Point::new(offset_x + x * scale, offset_y + y * scale),
                        Size::new(scale as u32, scale as u32),
                    )
                    .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                    .draw(&mut self.display)
                    .ok();
                }
            }
        }
        true
    }
}

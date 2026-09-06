use embedded_graphics::prelude::DrawTarget;
use super::super::{
    BootDisplay, COLOR_BG, COLOR_DANGER, COLOR_HINT, KASPA_TEAL, draw_lato_hint,
    draw_lato_title, measure_hint, measure_title,
};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_seed_qr_payload(
        &mut self,
        data: &[u8],
        title: &str,
        numeric: bool,
    ) {
        self.display.clear(COLOR_BG).ok();
        let title_width = measure_hint(title);
        draw_lato_hint(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            14,
            KASPA_TEAL,
        );

        let hint = "Tap for grid view";
        let hint_width = measure_hint(hint);
        draw_lato_hint(
            &mut self.display,
            hint,
            (320 - hint_width) / 2,
            238,
            COLOR_HINT,
        );

        let options = super::qr_renderer::QrRenderOptions {
            x: 56,
            y: 20,
            width: 208,
            height: 210,
            quiet_zone: 4,
        };
        let rendered = if numeric {
            self.draw_numeric_qr(data, options)
        } else {
            self.draw_encoded_qr(data, options)
        };

        if !rendered {
            let error_width = measure_title("QR Error");
            draw_lato_title(
                &mut self.display,
                "QR Error",
                (320 - error_width) / 2,
                120,
                COLOR_DANGER,
            );
        }

        // This screen clears the full frame for the QR, so restore Back after
        // rendering. The normal redraw epilogue overlays Home separately.
        self.draw_back_button();
    }
}

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_HINT, COLOR_TEXT,
    CornerRadii, DrawTarget, Drawable, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle,
    Rectangle, RoundedRectangle, Size, draw_lato_body, draw_lato_hint, draw_lato_title,
    draw_oswald_header, measure_body, measure_header, measure_hint, measure_title,
};

impl<'a> BootDisplay<'a> {
    pub fn draw_showqr_popup(&mut self) {
        self.draw_two_button_popup(
            "SIGNED TX",
            &["Transaction signed successfully.", "Save to SD card or return", "to view the QR code."],
            "Save to SD",
            "Back to QR",
        );
    }

    pub fn draw_kpub_export_popup(&mut self) {
        self.draw_two_button_popup(
            "KPUB EXPORTED",
            &["Watch-only key exported.", "Save to SD card or return", "to view the QR code."],
            "Save to SD",
            "Back to QR",
        );
    }

    pub fn draw_kpub_scanned_popup(&mut self) {
        self.draw_two_button_popup(
            "KPUB SCANNED",
            &["Watch-only key received.", "Display as QR or save to SD."],
            "Show QR",
            "Save to SD",
        );
    }

    pub fn draw_kspt_encrypt_ask(&mut self) {
        self.draw_two_button_popup(
            "ENCRYPT FILE?",
            &["Encrypt the file with a", "password before saving?"],
            "Yes",
            "No",
        );
    }

    pub fn draw_yes_no_ask(&mut self, header: &str, line1: &str, line2: &str) {
        self.draw_two_button_popup(header, &[line1, line2], "Yes", "No");
    }

    pub fn draw_qr_mode_choice(&mut self) {
        self.draw_two_button_popup(
            "QR DISPLAY MODE",
            &["Multiple QR frames required.", "Choose display mode:"],
            "Auto Cycle",
            "Manual",
        );
        let auto_hint = "Auto: frames cycle automatically";
        let auto_width = measure_hint(auto_hint);
        draw_lato_hint(
            &mut self.display,
            auto_hint,
            (320 - auto_width) / 2,
            200,
            COLOR_HINT,
        );
        let manual_hint = "Manual: tap to advance frames";
        let manual_width = measure_hint(manual_hint);
        draw_lato_hint(
            &mut self.display,
            manual_hint,
            (320 - manual_width) / 2,
            216,
            COLOR_HINT,
        );
    }

    fn draw_two_button_popup(
        &mut self,
        header: &str,
        body: &[&str],
        left_label: &str,
        right_label: &str,
    ) {
        self.display.clear(COLOR_BG).ok();

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

        for (index, line) in body.iter().take(3).enumerate() {
            let width = measure_body(line);
            let y = [75, 95, 115][index];
            draw_lato_body(&mut self.display, line, (320 - width) / 2, y, COLOR_TEXT);
        }

        let corners = CornerRadii::new(Size::new(6, 6));
        let left_zone = crate::ui::layout::MODAL_LEFT_BUTTON_ZONE;
        let left = Rectangle::new(
            Point::new(i32::from(left_zone.x), i32::from(left_zone.y)),
            Size::new(u32::from(left_zone.w), u32::from(left_zone.h)),
        );
        RoundedRectangle::new(left, corners)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display)
            .ok();
        let left_width = measure_title(left_label);
        draw_lato_title(
            &mut self.display,
            left_label,
            i32::from(left_zone.x) + (i32::from(left_zone.w) - left_width) / 2,
            i32::from(left_zone.y + left_zone.h) - 16,
            COLOR_BG,
        );

        let right_zone = crate::ui::layout::MODAL_RIGHT_BUTTON_ZONE;
        let right = Rectangle::new(
            Point::new(i32::from(right_zone.x), i32::from(right_zone.y)),
            Size::new(u32::from(right_zone.w), u32::from(right_zone.h)),
        );
        RoundedRectangle::new(right, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        RoundedRectangle::new(right, corners)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display)
            .ok();
        let right_width = measure_title(right_label);
        draw_lato_title(
            &mut self.display,
            right_label,
            i32::from(right_zone.x) + (i32::from(right_zone.w) - right_width) / 2,
            i32::from(right_zone.y + right_zone.h) - 16,
            COLOR_TEXT,
        );

        self.draw_back_button();
    }
}

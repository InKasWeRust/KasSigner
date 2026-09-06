// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_HINT,
    COLOR_ORANGE,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    CornerRadii,
    DrawTarget,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    RoundedRectangle,
    Size,
    draw_lato_18,
    draw_lato_body,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_18,
    measure_body,
    measure_header,
    measure_hint,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Choose between metadata and compressed-image seed carriers.
    pub fn draw_stego_carrier_choice(&mut self) {
        self.clear_keep_nav();
        let title = "BACKUP CARRIER";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            28,
            KASPA_TEAL,
        );
        Line::new(Point::new(20, 39), Point::new(300, 39))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        for (index, carrier) in crate::services::stego::CARRIERS.iter().enumerate() {
            let top = 60 + index as i32 * 76;
            let rect = Rectangle::new(Point::new(15, top), Size::new(290, 66));
            let corners = CornerRadii::new(Size::new(6, 6));
            RoundedRectangle::new(rect, corners)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display)
                .ok();
            RoundedRectangle::new(rect, corners)
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(&mut self.display)
                .ok();
            draw_lato_title(&mut self.display, carrier.label(), 26, top + 22, COLOR_TEXT);
            draw_lato_body(
                &mut self.display,
                carrier.description(),
                26,
                top + 42,
                COLOR_TEXT_DIM,
            );
            draw_lato_hint(
                &mut self.display,
                carrier.tradeoff(),
                26,
                top + 59,
                COLOR_HINT,
            );
        }
    }
    /// Choose between device-bound and portable backup protection.
    pub fn draw_stego_security_choice(&mut self) {
        self.clear_keep_nav();
        let title = "BACKUP SECURITY";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display, title, (320 - title_width) / 2, 28, KASPA_TEAL,
        );
        Line::new(Point::new(20, 39), Point::new(300, 39))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let rows = [
            ("DEVICE-BOUND", "Original device required", "Not your only disaster backup"),
            ("PORTABLE BACKUP", "Restore: JPEG + Password", "Works on another KasSigner"),
        ];
        for (index, (label, description, tradeoff)) in rows.iter().enumerate() {
            let top = 60 + index as i32 * 76;
            let rect = Rectangle::new(Point::new(15, top), Size::new(290, 66));
            let corners = CornerRadii::new(Size::new(6, 6));
            RoundedRectangle::new(rect, corners)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(rect, corners)
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(&mut self.display).ok();
            draw_lato_title(&mut self.display, label, 26, top + 22, COLOR_TEXT);
            draw_lato_body(&mut self.display, description, 26, top + 42, COLOR_TEXT_DIM);
            draw_lato_hint(&mut self.display, tradeoff, 26, top + 59, COLOR_HINT);
        }
    }

/// Draw descriptor input choice: Type manually / Load from SD
    /// Uses standard template layout with rows and icons
    pub fn draw_stego_desc_choice(&mut self, is_import: bool) {
        let subtitle = if is_import { "Carrier text - not backup password" } else { "Visible carrier text - not a password" };
        self.draw_input_source_choice("DESCRIPTOR", subtitle, false);
    }

/// Draw "Hide a hint?" ask screen with YES/NO buttons
    pub fn draw_stego_pp_ask(&mut self) {
        self.clear_keep_nav();
        let tw = measure_header("HIDE A HINT?");
        draw_oswald_header(&mut self.display, "HIDE A HINT?", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let w1 = measure_body("Hide a personal hint inside");
        draw_lato_body(&mut self.display, "Hide a personal hint inside", (320 - w1) / 2, 70, COLOR_TEXT);
        let w2 = measure_body("the image descriptor to help");
        draw_lato_body(&mut self.display, "the image descriptor to help", (320 - w2) / 2, 90, COLOR_TEXT);
        let w3 = measure_body("you remember your passphrase.");
        draw_lato_body(&mut self.display, "you remember your passphrase.", (320 - w3) / 2, 110, COLOR_TEXT);
        let w4 = measure_hint("Optional. Tap NO to skip.");
        draw_lato_hint(&mut self.display, "Optional. Tap NO to skip.", (320 - w4) / 2, 140, COLOR_HINT);

        let btn_corner = CornerRadii::new(Size::new(6, 6));
        // NO button
        let no_rect = Rectangle::new(Point::new(20, 175), Size::new(130, 40));
        RoundedRectangle::new(no_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(no_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let nw = measure_body("NO");
        draw_lato_body(&mut self.display, "NO", 20 + (130 - nw) / 2, 201, COLOR_TEXT);

        // YES button
        let yes_rect = Rectangle::new(Point::new(170, 175), Size::new(130, 40));
        RoundedRectangle::new(yes_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let yw = measure_body("YES");
        draw_lato_body(&mut self.display, "YES", 170 + (130 - yw) / 2, 201, COLOR_BG);

    }

/// Draw hint picker screen: 4 presets + Custom option
    pub fn draw_stego_hint_picker(&mut self) {
        self.clear_keep_nav();
        let tw = measure_header("RECOVERY HINT");
        draw_oswald_header(&mut self.display, "RECOVERY HINT", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let sw = measure_18("The answer is your BIP39 passphrase.");
        draw_lato_18(&mut self.display, "The answer is your BIP39 passphrase.", (320 - sw) / 2, 58, COLOR_ORANGE);

        let btn_corner = CornerRadii::new(Size::new(4, 4));
        for i in 0..4u8 {
            let hint = if (i as usize) < crate::services::stego::HINT_PRESETS.len() {
                crate::services::stego::HINT_PRESETS[i as usize]
            } else {
                "Custom..."
            };
            let row_y = 68 + i as i32 * 36;

            let rect = Rectangle::new(Point::new(15, row_y), Size::new(290, 30));
            RoundedRectangle::new(rect, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(rect, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(&mut self.display).ok();

            draw_lato_body(&mut self.display, hint, 25, row_y + 21, COLOR_TEXT);
        }

    }

/// Draw hint reveal screen after stego import (seed recovered + hint found)
    pub fn draw_stego_hint_reveal(&mut self, hint: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("SEED RECOVERED");
        draw_oswald_header(&mut self.display, "SEED RECOVERED", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let rw = measure_body("A recovery hint was found:");
        draw_lato_body(&mut self.display, "A recovery hint was found:", (320 - rw) / 2, 68, COLOR_TEXT);

        // Draw hint on gray row background, white text, centered
        let row_corner = CornerRadii::new(Size::new(4, 4));
        if hint.len() <= 30 {
            let row_rect = Rectangle::new(Point::new(15, 85), Size::new(290, 28));
            RoundedRectangle::new(row_rect, row_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            let hw = measure_title(hint);
            draw_lato_title(&mut self.display, hint, (320 - hw) / 2, 106, COLOR_TEXT);
        } else {
            let split = hint[..30].rfind(' ').unwrap_or(30);
            let line1 = &hint[..split];
            let rest_start = if hint.as_bytes()[split] == b' ' { split + 1 } else { split };
            let rest_end = hint.len().min(rest_start + 30);

            let row1_rect = Rectangle::new(Point::new(15, 82), Size::new(290, 26));
            RoundedRectangle::new(row1_rect, row_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            let hw1 = measure_title(line1);
            draw_lato_title(&mut self.display, line1, (320 - hw1) / 2, 102, COLOR_TEXT);

            if rest_start < hint.len() {
                let line2 = &hint[rest_start..rest_end];
                let row2_rect = Rectangle::new(Point::new(15, 110), Size::new(290, 26));
                RoundedRectangle::new(row2_rect, row_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                let hw2 = measure_title(line2);
                draw_lato_title(&mut self.display, line2, (320 - hw2) / 2, 130, COLOR_TEXT);
            }
        }

        // "The answer IS your passphrase" — header font for maximum emphasis
        let aw = measure_header("The answer is your BIP39 passphrase.");
        draw_oswald_header(&mut self.display, "The answer is your BIP39 passphrase.", (320 - aw) / 2, 162, COLOR_ORANGE);
        let ew = measure_body("Enter it as your BIP39 25th word.");
        draw_lato_body(&mut self.display, "Enter it as your BIP39 25th word.", (320 - ew) / 2, 188, COLOR_TEXT_DIM);

        let cw = measure_hint("Tap to continue");
        draw_lato_hint(&mut self.display, "Tap to continue", (320 - cw) / 2, 222, COLOR_HINT);
    }




}

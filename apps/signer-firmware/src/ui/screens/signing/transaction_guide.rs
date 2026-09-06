// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_ORANGE, COLOR_TEXT,
    COLOR_TEXT_DIM, CornerRadii, Drawable, KASPA_TEAL, Line, Point, Primitive,
    PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_18, draw_lato_body,
    draw_lato_title, draw_oswald_header, measure_18, measure_body, measure_header,
    measure_title,
};

impl<'a> BootDisplay<'a> {

    /// Explain the second KasSee -> KasSigner anti-klepto handoff before
    /// reopening the camera. This prevents the reveal scan from looking like
    /// the signing workflow unexpectedly restarted.
    pub fn draw_anti_klepto_reveal_guide(&mut self) {
        self.clear_keep_nav();

        let title = "SCAN KASSEE QR";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            30,
            KASPA_TEAL,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        let lines = [
            "KasSee should now show",
            "the next signing QR.",
            "Press OK, then scan it",
            "with KasSigner.",
        ];
        for (index, line) in lines.iter().enumerate() {
            let width = measure_18(line);
            draw_lato_18(
                &mut self.display,
                line,
                (320 - width) / 2,
                70 + index as i32 * 24,
                COLOR_TEXT,
            );
        }

        let hint = "Signing session stays active";
        let hint_width = measure_body(hint);
        draw_lato_body(
            &mut self.display,
            hint,
            (320 - hint_width) / 2,
            165,
            COLOR_TEXT_DIM,
        );

        let zone = crate::ui::layout::ERROR_OK_ZONE;
        let rectangle = Rectangle::new(
            Point::new(i32::from(zone.x), i32::from(zone.y)),
            Size::new(u32::from(zone.w), u32::from(zone.h)),
        );
        RoundedRectangle::new(rectangle, CornerRadii::new(Size::new(6, 6)))
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display)
            .ok();
        let ok_width = measure_title("OK");
        draw_lato_title(
            &mut self.display,
            "OK",
            i32::from(zone.x) + (i32::from(zone.w) - ok_width) / 2,
            i32::from(zone.y) + 28,
            COLOR_BG,
        );
    }

    /// Draw the "Sign TX" guided instruction screen.
    pub fn draw_sign_tx_guide(&mut self, seed_loaded: bool, address: &str) {
        self.clear_keep_nav();

        let title_width = measure_header("SIGN TRANSACTION");
        draw_oswald_header(
            &mut self.display,
            "SIGN TRANSACTION",
            (320 - title_width) / 2,
            28,
            KASPA_TEAL,
        );
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        if !seed_loaded {
            let warning_width = measure_header("Load a seed first");
            draw_oswald_header(
                &mut self.display,
                "Load a seed first",
                (320 - warning_width) / 2,
                110,
                COLOR_DANGER,
            );
            let instruction = "Go to Seeds menu to create or import";
            let instruction_width = measure_body(instruction);
            draw_lato_body(
                &mut self.display,
                instruction,
                (320 - instruction_width) / 2,
                140,
                COLOR_TEXT_DIM,
            );
            return;
        }

        if address.is_empty() {
            let note = "Network verified during review";
            let width = measure_body(note);
            draw_lato_body(
                &mut self.display,
                note,
                (320 - width) / 2,
                58,
                COLOR_ORANGE,
            );
        } else {
            self.draw_compact_address(address);
        }
        Line::new(Point::new(30, 68), Point::new(290, 68))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display)
            .ok();

        const STEPS: [&str; 4] = [
            "Open your Kaspa wallet",
            "Import the kpub",
            "Create a Send transaction",
            "Show the PSKB QR code",
        ];
        const STEP_HEIGHT: i32 = 26;
        const AVAILABLE_TOP: i32 = 92;
        const AVAILABLE_BOTTOM: i32 = 186;
        let block_height = STEPS.len() as i32 * STEP_HEIGHT;
        let start_y =
            AVAILABLE_TOP + (AVAILABLE_BOTTOM - AVAILABLE_TOP - block_height) / 2;
        for (index, step) in STEPS.iter().enumerate() {
            let y = start_y + index as i32 * STEP_HEIGHT;
            let width = measure_18(step);
            draw_lato_18(
                &mut self.display,
                step,
                (320 - width) / 2,
                y,
                COLOR_TEXT,
            );
        }

        self.draw_guide_button(30, "EXP. KPUB");
        self.draw_guide_button(166, "SCAN PSKB");
    }

    fn draw_compact_address(&mut self, address: &str) {
        let mut buffer = [0u8; 32];
        let shown = if address.len() > 24 {
            let front = 14.min(address.len());
            let back = 8.min(address.len());
            let mut position = 0;
            for byte in address.as_bytes()[..front].iter().copied() {
                buffer[position] = byte;
                position += 1;
            }
            buffer[position..position + 3].copy_from_slice(b"...");
            position += 3;
            for byte in address.as_bytes()[address.len() - back..].iter().copied() {
                buffer[position] = byte;
                position += 1;
            }
            core::str::from_utf8(&buffer[..position]).unwrap_or("???")
        } else {
            address
        };
        let width = measure_title(shown);
        draw_lato_title(
            &mut self.display,
            shown,
            (320 - width) / 2,
            58,
            COLOR_ORANGE,
        );
    }

    fn draw_guide_button(&mut self, x: i32, label: &str) {
        const WIDTH: u32 = 124;
        const HEIGHT: u32 = 36;
        const Y: i32 = 194;
        let rectangle = Rectangle::new(Point::new(x, Y), Size::new(WIDTH, HEIGHT));
        RoundedRectangle::new(rectangle, CornerRadii::new(Size::new(6, 6)))
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display)
            .ok();
        let label_width = measure_title(label);
        draw_lato_title(
            &mut self.display,
            label,
            x + (WIDTH as i32 - label_width) / 2,
            Y + 24,
            COLOR_BG,
        );
    }
}

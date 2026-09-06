// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_TEXT,
    CornerRadii,
    DrawTarget,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    draw_lato_title,
    draw_oswald_header,
    measure_header,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Draw the 2x2 home screen grid (Connect, Scan QR, Wallet, Settings).
    pub fn draw_home_grid(&mut self, title: &str) {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).ok();

        // Title bar — Rubik Bold header centered
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Top-left boot-trust indicator: white = signed/software verified,
        // teal = Secure-Boot-V2 eFuse enforced, red X = neither.
        crate::ui::display::draw_security_badge(&mut self.display);


        // Icon raw data (56x56 RGB565 little-endian).
        // The 56x56 home-card icon is generated directly from the supplied kas-see.png artwork.
        static ICON_CONNECT: &[u8] = include_bytes!("../../../../assets/kas_see_56.raw");
        static ICON_SCAN: &[u8] = include_bytes!("../../../../assets/icon_send.raw");
        static ICON_WALLET: &[u8] = include_bytes!("../../../../assets/icon_wallet_56.raw");
        static ICON_SETTINGS: &[u8] = include_bytes!("../../../../assets/icon_about.raw");

        let icons: [&[u8]; 4] = [ICON_CONNECT, ICON_SCAN, ICON_WALLET, ICON_SETTINGS];
        let labels = crate::runtime::navigation::production::HOME_LABELS;
        let corner = CornerRadii::new(Size::new(8, 8));

        for i in 0..4 {
            let zone = crate::ui::layout::HOME_GRID_ZONES[i];
            let px = i32::from(zone.x);
            let py = i32::from(zone.y);
            let card_w = u32::from(zone.w);
            let card_h = u32::from(zone.h);

            // Rounded card background
            RoundedRectangle::new(Rectangle::new(Point::new(px, py), Size::new(card_w, card_h)), corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(Rectangle::new(Point::new(px, py), Size::new(card_w, card_h)), corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();

            // Icon (56x56) centered horizontally in card
            let raw_icon: ImageRawLE<Rgb565> = ImageRawLE::new(icons[i], 56);
            Image::new(&raw_icon, Point::new(px + 46, py + 2))
                .draw(&mut self.display).ok();

            // Label — Lato Bold 18px centered below icon
            let label = labels[i];
            let lw = measure_title(label);
            let lx = px + (card_w as i32 - lw) / 2;
            draw_lato_title(&mut self.display, label, lx, py + 80, COLOR_TEXT);
        }

    }

    #[cfg(feature = "m5stack")]
    pub fn draw_audio_toggle(&mut self, state: crate::runtime::input::AppState, audio_muted: bool) {
        use embedded_graphics::image::{Image, ImageRawLE};

        static ICON_MUTE: &[u8] = include_bytes!("../../../../assets/icon_mute_24.raw");
        static ICON_AUDIO: &[u8] = include_bytes!("../../../../assets/icon_audio_24.raw");

        let Some(zone) = crate::ui::layout::audio_toggle_zone(state) else { return; };
        // Keep the generous 40x40 touch target, but render a 30x30 control to
        // match the trust/Home navigation icons and stay above separator lines.
        const VISUAL_SIZE: u32 = 30;
        let px = i32::from(zone.x) + 5;
        let py = 2;
        let rect = Rectangle::new(Point::new(px, py), Size::new(VISUAL_SIZE, VISUAL_SIZE));
        RoundedRectangle::new(rect, CornerRadii::new(Size::new(7, 7)))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(rect, CornerRadii::new(Size::new(7, 7)))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let raw_icon: ImageRawLE<Rgb565> = ImageRawLE::new(if audio_muted { ICON_MUTE } else { ICON_AUDIO }, 24);
        Image::new(&raw_icon, Point::new(px + 3, py + 3))
            .draw(&mut self.display).ok();
    }
}

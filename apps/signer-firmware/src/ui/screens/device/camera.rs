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
    COLOR_TEXT,
    DrawTarget,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    Size,
    draw_oswald_header,
    measure_header,
};

fn clear_camera_surface(display: &mut impl DrawTarget<Color = Rgb565>) {
    Rectangle::new(Point::new(0, 0), Size::new(320, 240))
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();
}

fn draw_back_chrome(display: &mut impl DrawTarget<Color = Rgb565>) {
    use embedded_graphics::image::{Image, ImageRawLE};
    let back: ImageRawLE<Rgb565> = ImageRawLE::new(
        crate::ui::display::icon_data::ICON_BACK,
        crate::ui::display::icon_data::ICON_BACK_W,
    );
    Image::new(&back, Point::new(0, 0)).draw(display).ok();
}

impl<'a> BootDisplay<'a> {
    /// Draw camera / QR scanner screen
    /// Shows status info and a viewfinder-style frame
    pub fn draw_camera_screen(&mut self) {
        self.draw_camera_screen_title("SCAN QR");
    }

    /// Guided anti-klepto reveal scanner. The protocol session is already fixed,
    /// so the title tells the user exactly which QR belongs here.
    pub fn draw_anti_klepto_reveal_camera_screen(&mut self) {
        self.draw_camera_screen_title("SCAN KASSEE QR");
    }

    fn draw_camera_screen_title(&mut self, title: &str) {
        clear_camera_surface(&mut self.display);
        draw_back_chrome(&mut self.display);
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
    }

    /// Blit a grayscale camera frame into the viewfinder area.
    /// Renders at (40, 30) with 240x180 pixels, leaving top 30px for back button.
    /// Redraws back button after blit so it's always visible during streaming.
    pub fn blit_camera_frame(&mut self, frame: &[u8], width: usize, height: usize,
                             qr_guide_info: u8) {
        use embedded_graphics::primitives::Rectangle;
        use embedded_graphics::prelude::*;
        use embedded_graphics::pixelcolor::Rgb565;
        use embedded_graphics::draw_target::DrawTarget;

        // Display area: centered below header chrome
        // Waveshare: 240x180 at (40, 45) — cam-tune can expand to (0, 0)
        // M5Stack: 240x194 at (40, 42) — below 42px chrome zone (back+header+divider)
        #[cfg(feature = "waveshare")]
        let cam_tune_mode = (qr_guide_info & 0x40) != 0;
        #[cfg(feature = "waveshare")]
        let (vf_x, vf_y, vf_w, vf_h) = if cam_tune_mode {
            (0i32, 0i32, 198usize, 178usize)
        } else {
            (40i32, 45i32, 240usize, 180usize)
        };
        #[cfg(feature = "m5stack")]
        let (vf_x, vf_y, vf_w, vf_h) = (40i32, 44i32, 240usize, 180usize);

        if width == 0 || height == 0 { return; }

        let dw = vf_w;
        let dh = vf_h;

        // Decode guide info: bit 7 = finders active
        let finders_active = (qr_guide_info & 0x80) != 0;

        // Frame border: 2px thick around entire viewfinder
        // Red/orange when idle, flashing green when finders detected
        let border_w = 2i32;
        let border_color = if finders_active {
            // Flash between bright and dim green using frame data parity
            let flash = (frame[0] as u16 + frame[width/2] as u16) & 1;
            if flash == 0 {
                Rgb565::new(0, 63, 0)
            } else {
                Rgb565::new(0, 42, 0)
            }
        } else {
            Rgb565::new(20, 8, 0) // dim red/amber — "scanning"
        };

        for vy in 0..dh {
            let src_y = if height > vf_h {
                vy * height / vf_h
            } else {
                vy * height / dh
            };
            if src_y >= height { break; }

            let area = Rectangle::new(
                Point::new(vf_x, vf_y + vy as i32),
                Size::new(dw as u32, 1),
            );

            let abs_y = vf_y + vy as i32;
            let on_top_border = abs_y < vf_y + border_w;
            let on_bot_border = abs_y >= vf_y + vf_h as i32 - border_w;

            let row_start = src_y * width;
            let _ = self.display.fill_contiguous(
                &area,
                (0..dw).map(move |vx| {
                    let abs_x = vf_x + vx as i32;
                    let on_left = abs_x < vf_x + border_w;
                    let on_right = abs_x >= vf_x + vf_w as i32 - border_w;
                    if on_top_border || on_bot_border || on_left || on_right {
                        return border_color;
                    }

                    let sx = if width >= vf_w {
                        (vx * width / vf_w).min(width - 1)
                    } else {
                        (vx * width / dw).min(width - 1)
                    };
                    let gray = frame[row_start + sx];
                    Rgb565::new(gray >> 3, gray >> 2, gray >> 3)
                }),
            );
        }

        // Icons persist outside blit rectangle — no per-frame redraw needed.
    }

}

// ═══════════════════════════════════════════════════════════════
// Camera Tune Screen (dev tool, feature-gated)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "waveshare")]
const CAM_TUNE_LABELS: [&str; 6] = [
    "AEC-H", "AEC-L", "Contr", "Brite", "AGC", "Sharp"
];

#[cfg(feature = "waveshare")]
impl<'a> crate::hw::display::BootDisplay<'a> {
    /// Draw the full cam-tune overlay: right panel (6 param buttons + EXIT) + bottom slider.
    /// Called once when cam-tune activates. Partial updates via update_cam_tune_slider.
    pub fn draw_cam_tune_overlay(&mut self, param: u8, vals: &[u8; 6]) {
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle, RoundedRectangle};
        use embedded_graphics::primitives::CornerRadii;
        use crate::ui::display::*;

        let corner = CornerRadii::new(Size::new(6, 6));

        // Right panel (x=198..320, y=0..180)
        Rectangle::new(Point::new(198, 0), Size::new(122, 180))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // EXIT button (116x32)
        RoundedRectangle::new(
            Rectangle::new(Point::new(202, 2), Size::new(116, 32)),
            corner
        ).into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
        .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "EXIT", 236, 26, COLOR_TEXT);

        // 6 param buttons: 3 rows x 2 cols
        let btn_w = 56u32;
        let btn_h = 44u32;
        let gap = 3i32;
        let grid_y0 = 38i32;
        let col0_x = 202i32;
        let col1_x = 262i32;
        let row_step = (btn_h as i32) + gap;

        for i in 0..6u8 {
            let row = i / 2;
            let col = i % 2;
            let bx = if col == 0 { col0_x } else { col1_x };
            let by = grid_y0 + row as i32 * row_step;
            let is_sel = i == param;

            let btn_bg = if is_sel {
                PrimitiveStyle::with_fill(KASPA_TEAL)
            } else {
                PrimitiveStyle::with_fill(COLOR_CARD)
            };
            RoundedRectangle::new(
                Rectangle::new(Point::new(bx, by), Size::new(btn_w, btn_h)),
                corner
            ).into_styled(btn_bg).draw(&mut self.display).ok();

            let label = CAM_TUNE_LABELS[i as usize];
            let label_color = if is_sel { COLOR_BG } else { COLOR_TEXT };
            let lw = measure_body(label);
            let lx = bx + (btn_w as i32 - lw) / 2;
            draw_lato_body(&mut self.display, label, lx.max(bx + 2), by + 30, label_color);
        }

        // Bottom slider bar
        self.update_cam_tune_slider(param, vals);
    }

    /// Partial redraw: only the bottom slider bar (y=180..240).
    pub fn update_cam_tune_slider(&mut self, param: u8, vals: &[u8; 6]) {
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle, RoundedRectangle};
        use embedded_graphics::primitives::CornerRadii;
        use crate::ui::display::*;

        let corner = CornerRadii::new(Size::new(6, 6));
        let slider_y = 180i32;
        let active_val = vals[param as usize];

        // Clear bottom bar
        Rectangle::new(Point::new(0, slider_y), Size::new(320, 60))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Label + hex + pct — centered vertically in top strip (y=180..200)
        // lato_body ~13px height, baseline at y=193 centers nicely
        let label = CAM_TUNE_LABELS[param as usize];
        let lw = measure_body(label);
        // Center label+hex+pct group: label(lw) + gap(6) + hex(~40) + gap(6) + pct(~36) = ~lw+88
        // Approximate: center the whole group in 320px
        let group_w = lw + 6 + 40 + 6 + 36;
        let gx = ((320 - group_w) / 2).max(4);
        draw_lato_body(&mut self.display, label, gx, slider_y + 13, KASPA_TEAL);

        let mut vbuf = [0u8; 4];
        vbuf[0] = b'0'; vbuf[1] = b'x';
        vbuf[2] = b"0123456789ABCDEF"[(active_val >> 4) as usize];
        vbuf[3] = b"0123456789ABCDEF"[(active_val & 0x0F) as usize];
        if let Ok(vs) = core::str::from_utf8(&vbuf) {
            draw_lato_title(&mut self.display, vs, gx + lw + 6, slider_y + 13, COLOR_TEXT);
        }
        let pct = (active_val as u16 * 100 / 255) as u8;
        let mut dbuf = [b' '; 4];
        dbuf[0] = b'0' + (pct / 100); dbuf[1] = b'0' + ((pct / 10) % 10);
        dbuf[2] = b'0' + (pct % 10); dbuf[3] = b'%';
        if let Ok(ds) = core::str::from_utf8(&dbuf) {
            draw_lato_body(&mut self.display, ds, gx + lw + 6 + 40 + 6, slider_y + 13, COLOR_TEXT_DIM);
        }

        // [-] button (50x34 at x=2, y=slider_y+20) — center "-" in button
        let btn_m = Rectangle::new(Point::new(2, slider_y + 20), Size::new(50, 34));
        RoundedRectangle::new(btn_m, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_m, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let mw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 2 + (50 - mw) / 2, slider_y + 44, COLOR_TEXT);

        // Slider track — centered vertically between buttons (y=200..234 → center y=217)
        let track_x0 = 56i32;
        let track_x1 = 264i32;
        let track_w = (track_x1 - track_x0) as u32;
        let track_y = slider_y + 30;
        let track_h = 10u32;

        RoundedRectangle::new(
            Rectangle::new(Point::new(track_x0, track_y), Size::new(track_w, track_h)),
            CornerRadii::new(Size::new(5, 5))
        ).into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT_DIM, 1)).draw(&mut self.display).ok();
        let fill_w = (active_val as u32 * track_w) / 255;
        if fill_w > 0 {
            RoundedRectangle::new(
                Rectangle::new(Point::new(track_x0, track_y), Size::new(fill_w.min(track_w), track_h)),
                CornerRadii::new(Size::new(5, 5))
            ).into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT)).draw(&mut self.display).ok();
        }
        let thumb_x = track_x0 + (active_val as i32 * (track_x1 - track_x0 - 12)) / 255;
        RoundedRectangle::new(
            Rectangle::new(Point::new(thumb_x, track_y - 4), Size::new(12, track_h + 8)),
            CornerRadii::new(Size::new(6, 6))
        ).into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(&mut self.display).ok();

        // [+] button (50x34 at x=268, y=slider_y+20) — center "+" in button
        let btn_p = Rectangle::new(Point::new(268, slider_y + 20), Size::new(50, 34));
        RoundedRectangle::new(btn_p, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_p, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let pw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 268 + (50 - pw) / 2, slider_y + 44, COLOR_TEXT);
    }
}

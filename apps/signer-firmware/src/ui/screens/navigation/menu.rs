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
    Circle,
    CornerRadii,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    Triangle,
    draw_lato_title,
    draw_menu_icon,
    draw_oswald_header,
    measure_header};

impl<'a> BootDisplay<'a> {
    /// Draw one standard navigation card with its shared visual treatment.
    pub(super) fn draw_navigation_card(
        &mut self,
        label: &str,
        start_x: i32,
        y: i32,
        card_w: u32,
        card_h: u32,
    ) {
        let card_rect = Rectangle::new(Point::new(start_x, y), Size::new(card_w, card_h));
        let card_corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(card_rect, card_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        RoundedRectangle::new(card_rect, card_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        draw_menu_icon(&mut self.display, label, Point::new(start_x + 8, y + 9));
        draw_lato_title(&mut self.display, label, start_x + 42, y + 28, COLOR_TEXT);
    }

    /// Partial redraw: only title + card interiors + page indicators.
    /// Teal borders stay from the previous draw — no blink.
    pub fn update_menu_content(&mut self, title: &str, menu: &crate::runtime::input::Menu) {
        // Clear the centered title strip while preserving the corner nav icons.
        Rectangle::new(Point::new(34, 0), Size::new(252, 34))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Clear the entire separator band. Other screens use y=34..40 and a
        // center-only clear left short line remnants at x=20..34 / 286..300.
        Rectangle::new(Point::new(0, 34), Size::new(320, 9))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Left strip (x=0..44, y=42..230) — arrows live here
        Rectangle::new(Point::new(0, 42), Size::new(44, 188))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Right strip (x=276..320, y=42..230) — arrows live here
        Rectangle::new(Point::new(276, 42), Size::new(44, 188))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Gaps in card column: above first card, between cards, below last card
        // y=42..46 (above card 1), y=88..92, y=134..138, y=180..184, y=226..230
        for gap_y in &[42i32, 88, 134, 180, 226] {
            Rectangle::new(Point::new(44, *gap_y), Size::new(232, 4))
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut self.display).ok();
        }
        // Bottom strip below cards (y=230..240)
        Rectangle::new(Point::new(0, 230), Size::new(320, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Repaint nav icons
        self.draw_back_button();

        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);

        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Redraw cards (with borders — they paint over the old content cleanly)
        self.draw_menu_cards(menu);
        self.draw_menu_page_indicators(menu);
    }

    /// Draw the 4 menu card slots with borders, icons, and labels.
    fn draw_menu_cards(&mut self, menu: &crate::runtime::input::Menu) {
        let max_visible = crate::runtime::input::Menu::MAX_VISIBLE;
        let visible_count = max_visible.min(menu.count.saturating_sub(menu.scroll));
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let card_w: u32 = 232; // center content area (320 - 40 - 40 - 8 margin)
        let start_y: i32 = 46;
        let start_x: i32 = 44; // 40px left strip + 4px margin

        // Near-black teal for inactive arrows/dots — max contrast with active
        for i in 0..visible_count {
            let item_idx = menu.scroll + i;
            if item_idx >= menu.count { break; }

            let y = start_y + (i as i32) * (card_h + card_gap);
            let label = menu.items[item_idx as usize];

            self.draw_navigation_card(label, start_x, y, card_w, card_h as u32);
        }

        // Clear unused card slots (when fewer than 4 items visible)
        for i in visible_count..max_visible {
            let y = start_y + (i as i32) * (card_h + card_gap);
            Rectangle::new(Point::new(start_x, y), Size::new(card_w, card_h as u32))
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut self.display).ok();
        }
    }

    /// Draw page arrows and dots for menu pagination.
    fn draw_menu_page_indicators(&mut self, menu: &crate::runtime::input::Menu) {
        let max_visible = crate::runtime::input::Menu::MAX_VISIBLE;
        let teal_dark = Rgb565::new(0b00001, 0b000100, 0b00010);

        // Clear arrow areas
        Rectangle::new(Point::new(0, 115), Size::new(40, 50))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        Rectangle::new(Point::new(280, 115), Size::new(40, 50))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Left strip: ◀ page-up arrow
        if menu.count > max_visible {
            let arr_color = if menu.can_page_up() { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(5, 138),    // left tip
                Point::new(30, 121),   // top-right
                Point::new(30, 155),   // bottom-right
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();
        }

        // Right strip: ▶ page-down arrow
        if menu.count > max_visible {
            let arr_color = if menu.can_page_down() { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(315, 138),  // right tip
                Point::new(290, 121),  // top-left
                Point::new(290, 155),  // bottom-left
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();
        }

        // Clear dots area
        Rectangle::new(Point::new(0, 230), Size::new(320, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Page dots at bottom — 7px diameter, y=232
        let total_pages = menu.total_pages();
        if total_pages > 1 {
            let current_page = menu.current_page();
            let dot_d: i32 = 7;
            let dot_gap: i32 = 8;
            let total_w = (total_pages as i32) * dot_d + ((total_pages as i32) - 1) * dot_gap;
            let dot_start_x = (320 - total_w) / 2;

            for p in 0..total_pages {
                let dx = dot_start_x + (p as i32) * (dot_d + dot_gap);
                let color = if p == current_page { KASPA_ACCENT } else { teal_dark };
                Circle::new(Point::new(dx, 232), dot_d as u32)
                    .into_styled(PrimitiveStyle::with_fill(color))
                    .draw(&mut self.display).ok();
            }
        }

    }
}

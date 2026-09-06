// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_DANGER,
    COLOR_HINT,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    CornerRadii,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    RoundedRectangle,
    Size,
    draw_lato_body,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    draw_rubik_big,
    measure_big,
    measure_body,
    measure_header,
    measure_hint,
    measure_title,
};

impl<'a> BootDisplay<'a> {
// ═══════════════════════════════════════════════════════════════
    // Multisig Wallet Creation Screens
    // ═══════════════════════════════════════════════════════════════

    /// Draw multisig M-of-N chooser screen
    /// Layout: header, M selector with +/-, N selector with +/-, GO button
    /// Touch zones:
    ///   M-: (40,72,50,36)  M+: (230,72,50,36)
    ///   N-: (40,122,50,36) N+: (230,122,50,36)
    ///   GO: (90,175,140,40)
    pub fn draw_multisig_choose_mn(&mut self, m: u8, n: u8) {
        self.clear_keep_nav();

        let tw = measure_header("CREATE MULTISIG");
        draw_oswald_header(&mut self.display, "CREATE MULTISIG", (320 - tw) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(6, 6));

        // ── M row: "Required sigs (M)"  [-]  value  [+] ──
        let lm = measure_body("Required sigs (M):");
        draw_lato_body(&mut self.display, "Required sigs (M):", (320 - lm) / 2, 62, COLOR_TEXT_DIM);

        let row_m_y: i32 = 72;
        // [-] button
        let m_minus = Rectangle::new(Point::new(60, row_m_y), Size::new(50, 38));
        RoundedRectangle::new(m_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(m_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let mmw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 60 + (50 - mmw) / 2, row_m_y + 27, COLOR_TEXT);

        // M value (big centered)
        let mut m_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut m_buf, format_args!("{m}")).ok();
        let mvw = measure_big(m_buf.as_str());
        draw_rubik_big(&mut self.display, &m_buf, (320 - mvw) / 2, row_m_y + 30, KASPA_ACCENT);

        // [+] button
        let m_plus = Rectangle::new(Point::new(210, row_m_y), Size::new(50, 38));
        RoundedRectangle::new(m_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(m_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let mpw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 210 + (50 - mpw) / 2, row_m_y + 27, COLOR_TEXT);

        // ── N row: "Total keys (N)"  [-]  value  [+] ──
        let ln = measure_body("Total keys (N):");
        draw_lato_body(&mut self.display, "Total keys (N):", (320 - ln) / 2, 130, COLOR_TEXT_DIM);

        let row_n_y: i32 = 140;
        let n_minus = Rectangle::new(Point::new(60, row_n_y), Size::new(50, 38));
        RoundedRectangle::new(n_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(n_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let nmw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 60 + (50 - nmw) / 2, row_n_y + 27, COLOR_TEXT);

        let mut n_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut n_buf, format_args!("{n}")).ok();
        let nvw = measure_big(n_buf.as_str());
        draw_rubik_big(&mut self.display, &n_buf, (320 - nvw) / 2, row_n_y + 30, KASPA_ACCENT);

        let n_plus = Rectangle::new(Point::new(210, row_n_y), Size::new(50, 38));
        RoundedRectangle::new(n_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(n_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let npw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 210 + (50 - npw) / 2, row_n_y + 27, COLOR_TEXT);

        // Validation hint
        let valid = m >= 1 && m <= n && n <= 5;
        if !valid {
            let hw = measure_hint("M must be 1..N, N max 5");
            draw_lato_hint(&mut self.display, "M must be 1..N, N max 5", (320 - hw) / 2, 192, COLOR_DANGER);
        }

        // NEXT button — teal when valid, dim when not
        let btn_w: u32 = 160;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 190;
        let go_color = if valid { KASPA_TEAL } else { COLOR_CARD };
        let go_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, 40));
        RoundedRectangle::new(go_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(go_color))
            .draw(&mut self.display).ok();
        let text_color = if valid { COLOR_BG } else { COLOR_TEXT_DIM };
        let gw = measure_title("NEXT");
        draw_lato_title(&mut self.display, "NEXT", btn_x + (btn_w as i32 - gw) / 2, btn_y + 28, text_color);

    }

/// Draw multisig "add key" screen — prompts to scan kpub or choose a wallet.
    /// key_idx: which key we're collecting (0-based), n: total keys needed
    /// can_choose_wallet: whether a loaded wallet or free wallet slot is available
    /// Touch zones:
    ///   "Scan QR":   (30, 90, 260, 45)
    ///   "Use Loaded": (30, 145, 260, 45)
    pub fn draw_multisig_add_key(&mut self, key_idx: u8, n: u8, can_choose_wallet: bool) {
        self.clear_keep_nav();

        let mut title_buf: heapless::String<20> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("KEY {}/{}", key_idx + 1, n)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 28, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let bw = measure_body("Add a cosigner kpub:");
        draw_lato_body(&mut self.display, "Add a cosigner kpub:", (320 - bw) / 2, 65, COLOR_TEXT);
        let hw = measure_hint("Scan a kpub QR or choose a wallet");
        draw_lato_hint(&mut self.display, "Scan a kpub QR or choose a wallet", (320 - hw) / 2, 80, COLOR_TEXT_DIM);

        let btn_corner = CornerRadii::new(Size::new(8, 8));

        // "Scan QR" button
        let scan_rect = Rectangle::new(Point::new(30, 90), Size::new(260, 45));
        RoundedRectangle::new(scan_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(scan_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let sw = measure_title("Scan kpub QR");
        draw_lato_title(&mut self.display, "Scan kpub QR", 30 + (260 - sw) / 2, 120, COLOR_TEXT);

        // Canonical wallet-picker button
        let use_color = if can_choose_wallet { COLOR_CARD } else { COLOR_BG };
        let use_border = if can_choose_wallet { KASPA_TEAL } else { COLOR_CARD_BORDER };
        let use_rect = Rectangle::new(Point::new(30, 145), Size::new(260, 45));
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(use_color))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(use_border, 1))
            .draw(&mut self.display).ok();
        let label = if can_choose_wallet { "Choose Wallet" } else { "No wallet slots" };
        let text_color = if can_choose_wallet { COLOR_TEXT } else { COLOR_TEXT_DIM };
        let lw = measure_title(label);
        draw_lato_title(&mut self.display, label, 30 + (260 - lw) / 2, 175, text_color);

        // Show keys collected so far
        if key_idx > 0 {
            let mut prog: heapless::String<16> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut prog, format_args!("{key_idx} key(s) added")).ok();
            let pw = measure_hint(prog.as_str());
            draw_lato_hint(&mut self.display, &prog, (320 - pw) / 2, 210, KASPA_ACCENT);
        }

    }

/// Draw multisig wallet picker using the same canonical cards as WALLETS.
    /// The first `+` row creates a wallet and returns to this exact key slot.
    pub fn draw_multisig_pick_seed(&mut self, key_idx: u8, n: u8, seed_mgr: &crate::wallet::seed_manager::SeedManager, scroll: u8) {
        self.clear_keep_nav();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("SELECT WALLET {}/{}", key_idx + 1, n)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        self.draw_seed_slot_list(
            seed_mgr,
            scroll,
            super::super::seed_slots::SeedSlotListConfig {
                start_y: 46,
                include_add_slot: true,
                active_fill: COLOR_CARD_BORDER,
                active_border: KASPA_TEAL,
                active_text: KASPA_TEAL,
            },
        );

        let hw = measure_hint("Tap wallet to use; + adds wallet");
        draw_lato_hint(&mut self.display, "Tap wallet to use; + adds wallet", (320 - hw) / 2, 195, COLOR_HINT);
    }

}

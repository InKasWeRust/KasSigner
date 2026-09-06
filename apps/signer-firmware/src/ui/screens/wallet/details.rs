//! Intent-based wallet details screen.

use super::super::{
    BootDisplay, COLOR_CARD, COLOR_CARD_BORDER, COLOR_RED_BTN, COLOR_TEXT, COLOR_TEXT_DIM,
    CornerRadii, Drawable, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle,
    RoundedRectangle, Size, draw_lato_body, draw_lato_title, draw_oswald_header, measure_header,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    pub fn draw_wallet_details(&mut self, ad: &crate::runtime::data::AppData) {
        self.clear_keep_nav();
        let title = "WALLET DETAILS";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        if let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() {
            let mut wallet: heapless::String<24> = heapless::String::new();
            if slot.name_len > 0 {
                for ch in slot.name_str().chars().take(20) {
                    if wallet.push(ch).is_err() { break; }
                }
            } else {
                core::fmt::Write::write_fmt(
                    &mut wallet,
                    format_args!("Wallet {}", usize::from(ad.wallet.seeds.seed_mgr.active) + 1),
                ).ok();
            }
            draw_lato_title(&mut self.display, wallet.as_str(), 28, 68, COLOR_TEXT);
            draw_lato_body(&mut self.display, slot.source.display_label(), 28, 91, COLOR_TEXT_DIM);
            let mut fp = [0u8; 8];
            slot.fingerprint_hex(&mut fp);
            let fp = core::str::from_utf8(&fp).unwrap_or("????????");
            draw_lato_body(&mut self.display, fp, 28, 111, COLOR_TEXT_DIM);
        }
        if let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() {
            let protection_label = match slot.protection {
                crate::wallet::seed_manager::WalletProtection::DeviceOnly
                    if ad.storage.persistence.advanced.saved_wallet => "Add PIN / Password",
                crate::wallet::seed_manager::WalletProtection::DeviceOnly => "Session Only",
                crate::wallet::seed_manager::WalletProtection::Pin => "PIN Enabled",
                crate::wallet::seed_manager::WalletProtection::Password => "Password Enabled",
            };
            draw_details_button(
                &mut self.display,
                45,
                116,
                COLOR_CARD,
                COLOR_CARD_BORDER,
                protection_label,
            );
        }
        draw_details_button(&mut self.display, 45, 154, COLOR_CARD, COLOR_CARD_BORDER, "Edit Name");
        draw_details_button(&mut self.display, 45, 192, COLOR_RED_BTN, COLOR_RED_BTN, "Delete Wallet");
        self.draw_back_button();
    }
}

fn draw_details_button(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = embedded_graphics::pixelcolor::Rgb565>,
    x: i32, y: i32, fill: embedded_graphics::pixelcolor::Rgb565,
    border: embedded_graphics::pixelcolor::Rgb565, label: &str,
) {
    let rect = Rectangle::new(Point::new(x, y), Size::new(230, 30));
    let rounded = RoundedRectangle::new(rect, CornerRadii::new(Size::new(6, 6)));
    rounded.into_styled(PrimitiveStyle::with_fill(fill)).draw(display).ok();
    rounded.into_styled(PrimitiveStyle::with_stroke(border, 1)).draw(display).ok();
    let lw = measure_title(label);
    draw_lato_title(display, label, (320 - lw) / 2, y + 21, COLOR_TEXT);
}

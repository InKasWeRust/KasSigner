use core::fmt::Write as _;
use super::super::{
    BootDisplay, COLOR_BG, COLOR_ORANGE, COLOR_TEXT_DIM, CornerRadii, Drawable,
    KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle,
    RoundedRectangle, Size, draw_lato_body, draw_lato_hint, draw_lato_title,
    draw_oswald_header, measure_body, measure_header, measure_title,
};
use crate::runtime::data::{AppData, CovenantSigningMode, CovenantSigningPhase};
use shared_signer::covenant_sign::KnownScheme;

impl<'a> BootDisplay<'a> {
    pub fn draw_covenant_sign_review(&mut self, ad: &AppData) {
        let binding = ad.signing.covenant.mode == CovenantSigningMode::BindKnown;
        self.covenant_header(if binding { "BIND COVENANT KEY" } else { "COVENANT SIGN" });
        let scheme = match ad.signing.covenant.scheme {
            KnownScheme::OracleV1 => "ORACLE-V1 VERIFIED",
            KnownScheme::Sha256Preimage => "SHA-256 CONTEXT VERIFIED",
            KnownScheme::None => "KNOWN COVENANT VERIFIED",
        };
        self.center_body(scheme, 56, KASPA_TEAL);
        let pages = ad.signing.covenant.context_page_count();
        let page = ad.signing.covenant.context_page.saturating_add(1);
        let page_text = ad.signing.covenant.context_page_text();
        self.draw_centered_wrapped_title(page_text, 66, 18, 14, 124);
        self.draw_commitment_prefix(&ad.signing.covenant.commitment, 132);
        let final_action = if binding { "BIND KEY" } else { "SIGN" };
        let button = if page < pages { "NEXT" } else { final_action };
        self.covenant_button(button, 188, KASPA_TEAL);
    }

    pub fn draw_covenant_opaque_warning(&mut self, ad: &AppData) {
        let binding = ad.signing.covenant.mode == CovenantSigningMode::BindOpaque;
        self.covenant_header(if binding { "BIND OPAQUE KEY" } else { "OPAQUE COVENANT" });
        self.center_body("KasSigner cannot verify", 65, COLOR_ORANGE);
        self.center_body(if binding { "how this script uses the key." } else { "what this hash authorizes." }, 84, COLOR_ORANGE);
        self.center_body("Only the isolated covenant", 112, COLOR_TEXT_DIM);
        self.center_body("key can sign it; wallet funds", 130, COLOR_TEXT_DIM);
        self.center_body("cannot be authorized by this key.", 148, COLOR_TEXT_DIM);
        self.draw_hex_prefix("KEY INSTANCE", &ad.signing.covenant.key_id, 166);
        self.covenant_button("I UNDERSTAND", 188, KASPA_ACCENT);
    }

    pub fn draw_covenant_opaque_confirm(&mut self, ad: &AppData) {
        let binding = ad.signing.covenant.mode == CovenantSigningMode::BindOpaque;
        self.covenant_header(if binding { "CONFIRM KEY BINDING" } else { "CONFIRM OPAQUE SIGN" });
        self.center_body(if binding { "BIND TO EXACT SCRIPT" } else { "UNVERIFIED AUTHORIZATION" }, 54, COLOR_ORANGE);
        if binding {
            self.draw_hex_prefix("KEY INSTANCE", &ad.signing.covenant.key_id, 76);
            self.draw_hex_prefix("SCRIPT SHA-256", &ad.signing.covenant.script_hash, 126);
        } else {
            self.draw_full_commitment(&ad.signing.covenant.commitment, 69);
            self.draw_hex_prefix("SCRIPT SHA-256", &ad.signing.covenant.script_hash, 146);
        }
        self.covenant_button(if binding { "BIND KEY" } else { "SIGN OPAQUE" }, 188, KASPA_ACCENT);
    }

    pub fn draw_covenant_key_result(&mut self, ad: &AppData) {
        self.covenant_header("COVENANT KEY");
        self.center_body("Isolated key ready", 68, KASPA_TEAL);
        self.draw_hex_prefix("KEY ID", &ad.signing.covenant.key_id, 102);
        self.draw_hex_prefix("PUBKEY", &ad.signing.covenant.pubkey_x, 140);
        self.covenant_button("SHOW QR", 188, KASPA_ACCENT);
    }

    pub fn draw_covenant_sign_result(&mut self, ad: &AppData) {
        if ad.signing.covenant.phase == CovenantSigningPhase::AwaitingReveal {
            self.covenant_header("NONCE COMMITTED");
            self.center_body("Host contribution required", 68, KASPA_TEAL);
            self.draw_hex_prefix("COMMITMENT", &ad.signing.covenant.commitment, 108);
            let mut nonce_x = [0u8; 32];
            nonce_x.copy_from_slice(&ad.signing.covenant.nonce_point[1..33]);
            self.draw_hex_prefix("NONCE", &nonce_x, 146);
            let button = if ad.signing.covenant.nonce_qr_shown { "SCAN REVEAL" } else { "SHOW NONCE QR" };
            self.covenant_button(button, 188, KASPA_ACCENT);
            return;
        }
        let binding = matches!(ad.signing.covenant.mode, CovenantSigningMode::BindKnown | CovenantSigningMode::BindOpaque);
        self.covenant_header(if binding { "COVENANT KEY BOUND" } else { "COVENANT SIGNED" });
        let mode = match ad.signing.covenant.mode {
            CovenantSigningMode::Known => "Known context verified",
            CovenantSigningMode::Opaque => "Opaque commitment signed",
            CovenantSigningMode::BindKnown | CovenantSigningMode::BindOpaque => "Covenant key binding ready",
            _ => "Covenant response ready",
        };
        self.center_body(mode, 68, KASPA_TEAL);
        if binding {
            self.draw_hex_prefix("SCRIPT SHA-256", &ad.signing.covenant.script_hash, 108);
        } else {
            self.draw_hex_prefix("COMMITMENT", &ad.signing.covenant.commitment, 108);
        }
        self.draw_hex_prefix("PUBKEY", &ad.signing.covenant.pubkey_x, 146);
        self.covenant_button("SHOW QR", 188, KASPA_ACCENT);
    }

    fn covenant_header(&mut self, title: &str) {
        self.clear_keep_nav();
        let width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - width) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
    }

    fn center_body(&mut self, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
        let width = measure_body(text);
        draw_lato_body(&mut self.display, text, (320 - width) / 2, y, color);
    }

    fn draw_commitment_prefix(&mut self, value: &[u8; 32], y: i32) {
        self.draw_hex_prefix("COMMITMENT", value, y);
    }

    fn draw_full_commitment(&mut self, value: &[u8; 32], y: i32) {
        self.center_body("COMMITMENT (FULL)", y, COLOR_TEXT_DIM);
        let chars = b"0123456789abcdef";
        let mut line = [0u8; 16];
        for row in 0..4 {
            let offset = row * 8;
            for index in 0..8 {
                let byte = value[offset + index];
                line[index * 2] = chars[(byte >> 4) as usize];
                line[index * 2 + 1] = chars[(byte & 0x0f) as usize];
            }
            let text = core::str::from_utf8(&line).unwrap_or("?");
            let width = measure_body(text);
            draw_lato_body(&mut self.display, text, (320 - width) / 2, y + 17 + row as i32 * 16, KASPA_ACCENT);
        }
    }

    fn draw_hex_prefix(&mut self, label: &str, value: &[u8; 32], y: i32) {
        let chars = b"0123456789abcdef";
        let mut text = [0u8; 19];
        for index in 0..8 {
            text[index * 2] = chars[(value[index] >> 4) as usize];
            text[index * 2 + 1] = chars[(value[index] & 0x0f) as usize];
        }
        text[16..19].copy_from_slice(b"...");
        let label_width = measure_body(label);
        draw_lato_hint(&mut self.display, label, (320 - label_width) / 2, y, COLOR_TEXT_DIM);
        let value_text = core::str::from_utf8(&text).unwrap_or("?");
        let width = measure_body(value_text);
        draw_lato_body(&mut self.display, value_text, (320 - width) / 2, y + 18, KASPA_ACCENT);
    }

    fn covenant_button(&mut self, label: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
        let rect = Rectangle::new(Point::new(60, y), Size::new(200, 38));
        RoundedRectangle::new(rect, CornerRadii::new(Size::new(8, 8)))
            .into_styled(PrimitiveStyle::with_fill(color))
            .draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, 60 + (200 - width) / 2, y + 27, COLOR_BG);
    }
}


fn private_swap_kas_line(label: &str, value: u64) -> heapless::String<40> {
    let mut out = heapless::String::<40>::new();
    let _ = write!(&mut out, "{} {}.{:08} KAS", label, value / 100_000_000, value % 100_000_000);
    out
}

impl<'a> BootDisplay<'a> {
    pub fn draw_private_swap_review(&mut self, ad: &AppData) {
        use crate::runtime::data::PrivateSwapMode;
        let s=&ad.signing.private_swap;
        let (title, action)=match s.mode {
            PrivateSwapMode::Bind=>("BIND PRIVATE SWAP","BIND KEY"),
            PrivateSwapMode::PreSign=>("PRIVATE SWAP CLAIM","PRE-SIGN"),
            PrivateSwapMode::Complete=>("COMPLETE SWAP CLAIM","COMPLETE"),
            _=>("PRIVATE SWAP","CONFIRM"),
        };
        self.covenant_header(title);
        self.center_body("ADAPTOR SIGNATURE v2",52,KASPA_TEAL);
        if s.mode==PrivateSwapMode::Bind {
            self.draw_hex_prefix("DEST SCRIPT SHA-256",&s.destination_hash,82);
            self.draw_hex_prefix("KEY INSTANCE",&s.key_id,124);
        } else {
            let amount = private_swap_kas_line("OUTPUT", s.output_amount);
            let fee = private_swap_kas_line("FEE", s.fee);
            let mut refund = heapless::String::<40>::new();
            let _ = write!(&mut refund, "REFUND DAA {}", s.refund_locktime_daa);
            self.center_body(amount.as_str(),63,KASPA_TEAL);
            self.center_body(fee.as_str(),82,COLOR_TEXT_DIM);
            self.center_body(refund.as_str(),101,COLOR_TEXT_DIM);
            self.draw_hex_prefix("DEST SCRIPT SHA-256",&s.destination_hash,116);
            self.draw_hex_prefix("TX SIGHASH",&s.sighash,151);
        }
        self.covenant_button(action,188,KASPA_ACCENT);
    }

    pub fn draw_private_swap_key_result(&mut self, ad:&AppData) {
        let s=&ad.signing.private_swap;
        self.covenant_header("PRIVATE SWAP KEY");
        self.center_body("Isolated swap key ready",54,KASPA_TEAL);
        self.draw_hex_prefix("KEY ID",&s.key_id,78);
        self.draw_hex_prefix("CLAIM PUBKEY",&s.claim_pubkey,116);
        self.draw_hex_prefix("ADAPTOR POINT",&s.adaptor_point,154);
        self.covenant_button("SHOW QR",188,KASPA_ACCENT);
    }

    pub fn draw_private_swap_result(&mut self, ad:&AppData) {
        use crate::runtime::data::{PrivateSwapMode,PrivateSwapPhase};
        let s=&ad.signing.private_swap;
        if s.phase==PrivateSwapPhase::AwaitingReveal {
            self.covenant_header("SWAP NONCE COMMITTED");
            self.center_body("Host contribution required",60,KASPA_TEAL);
            self.draw_hex_prefix("TX SIGHASH",&s.sighash,92);
            let mut nx=[0u8;32]; nx.copy_from_slice(&s.nonce_point[1..33]);
            self.draw_hex_prefix("BASE NONCE",&nx,132);
            self.covenant_button(if s.nonce_qr_shown{"SCAN REVEAL"}else{"SHOW NONCE QR"},188,KASPA_ACCENT);
            return;
        }
        let title=match s.mode {PrivateSwapMode::Bind=>"SWAP KEY BOUND",PrivateSwapMode::PreSign=>"ADAPTOR PRE-SIGNED",PrivateSwapMode::Complete=>"SWAP CLAIM COMPLETE",_=>"PRIVATE SWAP"};
        self.covenant_header(title);
        self.center_body("No preimage / tx-sighash bound",62,KASPA_TEAL);
        self.draw_hex_prefix("TX / SCRIPT",if s.mode==PrivateSwapMode::Bind{&s.script_hash}else{&s.sighash},104);
        self.draw_hex_prefix("CLAIM PUBKEY",&s.claim_pubkey,144);
        self.covenant_button("SHOW QR",188,KASPA_ACCENT);
    }
}

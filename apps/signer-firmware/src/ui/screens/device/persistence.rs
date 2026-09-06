//! First-start wallet setup, final storage choice, and credential screens.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT, COLOR_TEXT_DIM,
    CornerRadii, Drawable, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle,
    RoundedRectangle, Size, draw_lato_hint, draw_lato_title, draw_oswald_header, measure_header,
    measure_hint, measure_title,
};
use crate::ui::keyboard::KeyboardMode;

pub(crate) const FRESH_BUTTON_Y: core::ops::RangeInclusive<u16> = 42..=76;
pub(crate) const SAVE_BUTTON_Y: core::ops::RangeInclusive<u16> = 125..=159;
pub(crate) const BUTTON_X: core::ops::RangeInclusive<u16> = 18..=302;
pub(crate) const PIN_BUTTON_Y: core::ops::RangeInclusive<u16> = 48..=82;
pub(crate) const PASSWORD_BUTTON_Y: core::ops::RangeInclusive<u16> = 96..=130;
pub(crate) const PROTECT_BUTTON_Y: core::ops::RangeInclusive<u16> = 48..=82;
pub(crate) const NO_PROTECT_BUTTON_Y: core::ops::RangeInclusive<u16> = 118..=152;
pub(crate) const ACK_BUTTON_X: core::ops::RangeInclusive<u16> = 18..=302;
pub(crate) const ACK_BUTTON_Y: core::ops::RangeInclusive<u16> = 168..=207;
pub(crate) const RESTORE_ROW_Y: [core::ops::RangeInclusive<u16>; 4] = [
    46..=87, 92..=133, 138..=179, 184..=225,
];
pub(crate) const NO_DICE_BUTTON_Y: core::ops::RangeInclusive<u16> = 58..=92;
pub(crate) const ADD_DICE_BUTTON_Y: core::ops::RangeInclusive<u16> = 112..=146;
// Touch choice hitboxes include four pixels of non-overlapping vertical slop
// around their visible 35px cards. The CoreS3 trace recorded an intended
// No Touch tap at y=57, one pixel above the drawn card, which was otherwise lost.
pub(crate) const NO_TOUCH_BUTTON_Y: core::ops::RangeInclusive<u16> = 54..=96;
pub(crate) const ADD_TOUCH_BUTTON_Y: core::ops::RangeInclusive<u16> = 108..=150;
pub(crate) const DICE_25_BUTTON_Y: core::ops::RangeInclusive<u16> = 48..=82;
pub(crate) const DICE_50_BUTTON_Y: core::ops::RangeInclusive<u16> = 90..=124;
pub(crate) const DICE_100_BUTTON_Y: core::ops::RangeInclusive<u16> = 132..=166;
pub(crate) const DICE_200_BUTTON_Y: core::ops::RangeInclusive<u16> = 174..=208;

const PIN_PAD_X: [core::ops::RangeInclusive<u16>; 3] = [20..=103, 118..=201, 216..=299];
// The bottom row accepts 5 px of downward touch slop. CoreS3 samples can land
// a few pixels below the rendered card near the display edge; keeping that tap in
// the credential domain avoids an intended OK/DEL tap falling through routing.
const PIN_PAD_Y: [core::ops::RangeInclusive<u16>; 4] = [82..=113, 120..=151, 158..=189, 196..=232];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinPadAction {
    Digit(u8),
    Backspace,
    Submit,
}

pub(crate) fn pin_pad_action(x: u16, y: u16) -> Option<PinPadAction> {
    let column = PIN_PAD_X.iter().position(|range| range.contains(&x))?;
    let row = PIN_PAD_Y.iter().position(|range| range.contains(&y))?;
    match (row, column) {
        (0..=2, 0..=2) => Some(PinPadAction::Digit(b'1' + (row * 3 + column) as u8)),
        (3, 0) => Some(PinPadAction::Backspace),
        (3, 1) => Some(PinPadAction::Digit(b'0')),
        (3, 2) => Some(PinPadAction::Submit),
        _ => None,
    }
}

impl<'a> BootDisplay<'a> {
    pub fn draw_storage_mode_choice(&mut self) {
        self.draw_wallet_choice(false);
    }

    pub fn draw_add_wallet_choice(&mut self) {
        self.draw_wallet_choice(true);
    }

    fn draw_wallet_choice(&mut self, show_back: bool) {
        if show_back { self.clear_keep_nav(); } else { self.clear_screen(); }
        self.draw_storage_header("WELCOME");
        self.draw_storage_button(42, "Create Wallet");
        self.draw_centered_hint("Create new recovery words securely.", 96);
        self.draw_storage_button(125, "Restore Wallet");
        self.draw_centered_hint("Words, SeedQR, SD, or advanced restore.", 179);
    }

    pub fn draw_storage_finalize_choice(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("STORAGE");
        self.draw_storage_button(42, "Save Securely on Device");
        self.draw_centered_hint("Protected by this signer device.", 96);
        self.draw_storage_button(125, "Use for This Session Only");
        self.draw_centered_hint("Wallet is cleared when power is removed.", 179);
    }

    pub fn draw_restore_word_12_detected(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("RECOVERY WORDS");
        self.draw_centered_hint("The first 12 words form a valid wallet.", 54);
        self.draw_storage_button(76, "Restore 12-Word Wallet");
        self.draw_storage_button(130, "Continue to 24 Words");
        self.draw_centered_hint("Choose Continue if your backup has 24 words.", 190);
    }

    pub fn draw_storage_seed_dice_choice(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("ADD DICE");
        self.draw_storage_button(58, "No Dice");
        self.draw_storage_button(112, "Add Dice Rolls");
        self.draw_centered_hint("Hardware + camera are always used.", 174);
        self.draw_centered_hint("Dice can add extra user entropy.", 192);
    }

    pub fn draw_storage_seed_dice_count_choice(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("HOW MANY DICE ROLLS?");
        self.draw_storage_button(48, "25 Rolls");
        self.draw_storage_button(90, "50 Rolls");
        self.draw_storage_button(132, "100 Rolls");
        self.draw_storage_button(174, "200 Rolls");
    }

    pub fn draw_storage_seed_touch_choice(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("ADD TOUCH");
        self.draw_storage_button(58, "No Touch Entropy");
        self.draw_storage_button(112, "Add Touch Entropy");
        self.draw_centered_hint("Touch adds extra entropy.", 183);
    }

    pub fn draw_storage_recovery_acknowledgement(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("RECOVERY BACKUP");
        // Keep every line comfortably inside 320 px. Long centered strings can
        // otherwise start at a negative x-coordinate and clip both ends.
        self.draw_centered_hint("Recovery words are your", 58);
        self.draw_centered_hint("permanent portable backup.", 76);
        self.draw_centered_hint("Store them privately and securely.", 98);
        self.draw_centered_hint("They restore your wallet elsewhere.", 118);
        self.draw_centered_hint("Device storage is a convenience copy.", 138);
        self.draw_storage_button(168, "I BACKED UP MY WORDS");
    }

    pub fn draw_storage_protection_choice(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("PROTECT THIS WALLET?");
        self.draw_storage_button(48, "Use PIN / Password");
        self.draw_centered_hint("Recommended", 98);
        self.draw_storage_button(118, "No PIN / Password");
        self.draw_centered_hint("Anyone with physical access", 176);
        self.draw_centered_hint("can use an unprotected wallet.", 194);
    }

    pub fn draw_storage_credential_type(&mut self) {
        self.clear_keep_nav();
        self.draw_storage_header("PIN OR PASSWORD");
        self.draw_storage_button(48, "Use PIN");
        self.draw_storage_button(96, "Use Password");
        self.draw_centered_hint("Weak credentials are easier to crack.", 151);
        self.draw_centered_hint("PIN: 6-12 digits.", 169);
        self.draw_centered_hint("Password: 8+ with a letter + number.", 187);
        self.draw_centered_hint("12+ mixed characters recommended.", 205);
    }

    pub fn draw_storage_pin_entry(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        title: &str,
        reveal: bool,
    ) {
        self.clear_keep_nav();
        self.draw_storage_header(title);
        if reveal {
            self.draw_visible_pin(input);
        } else {
            self.draw_masked_pin(input);
        }
        self.draw_pin_pad();
    }

    pub fn update_storage_pin_value(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        reveal: bool,
    ) {
        Rectangle::new(Point::new(0, 40), Size::new(320, 38))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        if reveal { self.draw_visible_pin(input); } else { self.draw_masked_pin(input); }
    }

    pub fn draw_storage_secret_entry(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        title: &str,
        numeric: bool,
        reveal: bool,
    ) {
        self.clear_keep_nav();
        self.draw_storage_header(title);

        if reveal {
            self.draw_visible_credential(input);
        } else {
            self.draw_masked_credential(input);
        }

        crate::ui::keyboard::draw_keyboard(
            &mut self.display,
            if numeric { KeyboardMode::Numeric } else { KeyboardMode::Full },
            input.page,
        );
    }

    #[cfg(feature = "m5stack")]
    pub fn draw_numeric_format_entry(
        &mut self,
        input: &crate::wallet::seed_manager::PassphraseInput,
        title: &str,
        hint: &str,
    ) {
        self.draw_storage_secret_entry(input, title, true, true);
        if input.len == 0 {
            Rectangle::new(Point::new(0, 40), Size::new(320, 38))
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut self.display).ok();
            self.draw_centered_hint(hint, 63);
        }
    }

    fn draw_visible_pin(&mut self, input: &crate::wallet::seed_manager::PassphraseInput) {
        if input.len == 0 {
            self.draw_centered_hint("PIN will be shown here", 63);
            return;
        }
        let end = input.len.min(12);
        let text = core::str::from_utf8(&input.buf[..end]).unwrap_or("");
        let width = measure_title(text);
        draw_lato_title(&mut self.display, text, (320i32.saturating_sub(width) / 2).max(18), 65, COLOR_TEXT);
    }

    fn draw_masked_pin(&mut self, input: &crate::wallet::seed_manager::PassphraseInput) {
        let visible = input.len.min(12);
        let star_width = measure_title("*");
        let total_width = star_width.saturating_mul(visible as i32);
        let mut x = (320i32.saturating_sub(total_width) / 2).max(8);
        for _ in 0..visible {
            draw_lato_title(&mut self.display, "*", x, 65, COLOR_TEXT);
            x = x.saturating_add(star_width);
        }
        if visible == 0 {
            self.draw_centered_hint("Enter PIN to unlock", 63);
        }
    }

    fn draw_pin_pad(&mut self) {
        const LABELS: [[&str; 3]; 4] = [
            ["1", "2", "3"],
            ["4", "5", "6"],
            ["7", "8", "9"],
            ["DEL", "0", "OK"],
        ];
        for (row, y_range) in PIN_PAD_Y.iter().enumerate() {
            for (column, x_range) in PIN_PAD_X.iter().enumerate() {
                let x = i32::from(*x_range.start());
                let y = i32::from(*y_range.start());
                let width = u32::from(*x_range.end() - *x_range.start() + 1);
                let height = u32::from(*y_range.end() - *y_range.start() + 1);
                let rectangle = Rectangle::new(Point::new(x, y), Size::new(width, height));
                let corners = CornerRadii::new(Size::new(6, 6));
                RoundedRectangle::new(rectangle, corners)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(rectangle, corners)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
                let label = LABELS[row][column];
                let label_width = measure_title(label);
                draw_lato_title(
                    &mut self.display,
                    label,
                    x + (width as i32 - label_width) / 2,
                    y + 23,
                    COLOR_TEXT,
                );
            }
        }
    }

    fn draw_visible_credential(&mut self, input: &crate::wallet::seed_manager::PassphraseInput) {
        if input.len == 0 {
            self.draw_centered_hint("Your entry will be shown here", 63);
            return;
        }
        // Setup/confirmation deliberately shows the credential so the owner can
        // verify exactly what was entered. Bound the window so long passwords
        // cannot clip off-screen; unlock screens remain masked.
        let window = 20usize;
        let start = input.cursor.saturating_sub(window).min(input.len.saturating_sub(window.min(input.len)));
        let end = (start + window).min(input.len);
        let text = core::str::from_utf8(&input.buf[start..end]).unwrap_or("");
        let width = measure_title(text);
        draw_lato_title(&mut self.display, text, ((320 - width) / 2).max(18), 65, COLOR_TEXT);
        if start > 0 { draw_lato_hint(&mut self.display, "<", 8, 62, COLOR_TEXT_DIM); }
        if end < input.len { draw_lato_hint(&mut self.display, ">", 306, 62, COLOR_TEXT_DIM); }
    }

    fn draw_masked_credential(&mut self, input: &crate::wallet::seed_manager::PassphraseInput) {
        let visible = input.len.min(22);
        let star_width = measure_title("*");
        let total_width = star_width * visible as i32;
        let mut x = ((320 - total_width) / 2).max(8);
        for _ in 0..visible {
            draw_lato_title(&mut self.display, "*", x, 65, COLOR_TEXT);
            x += star_width;
        }
        if input.len > visible {
            draw_lato_hint(&mut self.display, "...", 292, 62, COLOR_TEXT_DIM);
        }
        if input.len == 0 {
            self.draw_centered_hint("Enter credential to unlock", 63);
        }
    }

    fn draw_storage_header(&mut self, title: &str) {
        let title_width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - title_width) / 2, 26, KASPA_TEAL);
        Line::new(Point::new(20, 34), Point::new(300, 34))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
    }

    fn draw_storage_button(&mut self, y: i32, label: &str) {
        let rectangle = Rectangle::new(Point::new(18, y), Size::new(284, 35));
        let corners = CornerRadii::new(Size::new(7, 7));
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(rectangle, corners)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let width = measure_title(label);
        draw_lato_title(&mut self.display, label, (320 - width) / 2, y + 24, COLOR_TEXT);
    }

    fn draw_centered_hint(&mut self, text: &str, y: i32) {
        let width = measure_hint(text);
        draw_lato_hint(&mut self.display, text, (320 - width) / 2, y, COLOR_TEXT_DIM);
    }
}

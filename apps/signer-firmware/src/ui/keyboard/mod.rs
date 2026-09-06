//! Unified keyboard facade.

mod renderer;

pub use signer_firmware_core::input::keyboard::{hit_test, KeyAction, KeyboardMode};
pub use renderer::draw_keyboard;

pub fn suggestion_chip(
    x: u16,
    y: u16,
    word_input: &crate::wallet::mnemonic::WordInput,
) -> Option<u16> {
    signer_firmware_core::input::keyboard::suggestion_hit_test(
        x,
        y,
        word_input.num_suggestions,
        &word_input.suggestions,
    )
}

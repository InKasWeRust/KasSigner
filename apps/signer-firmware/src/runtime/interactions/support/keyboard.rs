// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Shared keyboard interaction controller.

use crate::{
    hw::display::BootDisplay,
    ui::keyboard::{hit_test, KeyAction, KeyboardMode},
    wallet::seed_manager::PassphraseInput,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyboardAction {
    None,
    Edited,
    Submitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyboardPolicy {
    pub(crate) allow_space: bool,
}

impl KeyboardPolicy {
    pub(crate) const PASSPHRASE: Self = Self { allow_space: true };
    pub(crate) const COMPACT_TEXT: Self = Self { allow_space: false };
}

pub(crate) fn handle_keyboard(
    input: &mut PassphraseInput,
    display: &mut BootDisplay<'_>,
    x: u16,
    y: u16,
    policy: KeyboardPolicy,
) -> KeyboardAction {
    match hit_test(x, y, KeyboardMode::Full, input.page) {
        KeyAction::Char(character) => {
            input.push_char(character);
            display.draw_keyboard_screen(input);
            KeyboardAction::Edited
        }
        KeyAction::Page => {
            input.next_page();
            display.draw_keyboard_keys_only(input);
            KeyboardAction::Edited
        }
        KeyAction::Backspace => {
            input.backspace();
            display.draw_keyboard_screen(input);
            KeyboardAction::Edited
        }
        KeyAction::Space if policy.allow_space => {
            input.push_char(b' ');
            display.draw_keyboard_screen(input);
            KeyboardAction::Edited
        }
        KeyAction::CursorLeft => {
            input.cursor_left();
            display.draw_keyboard_screen(input);
            KeyboardAction::Edited
        }
        KeyAction::CursorRight => {
            input.cursor_right();
            display.draw_keyboard_screen(input);
            KeyboardAction::Edited
        }
        KeyAction::Ok => KeyboardAction::Submitted,
        _ => KeyboardAction::None,
    }
}

pub(crate) fn handle_passphrase_keyboard(
    input: &mut PassphraseInput,
    display: &mut BootDisplay<'_>,
    x: u16,
    y: u16,
) -> KeyboardAction {
    handle_keyboard(input, display, x, y, KeyboardPolicy::PASSPHRASE)
}

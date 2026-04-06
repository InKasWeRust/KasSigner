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

// ui/helpers.rs — Shared UI helper functions (hit-test, validation)


use crate::{ui::setup_wizard, ui::seed_manager, wallet};

/// Passphrase keyboard hit-test — shared by stego, sd, and seed handlers.
/// Returns: 0=miss, 1=char typed (or cursor moved), 2=page toggle, 4=backspace, 5=space, 6=done.
pub fn pp_keyboard_hit(x: u16, y: u16, pp: &mut seed_manager::PassphraseInput) -> u8 {
    use crate::ui::keyboard::{hit_test, KeyboardMode, KeyAction};
    match hit_test(x, y, KeyboardMode::Full, pp.page) {
        KeyAction::Char(ch) => { pp.push_char(ch); 1 }
        KeyAction::Page => 2,
        KeyAction::Backspace => 4,
        KeyAction::Space => 5,
        KeyAction::Ok => 6,
        KeyAction::CursorLeft => { pp.cursor_left(); 1 }
        KeyAction::CursorRight => { pp.cursor_right(); 1 }
        _ => 0,
    }
}
/// Check suggestion chip taps. Returns Some(word_index) if tapped.
#[inline(never)]
pub fn suggestion_hit_test(x: u16, y: u16, word_input: &setup_wizard::WordInput) -> Option<u16> {
    if !(72..=96).contains(&y) || word_input.num_suggestions <= 1 {
        return None;
    }
    for i in 0..(word_input.num_suggestions as usize).min(3) {
        let sx = 4 + (i as u16) * 106;
        if x >= sx && x < sx + 102 {
            return Some(word_input.suggestions[i]);
        }
    }
    None
}

/// Validate a complete mnemonic (12 or 24 words)
#[inline(never)]
pub fn validate_mnemonic(indices: &[u16; 24], wc: u8) -> bool {
    if wc == 12 {
        let m = wallet::bip39::Mnemonic12 {
            indices: {
                let mut arr = [0u16; 12];
                arr.copy_from_slice(&indices[..12]);
                arr
            }
        };
        wallet::bip39::validate_mnemonic_12(&m).is_ok()
    } else {
        let m = wallet::bip39::Mnemonic24 {
            indices: {
                let mut arr = [0u16; 24];
                arr.copy_from_slice(&indices[..24]);
                arr
            }
        };
        wallet::bip39::validate_mnemonic_24(&m).is_ok()
    }
}

/// Compute last word for calc-last-word feature
#[inline(never)]
pub fn compute_last_word(indices: &[u16; 24], wc: u8) -> u16 {
    if wc == 12 {
        let mut arr = [0u16; 11];
        arr.copy_from_slice(&indices[..11]);
        setup_wizard::calc_last_word_12(&arr)
    } else {
        let mut arr = [0u16; 23];
        arr.copy_from_slice(&indices[..23]);
        setup_wizard::calc_last_word_24(&arr)
    }
}

/// Parse a single hex character to its 4-bit value. Returns 0xFF on invalid.
pub fn hex_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0xFF,
    }
}

/// Derive all 20 Kaspa pubkeys from mnemonic + passphrase into cache.
/// Also caches the account key (65 bytes) for instant out-of-range derivations.
/// Takes ~5s on ESP32-S3 (PBKDF2 dominates). After this, address switching is instant.
#[inline(never)]
pub fn format_test_line<'a>(buf: &'a mut [u8; 40], prefix: &str, value: u32, suffix: &str) -> &'a str {
    let mut pos = 0usize;
    for &b in prefix.as_bytes() {
        if pos < 40 { buf[pos] = b; pos += 1; }
    }
    // Format number
    if value == 0 {
        if pos < 40 { buf[pos] = b'0'; pos += 1; }
    } else {
        let mut digits = [0u8; 10];
        let mut n = value;
        let mut dpos = 0;
        while n > 0 {
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
        for i in (0..dpos).rev() {
            if pos < 40 { buf[pos] = digits[i]; pos += 1; }
        }
    }
    for &b in suffix.as_bytes() {
        if pos < 40 { buf[pos] = b; pos += 1; }
    }
    core::str::from_utf8(&buf[..pos]).unwrap_or("?")
}

//
// Never returns. Shows error on screen indefinitely.
// In production there is no UART output, only the screen.

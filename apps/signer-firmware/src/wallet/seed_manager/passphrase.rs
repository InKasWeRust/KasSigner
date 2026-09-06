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

// BIP39 passphrase keyboard state.

/// Passphrase input state for BIP39 passphrase entry.
/// Supports a-z, A-Z, 0-9, space, and basic symbols.
pub struct PassphraseInput {
    pub buf: [u8; 128],
    pub len: usize,
    /// Cursor position (0 = before first char, len = after last char)
    pub cursor: usize,
    /// Keyboard page: 0=lowercase, 1=uppercase, 2=digits+symbols
    pub page: u8,
}

impl PassphraseInput {
        /// Create a new empty passphrase input.
pub fn new() -> Self {
        Self {
            buf: [0; 128],
            len: 0,
            cursor: 0,
            page: 0,
        }
    }

        /// Insert a character at cursor position.
pub fn push_char(&mut self, c: u8) {
        if self.len < 128 {
            // Shift everything after cursor right by 1
            let mut i = self.len;
            while i > self.cursor {
                self.buf[i] = self.buf[i - 1];
                i -= 1;
            }
            self.buf[self.cursor] = c;
            self.len += 1;
            self.cursor += 1;
        }
    }

        /// Delete character before cursor (backspace).
pub fn backspace(&mut self) {
        if self.cursor > 0 {
            // Shift everything after cursor left by 1
            let mut i = self.cursor - 1;
            while i + 1 < self.len {
                self.buf[i] = self.buf[i + 1];
                i += 1;
            }
            self.len -= 1;
            self.buf[self.len] = 0;
            self.cursor -= 1;
        }
    }

        /// Move cursor left.
pub fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

        /// Move cursor right.
pub fn cursor_right(&mut self) {
        if self.cursor < self.len {
            self.cursor += 1;
        }
    }

        /// Clear the passphrase buffer completely.
pub fn reset(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.buf);
        self.len = 0;
        self.cursor = 0;
        self.page = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

        /// Cycle to the next keyboard page (lowercase → uppercase → symbols).
pub fn next_page(&mut self) {
        self.page = (self.page + 1) % 4;
    }

        /// Get the current passphrase as a UTF-8 string slice.
pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

}

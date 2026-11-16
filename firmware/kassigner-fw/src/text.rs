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

//! Text typed on the keyboard (printable ASCII, a cursor, a fixed most,
//! wiped when cleared or dropped), and bytes written as hex.
//!
//! What is typed is usually a secret: a passphrase, a backup's password. It
//! lives in this one buffer and is never part of a [`crate::flow::Screen`],
//! which the binary prints on its console: the screen carries only a
//! [`Field`], whose debug output says nothing.

use crate::wipe;

/// Printable ASCII (the keyboard's alphabet), what counts as a message and
/// which messages this unit signs: level 1's rules
/// ([`kassigner_protocol::message`]), which a companion applies too.
pub use kassigner_protocol::message::{is_signable, is_text as is_message, printable, read_hex};

/// `bytes` as hex, lower case, into `out`, which needs twice their length.
/// Returns the characters written.
pub fn write_hex(bytes: &[u8], out: &mut [u8]) -> usize {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = DIGITS[usize::from(b >> 4)];
        out[i * 2 + 1] = DIGITS[usize::from(b & 0x0F)];
    }
    bytes.len() * 2
}

/// Text being typed, at most `N` bytes, with a cursor in it.
pub struct Typed<const N: usize> {
    bytes: [u8; N],
    len: usize,
    cursor: usize,
}

impl<const N: usize> Default for Typed<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Typed<N> {
    /// Nothing typed.
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
            cursor: 0,
        }
    }

    /// What is typed.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// What is typed, as text: printable ASCII, so always valid.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Bytes typed.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing is typed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Where the cursor is: the bytes before it.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The length and cursor, for a screen to compare and not to show.
    pub fn field(&self) -> Field {
        Field {
            len: u8::try_from(self.len).unwrap_or(u8::MAX),
            cursor: u8::try_from(self.cursor).unwrap_or(u8::MAX),
        }
    }

    /// Put `c` at the cursor and move past it. Nothing happens if `c` is
    /// not printable or the text is full; the answer says which.
    pub fn insert(&mut self, c: u8) -> bool {
        if !printable(c) || self.len == N {
            return false;
        }
        self.bytes
            .copy_within(self.cursor..self.len, self.cursor + 1);
        self.bytes[self.cursor] = c;
        self.len += 1;
        self.cursor += 1;
        true
    }

    /// Remove the byte before the cursor, if there is one.
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.bytes
            .copy_within(self.cursor..self.len, self.cursor - 1);
        self.len -= 1;
        self.cursor -= 1;
        self.bytes[self.len] = 0;
    }

    /// Move the cursor one back, if it can.
    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the cursor one on, if it can.
    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.len);
    }

    /// Wipe it all.
    pub fn clear(&mut self) {
        wipe::wipe(&mut self.bytes);
        self.len = 0;
        self.cursor = 0;
    }
}

impl<const N: usize> Drop for Typed<N> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// How much is typed and where the cursor is, without what: the part of
/// typed text a screen may carry. It changes with an edit, so the screen is
/// redrawn; printed, it shows nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Field {
    len: u8,
    cursor: u8,
}

impl core::fmt::Debug for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Field(..)")
    }
}

/// A number a screen carries to tell its states apart, which the console
/// must not print: which valid last word is shown is seven bits of a seed.
/// Also the digits typed on a keypad and the BIP85 child's index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hidden<T = u16>(pub T);

impl<T> core::fmt::Debug for Hidden<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hidden(..)")
    }
}

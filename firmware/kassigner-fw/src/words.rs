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

//! Looking a word up as it is typed.
//!
//! A prefix is up to eight lower-case letters, the longest BIP39 word. Its
//! matches are the list's words that start with it: how many, the first
//! three (shown as suggestions), and the one it is exactly. A prefix is
//! taken as a word when it is one, or when it matches only one.

use kassigner_crypto::bip39::index_to_word;

/// The longest BIP39 word, and so the most a prefix holds.
pub const PREFIX_MAX: usize = 8;

/// Suggestions shown.
pub const SHOWN: usize = 3;

/// What a prefix matches in the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// How many words start with it.
    pub count: u16,
    /// The first [`Lookup::shown`] of them, in the list's order.
    pub first: [u16; SHOWN],
    pub shown: usize,
    /// The word it is exactly, if it is one.
    pub exact: Option<u16>,
}

impl Lookup {
    /// The word the prefix stands for, if it stands for one: the word it is,
    /// or the only word it starts.
    pub const fn taken(&self) -> Option<u16> {
        match (self.exact, self.count) {
            (Some(i), _) => Some(i),
            (None, 1) => Some(self.first[0]),
            _ => None,
        }
    }
}

/// The list's words starting with `prefix`; an empty prefix matches
/// nothing.
pub fn lookup(prefix: &str) -> Lookup {
    let mut l = Lookup {
        count: 0,
        first: [0; SHOWN],
        shown: 0,
        exact: None,
    };
    if prefix.is_empty() {
        return l;
    }
    for i in 0..2048u16 {
        let Some(word) = index_to_word(i) else {
            break;
        };
        if !word.starts_with(prefix) {
            continue;
        }
        if l.shown < SHOWN {
            l.first[l.shown] = i;
            l.shown += 1;
        }
        if word.len() == prefix.len() {
            l.exact = Some(i);
        }
        l.count += 1;
    }
    l
}

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

use kassigner_crypto::bip39::{index_to_word, word_to_index};
use kassigner_fw::words::{lookup, SHOWN};

/// **A prefix and what it matches.** An empty or unmatched prefix stands
/// for nothing; a prefix of one word stands for it; a whole word stands for
/// itself even when longer words start with it; several matches suggest the
/// first three.
#[test]
fn a_prefix_stands_for_a_word_when_it_can() {
    let i = |w: &str| word_to_index(w).unwrap();
    assert_eq!(lookup("").count, 0);

    let one = lookup("aba");
    assert_eq!((one.count, one.taken()), (1, Some(i("abandon"))));

    let whole = lookup("act");
    assert!(whole.count > 1, "action, actor and more start with it");
    assert_eq!(whole.taken(), Some(i("act")));

    let many = lookup("ab");
    assert!(many.count > SHOWN as u16);
    assert_eq!(many.shown, SHOWN);
    assert_eq!(many.taken(), None);
    let shown: Vec<&str> = many
        .first
        .iter()
        .map(|&w| index_to_word(w).unwrap())
        .collect();
    assert_eq!(shown, ["abandon", "ability", "able"]);

    assert_eq!(lookup("qz").count, 0);
    assert_eq!(lookup("qz").taken(), None);
    assert_eq!(lookup("zoo").taken(), Some(i("zoo")));
}

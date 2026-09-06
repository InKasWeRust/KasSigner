// BIP39 word-list lookup.

use super::Bip39Error;
use crate::derivation::bip39_wordlist::WORDLIST;

// ─── Word ↔ index conversion ────────────────────────────────────

/// Look up a word in the wordlist and return its index.
/// Binary search O(log n) since the wordlist is alphabetically sorted.
pub fn word_to_index(word: &str) -> Result<u16, Bip39Error> {
    WORDLIST
        .binary_search_by(|candidate| str_cmp(candidate, word))
        .map(|index| index as u16)
        .map_err(|_| Bip39Error::WordNotFound)
}

/// Return the word corresponding to an index (0-2047).
pub fn index_to_word(index: u16) -> &'static str {
    if (index as usize) < WORDLIST.len() {
        WORDLIST[index as usize]
    } else {
        "???"
    }
}

/// no-std string comparison (lexicographic, byte-by-byte).
fn str_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.as_bytes().cmp(b.as_bytes())
}

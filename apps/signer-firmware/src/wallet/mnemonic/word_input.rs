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

// BIP39 word-prefix input and suggestions.

/// Word input state for importing mnemonics
pub struct WordInput {
    /// Current prefix being typed (up to 8 chars)
    pub prefix: [u8; 8],
    pub prefix_len: usize,
    /// Matching word index from wordlist (-1 = no match)
    pub matched_index: Option<u16>,
    /// Number of matches for current prefix
    pub match_count: u16,
    /// First few matching indices (for showing suggestions)
    pub suggestions: [u16; 4],
    pub num_suggestions: u8,
}

impl WordInput {
    pub fn new() -> Self {
        Self {
            prefix: [0; 8],
            prefix_len: 0,
            matched_index: None,
            match_count: 0,
            suggestions: [0; 4],
            num_suggestions: 0,
        }
    }

    /// Add a character to the prefix and update matches
    pub fn push_char(&mut self, c: u8) {
        if self.prefix_len < 8 {
            self.prefix[self.prefix_len] = c;
            self.prefix_len += 1;
            self.update_matches();
        }
    }

    /// Remove last character
    pub fn backspace(&mut self) {
        if self.prefix_len > 0 {
            self.prefix_len -= 1;
            self.prefix[self.prefix_len] = 0;
            self.update_matches();
        }
    }

    /// Reset for next word
    pub fn reset(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.prefix);
        shared_signer::bytes::zeroize_u16(&mut self.suggestions);
        self.prefix_len = 0;
        self.matched_index = None;
        self.match_count = 0;
        self.num_suggestions = 0;
    }

    /// Update matching words from the BIP39 wordlist
    fn update_matches(&mut self) {
        use offline_signer::derivation::bip39_wordlist::WORDLIST;

        self.match_count = 0;
        self.matched_index = None;
        self.num_suggestions = 0;

        if self.prefix_len == 0 {
            return;
        }

        let prefix = &self.prefix[..self.prefix_len];

        for (idx, &word) in WORDLIST.iter().enumerate() {
            let word_bytes = word.as_bytes();
            if word_bytes.len() >= self.prefix_len {
                let matches = word_bytes[..self.prefix_len]
                    .iter()
                    .zip(prefix.iter())
                    .all(|(a, b)| *a == *b);

                if matches {
                    self.match_count += 1;

                    if (self.num_suggestions as usize) < 4 {
                        self.suggestions[self.num_suggestions as usize] = idx as u16;
                        self.num_suggestions += 1;
                    }

                    // Exact match?
                    if word_bytes.len() == self.prefix_len {
                        self.matched_index = Some(idx as u16);
                    }
                }
            }
        }

        // If only one match, auto-select it
        if self.match_count == 1 {
            self.matched_index = Some(self.suggestions[0]);
        }
    }

    /// Get the prefix as a str
    pub fn prefix_str(&self) -> &str {
        core::str::from_utf8(&self.prefix[..self.prefix_len]).unwrap_or("")
    }
}

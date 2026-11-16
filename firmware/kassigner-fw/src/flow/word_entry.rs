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

//! Words typed one at a time, for Import Words and Calc Last Word.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// 12 or 24 words; the chosen tool starts fresh.
    pub(super) fn on_word_count(&mut self, event: Event<'_>, action: CountFor) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match word_screens::count_target(self.scale, x, y)? {
            word_screens::Target::Nav(Nav::Home) => self.leave_words(State::Home),
            word_screens::Target::Words(n) => {
                let next = match action {
                    CountFor::Words(action) => State::Words { action },
                    CountFor::Dice => State::Dice,
                    CountFor::Bip85 => State::Bip85,
                };
                self.leave_words(next);
                self.leave_dice();
                self.word_count = usize::from(n);
                self.bip85_index = 0;
            }
            _ => self.leave_words(seed_tools(action)),
        }
        None
    }

    /// A word at a time: letters, then a suggestion or OK takes the word.
    /// The arrows move between the words entered, to keep or retype. Back
    /// leaves, every word wiped.
    pub(super) fn on_words(&mut self, event: Event<'_>, action: WordsFor) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let mode = self.word_mode();
        let target = keyboard::target(self.scale, 0, mode, x, y)?;
        if !matches!(target, keyboard::Target::Nav(_)) {
            self.word_invalid = false;
        }
        match target {
            keyboard::Target::Nav(Nav::Home) => self.leave_words(State::Home),
            keyboard::Target::Nav(_) => self.leave_words(seed_tools(CountFor::Words(action))),
            keyboard::Target::Chip(i) => {
                let found = lookup(self.typed.as_str());
                if usize::from(i) < found.shown {
                    self.take_word(action, found.first[usize::from(i)]);
                }
            }
            keyboard::Target::Key(keyboard::Key::Char(c)) => {
                if self.typed.len() < PREFIX_MAX {
                    self.typed.insert(c);
                }
            }
            keyboard::Target::Key(keyboard::Key::Delete) => self.typed.backspace(),
            keyboard::Target::Key(keyboard::Key::Left) => self.show_word(self.word_pos - 1),
            keyboard::Target::Key(keyboard::Key::Right) => self.show_word(self.word_pos + 1),
            keyboard::Target::Key(keyboard::Key::Ok) => {
                if let Some(i) = lookup(self.typed.as_str()).taken() {
                    self.take_word(action, i);
                }
            }
            keyboard::Target::Key(_) => {}
        }
        None
    }

    /// Which word keys act at this point of the typing.
    pub(super) fn word_mode(&self) -> keyboard::Mode {
        let found = lookup(self.typed.as_str());
        keyboard::Mode::Word {
            back: self.word_pos > 0,
            on: self.word_pos < self.word_filled,
            take: found.taken().is_some(),
            chips: if found.count > 1 {
                found.shown as u8
            } else {
                0
            },
        }
    }

    /// Go to place `pos`, its word (if any) on the line to keep or retype.
    pub(super) fn show_word(&mut self, pos: usize) {
        self.typed.clear();
        self.word_pos = pos.min(self.word_filled);
        if self.word_pos < self.word_filled {
            if let Some(word) = index_to_word(self.phrase[self.word_pos]) {
                for &c in word.as_bytes() {
                    self.typed.insert(c);
                }
            }
        }
    }

    /// Word `i` at the place being typed, then the next place. With every
    /// place filled, Import checks the phrase: valid, on to the passphrase;
    /// invalid, flagged, staying on the last word. Calc Last Word goes to the
    /// last word.
    pub(super) fn take_word(&mut self, action: WordsFor, i: u16) {
        let pos = self.word_pos;
        self.phrase[pos] = i;
        self.word_filled = self.word_filled.max(pos + 1);
        let needed = match action {
            WordsFor::Import => self.word_count,
            WordsFor::LastWord => self.word_count - 1,
        };
        if pos + 1 < needed {
            self.show_word(pos + 1);
            return;
        }
        // The last place: the first empty earlier place is next.
        if self.word_filled < needed {
            self.show_word(self.word_filled);
            return;
        }
        match action {
            WordsFor::LastWord => {
                self.typed.clear();
                self.state = State::LastWord { choice: 0 };
            }
            WordsFor::Import => match bip39::from_indices(&self.phrase[..self.word_count]) {
                Ok(m) => {
                    self.hold_loaded(m);
                    // The words wiped, the passphrase next.
                    self.leave_words(State::Home);
                    self.ask_passphrase();
                }
                Err(_) => {
                    self.word_invalid = true;
                    self.show_word(pos);
                }
            },
        }
    }

    /// Calc Last Word's last word: the arrows step through the valid ones,
    /// wrapping; OK takes it, on to the passphrase. Back goes to the word
    /// before.
    pub(super) fn on_last_word(&mut self, event: Event<'_>, choice: u16) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let first = self.word_count - 1;
        let choices = bip39::last_word_choices(first).unwrap_or(1);
        match word_screens::last_target(self.scale, x, y)? {
            word_screens::Target::Nav(Nav::Home) => self.leave_words(State::Home),
            word_screens::Target::Nav(Nav::PageUp) => {
                self.state = State::LastWord {
                    choice: (choice + choices - 1) % choices,
                }
            }
            word_screens::Target::Nav(Nav::PageDown) => {
                self.state = State::LastWord {
                    choice: (choice + 1) % choices,
                }
            }
            word_screens::Target::Ok => {
                let words = bip39::last_word(&self.phrase[..first], choice)
                    .ok()
                    .and_then(|last| {
                        self.phrase[first] = last;
                        bip39::from_indices(&self.phrase[..self.word_count]).ok()
                    });
                match words {
                    Some(m) => {
                        self.hold_loaded(m);
                        // The words wiped, the passphrase next.
                        self.leave_words(State::Home);
                        self.ask_passphrase();
                    }
                    None => self.leave_words(seed_tools(CountFor::Words(WordsFor::LastWord))),
                }
            }
            word_screens::Target::Nav(_) => {
                self.state = State::Words {
                    action: WordsFor::LastWord,
                };
                self.show_word(first - 1);
            }
            word_screens::Target::Words(_) => {}
        }
        None
    }

    /// Leave a word tool for `next`: every word and letter wiped.
    pub(super) fn leave_words(&mut self, next: State) {
        self.phrase.zeroize();
        self.typed.clear();
        self.word_pos = 0;
        self.word_filled = 0;
        self.word_invalid = false;
        self.state = next;
    }

    /// The word being typed, for drawing its line: the keys that act, the
    /// word, the suggestions or an error. Never part of a [`Screen`].
    pub fn word_line(&self) -> (keyboard::Mode, keyboard::WordLine<'static>) {
        let typed = self.typed.as_str();
        let found = lookup(typed);
        let word = |i: u16| index_to_word(i).unwrap_or("");
        let completes = found.taken().map(word).filter(|&w| w != typed);
        let mut chips = [""; crate::words::SHOWN];
        for (c, &i) in chips.iter_mut().zip(&found.first[..found.shown]) {
            *c = word(i);
        }
        let status = if self.word_invalid {
            Some(("Invalid seed phrase", crate::ui::color::DANGER))
        } else if !typed.is_empty() && found.count == 0 {
            Some(("No matches", crate::ui::color::DANGER))
        } else {
            None
        };
        let line = keyboard::WordLine {
            completes,
            chips,
            shown: if found.count > 1 { found.shown } else { 0 },
            status,
        };
        (self.word_mode(), line)
    }

    /// Calc Last Word's word, its number and the count, for drawing: never
    /// part of a [`Screen`].
    pub fn last_word(&self) -> Option<(&'static str, u16, u16)> {
        let State::LastWord { choice } = self.state else {
            return None;
        };
        let first = self.word_count - 1;
        let choices = bip39::last_word_choices(first)?;
        let last = bip39::last_word(&self.phrase[..first], choice).ok()?;
        Some((index_to_word(last)?, choice, choices))
    }
}

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

//! Seed Tools: Dice Seed, BIP85 Child, a seed's words and SeedQR.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// Dice Seed: a tap per roll, UNDO taking one back. At the count the
    /// seed is made, its words shown, then its passphrase. Rolls that do not
    /// look like dice are refused; a face under [`DICE_UNEVEN_PERCENT`] of
    /// them brings UNEVEN ROLLS. The rolls are wiped at the count, and on
    /// Back or Home.
    pub(super) fn on_dice(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match dice_screen::target(self.scale, self.rolled, x, y)? {
            dice_screen::Target::Nav(Nav::Home) => {
                self.leave_dice();
                self.state = State::Home;
            }
            dice_screen::Target::Nav(_) => {
                self.leave_dice();
                self.state = seed_tools(CountFor::Dice);
            }
            dice_screen::Target::Undo => self.rolled = self.rolled.saturating_sub(1),
            dice_screen::Target::Face(f) => {
                let target = self.dice_target();
                if self.rolled < target {
                    // As characters: the crate hashes typed digits, so a
                    // seed can be checked off the device as other tools do.
                    self.rolls[self.rolled] = b'0' + f;
                    self.rolled += 1;
                }
                if self.rolled == target {
                    let words = if self.word_count == 24 {
                        Words::TwentyFour
                    } else {
                        Words::Twelve
                    };
                    let made = kassigner_crypto::seed::from_dice(&self.rolls[..target], words);
                    let uneven = least_face(&self.rolls[..target]);
                    self.leave_dice();
                    match made {
                        Ok(m) => match uneven {
                            Some(least) => {
                                self.uneven = least;
                                self.pending = Some(m);
                                self.state = State::DiceUneven;
                            }
                            None => self.show_new_words(m, AfterWords::Passphrase),
                        },
                        Err(_) => {
                            self.since_us = self.now_us;
                            self.state = State::DiceRefused;
                        }
                    }
                }
            }
        }
        None
    }

    /// UNEVEN ROLLS: ROLL AGAIN (left) or Back drops the seed and rolls
    /// again; USE THEM goes on to its words; Home drops it.
    pub(super) fn on_dice_uneven(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let answer = tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))?;
        self.uneven = (0, 0);
        match answer {
            dialog::Target::Accept => match self.pending.take() {
                Some(m) => self.show_new_words(m, AfterWords::Passphrase),
                None => self.state = State::Home,
            },
            dialog::Target::Nav(Nav::Home) => {
                self.pending = None;
                self.state = State::Home;
            }
            dialog::Target::Cancel | dialog::Target::Nav(_) => {
                self.pending = None;
                self.state = State::Dice;
            }
        }
        None
    }

    /// UNEVEN ROLLS' face, its count and the rolls' count, for drawing.
    pub fn dice_uneven(&self) -> Option<(u8, usize, usize)> {
        (self.state == State::DiceUneven)
            .then(|| (self.uneven.0, self.uneven.1, self.dice_target()))
    }

    /// Rolls the count asks for.
    pub(super) fn dice_target(&self) -> usize {
        if self.word_count == 24 {
            DICE_ROLLS_24
        } else {
            DICE_ROLLS_12
        }
    }

    /// Wipe the rolls.
    pub(super) fn leave_dice(&mut self) {
        self.rolls.zeroize();
        self.rolled = 0;
    }

    /// BIP85 Child: "-" and "+" step the index, a tap on it opens the
    /// keypad, DERIVE derives.
    pub(super) fn on_bip85(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match bip85_screen::target(self.scale, self.bip85_index == 0, x, y)? {
            bip85_screen::Target::Nav(Nav::Home) => self.state = State::Home,
            bip85_screen::Target::Nav(_) => self.state = seed_tools(CountFor::Bip85),
            bip85_screen::Target::Minus => self.bip85_index = self.bip85_index.saturating_sub(1),
            bip85_screen::Target::Plus => self.bip85_index = (self.bip85_index + 1).min(INDEX_MAX),
            bip85_screen::Target::Index => {
                self.pad_len = 0;
                self.state = State::Bip85Index;
            }
            bip85_screen::Target::Derive => self.state = State::Bip85Deriving,
        }
        None
    }

    /// The child's index on the keypad, as for the Address tool.
    pub(super) fn on_bip85_index(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match keypad::target(self.scale, x, y)? {
            keypad::Target::Nav(Nav::Home) => self.state = State::Home,
            keypad::Target::Nav(_) => self.state = State::Bip85,
            keypad::Target::Key(keypad::Key::Digit(d)) => {
                if self.pad_len < INDEX_DIGITS {
                    self.pad[self.pad_len] = b'0' + d;
                    self.pad_len += 1;
                }
            }
            keypad::Target::Key(keypad::Key::Clear) => self.pad_len = 0,
            keypad::Target::Key(keypad::Key::Go) => {
                if self.pad_len > 0 {
                    self.bip85_index = self.pad[..self.pad_len]
                        .iter()
                        .fold(0u32, |n, &c| n * 10 + u32::from(c - b'0'));
                    self.state = State::Bip85;
                }
            }
        }
        None
    }

    /// DERIVING, on the next tick: the child of the seed in use, its words
    /// shown, then stored.
    pub(super) fn on_bip85_deriving(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tick { .. } = event else {
            return None;
        };
        wipe::begin_depth(self.stack);
        let child = match self.slots.active() {
            Some((_, slot)) => bip85_child(slot, self.word_count as u32, self.bip85_index),
            None => Err(Refusal::NoWallet),
        };
        // Scrub the parent's seed and master key whatever the result: a
        // refusal goes to the error screen, not to a step that scrubs.
        wipe::scrub_flow();
        match child {
            Ok(m) => self.show_new_words(m, AfterWords::Store),
            Err(why) => self.refuse(why),
        }
        None
    }

    /// Show a new seed's words, one at a time.
    pub(super) fn show_new_words(&mut self, m: Mnemonic, after: AfterWords) {
        self.word_count = m.len();
        self.pending = Some(m);
        self.after_words = after;
        self.made_later = false;
        self.state = State::ShowWords { pos: 0 };
    }

    /// A tap for the next word, then [`Flow::after_last_word`]. Back or Home
    /// drops a seed being made.
    pub(super) fn on_show_words<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        pos: u8,
        rng: &mut E,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let corner = |nav| crate::ui::chrome::corner(self.scale, nav).contains(x, y);
        if corner(Nav::Back) || corner(Nav::Home) {
            self.pending = None;
            self.state = match (corner(Nav::Home), self.after_words) {
                (true, _) => State::Home,
                (false, AfterWords::Passphrase) => seed_tools(CountFor::Dice),
                (false, AfterWords::Store) => seed_tools(CountFor::Bip85),
                (false, AfterWords::NewSeed) => State::Menu {
                    menu: MenuId::SeedTools,
                    page: 0,
                },
                (false, AfterWords::SeedBackup) => seed_backup(),
            };
            return None;
        }
        if usize::from(pos) + 1 < self.word_count {
            self.state = State::ShowWords { pos: pos + 1 };
            return None;
        }
        self.after_last_word(rng);
        None
    }

    /// The grid view: the left strip pans left and right, the right strip up
    /// and down, a module at a time, within the code. Back goes on as
    /// [`Flow::seed_shown`] says.
    pub(super) fn on_seedqr_grid(
        &mut self,
        event: Event<'_>,
        compact: bool,
        (x, y): (u8, u8),
    ) -> Option<Command> {
        let Event::Tap { x: tx, y: ty } = event else {
            return None;
        };
        let words = match self.slots.active() {
            Some((_, Slot::Mnemonic { mnemonic, .. })) => mnemonic.len(),
            _ => return None,
        };
        let max = seedqr_size(compact, words).saturating_sub(seedqr::VIEW);
        let (x, y) = match seedqr::target(self.scale, tx, ty)? {
            seedqr::Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            seedqr::Target::Nav(_) => {
                self.seed_shown(false, compact);
                return None;
            }
            seedqr::Target::Left => (x.saturating_sub(1), y),
            seedqr::Target::Right => ((x + 1).min(max), y),
            seedqr::Target::Up => (x, y.saturating_sub(1)),
            seedqr::Target::Down => (x, (y + 1).min(max)),
        };
        self.state = State::SeedQrGrid { compact, x, y };
        None
    }

    /// The word shown, for drawing: never part of a [`Screen`].
    pub fn shown_word(&self) -> Option<&'static str> {
        let State::ShowWords { pos } = self.state else {
            return None;
        };
        match (self.after_words, self.slots.active()) {
            (AfterWords::SeedBackup, Some((_, Slot::Mnemonic { mnemonic, .. }))) => {
                mnemonic.word(usize::from(pos))
            }
            (AfterWords::SeedBackup, _) => None,
            _ => self.pending.as_ref()?.word(usize::from(pos)),
        }
    }
}

/// A BIP85 child of `slot`, `words` long, at `index`. A frame of its own,
/// so the scrub after it reaches the seed and master key, as with
/// [`open_step`](slots::open_step).
#[inline(never)]
pub(super) fn bip85_child(slot: &Slot, words: u32, index: u32) -> Result<Mnemonic, Refusal> {
    let Slot::Mnemonic {
        mnemonic,
        passphrase,
    } = slot
    else {
        return Err(Refusal::NoPhrase);
    };
    let master = master_of(mnemonic, passphrase.as_str())?;
    bip85::derive_mnemonic(&master, words, index).map_err(|_| Refusal::NotDerived)
}

/// The face seen least (lowest on a tie) and its count, if under
/// [`DICE_UNEVEN_PERCENT`] of the rolls (digits as typed).
fn least_face(rolls: &[u8]) -> Option<(u8, usize)> {
    let mut counts = [0usize; 6];
    for &r in rolls {
        if let Some(c) = counts.get_mut(usize::from(r.wrapping_sub(b'1'))) {
            *c += 1;
        }
    }
    let (face, &least) = counts.iter().enumerate().min_by_key(|&(_, c)| *c)?;
    (least * 100 < rolls.len() * DICE_UNEVEN_PERCENT).then_some((face as u8 + 1, least))
}

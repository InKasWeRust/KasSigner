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

//! The backup check. A seed made here (New Seed, Dice Seed, BIP85 Child) is
//! marked, and can only be backed up, until its backup is checked; its row
//! says NO BACKUP instead of a fingerprint.
//!
//! The mark clears when three of its words are picked, each from four; when
//! a copy of its SeedQR or Plain Text QR is scanned back and reads as this
//! seed; or when a backup is written to the card. A seed loaded from outside
//! came from a backup and is never marked.

use super::*;

/// Words a check asks.
pub const CHECK_ROUNDS: u8 = 3;

/// Words offered for each: the right one and three others.
pub const CHOICES: usize = word_screens::CHOICES;

/// How long BACKUP CHECKED shows, as a write's result does.
pub const CHECKED_US: u64 = 3_000_000;

const ROUNDS: usize = CHECK_ROUNDS as usize;

/// The places asked (from 0), the words offered at each (list indices) and
/// which is right. Part of a seed: wiped however the check ends.
pub(super) struct WordChecks {
    places: [u8; ROUNDS],
    offered: [[u16; CHOICES]; ROUNDS],
    right: [u8; ROUNDS],
}

impl WordChecks {
    pub(super) const EMPTY: Self = Self {
        places: [0; ROUNDS],
        offered: [[0; CHOICES]; ROUNDS],
        right: [0; ROUNDS],
    };

    /// [`CHECK_ROUNDS`] random places of `phrase`, in order, each with its
    /// word among three other distinct words, at a random position.
    fn draw<E: Entropy + ?Sized>(phrase: &Mnemonic, rng: &mut E) -> Result<Self, Refusal> {
        let len = phrase.len();
        let mut c = Self::EMPTY;
        let mut draws = Draws::new();
        let mut taken = 0;
        while taken < ROUNDS {
            let p = draws.below(rng, len)? as u8;
            if !c.places[..taken].contains(&p) {
                c.places[taken] = p;
                taken += 1;
            }
        }
        c.places.sort_unstable();
        for r in 0..ROUNDS {
            let word = phrase
                .index(usize::from(c.places[r]))
                .ok_or(Refusal::NotDerived)?;
            let right = draws.below(rng, CHOICES)?;
            let mut filled = 0;
            while filled < CHOICES {
                if filled == right {
                    c.offered[r][filled] = word;
                    filled += 1;
                    continue;
                }
                let other = draws.below(rng, kassigner_crypto::wordlist::WORDLIST.len())? as u16;
                if other != word && !c.offered[r][..filled].contains(&other) {
                    c.offered[r][filled] = other;
                    filled += 1;
                }
            }
            c.right[r] = right as u8;
        }
        draws.buf.zeroize();
        Ok(c)
    }

    pub(super) fn clear(&mut self) {
        self.places.zeroize();
        self.offered.zeroize();
        self.right.zeroize();
    }
}

/// The generator's bytes for one check, filled [`DRAWN`] at a time.
struct Draws {
    buf: [u8; DRAWN],
    at: usize,
    fills: u8,
}

/// Bytes per fill: 64 numbers, more than a check uses with its repeats.
const DRAWN: usize = 128;

/// Fills per check before the generator counts as stuck and is refused.
const FILLS: u8 = 8;

impl Draws {
    const fn new() -> Self {
        Self {
            buf: [0; DRAWN],
            at: DRAWN,
            fills: 0,
        }
    }

    /// A uniform number below `n` from two bytes, rejected at or past the
    /// largest multiple of `n` up to 65,536. A failing or stuck generator is
    /// refused.
    fn below<E: Entropy + ?Sized>(&mut self, rng: &mut E, n: usize) -> Result<usize, Refusal> {
        let n = n.max(1) as u32;
        let limit = 0x1_0000 / n * n;
        loop {
            if self.at + 2 > DRAWN {
                if self.fills == FILLS {
                    return Err(Refusal::NoEntropy);
                }
                rng.fill(&mut self.buf).map_err(|_| Refusal::NoEntropy)?;
                self.fills += 1;
                self.at = 0;
            }
            let v = u32::from(u16::from_le_bytes([
                self.buf[self.at],
                self.buf[self.at + 1],
            ]));
            self.at += 2;
            if v < limit {
                return Ok((v % n) as usize);
            }
        }
    }
}

impl Drop for Draws {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Whether two phrases match, compared over all twenty-four places, as the
/// slots compare.
fn same_words(a: &Mnemonic, b: &Mnemonic) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..bip39::WORDS_24 {
        diff |= usize::from(a.index(i).unwrap_or(0) ^ b.index(i).unwrap_or(0));
    }
    diff == 0
}

/// Whether a code is `held`'s words, as SeedQR or text, read as the home
/// scanner reads. A frame of its own, so the scrub after the scan reaches
/// what it read.
#[inline(never)]
fn reads_as(bytes: &[u8], held: &Mnemonic) -> bool {
    let read = match seed::read_qr(bytes) {
        Ok((m, _)) => Some(m),
        Err(seed::ReadError::NotSeedQr) if crate::text::is_message(bytes) => {
            match seed::read_words(bytes) {
                seed::Text::Seed(m) => Some(m),
                _ => None,
            }
        }
        Err(_) => None,
    };
    read.is_some_and(|m| same_words(&m, held))
}

impl<'b, const N: usize> Flow<'b, N> {
    /// Whether the seed in use is marked.
    pub(super) fn in_use_unbacked(&self) -> bool {
        self.slots.active().is_some_and(|(i, _)| self.unbacked[i])
    }

    /// Whether the seed in use may be used: one made here with no checked
    /// backup is refused (NO BACKUP YET).
    pub(super) fn backed_or_refuse(&mut self) -> bool {
        if self.in_use_unbacked() {
            self.refuse(Refusal::NotBackedUp);
            return false;
        }
        true
    }

    /// Clears the seed in use's mark.
    pub(super) fn mark_backed(&mut self) {
        if let Some((i, _)) = self.slots.active() {
            self.unbacked[i] = false;
        }
    }

    /// What is checked: the seed being made, or Show Seed Words' seed.
    fn checked_phrase(&self) -> Option<&Mnemonic> {
        match (self.after_words, self.slots.active()) {
            (AfterWords::SeedBackup, Some((_, Slot::Mnemonic { mnemonic, .. }))) => Some(mnemonic),
            (AfterWords::SeedBackup, _) => None,
            _ => self.pending.as_ref(),
        }
    }

    /// After the words: a dice seed to its passphrase, a new seed or BIP85
    /// child stored, Show Seed Words back to Seed Backup.
    pub(super) fn words_done(&mut self) {
        match self.after_words {
            AfterWords::Passphrase => self.ask_passphrase(),
            AfterWords::Store | AfterWords::NewSeed => match self.pending.take() {
                Some(mut m) => self.store(&mut m, b""),
                None => self.state = State::Home,
            },
            AfterWords::SeedBackup => self.state = seed_backup(),
        }
    }

    /// After the last word: BACKUP CHECK for a seed being made; for Show
    /// Seed Words, the check if the seed has no backup, else Seed Backup.
    pub(super) fn after_last_word<E: Entropy + ?Sized>(&mut self, rng: &mut E) {
        match self.after_words {
            AfterWords::SeedBackup if self.in_use_unbacked() => self.start_check(rng),
            AfterWords::SeedBackup => self.state = seed_backup(),
            _ => self.state = State::BackupAsk { by: Check::Words },
        }
    }

    /// CHECK 1/3, drawn now; a failed draw drops a seed being made.
    fn start_check<E: Entropy + ?Sized>(&mut self, rng: &mut E) {
        let drawn = match self.checked_phrase() {
            Some(phrase) => WordChecks::draw(phrase, rng),
            None => Err(Refusal::NoPhrase),
        };
        match drawn {
            Ok(c) => {
                self.checks = c;
                self.state = State::WordCheck { round: 0 };
            }
            Err(why) => {
                if self.after_words != AfterWords::SeedBackup {
                    self.pending = None;
                }
                self.refuse(why);
            }
        }
    }

    /// Where a check's Back goes: BACKUP CHECK for a seed being made, else
    /// Seed Backup.
    fn check_back(&self) -> State {
        match self.after_words {
            AfterWords::SeedBackup => seed_backup(),
            _ => State::BackupAsk { by: Check::Words },
        }
    }

    /// Home from the check drops a seed being made.
    fn check_home(&mut self) {
        self.checks.clear();
        if self.after_words != AfterWords::SeedBackup {
            self.pending = None;
        }
        self.state = State::Home;
    }

    /// BACKUP CHECK: CHECK (left) checks now; LATER (right) goes on, a seed
    /// being made stored marked, a code to SEED EXPORTED. Back goes to the
    /// last word, or where SEED EXPORTED's Back goes.
    pub(super) fn on_backup_ask<E: Entropy + ?Sized>(
        &mut self,
        event: Event<'_>,
        by: Check,
        pressed_at: Option<(u16, u16)>,
        rng: &mut E,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match (
            tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))?,
            by,
        ) {
            (dialog::Target::Nav(Nav::Home), _) => self.check_home(),
            (dialog::Target::Nav(_), Check::Words) => {
                let last = self.word_count.saturating_sub(1) as u8;
                self.state = State::ShowWords { pos: last };
            }
            (dialog::Target::Nav(_), Check::Code { plain: true, .. }) => {
                self.state = State::PlainFormat
            }
            (dialog::Target::Nav(_), Check::Code { .. }) => self.state = exports::qr_export(),
            (dialog::Target::Cancel, Check::Words) => self.start_check(rng),
            (dialog::Target::Cancel, Check::Code { plain, compact }) => {
                self.progress = (0, 0);
                self.received = 0;
                self.state = State::BackupScan { plain, compact };
                return Some(Command::CameraOn);
            }
            (dialog::Target::Accept, Check::Words) => {
                self.made_later = true;
                self.words_done();
            }
            (dialog::Target::Accept, Check::Code { plain, compact }) => {
                self.state = State::SeedDone { plain, compact }
            }
        }
        None
    }

    /// CHECK n/3: the right word goes on (after the last, BACKUP CHECKED); a
    /// wrong one fails and the words show again from the first. An answer
    /// counts only pressed and lifted on the same word.
    pub(super) fn on_word_check(
        &mut self,
        event: Event<'_>,
        round: u8,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let scale = self.scale;
        match tapped(pressed_at, (x, y), |x, y| {
            word_screens::check_target(scale, x, y)
        })? {
            word_screens::CheckTarget::Nav(Nav::Home) => self.check_home(),
            word_screens::CheckTarget::Nav(_) => {
                self.checks.clear();
                self.state = self.check_back();
            }
            word_screens::CheckTarget::Choice(k) => {
                let r = usize::from(round);
                if usize::from(self.checks.right[r]) != k {
                    self.checks.clear();
                    self.since_us = self.now_us;
                    self.state = State::CheckFailed { by: Check::Words };
                } else if round + 1 < CHECK_ROUNDS {
                    self.state = State::WordCheck { round: round + 1 };
                } else {
                    self.checks.clear();
                    if self.after_words == AfterWords::SeedBackup {
                        self.mark_backed();
                    }
                    self.made_later = false;
                    self.since_us = self.now_us;
                    self.state = State::BackupChecked { by: Check::Words };
                }
            }
        }
        None
    }

    /// The place asked and the four words offered, for drawing: never part
    /// of a [`Screen`].
    pub fn check_words(&self) -> Option<(u8, [&'static str; CHOICES])> {
        let State::WordCheck { round } = self.state else {
            return None;
        };
        let r = usize::from(round);
        let mut out = [""; CHOICES];
        for (o, &i) in out.iter_mut().zip(self.checks.offered[r].iter()) {
            *o = bip39::index_to_word(i)?;
        }
        Some((self.checks.places[r], out))
    }

    /// The place CHECK asks at `round`, for its screen.
    pub(super) fn check_place(&self, round: u8) -> u8 {
        self.checks.places[usize::from(round).min(ROUNDS - 1)]
    }

    /// A failed check, then the words from the first, or BACKUP CHECK for a
    /// code.
    pub(super) fn on_check_failed(&mut self, event: Event<'_>, by: Check) -> Option<Command> {
        if let Event::Tick { now_us } = event {
            if now_us.saturating_sub(self.since_us) >= ERROR_US {
                self.state = match by {
                    Check::Words => State::ShowWords { pos: 0 },
                    Check::Code { .. } => State::BackupAsk { by },
                };
            }
        }
        None
    }

    /// BACKUP CHECKED, then a seed being made goes on unmarked; else Seed
    /// Backup.
    pub(super) fn on_backup_checked(&mut self, event: Event<'_>, by: Check) -> Option<Command> {
        if let Event::Tick { now_us } = event {
            if now_us.saturating_sub(self.since_us) >= CHECKED_US {
                match (by, self.after_words) {
                    (
                        Check::Words,
                        AfterWords::Passphrase | AfterWords::Store | AfterWords::NewSeed,
                    ) => self.words_done(),
                    _ => self.state = seed_backup(),
                }
            }
        }
        None
    }

    /// The camera, for the code's copy: read as the seed in use, its mark
    /// clears; anything else fails. Back goes to BACKUP CHECK.
    pub(super) fn on_backup_scan(
        &mut self,
        event: Event<'_>,
        plain: bool,
        compact: bool,
    ) -> Option<Command> {
        let by = Check::Code { plain, compact };
        match event {
            Event::Progress {
                have,
                total,
                received,
            } => {
                self.progress = (have, total);
                self.received = received;
                None
            }
            Event::Tap { x, y } => {
                if !camera::back(self.scale).contains(x, y) {
                    return None;
                }
                self.state = State::BackupAsk { by };
                Some(Command::CameraOff)
            }
            // Read in place, never copied: internal RAM or the payload buffer
            // the binary wipes after the scan. The reader notes its depth, so
            // the scrub after the scan runs to the floor.
            Event::Code(bytes) | Event::Opaque(bytes) => {
                wipe::begin_depth(self.stack);
                let same = match self.slots.active() {
                    Some((_, Slot::Mnemonic { mnemonic, .. })) => reads_as(bytes, mnemonic),
                    _ => false,
                };
                self.since_us = self.now_us;
                if same {
                    self.mark_backed();
                    self.state = State::BackupChecked { by };
                } else {
                    self.state = State::CheckFailed { by };
                }
                Some(Command::CameraOff)
            }
            Event::Payload(_) => {
                self.since_us = self.now_us;
                self.state = State::CheckFailed { by };
                Some(Command::CameraOff)
            }
            Event::CameraLost => {
                self.refuse(Refusal::NoCamera);
                Some(Command::CameraOff)
            }
            _ => None,
        }
    }

    /// After a seed's SeedQR or Plain Text QR: BACKUP CHECK if it is marked,
    /// else SEED EXPORTED.
    pub(super) fn seed_shown(&mut self, plain: bool, compact: bool) {
        self.state = if self.in_use_unbacked() {
            State::BackupAsk {
                by: Check::Code { plain, compact },
            }
        } else {
            State::SeedDone { plain, compact }
        };
    }
}

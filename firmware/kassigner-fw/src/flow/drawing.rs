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

//! What to draw: the screen each state names.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    // ── What to draw ────────────────────────────────────────────────────

    /// The screen for the state, marking a review page as drawn.
    ///
    /// The one place `seen` gains a bit: a page counts as seen when it is put
    /// on the screen, not when asked for, and only if it can be.
    /// [`Flow::review`] builds exactly what the binary draws; a page it
    /// cannot build is refused, not counted, as is CONFIRM SEND? without its
    /// totals, rather than the panel going black with the page counted seen
    /// or CONFIRM live behind it. A page the panel then fails to take is
    /// reported at once ([`Event::NotDrawn`]): its bit is cleared and the
    /// review refused.
    pub(super) fn screen(&mut self) -> Screen {
        match self.state {
            State::Boot => Screen::Booting,
            State::Halted(h) => Screen::Halted(h),
            State::Verified(check) => Screen::Verified(check),
            State::Home => Screen::Home,
            State::Wiped => Screen::Wiped,
            State::Menu { menu, page } => Screen::Menu { menu, page },
            State::Seeds { page } => Screen::Seeds { page },
            State::Scanning => Screen::Scanning {
                have: self.progress.0,
                total: self.progress.1,
                received: self.received,
                hint: self.seed_hint,
            },
            State::Reviewing => {
                // Built once a page: its drawing does not change.
                if self.seen & (1 << self.page) == 0 && self.review(|_| ()).is_none() {
                    self.refuse(Refusal::NotDrawn);
                    return Screen::Refused(Refusal::NotDrawn);
                }
                self.seen |= 1 << self.page;
                match self.with_session(|s| s.pages()) {
                    Ok(pages) => Screen::Page {
                        index: self.page,
                        pages,
                    },
                    Err(why) => Screen::Refused(why),
                }
            }
            State::Confirming => {
                if self.totals().is_none() {
                    self.refuse(Refusal::NotDrawn);
                    return Screen::Refused(Refusal::NotDrawn);
                }
                Screen::Confirm
            }
            State::Checking { .. } => Screen::Checking,
            State::Signing => Screen::Signing,
            State::ReplyFormat => Screen::ReplyFormat,
            State::ReplyMode => Screen::ReplyMode,
            State::ReplyDone => Screen::ReplyDone,
            State::MessageDone => Screen::MessageDone,
            State::AddressDone => Screen::AddressDone,
            State::SeedDone { .. } => Screen::SeedDone,
            State::Showing { frame } => Screen::Reply {
                frame,
                frames: self.reply_frames(),
            },
            State::Refused(r) => Screen::Refused(r),
            State::Generating => match self.collector.as_ref() {
                Some(c) => Screen::Generating {
                    credited: c.credited(),
                    share: c.share(),
                    short: c.short(),
                },
                None => Screen::Home,
            },
            State::Asking { next, .. } => Screen::Asking {
                checked: keyring::BANK + next,
            },
            State::Searching { next, .. } => Screen::Searching {
                done: next,
                total: keyring::SWEEP,
            },
            State::Loading => Screen::Loading {
                words: self.pending.as_ref().map_or(0, |m| m.len()),
            },
            State::Opening { .. } => Screen::Opening {
                done: self.opening.as_ref().map_or(0, |o| o.done + 1),
                total: OPEN_STEPS,
            },
            State::Deleting {
                slot,
                armed,
                held_since,
            } => Screen::Deleting {
                slot: self.row_of(slot),
                hold: self.held(armed, held_since),
            },
            State::Display => Screen::Display {
                level: self.backlight,
            },
            State::Audio => Screen::Audio { level: self.volume },
            State::About => Screen::About(self.check),
            State::CameraTune { knob } => Screen::CameraTune {
                knob,
                value: self.tune[knob],
                auto: self.has_auto.then_some(self.auto),
            },
            State::Card => Screen::Card { status: self.card },
            State::Passphrase { page } => Screen::Keyboard {
                typing: Typing::Passphrase,
                page,
                field: self.typed.field(),
            },
            State::PassphraseAgain { page } => Screen::Keyboard {
                typing: Typing::PassphraseAgain,
                page,
                field: self.typed.field(),
            },
            State::ImportExport => Screen::ImportExport,
            State::StegoCarrier => Screen::StegoCarrier,
            State::StegoDescriptor { page } => Screen::Keyboard {
                typing: Typing::Descriptor,
                page,
                field: self.typed.field(),
            },
            State::StegoPreview => Screen::StegoPreview,
            State::StegoHintAsk => Screen::StegoHintAsk,
            State::StegoHint => Screen::StegoHint,
            State::StegoHintType { page } => Screen::Keyboard {
                typing: Typing::Hint,
                page,
                field: self.typed.field(),
            },
            State::StegoConfirm => Screen::StegoConfirm {
                hint: self.hint_len > 0,
            },
            State::StegoSealing { done } => Screen::BackupSealing {
                done,
                total: PBKDF2_ITERATIONS,
            },
            State::StegoEmbedding => Screen::StegoEmbedding,
            State::StegoDone => Screen::StegoDone,
            State::StegoKey { page } => Screen::Keyboard {
                typing: Typing::Descriptor,
                page,
                field: self.desc.field(),
            },
            State::StegoReading => Screen::StegoReading,
            State::StegoOpening { done } => Screen::RestoreOpening {
                done,
                total: PBKDF2_ITERATIONS,
            },
            State::StegoFound => Screen::StegoFound {
                words: self.pending.as_ref().map_or(0, |m| m.len() as u8),
                carrier: self.carrier,
                two: self.unhide.two(),
            },
            State::StegoHintShown => Screen::StegoHintShown,
            State::StegoOverwrite => Screen::StegoOverwrite,
            State::StegoOldKey { page } => Screen::Keyboard {
                typing: Typing::OldDescriptor,
                page,
                field: self.desc.field(),
            },
            State::BackupWarning => Screen::BackupWarning,
            State::BackupName { page } if self.saving == Saving::Signature => Screen::Keyboard {
                typing: Typing::SigFileName,
                page,
                field: self.typed.field(),
            },
            State::BackupName { page } if matches!(self.saving, Saving::Kpub(_)) => {
                Screen::Keyboard {
                    typing: Typing::KpubFileName,
                    page,
                    field: self.typed.field(),
                }
            }
            State::BackupName { page } => Screen::Keyboard {
                typing: Typing::FileName,
                page,
                field: self.typed.field(),
            },
            State::BackupOverwrite => Screen::BackupOverwrite {
                name: card::FileName(self.backup_name),
            },
            State::OverwritePassword { page } => Screen::Keyboard {
                typing: Typing::OverwritePassword,
                page,
                field: self.typed.field(),
            },
            // The restore's bar: the same work, a file opened by password.
            State::OverwriteOpening { done } => Screen::RestoreOpening {
                done,
                total: PBKDF2_ITERATIONS,
            },
            State::BackupPassword { page, again } => Screen::Keyboard {
                typing: if again {
                    Typing::PasswordAgain
                } else {
                    Typing::Password
                },
                page,
                field: self.typed.field(),
            },
            State::BackupSealing { done } => Screen::BackupSealing {
                done,
                total: PBKDF2_ITERATIONS,
            },
            State::RestoreList { page } => Screen::RestoreList {
                page,
                count: self.listed,
                extra: self.extra,
            },
            State::WordCount { action } => Screen::WordCount { action },
            State::Dice => Screen::Dice {
                rolled: self.rolled as u16,
                target: self.dice_target() as u16,
            },
            State::DiceRefused => Screen::DiceRefused,
            State::DiceUneven => Screen::DiceUneven,
            State::Bip85 => Screen::Bip85 {
                words: self.word_count as u8,
                index: Hidden(self.bip85_index),
            },
            State::Bip85Index => Screen::Bip85Index {
                typed: Hidden(self.pad),
                len: self.pad_len as u8,
            },
            State::Bip85Deriving => Screen::Bip85Deriving,
            State::ShowWords { pos } => Screen::ShowWords {
                pos,
                of: self.word_count as u8,
            },
            State::BackupAsk { by } => Screen::BackupAsk {
                qr: by != Check::Words,
            },
            State::WordCheck { round } => Screen::WordCheck {
                round,
                place: self.check_place(round),
            },
            State::CheckFailed { by } => Screen::CheckFailed {
                qr: by != Check::Words,
            },
            State::BackupChecked { .. } => Screen::BackupChecked,
            State::BackupScan { .. } => Screen::BackupScan {
                have: self.progress.0,
                total: self.progress.1,
                received: self.received,
            },
            State::SeedQr { compact } => Screen::SeedQr { compact },
            State::SeedQrGrid { compact, x, y } => Screen::SeedQrGrid { compact, x, y },
            State::PlainQr => Screen::PlainQr,
            State::PlainFormat => Screen::PlainFormat,
            State::PlainMode => Screen::PlainMode,
            State::PlainFrames { frame } => Screen::PlainFrames {
                frame,
                frames: self.plain_frames,
            },
            State::KpubFormat => Screen::KpubFormat,
            State::KpubMode => Screen::KpubMode,
            State::KpubQr { frame } => Screen::KpubQr {
                frame,
                frames: self.kpub_frames,
            },
            State::KpubExported => Screen::KpubExported,
            State::KpubEncrypt => Screen::KpubEncrypt,
            State::KpubScanned => Screen::KpubScanned,
            State::CreateMultisig { m, n } => Screen::CreateMultisig { m, n },
            State::AddKey => {
                let (key, of) = self.next_key();
                Screen::AddKey { key, of }
            }
            State::SelectSeed { page } => {
                let (key, of) = self.next_key();
                Screen::SelectSeed { page, key, of }
            }
            State::CosignerKey => Screen::CosignerKey,
            State::Descriptor => Screen::Descriptor { own: self.desc_own },
            State::DescriptorFormat => Screen::DescriptorFormat,
            State::DescriptorMode => Screen::DescriptorMode,
            State::DescriptorFrames { frame } => Screen::DescriptorFrames {
                frame,
                frames: self.desc_frames,
            },
            State::LoadGroup => {
                let (m, n) = self
                    .loading
                    .as_ref()
                    .map_or((0, 0), |g| (g.required(), g.total()));
                let held = match (self.group.as_ref(), self.loading.as_ref()) {
                    (None, _) => multisig_screen::Held::Nothing,
                    (Some(h), Some(g)) if h == g => multisig_screen::Held::Same,
                    (Some(h), _) => multisig_screen::Held::Other(h.required(), h.total()),
                };
                Screen::LoadGroup {
                    m,
                    n,
                    seed: self.load_seed,
                    held,
                }
            }
            State::FileAddress => Screen::FileAddress {
                name: card::FileName(self.backup_name),
            },
            State::FileAddressQr => Screen::FileAddressQr,
            State::Savings { page } => Screen::Savings { page },
            State::SavingsSearching { page, next, .. } => {
                Screen::SavingsSearching { page, at: next }
            }
            State::SavingsFormat { .. } => Screen::SavingsFormat,
            State::SavingsMode { .. } => Screen::SavingsMode,
            State::SavingsFrames { frame, .. } => Screen::SavingsFrames {
                frame,
                frames: self.card_frames,
            },
            State::SavingsAddressQr => Screen::SavingsAddressQr,
            State::Address if self.addr_group => Screen::GroupAddress {
                change: self.addr_change,
                index: self.addr_index,
                cosigner: self.addr_cosigner,
            },
            State::Address if self.addr_kcc3 => Screen::Kcc3Address {
                change: self.addr_change,
                index: self.addr_index,
            },
            State::Address if self.addr_sign => Screen::SignWith {
                change: self.addr_change,
                index: self.addr_index,
            },
            State::Address if self.addr_key => Screen::PrivateKey {
                change: self.addr_change,
                index: self.addr_index,
                single: !self.keys.as_ref().is_some_and(|k| k.has_chains()),
            },
            State::Address => Screen::Address {
                change: self.addr_change,
                index: self.addr_index,
                single: !self.keys.as_ref().is_some_and(|k| k.has_chains()),
            },
            State::AddressQr if self.addr_key => Screen::PrivateKeyQr {
                change: self.addr_change,
                index: self.addr_index,
            },
            State::AddressQr => Screen::AddressQr {
                change: self.addr_change,
                index: self.addr_index,
            },
            State::Kprv { master } => Screen::Kprv { master },
            State::KprvQr { master } => Screen::KprvQr { master },
            State::KprvDeriving => Screen::KprvDeriving,
            State::KeyDeriving => Screen::KeyDeriving,
            State::GroupDeriving => {
                let (done, total) = self.branches.progress();
                Screen::GroupDeriving { done, total }
            }
            State::RawKeyConfirm => Screen::RawKeyConfirm,
            State::MessageType { page } => Screen::Keyboard {
                typing: Typing::Message,
                page,
                field: self.typed.field(),
            },
            State::MessageScan => Screen::MessageScan {
                have: self.progress.0,
                total: self.progress.1,
                received: self.received,
            },
            State::MessagePreview { page } => {
                let pages = address_screen::message_pages(self.message_text());
                self.msg_read = self.msg_read.max(page);
                Screen::MessagePreview {
                    page,
                    pages,
                    signed: self.msg_signed,
                    live: self.msg_signed || self.msg_read + 1 >= pages,
                }
            }
            State::MessageCheck { valid } => Screen::MessageCheck { valid },
            State::MessageConfirm => Screen::MessageConfirm,
            State::MessageSigning => Screen::MessageSigning,
            State::MessageResult { page } => Screen::MessageResult { page },
            State::MessageFormat => Screen::MessageFormat,
            State::MessageMode => Screen::MessageMode,
            State::MessageFrames { frame } => Screen::MessageFrames {
                frame,
                frames: self.msg_frames,
            },
            State::RawKey => Screen::Keyboard {
                typing: Typing::RawKey,
                page: keyboard::HEX_PAGE,
                field: self.typed.field(),
            },
            State::AddressIndex => Screen::AddressIndex {
                typed: Hidden(self.pad),
                len: self.pad_len as u8,
            },
            State::Words { action } => Screen::Words {
                action,
                pos: self.word_pos as u8,
                of: match action {
                    WordsFor::Import => self.word_count as u8,
                    WordsFor::LastWord => self.word_count as u8 - 1,
                },
                filled: self.word_filled as u8,
                field: self.typed.field(),
                invalid: self.word_invalid,
            },
            State::LastWord { choice } => Screen::LastWord {
                of: self.word_count as u8,
                choices: bip39::last_word_choices(self.word_count - 1).unwrap_or(0),
                at: Hidden(choice),
            },
            State::RestoreDelete {
                armed, held_since, ..
            } => Screen::RestoreDelete {
                name: card::FileName(self.backup_name),
                hold: self.held(armed, held_since),
            },
            State::RestorePassword { page } => Screen::Keyboard {
                typing: if self.deleting {
                    Typing::DeletePassword
                } else {
                    Typing::Password
                },
                page,
                field: self.typed.field(),
            },
            State::RestoreOpening { done } => Screen::RestoreOpening {
                done,
                total: PBKDF2_ITERATIONS,
            },
            State::CardFormat { armed, held_since } => Screen::CardFormat {
                hold: self.held(armed, held_since),
            },
            State::CardBusy(job) => Screen::CardBusy(job),
            State::CardDone { job, outcome } => Screen::CardDone { job, outcome },
        }
    }
}

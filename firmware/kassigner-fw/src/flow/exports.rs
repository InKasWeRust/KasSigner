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

//! QR Export and the kpub: a seed's code and its plain text, and the kpub
//! made, scanned, shown and saved.

use super::*;

/// The longest plain-text phrase: 24 words of at most 8 letters, 23 spaces.
pub(super) const PLAIN_MAX: usize = 24 * 8 + 23;

impl<'b, const N: usize> Flow<'b, N> {
    /// The kpub of the wallet in use's `key` account, as text and in v1.0.7's
    /// raw form. None for a raw key; no cosigner key without a `45'` node (an
    /// xprv imported at the account).
    pub(super) fn make_kpub(&mut self, key: KpubKey) -> Result<(), Refusal> {
        let wallet = self.keys.as_ref().ok_or(Refusal::NoWallet)?.wallet();
        let account = match (wallet, key) {
            (Wallet::Hd { single, .. }, KpubKey::Single) => single,
            (
                Wallet::Hd {
                    multisig: Some(m), ..
                },
                KpubKey::Cosigner,
            ) => m,
            _ => return Err(Refusal::NoPhrase),
        };
        wipe::begin_depth(self.stack);
        let public = public_of(account);
        wipe::scrub_flow();
        self.set_kpub(&public)?;
        self.kpub_key = key;
        self.kpub_exit = State::Menu {
            menu: MenuId::WatchOnly,
            page: 0,
        };
        Ok(())
    }

    /// Hold `public` as the kpub shown and saved: its text and its raw form.
    pub(super) fn set_kpub(&mut self, public: &ExtendedPublicKey) -> Result<(), Refusal> {
        self.kpub_len = public
            .to_text(KeyPrefix::Kpub, &mut self.kpub)
            .map_err(|_| Refusal::NotDerived)?;
        self.kpub_raw[0] = KPUB_RAW_MARK;
        public
            .serialize(KeyPrefix::Kpub, &mut self.kpub_raw[1..])
            .map_err(|_| Refusal::NotDerived)?;
        Ok(())
    }

    /// A kpub scanned, as text or in frames, v1.0.7's or v1.1.0's: KPUB
    /// SCANNED, to show or save it. Saved, its name starts as `KPnnnn` for
    /// the person to change: a kpub does not say which account it is.
    pub(super) fn take_kpub(&mut self, public: &ExtendedPublicKey) {
        if let Err(why) = self.set_kpub(public) {
            self.refuse(why);
            return;
        }
        self.kpub_key = KpubKey::Single;
        self.kpub_exit = State::Home;
        self.state = State::KpubScanned;
    }

    /// KPUB SCANNED: Save to SD, or Show QR.
    pub(super) fn on_kpub_scanned(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(_) => self.state = State::Home,
            dialog::Target::Cancel => {
                return self.start_saving(Saving::Kpub(KpubKey::Single), self.kpub_exit)
            }
            dialog::Target::Accept => self.state = State::KpubFormat,
        }
        None
    }

    /// KPUB EXPORT QR: Wallet is one code; KasSigner is two frames, their
    /// mode asked.
    pub(super) fn on_kpub_format(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match kpub_screen::target(self.scale, x, y)? {
            kpub_screen::Target::Nav(Nav::Home) => self.state = State::Home,
            // Back where the kpub came from: Watch-Only, or KPUB SCANNED.
            kpub_screen::Target::Nav(_) => {
                self.state = match self.kpub_exit {
                    State::Home => State::KpubScanned,
                    exit => exit,
                }
            }
            kpub_screen::Target::Wallet => {
                self.kpub_frames = 1;
                self.show_kpub();
            }
            kpub_screen::Target::KasSigner => {
                self.kpub_frames = kpub_screen::KPUB_FRAMES as u8;
                self.state = State::KpubMode;
            }
        }
        None
    }

    /// QR DISPLAY MODE: Auto Cycle, or Manual.
    pub(super) fn on_kpub_mode(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::KpubFormat,
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_kpub();
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_kpub();
            }
        }
        None
    }

    /// The kpub from its first frame.
    pub(super) fn show_kpub(&mut self) {
        self.frame_us = limits::KASSIGNER_FRAME_US;
        self.frame_since = self.now_us;
        self.state = State::KpubQr { frame: 0 };
    }

    /// The kpub shown: Auto Cycle turns frames every
    /// [`KASSIGNER_FRAME_US`](limits::KASSIGNER_FRAME_US), Manual a tap at a
    /// time. A tap on one code, on cycling frames, or past the last is KPUB
    /// EXPORTED.
    pub(super) fn on_kpub_qr(&mut self, event: Event<'_>, frame: u8) -> Option<Command> {
        let frames = self.kpub_frames;
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::KpubQr { frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::KpubQr { frame: frame + 1 };
            }
            Event::Tap { .. } => self.state = State::KpubExported,
            _ => {}
        }
        None
    }

    /// KPUB EXPORTED: Save to SD, or Back to QR.
    pub(super) fn on_kpub_exported(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::KpubFormat,
            dialog::Target::Cancel => {
                return self.start_saving(Saving::Kpub(self.kpub_key), self.kpub_exit)
            }
            dialog::Target::Accept => self.show_kpub(),
        }
        None
    }

    /// ENCRYPT FILE?: Yes asks a password; No writes the file plain; Home
    /// lets go a card held for its save.
    pub(super) fn on_kpub_encrypt(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.leave_card(State::Home),
            dialog::Target::Nav(_) => self.state = self.saving_from(),
            dialog::Target::Cancel => self.start_password(),
            dialog::Target::Accept => {
                if self.saving == Saving::Signature {
                    // Plain: the record straight into the write's buffer.
                    let Some(n) = self.write_record(false) else {
                        return self.seal_failed(Refusal::TooLong);
                    };
                    self.file_len = n;
                } else if self.saving == Saving::Reply {
                    // Plain: a copy into the request's buffer, which the write
                    // takes; the reply stays for Back to QR.
                    let n = self.reply_len;
                    let Some(out) = self.buffers.request.get_mut(..n) else {
                        return self.seal_failed(Refusal::TooLong);
                    };
                    out.copy_from_slice(&self.buffers.reply[..n]);
                    self.file_len = n;
                } else if matches!(self.saving, Saving::Address | Saving::GroupAddress) {
                    let n = self.addr_len;
                    self.file[..n].copy_from_slice(&self.addr_text[..n]);
                    self.file_len = n;
                } else if matches!(self.saving, Saving::Descriptor | Saving::Card) {
                    // Plain: into the request's buffer, which the write takes;
                    // a card's line in the descriptor's room, the longest.
                    let mut text = [0u8; DESCRIPTOR_FILE_MAX];
                    let made = if self.saving == Saving::Card {
                        self.card_line(&mut text)
                    } else {
                        self.descriptor_file(&mut text)
                    };
                    let Some(n) = made else {
                        return self.seal_failed(Refusal::NotSaved);
                    };
                    let Some(out) = self.buffers.request.get_mut(..n) else {
                        return self.seal_failed(Refusal::TooLong);
                    };
                    out.copy_from_slice(&text[..n]);
                    self.file_len = n;
                } else {
                    let Some(n) = self.kpub_file() else {
                        return self.seal_failed(Refusal::NotSaved);
                    };
                    self.file_len = n;
                }
                self.state = State::CardBusy(Job::Write);
                return Some(Command::Card(Job::Write));
            }
        }
        None
    }

    /// A kpub file's text into the file buffer, a cosigner's by
    /// [`crate::kpub::write_cosigner`]; its length, or `None` for a
    /// cosigner's with no seed in use.
    pub(super) fn kpub_file(&mut self) -> Option<usize> {
        let kpub = &self.kpub[..self.kpub_len];
        if self.saving == Saving::Kpub(KpubKey::Cosigner) {
            crate::kpub::write_cosigner(self.fingerprint()?, kpub, &mut self.file)
        } else {
            self.file.get_mut(..kpub.len())?.copy_from_slice(kpub);
            Some(kpub.len())
        }
    }

    /// The kpub's code for frame `frame`: its text whole, or a frame of its
    /// raw form in v1.1.0's framing, `Format::Kpub`. For drawing.
    pub fn kpub_code(&self, frame: u8) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_protocol::frame;
        use kassigner_qr::encode::encode;
        if self.kpub_frames <= 1 {
            return encode(&self.kpub[..self.kpub_len]).ok();
        }
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + KPUB_RAW_LEN];
        let total = kpub_screen::KPUB_FRAMES as u8;
        let n = frame::write_split(Format::Kpub, &self.kpub_raw, frame, total, &mut buf).ok()?;
        encode(&buf[..n]).ok()
    }

    /// The code QR Export shows, made from the seed in use: a SeedQR (the
    /// encoders New Seed uses), or the words as text, wiped once encoded.
    /// The code wipes itself when dropped. For drawing only.
    pub fn export_code(&self) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_qr::encode::encode;
        let Some((_, Slot::Mnemonic { mnemonic, .. })) = self.slots.active() else {
            return None;
        };
        match self.state {
            State::SeedQr { compact: false } | State::SeedQrGrid { compact: false, .. } => {
                seed::standard_qr(mnemonic).ok()
            }
            State::SeedQr { compact: true } | State::SeedQrGrid { compact: true, .. } => {
                seed::compact_qr(mnemonic).ok()
            }
            State::PlainQr => {
                let mut text = [0u8; PLAIN_MAX];
                let n = plain_text(mnemonic, &mut text);
                let code = encode(&text[..n]).ok();
                wipe::wipe(&mut text);
                code
            }
            _ => None,
        }
    }

    /// How many codes Plain Text QR takes for a wallet (one, up to version 9)
    /// or a unit (version 3 frames).
    pub fn plain_codes(&self, wallet: bool) -> usize {
        let Some((_, Slot::Mnemonic { mnemonic, .. })) = self.slots.active() else {
            return 0;
        };
        // The text's length, without writing it anywhere.
        let len = (0..mnemonic.len())
            .filter_map(|i| mnemonic.word(i))
            .map(|w| w.len() + 1)
            .sum::<usize>()
            .saturating_sub(1);
        message_codes(len, wallet)
    }

    /// Plain Text QR's KasSigner code for frame `frame`: the words in version
    /// 3 `Format::Opaque` frames, which a unit's scanner reads as seed words,
    /// or one code if they fit. The text is wiped once encoded; the code
    /// wipes itself when dropped. For drawing only.
    pub fn plain_frame(&self, frame: u8) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_protocol::frame;
        use kassigner_qr::encode::encode;
        let Some((_, Slot::Mnemonic { mnemonic, .. })) = self.slots.active() else {
            return None;
        };
        let mut text = [0u8; PLAIN_MAX];
        let n = plain_text(mnemonic, &mut text);
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + PLAIN_MAX];
        let code = if self.plain_frames <= 1 {
            encode(&text[..n]).ok()
        } else {
            frame::write_split(
                Format::Opaque,
                &text[..n],
                frame,
                self.plain_frames,
                &mut buf,
            )
            .ok()
            .and_then(|m| encode(&buf[..m]).ok())
        };
        wipe::wipe(&mut text);
        wipe::wipe(&mut buf);
        code
    }

    /// Plain Text QR: Wallet shows one code; KasSigner frames, with Auto
    /// Cycle or Manual asked if there are several.
    pub(super) fn on_plain_format(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let target = kpub_screen::target(self.scale, x, y)?;
        let wallet = match target {
            kpub_screen::Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            kpub_screen::Target::Nav(_) => {
                self.state = qr_export();
                return None;
            }
            kpub_screen::Target::Wallet => true,
            kpub_screen::Target::KasSigner => false,
        };
        match u8::try_from(self.plain_codes(wallet)) {
            Ok(0) => self.refuse(Refusal::NoPhrase),
            Ok(1) => {
                self.plain_frames = 1;
                self.state = State::PlainQr;
            }
            Ok(f) => {
                self.plain_frames = f;
                self.state = State::PlainMode;
            }
            Err(_) => self.refuse(Refusal::TooLong),
        }
        None
    }

    /// QR DISPLAY MODE for the words' frames.
    pub(super) fn on_plain_mode(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::PlainFormat,
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_plain();
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_plain();
            }
        }
        None
    }

    /// The words from their first frame.
    pub(super) fn show_plain(&mut self) {
        self.frame_us = limits::KASSIGNER_FRAME_US;
        self.frame_since = self.now_us;
        self.state = State::PlainFrames { frame: 0 };
    }

    /// The words' frames, as a kpub's: Auto Cycle or a tap at a time; a tap
    /// on cycling frames or past the last ends them ([`Self::seed_shown`]).
    pub(super) fn on_plain_frames(&mut self, event: Event<'_>, frame: u8) -> Option<Command> {
        let frames = self.plain_frames;
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::PlainFrames { frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::PlainFrames { frame: frame + 1 };
            }
            Event::Tap { .. } => self.seed_shown(true, false),
            _ => {}
        }
        None
    }

    /// SEED EXPORTED: Save to SD is the seed's backup, warning first and
    /// always sealed: a seed never goes to the card plain. Back to QR shows
    /// the code again.
    pub(super) fn on_seed_done(
        &mut self,
        event: Event<'_>,
        plain: bool,
        compact: bool,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) if plain => self.state = State::PlainFormat,
            dialog::Target::Nav(_) => self.state = qr_export(),
            dialog::Target::Cancel => {
                self.backup_back = State::SeedDone { plain, compact };
                self.state = State::BackupWarning;
            }
            dialog::Target::Accept if plain && self.plain_frames > 1 => self.show_plain(),
            dialog::Target::Accept if plain => self.state = State::PlainQr,
            dialog::Target::Accept => self.state = State::SeedQr { compact },
        }
        None
    }
}

/// QR Export's menu.
pub(super) const fn qr_export() -> State {
    State::Menu {
        menu: MenuId::QrExport,
        page: 0,
    }
}

/// A seed's words as a Plain Text QR holds them, into `out`: lower case, a
/// space between each. Their length.
pub(super) fn plain_text(mnemonic: &Mnemonic, out: &mut [u8; PLAIN_MAX]) -> usize {
    let mut n = 0;
    for i in 0..mnemonic.len() {
        let Some(word) = mnemonic.word(i) else {
            break;
        };
        if i > 0 {
            out[n] = b' ';
            n += 1;
        }
        out[n..n + word.len()].copy_from_slice(word.as_bytes());
        n += word.len();
    }
    n
}

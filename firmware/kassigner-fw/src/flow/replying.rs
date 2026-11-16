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

//! SIGNED TX QR: the reply's format, its codes and how they are shown.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// The reply's format: a bundle for a bundle, else a KSPT.
    pub fn reply_format(&self) -> Format {
        if self.document_len.is_some() {
            Format::Pskb
        } else {
            Format::Kspt
        }
    }

    /// The reply being shown, empty otherwise.
    pub fn reply(&self) -> &[u8] {
        &self.buffers.reply[..self.reply_len]
    }

    /// The reply in v1.0.7's form, which Wallet shows in its place: empty
    /// but for a single-key `0x01` request, a wallet built on that
    /// release's.
    pub fn reply_v107(&self) -> &[u8] {
        &self.buffers.edited[..self.reply_v107]
    }

    /// How many codes the reply takes, at least one: for a wallet, frames
    /// of this display's size capped at [`limits::FRAME_PAYLOAD`] (the count
    /// drawn, whatever a board says), or v1.0.7's frames for its form; for
    /// another unit, version-3 frames.
    pub fn reply_codes(&self, wallet: bool) -> usize {
        if wallet && self.reply_v107 != 0 {
            return frame::v107::codes(self.reply_v107);
        }
        let per = if wallet {
            self.capacity
                .display_bytes_per_frame
                .min(limits::FRAME_PAYLOAD)
        } else {
            UNIT_FRAME_BYTES
        };
        kassigner_protocol::frame::frames_needed(self.reply_len, per).max(1)
    }

    /// Whether the reply fits the `max_frames` a unit reassembles: always
    /// for a wallet, the reply being planned against this display, and its
    /// v1.0.7 form kept only within that release's frames.
    pub fn reply_fits(&self, wallet: bool) -> bool {
        (wallet && self.reply_v107 != 0) || self.reply_codes(wallet) <= self.profile.max_frames
    }

    /// The frames the reply is shown in, as SIGNED TX QR chose.
    pub fn reply_frames(&self) -> u8 {
        u8::try_from(self.reply_codes(self.reply_wallet)).unwrap_or(u8::MAX)
    }

    /// The reply's signature count, for a multisig input.
    pub fn reply_signers(&self) -> Option<reply::Signers> {
        self.reply_signers
    }

    /// The reply's code for frame `frame`, for drawing.
    pub fn reply_code(&self, frame: u8) -> Option<kassigner_qr::encode::QrMatrix> {
        use kassigner_protocol::frame;
        let total = self.reply_frames();
        if self.reply_wallet && self.reply_v107 != 0 {
            let mut buf = [0u8; frame::v107::CODE_LEN];
            let n = frame::v107::write(self.reply_v107(), usize::from(frame), &mut buf)?;
            return frame_code(&buf[..n], total > 1);
        }
        let mut buf = [0u8; frame::FIRST_HEADER_LEN + limits::FRAME_PAYLOAD];
        let format = self.reply_format();
        let n = frame::write_split(format, self.reply(), frame, total, &mut buf).ok()?;
        frame_code(&buf[..n], self.reply_wallet && total > 1)
    }

    /// SIGNED TX QR: Wallet (version-9 frames) or KasSigner (version-3), QR
    /// DISPLAY MODE first for more than one code. KasSigner past what a unit
    /// reassembles does nothing. Back or Home is done with the reply.
    pub(super) fn on_reply_format(&mut self, event: Event<'_>) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let wallet = match kpub_screen::target(self.scale, x, y)? {
            kpub_screen::Target::Nav(_) => {
                self.state = State::Home;
                return None;
            }
            kpub_screen::Target::Wallet => true,
            kpub_screen::Target::KasSigner => false,
        };
        if !self.reply_fits(wallet) {
            return None;
        }
        self.reply_wallet = wallet;
        if self.reply_frames() > 1 {
            self.state = State::ReplyMode;
        } else {
            self.show_reply();
        }
        None
    }

    /// QR DISPLAY MODE for the reply's frames. Back is SIGNED TX QR; Home is
    /// done with the reply.
    pub(super) fn on_reply_mode(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::ReplyFormat,
            dialog::Target::Cancel => {
                self.manual = false;
                self.show_reply();
            }
            dialog::Target::Accept => {
                self.manual = true;
                self.show_reply();
            }
        }
        None
    }

    /// The reply from its first frame.
    pub(super) fn show_reply(&mut self) {
        self.frame_us = if self.reply_wallet {
            limits::WALLET_FRAME_US
        } else {
            limits::KASSIGNER_FRAME_US
        };
        self.frame_since = self.now_us;
        self.state = State::Showing { frame: 0 };
    }

    /// The reply shown: in Auto Cycle frames turn every
    /// [`WALLET_FRAME_US`](limits::WALLET_FRAME_US) or
    /// [`KASSIGNER_FRAME_US`](limits::KASSIGNER_FRAME_US), in Manual by tap.
    /// A tap in Auto Cycle, or on the last frame, is SIGNED TX.
    pub(super) fn on_showing(&mut self, event: Event<'_>, frame: u8) -> Option<Command> {
        let frames = self.reply_frames();
        match event {
            Event::Tick { now_us } if !self.manual => {
                if let Some(next) = self.turn(now_us, frame, frames) {
                    self.state = State::Showing { frame: next };
                }
            }
            Event::Tap { .. } if self.manual && frame + 1 < frames => {
                self.state = State::Showing { frame: frame + 1 };
            }
            Event::Tap { .. } => self.state = State::ReplyDone,
            _ => {}
        }
        None
    }

    /// SIGNED TX: Save to SD (`TXnnnn.KSP`) or Back to QR. Back is SIGNED TX
    /// QR; Home is done with the reply.
    pub(super) fn on_reply_done(
        &mut self,
        event: Event<'_>,
        pressed_at: Option<(u16, u16)>,
    ) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        match tapped(pressed_at, (x, y), |x, y| dialog::target(self.scale, x, y))? {
            dialog::Target::Nav(Nav::Home) => self.state = State::Home,
            dialog::Target::Nav(_) => self.state = State::ReplyFormat,
            dialog::Target::Cancel => return self.start_saving(Saving::Reply, State::ReplyDone),
            dialog::Target::Accept => self.show_reply(),
        }
        None
    }

    /// Once the flow is home, however it got there, the reply is wiped with
    /// its request.
    pub(super) fn keep_reply(&mut self) {
        if self.reply_len == 0 || self.state != State::Home {
            return;
        }
        wipe::wipe(&mut self.buffers.reply[..self.reply_len]);
        wipe::wipe(&mut self.buffers.edited[..self.reply_v107]);
        self.reply_len = 0;
        self.reply_signers = None;
        self.reply_v107 = 0;
        self.reply_wallet = true;
        self.drop_request();
    }
}

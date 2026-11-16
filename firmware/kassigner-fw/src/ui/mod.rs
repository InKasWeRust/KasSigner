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

//! The screen, drawn a band at a time.
//!
//! Each band of rows is composed in a small buffer in internal RAM, lent by
//! the binary, and sent in one transfer: every pixel arrives once and final,
//! and text and rounded corners blend against the band's pixels, as a panel
//! cannot be read back. A whole screen would take 150 KB of internal RAM on
//! an S3, or PSRAM, which must never hold a seed screen. After a screen
//! [`crate::flow::Screen::shows_secret`] says yes to, the signing binary
//! scrubs the stack, the band and the encoder's scratch with it.
//!
//! - [`color`], [`band`] (with [`band::render`], which draws a region band
//!   by band), [`font`] and [`image`] (glyphs, icons and pictures), [`scale`]
//!   (the 320 by 240 design on any panel) and [`chrome`] (what screens share).
//! - [`brand`], [`menu`], [`seeds`], [`dialog`], [`camera`], [`backup`],
//!   [`loading`], [`settings`], [`camtune`], [`sd_card`], [`keyboard`],
//!   [`words`], [`address`], [`keypad`], [`dice`], [`bip85`], [`seedqr`],
//!   [`kpub`], [`multisig`], [`stego`], [`review`], [`savings`] and
//!   [`refusal`]: the screens. Each places its tappable things in one
//!   function that its drawing and the touch both call.
//! - `gen`: tables written by `tests/ui_assets.rs` from `assets/`.
//!
//! Nothing here knows a board: a panel is `kassigner_hal::display::Display`,
//! and host tests draw into a plain buffer.

pub mod address;
pub mod backup;
pub mod band;
pub mod bip85;
pub mod brand;
pub mod camera;
pub mod camtune;
pub mod chrome;
pub mod color;
pub mod dialog;
pub mod dice;
pub mod font;
pub mod gen;
pub mod image;
pub mod keyboard;
pub mod keypad;
pub mod kpub;
pub mod loading;
pub mod menu;
pub mod multisig;
pub mod refusal;
pub mod review;
pub mod savings;
pub mod scale;
pub mod sd_card;
pub mod seedqr;
pub mod seeds;
pub mod settings;
pub mod stego;
pub mod words;

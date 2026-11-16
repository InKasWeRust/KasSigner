// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Our covenant cards: programs of ours, written in SilverScript.
//!
//! Each card's source is in `sil/`; here is its compiled template: the
//! prefix before the state, the suffix after, and the hash that names the
//! card. Every value is state, so a card is its values between the halves.
//! The tests compile each source with `silverscript-lang` 1.0.1, require
//! the same bytes, and run the spends through rusty-kaspa's script engine.
//! The layouts are KCC-1's, in `kassigner-kaspa`; here are the programs and
//! the rules a card adds, such as a whole-minute time.

pub mod backup;
pub mod savings;

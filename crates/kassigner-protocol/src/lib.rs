// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KasSigner's own wire formats.
//!
//! Byte layouts and bounds, and the checks a unit makes with no key
//! ([`check`]), which a companion applies too, before showing a request and
//! when reading a reply. Kaspa's rules come from `kassigner-kaspa` and are
//! not restated here. No key material.
//!
//! Every line here is a decision of ours, so nothing enters without a
//! written reason, and a format does not change before its vectors pass.
//!
//! No fixed-size arrays: everything parses into borrowed slices, with bounds
//! passed in. A device supplies static buffers, a browser a heap. An array
//! sized to one board would read as a rule of the format, not one device's
//! memory budget.

#![no_std]
#![forbid(unsafe_code)]

pub mod bundle;
pub mod card;
pub mod check;
pub mod container;
pub mod descriptor;
pub mod ecies;
pub mod frame;
pub mod group;
pub mod kpub;
pub mod kspt;
pub mod message;
pub mod payload;
pub mod profile;
pub mod stego;

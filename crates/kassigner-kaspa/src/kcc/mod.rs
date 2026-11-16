// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Kaspa Calls for Conventions for covenants, restated `no_std`.
//!
//! KCC-1, "Covenant Concepts, Byte Layouts, and ABI", and KCC-2, "Authority
//! Schemes", both Final, from `kaspanet/kccs` at
//! `1ed87aef59faff8354061aee30f734a3b8b2c3d2`, CC0; their vectors are copied
//! unchanged into `spec/vectors/v110/covenants/`. SilverScript 1.0.1
//! (`silverscript-lang`, `silverscript-abi`, dev-dependencies) emits KCC-1's
//! layouts and is checked against too. KCC-3 is a script form, in
//! [`crate::script`].
//!
//! - [`hash`]: BLAKE3, unkeyed and keyed, and a template's hash.
//! - [`abi`]: value types, their names, an entrypoint's dispatch tag.
//! - [`push`]: the two data pushes.
//! - [`envelope`]: a program's lock, and a spend's invocation.
//! - [`value`]: arguments read by their types, and an `int` written.
//! - [`state`]: a program cut at its state, and the state read.
//! - [`authority`]: KCC-2's schemes.
//!
//! Time-Locked Savings uses [`abi`], [`hash`], [`push`], [`state`] and
//! [`value`]. [`envelope`], [`authority`], [`abi::check_entrypoints`],
//! [`state::check_state`] and [`value`]'s argument readers are for the cards
//! to come; nothing on a unit calls them yet.
//!
//! A program's ABI comes from a source the signer trusts, never the request
//! (KCC-1 7.2), and a spend's arguments are not signed (7.4): both are the
//! unit's to keep. This crate checks layouts only.

pub mod abi;
pub mod authority;
pub mod envelope;
pub mod hash;
pub mod push;
pub mod state;
pub mod value;

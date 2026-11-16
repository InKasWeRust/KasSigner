// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! PSKB, rusty-kaspa's partially signed bundle format (upstream
//! `wallet/pskt/src/bundle.rs`, `global.rs`, `input.rs`, `output.rs`).
//!
//! rusty-kaspa's format, not ours: level 0, like the consensus rules. Our
//! level-1 format is not another encoding of it: PSKB is a document several
//! parties edit in turn, ours a snapshot for a camera.
//!
//! The top level is a JSON array (`Bundle(pub Vec<PSKTInner>)`), so one
//! envelope can carry several transactions.
//!
//! No serde: `serde_json` needs an allocator and several hundred kilobytes
//! of code. This is a strict parser over borrowed bytes that holds every
//! value to what upstream reads and reports every member it does not know,
//! never skipping one silently: a signer must not sign what it cannot show.
//!
//! A device is one party of several, so members for a later role survive:
//! output copies the document through with splices ([`emit()`]), every
//! other byte as it arrived.

pub mod emit;
pub mod envelope;
pub mod lexer;
pub mod schema;
pub mod signature;
pub mod transaction;
mod values;
pub mod write;

pub use emit::{
    emit, emitted_len, write_partial_sig, EmitError, Splice, PARTIAL_SIG_MEMBER_LEN, SIGNATURE_LEN,
};
pub use envelope::{decode_envelope, decoded_len, encode_envelope, EnvelopeError, MAGIC};
pub use lexer::{LexError, Lexer, Token};
pub use schema::{check, walk, Checked, Field, ParseError, Scope, Span, Visitor};

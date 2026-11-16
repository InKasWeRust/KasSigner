// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa's rules, and the standards Kaspa adopts, restated `no_std`.
//!
//! Nothing here was designed by us: every item traces to a file and line of
//! rusty-kaspa, a BIP or a published standard. No key material, no
//! allocation policy, no I/O, no state.
//!
//! Deliberately absent:
//!
//! - **Rules needing chain state.** Several limits resolve against the
//!   current DAA score, which an air-gapped signer does not have; a score in
//!   a payload is the attacker's to choose. Rules gated on the transaction
//!   version are here: the version is in the payload.
//! - **The script engine.** A signer never runs a script; this crate has the
//!   opcode table and a disassembler.
//! - **Signing.** Verification is here; key material lives in one other
//!   crate.
//!
//! The pin: rusty-kaspa `01b532e8b553523216471682649693af92f0fd16`, v2.1.0.
//! Toccata, the covenant hardfork, is active on mainnet from DAA score
//! 474,165,565 (`docs/toccata-guide.md` at the pin). Record per value which
//! side of which fork it came from, so the next fork's lines can be found.
//!
//! Conformance is by value, not by name: the same inputs give the same bytes,
//! asserted in `tests/`.

#![no_std]
#![forbid(unsafe_code)]

pub mod address;
pub mod base58;
pub mod bip32_public;
pub mod bip340;
pub mod constants;
pub mod derivation;
/// Hex digits for the crate's own readers and writers.
mod hex;
/// Known answers for a device to run at boot, beside
/// `kassigner_crypto::kat`.
pub mod kat;
pub mod kcc;
pub mod mass;
pub mod multisig;
pub mod pskb;
pub mod rpc;
pub mod safe_json;
pub mod script;
pub mod sighash;
pub mod subnets;
pub mod tx;
pub mod wrpc;

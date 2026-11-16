// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The companion's side of a KasSigner unit.
//!
//! A unit is air-gapped: everything it knows arrives as a QR code it reads,
//! and everything it says leaves as a QR code it shows. An app on the other
//! side does five things, one module each:
//!
//! 1. **Import** what the unit hands over: a kpub, a cosigner's file, a
//!    multisig descriptor, a 22' address, a signed message ([`import`]).
//! 2. **Watch** the addresses and locking scripts that follow, as the unit
//!    derives them ([`watch`]).
//! 3. **Request** a signature on a transaction, with the hints the unit
//!    needs, checked against its rules first so a refusal shows in the app
//!    ([`request`]).
//! 4. **Transport** the request in the unit's frames, and reassemble the
//!    reply from the frames it shows ([`transport`]).
//! 5. **Reply**: signatures checked, cosigners' replies merged, the
//!    transaction finished for broadcast ([`reply`]).
//!
//! [`card`] makes and backs up a Time-Locked Savings card, whose UTXOs are
//! spent through steps 3 to 5 like any coin. [`bundle`] does steps 3 to 5
//! for an app that speaks rusty-kaspa's bundles, under the same rules. A
//! request can also be written as a bundle ([`request::bundle`]) or in the
//! WASM SDK's safe JSON ([`request::safe_json()`]), read back signed with
//! [`reply::finalize_safe_json`]. [`message`] sends a text for the unit to
//! sign and verifies the signed record. [`node`] writes an app's calls to a
//! node's wRPC and reads the answers; which node, the connection, and where
//! the app keeps what it watches are the app's. Nothing here holds state
//! between calls.
//!
//! Nothing in this crate's dependency tree holds a seed or a private key:
//! `kassigner-crypto`, the one crate that does, is not in it, which
//! `tests/no_keys.rs` checks with `cargo tree -p kassigner-sdk` at every
//! test run. An app built on this crate cannot sign.
//!
//! Every rule here is read from where the unit reads it, `kassigner_kaspa`
//! for Kaspa's and `kassigner_protocol` for ours, so an app and a unit
//! cannot disagree about a format or a limit.
//!
//! `no_std`, no allocation: buffers are the caller's and bounds arrive as
//! parameters. A browser passes vectors, a device static arrays.

#![no_std]
#![forbid(unsafe_code)]

pub mod bundle;
pub mod card;
pub mod import;
pub mod message;
pub mod node;
pub mod reply;
pub mod request;
pub mod transport;
pub mod watch;

/// The network an address names. The SDK takes and writes mainnet
/// addresses only; this names another network in the error that refuses
/// it.
pub use kassigner_kaspa::address::Prefix as Network;
/// What a unit accepts: its bounds, which a request is built within.
pub use kassigner_protocol::profile::Profile;

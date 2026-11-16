// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The SDK for a browser: [`kassigner_sdk_host`] behind `wasm-bindgen`.
//! Every class wraps the host crate's type and every function calls its
//! function; every rule, format and check is the SDK's.
//!
//! - [`watch`]: [`watch::read_import`], [`watch::Account`],
//!   [`watch::Group`], [`watch::Kcc3Address`].
//! - [`request`]: [`request::RequestBuilder`], [`request::summary`].
//! - [`transport`]: [`transport::codes`], [`transport::Reader`],
//!   [`transport::decode_qr`].
//! - [`reply`]: [`reply::read_reply`], [`reply::merge_replies`],
//!   [`reply::finalize_reply`].
//! - [`bundle`]: the same over rusty-kaspa's bundles.
//! - [`message`]: [`message::message_codes`], [`message::verify_message`].
//! - [`node`]: [`node::Node`], a node's wRPC: coins, fee rates and the
//!   signed transaction's submission.
//! - [`card`]: [`card::Card`], the Time-Locked Savings covenant card, whose
//!   UTXOs [`request::RequestBuilder`] spends (`spendCard`).
//!
//! Built without the `transactions` feature (`build.sh watch`), the package
//! only watches: [`request`], [`reply`], [`bundle`], [`Rates`] and
//! `Node.submitTransaction` are left out, and nothing in it can build,
//! finish or send a transaction. [`coin::Coin`] is in both.
//!
//! Bytes are `Uint8Array`, text a string, every `u64` (sompi, masses, DAA
//! scores, times) a `BigInt`, counts and indexes numbers. A failure throws
//! an `Error` whose message is the SDK's name for it, such as
//! `Insufficient { have: 5, need: 7 }`. Apart from the JavaScript
//! boundary this is plain Rust, so `cargo test` covers it on the host.

#![deny(unsafe_code)]

#[cfg(feature = "transactions")]
pub mod bundle;
pub mod card;
pub mod coin;
pub mod message;
pub mod node;
#[cfg(feature = "transactions")]
pub mod reply;
#[cfg(feature = "transactions")]
pub mod request;
pub mod transport;
pub mod watch;

use wasm_bindgen::prelude::*;

use kassigner_sdk_host as host;

/// Why a call failed, the host crate's [`host::Fault`]: the SDK's name for
/// it, thrown to JavaScript as an `Error`'s message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault(pub String);

impl From<host::Fault> for Fault {
    fn from(f: host::Fault) -> Self {
        Fault(f.0)
    }
}

impl From<Fault> for JsValue {
    fn from(f: Fault) -> Self {
        JsError::new(&f.0).into()
    }
}

/// What a unit accepts: the bounds every buffer is sized by and every
/// request is built within.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    inner: host::Profile,
}

#[wasm_bindgen]
impl Profile {
    /// The ESP32-S3 units' profile, which the P4 units share: the bounds
    /// their firmware declares.
    #[wasm_bindgen(js_name = esp32s3)]
    pub fn esp32s3() -> Profile {
        Profile {
            inner: host::Profile::esp32s3(),
        }
    }

    #[wasm_bindgen(getter, js_name = maxInputs)]
    pub fn max_inputs(&self) -> u32 {
        self.inner.max_inputs()
    }

    #[wasm_bindgen(getter, js_name = maxOutputs)]
    pub fn max_outputs(&self) -> u32 {
        self.inner.max_outputs()
    }

    #[wasm_bindgen(getter, js_name = maxFrames)]
    pub fn max_frames(&self) -> u32 {
        self.inner.max_frames()
    }

    #[wasm_bindgen(getter, js_name = maxReassembled)]
    pub fn max_reassembled(&self) -> u32 {
        self.inner.max_reassembled()
    }

    #[wasm_bindgen(getter, js_name = maxSigsPerInput)]
    pub fn max_sigs_per_input(&self) -> u32 {
        self.inner.max_sigs_per_input()
    }

    #[wasm_bindgen(getter, js_name = maxRedeem)]
    pub fn max_redeem(&self) -> u32 {
        self.inner.max_redeem()
    }
}

impl Profile {
    /// The host crate's profile.
    pub const fn inner(&self) -> &host::Profile {
        &self.inner
    }
}

/// A network's mass rates, which the fee is paid over.
#[cfg(feature = "transactions")]
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    inner: host::Rates,
}

#[cfg(feature = "transactions")]
#[wasm_bindgen]
impl Rates {
    /// Mainnet's rates.
    pub fn mainnet() -> Rates {
        Rates {
            inner: host::Rates::mainnet(),
        }
    }
}

#[cfg(feature = "transactions")]
impl Rates {
    /// The host crate's rates.
    pub const fn inner(&self) -> &host::Rates {
        &self.inner
    }
}

/// This package's version: the SDK's release.
#[wasm_bindgen]
pub fn version() -> String {
    host::version()
}

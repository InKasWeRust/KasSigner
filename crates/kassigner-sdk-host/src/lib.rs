// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The SDK for a host with an allocator: [`kassigner_sdk`] with its
//! buffers inside and plain values out.
//!
//! The SDK takes the caller's buffers; each call here sizes them from the
//! [`Profile`] given and returns owned values. Every rule is the SDK's,
//! which is the unit's. `kassigner-sdk-wasm` and `kassigner-sdk-ffi` wrap
//! this layer.
//!
//! - [`watch`]: what a unit hands over, and the addresses and scripts to
//!   watch.
//! - [`request`]: a [`request::RequestBuilder`] builds what the unit signs.
//! - [`transport`]: the codes a unit reads, and a reader for what it shows.
//! - [`reply`]: a reply read against its request, cosigners' replies
//!   merged, the transaction finished for `submitTransaction`.
//! - [`bundle`]: the same over rusty-kaspa's bundles.
//! - [`message`]: a text's codes, and a signed record verified.
//! - [`card`]: a Time-Locked Savings card made, backed up and read back.
//! - [`node`]: a node's wRPC calls written and its answers read.
//!
//! Bytes are `Vec<u8>`, text `String`, sompi and masses `u64`, counts
//! `u32`. An error is a [`Fault`], its text the SDK's name for it where
//! there is one, such as `Insufficient { have: 5, need: 7 }`.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod card;
pub mod message;
pub mod node;
pub mod reply;
pub mod request;
pub mod transport;
pub mod watch;

use kassigner_kaspa::mass::MassRates;

/// Why a call failed: the SDK's own name for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault(pub String);

impl Fault {
    /// The fault for an SDK error, named as the SDK names it.
    pub fn of<E: core::fmt::Debug>(e: E) -> Self {
        Fault(format!("{e:?}"))
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fault {}

/// `bytes` as lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * bytes.len());
    for &b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0x0f)] as char);
    }
    s
}

/// `text`, whitespace at its ends aside, as exactly `N` bytes of hex,
/// `0-9`, `a-f` or `A-F`. Read as bytes, not sliced as text, so a
/// multi-byte character is refused, not a panic.
pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N], Fault> {
    let t = text.trim();
    if !t.is_ascii() {
        return Err(Fault(format!("expected {N} bytes of hex, got other text")));
    }
    let t = t.as_bytes();
    if t.len() != 2 * N {
        return Err(Fault(format!(
            "expected {N} bytes of hex, got {} digits",
            t.len()
        )));
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = match (digit(t[2 * i]), digit(t[2 * i + 1])) {
            (Some(high), Some(low)) => high << 4 | low,
            _ => return Err(Fault(format!("not hex at {}", 2 * i))),
        };
    }
    Ok(out)
}

/// What a unit accepts: the SDK's [`Profile`](kassigner_sdk::Profile),
/// which sizes every buffer here and bounds every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    inner: kassigner_sdk::Profile,
}

impl Profile {
    /// The profile every unit is built on, the P4 included: 32 inputs, 8
    /// outputs, 64 frames, 16,381 bytes reassembled.
    pub const fn esp32s3() -> Profile {
        Profile {
            inner: kassigner_sdk::Profile::ESP32S3,
        }
    }

    /// The SDK's profile.
    pub const fn inner(&self) -> &kassigner_sdk::Profile {
        &self.inner
    }

    pub const fn max_inputs(&self) -> u32 {
        self.inner.max_inputs as u32
    }

    pub const fn max_outputs(&self) -> u32 {
        self.inner.max_outputs as u32
    }

    pub const fn max_frames(&self) -> u32 {
        self.inner.max_frames as u32
    }

    pub const fn max_reassembled(&self) -> u32 {
        self.inner.max_reassembled as u32
    }

    pub const fn max_sigs_per_input(&self) -> u32 {
        self.inner.max_sigs_per_input as u32
    }

    pub const fn max_redeem(&self) -> u32 {
        self.inner.max_redeem as u32
    }
}

/// A network's mass rates, [`MassRates`], which a fee is computed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    inner: MassRates,
}

impl Rates {
    /// Mainnet's rates.
    pub const fn mainnet() -> Rates {
        Rates {
            inner: MassRates::MAINNET,
        }
    }

    /// The SDK's rates.
    pub const fn inner(&self) -> &MassRates {
        &self.inner
    }
}

/// This crate's version, which a binding reports.
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

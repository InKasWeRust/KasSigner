// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A rusty-kaspa bundle through a unit: [`kassigner_sdk_host::bundle`] for
//! JavaScript. A `PSKB` envelope is text, passed as its bytes.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::bundle as host;

use crate::reply::{Checked, Finalized};
use crate::request::Summary;
use crate::watch::{Account, Group};
use crate::{Fault, Profile, Rates};

/// The derivation hints a bundle's inputs get, one call an input.
#[wasm_bindgen]
#[derive(Clone, Debug, Default)]
pub struct Hints {
    inner: host::Hints,
}

#[wasm_bindgen]
impl Hints {
    /// No hints yet.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Hints {
        Hints::default()
    }

    /// Input `input` is a `44'` account's `chain`/`index`; `fingerprint`
    /// is the seed's master fingerprint, hex, when the app knows it.
    pub fn account(
        &mut self,
        input: u32,
        account: &Account,
        chain: u32,
        index: u32,
        fingerprint: Option<String>,
    ) -> Result<(), Fault> {
        Ok(self
            .inner
            .account(input, account.inner(), chain, index, fingerprint)?)
    }

    /// Input `input` is a `45'` group's `cosigner`/`chain`/`index`;
    /// `fingerprints` are the cosigners' seed fingerprints, hex, in key
    /// order, as many as the app knows; an empty string for one it does not.
    pub fn group(
        &mut self,
        input: u32,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        fingerprints: Vec<String>,
    ) -> Result<(), Fault> {
        Ok(self
            .inner
            .group(input, group.inner(), cosigner, chain, index, fingerprints)?)
    }
}

/// What [`prepare_bundle`] made.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    inner: host::Prepared,
}

#[wasm_bindgen]
impl Prepared {
    /// The envelope, `PSKB` and hex, as bytes: what
    /// [`crate::transport::codes`] shows the unit as format `pskb`.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.bytes.clone()
    }

    /// The envelope as text.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner.text()
    }

    /// Inputs of the transaction.
    #[wasm_bindgen(getter)]
    pub fn inputs(&self) -> u32 {
        self.inner.inputs
    }

    /// Signatures the unit's reply must carry in all.
    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> u32 {
        self.inner.signatures
    }
}

/// Prepare `bundle`, a wallet's `PSKB` envelope, for the unit: checked
/// against the unit's rules and written again with `hints` in its inputs.
///
/// Throws as the SDK's `BundleError` says: `NotOneTransaction`,
/// `Check(...)`, `Multisig(...)`, `Hint { input }`...
#[wasm_bindgen(js_name = prepareBundle)]
pub fn prepare_bundle(bundle: &[u8], hints: &Hints, profile: &Profile) -> Result<Prepared, Fault> {
    Ok(Prepared {
        inner: host::prepare_bundle(bundle, &hints.inner, profile.inner())?,
    })
}

/// Read `reply` against `request`, both envelopes: every signature
/// verified over the request's transaction.
///
/// Throws `NotTheRequest`, `Check(BadSignature { input })`...
#[wasm_bindgen(js_name = readBundle)]
pub fn read_bundle(request: &[u8], reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    Ok(Checked::over(host::read_bundle(
        request,
        reply,
        profile.inner(),
    )?))
}

/// Read `signed`, a signed bundle with no request: every signature
/// verified over its own transaction. [`bundle_summary`] gives what it pays.
///
/// Throws as [`read_bundle`] but `NotTheRequest`.
#[wasm_bindgen(js_name = readSignedBundle)]
pub fn read_signed_bundle(signed: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    Ok(Checked::over(host::read_signed_bundle(
        signed,
        profile.inner(),
    )?))
}

/// Merge `copies` of one signed bundle into one envelope, every signature
/// verified over the first copy's transaction; a key's signature in two
/// copies is kept once.
///
/// Throws `Check(BadSignature { input })` for a copy of another
/// transaction; as [`read_signed_bundle`].
#[wasm_bindgen(js_name = mergeSignedBundles)]
pub fn merge_signed_bundles(
    copies: Vec<js_sys::Uint8Array>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let held: Vec<Vec<u8>> = copies.iter().map(|r| r.to_vec()).collect();
    let refs: Vec<&[u8]> = held.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_signed_bundles(&refs, profile.inner())?)
}

/// Finish `signed`, a complete signed bundle, with no request: as
/// [`finalize_bundle`].
///
/// Throws as [`finalize_bundle`] but `NotTheRequest`.
#[wasm_bindgen(js_name = finalizeSignedBundle)]
pub fn finalize_signed_bundle(
    signed: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(Finalized::over(host::finalize_signed_bundle(
        signed,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?))
}

/// What `envelope`, a bundle, carries, as [`crate::request::summary`]
/// reads a KSPT. Nothing is verified.
///
/// Throws for what is not a bundle of one transaction.
#[wasm_bindgen(js_name = bundleSummary)]
pub fn bundle_summary(envelope: &[u8], profile: &Profile) -> Result<Summary, Fault> {
    Ok(Summary {
        inner: host::bundle_summary(envelope, profile.inner())?,
    })
}

/// Merge `replies`, cosigners' answers to `request`, into one envelope.
///
/// Throws as [`read_bundle`]; `Edit(SameKeyTwice)` for one key signing
/// twice.
#[wasm_bindgen(js_name = mergeBundles)]
pub fn merge_bundles(
    request: &[u8],
    replies: Vec<js_sys::Uint8Array>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let held: Vec<Vec<u8>> = replies.iter().map(|r| r.to_vec()).collect();
    let refs: Vec<&[u8]> = held.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_bundles(request, &refs, profile.inner())?)
}

/// Finish `reply`, a complete bundle reply to `request`: as
/// [`crate::reply::finalize_reply`] over a bundle.
///
/// Throws `NotTheRequest`, `Check(BadSignature { input })`,
/// `Finish(Signatures { .. })`, `Finish(FeeTooLow { .. })`...
#[wasm_bindgen(js_name = finalizeBundle)]
pub fn finalize_bundle(
    request: &[u8],
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(Finalized::over(host::finalize_bundle(
        request,
        reply,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?))
}

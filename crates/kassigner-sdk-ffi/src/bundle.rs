// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A rusty-kaspa bundle (PSKB) through a unit:
//! [`kassigner_sdk_host::bundle`] over the C ABI. An envelope is passed as
//! the bytes of its text.

use std::sync::Mutex;

use kassigner_sdk_host::bundle as host;

use crate::reply::{Checked, Finalized};
use crate::request::Summary;
use crate::watch::{Account, Group};
use crate::{lock, Fault, Profile, Rates};

/// The derivation hints a bundle's inputs get, one call an input.
#[derive(Debug, Default, uniffi::Object)]
pub struct Hints {
    inner: Mutex<host::Hints>,
}

#[uniffi::export]
impl Hints {
    /// No hints yet.
    #[uniffi::constructor]
    pub fn new() -> Hints {
        Hints::default()
    }

    /// Input `input` is a `44'` account's `chain`/`index`; `fingerprint`,
    /// hex, is the seed's master fingerprint if known.
    ///
    /// # Errors
    ///
    /// A fingerprint that is not 4 bytes of hex.
    pub fn account(
        &self,
        input: u32,
        account: &Account,
        chain: u32,
        index: u32,
        fingerprint: Option<String>,
    ) -> Result<(), Fault> {
        Ok(lock(&self.inner).account(input, account.inner(), chain, index, fingerprint)?)
    }

    /// Input `input` is a `45'` group's `cosigner`/`chain`/`index`;
    /// `fingerprints`, hex, are the cosigners' seed fingerprints in key
    /// order, as many as known, an empty string for an unknown one.
    ///
    /// # Errors
    ///
    /// A fingerprint that is not 4 bytes of hex.
    pub fn group(
        &self,
        input: u32,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        fingerprints: Vec<String>,
    ) -> Result<(), Fault> {
        Ok(lock(&self.inner).group(input, group.inner(), cosigner, chain, index, fingerprints)?)
    }
}

/// What [`prepare_bundle`] made.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Prepared {
    /// The envelope, `PSKB` and hex: what [`crate::transport::codes`]
    /// shows the unit as format `pskb`.
    pub bytes: Vec<u8>,
    /// The envelope as text.
    pub text: String,
    /// Inputs of the transaction.
    pub inputs: u32,
    /// Signatures the reply needs in all.
    pub signatures: u32,
}

impl From<host::Prepared> for Prepared {
    fn from(p: host::Prepared) -> Self {
        Prepared {
            text: p.text(),
            bytes: p.bytes,
            inputs: p.inputs,
            signatures: p.signatures,
        }
    }
}

/// Prepare `bundle`, a wallet's `PSKB` envelope, for the unit: checked by
/// the unit's rules, `hints` written into its inputs.
///
/// # Errors
///
/// The SDK's `BundleError`: `NotOneTransaction { count }`, `Check(...)`,
/// `Multisig(...)`, `Hint { input }`...
#[uniffi::export]
pub fn prepare_bundle(
    bundle: Vec<u8>,
    hints: &Hints,
    profile: &Profile,
) -> Result<Prepared, Fault> {
    Ok(host::prepare_bundle(&bundle, &lock(&hints.inner), profile.inner())?.into())
}

/// Read `reply` against `request`, both envelopes, every signature
/// verified.
///
/// # Errors
///
/// `NotTheRequest`, `Check(BadSignature { input })`...
#[uniffi::export]
pub fn read_bundle(request: Vec<u8>, reply: Vec<u8>, profile: &Profile) -> Result<Checked, Fault> {
    Ok(host::read_bundle(&request, &reply, profile.inner())?.into())
}

/// Read `signed_tx`, a signed bundle, with no request, every member
/// verified.
///
/// # Errors
///
/// As [`read_bundle`] but `NotTheRequest`.
#[uniffi::export]
pub fn read_signed_bundle(signed_tx: Vec<u8>, profile: &Profile) -> Result<Checked, Fault> {
    Ok(host::read_signed_bundle(&signed_tx, profile.inner())?.into())
}

/// Merge `copies` of one signed bundle, every copy's members verified over
/// the first's transaction; for a key two copies sign with, the first
/// stands.
///
/// # Errors
///
/// `Check(BadSignature { input })` for a member of a copy of another
/// transaction; as [`read_signed_bundle`].
#[uniffi::export]
pub fn merge_signed_bundles(copies: Vec<Vec<u8>>, profile: &Profile) -> Result<Vec<u8>, Fault> {
    let refs: Vec<&[u8]> = copies.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_signed_bundles(&refs, profile.inner())?)
}

/// Finish `signed_tx`, a complete signed bundle, with no request: as
/// [`finalize_bundle`].
///
/// # Errors
///
/// As [`finalize_bundle`] but `NotTheRequest`.
#[uniffi::export]
pub fn finalize_signed_bundle(
    signed_tx: Vec<u8>,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(
        host::finalize_signed_bundle(&signed_tx, allow_orphan, rates.inner(), profile.inner())?
            .into(),
    )
}

/// Read `envelope`, a bundle, unverified, as [`crate::request::summary`]
/// reads a KSPT.
///
/// # Errors
///
/// What is not a bundle of one transaction.
#[uniffi::export]
pub fn bundle_summary(envelope: Vec<u8>, profile: &Profile) -> Result<Summary, Fault> {
    Ok(host::bundle_summary(&envelope, profile.inner())?.into())
}

/// Merge `replies`, each a cosigner's answer to `request`, into one
/// envelope.
///
/// # Errors
///
/// As [`read_bundle`]; `Edit(SameKeyTwice)` for one key signing twice.
#[uniffi::export]
pub fn merge_bundles(
    request: Vec<u8>,
    replies: Vec<Vec<u8>>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let refs: Vec<&[u8]> = replies.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_bundles(&request, &refs, profile.inner())?)
}

/// Finish `reply`, a complete reply to `request`, as
/// [`crate::reply::finalize_reply`] does.
///
/// # Errors
///
/// `NotTheRequest`, `Check(BadSignature { input })`,
/// `Finish(Signatures { .. })`, `Finish(FeeTooLow { .. })`...
#[uniffi::export]
pub fn finalize_bundle(
    request: Vec<u8>,
    reply: Vec<u8>,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(host::finalize_bundle(
        &request,
        &reply,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?
    .into())
}

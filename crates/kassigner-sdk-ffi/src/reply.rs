// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reply read, merged and finished: [`kassigner_sdk_host::reply`] over
//! the C ABI.

use kassigner_sdk_host::reply as host;

use crate::{Fault, Profile, Rates};

/// What a checked reply holds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Checked {
    /// Signatures on the reply, all verified.
    pub signatures: u32,
    /// For a multisig, signatures present that count; none without one.
    pub present: Option<u32>,
    /// For a multisig, signatures the transaction needs.
    pub required: Option<u32>,
    /// Whether every input has what its script needs: ready to finalize.
    pub complete: bool,
}

impl From<host::Checked> for Checked {
    fn from(c: host::Checked) -> Self {
        Checked {
            signatures: c.signatures,
            present: c.present,
            required: c.required,
            complete: c.complete,
        }
    }
}

/// A finished transaction, and the bodies that submit it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Finalized {
    /// The transaction id, hex.
    pub id: String,
    /// The fee it pays, sompi.
    pub fee: u64,
    /// The storage mass it commits.
    pub storage_mass: u64,
    /// Its compute mass as signed.
    pub compute_mass: u64,
    /// `submitTransaction`'s `params` for a node's wRPC JSON port, to send
    /// unchanged.
    pub submit_json: String,
    /// The body of kaspa-rest-server's `POST /transactions` (api.kaspa.org
    /// and other instances).
    pub rest_json: String,
    /// `submitTransaction`'s payload for a node's wRPC Borsh port.
    pub submit_borsh: Vec<u8>,
    /// Each input's unlocking script, hex.
    pub unlocks: Vec<String>,
}

impl From<host::Finalized> for Finalized {
    fn from(f: host::Finalized) -> Self {
        Finalized {
            id: f.id,
            fee: f.fee,
            storage_mass: f.storage_mass,
            compute_mass: f.compute_mass,
            submit_json: f.submit_json,
            rest_json: f.rest_json,
            submit_borsh: f.submit_borsh,
            unlocks: f.unlocks,
        }
    }
}

impl From<Finalized> for host::Finalized {
    fn from(f: Finalized) -> Self {
        host::Finalized {
            id: f.id,
            fee: f.fee,
            storage_mass: f.storage_mass,
            compute_mass: f.compute_mass,
            submit_json: f.submit_json,
            rest_json: f.rest_json,
            submit_borsh: f.submit_borsh,
            unlocks: f.unlocks,
        }
    }
}

/// Read `reply` against `request`: the same transaction, every signature
/// verified.
///
/// # Errors
///
/// `NotTheRequest`, `Unverified(...)`, `Reply(...)` for bytes that are not
/// a KSPT.
#[uniffi::export]
pub fn read_reply(request: Vec<u8>, reply: Vec<u8>, profile: &Profile) -> Result<Checked, Fault> {
    Ok(host::read_reply(&request, &reply, profile.inner())?.into())
}

/// Read `signed_tx`, a signed transaction, with no request: every
/// signature verified over it.
///
/// # Errors
///
/// `Reply(...)` for bytes that are not a KSPT, `Unverified(Nothing)` for
/// none signed, `Unverified(...)`.
#[uniffi::export]
pub fn read_signed_reply(signed_tx: Vec<u8>, profile: &Profile) -> Result<Checked, Fault> {
    Ok(host::read_signed_reply(&signed_tx, profile.inner())?.into())
}

/// Merge `copies` of one signed transaction, each read as
/// [`read_signed_reply`] reads it; at a position two copies sign, the
/// first stands.
///
/// # Errors
///
/// `NotTheRequest` for a copy of another transaction; as
/// [`read_signed_reply`].
#[uniffi::export]
pub fn merge_signed_replies(copies: Vec<Vec<u8>>, profile: &Profile) -> Result<Vec<u8>, Fault> {
    let refs: Vec<&[u8]> = copies.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_signed_replies(&refs, profile.inner())?)
}

/// Finish `signed_tx`, a complete signed transaction, with no request: as
/// [`finalize_reply`].
///
/// # Errors
///
/// As [`read_signed_reply`]; then as [`finalize_reply`].
#[uniffi::export]
pub fn finalize_signed_reply(
    signed_tx: Vec<u8>,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(
        host::finalize_signed_reply(&signed_tx, allow_orphan, rates.inner(), profile.inner())?
            .into(),
    )
}

/// Merge `replies`, each a cosigner's answer to `request`, into one, each
/// read as [`read_reply`] reads it.
///
/// # Errors
///
/// As [`read_reply`]; `Merge(...)` for two signatures at one position.
#[uniffi::export]
pub fn merge_replies(
    request: Vec<u8>,
    replies: Vec<Vec<u8>>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let refs: Vec<&[u8]> = replies.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_replies(&request, &refs, profile.inner())?)
}

/// Finish `reply`, a complete reply to `request`: checked as
/// [`read_reply`] checks it, unlocking scripts written, masses computed,
/// the fee checked.
///
/// # Errors
///
/// `NotTheRequest`, `Unverified(...)` as [`read_reply`];
/// `Signatures { input, have, need }` for an input short of its threshold,
/// `FeeTooLow { fee, minimum }`, `Dust { output }`, `Redeem { input }`,
/// `Unspendable { input }`.
#[uniffi::export]
pub fn finalize_reply(
    request: Vec<u8>,
    reply: Vec<u8>,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(host::finalize_reply(
        &request,
        &reply,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?
    .into())
}

/// Finish `signed_json`, signed by a wallet in the WASM SDK's safe JSON,
/// against `request`, the safe JSON it was handed: the same transaction,
/// every input carrying an unlocking script, the id its own; masses
/// computed, fee checked. The node verifies the signatures.
///
/// # Errors
///
/// `RequestJson(...)`, `ReplyJson(...)`, `NotTheRequest`,
/// `Unsigned { input }`, `WrongId`, `Mass`, `FeeTooLow { fee, minimum }`,
/// `Dust { output }`.
#[uniffi::export]
pub fn finalize_safe_json(
    request: String,
    signed_json: String,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(host::finalize_safe_json(
        &request,
        &signed_json,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?
    .into())
}

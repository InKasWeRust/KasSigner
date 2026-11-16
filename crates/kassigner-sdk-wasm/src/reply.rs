// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reply read, merged and finished: [`kassigner_sdk_host::reply`] for
//! JavaScript.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::reply as host;

use crate::{Fault, Profile, Rates};

/// What a checked reply holds.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    inner: host::Checked,
}

#[wasm_bindgen]
impl Checked {
    /// Signatures on the reply, every one verified.
    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> u32 {
        self.inner.signatures
    }

    /// For a multisig, the signatures that count; none when no input is
    /// one.
    #[wasm_bindgen(getter)]
    pub fn present(&self) -> Option<u32> {
        self.inner.present
    }

    /// For a multisig, the signatures needed.
    #[wasm_bindgen(getter)]
    pub fn required(&self) -> Option<u32> {
        self.inner.required
    }

    /// Whether every input has what its script needs, so the reply can be
    /// finalized.
    #[wasm_bindgen(getter)]
    pub fn complete(&self) -> bool {
        self.inner.complete
    }
}

impl Checked {
    pub(crate) const fn over(inner: host::Checked) -> Checked {
        Checked { inner }
    }
}

/// A finished transaction: its id, fee and masses, and the requests that
/// submit it.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    inner: host::Finalized,
}

#[wasm_bindgen]
impl Finalized {
    /// The transaction id, hex, as a node names it.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// The fee it pays, sompi.
    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> u64 {
        self.inner.fee
    }

    /// The storage mass it commits.
    #[wasm_bindgen(getter, js_name = storageMass)]
    pub fn storage_mass(&self) -> u64 {
        self.inner.storage_mass
    }

    /// Its compute mass as signed.
    #[wasm_bindgen(getter, js_name = computeMass)]
    pub fn compute_mass(&self) -> u64 {
        self.inner.compute_mass
    }

    /// The `submitTransaction` call's `params` for a wRPC JSON port. Send
    /// it as it is: parsing it in JavaScript would round the amounts.
    #[wasm_bindgen(getter, js_name = submitJson)]
    pub fn submit_json(&self) -> String {
        self.inner.submit_json.clone()
    }

    /// The same for kaspa-rest-server: the body of `POST /transactions`
    /// (api.kaspa.org or any instance), sent as it is.
    #[wasm_bindgen(getter, js_name = restJson)]
    pub fn rest_json(&self) -> String {
        self.inner.rest_json.clone()
    }

    /// The same in Borsh: the payload `Node.submitTransaction` sends.
    #[wasm_bindgen(getter, js_name = submitBorsh)]
    pub fn submit_borsh(&self) -> Vec<u8> {
        self.inner.submit_borsh.clone()
    }

    /// Each input's unlocking script, hex.
    #[wasm_bindgen(getter)]
    pub fn unlocks(&self) -> Vec<String> {
        self.inner.unlocks.clone()
    }
}

impl Finalized {
    pub(crate) const fn over(inner: host::Finalized) -> Finalized {
        Finalized { inner }
    }

    /// The host crate's transaction.
    pub const fn inner(&self) -> &host::Finalized {
        &self.inner
    }
}

/// Read `reply` against `request`: the same transaction, every signature
/// verified over it.
///
/// Throws `NotTheRequest`, `Unverified(...)`, `Reply(...)` for bytes that
/// are not a KSPT.
#[wasm_bindgen(js_name = readReply)]
pub fn read_reply(request: &[u8], reply: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    Ok(Checked::over(host::read_reply(
        request,
        reply,
        profile.inner(),
    )?))
}

/// Read `signed`, a signed transaction with no request: every signature
/// verified over its own transaction. [`crate::request::summary`] gives
/// what it pays.
///
/// Throws `Reply(...)` for bytes that are not a KSPT,
/// `Unverified(Nothing)` for none signed, `Unverified(...)`.
#[wasm_bindgen(js_name = readSignedReply)]
pub fn read_signed_reply(signed: &[u8], profile: &Profile) -> Result<Checked, Fault> {
    Ok(Checked::over(host::read_signed_reply(
        signed,
        profile.inner(),
    )?))
}

/// Merge `copies` of one signed transaction into one, each read as
/// [`read_signed_reply`] reads it; a signature at a position an earlier
/// copy fills is left out.
///
/// Throws `NotTheRequest` for a copy of another transaction; as
/// [`read_signed_reply`].
#[wasm_bindgen(js_name = mergeSignedReplies)]
pub fn merge_signed_replies(
    copies: Vec<js_sys::Uint8Array>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let held: Vec<Vec<u8>> = copies.iter().map(|r| r.to_vec()).collect();
    let refs: Vec<&[u8]> = held.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_signed_replies(&refs, profile.inner())?)
}

/// Finish `signed`, a complete signed transaction, with no request: as
/// [`finalize_reply`].
///
/// Throws as [`read_signed_reply`]; then as [`finalize_reply`].
#[wasm_bindgen(js_name = finalizeSignedReply)]
pub fn finalize_signed_reply(
    signed: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(Finalized::over(host::finalize_signed_reply(
        signed,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?))
}

/// Merge `replies`, cosigners' answers to `request`, each read as
/// [`read_reply`] reads it, into one reply.
///
/// Throws as [`read_reply`]; `Merge(...)` for two signatures at one
/// position.
#[wasm_bindgen(js_name = mergeReplies)]
pub fn merge_replies(
    request: &[u8],
    replies: Vec<js_sys::Uint8Array>,
    profile: &Profile,
) -> Result<Vec<u8>, Fault> {
    let held: Vec<Vec<u8>> = replies.iter().map(|r| r.to_vec()).collect();
    let refs: Vec<&[u8]> = held.iter().map(|r| r.as_slice()).collect();
    Ok(host::merge_replies(request, &refs, profile.inner())?)
}

/// Finish `reply`, a complete reply to `request`: checked as by
/// [`read_reply`], unlocking scripts written, masses computed, the fee
/// checked against the minimum relay fee.
///
/// Throws `NotTheRequest`, `Unverified(...)` as [`read_reply`];
/// `Signatures { input, have, need }` for an input short of its threshold,
/// `FeeTooLow { fee, minimum }`, `Dust { output }`, `Redeem`,
/// `Unspendable`.
#[wasm_bindgen(js_name = finalizeReply)]
pub fn finalize_reply(
    request: &[u8],
    reply: &[u8],
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(Finalized::over(host::finalize_reply(
        request,
        reply,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?))
}

/// Finish `signed`, a wallet's signed WASM SDK safe JSON, against
/// `request`, the one it was handed (`RequestBuilder.buildSafeJson`): the
/// same transaction but for unlocking scripts, every input carrying one,
/// the id it states correct; masses computed, fee checked. A node verifies
/// the signatures on arrival.
///
/// Throws `RequestJson(...)`, `ReplyJson(...)`, `NotTheRequest`,
/// `Unsigned { input }`, `WrongId`, `Mass`, `FeeTooLow { fee, minimum }`,
/// `Dust { output }`.
#[wasm_bindgen(js_name = finalizeSafeJson)]
pub fn finalize_safe_json(
    request: &str,
    signed: &str,
    allow_orphan: bool,
    rates: &Rates,
    profile: &Profile,
) -> Result<Finalized, Fault> {
    Ok(Finalized::over(host::finalize_safe_json(
        request,
        signed,
        allow_orphan,
        rates.inner(),
        profile.inner(),
    )?))
}

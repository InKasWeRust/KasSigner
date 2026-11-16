// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A request built for the unit: [`kassigner_sdk_host::request`] over the
//! C ABI.

use std::sync::Mutex;

use kassigner_sdk_host::request as host;

use crate::card::Card;
use crate::watch::{Account, Group, Kcc3Address};
use crate::{lock, Fault, Profile, Rates};

/// A coin to spend. A bundle also needs its entry, `block_daa_score` and
/// `is_coinbase` (both or neither).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Coin {
    /// The transaction id, hex.
    pub tx_id: String,
    /// The output's index.
    pub index: u32,
    /// Sompi.
    pub amount: u64,
    /// The DAA score of the block that accepted it.
    #[uniffi(default = None)]
    pub block_daa_score: Option<u64>,
    /// Whether a coinbase made it.
    #[uniffi(default = None)]
    pub is_coinbase: Option<bool>,
    /// The covenant it is bound to, hex. A build refuses the coin,
    /// `CovenantBound { coin }`, unless an output continues its covenant
    /// ([`RequestBuilder::continue_covenant`]) or the request may end one
    /// ([`RequestBuilder::end_covenants`]).
    #[uniffi(default = None)]
    pub covenant_id: Option<String>,
}

impl Coin {
    fn host(&self) -> Result<host::Coin, Fault> {
        let coin = match (self.block_daa_score, self.is_coinbase) {
            (Some(daa), Some(coinbase)) => {
                host::Coin::with_entry(&self.tx_id, self.index, self.amount, daa, coinbase)?
            }
            (None, None) => host::Coin::new(&self.tx_id, self.index, self.amount)?,
            _ => {
                return Err(Fault::Sdk(
                    "a coin's entry is its DAA score and whether a coinbase made it".to_string(),
                ))
            }
        };
        Ok(match &self.covenant_id {
            Some(id) => coin.bound_to(id)?,
            None => coin,
        })
    }
}

/// Whether `coin` can be spent at DAA score `daa_score`: a coinbase's coin
/// from its block's score plus 1,000, any other at once; `None` without
/// its entry.
///
/// # Errors
///
/// An id or covenant id that is not 32 bytes of hex, or half an entry.
#[uniffi::export]
pub fn coin_spendable_at(coin: Coin, daa_score: u64) -> Result<Option<bool>, Fault> {
    Ok(coin.host()?.spendable_at(daa_score))
}

/// Gathers a request's coins, outputs and change, then builds it.
#[derive(Debug, Default, uniffi::Object)]
pub struct RequestBuilder {
    inner: Mutex<host::RequestBuilder>,
}

#[uniffi::export]
impl RequestBuilder {
    /// An empty request.
    #[uniffi::constructor]
    pub fn new() -> RequestBuilder {
        RequestBuilder::default()
    }

    /// Spend `coin`, of a `44'` account's `chain`/`index`.
    ///
    /// # Errors
    ///
    /// An id or covenant id that is not 32 bytes of hex, or half an entry.
    pub fn spend_account(
        &self,
        account: &Account,
        chain: u32,
        index: u32,
        coin: Coin,
    ) -> Result<(), Fault> {
        lock(&self.inner).spend_account(account.inner(), chain, index, &coin.host()?);
        Ok(())
    }

    /// Spend `coin`, of a `45'` group's `cosigner`/`chain`/`index`.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::spend_account`].
    pub fn spend_group(
        &self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        coin: Coin,
    ) -> Result<(), Fault> {
        lock(&self.inner).spend_group(group.inner(), cosigner, chain, index, &coin.host()?);
        Ok(())
    }

    /// Spend `coin`, of a `22'` address, with its `chain`/`index` under the
    /// `22'` account if known.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::spend_account`]; one of `chain` and `index`
    /// without the other.
    pub fn spend_kcc3(
        &self,
        address: &Kcc3Address,
        coin: Coin,
        chain: Option<u32>,
        index: Option<u32>,
    ) -> Result<(), Fault> {
        Ok(lock(&self.inner).spend_kcc3(address.inner(), &coin.host()?, chain, index)?)
    }

    /// Spend `coin`, a UTXO of `card`; the unit finds the key that signs.
    /// A build refuses a lock time before the card's, `CardLocked { coin }`;
    /// the safe JSON cannot carry the coin, `CardInSafeJson { coin }`.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::spend_account`].
    pub fn spend_card(&self, card: &Card, coin: Coin) -> Result<(), Fault> {
        Ok(lock(&self.inner).spend_card(card.inner(), &coin.host()?, None, None)?)
    }

    /// As [`RequestBuilder::spend_card`], signed by `account`'s receive
    /// `index` (`Card::signer` finds it). A build refuses a key that is not
    /// the card's, `NotTheCardsKey { coin }`.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::spend_account`].
    pub fn spend_card_as(
        &self,
        card: &Card,
        coin: Coin,
        account: &Account,
        index: u32,
    ) -> Result<(), Fault> {
        Ok(lock(&self.inner).spend_card(
            card.inner(),
            &coin.host()?,
            Some(account.inner()),
            Some(index),
        )?)
    }

    /// Pay `amount` sompi to `address`.
    ///
    /// # Errors
    ///
    /// Text that is not an address, an address not on mainnet, or an ECDSA
    /// key's.
    pub fn pay(&self, address: String, amount: u64) -> Result<(), Fault> {
        Ok(lock(&self.inner).pay(&address, amount)?)
    }

    /// Pay `amount` sompi to a locking script.
    pub fn pay_script(&self, script: Vec<u8>, amount: u64) {
        lock(&self.inner).pay_script(&script, amount);
    }

    /// Pay `amount` sompi to a `44'` account's own receive `index`, which
    /// the unit checks and shows as YOURS.
    ///
    /// # Errors
    ///
    /// A hardened index.
    pub fn pay_account(&self, account: &Account, index: u32, amount: u64) -> Result<(), Fault> {
        Ok(lock(&self.inner).pay_account(account.inner(), index, amount)?)
    }

    /// Let the request end a covenant: spend a coin bound to one with no
    /// output continuing it, so what the coin held leaves as plain KAS.
    /// Without it a build refuses such a coin, `CovenantBound { coin }`.
    /// The unit shows the covenant ending, `No output continues it`.
    pub fn end_covenants(&self) {
        lock(&self.inner).end_covenants();
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to the covenant coin `coin` is bound to, by its place among the
    /// coins: the output continues that covenant, under the coin's id, and
    /// the coin's input authorizes it. The transaction is then version 1,
    /// which a bundle cannot carry (`CovenantInBundle`).
    ///
    /// # Errors
    ///
    /// `BadBinding { output }` for an output not paid yet. A build gives it
    /// for a coin the request does not spend, or one bound to no covenant.
    pub fn continue_covenant(&self, output: u32, coin: u32) -> Result<(), Fault> {
        Ok(lock(&self.inner).continue_covenant(output, coin)?)
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to a new covenant that coin `coin`'s input authorizes, by its place
    /// among the coins. Every output started from the same coin is of that
    /// one covenant; [`summary`] reads its id from the built request. The
    /// transaction is then version 1, which a bundle cannot carry
    /// (`CovenantInBundle`).
    ///
    /// # Errors
    ///
    /// `BadBinding { output }` for an output not paid yet. A build gives it
    /// for a coin the request does not spend.
    pub fn start_covenant(&self, output: u32, coin: u32) -> Result<(), Fault> {
        Ok(lock(&self.inner).start_covenant(output, coin)?)
    }

    /// Send the change to a `44'` account's `chain`/`index`.
    pub fn change_to_account(&self, account: &Account, chain: u32, index: u32) {
        lock(&self.inner).change_to_account(account.inner(), chain, index);
    }

    /// Send the change to a `45'` group's `cosigner`/`chain`/`index`, which
    /// the unit shows as CHANGE.
    pub fn change_to_group(&self, group: &Group, cosigner: u32, chain: u32, index: u32) {
        lock(&self.inner).change_to_group(group.inner(), cosigner, chain, index);
    }

    /// Send everything the coins hold, less the fee, to `address`, instead
    /// of `pay` and a change.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::pay`].
    pub fn sweep_to(&self, address: String) -> Result<(), Fault> {
        Ok(lock(&self.inner).sweep_to(&address)?)
    }

    /// As [`RequestBuilder::sweep_to`], to a `44'` account's own
    /// `chain`/`index`, which the unit checks and shows as YOURS or CHANGE.
    ///
    /// # Errors
    ///
    /// A hardened index.
    pub fn sweep_to_account(&self, account: &Account, chain: u32, index: u32) -> Result<(), Fault> {
        Ok(lock(&self.inner).sweep_to_account(account.inner(), chain, index)?)
    }

    /// As [`RequestBuilder::sweep_to`], to a `45'` group's own
    /// `cosigner`/`chain`/`index`, which the unit checks and shows as
    /// CHANGE.
    ///
    /// # Errors
    ///
    /// A place the group has no address at.
    pub fn sweep_to_group(
        &self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
    ) -> Result<(), Fault> {
        Ok(lock(&self.inner).sweep_to_group(group.inner(), cosigner, chain, index)?)
    }

    /// The network's DAA score now (a node's `virtual_daa_score`): builds
    /// then refuse a coinbase's coin not yet mature,
    /// `ImmatureCoinbase { coin }`. A coin without its entry is not checked.
    pub fn at_daa_score(&self, daa_score: u64) {
        lock(&self.inner).at_daa_score(daa_score);
    }

    /// The lock time: a DAA score below 500,000,000,000 (rusty-kaspa's
    /// threshold), Unix time in milliseconds at or above it, zero (the
    /// default) for none. No block takes the transaction before it.
    pub fn lock_until(&self, lock_time: u64) {
        lock(&self.inner).lock_until(lock_time);
    }

    /// Build the request, a KSPT, at `fee_rate` sompi a gram (never under
    /// the minimum relay fee), over `rates` and within `profile`.
    ///
    /// # Errors
    ///
    /// `ImmatureCoinbase { coin }` ([`RequestBuilder::at_daa_score`]),
    /// then the SDK's `RequestError`: `Empty`, `TooMany`,
    /// `CovenantBound { coin }`, `BadBinding { output }`,
    /// `Insufficient { have, need }`,
    /// `Dust { output }`, `TooLong { len, limit }`...
    pub fn build(&self, fee_rate: u64, rates: &Rates, profile: &Profile) -> Result<Request, Fault> {
        Ok(lock(&self.inner)
            .build(fee_rate, rates.inner(), profile.inner())?
            .into())
    }

    /// As [`RequestBuilder::build`], as a rusty-kaspa bundle (PSKB) with
    /// every coin's entry, shown to the unit as format `pskb`.
    ///
    /// # Errors
    ///
    /// `NoEntry { coin }` for a coin without its entry; otherwise as
    /// [`RequestBuilder::build`], but never `Kspt(...)` or `TooLong`.
    pub fn build_bundle(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        Ok(lock(&self.inner)
            .build_bundle(fee_rate, rates.inner(), profile.inner())?
            .into())
    }

    /// As [`RequestBuilder::build`], unsigned in the safe JSON of
    /// rusty-kaspa's WASM SDK (`serializeToSafeJSON`) with every coin's
    /// entry and the storage mass, for a wallet to sign.
    ///
    /// # Errors
    ///
    /// As [`RequestBuilder::build_bundle`].
    pub fn build_safe_json(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        Ok(lock(&self.inner)
            .build_safe_json(fee_rate, rates.inner(), profile.inner())?
            .into())
    }
}

/// What a build made.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Request {
    /// The KSPT, the bundle's envelope, or the safe JSON; the reply is read
    /// against it.
    pub bytes: Vec<u8>,
    /// The fee the transaction pays, sompi.
    pub fee: u64,
    /// The mass the fee was computed over, grams.
    pub mass: u64,
    /// The change output's value, when there is one.
    pub change: Option<u64>,
    /// Signatures the reply needs in all.
    pub signatures: u32,
}

impl From<host::Request> for Request {
    fn from(r: host::Request) -> Self {
        Request {
            bytes: r.bytes,
            fee: r.fee,
            mass: r.mass,
            change: r.change,
            signatures: r.signatures,
        }
    }
}

/// One output, as [`summary`] reads it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OutputSummary {
    /// The mainnet address it pays; none for a script with no address.
    pub address: Option<String>,
    /// The locking script.
    pub script: Vec<u8>,
    /// Sompi.
    pub value: u64,
    /// The covenant it is bound to, hex: a continued covenant's, or the
    /// new one's the output starts; none for an output not bound.
    pub covenant_id: Option<String>,
    /// The input that authorizes the binding, by its place.
    pub authorizing_input: Option<u32>,
}

/// What a request or a reply carries.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Summary {
    /// Inputs.
    pub inputs: u32,
    /// Each input's outpoint, `txId:index`.
    pub outpoints: Vec<String>,
    /// Sompi the inputs hold.
    pub total_in: u64,
    /// The outputs.
    pub outputs: Vec<OutputSummary>,
    /// Sompi the outputs pay.
    pub total_out: u64,
    /// The fee: in less out.
    pub fee: u64,
    /// Signatures carried: none on a request.
    pub signatures: u32,
    /// The lock time, zero for none.
    pub lock_time: u64,
    /// The transaction's version: 1 with an output bound to a covenant.
    pub version: u32,
}

impl From<host::Summary> for Summary {
    fn from(s: host::Summary) -> Self {
        Summary {
            fee: s.fee(),
            inputs: s.inputs,
            outpoints: s.outpoints,
            total_in: s.total_in,
            outputs: s
                .outputs
                .into_iter()
                .map(|o| OutputSummary {
                    address: o.address,
                    script: o.script,
                    value: o.value,
                    covenant_id: o.covenant_id,
                    authorizing_input: o.authorizing_input,
                })
                .collect(),
            total_out: s.total_out,
            signatures: s.signatures,
            lock_time: s.lock_time,
            version: s.version,
        }
    }
}

/// Read `kspt`, a request or a reply, without verifying it.
///
/// # Errors
///
/// Bytes that are not a KSPT within `profile`.
#[uniffi::export]
pub fn summary(kspt: Vec<u8>, profile: &Profile) -> Result<Summary, Fault> {
    Ok(host::summary(&kspt, profile.inner())?.into())
}

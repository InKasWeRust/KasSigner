// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A request built for the unit: [`kassigner_sdk_host::request`] for
//! JavaScript.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::request as host;

use crate::card::Card;
use crate::coin::Coin;
use crate::watch::{Account, Group, Kcc3Address};
use crate::{Fault, Profile, Rates};

/// Gathers a request's coins, outputs and change, then builds it.
#[wasm_bindgen]
#[derive(Clone, Debug, Default)]
pub struct RequestBuilder {
    inner: host::RequestBuilder,
}

#[wasm_bindgen]
impl RequestBuilder {
    /// An empty request.
    #[wasm_bindgen(constructor)]
    pub fn new() -> RequestBuilder {
        RequestBuilder::default()
    }

    /// Spend `coin`, of a `44'` account's `chain`/`index`.
    #[wasm_bindgen(js_name = spendAccount)]
    pub fn spend_account(&mut self, account: &Account, chain: u32, index: u32, coin: &Coin) {
        self.inner
            .spend_account(account.inner(), chain, index, coin.inner());
    }

    /// Spend `coin`, of a `45'` group's `cosigner`/`chain`/`index`.
    #[wasm_bindgen(js_name = spendGroup)]
    pub fn spend_group(
        &mut self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
        coin: &Coin,
    ) {
        self.inner
            .spend_group(group.inner(), cosigner, chain, index, coin.inner());
    }

    /// Spend `coin`, of a `22'` address, with its `chain`/`index` below the
    /// `22'` account when the app knows it (both or neither).
    #[wasm_bindgen(js_name = spendKcc3)]
    pub fn spend_kcc3(
        &mut self,
        address: &Kcc3Address,
        coin: &Coin,
        chain: Option<u32>,
        index: Option<u32>,
    ) -> Result<(), Fault> {
        Ok(self
            .inner
            .spend_kcc3(address.inner(), coin.inner(), chain, index)?)
    }

    /// Spend `coin`, a UTXO of `card`, leaving the unit to find its key. A
    /// build throws `CardLocked { coin }` under a lock time before the
    /// card's; `buildSafeJson` throws `CardInSafeJson { coin }`.
    #[wasm_bindgen(js_name = spendCard)]
    pub fn spend_card(&mut self, card: &Card, coin: &Coin) -> Result<(), Fault> {
        Ok(self
            .inner
            .spend_card(card.inner(), coin.inner(), None, None)?)
    }

    /// As `spendCard`, signed by `account`'s receive `index`
    /// (`Card.signer`); a build throws `NotTheCardsKey { coin }` if that is
    /// neither of the card's keys.
    #[wasm_bindgen(js_name = spendCardAs)]
    pub fn spend_card_as(
        &mut self,
        card: &Card,
        coin: &Coin,
        account: &Account,
        index: u32,
    ) -> Result<(), Fault> {
        Ok(self.inner.spend_card(
            card.inner(),
            coin.inner(),
            Some(account.inner()),
            Some(index),
        )?)
    }

    /// Pay `amount` sompi to `address`, a mainnet address.
    pub fn pay(&mut self, address: &str, amount: u64) -> Result<(), Fault> {
        Ok(self.inner.pay(address, amount)?)
    }

    /// Pay `amount` sompi to a locking script.
    #[wasm_bindgen(js_name = payScript)]
    pub fn pay_script(&mut self, script: &[u8], amount: u64) {
        self.inner.pay_script(script, amount);
    }

    /// Pay `amount` sompi to a `44'` account's own receive address
    /// `index`, which the unit checks and shows as YOURS, `Receive #index`.
    ///
    /// Throws for an index the receive chain has no address at.
    #[wasm_bindgen(js_name = payAccount)]
    pub fn pay_account(&mut self, account: &Account, index: u32, amount: u64) -> Result<(), Fault> {
        Ok(self.inner.pay_account(account.inner(), index, amount)?)
    }

    /// Let the request end a covenant: spend a coin bound to one
    /// (`Coin.boundTo`) with no output continuing it, so what the coin held
    /// leaves as plain KAS. Without it a build throws
    /// `CovenantBound { coin }` for such a coin. The unit shows the
    /// covenant ending, `No output continues it`.
    #[wasm_bindgen(js_name = endCovenants)]
    pub fn end_covenants(&mut self) {
        self.inner.end_covenants();
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to the covenant coin `coin` is bound to, by its place among the
    /// coins: the output continues that covenant, under the coin's id, and
    /// the coin's input authorizes it. The transaction is then version 1,
    /// which `buildBundle` cannot carry (`CovenantInBundle`).
    ///
    /// Throws `BadBinding { output }` for an output not paid yet; a build
    /// throws it for a coin the request does not spend, or one bound to no
    /// covenant.
    #[wasm_bindgen(js_name = continueCovenant)]
    pub fn continue_covenant(&mut self, output: u32, coin: u32) -> Result<(), Fault> {
        Ok(self.inner.continue_covenant(output, coin)?)
    }

    /// Bind output `output`, by its place among the outputs paid so far,
    /// to a new covenant that coin `coin`'s input authorizes, by its place
    /// among the coins. Every output started from the same coin is of that
    /// one covenant; `summary` reads its id from the built request
    /// (`OutputSummary.covenantId`). The transaction is then version 1,
    /// which `buildBundle` cannot carry (`CovenantInBundle`).
    ///
    /// Throws `BadBinding { output }` for an output not paid yet; a build
    /// throws it for a coin the request does not spend.
    #[wasm_bindgen(js_name = startCovenant)]
    pub fn start_covenant(&mut self, output: u32, coin: u32) -> Result<(), Fault> {
        Ok(self.inner.start_covenant(output, coin)?)
    }

    /// Send the change to a `44'` account's `chain`/`index`.
    #[wasm_bindgen(js_name = changeToAccount)]
    pub fn change_to_account(&mut self, account: &Account, chain: u32, index: u32) {
        self.inner.change_to_account(account.inner(), chain, index);
    }

    /// Send the change to a `45'` group's `cosigner`/`chain`/`index`,
    /// marked for the unit to show as CHANGE.
    #[wasm_bindgen(js_name = changeToGroup)]
    pub fn change_to_group(&mut self, group: &Group, cosigner: u32, chain: u32, index: u32) {
        self.inner
            .change_to_group(group.inner(), cosigner, chain, index);
    }

    /// Everything the coins hold, less the fee, to `address`, a mainnet
    /// address: a `22'` spend, or emptying an account. Instead of `pay` and
    /// a change.
    #[wasm_bindgen(js_name = sweepTo)]
    pub fn sweep_to(&mut self, address: &str) -> Result<(), Fault> {
        Ok(self.inner.sweep_to(address)?)
    }

    /// As `sweepTo`, to a `44'` account's own `chain`/`index`, which the
    /// unit checks and shows as YOURS or CHANGE.
    ///
    /// Throws for a place the account has no address at.
    #[wasm_bindgen(js_name = sweepToAccount)]
    pub fn sweep_to_account(
        &mut self,
        account: &Account,
        chain: u32,
        index: u32,
    ) -> Result<(), Fault> {
        Ok(self.inner.sweep_to_account(account.inner(), chain, index)?)
    }

    /// As `sweepTo`, to a `45'` group's own `cosigner`/`chain`/`index`,
    /// which the unit checks and shows as CHANGE.
    ///
    /// Throws for a place the group has no address at.
    #[wasm_bindgen(js_name = sweepToGroup)]
    pub fn sweep_to_group(
        &mut self,
        group: &Group,
        cosigner: u32,
        chain: u32,
        index: u32,
    ) -> Result<(), Fault> {
        Ok(self
            .inner
            .sweep_to_group(group.inner(), cosigner, chain, index)?)
    }

    /// The network's DAA score now, `daa_score` (a node's
    /// `virtualDaaScore`): builds then throw `ImmatureCoinbase { coin }` for
    /// an immature coinbase coin with its entry.
    #[wasm_bindgen(js_name = atDaaScore)]
    pub fn at_daa_score(&mut self, daa_score: u64) {
        self.inner.at_daa_score(daa_score);
    }

    /// The lock time, `lock_time`: a DAA score below rusty-kaspa's
    /// threshold, 500,000,000,000, else milliseconds; zero, the default,
    /// for none. No block takes the transaction until it is past; the unit
    /// shows it on its LOCK TIME page.
    #[wasm_bindgen(js_name = lockUntil)]
    pub fn lock_until(&mut self, lock_time: u64) {
        self.inner.lock_until(lock_time);
    }

    /// Build the KSPT the unit reads, at `fee_rate` sompi a gram (never
    /// under the minimum relay fee), over `rates`, within `profile`.
    ///
    /// Throws `ImmatureCoinbase { coin }` first (`atDaaScore`), then as the
    /// SDK's `RequestError` says: `Empty`, `TooMany`,
    /// `Insufficient { have, need }`, `Dust { output }`, `SweepDust`,
    /// `Multisig(...)`, `TooLong { len, limit }`...
    pub fn build(&self, fee_rate: u64, rates: &Rates, profile: &Profile) -> Result<Request, Fault> {
        Ok(Request {
            inner: self.inner.build(fee_rate, rates.inner(), profile.inner())?,
        })
    }

    /// Build the request as rusty-kaspa's PSKB bundle, every coin with its
    /// entry (`Coin.withEntry`): shown to the unit as format `pskb`, its
    /// replies read with `readBundle`.
    ///
    /// Throws `NoEntry { coin }` for a coin without its entry, otherwise as
    /// `build` but never `Kspt(...)` or `TooLong`.
    #[wasm_bindgen(js_name = buildBundle)]
    pub fn build_bundle(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        Ok(Request {
            inner: self
                .inner
                .build_bundle(fee_rate, rates.inner(), profile.inner())?,
        })
    }

    /// Build the request, unsigned, as `Transaction.serializeToSafeJSON`
    /// writes it, for a wallet that signs that JSON; `text` is the JSON and
    /// `finalizeSafeJson` reads it back signed.
    ///
    /// Throws as `buildBundle`; `CardInSafeJson { coin }` for a card's UTXO.
    #[wasm_bindgen(js_name = buildSafeJson)]
    pub fn build_safe_json(
        &self,
        fee_rate: u64,
        rates: &Rates,
        profile: &Profile,
    ) -> Result<Request, Fault> {
        Ok(Request {
            inner: self
                .inner
                .build_safe_json(fee_rate, rates.inner(), profile.inner())?,
        })
    }
}

/// A built request: its bytes and what it pays.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    inner: host::Request,
}

#[wasm_bindgen]
impl Request {
    /// The KSPT, bundle envelope or safe JSON: what
    /// [`crate::transport::codes`] shows the unit or a wallet is handed,
    /// and what the reply is read against.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.bytes.clone()
    }

    /// The bytes as text: the bundle's envelope, or the safe JSON.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner.text()
    }

    /// The fee the transaction pays, sompi.
    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> u64 {
        self.inner.fee
    }

    /// The mass the fee was computed over, grams.
    #[wasm_bindgen(getter)]
    pub fn mass(&self) -> u64 {
        self.inner.mass
    }

    /// The change output's value, when there is one.
    #[wasm_bindgen(getter)]
    pub fn change(&self) -> Option<u64> {
        self.inner.change
    }

    /// Signatures the unit's reply must carry in all.
    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> u32 {
        self.inner.signatures
    }
}

/// One output of a request, as [`summary`] reads it.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSummary {
    inner: host::OutputSummary,
}

#[wasm_bindgen]
impl OutputSummary {
    /// The mainnet address the output pays; none for a script that pays
    /// no address.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.inner.address.clone()
    }

    /// The locking script.
    #[wasm_bindgen(getter)]
    pub fn script(&self) -> Vec<u8> {
        self.inner.script.clone()
    }

    /// Sompi.
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> u64 {
        self.inner.value
    }

    /// The covenant the output is bound to, hex: a continued covenant's,
    /// or the new one's the output starts; none for an output not bound.
    #[wasm_bindgen(getter, js_name = covenantId)]
    pub fn covenant_id(&self) -> Option<String> {
        self.inner.covenant_id.clone()
    }

    /// The input that authorizes the binding, by its place.
    #[wasm_bindgen(getter, js_name = authorizingInput)]
    pub fn authorizing_input(&self) -> Option<u32> {
        self.inner.authorizing_input
    }
}

/// What a request or a reply carries, read back.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub(crate) inner: host::Summary,
}

#[wasm_bindgen]
impl Summary {
    /// Inputs.
    #[wasm_bindgen(getter)]
    pub fn inputs(&self) -> u32 {
        self.inner.inputs
    }

    /// Each input's outpoint, `txId:index`.
    #[wasm_bindgen(getter)]
    pub fn outpoints(&self) -> Vec<String> {
        self.inner.outpoints.clone()
    }

    /// Sompi the inputs hold.
    #[wasm_bindgen(getter, js_name = totalIn)]
    pub fn total_in(&self) -> u64 {
        self.inner.total_in
    }

    /// The outputs.
    #[wasm_bindgen(getter)]
    pub fn outputs(&self) -> Vec<OutputSummary> {
        self.inner
            .outputs
            .iter()
            .cloned()
            .map(|inner| OutputSummary { inner })
            .collect()
    }

    /// Sompi the outputs pay.
    #[wasm_bindgen(getter, js_name = totalOut)]
    pub fn total_out(&self) -> u64 {
        self.inner.total_out
    }

    /// The fee: in less out.
    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> u64 {
        self.inner.fee()
    }

    /// Signatures the bytes carry: none on a request.
    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> u32 {
        self.inner.signatures
    }

    /// The lock time, zero for none: what the unit's LOCK TIME page shows.
    #[wasm_bindgen(getter, js_name = lockTime)]
    pub fn lock_time(&self) -> u64 {
        self.inner.lock_time
    }

    /// The transaction's version: 1 with an output bound to a covenant.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.inner.version
    }
}

/// What `kspt`, a request or a reply, carries. Nothing is verified;
/// [`crate::reply::read_reply`] does that.
///
/// Throws for bytes that do not parse as a KSPT within `profile`.
#[wasm_bindgen]
pub fn summary(kspt: &[u8], profile: &Profile) -> Result<Summary, Fault> {
    Ok(Summary {
        inner: host::summary(kspt, profile.inner())?,
    })
}

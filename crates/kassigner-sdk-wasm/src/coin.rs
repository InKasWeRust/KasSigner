// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A coin, as a node lists it and a request spends it:
//! [`kassigner_sdk_host::request::Coin`] for JavaScript.
//!
//! Apart from the request builder, so the watch-only package (built
//! without `transactions`) has it too: a wallet's view leaves a mining
//! reward out of its balance until `spendableAt` says it has matured.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::request as host;

use crate::Fault;

/// A coin to spend: its output and sompi, for a bundle its entry, and any
/// covenant it is bound to (`boundTo`).
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coin {
    inner: host::Coin,
}

#[wasm_bindgen]
impl Coin {
    /// The output `tx_id` (hex) : `index`, holding `amount` sompi.
    #[wasm_bindgen(constructor)]
    pub fn new(tx_id: &str, index: u32, amount: u64) -> Result<Coin, Fault> {
        Ok(Coin {
            inner: host::Coin::new(tx_id, index, amount)?,
        })
    }

    /// As `new Coin`, plus the DAA score of the block that accepted it and
    /// whether a coinbase made it, which a bundle carries.
    #[wasm_bindgen(js_name = withEntry)]
    pub fn with_entry(
        tx_id: &str,
        index: u32,
        amount: u64,
        block_daa_score: u64,
        is_coinbase: bool,
    ) -> Result<Coin, Fault> {
        Ok(Coin {
            inner: host::Coin::with_entry(tx_id, index, amount, block_daa_score, is_coinbase)?,
        })
    }

    /// The same coin, bound to the covenant `covenant_id` (hex), as
    /// `Utxo.coin()` binds it. A build throws `CovenantBound { coin }` for
    /// it unless an output continues its covenant (`continueCovenant`) or
    /// the request may end one (`endCovenants`).
    #[wasm_bindgen(js_name = boundTo)]
    pub fn bound_to(&self, covenant_id: &str) -> Result<Coin, Fault> {
        Ok(Coin {
            inner: self.inner.bound_to(covenant_id)?,
        })
    }

    /// The covenant it is bound to, hex, when it is.
    #[wasm_bindgen(getter, js_name = covenantId)]
    pub fn covenant_id(&self) -> Option<String> {
        self.inner.covenant_id()
    }

    /// The transaction id, hex.
    #[wasm_bindgen(getter, js_name = txId)]
    pub fn tx_id(&self) -> String {
        self.inner.tx_id()
    }

    /// The DAA score of the block that accepted it, when given.
    #[wasm_bindgen(getter, js_name = blockDaaScore)]
    pub fn block_daa_score(&self) -> Option<u64> {
        self.inner.block_daa_score()
    }

    /// Whether a coinbase made it, when given.
    #[wasm_bindgen(getter, js_name = isCoinbase)]
    pub fn is_coinbase(&self) -> Option<bool> {
        self.inner.is_coinbase()
    }

    /// Whether it can be spent at the network's DAA score `daa_score` (a
    /// node's `virtualDaaScore`): a coinbase's coin once `daa_score` is
    /// 1,000 past its block's (rusty-kaspa's rule on mainnet), any other at
    /// once; `undefined` without its entry.
    #[wasm_bindgen(js_name = spendableAt)]
    pub fn spendable_at(&self, daa_score: u64) -> Option<bool> {
        self.inner.spendable_at(daa_score)
    }

    /// The output's index.
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.inner.index()
    }

    /// Sompi.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> u64 {
        self.inner.amount()
    }
}

impl Coin {
    pub(crate) const fn over(inner: host::Coin) -> Coin {
        Coin { inner }
    }

    /// The host crate's coin.
    #[cfg(feature = "transactions")]
    pub(crate) const fn inner(&self) -> &host::Coin {
        &self.inner
    }
}

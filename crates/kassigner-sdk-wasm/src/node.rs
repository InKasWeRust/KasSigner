// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC: [`kassigner_sdk_host::node`] for JavaScript.
//!
//! The page opens the WebSocket; the SDK writes and reads its messages:
//!
//! ```js
//! const node = new Node("borsh");                    // the port's encoding
//! const ws = new WebSocket("wss://…");
//! ws.binaryType = "arraybuffer";                     // Borsh arrives as bytes
//! ws.onmessage = (e) => {
//!   const a = node.read(e.data);                     // an Answer, by its id
//!   if (a.error) …; else if (a.utxos) …;
//! };
//! ws.send(node.getUtxosByAddresses(1, addresses));
//! ws.send(node.getFeeEstimate(2));
//! ws.send(node.submitTransaction(3, finalized));     // once the unit signed
//! ```
//!
//! A request is a `Uint8Array` for Borsh, a string for JSON; `read` takes
//! either, or an `ArrayBuffer`.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::node as host;

use crate::coin::Coin;
#[cfg(feature = "transactions")]
use crate::reply::Finalized;
use crate::Fault;

/// Sending: with `transactions` only, so the watch-only package cannot.
#[cfg(feature = "transactions")]
#[wasm_bindgen]
impl Node {
    /// Request `id`, `submitTransaction` of `finalized`.
    #[wasm_bindgen(js_name = submitTransaction, unchecked_return_type = "Uint8Array | string")]
    pub fn submit_transaction(&self, id: u32, finalized: &Finalized) -> Result<JsValue, Fault> {
        Ok(self.outgoing(self.inner.submit_transaction(id, finalized.inner())?))
    }
}

/// A node's wRPC port, by the encoding it speaks.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    inner: host::Node,
}

#[wasm_bindgen]
impl Node {
    /// For a port speaking `encoding`: `"borsh"` or `"json"`.
    #[wasm_bindgen(constructor)]
    pub fn new(encoding: &str) -> Result<Node, Fault> {
        Ok(Node {
            inner: host::Node::new(encoding)?,
        })
    }

    /// `"borsh"` or `"json"`.
    #[wasm_bindgen(getter)]
    pub fn encoding(&self) -> String {
        self.inner.encoding()
    }

    /// A mainnet node's default port for this encoding: 17110 for Borsh,
    /// 18110 for JSON.
    #[wasm_bindgen(js_name = defaultPort)]
    pub fn default_port(&self) -> u16 {
        self.inner.default_port()
    }

    /// Request `id`, `getServerInfo`: the node's network, sync state, UTXO
    /// index and version.
    #[wasm_bindgen(js_name = getServerInfo, unchecked_return_type = "Uint8Array | string")]
    pub fn get_server_info(&self, id: u32) -> Result<JsValue, Fault> {
        Ok(self.outgoing(self.inner.get_server_info(id)?))
    }

    /// Request `id`, `getFeeEstimate`: fee rates and how fast each
    /// confirms.
    #[wasm_bindgen(js_name = getFeeEstimate, unchecked_return_type = "Uint8Array | string")]
    pub fn get_fee_estimate(&self, id: u32) -> Result<JsValue, Fault> {
        Ok(self.outgoing(self.inner.get_fee_estimate(id)?))
    }

    /// Request `id`, `getUtxosByAddresses`: every coin `addresses` hold
    /// (the node needs `--utxoindex`).
    ///
    /// Throws `Address { index, error }` for an address that does not
    /// decode.
    #[wasm_bindgen(js_name = getUtxosByAddresses, unchecked_return_type = "Uint8Array | string")]
    pub fn get_utxos_by_addresses(
        &self,
        id: u32,
        addresses: Vec<String>,
    ) -> Result<JsValue, Fault> {
        Ok(self.outgoing(self.inner.get_utxos_by_addresses(id, &addresses)?))
    }

    /// Read `message` from the node: a string, an `ArrayBuffer` or a
    /// `Uint8Array`.
    ///
    /// Throws `Malformed { at }` at the first wrong byte of a message no
    /// node writes; `Id(n)` for an id past a `u32`.
    pub fn read(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string | ArrayBuffer | Uint8Array")]
        message: &JsValue,
    ) -> Result<Answer, Fault> {
        let bytes = match message.as_string() {
            Some(text) => text.into_bytes(),
            None => js_sys::Uint8Array::new(message).to_vec(),
        };
        self.read_bytes(&bytes)
    }
}

impl Node {
    /// What [`Node::read`] reads, from bytes.
    pub fn read_bytes(&self, message: &[u8]) -> Result<Answer, Fault> {
        Ok(Answer {
            inner: self.inner.read(message)?,
        })
    }

    /// The host crate's node.
    pub const fn inner(&self) -> &host::Node {
        &self.inner
    }

    /// A request as `WebSocket.send` takes it: text for JSON, bytes for
    /// Borsh.
    fn outgoing(&self, bytes: Vec<u8>) -> JsValue {
        if self.inner.is_text() {
            JsValue::from_str(&String::from_utf8_lossy(&bytes))
        } else {
            js_sys::Uint8Array::from(&bytes[..]).into()
        }
    }
}

/// A node's message, read.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    inner: host::Answer,
}

#[wasm_bindgen]
impl Answer {
    /// The id of the request it answers; none on a notification.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Option<u32> {
        self.inner.id
    }

    /// `"reply"`, `"error"` or `"notification"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind.clone()
    }

    /// The call it answers (`"getUtxosByAddresses"` and the like), if the
    /// node names one the SDK makes; a Borsh node names none on
    /// `RPC method not found`.
    #[wasm_bindgen(getter)]
    pub fn call(&self) -> Option<String> {
        self.inner.call.clone()
    }

    /// On an error, the node's words: a refused transaction says why.
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.inner.error.clone()
    }

    /// On a `getServerInfo` reply.
    #[wasm_bindgen(getter, js_name = serverInfo)]
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.inner
            .server_info
            .clone()
            .map(|inner| ServerInfo { inner })
    }

    /// On a `getFeeEstimate` reply.
    #[wasm_bindgen(getter, js_name = feeEstimate)]
    pub fn fee_estimate(&self) -> Option<FeeEstimate> {
        self.inner
            .fee_estimate
            .clone()
            .map(|inner| FeeEstimate { inner })
    }

    /// On a `getUtxosByAddresses` reply, every coin, in the node's order.
    #[wasm_bindgen(getter)]
    pub fn utxos(&self) -> Option<Vec<Utxo>> {
        self.inner
            .utxos
            .clone()
            .map(|u| u.into_iter().map(|inner| Utxo { inner }).collect())
    }

    /// On a `submitTransaction` reply, the accepted transaction's id, hex.
    #[wasm_bindgen(getter, js_name = transactionId)]
    pub fn transaction_id(&self) -> Option<String> {
        self.inner.transaction_id.clone()
    }
}

/// The node's state.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    inner: host::ServerInfo,
}

#[wasm_bindgen]
impl ServerInfo {
    /// 1 on every known node; by upstream's rule a client refuses a node
    /// reporting another.
    #[wasm_bindgen(getter, js_name = rpcApiVersion)]
    pub fn rpc_api_version(&self) -> u16 {
        self.inner.rpc_api_version
    }

    #[wasm_bindgen(getter, js_name = rpcApiRevision)]
    pub fn rpc_api_revision(&self) -> u16 {
        self.inner.rpc_api_revision
    }

    /// The node's version, `2.1.0` and the like.
    #[wasm_bindgen(getter, js_name = serverVersion)]
    pub fn server_version(&self) -> String {
        self.inner.server_version.clone()
    }

    /// Its network, `mainnet`, `testnet-10` and the like. KasSigner is
    /// mainnet only: an app refuses any other.
    #[wasm_bindgen(getter)]
    pub fn network(&self) -> String {
        self.inner.network.clone()
    }

    /// Whether it keeps the UTXO index `getUtxosByAddresses` needs.
    #[wasm_bindgen(getter, js_name = hasUtxoIndex)]
    pub fn has_utxo_index(&self) -> bool {
        self.inner.has_utxo_index
    }

    /// Whether it has caught up with the network; until then the coins it
    /// lists may be stale.
    #[wasm_bindgen(getter, js_name = isSynced)]
    pub fn is_synced(&self) -> bool {
        self.inner.is_synced
    }

    #[wasm_bindgen(getter, js_name = virtualDaaScore)]
    pub fn virtual_daa_score(&self) -> u64 {
        self.inner.virtual_daa_score
    }
}

/// A fee rate the node expects to see confirmed within some seconds.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bucket {
    inner: host::Bucket,
}

#[wasm_bindgen]
impl Bucket {
    /// Sompi a gram of mass, as the node estimates it.
    #[wasm_bindgen(getter)]
    pub fn feerate(&self) -> f64 {
        self.inner.feerate
    }

    #[wasm_bindgen(getter, js_name = estimatedSeconds)]
    pub fn estimated_seconds(&self) -> f64 {
        self.inner.estimated_seconds
    }

    /// The rate as `RequestBuilder.build` takes it: whole sompi a gram,
    /// rounded up, at least 1. The minimum relay fee still applies.
    #[wasm_bindgen(getter, js_name = feeRate)]
    pub fn fee_rate(&self) -> u64 {
        self.inner.fee_rate
    }
}

/// The node's fee estimate, fastest first.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct FeeEstimate {
    inner: host::FeeEstimate,
}

#[wasm_bindgen]
impl FeeEstimate {
    #[wasm_bindgen(getter)]
    pub fn priority(&self) -> Bucket {
        Bucket {
            inner: self.inner.priority,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn normal(&self) -> Vec<Bucket> {
        self.inner
            .normal
            .iter()
            .map(|&inner| Bucket { inner })
            .collect()
    }

    #[wasm_bindgen(getter)]
    pub fn low(&self) -> Vec<Bucket> {
        self.inner
            .low
            .iter()
            .map(|&inner| Bucket { inner })
            .collect()
    }
}

/// A coin an address holds.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    inner: host::Utxo,
}

#[wasm_bindgen]
impl Utxo {
    /// The address asked about that holds it; a node may leave it out.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.inner.address.clone()
    }

    /// Its transaction's id, hex.
    #[wasm_bindgen(getter, js_name = transactionId)]
    pub fn transaction_id(&self) -> String {
        self.inner.transaction_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.inner.index
    }

    /// Sompi.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> u64 {
        self.inner.amount
    }

    #[wasm_bindgen(getter, js_name = scriptVersion)]
    pub fn script_version(&self) -> u16 {
        self.inner.script_version
    }

    /// The locking script.
    #[wasm_bindgen(getter)]
    pub fn script(&self) -> Vec<u8> {
        self.inner.script.clone()
    }

    /// When it was accepted, in DAA score.
    #[wasm_bindgen(getter, js_name = blockDaaScore)]
    pub fn block_daa_score(&self) -> u64 {
        self.inner.block_daa_score
    }

    /// A block reward, which matures before it can be spent.
    #[wasm_bindgen(getter, js_name = isCoinbase)]
    pub fn is_coinbase(&self) -> bool {
        self.inner.is_coinbase
    }

    /// The covenant it is bound to, hex; the SDK's requests bind none.
    #[wasm_bindgen(getter, js_name = covenantId)]
    pub fn covenant_id(&self) -> Option<String> {
        self.inner.covenant_id.clone()
    }

    /// This UTXO as a `Coin`, with its entry and any covenant it is bound
    /// to.
    pub fn coin(&self) -> Result<Coin, Fault> {
        Ok(Coin::over(self.inner.coin()?))
    }
}

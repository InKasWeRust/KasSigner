// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC: [`kassigner_sdk_host::node`] over the C ABI. The app
//! opens a WebSocket to a node's wRPC port; a [`Node`] for its encoding
//! writes each request and reads each message back.

use kassigner_sdk_host::node as host;

use crate::reply::Finalized;
use crate::request::Coin;
use crate::Fault;

/// A node's wRPC port, by the encoding it speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Node {
    inner: host::Node,
}

#[uniffi::export]
impl Node {
    /// For a port speaking `encoding`: `borsh` or `json`.
    ///
    /// # Errors
    ///
    /// Any other name.
    #[uniffi::constructor]
    pub fn new(encoding: String) -> Result<Node, Fault> {
        Ok(Node {
            inner: host::Node::new(&encoding)?,
        })
    }

    /// `borsh` or `json`.
    pub fn encoding(&self) -> String {
        self.inner.encoding()
    }

    /// Whether its messages are text frames (JSON), not binary (Borsh).
    pub fn is_text(&self) -> bool {
        self.inner.is_text()
    }

    /// A mainnet node's default port for it: 17110 Borsh, 18110 JSON.
    pub fn default_port(&self) -> u16 {
        self.inner.default_port()
    }

    /// Request `id`, `getServerInfo`.
    ///
    /// # Errors
    ///
    /// None in practice: only the id varies.
    pub fn get_server_info(&self, id: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.get_server_info(id)?)
    }

    /// Request `id`, `getFeeEstimate`.
    ///
    /// # Errors
    ///
    /// As [`Node::get_server_info`].
    pub fn get_fee_estimate(&self, id: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.get_fee_estimate(id)?)
    }

    /// Request `id`, `getUtxosByAddresses`: the coins `addresses` hold,
    /// from a node run with `--utxoindex`.
    ///
    /// # Errors
    ///
    /// `Address { index, error }` for an address that does not decode.
    pub fn get_utxos_by_addresses(
        &self,
        id: u32,
        addresses: Vec<String>,
    ) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.get_utxos_by_addresses(id, &addresses)?)
    }

    /// Request `id`, `submitTransaction`, for `finalized`.
    ///
    /// # Errors
    ///
    /// As [`Node::get_server_info`].
    pub fn submit_transaction(&self, id: u32, finalized: Finalized) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.submit_transaction(id, &finalized.into())?)
    }

    /// Read a `message` from the node.
    ///
    /// # Errors
    ///
    /// `Malformed { at }` for a message no node writes, at its first wrong
    /// byte; `Id(n)` for an id past a `u32`.
    pub fn read(&self, message: Vec<u8>) -> Result<Answer, Fault> {
        Ok(self.inner.read(&message)?.into())
    }
}

/// A node's message, read.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct Answer {
    /// The id of the request it answers; none on a notification.
    pub id: Option<u32>,
    /// `reply`, `error` or `notification`.
    pub kind: String,
    /// The call it answers (`getUtxosByAddresses`...) when the node names
    /// it; a Borsh node names none for a method it lacks, so match the id.
    pub call: Option<String>,
    /// On an error, the node's words, such as why it refused a transaction.
    pub error: Option<String>,
    /// On a `getServerInfo` reply.
    pub server_info: Option<ServerInfo>,
    /// On a `getFeeEstimate` reply.
    pub fee_estimate: Option<FeeEstimate>,
    /// On a `getUtxosByAddresses` reply, every coin, in the node's order.
    pub utxos: Option<Vec<Utxo>>,
    /// On a `submitTransaction` reply, the accepted transaction's id, hex.
    pub transaction_id: Option<String>,
}

impl From<host::Answer> for Answer {
    fn from(a: host::Answer) -> Self {
        Answer {
            id: a.id,
            kind: a.kind,
            call: a.call,
            error: a.error,
            server_info: a.server_info.map(Into::into),
            fee_estimate: a.fee_estimate.map(Into::into),
            utxos: a.utxos.map(|u| u.into_iter().map(Into::into).collect()),
            transaction_id: a.transaction_id,
        }
    }
}

/// The node's state.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ServerInfo {
    /// 1 on every node this SDK knows; a client refuses a node reporting
    /// another (rusty-kaspa's rule).
    pub rpc_api_version: u16,
    pub rpc_api_revision: u16,
    /// The node's version, `2.1.0` and the like.
    pub server_version: String,
    /// The network it follows: `mainnet`, `testnet-10`... KasSigner is
    /// mainnet only, so refuse any other.
    pub network: String,
    /// Whether it keeps the UTXO index `getUtxosByAddresses` needs.
    pub has_utxo_index: bool,
    /// Whether it has caught up; until then the coins it lists may be
    /// stale.
    pub is_synced: bool,
    pub virtual_daa_score: u64,
}

impl From<host::ServerInfo> for ServerInfo {
    fn from(i: host::ServerInfo) -> Self {
        ServerInfo {
            rpc_api_version: i.rpc_api_version,
            rpc_api_revision: i.rpc_api_revision,
            server_version: i.server_version,
            network: i.network,
            has_utxo_index: i.has_utxo_index,
            is_synced: i.is_synced,
            virtual_daa_score: i.virtual_daa_score,
        }
    }
}

/// A fee rate and how soon it confirms, by the node's estimate.
#[derive(Clone, Copy, Debug, PartialEq, uniffi::Record)]
pub struct Bucket {
    /// Sompi a gram, as the node gives it.
    pub feerate: f64,
    pub estimated_seconds: f64,
    /// The rate as `RequestBuilder.build` takes it: whole sompi a gram,
    /// rounded up.
    pub fee_rate: u64,
}

impl From<host::Bucket> for Bucket {
    fn from(b: host::Bucket) -> Self {
        Bucket {
            feerate: b.feerate,
            estimated_seconds: b.estimated_seconds,
            fee_rate: b.fee_rate,
        }
    }
}

/// The node's fee estimate, fastest first.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct FeeEstimate {
    pub priority: Bucket,
    pub normal: Vec<Bucket>,
    pub low: Vec<Bucket>,
}

impl From<host::FeeEstimate> for FeeEstimate {
    fn from(e: host::FeeEstimate) -> Self {
        FeeEstimate {
            priority: e.priority.into(),
            normal: e.normal.into_iter().map(Into::into).collect(),
            low: e.low.into_iter().map(Into::into).collect(),
        }
    }
}

/// A coin an address holds; [`utxo_coin`] makes it the [`Coin`] a request
/// spends.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Utxo {
    /// The address asked about that holds it; a node may leave it out.
    pub address: Option<String>,
    /// Its transaction's id, hex.
    pub transaction_id: String,
    pub index: u32,
    /// Sompi.
    pub amount: u64,
    pub script_version: u16,
    /// The locking script.
    pub script: Vec<u8>,
    /// When it was accepted, in DAA score.
    pub block_daa_score: u64,
    /// Whether a coinbase made it; such a coin matures before it is spent.
    pub is_coinbase: bool,
    /// The covenant it is bound to, hex; a request refuses such a coin.
    pub covenant_id: Option<String>,
}

impl From<host::Utxo> for Utxo {
    fn from(u: host::Utxo) -> Self {
        Utxo {
            address: u.address,
            transaction_id: u.transaction_id,
            index: u.index,
            amount: u.amount,
            script_version: u.script_version,
            script: u.script,
            block_daa_score: u.block_daa_score,
            is_coinbase: u.is_coinbase,
            covenant_id: u.covenant_id,
        }
    }
}

/// The [`Coin`] a request spends for `utxo`, entry and covenant id
/// included, so the covenant is not lost.
#[uniffi::export]
pub fn utxo_coin(utxo: Utxo) -> Coin {
    Coin {
        tx_id: utxo.transaction_id,
        index: utxo.index,
        amount: utxo.amount,
        block_daa_score: Some(utxo.block_daa_score),
        is_coinbase: Some(utxo.is_coinbase),
        covenant_id: utxo.covenant_id,
    }
}

// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC: [`kassigner_sdk::node`] over owned values.
//!
//! An app opens a WebSocket to a node's wRPC port, Borsh or JSON, and
//! makes a [`Node`] for its encoding. Each call is a message to send and
//! one to read:
//!
//! ```text
//! node.get_utxos_by_addresses(1, &addresses)  → send
//! node.get_fee_estimate(2)                    → send
//! node.read(what arrives)                     → Answer { id: 1, utxos, .. }
//!                                               Answer { id: 2, fee_estimate, .. }
//! node.submit_transaction(3, &finalized)      → send, once the unit has signed
//! node.read(what arrives)                     → Answer { id: 3, transaction_id, .. }
//!                                               or { error: the node's refusal }
//! ```
//!
//! The ids are the app's, any `u32`, and come back on the answers.

use kassigner_sdk::node::{self, Call, Encoding, Kind, Message, Params};

use crate::reply::Finalized;
use crate::request::Coin;
use crate::{hex, Fault};

/// A node's wRPC port, by the encoding it speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    encoding: Encoding,
}

impl Node {
    /// For a port speaking `encoding`: `borsh` or `json`.
    pub fn new(encoding: &str) -> Result<Node, Fault> {
        let encoding = match encoding.trim() {
            "borsh" => Encoding::Borsh,
            "json" => Encoding::Json,
            other => return Err(Fault(format!("no wRPC encoding named {other:?}"))),
        };
        Ok(Node { encoding })
    }

    /// `borsh` or `json`.
    pub fn encoding(&self) -> String {
        match self.encoding {
            Encoding::Borsh => "borsh",
            Encoding::Json => "json",
        }
        .to_string()
    }

    /// Whether its messages are text, sent as text frames: a JSON node's.
    pub fn is_text(&self) -> bool {
        self.encoding == Encoding::Json
    }

    /// The port a mainnet node opens for this encoding when none is named.
    pub fn default_port(&self) -> u16 {
        self.encoding.default_port(kassigner_sdk::Network::Mainnet)
    }

    fn request(&self, id: u32, p: &Params<'_>) -> Result<Vec<u8>, Fault> {
        let id = u64::from(id);
        let mut out = vec![0u8; node::request_len(id, p, self.encoding).map_err(Fault::of)?];
        let n = node::request(id, p, self.encoding, &mut out).map_err(Fault::of)?;
        out.truncate(n);
        Ok(out)
    }

    /// Request `id`, `getServerInfo`.
    pub fn get_server_info(&self, id: u32) -> Result<Vec<u8>, Fault> {
        self.request(id, &Params::GetServerInfo)
    }

    /// Request `id`, `getFeeEstimate`.
    pub fn get_fee_estimate(&self, id: u32) -> Result<Vec<u8>, Fault> {
        self.request(id, &Params::GetFeeEstimate)
    }

    /// Request `id`, `getUtxosByAddresses`: every coin `addresses` hold,
    /// which a node answers only when run with `--utxoindex`.
    ///
    /// # Errors
    ///
    /// `Address { index, error }` for an address that does not decode.
    pub fn get_utxos_by_addresses(&self, id: u32, addresses: &[String]) -> Result<Vec<u8>, Fault> {
        let texts: Vec<&[u8]> = addresses.iter().map(|a| a.trim().as_bytes()).collect();
        self.request(id, &Params::GetUtxosByAddresses { addresses: &texts })
    }

    /// Request `id`, `submitTransaction`: `finalized` handed to the node.
    pub fn submit_transaction(&self, id: u32, finalized: &Finalized) -> Result<Vec<u8>, Fault> {
        let params = match self.encoding {
            Encoding::Borsh => &finalized.submit_borsh,
            Encoding::Json => finalized.submit_json.as_bytes(),
        };
        let id = u64::from(id);
        let call = Call::SubmitTransaction;
        let mut out = vec![0u8; node::frame_len(id, call, self.encoding, params.len())];
        let n = node::frame(id, call, self.encoding, params, &mut out).map_err(Fault::of)?;
        out.truncate(n);
        Ok(out)
    }

    /// Read `message`, which arrived from the node.
    ///
    /// # Errors
    ///
    /// `Malformed { at }` for a message no node writes, `at` its first wrong
    /// byte; `Id(n)` for an id past a `u32`, which no request here sends.
    pub fn read(&self, message: &[u8]) -> Result<Answer, Fault> {
        let m = node::read(message, self.encoding).map_err(Fault::of)?;
        Answer::of(&m)
    }
}

/// A node's message, read.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    /// The id of the request it answers; none on a notification.
    pub id: Option<u32>,
    /// `reply`, `error` or `notification`.
    pub kind: String,
    /// The call it answers, by method name, when the node names one the SDK
    /// makes; a Borsh node names none for a call it does not serve.
    pub call: Option<String>,
    /// On an error, the node's words: a refused transaction says why.
    pub error: Option<String>,
    /// On a `getServerInfo` reply.
    pub server_info: Option<ServerInfo>,
    /// On a `getFeeEstimate` reply.
    pub fee_estimate: Option<FeeEstimate>,
    /// On a `getUtxosByAddresses` reply, every coin, in the node's order.
    pub utxos: Option<Vec<Utxo>>,
    /// On a `submitTransaction` reply, the id of the transaction the node
    /// accepted, hex.
    pub transaction_id: Option<String>,
}

impl Answer {
    fn of(m: &Message<'_>) -> Result<Answer, Fault> {
        let id =
            m.id.map(|id| u32::try_from(id).map_err(|_| Fault(format!("Id({id})"))))
                .transpose()?;
        let mut a = Answer {
            id,
            kind: match m.kind {
                Kind::Reply => "reply",
                Kind::Error => "error",
                Kind::Notification => "notification",
            }
            .to_string(),
            call: m.call.map(|c| c.method().to_string()),
            error: m.error().map(|t| t.to_string()),
            server_info: None,
            fee_estimate: None,
            utxos: None,
            transaction_id: None,
        };
        if m.kind != Kind::Reply {
            return Ok(a);
        }
        match m.call {
            Some(Call::GetServerInfo) => {
                a.server_info = Some(ServerInfo::of(&m.server_info().map_err(Fault::of)?));
            }
            Some(Call::GetFeeEstimate) => {
                a.fee_estimate = Some(FeeEstimate::of(&m.fee_estimate().map_err(Fault::of)?));
            }
            Some(Call::GetUtxosByAddresses) => {
                a.utxos = Some(
                    m.utxos()
                        .map_err(Fault::of)?
                        .map(|u| Utxo::of(&u))
                        .collect(),
                );
            }
            Some(Call::SubmitTransaction) => {
                a.transaction_id = Some(hex(&m.transaction_id().map_err(Fault::of)?));
            }
            None => {}
        }
        Ok(a)
    }
}

/// The node's state: upstream's `GetServerInfoResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    /// Upstream's rule: a client refuses a node that reports other than 1.
    pub rpc_api_version: u16,
    pub rpc_api_revision: u16,
    /// The node's version, such as `2.1.0`.
    pub server_version: String,
    /// The network it follows, as it names itself, such as `mainnet` or
    /// `testnet-10`. An app refuses any but `mainnet`.
    pub network: String,
    /// Whether it keeps the UTXO index `getUtxosByAddresses` needs.
    pub has_utxo_index: bool,
    /// Whether it has caught up; until then what it lists may be stale.
    pub is_synced: bool,
    pub virtual_daa_score: u64,
}

impl ServerInfo {
    fn of(i: &node::ServerInfo<'_>) -> ServerInfo {
        ServerInfo {
            rpc_api_version: i.rpc_api_version,
            rpc_api_revision: i.rpc_api_revision,
            server_version: i.server_version.to_string(),
            network: i.network.to_string(),
            has_utxo_index: i.has_utxo_index,
            is_synced: i.is_synced,
            virtual_daa_score: i.virtual_daa_score,
        }
    }
}

/// A fee rate the node expects to see confirmed within some seconds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bucket {
    /// Sompi a gram of mass, as the node estimates it.
    pub feerate: f64,
    pub estimated_seconds: f64,
    /// The rate as [`build`](crate::request::RequestBuilder::build) takes
    /// it: whole sompi a gram, rounded up, at least one. Not capped, as
    /// rusty-kaspa's wallet does not cap it; the guard is the fee shown
    /// before it is paid, by the app and on the unit's review screens.
    pub fee_rate: u64,
}

impl Bucket {
    fn of(b: &node::Bucket) -> Bucket {
        Bucket {
            feerate: b.feerate,
            estimated_seconds: b.estimated_seconds,
            fee_rate: b.sompi_per_gram(),
        }
    }
}

/// The node's fee estimate: upstream's `RpcFeeEstimate`, fastest first.
#[derive(Clone, Debug, PartialEq)]
pub struct FeeEstimate {
    pub priority: Bucket,
    pub normal: Vec<Bucket>,
    pub low: Vec<Bucket>,
}

impl FeeEstimate {
    fn of(e: &node::FeeEstimate<'_>) -> FeeEstimate {
        FeeEstimate {
            priority: Bucket::of(&e.priority),
            normal: e.normal.clone().map(|b| Bucket::of(&b)).collect(),
            low: e.low.clone().map(|b| Bucket::of(&b)).collect(),
        }
    }
}

/// A coin an address holds: upstream's `RpcUtxosByAddressesEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// The address asked about that holds it; a node may leave it out.
    pub address: Option<String>,
    /// The output it is: its transaction's id, hex, and its index.
    pub transaction_id: String,
    pub index: u32,
    /// Sompi.
    pub amount: u64,
    pub script_version: u16,
    /// The locking script.
    pub script: Vec<u8>,
    /// When it was accepted, in DAA score.
    pub block_daa_score: u64,
    /// A block reward, which matures before it can be spent.
    pub is_coinbase: bool,
    /// The covenant it is bound to, hex; a request spends no bound coin.
    pub covenant_id: Option<String>,
}

impl Utxo {
    fn of(u: &node::Utxo<'_>) -> Utxo {
        Utxo {
            address: u.address.and_then(|a| {
                let mut out = [0u8; kassigner_kaspa::address::MAX_ADDRESS_LEN];
                let n = a.encode(&mut out).ok()?;
                Some(crate::watch::text(&out[..n]))
            }),
            transaction_id: hex(&u.outpoint.transaction_id),
            index: u.outpoint.index,
            amount: u.amount,
            script_version: u.script_version,
            script: u.script.iter().collect(),
            block_daa_score: u.block_daa_score,
            is_coinbase: u.is_coinbase,
            covenant_id: u.covenant_id.map(|c| hex(&c)),
        }
    }

    /// This output as a coin to spend, with its entry and covenant.
    pub fn coin(&self) -> Result<Coin, Fault> {
        let coin = Coin::with_entry(
            &self.transaction_id,
            self.index,
            self.amount,
            self.block_daa_score,
            self.is_coinbase,
        )?;
        match &self.covenant_id {
            Some(id) => coin.bound_to(id),
            None => Ok(coin),
        }
    }
}

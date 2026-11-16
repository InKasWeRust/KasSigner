// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC: the four calls a spend makes, written and read.
//!
//! Upstream: rusty-kaspa's wRPC (`rpc/wrpc/`), workflow-rpc 0.18.0's
//! protocol (`src/messages.rs`) over the types of `rpc/core/src/model/`
//! (workflow-serializer 0.18.0). A node serves it over WebSocket, one port
//! per [`Encoding`], each off unless enabled: `--rpclisten-borsh` (17110 on
//! mainnet) and `--rpclisten-json` (18110).
//!
//! | [`Call`] | Asks | Answers |
//! |---|---|---|
//! | `getServerInfo` | nothing | network, sync, UTXO index, version ([`ServerInfo`]) |
//! | `getFeeEstimate` | nothing | fee rates and expected seconds ([`FeeEstimate`]) |
//! | `getUtxosByAddresses` | addresses | every coin they hold ([`Utxos`]); needs `--utxoindex` |
//! | `submitTransaction` | a signed transaction | its id, or the node's refusal |
//!
//! An app sends a [`request`] and [`read`]s the answer, matched by id.
//! Borsh's request is an `Option<u64>` id, a one-byte op, the params. The
//! node's message is an `Option<u64>` id, a kind and an `Option<u8>` op,
//! then by kind: `0`, a call made, its `Result` (`1` and the response, or
//! `0` and workflow-rpc's `ServerError`); `1`, a call the node could not
//! make, the `ServerError` alone, no op; `0xff`, a notification. JSON's
//! request and reply are `{"id":…,"method":"…","params":…}`, a refusal
//! `{"id":…,"method":"…","error":{"code":0,"message":"…","data":null}}`.
//!
//! A Borsh struct starts with its version, and a newer one only appends;
//! this module reads as upstream does, appended fields left unread, and
//! writes as 2.1.0 does. JSON's unknown fields are passed over.
//!
//! [`read`] checks the frame and a typed read ([`Message::utxos`] and the
//! rest) the whole response, so iterating cannot fail halfway; anything
//! else is [`WrpcError::Malformed`] at the offending byte. Nothing panics.
//!
//! The app holds the WebSocket and picks the ids; JSON goes as a text
//! frame. No subscriptions.

mod borsh;
pub(crate) mod json;
// The request's writing, the message's reading, and what a reply holds: the
// server's info and fees here, the coins in `utxos`.
mod reading;
mod reply;
mod utxos;
mod writing;

use core::fmt;

use crate::address::{self, AddressError, Prefix, Version, MAX_ADDRESS_LEN};
use crate::rpc::{self, RpcError, Shape, Sink};
use crate::tx::{Outpoint, Transaction, TransactionId};

use borsh::Reader;
use json::{At, Span, Unescaped};

pub use reading::*;
pub use reply::*;
pub use utxos::*;
pub use writing::*;

/// Upstream's `RPC_API_VERSION` (`rpc/core/src/api/ops.rs`), as in
/// [`ServerInfo::rpc_api_version`]; by upstream's rule a client refuses a
/// node with another.
pub const RPC_API_VERSION: u16 = 1;

/// How a node's port speaks: rusty-kaspa's `WrpcEncoding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Binary, the port `--rpclisten-borsh` opens.
    Borsh,
    /// Text, the port `--rpclisten-json` opens.
    Json,
}

impl Encoding {
    /// The default port on `network`: upstream's `default_borsh_rpc_port`
    /// and `default_json_rpc_port` (`consensus/core/src/network.rs`).
    pub const fn default_port(self, network: Prefix) -> u16 {
        let base = match self {
            Encoding::Borsh => 17_000,
            Encoding::Json => 18_000,
        };
        base + match network {
            Prefix::Mainnet => 110,
            Prefix::Testnet => 210,
            Prefix::Simnet => 510,
            Prefix::Devnet => 610,
        }
    }
}

/// A call this module writes and reads: upstream's `RpcApiOps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    GetServerInfo,
    GetFeeEstimate,
    GetUtxosByAddresses,
    SubmitTransaction,
}

impl Call {
    /// The four.
    pub const ALL: [Call; 4] = [
        Call::GetServerInfo,
        Call::GetFeeEstimate,
        Call::GetUtxosByAddresses,
        Call::SubmitTransaction,
    ];

    /// Its op, Borsh's name for it: the `RpcApiOps` discriminant.
    pub const fn op(self) -> u8 {
        match self {
            Call::GetServerInfo => 114,
            Call::GetFeeEstimate => 147,
            Call::GetUtxosByAddresses => 135,
            Call::SubmitTransaction => 125,
        }
    }

    /// Its method, JSON's name for it: the op in serde's `camelCase`.
    pub const fn method(self) -> &'static str {
        match self {
            Call::GetServerInfo => "getServerInfo",
            Call::GetFeeEstimate => "getFeeEstimate",
            Call::GetUtxosByAddresses => "getUtxosByAddresses",
            Call::SubmitTransaction => "submitTransaction",
        }
    }

    /// The call an op names, if it is one of the four.
    pub fn from_op(op: u8) -> Option<Call> {
        Call::ALL.into_iter().find(|c| c.op() == op)
    }

    /// The call a method names, if it is one of the four.
    pub fn from_method(method: &[u8]) -> Option<Call> {
        Call::ALL
            .into_iter()
            .find(|c| c.method().as_bytes() == method)
    }
}

/// Why a message was not written or not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrpcError {
    /// The caller's buffer cannot hold what is written.
    BufferTooSmall,
    /// Something to write is longer than a `u32` length holds.
    TooLong,
    /// An address does not decode: its place in the list, and why.
    Address { index: usize, error: AddressError },
    /// Not a message a node writes: the byte where it stops being one.
    Malformed { at: usize },
    /// The node's error, not a reply: [`Message::error`] reads it.
    Refused,
    /// The message answers another call, or is a notification.
    OtherCall,
}

impl From<RpcError> for WrpcError {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::BufferTooSmall => WrpcError::BufferTooSmall,
        }
    }
}

fn malformed(at: At) -> WrpcError {
    WrpcError::Malformed { at }
}

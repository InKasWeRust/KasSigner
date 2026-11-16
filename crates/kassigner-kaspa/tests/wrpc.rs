// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! wRPC conformance: `kassigner_kaspa::wrpc` against a node's own code.
//!
//! Every request written here is read back by a node's code (workflow-rpc
//! 0.18.0's framing and the request types at the pinned rev) as the request
//! upstream builds, and a Borsh request is byte for byte upstream's client's.
//! Every reply read here is written as a node writes it, which is checked
//! against a live kaspad 2.1.0 (`a_live_kaspad_frames_as_these_tests_do`).
//! Host-only, like `upstream.rs`.
//!
//! `the_node_vectors_are_current` writes what these checks prove into
//! `spec/vectors/v110/node/` for the layers that cannot link a node: with
//! `KASSIGNER_NODE_VECTORS=write` it writes them, otherwise it compares.

use borsh::BorshDeserialize;
use kaspa_addresses::{Address as UpAddress, Prefix as UpPrefix, Version as UpVersion};
use kaspa_consensus_core::network::{NetworkId as UpNetworkId, NetworkType};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ScriptPublicKey as UpSpk, Transaction as UpTransaction, TransactionInput as UpInput,
    TransactionOutpoint as UpOutpoint, TransactionOutput as UpOutput,
};
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::ops::RpcApiOps;
use kaspa_rpc_core::{
    GetFeeEstimateRequest, GetFeeEstimateResponse, GetServerInfoRequest, GetServerInfoResponse,
    GetUtxosByAddressesRequest, GetUtxosByAddressesResponse, RpcCovenantBinding, RpcError,
    RpcFeeEstimate, RpcFeerateBucket, RpcTransaction, RpcTransactionInput, RpcTransactionOutpoint,
    RpcTransactionOutput, RpcUtxoEntry, RpcUtxosByAddressesEntry, SubmitTransactionRequest,
    SubmitTransactionResponse,
};
use kassigner_kaspa::address::{Prefix, Version};
use kassigner_kaspa::tx as ours;
use kassigner_kaspa::wrpc::{
    self, Call, Encoding, Kind, Message, NetworkId, Params, WrpcError, RPC_API_VERSION,
};
use serde::{de::DeserializeOwned, Serialize};
use workflow_rpc::error::ServerError;
use workflow_rpc::id::Id64;
use workflow_rpc::messages::borsh::{
    BorshClientMessage, BorshReqHeader, BorshServerMessage, BorshServerMessageHeader,
    ServerMessageKind,
};
use workflow_rpc::messages::serde_json::{JSONServerMessage, JsonClientMessage, JsonServerError};
use workflow_serializer::prelude::{Deserializer, Serializable, Serializer};

const ID: u64 = 7;

fn id64(id: u64) -> Id64 {
    Id64::try_from_slice(&id.to_le_bytes()).unwrap()
}

fn op(call: Call) -> RpcApiOps {
    match call {
        Call::GetServerInfo => RpcApiOps::GetServerInfo,
        Call::GetFeeEstimate => RpcApiOps::GetFeeEstimate,
        Call::GetUtxosByAddresses => RpcApiOps::GetUtxosByAddresses,
        Call::SubmitTransaction => RpcApiOps::SubmitTransaction,
    }
}

fn written(id: u64, p: &Params<'_>, encoding: Encoding) -> Vec<u8> {
    let mut out = vec![0u8; wrpc::request_len(id, p, encoding).unwrap()];
    let n = wrpc::request(id, p, encoding, &mut out).unwrap();
    assert_eq!(n, out.len());
    out
}

// ── Requests ────────────────────────────────────────────────────────────────

/// What upstream's client sends for `req` in Borsh.
fn upstream_borsh_request<R: Serializer + Deserializer + Send + Sync>(
    call: Call,
    req: R,
) -> Vec<u8> {
    let payload = borsh::to_vec(&Serializable(req)).unwrap();
    let mut out = borsh::to_vec(&BorshReqHeader::new(Some(id64(ID)), op(call))).unwrap();
    out.extend_from_slice(&payload);
    out
}

/// Our Borsh request as a node reads it: id, op and the request,
/// re-serialized.
fn node_reads_borsh<R: Serializer + Deserializer + Send + Sync>(
    bytes: &[u8],
) -> (u64, RpcApiOps, Vec<u8>) {
    let m = BorshClientMessage::<RpcApiOps, Id64>::try_from(bytes).unwrap();
    let id = u64::from_le_bytes(
        borsh::to_vec(&m.header.id.unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let req = Serializable::<R>::try_from_slice(m.payload).unwrap();
    (id, m.header.op, borsh::to_vec(&req).unwrap())
}

/// Our JSON request as a node reads it: id and method, the request compared
/// as values.
fn node_reads_json<R: Serialize + DeserializeOwned>(bytes: &[u8], want: &R) -> (u64, RpcApiOps) {
    let text = std::str::from_utf8(bytes).unwrap();
    let m: JsonClientMessage<RpcApiOps, Id64> = serde_json::from_str(text).unwrap();
    let req: R = serde_json::from_value(m.params).unwrap();
    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        serde_json::to_value(want).unwrap()
    );
    let id = serde_json::to_value(m.id.unwrap())
        .unwrap()
        .as_u64()
        .unwrap();
    (id, m.method)
}

/// The empty requests: Borsh byte for byte as upstream's client writes
/// them, JSON as a node reads them.
#[test]
fn the_empty_requests_are_upstreams() {
    let borsh = written(ID, &Params::GetServerInfo, Encoding::Borsh);
    assert_eq!(
        borsh,
        upstream_borsh_request(Call::GetServerInfo, GetServerInfoRequest {})
    );
    let (id, op, _) = node_reads_borsh::<GetServerInfoRequest>(&borsh);
    assert_eq!((id, op), (ID, RpcApiOps::GetServerInfo));
    let json = written(ID, &Params::GetServerInfo, Encoding::Json);
    assert_eq!(
        node_reads_json(&json, &GetServerInfoRequest {}),
        (ID, RpcApiOps::GetServerInfo)
    );

    let borsh = written(u64::MAX, &Params::GetFeeEstimate, Encoding::Borsh);
    let (id, op, _) = node_reads_borsh::<GetFeeEstimateRequest>(&borsh);
    assert_eq!((id, op), (u64::MAX, RpcApiOps::GetFeeEstimate));
    let json = written(u64::MAX, &Params::GetFeeEstimate, Encoding::Json);
    assert_eq!(
        node_reads_json(&json, &GetFeeEstimateRequest {}),
        (u64::MAX, RpcApiOps::GetFeeEstimate)
    );
    assert_eq!(
        std::str::from_utf8(&json).unwrap(),
        "{\"id\":18446744073709551615,\"method\":\"getFeeEstimate\",\"params\":{}}"
    );
}

/// Five addresses: every version, every network.
fn addresses() -> Vec<UpAddress> {
    vec![
        UpAddress::new(UpPrefix::Mainnet, UpVersion::PubKey, &[0x11; 32]),
        UpAddress::new(UpPrefix::Mainnet, UpVersion::ScriptHash, &[0x22; 32]),
        UpAddress::new(UpPrefix::Testnet, UpVersion::PubKeyECDSA, &[0x03; 33]),
        UpAddress::new(UpPrefix::Simnet, UpVersion::PubKey, &[0x44; 32]),
        UpAddress::new(UpPrefix::Devnet, UpVersion::ScriptHash, &[0x55; 32]),
    ]
}

/// `getUtxosByAddresses` is upstream's for every address version and
/// network; an address that does not decode is refused with its place.
#[test]
fn the_utxos_request_is_upstreams() {
    let up = addresses();
    let texts: Vec<String> = up.iter().map(|a| a.to_string()).collect();
    let refs: Vec<&[u8]> = texts.iter().map(|t| t.as_bytes()).collect();
    let p = Params::GetUtxosByAddresses { addresses: &refs };
    let req = GetUtxosByAddressesRequest::new(up.clone());

    let borsh = written(ID, &p, Encoding::Borsh);
    assert_eq!(
        borsh,
        upstream_borsh_request(Call::GetUtxosByAddresses, req.clone())
    );
    let (_, op, _) = node_reads_borsh::<GetUtxosByAddressesRequest>(&borsh);
    assert_eq!(op, RpcApiOps::GetUtxosByAddresses);
    let json = written(ID, &p, Encoding::Json);
    assert_eq!(
        node_reads_json(&json, &req),
        (ID, RpcApiOps::GetUtxosByAddresses)
    );

    let bad: Vec<&[u8]> = vec![texts[0].as_bytes(), b"kaspa:qqqq"];
    for encoding in [Encoding::Borsh, Encoding::Json] {
        assert!(matches!(
            wrpc::request_len(
                ID,
                &Params::GetUtxosByAddresses { addresses: &bad },
                encoding
            ),
            Err(WrpcError::Address { index: 1, .. })
        ));
    }
    let none: Vec<&[u8]> = vec![];
    let empty = written(
        ID,
        &Params::GetUtxosByAddresses { addresses: &none },
        Encoding::Borsh,
    );
    assert_eq!(
        empty,
        upstream_borsh_request(
            Call::GetUtxosByAddresses,
            GetUtxosByAddressesRequest::new(vec![])
        )
    );
}

/// A signed transaction in both models, `version` 0 or 1, the second output
/// bound to a covenant on version 1.
fn transactions(
    version: u16,
) -> (
    Vec<ours::TransactionInput<'static>>,
    Vec<ours::TransactionOutput<'static>>,
    RpcTransaction,
) {
    static SPK: [u8; 34] = [0x20; 34];
    static SIG: [u8; 66] = [0x41; 66];
    static PAYLOAD: [u8; 5] = [9; 5];
    let inputs: Vec<ours::TransactionInput<'static>> = (0..2u8)
        .map(|i| ours::TransactionInput {
            previous_outpoint: ours::Outpoint {
                transaction_id: [i + 1; 32],
                index: u32::from(i) + 1,
            },
            sequence: 7 + u64::from(i),
            sig_op_count: if version == 0 { 1 } else { 0 },
            compute_budget: if version == 0 {
                0
            } else {
                1_000 + u16::from(i)
            },
            signature_script: &SIG,
            utxo_entry: ours::UtxoEntry {
                amount: 1,
                script_public_key: ours::ScriptPublicKey {
                    version: 0,
                    script: &SPK,
                },
            },
        })
        .collect();
    let outputs: Vec<ours::TransactionOutput<'static>> = (0..2u8)
        .map(|k| ours::TransactionOutput {
            value: 10_000_000 + u64::from(k),
            script_public_key: ours::ScriptPublicKey {
                version: 0,
                script: &SPK,
            },
            covenant: (version == 1 && k == 1).then_some(ours::CovenantBinding {
                authorizing_input: 1,
                covenant_id: [0xC0; 32],
            }),
        })
        .collect();
    let up = RpcTransaction {
        version,
        inputs: inputs
            .iter()
            .map(|i| RpcTransactionInput {
                previous_outpoint: RpcTransactionOutpoint {
                    transaction_id: Hash::from_bytes(i.previous_outpoint.transaction_id),
                    index: i.previous_outpoint.index,
                },
                signature_script: i.signature_script.to_vec(),
                sequence: i.sequence,
                sig_op_count: i.sig_op_count,
                compute_budget: i.compute_budget,
                verbose_data: None,
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|o| RpcTransactionOutput {
                value: o.value,
                script_public_key: UpSpk::from_vec(0, o.script_public_key.script.to_vec()),
                verbose_data: None,
                covenant: o.covenant.map(|c| {
                    RpcCovenantBinding(kaspa_consensus_core::tx::CovenantBinding::new(
                        c.authorizing_input,
                        Hash::from_bytes(c.covenant_id),
                    ))
                }),
            })
            .collect(),
        lock_time: 11,
        subnetwork_id: SubnetworkId::from_bytes([0; 20]),
        gas: 0,
        payload: PAYLOAD.to_vec(),
        storage_mass: 4_209,
        verbose_data: None,
    };
    (inputs, outputs, up)
}

/// `submitTransaction` is upstream's on both versions, and a node rebuilds
/// the consensus transaction from it.
#[test]
fn the_submit_request_is_upstreams() {
    for version in [0, 1] {
        let (inputs, outputs, up) = transactions(version);
        let tx = ours::Transaction {
            version,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 11,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: &[9; 5],
        };
        for allow_orphan in [false, true] {
            let p = Params::SubmitTransaction {
                transaction: &tx,
                storage_mass: 4_209,
                allow_orphan,
            };
            let req = SubmitTransactionRequest::new(up.clone(), allow_orphan);
            let borsh = written(ID, &p, Encoding::Borsh);
            assert_eq!(
                borsh,
                upstream_borsh_request(Call::SubmitTransaction, req.clone()),
                "version {version}"
            );
            let (_, op, _) = node_reads_borsh::<SubmitTransactionRequest>(&borsh);
            assert_eq!(op, RpcApiOps::SubmitTransaction);
            let json = written(ID, &p, Encoding::Json);
            assert_eq!(
                node_reads_json(&json, &req),
                (ID, RpcApiOps::SubmitTransaction)
            );

            // Params kept, then framed: the same message.
            for encoding in [Encoding::Borsh, Encoding::Json] {
                let mut params = vec![0u8; wrpc::params_len(&p, encoding).unwrap()];
                wrpc::params(&p, encoding, &mut params).unwrap();
                let mut framed =
                    vec![0u8; wrpc::frame_len(ID, Call::SubmitTransaction, encoding, params.len())];
                let n = wrpc::frame(ID, Call::SubmitTransaction, encoding, &params, &mut framed)
                    .unwrap();
                assert_eq!(framed[..n], written(ID, &p, encoding));
            }
        }
    }

    // The node's own conversion of a consensus transaction writes what ours
    // does.
    let (inputs, outputs, _) = transactions(0);
    let consensus = UpTransaction::new(
        0,
        inputs
            .iter()
            .map(|i| {
                UpInput::new(
                    UpOutpoint::new(
                        Hash::from_bytes(i.previous_outpoint.transaction_id),
                        i.previous_outpoint.index,
                    ),
                    i.signature_script.to_vec(),
                    i.sequence,
                    i.sig_op_count,
                )
            })
            .collect(),
        outputs
            .iter()
            .map(|o| {
                UpOutput::new(
                    o.value,
                    UpSpk::from_vec(0, o.script_public_key.script.to_vec()),
                )
            })
            .collect(),
        11,
        SubnetworkId::from_bytes([0; 20]),
        0,
        vec![9; 5],
    );
    consensus.set_storage_mass(4_209);
    let tx = ours::Transaction {
        version: 0,
        inputs: &inputs,
        outputs: &outputs,
        lock_time: 11,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: &[9; 5],
    };
    let p = Params::SubmitTransaction {
        transaction: &tx,
        storage_mass: 4_209,
        allow_orphan: false,
    };
    assert_eq!(
        written(ID, &p, Encoding::Borsh),
        upstream_borsh_request(
            Call::SubmitTransaction,
            SubmitTransactionRequest::new(RpcTransaction::from(&consensus), false)
        )
    );

    let mut small = [0u8; 16];
    assert_eq!(
        wrpc::request(ID, &p, Encoding::Borsh, &mut small),
        Err(WrpcError::BufferTooSmall)
    );
}

/// A signed transaction from the SDK (`single.submit.*`, written by
/// `kassigner-sdk-host`'s `tests/node.rs`) is what a node reads, under the
/// id the SDK computed.
#[test]
fn a_signed_transaction_from_the_sdk_is_what_a_node_reads() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v110/node");
    let read = |name: &str| {
        std::fs::read(dir.join(name)).unwrap_or_else(|e| {
            panic!("{name}: {e}; written by kassigner-sdk-host's tests/node.rs")
        })
    };
    let borsh = read("single.submit.request.borsh");
    let m = BorshClientMessage::<RpcApiOps, Id64>::try_from(&borsh[..]).unwrap();
    assert_eq!(m.header.op, RpcApiOps::SubmitTransaction);
    let req = Serializable::<SubmitTransactionRequest>::try_from_slice(m.payload)
        .unwrap()
        .into_inner();
    assert_eq!(
        borsh::to_vec(&Serializable(req.clone())).unwrap(),
        m.payload,
        "a node writes the request back as it came"
    );
    assert!(!req.allow_orphan);
    let mass = req.transaction.storage_mass;
    assert!(mass > 0);
    let tx = UpTransaction::try_from(req.transaction.clone()).unwrap();
    assert_eq!(tx.storage_mass(), mass);
    let id = String::from_utf8(read("single.submit.id")).unwrap();
    assert_eq!(tx.id().to_string(), id);

    let json = read("single.submit.request.json");
    let m: JsonClientMessage<RpcApiOps, Id64> =
        serde_json::from_str(std::str::from_utf8(&json).unwrap()).unwrap();
    assert_eq!(m.method, RpcApiOps::SubmitTransaction);
    let from_json: SubmitTransactionRequest = serde_json::from_value(m.params).unwrap();
    assert_eq!(
        serde_json::to_value(&from_json).unwrap(),
        serde_json::to_value(&req).unwrap()
    );
}

// ── Replies ─────────────────────────────────────────────────────────────────

/// What a node sends in Borsh for a reply to request `id` of `call`.
fn node_borsh_reply<R: Serializer + Deserializer + Send + Sync>(
    id: u64,
    call: Call,
    resp: R,
) -> Vec<u8> {
    node_borsh_returned(id, call, Ok(Serializable(resp)))
}

/// What a node sends in Borsh once a method has returned: the `Result`
/// itself, framed as a success.
fn node_borsh_returned<R: Serializer + Deserializer + Send + Sync>(
    id: u64,
    call: Call,
    returned: Result<Serializable<R>, ServerError>,
) -> Vec<u8> {
    let payload = borsh::to_vec(&returned).unwrap();
    BorshServerMessage::new(
        BorshServerMessageHeader::<RpcApiOps, Id64>::new(
            Some(id64(id)),
            ServerMessageKind::Success,
            Some(op(call)),
        ),
        &payload,
    )
    .try_to_vec()
    .unwrap()
}

/// What a node sends in JSON for a reply.
fn node_json_reply<R: Serialize>(id: u64, call: Call, resp: &R) -> Vec<u8> {
    serde_json::to_string(&JSONServerMessage::<RpcApiOps, Id64>::new(
        Some(id64(id)),
        Some(op(call)),
        Some(serde_json::to_value(resp).unwrap()),
        None,
    ))
    .unwrap()
    .into_bytes()
}

/// What a node sends for an error. In Borsh a method's refusal is what it
/// returned ([`node_borsh_returned`]), and an error raised before any method
/// runs is an error-kind message with no op; JSON sends either as `error`.
fn node_errors(id: u64, call: Call, err: ServerError, refused: bool) -> (Vec<u8>, Vec<u8>) {
    let borsh = if refused {
        node_borsh_returned::<SubmitTransactionResponse>(id, call, Err(err.clone()))
    } else {
        BorshServerMessage::new(
            BorshServerMessageHeader::<RpcApiOps, Id64>::new(
                Some(id64(id)),
                ServerMessageKind::Error,
                None,
            ),
            &borsh::to_vec(&err).unwrap(),
        )
        .try_to_vec()
        .unwrap()
    };
    let json = serde_json::to_string(&JSONServerMessage::<RpcApiOps, Id64>::new(
        Some(id64(id)),
        Some(op(call)),
        None,
        Some(JsonServerError::from(err)),
    ))
    .unwrap()
    .into_bytes();
    (borsh, json)
}

fn both<'a>(borsh: &'a [u8], json: &'a [u8]) -> [Message<'a>; 2] {
    [
        wrpc::read(borsh, Encoding::Borsh).unwrap(),
        wrpc::read(json, Encoding::Json).unwrap(),
    ]
}

fn server_info(network: UpNetworkId) -> GetServerInfoResponse {
    GetServerInfoResponse {
        rpc_api_version: 1,
        rpc_api_revision: 0,
        server_version: "2.1.0".into(),
        network_id: network,
        has_utxo_index: true,
        is_synced: false,
        virtual_daa_score: 474_165_565 + 1_000_000,
    }
}

/// `getServerInfo`'s reply reads as the node wrote it, for every network.
#[test]
fn the_server_info_reply_reads_as_written() {
    for (network, want) in [
        (
            UpNetworkId::new(NetworkType::Mainnet),
            NetworkId {
                network_type: Prefix::Mainnet,
                suffix: None,
            },
        ),
        (
            UpNetworkId::with_suffix(NetworkType::Testnet, 10),
            NetworkId {
                network_type: Prefix::Testnet,
                suffix: Some(10),
            },
        ),
        (
            UpNetworkId::new(NetworkType::Devnet),
            NetworkId {
                network_type: Prefix::Devnet,
                suffix: None,
            },
        ),
        (
            UpNetworkId::new(NetworkType::Simnet),
            NetworkId {
                network_type: Prefix::Simnet,
                suffix: None,
            },
        ),
    ] {
        let resp = server_info(network);
        let borsh = node_borsh_reply(ID, Call::GetServerInfo, resp.clone());
        let json = node_json_reply(ID, Call::GetServerInfo, &resp);
        for m in both(&borsh, &json) {
            assert_eq!(
                (m.id, m.kind, m.call),
                (Some(ID), Kind::Reply, Some(Call::GetServerInfo))
            );
            let info = m.server_info().unwrap();
            assert_eq!(info.rpc_api_version, RPC_API_VERSION);
            assert_eq!(info.rpc_api_revision, 0);
            assert_eq!(info.server_version.to_string(), "2.1.0");
            assert_eq!(info.network, want);
            assert_eq!(info.network.to_string(), network.to_string());
            assert!(info.has_utxo_index && !info.is_synced);
            assert_eq!(info.virtual_daa_score, 475_165_565);
            assert_eq!(m.fee_estimate().unwrap_err(), WrpcError::OtherCall);
            assert!(m.error().is_none());
        }
    }
}

/// A network number past `u32` is refused, as upstream's `FromStr` refuses
/// it, not read as a testnet with no number.
#[test]
fn a_network_number_past_u32_is_refused() {
    use core::str::FromStr;
    for name in [
        "mainnet",
        "testnet-10",
        "testnet-11",
        "testnet-0",
        "testnet-4294967295",
        "testnet-4294967296",
        "testnet-99999999999",
        "devnet",
        "simnet",
        "testnet-",
        "testnet-1-2",
        "mainnet-x",
        "nonet",
    ] {
        let ours = NetworkId::parse(name.as_bytes());
        let up = UpNetworkId::from_str(name).ok();
        assert_eq!(ours.is_some(), up.is_some(), "{name}");
        if let (Some(ours), Some(up)) = (ours, up) {
            assert_eq!(ours.to_string(), up.to_string(), "{name}");
            assert_eq!(ours.suffix, up.suffix, "{name}");
        }
    }
    assert_eq!(NetworkId::parse(b"testnet-99999999999"), None);
}

fn fee_estimate() -> GetFeeEstimateResponse {
    let b = |feerate: f64, estimated_seconds: f64| RpcFeerateBucket {
        feerate,
        estimated_seconds,
    };
    GetFeeEstimateResponse {
        estimate: RpcFeeEstimate {
            priority_bucket: b(1.000_000_1, 0.004),
            normal_buckets: vec![b(1.0, 0.5), b(1.0, 12.25)],
            low_buckets: vec![b(1.0, 60.0)],
        },
    }
}

/// `getFeeEstimate`'s reply reads to the bit; a rate rounds up to whole
/// sompi a gram.
#[test]
fn the_fee_estimate_reply_reads_as_written() {
    let resp = fee_estimate();
    let borsh = node_borsh_reply(ID, Call::GetFeeEstimate, resp.clone());
    let json = node_json_reply(ID, Call::GetFeeEstimate, &resp);
    for m in both(&borsh, &json) {
        let e = m.fee_estimate().unwrap();
        let bits = |b: wrpc::Bucket| (b.feerate.to_bits(), b.estimated_seconds.to_bits());
        let up = |b: &RpcFeerateBucket| (b.feerate.to_bits(), b.estimated_seconds.to_bits());
        assert_eq!(bits(e.priority), up(&resp.estimate.priority_bucket));
        assert_eq!(e.normal.len(), 2);
        assert_eq!(
            e.normal.clone().map(bits).collect::<Vec<_>>(),
            resp.estimate
                .normal_buckets
                .iter()
                .map(up)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            e.low.clone().map(bits).collect::<Vec<_>>(),
            resp.estimate.low_buckets.iter().map(up).collect::<Vec<_>>()
        );
        assert_eq!(e.priority.sompi_per_gram(), 2);
        assert_eq!(e.normal.clone().next().unwrap().sompi_per_gram(), 1);
    }
    let rate = |feerate| {
        wrpc::Bucket {
            feerate,
            estimated_seconds: 1.0,
        }
        .sompi_per_gram()
    };
    assert_eq!(
        [
            rate(0.0),
            rate(1.0),
            rate(1.5),
            rate(100.0),
            rate(100.000_01),
            rate(1e30)
        ],
        [1, 1, 2, 100, 101, u64::MAX]
    );
}

fn utxos() -> GetUtxosByAddressesResponse {
    let a = addresses();
    let entry = |address: Option<UpAddress>, n: u8, amount, coinbase, covenant: Option<Hash>| {
        RpcUtxosByAddressesEntry {
            address,
            outpoint: RpcTransactionOutpoint {
                transaction_id: Hash::from_bytes([n; 32]),
                index: u32::from(n),
            },
            utxo_entry: RpcUtxoEntry::new(
                amount,
                UpSpk::from_vec(0, vec![0x20 + n; 34]),
                1_000 + u64::from(n),
                coinbase,
                covenant,
            ),
        }
    };
    GetUtxosByAddressesResponse::new(vec![
        entry(Some(a[0].clone()), 1, 123_456_789, false, None),
        entry(
            Some(a[1].clone()),
            2,
            u64::MAX,
            false,
            Some(Hash::from_bytes([0xC0; 32])),
        ),
        entry(Some(a[2].clone()), 3, 1, true, None),
        entry(Some(a[3].clone()), 4, 2, false, None),
        entry(Some(a[4].clone()), 5, 3, false, None),
        entry(None, 6, 0, false, None),
    ])
}

/// `getUtxosByAddresses`' reply reads as written, with and without an
/// address and a covenant, amounts at both ends of a `u64`.
#[test]
fn the_utxos_reply_reads_as_written() {
    let resp = utxos();
    let borsh = node_borsh_reply(ID, Call::GetUtxosByAddresses, resp.clone());
    let json = node_json_reply(ID, Call::GetUtxosByAddresses, &resp);
    for m in both(&borsh, &json) {
        let got: Vec<wrpc::Utxo<'_>> = m.utxos().unwrap().collect();
        assert_eq!(got.len(), resp.entries.len());
        for (u, e) in got.iter().zip(&resp.entries) {
            let mut text = [0u8; kassigner_kaspa::address::MAX_ADDRESS_LEN];
            let address = u.address.map(|a| {
                let n = a.encode(&mut text).unwrap();
                String::from_utf8(text[..n].to_vec()).unwrap()
            });
            assert_eq!(address, e.address.as_ref().map(|a| a.to_string()));
            assert_eq!(
                u.outpoint.transaction_id,
                e.outpoint.transaction_id.as_bytes()
            );
            assert_eq!(u.outpoint.index, e.outpoint.index);
            assert_eq!(u.amount, e.utxo_entry.amount);
            assert_eq!(u.script_version, e.utxo_entry.script_public_key.version());
            assert_eq!(
                u.script.iter().collect::<Vec<u8>>(),
                e.utxo_entry.script_public_key.script()
            );
            let mut copy = vec![0u8; u.script.len()];
            assert_eq!(u.script.copy_to(&mut copy), Some(copy.len()));
            assert_eq!(copy, e.utxo_entry.script_public_key.script());
            assert_eq!(u.block_daa_score, e.utxo_entry.block_daa_score);
            assert_eq!(u.is_coinbase, e.utxo_entry.is_coinbase);
            assert_eq!(
                u.covenant_id,
                e.utxo_entry.covenant_id.map(|h| h.as_bytes())
            );
        }
        assert_eq!(got[1].address.unwrap().version, Version::ScriptHash);
        assert_eq!(got[2].address.unwrap().prefix, Prefix::Testnet);
        assert_eq!(got[3].address.unwrap().prefix, Prefix::Simnet);
        assert_eq!(got[4].address.unwrap().prefix, Prefix::Devnet);
        assert!(got[5].address.is_none());
    }

    // An empty reply: no coins.
    let none = GetUtxosByAddressesResponse::new(vec![]);
    let borsh = node_borsh_reply(ID, Call::GetUtxosByAddresses, none.clone());
    let json = node_json_reply(ID, Call::GetUtxosByAddresses, &none);
    for m in both(&borsh, &json) {
        assert_eq!(m.utxos().unwrap().len(), 0);
    }
}

/// A node before the covenant hardfork writes UTXO entry version 1, with no
/// covenant id; it reads here as upstream reads it.
#[test]
fn an_entry_from_before_the_covenant_hardfork_reads() {
    let resp = GetUtxosByAddressesResponse::new(vec![RpcUtxosByAddressesEntry {
        address: Some(addresses()[0].clone()),
        outpoint: RpcTransactionOutpoint {
            transaction_id: Hash::from_bytes([5; 32]),
            index: 5,
        },
        utxo_entry: RpcUtxoEntry::new(55, UpSpk::from_vec(0, vec![0x20; 34]), 9, false, None),
    }]);
    let v2 = node_borsh_reply(ID, Call::GetUtxosByAddresses, resp);
    // The entry is the message's tail: version 2, its fields, then the
    // covenant id's `None`, which version 1 lacks.
    let mut v1 = v2.clone();
    let entry_len_at = v1.len() - (1 + 8 + 2 + 4 + 34 + 8 + 1 + 1) - 4;
    assert_eq!((v1[entry_len_at + 4], v1.last()), (2, Some(&0)));
    v1[entry_len_at + 4] = 1;
    v1.pop();
    // Every length that holds the entry shrinks by the byte.
    let shrink = |v: &mut Vec<u8>, at: usize| {
        let n = u32::from_le_bytes(v[at..at + 4].try_into().unwrap()) - 1;
        v[at..at + 4].copy_from_slice(&n.to_le_bytes());
    };
    shrink(&mut v1, entry_len_at);
    // The response's, the entries' and the entry's payload lengths, placed by
    // the frame (12 bytes), the `Result`'s tag (1), the version (2) and the
    // count (4).
    shrink(&mut v1, 13);
    shrink(&mut v1, 13 + 4 + 2);
    shrink(&mut v1, 13 + 4 + 2 + 4 + 4);

    // As upstream's client reads it: `ServerResult::<Resp>::try_from_slice`.
    let up = BorshServerMessage::<RpcApiOps, Id64>::try_from(&v1[..]).unwrap();
    let up = Result::<Serializable<GetUtxosByAddressesResponse>, ServerError>::try_from_slice(
        up.payload,
    )
    .unwrap()
    .unwrap();
    assert_eq!(up.entries[0].utxo_entry.amount, 55);
    assert_eq!(up.entries[0].utxo_entry.covenant_id, None);

    let m = wrpc::read(&v1, Encoding::Borsh).unwrap();
    let u: Vec<_> = m.utxos().unwrap().collect();
    assert_eq!(u.len(), 1);
    assert_eq!((u[0].amount, u[0].covenant_id), (55, None));
    assert_eq!(u[0].outpoint.index, 5);
}

/// `submitTransaction`'s reply is the id, and a refusal the node's words as
/// upstream's `Display` writes them.
#[test]
fn the_submit_reply_and_a_refusal_read_as_written() {
    let id = Hash::from_bytes([0xAB; 32]);
    let resp = SubmitTransactionResponse::new(id);
    let borsh = node_borsh_reply(ID, Call::SubmitTransaction, resp.clone());
    let json = node_json_reply(ID, Call::SubmitTransaction, &resp);
    for m in both(&borsh, &json) {
        assert_eq!(m.transaction_id(), Ok(id.as_bytes()));
        assert_eq!(m.utxos().unwrap_err(), WrpcError::OtherCall);
    }

    let refusal = RpcError::RejectedTransaction(
        id,
        format!("transaction {id} is an orphan where orphan is disallowed"),
    )
    .to_string();
    for text in [
        refusal.as_str(),
        "a \"quoted\" reason,\ttabbed, caf\u{e9}, \u{1F600}, \\ and \u{1}",
        "",
    ] {
        let (borsh, json) = node_errors(
            ID,
            Call::SubmitTransaction,
            ServerError::Text(text.to_string()),
            true,
        );
        for m in both(&borsh, &json) {
            assert_eq!(
                (m.id, m.kind, m.call),
                (Some(ID), Kind::Error, Some(Call::SubmitTransaction))
            );
            assert_eq!(m.error().unwrap().to_string(), text);
            assert_eq!(m.transaction_id(), Err(WrpcError::Refused));
        }
    }

    // Every error the protocol raises, returned by a method or raised before
    // one (then Borsh names no call).
    for err in [
        ServerError::Close,
        ServerError::Timeout,
        ServerError::NoData,
        ServerError::NotFound,
        ServerError::PoisonError,
        ServerError::NonBorshRequest,
        ServerError::NonSerdeRequest,
        ServerError::ReqSerialize,
        ServerError::ReqDeserialize,
        ServerError::RespSerialize,
        ServerError::NotificationDeserialize("x".into()),
        ServerError::RespDeserialize("y".into()),
        ServerError::Data(vec![1, 2, 3]),
        ServerError::WebSocketError("gone".into()),
        ServerError::ReceiveChannelRx,
        ServerError::ReceiveChannelTx,
    ] {
        for refused in [true, false] {
            let (borsh, json) = node_errors(ID, Call::GetServerInfo, err.clone(), refused);
            let [b, j] = both(&borsh, &json);
            for m in [b, j] {
                assert_eq!((m.id, m.kind), (Some(ID), Kind::Error));
                assert_eq!(m.error().unwrap().to_string(), err.to_string());
            }
            assert_eq!(b.call, refused.then_some(Call::GetServerInfo));
            assert_eq!(j.call, Some(Call::GetServerInfo));
        }
    }
}

/// A notification is told apart; a frame not a node's is refused at its
/// first wrong byte, and no input panics.
#[test]
fn a_frame_not_a_nodes_is_refused() {
    let note = BorshServerMessage::new(
        BorshServerMessageHeader::<RpcApiOps, Id64>::new(
            None,
            ServerMessageKind::Notification,
            Some(RpcApiOps::UtxosChangedNotification),
        ),
        &[1, 2, 3],
    )
    .try_to_vec()
    .unwrap();
    let m = wrpc::read(&note, Encoding::Borsh).unwrap();
    assert_eq!((m.id, m.kind, m.call), (None, Kind::Notification, None));
    assert_eq!(m.utxos().unwrap_err(), WrpcError::OtherCall);
    let note = b"{\"method\":\"utxosChangedNotification\",\"params\":{\"added\":[]}}";
    let m = wrpc::read(note, Encoding::Json).unwrap();
    assert_eq!((m.id, m.kind, m.call), (None, Kind::Notification, None));

    let good = node_borsh_reply(
        ID,
        Call::GetServerInfo,
        server_info(UpNetworkId::new(NetworkType::Mainnet)),
    );
    // A kind no node writes; a byte past the response; a response cut
    // short.
    let mut bad = good.clone();
    bad[9] = 2;
    assert_eq!(
        wrpc::read(&bad, Encoding::Borsh).unwrap_err(),
        WrpcError::Malformed { at: 9 }
    );
    let mut long = good.clone();
    long.push(0);
    assert_eq!(
        wrpc::read(&long, Encoding::Borsh).unwrap_err(),
        WrpcError::Malformed { at: good.len() }
    );
    let short = &good[..good.len() - 1];
    assert!(matches!(
        wrpc::read(short, Encoding::Borsh),
        Err(WrpcError::Malformed { .. })
    ));
    for json in [
        &b""[..],
        b"[]",
        b"{\"id\":1}",
        b"{\"id\":-1,\"params\":{}}",
        b"{\"id\":1,\"params\":{}} x",
        b"{\"id\":1,\"error\":{\"message\":\"no code\"}}",
    ] {
        assert!(
            matches!(
                wrpc::read(json, Encoding::Json),
                Err(WrpcError::Malformed { .. })
            ),
            "{}",
            String::from_utf8_lossy(json)
        );
    }

    // Every message cut at every length, and every byte flipped: an
    // answer or a refusal, never a panic.
    let resp = utxos();
    for message in [
        node_borsh_reply(ID, Call::GetUtxosByAddresses, resp.clone()),
        node_json_reply(ID, Call::GetUtxosByAddresses, &resp),
        node_borsh_reply(ID, Call::GetFeeEstimate, fee_estimate()),
        node_json_reply(ID, Call::GetFeeEstimate, &fee_estimate()),
    ] {
        for encoding in [Encoding::Borsh, Encoding::Json] {
            for n in 0..message.len() {
                read_everything(&message[..n], encoding);
            }
            for k in 0..message.len() {
                let mut flipped = message.clone();
                flipped[k] ^= 0x5a;
                read_everything(&flipped, encoding);
            }
        }
    }
}

fn read_everything(bytes: &[u8], encoding: Encoding) {
    if let Ok(m) = wrpc::read(bytes, encoding) {
        let _ = m.error().map(|t| t.to_string());
        let _ = m.server_info().map(|i| i.server_version.to_string());
        if let Ok(e) = m.fee_estimate() {
            let _ = e.normal.chain(e.low).count();
        }
        if let Ok(u) = m.utxos() {
            for u in u {
                let _ = u.script.iter().count();
            }
        }
        let _ = m.transaction_id();
    }
}

/// A live kaspad frames its answers as these tests do: its answers, kept in
/// `spec/vectors/v110/node/kaspad/`, read by upstream's client code and
/// written again by this file's node, come out byte for byte, and each reads
/// here.
#[test]
fn a_live_kaspad_frames_as_these_tests_do() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/v110/node/kaspad");
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();

    fn borsh_again<R: Serializer + Deserializer + Send + Sync>(captured: &[u8], call: Call) {
        let m = BorshServerMessage::<RpcApiOps, Id64>::try_from(captured).unwrap();
        assert_eq!(m.header.op, Some(op(call)));
        let returned = Result::<Serializable<R>, ServerError>::try_from_slice(m.payload).unwrap();
        assert_eq!(node_borsh_returned(ID, call, returned), captured);
    }
    fn json_again<R: Serialize + DeserializeOwned>(captured: &[u8], call: Call) {
        let m: JSONServerMessage<RpcApiOps, Id64> = serde_json::from_slice(captured).unwrap();
        let resp: R = serde_json::from_value(m.params.unwrap()).unwrap();
        assert_eq!(node_json_reply(ID, call, &resp), captured);
    }
    borsh_again::<GetServerInfoResponse>(&read("server_info.reply.borsh"), Call::GetServerInfo);
    json_again::<GetServerInfoResponse>(&read("server_info.reply.json"), Call::GetServerInfo);
    borsh_again::<GetFeeEstimateResponse>(&read("fee_estimate.reply.borsh"), Call::GetFeeEstimate);
    json_again::<GetFeeEstimateResponse>(&read("fee_estimate.reply.json"), Call::GetFeeEstimate);
    borsh_again::<GetUtxosByAddressesResponse>(
        &read("utxos.reply.borsh"),
        Call::GetUtxosByAddresses,
    );
    json_again::<GetUtxosByAddressesResponse>(&read("utxos.reply.json"), Call::GetUtxosByAddresses);
    borsh_again::<SubmitTransactionResponse>(
        &read("single.submit.error.borsh"),
        Call::SubmitTransaction,
    );
    // The id it was sent, kept with its answer: an earlier single-signature
    // vector's, before its fee changed.
    let id = String::from_utf8(read("single.submit.id")).unwrap();
    let refusal = format!(
        "Rejected transaction {id}: transaction {id} is an orphan where orphan is disallowed"
    );
    let (borsh, json) = node_errors(
        ID,
        Call::SubmitTransaction,
        ServerError::Text(refusal.clone()),
        true,
    );
    assert_eq!(borsh, read("single.submit.error.borsh"));
    assert_eq!(json, read("single.submit.error.json"));
    let (no_op, _) = node_errors(ID, Call::GetServerInfo, ServerError::NotFound, false);
    assert_eq!(no_op, read("no_op.error.borsh"));

    for encoding in [Encoding::Borsh, Encoding::Json] {
        let ext = match encoding {
            Encoding::Borsh => "borsh",
            Encoding::Json => "json",
        };
        let message = |name: &str| read(&format!("{name}.{ext}"));
        let info = message("server_info.reply");
        let info = wrpc::read(&info, encoding).unwrap().server_info().unwrap();
        assert_eq!(
            (info.server_version.to_string(), info.network.to_string()),
            ("2.1.0".to_string(), "mainnet".to_string())
        );
        assert!(info.has_utxo_index);
        let fees = message("fee_estimate.reply");
        let fees = wrpc::read(&fees, encoding).unwrap().fee_estimate().unwrap();
        assert!(fees.priority.feerate >= 1.0 && fees.normal.len() > 0);
        let utxos = message("utxos.reply");
        assert_eq!(
            wrpc::read(&utxos, encoding).unwrap().utxos().unwrap().len(),
            0
        );
        let refused = message("single.submit.error");
        let m = wrpc::read(&refused, encoding).unwrap();
        assert_eq!(
            (m.id, m.kind, m.call),
            (Some(ID), Kind::Error, Some(Call::SubmitTransaction))
        );
        assert_eq!(m.error().unwrap().to_string(), refusal);
    }
    let no_op = read("no_op.error.borsh");
    let m = wrpc::read(&no_op, Encoding::Borsh).unwrap();
    assert_eq!((m.id, m.kind, m.call), (Some(ID), Kind::Error, None));
    assert_eq!(m.error().unwrap().to_string(), "RPC method not found");
}

// ── The vectors ─────────────────────────────────────────────────────────────

/// The node vectors are current: each compared with its file in
/// `spec/vectors/v110/node/`, or written with `KASSIGNER_NODE_VECTORS=write`.
#[test]
fn the_node_vectors_are_current() {
    let write = std::env::var("KASSIGNER_NODE_VECTORS").as_deref() == Ok("write");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v110/node");
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let texts: Vec<String> = addresses().iter().map(|a| a.to_string()).collect();
    let refs: Vec<&[u8]> = texts.iter().map(|t| t.as_bytes()).collect();
    let (inputs, outputs, _) = transactions(0);
    let tx = ours::Transaction {
        version: 0,
        inputs: &inputs,
        outputs: &outputs,
        lock_time: 11,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: &[9; 5],
    };
    let requests = [
        ("server_info", Params::GetServerInfo),
        ("fee_estimate", Params::GetFeeEstimate),
        ("utxos", Params::GetUtxosByAddresses { addresses: &refs }),
        (
            "submit",
            Params::SubmitTransaction {
                transaction: &tx,
                storage_mass: 4_209,
                allow_orphan: false,
            },
        ),
    ];
    for (name, p) in &requests {
        files.push((
            format!("{name}.request.borsh"),
            written(ID, p, Encoding::Borsh),
        ));
        files.push((
            format!("{name}.request.json"),
            written(ID, p, Encoding::Json),
        ));
    }
    let info = server_info(UpNetworkId::new(NetworkType::Mainnet));
    let id = Hash::from_bytes([0xAB; 32]);
    let submitted = SubmitTransactionResponse::new(id);
    let replies: [(&str, Vec<u8>, Vec<u8>); 4] = [
        (
            "server_info",
            node_borsh_reply(ID, Call::GetServerInfo, info.clone()),
            node_json_reply(ID, Call::GetServerInfo, &info),
        ),
        (
            "fee_estimate",
            node_borsh_reply(ID, Call::GetFeeEstimate, fee_estimate()),
            node_json_reply(ID, Call::GetFeeEstimate, &fee_estimate()),
        ),
        (
            "utxos",
            node_borsh_reply(ID, Call::GetUtxosByAddresses, utxos()),
            node_json_reply(ID, Call::GetUtxosByAddresses, &utxos()),
        ),
        (
            "submit",
            node_borsh_reply(ID, Call::SubmitTransaction, submitted.clone()),
            node_json_reply(ID, Call::SubmitTransaction, &submitted),
        ),
    ];
    for (name, borsh, json) in replies {
        files.push((format!("{name}.reply.borsh"), borsh));
        files.push((format!("{name}.reply.json"), json));
    }
    let refusal = RpcError::RejectedTransaction(
        id,
        format!("transaction {id} is an orphan where orphan is disallowed"),
    )
    .to_string();
    let (borsh, json) = node_errors(
        ID,
        Call::SubmitTransaction,
        ServerError::Text(refusal),
        true,
    );
    files.push(("submit.error.borsh".into(), borsh));
    files.push(("submit.error.json".into(), json));

    if write {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (name, bytes) in &files {
        let path = dir.join(name);
        if write {
            std::fs::write(&path, bytes).unwrap();
        } else {
            let have = std::fs::read(&path).unwrap_or_else(|_| {
                panic!("{} missing: KASSIGNER_NODE_VECTORS=write", path.display())
            });
            assert!(
                have == *bytes,
                "{name} is not current: KASSIGNER_NODE_VECTORS=write"
            );
        }
    }
}

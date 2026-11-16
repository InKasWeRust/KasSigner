// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC through the host layer, over the node vectors.
//!
//! `kassigner-kaspa`'s `tests/wrpc.rs` proves those vectors against a
//! node's own code; here a [`Node`] writes the same requests and reads the
//! same replies into an [`Answer`], in both encodings.

use kassigner_sdk_host::node::{Answer, Node, Utxo};
use kassigner_sdk_host::reply::finalize_reply;
use kassigner_sdk_host::{Fault, Profile, Rates};

const ID: u32 = 7;

fn vector(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../spec/vectors/v110/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn node_vector(name: &str) -> Vec<u8> {
    vector("node", name)
}

fn nodes() -> [(Node, &'static str); 2] {
    [
        (Node::new("borsh").unwrap(), "borsh"),
        (Node::new(" json ").unwrap(), "json"),
    ]
}

/// The five addresses `tests/wrpc.rs` asks about: every version, every
/// network.
fn addresses() -> Vec<String> {
    [
        "kaspa:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zng5quzmq",
        "kaspa:pq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy877axpvm",
        "kaspatest:qypsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqchrflxc9y",
        "kaspasim:qpzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg4aqz4udh",
        "kaspadev:pp2424242424242424242424242424242424242424242424242426q8v3gsq",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// **A node's encodings, by name.** Borsh and JSON; their default ports;
/// a JSON node's messages are text.
#[test]
fn a_node_is_named_by_its_encoding() {
    let [(borsh, _), (json, _)] = nodes();
    assert_eq!((borsh.encoding(), borsh.is_text()), ("borsh".into(), false));
    assert_eq!((json.encoding(), json.is_text()), ("json".into(), true));
    assert_eq!(borsh.default_port(), 17110);
    assert_eq!(json.default_port(), 18110);
    assert!(Node::new("grpc").is_err());
}

/// **The requests are the vectors'**, which a node was shown to read.
#[test]
fn the_requests_are_the_vectors() {
    let addresses = addresses();
    for (node, ext) in nodes() {
        assert_eq!(
            node.get_server_info(ID).unwrap(),
            node_vector(&format!("server_info.request.{ext}"))
        );
        assert_eq!(
            node.get_fee_estimate(ID).unwrap(),
            node_vector(&format!("fee_estimate.request.{ext}"))
        );
        assert_eq!(
            node.get_utxos_by_addresses(ID, &addresses).unwrap(),
            node_vector(&format!("utxos.request.{ext}"))
        );
        let bad = vec![addresses[0].clone(), "kaspa:nope".to_string()];
        let e = node.get_utxos_by_addresses(ID, &bad).unwrap_err();
        assert!(e.0.starts_with("Address { index: 1"), "{e}");
    }
}

/// **The replies read as the node wrote them**, the same in both
/// encodings, each holding what its call answers and nothing else.
#[test]
fn the_replies_read_as_written() {
    let mut answers: Vec<[Answer; 5]> = Vec::new();
    for (node, ext) in nodes() {
        let read = |name: &str| node.read(&node_vector(&format!("{name}.{ext}"))).unwrap();
        let info = read("server_info.reply");
        let fees = read("fee_estimate.reply");
        let utxos = read("utxos.reply");
        let submitted = read("submit.reply");
        let refused = read("submit.error");

        assert_eq!(
            (info.id, info.kind.as_str(), info.call.as_deref()),
            (Some(ID), "reply", Some("getServerInfo"))
        );
        let i = info.server_info.as_ref().unwrap();
        assert_eq!(
            (
                i.rpc_api_version,
                i.server_version.as_str(),
                i.network.as_str()
            ),
            (1, "2.1.0", "mainnet")
        );
        assert!(i.has_utxo_index && !i.is_synced);
        assert!(info.utxos.is_none() && info.error.is_none());

        let f = fees.fee_estimate.as_ref().unwrap();
        assert_eq!((f.priority.feerate, f.priority.fee_rate), (1.000_000_1, 2));
        assert_eq!(f.normal.len(), 2);
        assert_eq!((f.low[0].estimated_seconds, f.low[0].fee_rate), (60.0, 1));

        let u = utxos.utxos.as_ref().unwrap();
        assert_eq!(u.len(), 6);
        let addresses = addresses();
        for (k, a) in addresses.iter().enumerate() {
            assert_eq!(u[k].address.as_deref(), Some(a.as_str()));
        }
        assert_eq!(u[5].address, None);
        assert_eq!(u[0].amount, 123_456_789);
        assert_eq!(u[1].amount, u64::MAX);
        assert_eq!(u[1].covenant_id.as_deref(), Some("c0".repeat(32).as_str()));
        assert!(u[2].is_coinbase);
        assert_eq!(u[0].transaction_id, "01".repeat(32));
        assert_eq!((u[0].index, u[0].script_version), (1, 0));
        assert_eq!(u[0].script, vec![0x21; 34]);
        assert_eq!(u[3].block_daa_score, 1_004);
        let coin = u[0].coin().unwrap();
        assert_eq!(
            (coin.tx_id(), coin.index(), coin.amount()),
            ("01".repeat(32), 1, 123_456_789)
        );
        assert_eq!(
            (coin.block_daa_score(), coin.is_coinbase()),
            (Some(u[0].block_daa_score), Some(u[0].is_coinbase)),
            "the coin carries its entry, for a bundle"
        );

        assert_eq!(submitted.transaction_id, Some("ab".repeat(32)));

        assert_eq!((refused.id, refused.kind.as_str()), (Some(ID), "error"));
        let ab = "ab".repeat(32);
        assert_eq!(
            refused.error.as_deref(),
            Some(
                format!(
                    "Rejected transaction {ab}: transaction {ab} is an orphan where orphan is disallowed"
                )
                .as_str()
            )
        );
        assert!(refused.transaction_id.is_none());

        answers.push([info, fees, utxos, submitted, refused]);
    }
    // The same answers, whichever encoding carried them.
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0][4].call.as_deref(), Some("submitTransaction"));
}

/// **What is not a node's message is refused by name**, and a reply read
/// in the other encoding is not one.
#[test]
fn what_is_not_a_nodes_message_is_refused() {
    let [(borsh, _), (json, _)] = nodes();
    let e = borsh.read(&node_vector("utxos.reply.json")).unwrap_err();
    assert!(e.0.starts_with("Malformed { at: "), "{e}");
    let e = json.read(&node_vector("utxos.reply.borsh")).unwrap_err();
    assert!(e.0.starts_with("Malformed { at: "), "{e}");
    let mut big = node_vector("server_info.reply.borsh");
    big[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        borsh.read(&big).unwrap_err(),
        Fault(format!("Id({})", u64::MAX))
    );
}

/// **A signed transaction goes to a node as `submitTransaction`**, framed
/// around what `Finalized` carries. Written to `single.submit.*`, for
/// `tests/wrpc.rs` to read as a node, with `KASSIGNER_NODE_VECTORS=write`;
/// else compared.
#[test]
fn a_signed_transaction_goes_to_a_node() {
    let f = finalize_reply(
        &vector("sdk", "single.request"),
        &vector("sdk", "single.reply.abandon12"),
        false,
        &Rates::mainnet(),
        &Profile::esp32s3(),
    )
    .unwrap();
    let [(borsh, _), (json, _)] = nodes();
    let b = borsh.submit_transaction(ID, &f).unwrap();
    let mut header = vec![1];
    header.extend_from_slice(&u64::from(ID).to_le_bytes());
    header.push(125);
    assert_eq!(b[..10], header[..]);
    assert_eq!(b[10..], f.submit_borsh[..]);
    let j = json.submit_transaction(ID, &f).unwrap();
    assert_eq!(
        String::from_utf8(j.clone()).unwrap(),
        format!(
            "{{\"id\":7,\"method\":\"submitTransaction\",\"params\":{}}}",
            f.submit_json
        )
    );

    let write = std::env::var("KASSIGNER_NODE_VECTORS").as_deref() == Ok("write");
    let dir = format!(
        "{}/../../spec/vectors/v110/node",
        env!("CARGO_MANIFEST_DIR")
    );
    for (name, bytes) in [
        ("single.submit.request.borsh", b),
        ("single.submit.request.json", j),
        ("single.submit.id", f.id.clone().into_bytes()),
    ] {
        let path = format!("{dir}/{name}");
        if write {
            std::fs::write(&path, &bytes).unwrap();
        } else {
            assert!(
                std::fs::read(&path).ok().as_ref() == Some(&bytes),
                "{name} is not current: KASSIGNER_NODE_VECTORS=write"
            );
        }
    }
}

/// A coin's hex is the SDK's to check.
#[test]
fn a_coin_from_a_utxo_is_checked() {
    let u = Utxo {
        address: None,
        transaction_id: "zz".repeat(32),
        index: 0,
        amount: 1,
        script_version: 0,
        script: vec![],
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    };
    assert!(u.coin().is_err());
}

/// **A live kaspad's answers read**: kaspad 2.1.0's answers in both
/// encodings (`spec/vectors/v110/node/kaspad/`), its refusal of a signed
/// transaction, and a call it does not serve.
#[test]
fn a_live_kaspads_answers_read() {
    // The id of the transaction kaspad was sent, kept with its answer.
    let id = String::from_utf8(node_vector("kaspad/single.submit.id")).unwrap();
    for (node, ext) in nodes() {
        let read = |name: &str| {
            node.read(&node_vector(&format!("kaspad/{name}.{ext}")))
                .unwrap()
        };
        let i = read("server_info.reply").server_info.unwrap();
        assert_eq!(
            (i.server_version.as_str(), i.network.as_str()),
            ("2.1.0", "mainnet")
        );
        assert!(
            read("fee_estimate.reply")
                .fee_estimate
                .unwrap()
                .priority
                .fee_rate
                >= 1
        );
        assert_eq!(read("utxos.reply").utxos, Some(vec![]));
        let refused = read("single.submit.error");
        assert_eq!(
            (refused.kind.as_str(), refused.call.as_deref()),
            ("error", Some("submitTransaction"))
        );
        assert!(refused
            .error
            .unwrap()
            .starts_with(&format!("Rejected transaction {id}: ")));
    }
    let a = Node::new("borsh")
        .unwrap()
        .read(&node_vector("kaspad/no_op.error.borsh"))
        .unwrap();
    assert_eq!(
        (a.id, a.kind.as_str(), a.call, a.error.as_deref()),
        (Some(ID), "error", None, Some("RPC method not found"))
    );
}

// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a companion reads, fuzzed (`testkit/mutate.rs`) through the layer the
//! bindings wrap: replies, signed safe JSON, codes, typed text and a node's
//! answers. Every call must return on any input.
//!
//! Where an input answers a request, its first byte picks which of the
//! vectors' requests, and the rest is the answer.

#[path = "../../../testkit/mutate.rs"]
mod mutate;
#[path = "../../../testkit/vectors.rs"]
mod vectors;

use kassigner_kaspa::pskb::{decode_envelope, encode_envelope};
use kassigner_sdk_host::bundle::{
    bundle_summary, finalize_bundle, finalize_signed_bundle, merge_bundles, merge_signed_bundles,
    read_bundle, read_signed_bundle,
};
use kassigner_sdk_host::card::Card;
use kassigner_sdk_host::message::verify_message;
use kassigner_sdk_host::node::Node;
use kassigner_sdk_host::reply::{
    finalize_reply, finalize_safe_json, finalize_signed_reply, merge_replies, merge_signed_replies,
    read_reply, read_signed_reply,
};
use kassigner_sdk_host::transport::Reader;
use kassigner_sdk_host::watch::{read_import, script_of_address, Account, Group, Kcc3Address};
use kassigner_sdk_host::{Profile, Rates};

const P: Profile = Profile::esp32s3();
const R: Rates = Rates::mainnet();

/// The vector at `path` under `spec/vectors/`.
fn vector(path: &str) -> Vec<u8> {
    let (dir, name) = path.rsplit_once('/').unwrap();
    let mut found = vectors::files(dir, &[name]);
    assert_eq!(found.len(), 1, "{path}");
    found.remove(0)
}

/// The first byte's pick among `n`, and the rest.
fn pick(data: &[u8], n: usize) -> Option<(usize, &[u8])> {
    let (&first, rest) = data.split_first()?;
    Some((usize::from(first) % n, rest))
}

/// `answer` behind the byte that picks `request`.
fn picked(request: usize, answer: &[u8]) -> Vec<u8> {
    let mut out = vec![request as u8];
    out.extend_from_slice(answer);
    out
}

// ── A unit's reply, in KSPT ─────────────────────────────────────────────────

/// The vectors' KSPT requests, and the replies to each.
const KSPT: [(&str, &[&str]); 7] = [
    (
        "v110/sdk/single.request",
        &["v110/sdk/single.reply.abandon12"],
    ),
    (
        "v110/sdk/multisig.request",
        &[
            "v110/sdk/multisig.reply.abandon12",
            "v110/sdk/multisig.reply.zoo12",
        ],
    ),
    (
        "v110/sdk/savings.request",
        &[
            "v110/sdk/savings.reply.abandon12",
            "v110/sdk/savings.reply.zoo12",
        ],
    ),
    (
        "v110/sdk/sweep.request",
        &["v110/sdk/sweep.reply.abandon12"],
    ),
    // Version 1, an output bound to a covenant: started, continued, and
    // started by a group.
    (
        "v110/sdk/covenant.start.request",
        &["v110/sdk/covenant.start.reply.abandon12"],
    ),
    (
        "v110/sdk/covenant.continue.request",
        &["v110/sdk/covenant.continue.reply.abandon12"],
    ),
    (
        "v110/sdk/covenant.group.request",
        &[
            "v110/sdk/covenant.group.reply.abandon12",
            "v110/sdk/covenant.group.reply.both",
        ],
    ),
];

fn kspt_requests() -> Vec<Vec<u8>> {
    KSPT.iter().map(|(r, _)| vector(r)).collect()
}

fn kspt_replies(data: &[u8]) {
    thread_local! {
        static REQUESTS: Vec<Vec<u8>> = kspt_requests();
    }
    let Some((i, reply)) = pick(data, KSPT.len()) else {
        return;
    };
    REQUESTS.with(|requests| {
        let request = &requests[i];
        if read_reply(request, reply, &P).is_ok() {
            let _ = merge_replies(request, &[reply, reply], &P);
            let _ = finalize_reply(request, reply, false, &R, &P);
        }
        if read_signed_reply(reply, &P).is_ok() {
            let _ = merge_signed_replies(&[reply], &P);
            let _ = finalize_signed_reply(reply, true, &R, &P);
        }
    });
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_kspt_reply_any_bytes() {
    let mut seeds = Vec::new();
    for (i, (_, replies)) in KSPT.iter().enumerate() {
        for r in *replies {
            seeds.push(picked(i, &vector(r)));
        }
    }
    mutate::run("kspt reply", 2000, seeds, kspt_replies);
}

// ── A unit's reply, as a bundle ─────────────────────────────────────────────

/// The vectors' bundle requests, and the replies to each.
const BUNDLES: [(&str, &[&str]); 5] = [
    (
        "v110/sdk/pskb_send.request",
        &["v110/sdk/pskb_send.reply.abandon12"],
    ),
    (
        "v110/sdk/pskb_multisig.request",
        &[
            "v110/sdk/pskb_multisig.reply.abandon12",
            "v110/sdk/pskb_multisig.reply.zoo12",
        ],
    ),
    (
        "v110/sdk/single.bundle",
        &["v110/sdk/single.bundle.reply.abandon12"],
    ),
    (
        "v110/sdk/multisig.bundle",
        &[
            "v110/sdk/multisig.bundle.reply.abandon12",
            "v110/sdk/multisig.bundle.reply.zoo12",
        ],
    ),
    (
        "v110/sdk/savings.bundle",
        &[
            "v110/sdk/savings.bundle.reply.abandon12",
            "v110/sdk/savings.bundle.reply.zoo12",
        ],
    ),
];

/// A bundle's JSON, out of its envelope.
fn document(bundle: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bundle.len() / 2];
    let n = decode_envelope(bundle, &mut out).unwrap();
    out.truncate(n);
    out
}

/// A reply bundle, fed as its JSON and put in its envelope here, so the
/// mutations change the document rather than its hex.
fn bundle_replies(data: &[u8]) {
    thread_local! {
        static REQUESTS: Vec<Vec<u8>> = BUNDLES.iter().map(|(r, _)| vector(r)).collect();
    }
    let Some((i, json)) = pick(data, BUNDLES.len()) else {
        return;
    };
    let mut reply = vec![0u8; 4 + 2 * json.len()];
    encode_envelope(json, &mut reply).unwrap();
    REQUESTS.with(|requests| {
        let request = &requests[i];
        if read_bundle(request, &reply, &P).is_ok() {
            let _ = merge_bundles(request, &[&reply, &reply], &P);
            let _ = finalize_bundle(request, &reply, false, &R, &P);
        }
        if read_signed_bundle(&reply, &P).is_ok() {
            let _ = merge_signed_bundles(&[&reply], &P);
            let _ = finalize_signed_bundle(&reply, true, &R, &P);
        }
        let _ = bundle_summary(&reply, &P);
    });
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_bundle_reply_any_bytes() {
    // One reply a request: each bundle read is a whole verification.
    let seeds = BUNDLES
        .iter()
        .enumerate()
        .map(|(i, (_, replies))| picked(i, &document(&vector(replies[0]))))
        .collect();
    mutate::run("bundle reply", 600, seeds, bundle_replies);
}

// ── A wallet's signed safe JSON ─────────────────────────────────────────────

const SAFE: [(&str, &str); 2] = [
    (
        "v110/sdk/single.safe.json",
        "v110/sdk/single.safe.signed.json",
    ),
    (
        "v110/sdk/multisig.safe.json",
        "v110/sdk/multisig.safe.signed.json",
    ),
];

fn safe_json(data: &[u8]) {
    thread_local! {
        static REQUESTS: Vec<String> = SAFE
            .iter()
            .map(|(r, _)| String::from_utf8(vector(r)).unwrap())
            .collect();
    }
    let Some((i, signed)) = pick(data, SAFE.len()) else {
        return;
    };
    let Ok(signed) = std::str::from_utf8(signed) else {
        return;
    };
    REQUESTS.with(|requests| {
        let _ = finalize_safe_json(&requests[i], signed, false, &R, &P);
    });
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_signed_safe_json_any_bytes() {
    let seeds = SAFE
        .iter()
        .enumerate()
        .map(|(i, (_, signed))| picked(i, &vector(signed)))
        .collect();
    mutate::run("safe json", 600, seeds, safe_json);
}

// ── Codes off a screen ──────────────────────────────────────────────────────

/// Codes one after another, each a length byte and that many bytes, taken
/// by a reader and collected when whole.
fn codes(data: &[u8]) {
    let mut reader = Reader::new(&P, 255);
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let n = usize::from(len).min(tail.len());
        if let Ok(taken) = reader.take(&tail[..n]) {
            let _ = reader.received();
            let _ = reader.format();
            if taken.whole() {
                let _ = reader.collect();
            }
        }
        rest = &tail[n..];
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn codes_off_a_screen_any_bytes() {
    let mut seeds = Vec::new();
    for name in ["v110/sdk/single.reply.abandon12", "v110/sdk/message.record"] {
        let payload = vector(name);
        let plan = kassigner_sdk_host::transport::codes(&payload, "kspt", &P)
            .or_else(|_| kassigner_sdk_host::transport::codes(&payload, "opaque", &P))
            .unwrap();
        let mut seed = Vec::new();
        for i in 0..plan.frames() {
            let code = plan.bytes(i).unwrap();
            seed.push(code.len() as u8);
            seed.extend_from_slice(&code);
        }
        seeds.push(seed);
    }
    mutate::run("codes", 2000, seeds, codes);
}

// ── Text a person or a code hands over ──────────────────────────────────────

fn texts(data: &[u8]) {
    let _ = read_import(data);
    let _ = verify_message(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Card::from_backup(text);
    let _ = script_of_address(text);
    let _ = Kcc3Address::read(text);
    if let Ok(account) = Account::from_kpub(text) {
        let _ = account.address(0, 0);
    }
    if let Ok(group) = Group::from_descriptor(text) {
        let _ = group.address(0, 0, 0);
        let _ = group.descriptor();
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_text_any_bytes() {
    let mut seeds = vec![
        vector("v110/sdk/message.record"),
        vector("v110/sdk/savings.backup"),
        vector("v107/cards/KP000001.TXT"),
        b"kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh".to_vec(),
    ];
    let kpub = String::from_utf8(vector("v107/cards/KP000001.TXT")).unwrap();
    let account = Account::from_kpub(kpub.trim()).unwrap();
    seeds.push(account.address(0, 0).unwrap().into_bytes());
    mutate::run("text", 2000, seeds, texts);
}

// ── What a node sends ───────────────────────────────────────────────────────

fn node_answers(data: &[u8]) {
    let Some((i, message)) = pick(data, 2) else {
        return;
    };
    let node = Node::new(["json", "borsh"][i]).unwrap();
    let _ = node.read(message);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_node_answer_any_bytes() {
    let mut seeds = Vec::new();
    for name in ["server_info", "fee_estimate", "utxos"] {
        seeds.push(picked(
            0,
            &vector(&format!("v110/node/kaspad/{name}.reply.json")),
        ));
        seeds.push(picked(
            1,
            &vector(&format!("v110/node/kaspad/{name}.reply.borsh")),
        ));
    }
    seeds.push(picked(
        0,
        &vector("v110/node/kaspad/single.submit.error.json"),
    ));
    seeds.push(picked(
        1,
        &vector("v110/node/kaspad/single.submit.error.borsh"),
    ));
    mutate::run("node answer", 2000, seeds, node_answers);
}

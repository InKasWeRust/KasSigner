// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The classes JavaScript sees, called as plain Rust on the host, give
//! what `kassigner-sdk-host` gives; the logic is tested there.
//!
//! The full package's: built without `transactions`, the crate has no
//! request to build, and `tests/watch.rs` covers what is left.

#![cfg(feature = "transactions")]

use kassigner_sdk_host as host;
use kassigner_sdk_wasm::coin::Coin;
use kassigner_sdk_wasm::request::{summary, RequestBuilder};
use kassigner_sdk_wasm::transport::{codes, Reader};
use kassigner_sdk_wasm::watch::{read_import, Account};
use kassigner_sdk_wasm::{Fault, Profile, Rates};

const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const KAS: u64 = 100_000_000;

/// A coinbase's coin waits to mature through the wrappers: `spendableAt`
/// and a build's `ImmatureCoinbase`.
#[test]
fn a_mining_reward_waits_through_the_wrappers() {
    let mined = 90_000_000;
    let reward = Coin::with_entry(&"01".repeat(32), 1, 3 * KAS, mined, true).unwrap();
    assert_eq!(reward.spendable_at(mined + 999), Some(false));
    assert_eq!(reward.spendable_at(mined + 1_000), Some(true));
    let bare = Coin::new(&"02".repeat(32), 2, KAS).unwrap();
    assert_eq!(bare.spendable_at(mined), None);

    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mut b = RequestBuilder::new();
    b.spend_account(&a, 0, 0, &reward);
    b.pay(&a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    b.at_daa_score(mined + 999);
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    assert_eq!(
        b.build(100, &rates, &p).unwrap_err(),
        Fault("ImmatureCoinbase { coin: 0 }".into())
    );
    b.at_daa_score(mined + 1_000);
    assert!(b.build(100, &rates, &p).is_ok());
}

/// A coin bound to a covenant is refused through the wrappers:
/// `Coin.boundTo`, `covenantId` and a build's `CovenantBound`.
#[test]
fn a_bound_coin_is_refused_through_the_wrappers() {
    let id = "5a".repeat(32);
    let coin = Coin::with_entry(&"01".repeat(32), 1, 3 * KAS, 90_000_001, false).unwrap();
    assert_eq!(coin.covenant_id(), None);
    let bound = coin.bound_to(&id).unwrap();
    assert_eq!(bound.covenant_id(), Some(id));
    assert!(coin.bound_to("5a").is_err());

    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let build = |c: &Coin| {
        let mut b = RequestBuilder::new();
        b.spend_account(&a, 0, 0, c);
        b.pay(&a.address(0, 1).unwrap(), 2 * KAS).unwrap();
        b.change_to_account(&a, 1, 0);
        b.build(100, &rates, &p)
    };
    assert!(build(&coin).is_ok());
    assert_eq!(
        build(&bound).unwrap_err(),
        Fault("CovenantBound { coin: 0 }".into())
    );
}

/// A file of `spec/vectors/v110/sdk/`.
fn sdk_vector(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../spec/vectors/v110/sdk/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The bench's covenant request before its bindings, as the SDK's vectors
/// have it: two `44'` coins of 1000 KAS, `bound` the covenant the first is
/// bound to, `outputs` outputs of 100 KAS to the covenant's script.
fn covenant_builder(bound: Option<&str>, outputs: usize) -> RequestBuilder {
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    // The script hash of `77…77`: `OP_BLAKE2B <32 bytes> OP_EQUAL`.
    let mut script = vec![0xaa, 0x20];
    script.extend([0x77; 32]);
    script.push(0x87);
    let mut b = RequestBuilder::new();
    for n in [1u32, 2] {
        let id = format!("{n:02x}").repeat(32);
        let mut c = Coin::with_entry(&id, n, 1000 * KAS, 0, false).unwrap();
        if let (1, Some(covenant)) = (n, bound) {
            c = c.bound_to(covenant).unwrap();
        }
        b.spend_account(&a, 0, n, &c);
    }
    for _ in 0..outputs {
        b.pay_script(&script, 100 * KAS);
    }
    b.change_to_account(&a, 1, 0);
    b
}

/// Covenants go through the wrappers: `startCovenant` and
/// `continueCovenant` build the SDK's own requests byte for byte, the
/// summary's `version`, `covenantId` and `authorizingInput` read them back,
/// `endCovenants` lets a covenant end, and the refusals come by name.
#[test]
fn covenants_go_through_the_wrappers() {
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let id = "5a".repeat(32);

    let mut start = covenant_builder(None, 2);
    start.start_covenant(0, 0).unwrap();
    start.start_covenant(1, 0).unwrap();
    let r = start.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes(), sdk_vector("covenant.start.request"));
    let s = summary(&r.bytes(), &p).unwrap();
    assert_eq!(s.version(), 1);
    let outputs = s.outputs();
    let made = outputs[0].covenant_id().expect("bound");
    assert_eq!(outputs[1].covenant_id(), Some(made));
    assert_eq!(outputs[0].authorizing_input(), Some(0));
    assert_eq!(
        (outputs[2].covenant_id(), outputs[2].authorizing_input()),
        (None, None),
        "the change is not bound"
    );
    assert!(start
        .build_safe_json(100, &rates, &p)
        .unwrap()
        .text()
        .contains("\"version\":1"));
    assert_eq!(
        start.build_bundle(100, &rates, &p).unwrap_err(),
        Fault("CovenantInBundle".into())
    );

    let mut go_on = covenant_builder(Some(&id), 1);
    assert_eq!(
        go_on.build(100, &rates, &p).unwrap_err(),
        Fault("CovenantBound { coin: 0 }".into())
    );
    let mut ends = go_on.clone();
    ends.end_covenants();
    let ended = ends.build(100, &rates, &p).unwrap();
    assert_eq!(summary(&ended.bytes(), &p).unwrap().version(), 0);
    go_on.continue_covenant(0, 0).unwrap();
    let r = go_on.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes(), sdk_vector("covenant.continue.request"));
    let s = summary(&r.bytes(), &p).unwrap();
    assert_eq!(s.outputs()[0].covenant_id(), Some(id));

    assert_eq!(
        go_on.start_covenant(1, 0).unwrap_err(),
        Fault("BadBinding { output: 1 }".into())
    );
    go_on.continue_covenant(0, 1).unwrap();
    assert_eq!(
        go_on.build(100, &rates, &p).unwrap_err(),
        Fault("BadBinding { output: 0 }".into())
    );
}

/// A lock time goes through the wrappers: `lockUntil` and the summary's
/// `lockTime`.
#[test]
fn a_lock_time_goes_through_the_wrappers() {
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let mut b = RequestBuilder::new();
    b.spend_account(&a, 0, 0, &Coin::new(&"01".repeat(32), 1, 3 * KAS).unwrap());
    b.pay(&a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    b.lock_until(412_345_678);
    let r = b.build(100, &rates, &p).unwrap();
    assert_eq!(summary(&r.bytes(), &p).unwrap().lock_time(), 412_345_678);
}

/// The wrappers build the host crate's requests byte for byte, as a KSPT,
/// a bundle and the safe JSON; the codes read back; a refusal carries the
/// SDK's name.
#[test]
fn the_wrappers_wrap() {
    let p = Profile::esp32s3();
    let rates = Rates::mainnet();
    assert_eq!(p.max_inputs(), host::Profile::esp32s3().max_inputs());
    let i = read_import(ABANDON12_KPUB44.as_bytes()).unwrap();
    assert_eq!(i.kind(), "account");
    let a = i.account().unwrap();
    assert_eq!(a, Account::from_kpub(ABANDON12_KPUB44).unwrap());
    let coin = |n: u8, amount: u64| {
        Coin::new(
            &"11".repeat(32).replace("11", &format!("{n:02x}")),
            u32::from(n),
            amount,
        )
        .unwrap()
    };

    let mut b = RequestBuilder::new();
    b.spend_account(&a, 0, 0, &coin(1, 3 * KAS));
    b.pay(&a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    let r = b.build(100, &rates, &p).unwrap();

    let ha = host::watch::Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mut hb = host::request::RequestBuilder::new();
    hb.spend_account(
        &ha,
        0,
        0,
        &host::request::Coin::new(&"01".repeat(32), 1, 3 * KAS).unwrap(),
    );
    hb.pay(&ha.address(0, 1).unwrap(), 2 * KAS).unwrap();
    hb.change_to_account(&ha, 1, 0);
    let hr = hb
        .build(100, &host::Rates::mainnet(), &host::Profile::esp32s3())
        .unwrap();
    assert_eq!(r.bytes(), hr.bytes);
    assert_eq!(
        (r.fee(), r.mass(), r.change(), r.signatures()),
        (hr.fee, hr.mass, hr.change, hr.signatures)
    );

    let s = summary(&r.bytes(), &p).unwrap();
    assert_eq!(s.total_in(), 3 * KAS);
    assert_eq!(s.outputs().len(), 2);
    let c = codes(&r.bytes(), "kspt", &p).unwrap();
    let mut reader = Reader::new(&p, 225);
    for k in 0..c.frames() {
        let t = reader.take(&c.bytes(k).unwrap()).unwrap();
        assert_eq!(t.whole(), k + 1 == c.frames());
    }
    assert_eq!(reader.collect().unwrap(), r.bytes());
    assert_eq!(
        RequestBuilder::new().build(100, &rates, &p).unwrap_err(),
        Fault("Empty".to_string())
    );

    // Paying its own receive address 777, past the keys a unit derives up
    // front.
    let mut own = RequestBuilder::new();
    own.spend_account(&a, 0, 0, &coin(1, 3 * KAS));
    own.pay_account(&a, 777, 2 * KAS).unwrap();
    own.change_to_account(&a, 1, 0);
    let mut host_own = host::request::RequestBuilder::new();
    host_own.spend_account(
        &ha,
        0,
        0,
        &host::request::Coin::new(&"01".repeat(32), 1, 3 * KAS).unwrap(),
    );
    host_own.pay_account(&ha, 777, 2 * KAS).unwrap();
    host_own.change_to_account(&ha, 1, 0);
    assert_eq!(
        own.build(100, &rates, &p).unwrap().bytes(),
        host_own
            .build(100, &host::Rates::mainnet(), &host::Profile::esp32s3())
            .unwrap()
            .bytes
    );
    assert!(RequestBuilder::new()
        .pay_account(&a, 0x8000_0000, KAS)
        .is_err());

    // The coins gathered on its own change 560.
    let mut gathered = RequestBuilder::new();
    gathered.spend_account(&a, 0, 0, &coin(1, 3 * KAS));
    gathered.sweep_to_account(&a, 1, 560).unwrap();
    let mut host_gathered = host::request::RequestBuilder::new();
    host_gathered.spend_account(
        &ha,
        0,
        0,
        &host::request::Coin::new(&"01".repeat(32), 1, 3 * KAS).unwrap(),
    );
    host_gathered.sweep_to_account(&ha, 1, 560).unwrap();
    assert_eq!(
        gathered.build(100, &rates, &p).unwrap().bytes(),
        host_gathered
            .build(100, &host::Rates::mainnet(), &host::Profile::esp32s3())
            .unwrap()
            .bytes
    );

    let entered = Coin::with_entry(&"01".repeat(32), 1, 3 * KAS, 90_000_001, false).unwrap();
    assert_eq!(
        (entered.block_daa_score(), entered.is_coinbase()),
        (Some(90_000_001), Some(false))
    );
    let mut bb = RequestBuilder::new();
    bb.spend_account(&a, 0, 0, &entered);
    bb.pay(&a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    bb.change_to_account(&a, 1, 0);
    let mut hbb = host::request::RequestBuilder::new();
    hbb.spend_account(
        &ha,
        0,
        0,
        &host::request::Coin::with_entry(&"01".repeat(32), 1, 3 * KAS, 90_000_001, false).unwrap(),
    );
    hbb.pay(&ha.address(0, 1).unwrap(), 2 * KAS).unwrap();
    hbb.change_to_account(&ha, 1, 0);
    let bundle = bb.build_bundle(100, &rates, &p).unwrap();
    assert_eq!(
        bundle.bytes(),
        hbb.build_bundle(100, &host::Rates::mainnet(), &host::Profile::esp32s3())
            .unwrap()
            .bytes
    );
    assert_eq!(
        b.build_bundle(100, &rates, &p).unwrap_err(),
        Fault("NoEntry { coin: 0 }".to_string())
    );
    let safe = bb.build_safe_json(100, &rates, &p).unwrap();
    assert_eq!(
        safe.text(),
        hbb.build_safe_json(100, &host::Rates::mainnet(), &host::Profile::esp32s3())
            .unwrap()
            .text()
    );
    assert!(safe.text().starts_with("{\"id\":"));
    assert_eq!(
        kassigner_sdk_wasm::reply::finalize_safe_json(
            &safe.text(),
            &safe.text(),
            false,
            &rates,
            &p
        )
        .unwrap_err(),
        Fault("Unsigned { input: 0 }".to_string())
    );
}

/// A signed KSPT and bundle, read and finished with no request as the host
/// crate does. The merges take JavaScript arrays: `check/check.mjs` covers
/// them.
#[test]
fn the_signed_wrappers_wrap() {
    use kassigner_sdk_wasm::bundle::{bundle_summary, finalize_signed_bundle, read_signed_bundle};
    use kassigner_sdk_wasm::reply::{finalize_signed_reply, read_signed_reply};
    let vector = |name: &str| {
        std::fs::read(format!(
            "{}/../../spec/vectors/v110/sdk/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let (hp, hr) = (host::Profile::esp32s3(), host::Rates::mainnet());
    let kspt = vector("single.reply.abandon12");
    assert!(read_signed_reply(&kspt, &p).unwrap().complete());
    assert_eq!(
        finalize_signed_reply(&kspt, false, &rates, &p)
            .unwrap()
            .id(),
        host::reply::finalize_signed_reply(&kspt, false, &hr, &hp)
            .unwrap()
            .id
    );
    let pskb = vector("pskb_send.reply.abandon12");
    assert!(read_signed_bundle(&pskb, &p).unwrap().complete());
    assert_eq!(
        finalize_signed_bundle(&pskb, false, &rates, &p)
            .unwrap()
            .id(),
        host::bundle::finalize_signed_bundle(&pskb, false, &hr, &hp)
            .unwrap()
            .id
    );
    assert_eq!(
        bundle_summary(&pskb, &p).unwrap().fee(),
        host::bundle::bundle_summary(&pskb, &hp).unwrap().fee()
    );
    assert_eq!(
        read_signed_reply(&vector("single.request"), &p).unwrap_err(),
        Fault("Unverified(Nothing)".to_string())
    );
}

/// A node's answers, read from the node vectors, are the host crate's. The
/// requests are JavaScript values: `check/check.mjs` checks them.
#[test]
fn the_node_wrappers_wrap() {
    use kassigner_sdk_wasm::node::Node;
    let vector = |name: &str| {
        std::fs::read(format!(
            "{}/../../spec/vectors/v110/node/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    for encoding in ["borsh", "json"] {
        let node = Node::new(encoding).unwrap();
        assert_eq!(node.encoding(), encoding);
        let reply = vector(&format!("utxos.reply.{encoding}"));
        let a = node.read_bytes(&reply).unwrap();
        let h = host::node::Node::new(encoding)
            .unwrap()
            .read(&reply)
            .unwrap();
        assert_eq!(
            (a.id(), a.kind(), a.call()),
            (h.id, h.kind.clone(), h.call.clone())
        );
        let utxos = a.utxos().unwrap();
        let hu = h.utxos.unwrap();
        assert_eq!(utxos.len(), hu.len());
        assert_eq!(utxos[1].amount(), hu[1].amount);
        assert_eq!(utxos[0].coin().unwrap().tx_id(), hu[0].transaction_id);
        assert!(a.server_info().is_none() && a.error().is_none());
        let refused = node
            .read_bytes(&vector(&format!("submit.error.{encoding}")))
            .unwrap();
        assert_eq!(refused.kind(), "error");
        let fees = node
            .read_bytes(&vector(&format!("fee_estimate.reply.{encoding}")))
            .unwrap()
            .fee_estimate()
            .unwrap();
        assert_eq!(fees.priority().fee_rate(), 2);
        assert_eq!(fees.normal().len(), 2);
    }
    assert_eq!(
        Node::new("grpc").unwrap_err(),
        Fault("no wRPC encoding named \"grpc\"".to_string())
    );
}

/// A covenant card through the wrappers: its backup line read and written
/// again, the card made again, its key found; its claim, by `spendCardAs`
/// and `spendCard`, is the committed KSPT and bundle; the host's refusals
/// come through by name.
#[test]
fn a_card_goes_through_the_wrappers() {
    use kassigner_sdk_wasm::card::Card;
    let vector = |name: &str| {
        std::fs::read(format!(
            "{}/../../spec/vectors/v110/sdk/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let a = Account::from_kpub(
        "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8",
    )
    .unwrap();
    let line = String::from_utf8(vector("savings.backup")).unwrap();
    let card = Card::from_backup(&line).unwrap();
    assert_eq!(card.backup().unwrap(), line);
    let again = Card::savings(
        &card.owner().unwrap(),
        card.recovery().unwrap(),
        card.unlock_day(),
        card.unlock_month(),
        card.unlock_year(),
        card.unlock_hour(),
        card.unlock_minute(),
    )
    .unwrap();
    assert_eq!(again, card);
    let eve = Card::savings(&card.owner().unwrap(), None, 31, 12, 2026, 23, 59).unwrap();
    assert_eq!((eve.unlock_hour(), eve.unlock_minute()), (23, 59));
    assert_eq!(eve.unlock_ms(), card.unlock_ms() - 60_000);
    let signer = card.signer(&a, 20).unwrap().unwrap();
    assert_eq!((signer.index(), signer.recovers()), (0, false));

    let to = summary(&vector("savings.request"), &p).unwrap().outputs()[0]
        .address()
        .unwrap();
    let entered = |n: u8, amount: u64| {
        Coin::with_entry(
            &host::hex(&[n; 32]),
            u32::from(n),
            amount,
            90_000_000 + u64::from(n),
            false,
        )
        .unwrap()
    };
    let mut b = RequestBuilder::new();
    b.lock_until(card.unlock_ms());
    b.spend_card_as(&card, &entered(1, 500_000_000), &a, 0)
        .unwrap();
    b.spend_card(&card, &entered(2, 300_000_000)).unwrap();
    b.sweep_to(&to).unwrap();
    assert_eq!(
        b.build(100, &rates, &p).unwrap().bytes(),
        vector("savings.request")
    );
    assert_eq!(
        b.build_bundle(100, &rates, &p).unwrap().bytes(),
        vector("savings.bundle")
    );
    assert_eq!(
        b.build_safe_json(100, &rates, &p).unwrap_err(),
        Fault("CardInSafeJson { coin: 0 }".to_string())
    );
    let mut wrong = RequestBuilder::new();
    wrong.lock_until(card.unlock_ms());
    wrong
        .spend_card_as(&card, &entered(1, 500_000_000), &a, 3)
        .unwrap();
    wrong.sweep_to(&to).unwrap();
    assert_eq!(
        wrong.build(100, &rates, &p).unwrap_err(),
        Fault("NotTheCardsKey { coin: 0 }".to_string())
    );
    for (day, hour, minute) in [(29, 0, 0), (1, 24, 0), (1, 0, 60)] {
        assert_eq!(
            Card::savings(&card.owner().unwrap(), None, day, 2, 2027, hour, minute).unwrap_err(),
            Fault("Date".to_string()),
            "{day}/02/2027 {hour}:{minute}"
        );
    }
}

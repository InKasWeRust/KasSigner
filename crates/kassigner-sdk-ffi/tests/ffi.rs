// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The C-ABI layer called as plain Rust; `build.sh` runs the generated
//! bindings (`check/`).

use kassigner_sdk_ffi::node::{utxo_coin, Utxo};
use kassigner_sdk_ffi::request::{coin_spendable_at, summary, Coin, RequestBuilder};
use kassigner_sdk_ffi::transport::{codes, Reader};
use kassigner_sdk_ffi::watch::{read_import, Account};
use kassigner_sdk_ffi::{Fault, Profile, Rates};

const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const KAS: u64 = 100_000_000;

/// A coinbase's coin waits for maturity, as a coin and in a build; half an
/// entry is refused.
#[test]
fn a_mining_reward_waits_through_the_layer() {
    let reward = |block_daa_score, is_coinbase| Coin {
        tx_id: "01".repeat(32),
        index: 1,
        amount: 3 * KAS,
        block_daa_score,
        is_coinbase,
        covenant_id: None,
    };
    let mined = 90_000_000;
    assert_eq!(
        coin_spendable_at(reward(Some(mined), Some(true)), mined + 999),
        Ok(Some(false))
    );
    assert_eq!(
        coin_spendable_at(reward(Some(mined), Some(true)), mined + 1_000),
        Ok(Some(true))
    );
    assert_eq!(coin_spendable_at(reward(None, None), mined), Ok(None));
    assert!(coin_spendable_at(reward(Some(mined), None), mined).is_err());

    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    let b = RequestBuilder::new();
    b.spend_account(&a, 0, 0, reward(Some(mined), Some(true)))
        .unwrap();
    b.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    b.at_daa_score(mined + 999);
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    assert_eq!(
        b.build(100, &rates, &p).unwrap_err(),
        Fault::Sdk("ImmatureCoinbase { coin: 0 }".into())
    );
    b.at_daa_score(mined + 1_000);
    assert!(b.build(100, &rates, &p).is_ok());
}

/// A coin bound to a covenant is refused by name, and so is a covenant id
/// that is not 32 bytes of hex.
#[test]
fn a_bound_coin_is_refused_through_the_layer() {
    let coin = |covenant_id: Option<String>| Coin {
        tx_id: "01".repeat(32),
        index: 1,
        amount: 3 * KAS,
        block_daa_score: Some(90_000_001),
        is_coinbase: Some(false),
        covenant_id,
    };
    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let build = |c: Coin| {
        let b = RequestBuilder::new();
        b.spend_account(&a, 0, 0, c)?;
        b.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
        b.change_to_account(&a, 1, 0);
        b.build(100, &rates, &p)
    };
    assert!(build(coin(None)).is_ok());
    assert_eq!(
        build(coin(Some("5a".repeat(32)))).unwrap_err(),
        Fault::Sdk("CovenantBound { coin: 0 }".into())
    );
    assert!(build(coin(Some("5a".into()))).is_err());
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
    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    // The script hash of `77…77`: `OP_BLAKE2B <32 bytes> OP_EQUAL`.
    let mut script = vec![0xaa, 0x20];
    script.extend([0x77; 32]);
    script.push(0x87);
    let b = RequestBuilder::new();
    for n in [1u32, 2] {
        let coin = Coin {
            tx_id: format!("{n:02x}").repeat(32),
            index: n,
            amount: 1000 * KAS,
            block_daa_score: Some(0),
            is_coinbase: Some(false),
            covenant_id: bound.filter(|_| n == 1).map(str::to_string),
        };
        b.spend_account(&a, 0, n, coin).unwrap();
    }
    for _ in 0..outputs {
        b.pay_script(script.clone(), 100 * KAS);
    }
    b.change_to_account(&a, 1, 0);
    b
}

/// Covenants go through the layer: `start_covenant` and
/// `continue_covenant` build the SDK's own requests byte for byte, the
/// summary's `version`, `covenant_id` and `authorizing_input` read them
/// back, `end_covenants` lets a covenant end, and the refusals come by
/// name.
#[test]
fn covenants_go_through_the_layer() {
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let id = "5a".repeat(32);

    let start = covenant_builder(None, 2);
    start.start_covenant(0, 0).unwrap();
    start.start_covenant(1, 0).unwrap();
    let r = start.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes, sdk_vector("covenant.start.request"));
    let s = summary(r.bytes, &p).unwrap();
    assert_eq!(s.version, 1);
    let made = s.outputs[0].covenant_id.clone().expect("bound");
    assert_eq!(s.outputs[1].covenant_id, Some(made));
    assert_eq!(s.outputs[0].authorizing_input, Some(0));
    assert_eq!(
        (&s.outputs[2].covenant_id, s.outputs[2].authorizing_input),
        (&None, None),
        "the change is not bound"
    );
    let safe = start.build_safe_json(100, &rates, &p).unwrap();
    assert!(String::from_utf8(safe.bytes)
        .unwrap()
        .contains("\"version\":1"));
    assert_eq!(
        start.build_bundle(100, &rates, &p).unwrap_err(),
        Fault::Sdk("CovenantInBundle".into())
    );

    let ends = covenant_builder(Some(&id), 1);
    assert_eq!(
        ends.build(100, &rates, &p).unwrap_err(),
        Fault::Sdk("CovenantBound { coin: 0 }".into())
    );
    ends.end_covenants();
    let ended = ends.build(100, &rates, &p).unwrap();
    assert_eq!(summary(ended.bytes, &p).unwrap().version, 0);

    let go_on = covenant_builder(Some(&id), 1);
    go_on.continue_covenant(0, 0).unwrap();
    let r = go_on.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes, sdk_vector("covenant.continue.request"));
    let s = summary(r.bytes, &p).unwrap();
    assert_eq!(s.outputs[0].covenant_id, Some(id));

    assert_eq!(
        go_on.start_covenant(1, 0).unwrap_err(),
        Fault::Sdk("BadBinding { output: 1 }".into())
    );
    go_on.continue_covenant(0, 1).unwrap();
    assert_eq!(
        go_on.build(100, &rates, &p).unwrap_err(),
        Fault::Sdk("BadBinding { output: 0 }".into())
    );
}

/// `utxo_coin` keeps the entry and the covenant id: a bound UTXO is
/// refused, an unbound one builds.
#[test]
fn a_utxo_is_its_coin_through_the_layer() {
    let utxo = |covenant_id: Option<String>| Utxo {
        address: None,
        transaction_id: "01".repeat(32),
        index: 1,
        amount: 3 * KAS,
        script_version: 0,
        script: vec![],
        block_daa_score: 90_000_001,
        is_coinbase: false,
        covenant_id,
    };
    assert_eq!(
        utxo_coin(utxo(Some("5a".repeat(32)))),
        Coin {
            tx_id: "01".repeat(32),
            index: 1,
            amount: 3 * KAS,
            block_daa_score: Some(90_000_001),
            is_coinbase: Some(false),
            covenant_id: Some("5a".repeat(32)),
        }
    );
    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let build = |u: Utxo| {
        let b = RequestBuilder::new();
        b.spend_account(&a, 0, 0, utxo_coin(u))?;
        b.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
        b.change_to_account(&a, 1, 0);
        b.build(100, &rates, &p)
    };
    assert!(build(utxo(None)).is_ok());
    assert_eq!(
        build(utxo(Some("5a".repeat(32)))).unwrap_err(),
        Fault::Sdk("CovenantBound { coin: 0 }".into())
    );
}

/// `lock_until` reaches the summary's `lock_time`.
#[test]
fn a_lock_time_goes_through_the_layer() {
    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let b = RequestBuilder::new();
    b.spend_account(
        &a,
        0,
        0,
        Coin {
            tx_id: "01".repeat(32),
            index: 1,
            amount: 3 * KAS,
            block_daa_score: None,
            is_coinbase: None,
            covenant_id: None,
        },
    )
    .unwrap();
    b.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    b.lock_until(1_798_761_599_000);
    let r = b.build(100, &rates, &p).unwrap();
    assert_eq!(summary(r.bytes, &p).unwrap().lock_time, 1_798_761_599_000);
}

/// A round through the layer's own types.
#[test]
fn the_layer_delegates() {
    let p = Profile::esp32s3();
    let rates = Rates::mainnet();
    let i = read_import(ABANDON12_KPUB44.as_bytes().to_vec()).unwrap();
    assert_eq!(i.kind, "account");
    let a = i.account.unwrap();
    assert_eq!(
        a.address(0, 0).unwrap(),
        Account::from_kpub(ABANDON12_KPUB44.into())
            .unwrap()
            .address(0, 0)
            .unwrap()
    );
    let b = RequestBuilder::new();
    b.spend_account(
        &a,
        0,
        0,
        Coin {
            tx_id: "01".repeat(32),
            index: 1,
            amount: 3 * KAS,
            block_daa_score: Some(90_000_001),
            is_coinbase: Some(false),
            covenant_id: None,
        },
    )
    .unwrap();
    assert_eq!(
        b.spend_account(
            &a,
            0,
            0,
            Coin {
                tx_id: "zz".into(),
                index: 1,
                amount: 1,
                block_daa_score: None,
                is_coinbase: None,
                covenant_id: None,
            },
        )
        .unwrap_err(),
        Fault::Sdk("expected 32 bytes of hex, got 2 digits".into())
    );
    b.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    b.change_to_account(&a, 1, 0);
    let r = b.build(100, &rates, &p).unwrap();
    assert_eq!(r.signatures, 1);
    // Paid as the account's own receive 1, which the unit finds without a
    // hint: the same bytes. A hardened index is refused.
    let own = RequestBuilder::new();
    own.spend_account(
        &a,
        0,
        0,
        Coin {
            tx_id: "01".repeat(32),
            index: 1,
            amount: 3 * KAS,
            block_daa_score: Some(90_000_001),
            is_coinbase: Some(false),
            covenant_id: None,
        },
    )
    .unwrap();
    own.pay_account(&a, 1, 2 * KAS).unwrap();
    own.change_to_account(&a, 1, 0);
    assert_eq!(own.build(100, &rates, &p).unwrap().bytes, r.bytes);
    assert!(own.pay_account(&a, 0x8000_0001, KAS).is_err());
    // Swept to its own change 4, which the unit finds without a hint: the
    // same bytes as a sweep to that address.
    let gathered = |own: bool| {
        let b = RequestBuilder::new();
        b.spend_account(
            &a,
            0,
            0,
            Coin {
                tx_id: "01".repeat(32),
                index: 1,
                amount: 3 * KAS,
                block_daa_score: None,
                is_coinbase: None,
                covenant_id: None,
            },
        )
        .unwrap();
        if own {
            b.sweep_to_account(&a, 1, 4).unwrap();
        } else {
            b.sweep_to(a.address(1, 4).unwrap()).unwrap();
        }
        b.build(100, &rates, &p).unwrap().bytes
    };
    assert_eq!(gathered(true), gathered(false));
    assert!(own.sweep_to_account(&a, 1, 0x8000_0004).is_err());
    let s = summary(r.bytes.clone(), &p).unwrap();
    assert_eq!((s.total_in, s.fee), (3 * KAS, r.fee));
    let c = codes(r.bytes.clone(), "kspt".into(), &p).unwrap();
    let reader = Reader::new(&p, 225);
    for k in 0..c.frames() {
        let t = reader.take(c.bytes(k).unwrap()).unwrap();
        assert_eq!(t.whole, k + 1 == c.frames());
    }
    assert_eq!(reader.collect().unwrap(), r.bytes);
    assert_eq!(
        RequestBuilder::new()
            .build(100, &rates, &p)
            .unwrap_err()
            .to_string(),
        "Empty"
    );

    let bundle = b.build_bundle(100, &rates, &p).unwrap();
    assert!(bundle.bytes.starts_with(b"PSKB"));
    let safe = b.build_safe_json(100, &rates, &p).unwrap();
    assert!(safe.bytes.starts_with(b"{\"id\":"));
    let text = String::from_utf8(safe.bytes).unwrap();
    assert_eq!(
        kassigner_sdk_ffi::reply::finalize_safe_json(text.clone(), text, false, &rates, &p)
            .unwrap_err()
            .to_string(),
        "Unsigned { input: 0 }"
    );
    assert_eq!(
        (bundle.fee, bundle.change, bundle.signatures),
        (r.fee, r.change, r.signatures)
    );
    let bare = RequestBuilder::new();
    bare.spend_account(
        &a,
        0,
        0,
        Coin {
            tx_id: "01".repeat(32),
            index: 1,
            amount: 3 * KAS,
            block_daa_score: None,
            is_coinbase: None,
            covenant_id: None,
        },
    )
    .unwrap();
    bare.pay(a.address(0, 1).unwrap(), 2 * KAS).unwrap();
    assert_eq!(
        bare.build_bundle(100, &rates, &p).unwrap_err().to_string(),
        "NoEntry { coin: 0 }"
    );
    assert!(bare
        .spend_account(
            &a,
            0,
            1,
            Coin {
                tx_id: "02".repeat(32),
                index: 2,
                amount: KAS,
                block_daa_score: Some(1),
                is_coinbase: None,
                covenant_id: None,
            },
        )
        .is_err());
}

/// A node's requests and answers through the layer's records.
#[test]
fn the_node_layer_delegates() {
    use kassigner_sdk_ffi::node::Node;
    let vector = |name: &str| {
        std::fs::read(format!(
            "{}/../../spec/vectors/v110/node/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    for encoding in ["borsh", "json"] {
        let node = Node::new(encoding.into()).unwrap();
        assert_eq!(node.is_text(), encoding == "json");
        assert_eq!(
            node.get_fee_estimate(7).unwrap(),
            vector(&format!("fee_estimate.request.{encoding}"))
        );
        let a = node
            .read(vector(&format!("utxos.reply.{encoding}")))
            .unwrap();
        assert_eq!(
            (a.id, a.call.as_deref()),
            (Some(7), Some("getUtxosByAddresses"))
        );
        let u = a.utxos.unwrap();
        assert_eq!((u.len(), u[1].amount), (6, u64::MAX));
        let e = node
            .read(vector(&format!("fee_estimate.reply.{encoding}")))
            .unwrap()
            .fee_estimate
            .unwrap();
        assert_eq!((e.priority.fee_rate, e.normal.len()), (2, 2));
    }
    assert_eq!(
        Node::new("grpc".into()).unwrap_err(),
        Fault::Sdk("no wRPC encoding named \"grpc\"".into())
    );
}

/// A covenant card: its backup line read and written again, the card made
/// again, the owner's key found, its claim the vectors' KSPT and bundle;
/// the safe JSON, an impossible time and a key not the card's refused.
#[test]
fn a_card_goes_through_the_layer() {
    use kassigner_sdk_ffi::card::{Card, CardSigner};
    let vector = |name: &str| {
        std::fs::read(format!(
            "{}/../../spec/vectors/v110/sdk/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let (p, rates) = (Profile::esp32s3(), Rates::mainnet());
    let a = Account::from_kpub(ABANDON12_KPUB44.into()).unwrap();
    let line = String::from_utf8(vector("savings.backup")).unwrap();
    let card = Card::from_backup(line.clone()).unwrap();
    assert_eq!(card.backup().unwrap(), line);
    assert_eq!(
        card.signer(&a, 20).unwrap(),
        Some(CardSigner {
            index: 0,
            recovers: false
        })
    );
    let again = Card::savings(
        card.owner().unwrap(),
        card.recovery().unwrap(),
        card.unlock_day(),
        card.unlock_month(),
        card.unlock_year(),
        card.unlock_hour(),
        card.unlock_minute(),
    )
    .unwrap();
    assert_eq!(again.backup().unwrap(), line);
    let eve = Card::savings(card.owner().unwrap(), None, 31, 12, 2026, 23, 59).unwrap();
    assert_eq!((eve.unlock_hour(), eve.unlock_minute()), (23, 59));
    assert_eq!(eve.unlock_ms(), card.unlock_ms() - 60_000);
    for (hour, minute) in [(24, 0), (0, 60)] {
        assert_eq!(
            Card::savings(card.owner().unwrap(), None, 1, 1, 2027, hour, minute).unwrap_err(),
            Fault::Sdk("Date".to_string()),
            "{hour}:{minute}"
        );
    }
    let to = summary(vector("savings.request"), &p).unwrap().outputs[0]
        .address
        .clone()
        .unwrap();
    let entered = |n: u8, amount: u64| Coin {
        tx_id: format!("{n:02x}").repeat(32),
        index: u32::from(n),
        amount,
        block_daa_score: Some(90_000_000 + u64::from(n)),
        is_coinbase: Some(false),
        covenant_id: None,
    };
    let b = RequestBuilder::new();
    b.lock_until(card.unlock_ms());
    b.spend_card_as(&card, entered(1, 500_000_000), &a, 0)
        .unwrap();
    b.spend_card(&card, entered(2, 300_000_000)).unwrap();
    b.sweep_to(to).unwrap();
    assert_eq!(
        b.build(100, &rates, &p).unwrap().bytes,
        vector("savings.request")
    );
    assert_eq!(
        b.build_bundle(100, &rates, &p).unwrap().bytes,
        vector("savings.bundle")
    );
    assert_eq!(
        b.build_safe_json(100, &rates, &p).unwrap_err(),
        Fault::Sdk("CardInSafeJson { coin: 0 }".to_string())
    );
    let wrong = RequestBuilder::new();
    wrong.lock_until(card.unlock_ms());
    wrong
        .spend_card_as(&card, entered(1, 500_000_000), &a, 3)
        .unwrap();
    wrong
        .sweep_to(
            summary(vector("savings.request"), &p).unwrap().outputs[0]
                .address
                .clone()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        wrong.build(100, &rates, &p).unwrap_err(),
        Fault::Sdk("NotTheCardsKey { coin: 0 }".to_string())
    );
}

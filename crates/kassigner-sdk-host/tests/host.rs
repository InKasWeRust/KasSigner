// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The host layer gives what the SDK gives. What needs a signature is
//! tested where the seeds are, in `kassigner-fw/tests/sdk.rs`.

use kassigner_kaspa::address::MAX_ADDRESS_LEN;
use kassigner_kaspa::mass::minimum_relay_fee;
use kassigner_protocol::kpub;
use kassigner_sdk::transport::Codes as SdkCodes;
use kassigner_sdk::watch::{CHANGE, RECEIVE};
use kassigner_sdk_host::bundle::{prepare_bundle, Hints};
use kassigner_sdk_host::message::{is_text, message_codes};
use kassigner_sdk_host::request::{summary, Coin, RequestBuilder};
use kassigner_sdk_host::transport::{codes, decode_qr, Reader};
use kassigner_sdk_host::watch::{
    address_of_script, read_import, script_of_address, Account, Group, Kcc3Address,
};
use kassigner_sdk_host::{hex, unhex, version, Fault, Profile, Rates};

/// The bench's keys, as the SDK's tests have them.
const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const ABANDON12_KPUB45: &str = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";
const ABANDON24_KPUB45: &str = "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW";
const ZOO12_KPUB45: &str = "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU";
/// A seed's KCC-3 receive 0 (`kassigner-kaspa/tests/kcc3.rs`).
const KCC3_ADDRESS: &str = "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa";
const KAS: u64 = 100_000_000;

/// The bench's send bundle, as the firmware's tests have it.
const PSKB_SEND: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/vectors/v107/site/pskb_send.bin"
));

fn profile() -> Profile {
    Profile::esp32s3()
}

fn descriptor() -> String {
    format!("multi_hd45(2,{ABANDON12_KPUB45},{ABANDON24_KPUB45},{ZOO12_KPUB45})")
}

fn coin(n: u8, amount: u64) -> Coin {
    Coin::new(&hex(&[n; 32]), u32::from(n), amount).unwrap()
}

/// **The profile and the helpers say what the SDK says.**
#[test]
fn the_profile_is_the_sdks() {
    let p = profile();
    let s = kassigner_sdk::Profile::ESP32S3;
    assert_eq!(p.max_inputs() as usize, s.max_inputs);
    assert_eq!(p.max_outputs() as usize, s.max_outputs);
    assert_eq!(p.max_frames() as usize, s.max_frames);
    assert_eq!(p.max_reassembled() as usize, s.max_reassembled);
    assert_eq!(p.max_sigs_per_input() as usize, s.max_sigs_per_input);
    assert_eq!(p.max_redeem() as usize, s.max_redeem);
    assert_eq!(
        Rates::mainnet().inner(),
        &kassigner_kaspa::mass::MassRates::MAINNET
    );
    assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(hex(&[0xde, 0xad]), "dead");
    assert_eq!(unhex::<2>("DEAD"), Ok([0xde, 0xad]));
    assert!(unhex::<2>("dea").is_err());
    assert!(unhex::<2>("zzzz").is_err());
    assert_eq!(
        Fault::of(kassigner_sdk::request::RequestError::Insufficient { have: 5, need: 7 }),
        Fault("Insufficient { have: 5, need: 7 }".to_string())
    );
}

/// **Hex is read as bytes**: a character of more than one byte is refused,
/// not a panic, and a sign is not a digit.
#[test]
fn the_hex_reader_refuses_what_is_not_hex() {
    assert_eq!(unhex::<2>("0fA0"), Ok([0x0f, 0xa0]));
    assert_eq!(unhex::<2>(" 0fa0\n"), Ok([0x0f, 0xa0]));
    assert_eq!(
        unhex::<2>("aéb"),
        Err(Fault("expected 2 bytes of hex, got other text".to_string()))
    );
    assert!(unhex::<32>(&"é".repeat(32)).is_err());
    assert_eq!(unhex::<1>("+f"), Err(Fault("not hex at 0".to_string())));
    assert_eq!(unhex::<2>("00-1"), Err(Fault("not hex at 2".to_string())));
}

/// **An import is read, and the types derive what the SDK derives.**
#[test]
fn imports_and_addresses_are_the_sdks() {
    let i = read_import(ABANDON12_KPUB44.as_bytes()).unwrap();
    assert_eq!(i.kind, "account");
    let a = i.account.unwrap();
    let sdk = kassigner_sdk::watch::Account::new(kpub::read(ABANDON12_KPUB44.as_bytes()).unwrap());
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = sdk.address(RECEIVE, 0, &mut out).unwrap();
    assert_eq!(a.address(RECEIVE, 0).unwrap().as_bytes(), &out[..n]);
    assert_eq!(a.script(CHANGE, 3).unwrap(), sdk.script(CHANGE, 3).unwrap());
    assert_eq!(
        a.public_key(RECEIVE, 1).unwrap(),
        hex(&sdk.public_key(RECEIVE, 1).unwrap())
    );
    assert!(a.address(RECEIVE, 0x8000_0000).is_err());
    assert_eq!(Account::from_kpub(ABANDON12_KPUB44).unwrap(), a);
    assert!(Account::from_kpub("kpubnonsense").is_err());

    let text = format!("[73c5da0a/45'/111111'/0']{ABANDON12_KPUB45}");
    let i = read_import(text.as_bytes()).unwrap();
    assert_eq!(i.kind, "cosigner");
    assert_eq!(i.fingerprint.as_deref(), Some("73c5da0a"));
    assert!(i.account.is_some());

    let line = descriptor();
    let i = read_import(format!("# the bench's group\n{line}\n").as_bytes()).unwrap();
    assert_eq!(i.kind, "descriptor");
    assert_eq!(i.descriptor.as_deref(), Some(line.as_str()));
    let g = i.group.unwrap();
    assert_eq!((g.required(), g.total()), (2, 3));
    let sdk_g = kassigner_sdk::watch::Group::from_descriptor(&line).unwrap();
    let n = kassigner_sdk::watch::group_address(&sdk_g, 0, RECEIVE, 0, &mut out).unwrap();
    assert_eq!(g.address(0, RECEIVE, 0).unwrap().as_bytes(), &out[..n]);
    let mut redeem = [0u8; kassigner_sdk::watch::MAX_REDEEM];
    let m = sdk_g.redeem(0, RECEIVE, 0, &mut redeem).unwrap();
    assert_eq!(g.redeem(0, RECEIVE, 0).unwrap(), &redeem[..m]);
    assert_eq!(
        g.script(0, RECEIVE, 0).unwrap(),
        kassigner_sdk::watch::group_script(&sdk_g, 0, RECEIVE, 0).unwrap()
    );
    assert_eq!(Group::from_descriptor(&g.descriptor().unwrap()).unwrap(), g);
    assert!(Group::from_descriptor("multi_hd45(2,kpubnonsense)").is_err());

    let i = read_import(format!("  {KCC3_ADDRESS}\n").as_bytes()).unwrap();
    assert_eq!(i.kind, "kcc3Address");
    let k = i.kcc3_address.unwrap();
    assert_eq!(k.text(), KCC3_ADDRESS);
    assert_eq!(k.script(), script_of_address(KCC3_ADDRESS).unwrap());
    assert_eq!(Kcc3Address::read(KCC3_ADDRESS).unwrap(), k);
    assert_eq!(address_of_script(&k.script()).unwrap(), KCC3_ADDRESS);
    assert!(address_of_script(&[0x51, 0x87]).is_err());

    assert_eq!(
        read_import(b"hello").unwrap_err(),
        Fault("NotRecognised".to_string())
    );
}

/// The bench's three requests through the builder: the 44' spend, the
/// group's, the 22' sweep.
fn the_three_requests() -> Vec<(RequestBuilder, u64)> {
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let g = Group::from_descriptor(&descriptor()).unwrap();
    let k = Kcc3Address::read(KCC3_ADDRESS).unwrap();
    let to_a1 = a.address(RECEIVE, 1).unwrap();
    let to_a0 = a.address(RECEIVE, 0).unwrap();

    let mut single = RequestBuilder::new();
    single.spend_account(&a, RECEIVE, 0, &coin(1, 3 * KAS));
    single.spend_account(&a, CHANGE, 3, &coin(2, 2 * KAS));
    single.pay(&to_a1, 4 * KAS).unwrap();
    single.change_to_account(&a, CHANGE, 4);

    let mut multisig = RequestBuilder::new();
    multisig.spend_group(&g, 0, RECEIVE, 0, &coin(3, 10 * KAS));
    multisig.pay_script(&a.script(RECEIVE, 1).unwrap(), 7 * KAS);
    multisig.change_to_group(&g, 0, CHANGE, 0);

    let mut sweep = RequestBuilder::new();
    sweep.spend_kcc3(&k, &coin(4, 5 * KAS), None, None).unwrap();
    sweep
        .spend_kcc3(&k, &coin(5, KAS / 2), Some(RECEIVE), Some(0))
        .unwrap();
    sweep.sweep_to(&to_a0).unwrap();

    vec![
        (single, 5 * KAS),
        (multisig, 10 * KAS),
        (sweep, 5 * KAS + KAS / 2),
    ]
}

/// **The builder builds what the SDK builds, and refuses what it
/// refuses**, by the SDK's names; a coin past the search depth is built
/// with its hint.
#[test]
fn the_builder_builds_the_three_requests() {
    let p = profile();
    let rates = Rates::mainnet();
    for (k, (builder, have)) in the_three_requests().iter().enumerate() {
        let r = builder.build(100, &rates, &p).unwrap();
        assert_eq!(r.fee, minimum_relay_fee(r.mass), "{k}: the minimum rate");
        let s = summary(&r.bytes, &p).unwrap();
        assert_eq!(s.total_in, *have, "{k}");
        assert_eq!(s.total_out + r.fee, *have, "{k}: the values balance");
        assert_eq!(s.fee(), r.fee);
        assert_eq!(s.signatures, 0);
        assert_eq!(s.outpoints.len(), s.inputs as usize);
        assert!(s.outputs.iter().all(|o| o.address.is_some()), "{k}");
        match k {
            0 => assert_eq!(
                (r.signatures, r.change, s.outputs.len()),
                (2, Some(KAS - r.fee), 2)
            ),
            1 => assert_eq!(
                (r.signatures, r.change, s.outputs.len()),
                (2, Some(3 * KAS - r.fee), 2)
            ),
            _ => assert_eq!((r.signatures, r.change, s.outputs.len()), (2, None, 1)),
        }
        let higher = builder.build(10_000, &rates, &p).unwrap();
        assert!(higher.fee > r.fee, "{k}: a higher rate pays more");
    }
    assert_eq!(
        RequestBuilder::new().build(100, &rates, &p).unwrap_err(),
        Fault("Empty".to_string())
    );
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mut deep = RequestBuilder::new();
    deep.spend_account(&a, RECEIVE, 1000, &coin(1, KAS));
    deep.pay(&a.address(RECEIVE, 0).unwrap(), KAS / 2).unwrap();
    assert!(deep.build(100, &rates, &p).is_ok());
    let mut poor = RequestBuilder::new();
    poor.spend_account(&a, RECEIVE, 0, &coin(1, KAS));
    poor.pay(&a.address(RECEIVE, 0).unwrap(), 2 * KAS).unwrap();
    assert!(poor
        .build(100, &rates, &p)
        .unwrap_err()
        .0
        .starts_with("Insufficient { have: 100000000, need: 2"));
    let mut hinted = RequestBuilder::new();
    let k = Kcc3Address::read(KCC3_ADDRESS).unwrap();
    assert!(hinted.spend_kcc3(&k, &coin(1, KAS), Some(0), None).is_err());
    assert!(Coin::new("abcd", 0, 1).is_err());
    let c = coin(7, 9);
    assert_eq!((c.tx_id(), c.index(), c.amount()), (hex(&[7; 32]), 7, 9));
}

/// A matrix drawn at `scale` pixels a module with a quiet zone, gray.
fn rasterize(
    m: &kassigner_sdk_host::transport::Matrix,
    scale: usize,
    quiet: usize,
) -> (usize, Vec<u8>) {
    let n = usize::from(m.size);
    let side = (n + 2 * quiet) * scale;
    let mut px = vec![0xFFu8; side * side];
    for y in 0..n {
        for x in 0..n {
            if m.dark(x as u8, y as u8) {
                for dy in 0..scale {
                    for dx in 0..scale {
                        px[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    (side, px)
}

/// **The codes are the SDK's plan, each decodes with the unit's decoder,
/// and a reader fed them last first, twice over, collects the payload.**
#[test]
fn codes_round_trip_through_the_reader_and_the_decoder() {
    let p = profile();
    let rates = Rates::mainnet();
    for (builder, _) in the_three_requests() {
        let bytes = builder.build(100, &rates, &p).unwrap().bytes;
        let c = codes(&bytes, "kspt", &p).unwrap();
        let plan = SdkCodes::plan(bytes.len(), p.inner()).unwrap();
        assert_eq!(
            (c.frames() as usize, c.version(), c.bare(), c.period_ms()),
            (plan.frames, plan.version, plan.bare, plan.period_ms())
        );
        assert!(c.bytes(c.frames()).is_err(), "past the plan");
        let mut reader = Reader::new(&p, 225);
        let order: Vec<u32> = (0..c.frames()).rev().chain(0..c.frames()).collect();
        let mut whole = false;
        let mut held = 0u64;
        for (k, i) in order.iter().enumerate() {
            let frame = c.bytes(*i).unwrap();
            let m = c.matrix(*i).unwrap();
            assert_eq!(m.modules.len(), usize::from(m.size) * usize::from(m.size));
            let svg = c.svg(*i, 4).unwrap();
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
            let (side, mut px) = rasterize(&m, 4, 4);
            let decoded = decode_qr(&px, side as u32, side as u32, 8)
                .unwrap()
                .expect("the decoder reads it");
            assert_eq!(decoded, frame, "frame {i} decodes to its bytes");
            px.fill(0x80);
            assert_eq!(
                decode_qr(&px, side as u32, side as u32, 8).unwrap(),
                None,
                "a blank frame"
            );
            let t = reader.take(&frame).unwrap();
            held |= 1 << i;
            let want = if c.bare() { 0 } else { held };
            assert_eq!(reader.received(), want, "frame {i} is in");
            if k + 1 == c.frames() as usize {
                assert_eq!(
                    (t.status, t.length as usize, t.whole()),
                    ("whole", bytes.len(), true)
                );
                whole = true;
            } else if k + 1 < c.frames() as usize {
                assert_eq!(
                    (t.status, t.have as usize, t.need as usize),
                    ("partial", k + 1, plan.frames)
                );
            } else {
                assert_eq!(t.status, "nothing");
            }
            assert_eq!(reader.format().as_deref(), Some("kspt"));
        }
        assert!(whole);
        assert_eq!(reader.collect().unwrap(), bytes);
        reader.reset();
        assert_eq!(reader.format(), None);
        assert_eq!(reader.received(), 0, "a reset forgets them");
        assert_eq!(reader.take(b"hello").unwrap().status, "notAReply");
        assert!(
            reader.collect().is_err(),
            "nothing to collect after a reset"
        );
    }
    assert!(codes(&[], "kspt", &p).is_err());
    assert!(codes(b"x", "nonsense", &p).is_err());
    assert!(
        decode_qr(&[0; 16], 4, 5, 8).is_err(),
        "fewer pixels than the sides say"
    );
}

/// **A text's codes and the unit's rule for a text.**
#[test]
fn a_text_is_planned_as_the_sdk_plans_it() {
    let p = profile();
    assert!(is_text("hello, unit"));
    assert!(!is_text(""));
    assert!(!is_text("tab\there"));
    assert!(!is_text("hello, unit "));
    assert!(!is_text("hello, unit\n"));
    let c = message_codes("hello, unit", &p).unwrap();
    assert_eq!((c.frames(), c.bare()), (1, true));
    assert_eq!(c.bytes(0).unwrap(), b"hello, unit");
    let long = "x".repeat(1000);
    let c = message_codes(&long, &p).unwrap();
    assert!(c.frames() > 1 && !c.bare());
    assert_eq!(
        message_codes("", &p).unwrap_err(),
        Fault("NotText".to_string())
    );
    for text in ["hello, unit ", "hello \nunit", "hello, unit\r\n"] {
        assert_eq!(
            message_codes(text, &p).unwrap_err(),
            Fault("TrailingWhitespace".to_string())
        );
    }
}

/// **A bundle is prepared with its hint**, as the SDK writes it; a hint for
/// an input the bundle lacks is refused.
#[test]
fn a_bundle_is_prepared_with_its_hint() {
    let p = profile();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mut hints = Hints::new();
    hints
        .account(0, &a, RECEIVE, 0, Some("73c5da0a".to_string()))
        .unwrap();
    let r = prepare_bundle(PSKB_SEND, &hints, &p).unwrap();
    assert_eq!((r.inputs, r.signatures), (1, 1));
    let text = r.text();
    assert!(text.starts_with("PSKB"));
    let mut doc = vec![0u8; text.len()];
    let n = kassigner_kaspa::pskb::decode_envelope(text.as_bytes(), &mut doc).unwrap();
    let doc = String::from_utf8_lossy(&doc[..n]);
    assert!(
        doc.contains("\"keyFingerprint\":\"73c5da0a\",\"derivationPath\":\"m/44'/111111'/0'/0/0\"")
    );
    let c = codes(&r.bytes, "pskb", &p).unwrap();
    assert!(c.frames() > 1);

    let mut wrong = Hints::new();
    wrong.account(3, &a, RECEIVE, 0, None).unwrap();
    assert_eq!(
        prepare_bundle(PSKB_SEND, &wrong, &p).unwrap_err(),
        Fault("Hint { input: 3 }".to_string())
    );
    let g = Group::from_descriptor(&descriptor()).unwrap();
    let mut group_hint = Hints::new();
    assert!(group_hint
        .group(0, &g, 0, RECEIVE, 0, vec!["zz".to_string()])
        .is_err());
    group_hint
        .group(
            0,
            &g,
            0,
            RECEIVE,
            0,
            vec!["73c5da0a".to_string(), String::new()],
        )
        .unwrap();
}

// ── The reply side, over the SDK's vectors ──────────────────────────────────

/// A file of `spec/vectors/v110/sdk/`.
fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../spec/vectors/v110/sdk/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// **A unit's replies are read, merged and finished as by the SDK**, KSPT
/// and bundle; a reply against another request is refused by name.
#[test]
fn replies_go_through_the_host_layer() {
    use kassigner_sdk_host::bundle::{finalize_bundle, merge_bundles, read_bundle};
    use kassigner_sdk_host::reply::{finalize_reply, merge_replies, read_reply};
    let p = profile();
    let rates = Rates::mainnet();

    let (req, rep) = (vector("single.request"), vector("single.reply.abandon12"));
    let c = read_reply(&req, &rep, &p).unwrap();
    assert_eq!((c.signatures, c.present, c.complete), (2, None, true));
    let f = finalize_reply(&req, &rep, false, &rates, &p).unwrap();
    assert_eq!(f.id.len(), 64);
    assert_eq!(f.fee, summary(&rep, &p).unwrap().fee());
    assert!(f
        .submit_json
        .contains(&format!("\"mass\":{}", f.storage_mass)));
    assert!(f.rest_json.contains("\"amount\":400000000"));
    assert_eq!(f.unlocks.len(), 2);
    assert_eq!(
        read_reply(&vector("sweep.request"), &rep, &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );
    assert_eq!(
        finalize_reply(&vector("sweep.request"), &rep, false, &rates, &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );

    let req = vector("multisig.request");
    let (first, second) = (
        vector("multisig.reply.abandon12"),
        vector("multisig.reply.zoo12"),
    );
    let c = read_reply(&req, &first, &p).unwrap();
    assert_eq!(
        (c.present, c.required, c.complete),
        (Some(1), Some(2), false)
    );
    assert_eq!(
        finalize_reply(&req, &first, false, &rates, &p).unwrap_err(),
        Fault("Signatures { input: 0, have: 1, need: 2 }".to_string())
    );
    let merged = merge_replies(&req, &[&first, &second], &p).unwrap();
    let c = read_reply(&req, &merged, &p).unwrap();
    assert_eq!((c.present, c.complete), (Some(2), true));
    let f = finalize_reply(&req, &merged, false, &rates, &p).unwrap();
    assert_eq!(f.unlocks.len(), 1);
    assert!(
        f.unlocks[0].len() > 2 * 132,
        "two signatures and the redeem"
    );

    let (req, rep) = (vector("sweep.request"), vector("sweep.reply.abandon12"));
    assert!(read_reply(&req, &rep, &p).unwrap().complete);
    let f = finalize_reply(&req, &rep, false, &rates, &p).unwrap();
    assert!(f.unlocks.iter().all(|u| u.len() == 2 * (66 + 35)));

    let (req, rep) = (
        vector("pskb_send.request"),
        vector("pskb_send.reply.abandon12"),
    );
    assert!(read_bundle(&req, &rep, &p).unwrap().complete);
    let f = finalize_bundle(&req, &rep, false, &rates, &p).unwrap();
    assert_eq!(f.fee, 10_000_000);
    assert_eq!(
        finalize_bundle(&vector("pskb_multisig.request"), &rep, false, &rates, &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );
    let req = vector("pskb_multisig.request");
    let (first, second) = (
        vector("pskb_multisig.reply.abandon12"),
        vector("pskb_multisig.reply.zoo12"),
    );
    assert!(!read_bundle(&req, &first, &p).unwrap().complete);
    let merged = merge_bundles(&req, &[&first, &second], &p).unwrap();
    assert!(read_bundle(&req, &merged, &p).unwrap().complete);
    finalize_bundle(&req, &merged, false, &rates, &p).unwrap();

    let record = vector("message.record");
    let v = kassigner_sdk_host::message::verify_message(&record).unwrap();
    assert_eq!(v.record.text, "kassigner.org login");
    kassigner_sdk_host::message::verify_message_against(
        &record,
        "kassigner.org login",
        &v.record.address,
    )
    .unwrap();
    let i = read_import(&record).unwrap();
    assert_eq!(i.kind, "signedMessage");
}

/// **A request built as a bundle or in the safe JSON is the SDK's**, byte
/// for byte, and finishes to the KSPT's transaction. A coin without its
/// entry is refused by name.
#[test]
fn the_builder_builds_a_bundle() {
    use kassigner_sdk_host::bundle::{finalize_bundle, merge_bundles, read_bundle};
    use kassigner_sdk_host::reply::{finalize_reply, finalize_safe_json, merge_replies};
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let g = Group::from_descriptor(&descriptor()).unwrap();
    let with_entry = Coin::with_entry(&hex(&[3; 32]), 3, 10 * KAS, 90_000_003, false).unwrap();
    assert_eq!(
        (with_entry.block_daa_score(), with_entry.is_coinbase()),
        (Some(90_000_003), Some(false))
    );
    assert_eq!(
        (coin(3, KAS).block_daa_score(), coin(3, KAS).is_coinbase()),
        (None, None)
    );
    let mut b = RequestBuilder::new();
    b.spend_group(&g, 0, RECEIVE, 0, &with_entry);
    b.pay_script(&a.script(RECEIVE, 1).unwrap(), 7 * KAS);
    b.change_to_group(&g, 0, CHANGE, 0);
    let kspt = b.build(100, &rates, &p).unwrap();
    let bundle = b.build_bundle(100, &rates, &p).unwrap();
    assert_eq!(kspt.bytes, vector("multisig.request"));
    assert_eq!(bundle.bytes, vector("multisig.bundle"));
    assert_eq!(
        (bundle.fee, bundle.mass, bundle.change, bundle.signatures),
        (kspt.fee, kspt.mass, kspt.change, kspt.signatures)
    );

    let (first, second) = (
        vector("multisig.bundle.reply.abandon12"),
        vector("multisig.bundle.reply.zoo12"),
    );
    assert!(!read_bundle(&bundle.bytes, &first, &p).unwrap().complete);
    let merged = merge_bundles(&bundle.bytes, &[&first, &second], &p).unwrap();
    assert!(read_bundle(&bundle.bytes, &merged, &p).unwrap().complete);
    let from_bundle = finalize_bundle(&bundle.bytes, &merged, false, &rates, &p).unwrap();
    let from_kspt = finalize_reply(
        &kspt.bytes,
        &merge_replies(
            &kspt.bytes,
            &[
                &vector("multisig.reply.abandon12"),
                &vector("multisig.reply.zoo12"),
            ],
            &p,
        )
        .unwrap(),
        false,
        &rates,
        &p,
    )
    .unwrap();
    assert_eq!(from_bundle.id, from_kspt.id, "the same transaction");
    assert_eq!(from_bundle.submit_json, from_kspt.submit_json);

    let safe = b.build_safe_json(100, &rates, &p).unwrap();
    assert_eq!(safe.bytes, vector("multisig.safe.json"));
    assert_eq!(
        (safe.fee, safe.mass, safe.change),
        (kspt.fee, kspt.mass, kspt.change)
    );
    let signed = String::from_utf8(vector("multisig.safe.signed.json")).unwrap();
    let from_safe = finalize_safe_json(&safe.text(), &signed, false, &rates, &p).unwrap();
    assert_eq!(from_safe.id, from_kspt.id, "the same transaction");
    assert_eq!(from_safe.submit_json, from_kspt.submit_json);
    assert_eq!(
        finalize_safe_json(&safe.text(), &safe.text(), false, &rates, &p).unwrap_err(),
        Fault("Unsigned { input: 0 }".to_string())
    );

    let mut bare = RequestBuilder::new();
    bare.spend_group(&g, 0, RECEIVE, 0, &coin(3, 10 * KAS));
    bare.pay_script(&a.script(RECEIVE, 1).unwrap(), 7 * KAS);
    assert!(bare.build(100, &rates, &p).is_ok());
    assert_eq!(
        bare.build_bundle(100, &rates, &p).unwrap_err(),
        Fault("NoEntry { coin: 0 }".to_string())
    );
    assert_eq!(
        bare.build_safe_json(100, &rates, &p).unwrap_err(),
        Fault("NoEntry { coin: 0 }".to_string())
    );
}

/// **An own receive address is paid with its place**: the transaction
/// `pay` makes, with the output's `0x48` record and bundle path past the
/// keys the unit searches by itself. A hardened index is refused.
#[test]
fn the_builder_pays_an_own_receive_address() {
    use kassigner_protocol::kspt::{self, AccountHint, Record};
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let coin = Coin::with_entry(&hex(&[1; 32]), 1, 3 * KAS, 90_000_001, false).unwrap();
    let builder = |own: bool, index: u32| {
        let mut b = RequestBuilder::new();
        b.spend_account(&a, RECEIVE, 0, &coin);
        if own {
            b.pay_account(&a, index, KAS).unwrap();
        } else {
            b.pay(&a.address(RECEIVE, index).unwrap(), KAS).unwrap();
        }
        b.change_to_account(&a, CHANGE, 2);
        b
    };

    let (own, plain) = (builder(true, 777), builder(false, 777));
    let (r, q) = (
        own.build(100, &rates, &p).unwrap(),
        plain.build(100, &rates, &p).unwrap(),
    );
    assert_eq!((r.fee, r.mass, r.change), (q.fee, q.mass, q.change));
    assert_eq!(
        summary(&r.bytes, &p).unwrap(),
        summary(&q.bytes, &p).unwrap(),
        "the same transaction"
    );
    let records: Vec<_> = kspt::parse(&r.bytes, p.inner())
        .unwrap()
        .records()
        .collect();
    assert_eq!(
        records,
        [Record::AccountOutputHint(AccountHint {
            index: 0,
            chain: RECEIVE,
            addr_index: 777
        })]
    );
    let bundle = own.build_bundle(100, &rates, &p).unwrap();
    assert_eq!(bundle.fee, r.fee);
    let mut doc = vec![0u8; bundle.bytes.len()];
    let n = kassigner_kaspa::pskb::decode_envelope(&bundle.bytes, &mut doc).unwrap();
    let doc = String::from_utf8(doc[..n].to_vec()).unwrap();
    assert!(doc.contains("\"derivationPath\":\"m/44'/111111'/0'/0/777\""));

    assert_eq!(
        builder(true, 3).build(100, &rates, &p).unwrap().bytes,
        builder(false, 3).build(100, &rates, &p).unwrap().bytes,
        "the bank's: nothing more"
    );
    assert!(RequestBuilder::new()
        .pay_account(&a, 0x8000_0003, KAS)
        .is_err());
}

/// **A mining reward is spent once it has matured**, in every format; with
/// no DAA score given, nothing is checked.
#[test]
fn a_mining_reward_is_spent_once_it_has_matured() {
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mined = 90_000_000;
    let reward = Coin::with_entry(&hex(&[1; 32]), 1, 3 * KAS, mined, true).unwrap();
    let paid = Coin::with_entry(&hex(&[2; 32]), 2, 3 * KAS, mined, false).unwrap();
    assert_eq!(reward.spendable_at(mined + 999), Some(false));
    assert_eq!(reward.spendable_at(mined + 1_000), Some(true));
    assert_eq!(paid.spendable_at(mined), Some(true));
    assert_eq!(coin(3, KAS).spendable_at(mined), None);

    let builder = |c: &Coin, daa: Option<u64>| {
        let mut b = RequestBuilder::new();
        b.spend_account(&a, RECEIVE, 0, &coin(3, KAS));
        b.spend_account(&a, RECEIVE, 0, c);
        b.pay(&a.address(RECEIVE, 1).unwrap(), KAS).unwrap();
        b.change_to_account(&a, CHANGE, 0);
        if let Some(d) = daa {
            b.at_daa_score(d);
        }
        b
    };
    let young = builder(&reward, Some(mined + 999));
    let refused = Fault("ImmatureCoinbase { coin: 1 }".to_string());
    assert_eq!(young.build(100, &rates, &p).err(), Some(refused.clone()));
    assert_eq!(
        young.build_bundle(100, &rates, &p).err(),
        Some(refused.clone())
    );
    assert_eq!(young.build_safe_json(100, &rates, &p).err(), Some(refused));

    let at = |c: &Coin, daa: Option<u64>| builder(c, daa).build(100, &rates, &p).unwrap().bytes;
    let unchecked = at(&reward, None);
    assert_eq!(at(&reward, Some(mined + 1_000)), unchecked, "matured");
    assert!(builder(&paid, Some(mined)).build(100, &rates, &p).is_ok());
}

/// **A lock time is set on the builder and read back**, at the same fee;
/// a new builder's is zero.
#[test]
fn the_builder_sets_a_lock_time() {
    use kassigner_sdk_host::bundle::bundle_summary;
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let coin = Coin::with_entry(&hex(&[1; 32]), 1, 3 * KAS, 90_000_001, false).unwrap();
    let mut b = RequestBuilder::new();
    b.spend_account(&a, RECEIVE, 0, &coin);
    b.pay(&a.address(RECEIVE, 1).unwrap(), KAS).unwrap();
    b.change_to_account(&a, CHANGE, 0);
    let plain = b.build(100, &rates, &p).unwrap();
    assert_eq!(summary(&plain.bytes, &p).unwrap().lock_time, 0);
    for lock in [412_345_678, 1_798_761_599_000] {
        b.lock_until(lock);
        let r = b.build(100, &rates, &p).unwrap();
        assert_eq!(
            (r.fee, r.mass, r.change),
            (plain.fee, plain.mass, plain.change)
        );
        assert_eq!(summary(&r.bytes, &p).unwrap().lock_time, lock);
        let bundle = b.build_bundle(100, &rates, &p).unwrap();
        assert_eq!(bundle_summary(&bundle.bytes, &p).unwrap().lock_time, lock);
    }
    b.lock_until(0);
    assert_eq!(b.build(100, &rates, &p).unwrap().bytes, plain.bytes);
}

/// **A coin bound to a covenant is left alone**: every build refuses it by
/// name.
#[test]
fn a_coin_bound_to_a_covenant_is_left_alone() {
    use kassigner_sdk_host::node::Utxo;
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let id = hex(&[0x5a; 32]);
    let listed = |covenant_id: Option<String>| Utxo {
        address: None,
        transaction_id: hex(&[2; 32]),
        index: 2,
        amount: 3 * KAS,
        script_version: 0,
        script: Vec::new(),
        block_daa_score: 90_000_002,
        is_coinbase: false,
        covenant_id,
    };
    let free = listed(None).coin().unwrap();
    let bound = listed(Some(id.clone())).coin().unwrap();
    assert_eq!(free.covenant_id(), None);
    assert_eq!(bound.covenant_id(), Some(id.clone()));
    assert_eq!(free.bound_to(&id).unwrap(), bound);
    assert!(free.bound_to("5a").is_err());
    assert!(listed(Some("5a".to_string())).coin().is_err());

    let first = Coin::with_entry(&hex(&[1; 32]), 1, 3 * KAS, 90_000_001, false).unwrap();
    let builder = |c: &Coin| {
        let mut b = RequestBuilder::new();
        b.spend_account(&a, RECEIVE, 0, &first);
        b.spend_account(&a, RECEIVE, 1, c);
        b.pay(&a.address(RECEIVE, 2).unwrap(), 4 * KAS).unwrap();
        b.change_to_account(&a, CHANGE, 0);
        b
    };
    assert!(builder(&free).build(100, &rates, &p).is_ok());
    assert!(builder(&free).build_bundle(100, &rates, &p).is_ok());
    assert!(builder(&free).build_safe_json(100, &rates, &p).is_ok());
    let refused = Some(Fault("CovenantBound { coin: 1 }".to_string()));
    assert_eq!(builder(&bound).build(100, &rates, &p).err(), refused);
    assert_eq!(builder(&bound).build_bundle(100, &rates, &p).err(), refused);
    assert_eq!(
        builder(&bound).build_safe_json(100, &rates, &p).err(),
        refused
    );
}

/// The script the bench's covenant outputs pay, as the SDK's tests have it.
fn covenant_script() -> Vec<u8> {
    kassigner_kaspa::script::pay_to_script_hash(&[0x77; 32]).to_vec()
}

/// The bench's covenant requests, as the SDK's vectors have them: two `44'`
/// coins of 1000 KAS (receive 1 and 2), `bound` the covenant coin 0 is
/// bound to, `outputs` outputs of 100 KAS to the covenant's script, change
/// to change 0.
fn covenant_builder(bound: Option<&str>, outputs: usize) -> RequestBuilder {
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let mut b = RequestBuilder::new();
    for n in [1u8, 2] {
        let mut c = Coin::with_entry(&hex(&[n; 32]), u32::from(n), 1000 * KAS, 0, false).unwrap();
        if let (1, Some(id)) = (n, bound) {
            c = c.bound_to(id).unwrap();
        }
        b.spend_account(&a, RECEIVE, u32::from(n), &c);
    }
    for _ in 0..outputs {
        b.pay_script(&covenant_script(), 100 * KAS);
    }
    b.change_to_account(&a, CHANGE, 0);
    b
}

/// **An output is bound to a covenant as the SDK binds it**: the builder's
/// `start_covenant` and `continue_covenant` make, byte for byte, the SDK's
/// own requests (its vectors), a group's too; `summary` reads the version
/// and each bound output's covenant back; the replies finish with every
/// input's compute budget.
#[test]
fn the_builder_binds_outputs_as_the_sdk_does() {
    use kassigner_sdk_host::reply::{finalize_reply, merge_replies};
    let p = profile();
    let rates = Rates::mainnet();
    let id = hex(&[0x5a; 32]);

    // A new covenant in the two first outputs, from coin 0.
    let mut start = covenant_builder(None, 2);
    start.start_covenant(0, 0).unwrap();
    start.start_covenant(1, 0).unwrap();
    let r = start.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes, vector("covenant.start.request"));
    let s = summary(&r.bytes, &p).unwrap();
    assert_eq!(s.version, 1);
    let made = s.outputs[0].covenant_id.clone().expect("bound");
    assert_eq!(made.len(), 64);
    let bindings: Vec<_> = s
        .outputs
        .iter()
        .map(|o| (o.covenant_id.clone(), o.authorizing_input))
        .collect();
    assert_eq!(
        bindings,
        [
            (Some(made.clone()), Some(0)),
            (Some(made), Some(0)),
            (None, None)
        ],
        "the change is not bound"
    );
    let f = finalize_reply(
        &r.bytes,
        &vector("covenant.start.reply.abandon12"),
        false,
        &rates,
        &p,
    )
    .unwrap();
    assert_eq!(f.fee, r.fee, "the fee the request found");
    assert_eq!(f.submit_json.matches("\"sigOpCount\":0").count(), 2);
    assert_eq!(f.submit_json.matches("\"computeBudget\":10").count(), 2);
    assert!(f.submit_json.contains("\"version\":1"));

    // The same outputs unbound: the plain request, version 0.
    let plain = covenant_builder(None, 2).build(100, &rates, &p).unwrap();
    let s = summary(&plain.bytes, &p).unwrap();
    assert_eq!(s.version, 0);
    assert!(s.outputs.iter().all(|o| o.covenant_id.is_none()));
    assert_eq!(r.fee - plain.fee, (2 * 2 + 2 * 34) * 100);

    // Coin 0's covenant continued in the first output.
    let mut go_on = covenant_builder(Some(&id), 1);
    go_on.continue_covenant(0, 0).unwrap();
    let r = go_on.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes, vector("covenant.continue.request"));
    let s = summary(&r.bytes, &p).unwrap();
    assert_eq!(
        (
            s.version,
            s.outputs[0].covenant_id.as_deref(),
            s.outputs[0].authorizing_input
        ),
        (1, Some(id.as_str()), Some(0))
    );
    let f = finalize_reply(
        &r.bytes,
        &vector("covenant.continue.reply.abandon12"),
        false,
        &rates,
        &p,
    )
    .unwrap();
    assert_eq!(f.fee, r.fee);

    // A group starts one: ten units of budget a key.
    let g = Group::from_descriptor(&descriptor()).unwrap();
    let mut group = RequestBuilder::new();
    group.spend_group(&g, 0, RECEIVE, 0, &coin(3, 1000 * KAS));
    group.pay_script(&covenant_script(), 100 * KAS);
    group.start_covenant(0, 0).unwrap();
    group.change_to_group(&g, 0, CHANGE, 0);
    let r = group.build(100, &rates, &p).unwrap();
    assert_eq!(r.bytes, vector("covenant.group.request"));
    let both = vector("covenant.group.reply.both");
    let merged = merge_replies(&r.bytes, &[&both], &p).unwrap();
    let f = finalize_reply(&r.bytes, &merged, false, &rates, &p).unwrap();
    assert_eq!(f.fee, r.fee);
    assert!(f.submit_json.contains("\"computeBudget\":30"));

    // The safe JSON carries it, version 1 with the budgets; a bundle
    // cannot.
    let safe = start.build_safe_json(100, &rates, &p).unwrap().text();
    assert!(safe.contains("\"version\":1"), "{safe}");
    assert_eq!(safe.matches("\"computeBudget\":10").count(), 2, "{safe}");
    assert_eq!(
        start.build_bundle(100, &rates, &p).err(),
        Some(Fault("CovenantInBundle".to_string()))
    );
    assert_eq!(
        go_on.build_bundle(100, &rates, &p).err(),
        Some(Fault("CovenantInBundle".to_string()))
    );
}

/// **A covenant ends only when the request says it may**, and a binding
/// names an output paid and a coin spent: the SDK's refusals by name.
#[test]
fn the_builder_refuses_covenants_as_the_sdk_does() {
    let p = profile();
    let rates = Rates::mainnet();
    let id = hex(&[0x5a; 32]);
    let fault = |text: &str| Some(Fault(text.to_string()));

    // A bound coin with no output continuing its covenant.
    let ends = covenant_builder(Some(&id), 1);
    let refused = fault("CovenantBound { coin: 0 }");
    assert_eq!(ends.build(100, &rates, &p).err(), refused);
    assert_eq!(ends.build_bundle(100, &rates, &p).err(), refused);
    assert_eq!(ends.build_safe_json(100, &rates, &p).err(), refused);
    // Starting another covenant does not keep it.
    let mut starts = ends.clone();
    starts.start_covenant(0, 0).unwrap();
    assert_eq!(starts.build(100, &rates, &p).err(), refused);
    // With the request's word it ends: version 0, the coin's covenant named
    // for the unit, as a KSPT, a bundle and the safe JSON.
    let mut may = ends.clone();
    may.end_covenants();
    let r = may.build(100, &rates, &p).unwrap();
    assert_eq!(summary(&r.bytes, &p).unwrap().version, 0);
    assert!(
        r.bytes.windows(32).any(|w| w == [0x5a; 32]),
        "the request names the covenant"
    );
    assert!(may.build_bundle(100, &rates, &p).is_ok());
    let safe = may.build_safe_json(100, &rates, &p).unwrap().text();
    assert!(safe.contains(&format!("\"covenantId\":\"{id}\"")), "{safe}");
    // Continued, nothing ends, and the word is not needed.
    let mut go_on = ends.clone();
    go_on.continue_covenant(0, 0).unwrap();
    assert!(go_on.build(100, &rates, &p).is_ok());

    // An output not paid yet, at once; a coin not spent, or bound to no
    // covenant, at the build.
    let mut b = covenant_builder(Some(&id), 1);
    assert_eq!(
        b.start_covenant(1, 0).err(),
        fault("BadBinding { output: 1 }")
    );
    assert_eq!(
        b.continue_covenant(7, 0).err(),
        fault("BadBinding { output: 7 }")
    );
    b.end_covenants();
    b.start_covenant(0, 2).unwrap();
    assert_eq!(
        b.build(100, &rates, &p).err(),
        fault("BadBinding { output: 0 }")
    );
    b.continue_covenant(0, 1).unwrap();
    assert_eq!(
        b.build(100, &rates, &p).err(),
        fault("BadBinding { output: 0 }")
    );
}

/// **A sweep to the wallet's own address is built with its place**: the
/// transaction `sweep_to` makes, with the account's `0x48` record or the
/// group's `0x45`. A hardened index is refused.
#[test]
fn the_builder_sweeps_to_its_own_address() {
    use kassigner_protocol::kspt::{self, AccountHint, Hint, Record};
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let g = Group::from_descriptor(&descriptor()).unwrap();
    let coin = Coin::with_entry(&hex(&[1; 32]), 1, 3 * KAS, 90_000_001, false).unwrap();
    // The output hints: a group's input carries its own besides.
    let records = |bytes: &[u8]| -> Vec<Record<'static>> {
        kspt::parse(bytes, p.inner())
            .unwrap()
            .records()
            .filter_map(|r| match r {
                Record::AccountOutputHint(h) => Some(Record::AccountOutputHint(h)),
                Record::OutputHint(h) => Some(Record::OutputHint(h)),
                _ => None,
            })
            .collect()
    };

    let mut own = RequestBuilder::new();
    own.spend_account(&a, RECEIVE, 0, &coin);
    own.sweep_to_account(&a, CHANGE, 560).unwrap();
    let mut plain = RequestBuilder::new();
    plain.spend_account(&a, RECEIVE, 0, &coin);
    plain.sweep_to(&a.address(CHANGE, 560).unwrap()).unwrap();
    let (r, q) = (
        own.build(100, &rates, &p).unwrap(),
        plain.build(100, &rates, &p).unwrap(),
    );
    assert_eq!((r.fee, r.mass, r.change), (q.fee, q.mass, None));
    assert_eq!(
        summary(&r.bytes, &p).unwrap(),
        summary(&q.bytes, &p).unwrap(),
        "the same transaction"
    );
    assert_eq!(
        records(&r.bytes),
        [Record::AccountOutputHint(AccountHint {
            index: 0,
            chain: CHANGE,
            addr_index: 560
        })]
    );
    let bundle = own.build_bundle(100, &rates, &p).unwrap();
    let mut doc = vec![0u8; bundle.bytes.len()];
    let n = kassigner_kaspa::pskb::decode_envelope(&bundle.bytes, &mut doc).unwrap();
    let doc = String::from_utf8(doc[..n].to_vec()).unwrap();
    assert!(doc.contains("\"derivationPath\":\"m/44'/111111'/0'/1/560\""));

    let mut vault = RequestBuilder::new();
    vault.spend_group(&g, 0, RECEIVE, 0, &coin);
    vault.sweep_to_group(&g, 0, CHANGE, 7).unwrap();
    let v = vault.build(100, &rates, &p).unwrap();
    assert_eq!(
        summary(&v.bytes, &p).unwrap().outputs[0].address,
        Some(g.address(0, CHANGE, 7).unwrap())
    );
    assert_eq!(
        records(&v.bytes),
        [Record::OutputHint(Hint {
            index: 0,
            cosigner: 0,
            chain: CHANGE,
            addr_index: 7
        })]
    );

    assert!(RequestBuilder::new()
        .sweep_to_account(&a, CHANGE, 0x8000_0001)
        .is_err());
}

/// **A transaction signed already goes through with no request**, as a
/// send saved to the SD card and broadcast later: read, merged and finished
/// as against its request, a cosigner in two copies held once. KSPT and
/// bundle alike.
#[test]
fn a_signed_transaction_goes_through_by_itself() {
    use kassigner_sdk_host::bundle::{
        bundle_summary, finalize_bundle, finalize_signed_bundle, merge_bundles,
        merge_signed_bundles, read_signed_bundle,
    };
    use kassigner_sdk_host::reply::{
        finalize_reply, finalize_signed_reply, merge_replies, merge_signed_replies,
        read_signed_reply,
    };
    let p = profile();
    let rates = Rates::mainnet();

    let (req, rep) = (vector("single.request"), vector("single.reply.abandon12"));
    let c = read_signed_reply(&rep, &p).unwrap();
    assert_eq!((c.signatures, c.present, c.complete), (2, None, true));
    assert_eq!(
        finalize_signed_reply(&rep, false, &rates, &p).unwrap(),
        finalize_reply(&req, &rep, false, &rates, &p).unwrap()
    );
    assert_eq!(
        read_signed_reply(&req, &p).unwrap_err(),
        Fault("Unverified(Nothing)".to_string())
    );

    let req = vector("multisig.request");
    let (first, second) = (
        vector("multisig.reply.abandon12"),
        vector("multisig.reply.zoo12"),
    );
    let c = read_signed_reply(&first, &p).unwrap();
    assert_eq!(
        (c.present, c.required, c.complete),
        (Some(1), Some(2), false)
    );
    assert_eq!(
        finalize_signed_reply(&first, false, &rates, &p).unwrap_err(),
        Fault("Signatures { input: 0, have: 1, need: 2 }".to_string())
    );
    let merged = merge_signed_replies(&[&first, &second], &p).unwrap();
    assert_eq!(merged, merge_replies(&req, &[&first, &second], &p).unwrap());
    assert_eq!(
        merge_signed_replies(&[&merged, &second], &p).unwrap(),
        merged
    );
    assert_eq!(
        merge_signed_replies(&[&second, &merged], &p).unwrap(),
        merged
    );
    assert!(merge_replies(&req, &[&merged, &second], &p)
        .unwrap_err()
        .0
        .starts_with("Merge("));
    assert_eq!(
        finalize_signed_reply(&merged, false, &rates, &p).unwrap(),
        finalize_reply(&req, &merged, false, &rates, &p).unwrap()
    );
    assert_eq!(
        merge_signed_replies(&[&first, &vector("single.reply.abandon12")], &p).unwrap_err(),
        Fault("NotTheRequest".to_string())
    );
    // A byte of the first copy's signature changed: the copy the others
    // are held to is verified too.
    let at = (0..req.len()).find(|&k| req[k] != first[k]).unwrap();
    let mut forged = first.clone();
    forged[at + 10] ^= 1;
    assert!(merge_signed_replies(&[&forged, &second], &p)
        .unwrap_err()
        .0
        .starts_with("Unverified("));

    let (req, rep) = (
        vector("pskb_send.request"),
        vector("pskb_send.reply.abandon12"),
    );
    assert!(read_signed_bundle(&rep, &p).unwrap().complete);
    assert_eq!(
        finalize_signed_bundle(&rep, false, &rates, &p).unwrap(),
        finalize_bundle(&req, &rep, false, &rates, &p).unwrap()
    );
    let s = bundle_summary(&rep, &p).unwrap();
    assert_eq!(s.fee(), 10_000_000);
    assert_eq!(s.signatures as usize, s.outpoints.len());
    assert_eq!(bundle_summary(&req, &p).unwrap().signatures, 0);

    let req = vector("pskb_multisig.request");
    let (first, second) = (
        vector("pskb_multisig.reply.abandon12"),
        vector("pskb_multisig.reply.zoo12"),
    );
    assert!(!read_signed_bundle(&first, &p).unwrap().complete);
    let merged = merge_signed_bundles(&[&first, &second], &p).unwrap();
    assert!(read_signed_bundle(&merged, &p).unwrap().complete);
    let finished = finalize_signed_bundle(&merged, false, &rates, &p).unwrap();
    let theirs = merge_bundles(&req, &[&first, &second], &p).unwrap();
    assert_eq!(
        finished,
        finalize_bundle(&req, &theirs, false, &rates, &p).unwrap()
    );
    let again = merge_signed_bundles(&[&merged, &second], &p).unwrap();
    assert_eq!(
        finalize_signed_bundle(&again, false, &rates, &p).unwrap(),
        finished
    );
    assert!(merge_bundles(&req, &[&merged, &second], &p).is_err());
    assert!(merge_signed_bundles(&[&first, &vector("pskb_send.reply.abandon12")], &p).is_err());
}

// ── A covenant card ─────────────────────────────────────────────────────────

/// **A Time-Locked Savings card goes through the host layer**: backed up
/// and read back, made again, its key found, its claim byte for byte the
/// SDK's and its replies finished; what the SDK refuses, refused by name.
#[test]
fn a_card_goes_through_the_host_layer() {
    use kassigner_sdk_host::bundle::finalize_bundle;
    use kassigner_sdk_host::card::{Card, CardSigner};
    use kassigner_sdk_host::reply::finalize_reply;
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let line = String::from_utf8(vector("savings.backup")).unwrap();
    let card = Card::from_backup(&line).unwrap();
    assert_eq!(card.backup().unwrap(), line);
    let recovery = card.recovery().unwrap();
    let again = Card::savings(
        &card.owner().unwrap(),
        recovery.as_deref(),
        card.unlock_day(),
        card.unlock_month(),
        card.unlock_year(),
        card.unlock_hour(),
        card.unlock_minute(),
    )
    .unwrap();
    assert_eq!(again, card);
    assert_eq!(
        (card.unlock_day(), card.unlock_month(), card.unlock_year()),
        (1, 1, 2027)
    );
    assert_eq!((card.unlock_hour(), card.unlock_minute()), (0, 0));
    assert_eq!(card.unlock_ms(), 1_798_761_600_000);
    let eve = Card::savings(&card.owner().unwrap(), None, 31, 12, 2026, 23, 59).unwrap();
    assert_eq!(
        (eve.unlock_day(), eve.unlock_month(), eve.unlock_year()),
        (31, 12, 2026)
    );
    assert_eq!((eve.unlock_hour(), eve.unlock_minute()), (23, 59));
    assert_eq!(eve.unlock_ms(), card.unlock_ms() - 60_000);
    assert_eq!(eve.recovery().unwrap(), None);
    assert!(eve.backup().unwrap().contains(",31/12/2026 23:59,"));
    assert_eq!(card.owner().unwrap(), a.address(RECEIVE, 0).unwrap());
    assert!(card.address().unwrap().starts_with("kaspa:p"));
    assert_eq!(card.script().len(), 35);
    assert_eq!(
        card.signer(&a, 20).unwrap(),
        Some(CardSigner {
            index: 0,
            recovers: false
        })
    );

    // The firmware tests' claim: two UTXOs, the first's key named, swept
    // at the card's minute.
    let to = summary(&vector("savings.request"), &p).unwrap().outputs[0]
        .address
        .clone()
        .unwrap();
    let first = Coin::with_entry(&hex(&[1; 32]), 1, 5 * KAS, 90_000_001, false).unwrap();
    let second = Coin::with_entry(&hex(&[2; 32]), 2, 3 * KAS, 90_000_002, false).unwrap();
    let mut b = RequestBuilder::new();
    b.lock_until(card.unlock_ms());
    b.spend_card(&card, &first, Some(&a), Some(0)).unwrap();
    b.spend_card(&card, &second, None, None).unwrap();
    b.sweep_to(&to).unwrap();
    let kspt = b.build(100, &rates, &p).unwrap();
    let bundle = b.build_bundle(100, &rates, &p).unwrap();
    assert_eq!(kspt.bytes, vector("savings.request"));
    assert_eq!(bundle.bytes, vector("savings.bundle"));
    for (seed, entry) in [("abandon12", "claim"), ("zoo12", "recover")] {
        let reply = vector(&format!("savings.reply.{seed}"));
        let f = finalize_reply(&kspt.bytes, &reply, false, &rates, &p).unwrap();
        let reply = vector(&format!("savings.bundle.reply.{seed}"));
        let fb = finalize_bundle(&bundle.bytes, &reply, false, &rates, &p).unwrap();
        assert_eq!(fb.id, f.id, "{seed}: the bundle's is the KSPT's");
        let signed = String::from_utf8(vector(&format!("savings.{entry}.signed.json"))).unwrap();
        assert!(
            signed.starts_with(&format!("{{\"id\":\"{}\"", f.id)),
            "{seed}: the transaction the SDK finished"
        );
        assert_eq!(f.unlocks.len(), 2);
        assert!(f.unlocks.iter().all(|u| u.len() == 2 * 231));
    }

    // Refused by name.
    let build = |b: &RequestBuilder| b.build(100, &rates, &p).unwrap_err();
    let mut early = RequestBuilder::new();
    early.lock_until(card.unlock_ms() - 1);
    early.spend_card(&card, &first, None, None).unwrap();
    early.sweep_to(&to).unwrap();
    assert_eq!(build(&early), Fault("CardLocked { coin: 0 }".to_string()));
    let mut wrong = RequestBuilder::new();
    wrong.lock_until(card.unlock_ms());
    wrong.spend_card(&card, &first, Some(&a), Some(3)).unwrap();
    wrong.sweep_to(&to).unwrap();
    assert_eq!(
        build(&wrong),
        Fault("NotTheCardsKey { coin: 0 }".to_string())
    );
    assert_eq!(
        b.build_safe_json(100, &rates, &p).unwrap_err(),
        Fault("CardInSafeJson { coin: 0 }".to_string())
    );
    assert!(RequestBuilder::new()
        .spend_card(&card, &first, Some(&a), None)
        .is_err());
    assert_eq!(
        Card::savings(&card.address().unwrap(), None, 1, 1, 2027, 0, 0).unwrap_err(),
        Fault("Owner(NotAKey)".to_string())
    );
    let owner = card.owner().unwrap();
    for (day, month, year, hour, minute) in [
        (29, 2, 2027, 0, 0),
        (257, 1, 2027, 0, 0),
        (1, 1, 2027, 24, 0),
        (1, 1, 2027, 0, 60),
        (1, 1, 2027, 256, 0),
        (5, 11, 1985, 0, 53),
    ] {
        assert_eq!(
            Card::savings(&owner, None, day, month, year, hour, minute).unwrap_err(),
            Fault("Date".to_string()),
            "{day}/{month}/{year} {hour}:{minute}"
        );
    }
    for bad in ["1/1/2027 00:00", "01/01/2027"] {
        assert_eq!(
            Card::from_backup(&line.replace("01/01/2027 00:00", bad)).unwrap_err(),
            Fault("BadDate".to_string()),
            "{bad}"
        );
    }
}

/// A reply that writes one cosigner's signature twice, the key repeated in its
/// `partialSigs`, must be refused, not read as two signatures. Upstream keeps
/// `partialSigs` as a map by key, so only a crafted or foreign bundle does
/// this; the reader refuses it with the reason the writer gives for the same
/// thing.
#[test]
fn a_reply_with_one_key_signed_twice_is_refused() {
    use kassigner_sdk_host::bundle::read_bundle;

    fn duplicate_first_partial_sig(reply: &[u8]) -> Vec<u8> {
        assert_eq!(&reply[..4], b"PSKB", "a PSKB envelope");
        let nibble = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("hex"),
        };
        let json: Vec<u8> = reply[4..]
            .chunks(2)
            .map(|c| (nibble(c[0]) << 4) | nibble(c[1]))
            .collect();
        let json = String::from_utf8(json).unwrap();
        let marker = "\"partialSigs\":{";
        let start = json.find(marker).unwrap() + marker.len();
        // The one member runs to the first "}}": the inner schnorr object's
        // close, then the map's. Keep the first brace, drop the second.
        let end = start + json[start..].find("}}").unwrap() + 1;
        let member = &json[start..end];
        let crafted = format!("{},{}{}", &json[..end], member, &json[end..]);
        let mut out = b"PSKB".to_vec();
        out.extend_from_slice(hex(crafted.as_bytes()).as_bytes());
        out
    }

    let p = profile();
    let request = vector("multisig.bundle");
    let honest = vector("multisig.bundle.reply.abandon12");

    // As written by one cosigner: one signature, not complete.
    let read = read_bundle(&request, &honest, &p).unwrap();
    assert_eq!((read.signatures, read.complete), (1, false));

    // The same member written a second time: refused, and not read as two.
    let crafted = duplicate_first_partial_sig(&honest);
    let err = read_bundle(&request, &crafted, &p).unwrap_err();
    assert!(format!("{err:?}").contains("SameKeyTwice"), "{err:?}");
}

/// **A request that spends one coin twice is refused**, in the three forms a
/// request is written in. A node refuses a transaction with an outpoint
/// spent twice and the unit refuses the request on arrival ("A UTXO is spent
/// twice"), so the builder must: it used to build it, the coin's amount
/// counted twice in the inputs.
#[test]
fn a_request_that_spends_one_coin_twice_is_refused() {
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let to = a.address(RECEIVE, 1).unwrap();
    let entry = |n: u8| Coin::with_entry(&hex(&[n; 32]), u32::from(n), 3 * KAS, 90_000_000, false);

    // The same outpoint twice, under two addresses' keys and with two
    // amounts: the outpoint alone makes it the same coin.
    let mut twice = RequestBuilder::new();
    twice.spend_account(&a, RECEIVE, 0, &entry(1).unwrap());
    twice.spend_account(&a, RECEIVE, 0, &entry(2).unwrap());
    twice.spend_account(
        &a,
        RECEIVE,
        5,
        &Coin::with_entry(&hex(&[1; 32]), 1, KAS, 90_000_000, false).unwrap(),
    );
    twice.pay(&to, KAS).unwrap();
    twice.change_to_account(&a, CHANGE, 0);
    let is_twice = |e: &str| e == "CoinTwice { coin: 2 }";
    let err = twice.build(100, &rates, &p).unwrap_err();
    assert!(is_twice(&err.0), "KSPT: {err:?}");
    let err = twice.build_bundle(100, &rates, &p).unwrap_err();
    assert!(is_twice(&err.0), "PSKB: {err:?}");
    let err = twice.build_safe_json(100, &rates, &p).unwrap_err();
    assert!(is_twice(&err.0), "safe JSON: {err:?}");

    // The same transaction's other output is another coin: both build.
    let mut ok = RequestBuilder::new();
    ok.spend_account(&a, RECEIVE, 0, &entry(1).unwrap());
    ok.spend_account(
        &a,
        RECEIVE,
        0,
        &Coin::with_entry(&hex(&[1; 32]), 2, 3 * KAS, 90_000_000, false).unwrap(),
    );
    ok.pay(&to, KAS).unwrap();
    ok.change_to_account(&a, CHANGE, 0);
    assert!(ok.build(100, &rates, &p).is_ok(), "two outputs of one tx");
}

/// **A request whose finished transaction is over the block storage limit is
/// refused**, change path and sweep path alike. The builder used to price the
/// fee on the change before the fee, or, for a sweep, on compute alone, and
/// never checked the real storage mass of the small output left; a node
/// refuses such a transaction, so the builder must too.
#[test]
fn a_request_over_the_block_storage_limit_is_refused() {
    let p = profile();
    let rates = Rates::mainnet();
    let a = Account::from_kpub(ABANDON12_KPUB44).unwrap();
    let k = Kcc3Address::read(KCC3_ADDRESS).unwrap();

    // A 0.25 KAS coin, a 0.1284 KAS payment, change kept: the fee priced on
    // the pre-fee change leaves a 0.0015 KAS change whose storage mass is far
    // over the limit. Refused on the final values.
    let mut change = RequestBuilder::new();
    change.spend_account(&a, RECEIVE, 0, &coin(1, 25_000_000));
    change
        .pay(&a.address(RECEIVE, 1).unwrap(), 12_840_000)
        .unwrap();
    change.change_to_account(&a, CHANGE, 0);
    let err = change.build(100, &rates, &p).unwrap_err();
    assert!(err.0.starts_with("StorageMass"), "change: {err:?}");

    // A sweep of the same coin at a rate that eats most of it: the one output
    // left is small enough that its storage mass is over the limit, and a
    // sweep is priced on compute alone, so nothing caught it before.
    let mut sweep = RequestBuilder::new();
    sweep
        .spend_kcc3(&k, &coin(2, 25_000_000), None, None)
        .unwrap();
    sweep.sweep_to(&a.address(RECEIVE, 0).unwrap()).unwrap();
    let err = sweep.build(15_000, &rates, &p).unwrap_err();
    assert!(err.0.starts_with("StorageMass"), "sweep: {err:?}");

    // A healthy send, a 1 KAS coin paying 0.5 KAS, still builds: its change
    // is large, so its storage mass stays well under the limit.
    let mut ok = RequestBuilder::new();
    ok.spend_account(&a, RECEIVE, 0, &coin(3, 100_000_000));
    ok.pay(&a.address(RECEIVE, 1).unwrap(), 50_000_000).unwrap();
    ok.change_to_account(&a, CHANGE, 0);
    assert!(
        ok.build(100, &rates, &p).is_ok(),
        "a healthy send still builds"
    );
}

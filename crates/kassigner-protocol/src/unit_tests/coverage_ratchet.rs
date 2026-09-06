use serde_json::{json, Value};

use crate::pskt::test_support::{
    document, encode, find_pubkey_position, parse_derivation, parse_ms45, parse_multisig_redeem,
    Format,
};
use crate::{
    decode_account, encode_pskt, merge_signed_kspt, AddressBranch, Network, ProtocolErrorKind,
    QrDecoder, SigningRequest,
};

#[test]
fn stable_enum_names_network_display_and_branch_codes_are_exhaustive() {
    let error_kinds = [
        (ProtocolErrorKind::MalformedRequest, "malformedRequest"),
        (ProtocolErrorKind::WrongNetwork, "wrongNetwork"),
        (
            ProtocolErrorKind::TransactionMismatch,
            "transactionMismatch",
        ),
        (ProtocolErrorKind::PairingMismatch, "pairingMismatch"),
        (ProtocolErrorKind::Qr, "qr"),
        (ProtocolErrorKind::Finalization, "finalization"),
        (ProtocolErrorKind::Derivation, "derivation"),
        (ProtocolErrorKind::Encoding, "encoding"),
        (ProtocolErrorKind::Decoding, "decoding"),
        (ProtocolErrorKind::Unsupported, "unsupported"),
        (ProtocolErrorKind::Internal, "internal"),
    ];
    for (kind, expected) in error_kinds {
        assert_eq!(kind.as_str(), expected);
    }

    let networks = [
        (Network::Mainnet, "mainnet", "kaspa", 1),
        (Network::Testnet10, "testnet-10", "kaspatest", 2),
        (Network::Testnet11, "testnet-11", "kaspatest", 2),
        (Network::Testnet12, "testnet-12", "kaspatest", 2),
        (Network::Devnet, "devnet", "kaspadev", 3),
        (Network::Simnet, "simnet", "kaspasim", 4),
    ];
    for (network, text, prefix, code) in networks {
        assert_eq!(network.to_string(), text);
        assert_eq!(Network::parse(text), Ok(network));
        assert_eq!(network.address_prefix(), prefix);
        assert_eq!(network.kspt_code(), code);
    }
    assert_eq!(AddressBranch::from_code(0), Ok(AddressBranch::Receive));
    assert_eq!(AddressBranch::from_code(1), Ok(AddressBranch::Change));
    assert_eq!(
        AddressBranch::from_code(2).unwrap_err().kind(),
        ProtocolErrorKind::Derivation
    );
}

#[test]
fn account_descriptor_accepts_canonical_raw_and_hex_wrapped_account_keys() {
    let (text, payload) = canonical_account_key();
    let descriptor = decode_account(&text, Network::Mainnet).expect("canonical account");
    assert_eq!(descriptor.receive_addresses.len(), 20);
    assert_eq!(descriptor.change_addresses.len(), 20);
    assert!(descriptor.receive_addresses[0]
        .address
        .starts_with("kaspa:"));

    let raw = decode_account(&hex::encode(payload), Network::Testnet10).expect("raw payload hex");
    assert!(raw.receive_addresses[0].address.starts_with("kaspatest:"));
    let wrapped = decode_account(&hex::encode(text.as_bytes()), Network::Devnet)
        .expect("hex-wrapped canonical text");
    assert!(wrapped.receive_addresses[0]
        .address
        .starts_with("kaspadev:"));
    assert!(decode_account("00", Network::Mainnet).is_err());
}

#[test]
fn relay_field_parsers_cover_multisig_positions_ms45_and_derivation_boundaries() {
    let redeem = multisig(&[0x11, 0x22, 0x33], 2);
    assert_eq!(parse_multisig_redeem(&redeem), Some((2, 3)));
    assert_eq!(
        parse_multisig_redeem(&multisig(&(1u8..=16).collect::<Vec<_>>(), 16)),
        Some((16, 16))
    );
    for invalid in [
        vec![],
        vec![0x50, 0x51, 0xae],
        vec![0x51, 0x20, 0x11, 0x51, 0xae],
        vec![0x52, 0x20, 0x11, 0x51, 0xae],
        {
            let mut value = multisig(&[0x11], 1);
            value[1] = 0x21;
            value
        },
        {
            let mut value = multisig(&[0x11], 1);
            *value.last_mut().unwrap() = 0xad;
            value
        },
    ] {
        assert_eq!(parse_multisig_redeem(&invalid), None);
    }
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "22".repeat(32))),
        Some(1)
    );
    assert_eq!(find_pubkey_position(&redeem, "00"), None);
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "zz".repeat(32))),
        None
    );
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "44".repeat(32))),
        None
    );
    let mut bad_push = redeem.clone();
    bad_push[1] = 0x21;
    assert_eq!(
        find_pubkey_position(&bad_push, &format!("02{}", "11".repeat(32))),
        None
    );

    assert_eq!(
        parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2/1/9"}})),
        Some((2, 1, 9))
    );
    assert_eq!(
        parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2/2/9"}})),
        None
    );
    assert_eq!(
        parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2'/1/9"}})),
        None
    );

    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": "7"}})),
        Some((0, 7))
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 1, "index": 8}})),
        Some((1, 8))
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 2, "index": 8}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 256, "index": 8}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": 0x8000_0000u64}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": u64::MAX}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": "not-a-number"}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": true}})),
        None
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"index": "7"}})),
        None
    );
    assert_eq!(parse_derivation(&json!({})), None);
}

#[test]
fn qr_raw_paths_and_signing_request_success_are_covered() {
    let mut decoder = QrDecoder::new();
    assert_eq!(
        decoder.accept(b"raw").expect("raw QR"),
        Some(b"raw".to_vec())
    );
    assert!(decoder
        .accept(&shared_signer::qr_frame::FRAME_MAGIC)
        .is_err());

    let frames = crate::encode_qr_frames(&vec![0x55; 240]).expect("multi-frame");
    assert!(decoder
        .accept(&frames[0].payload)
        .expect("session start")
        .is_none());
    assert!(decoder.accept(b"raw while active").is_err());
    decoder.reset();

    let request = SigningRequest::from_pskt(&base_pskb(json!({}), None), Network::Mainnet)
        .expect("signing request");
    assert!(!request.kspt_hex.is_empty());
    assert!(!request.qr_frames().is_empty());
}

#[test]
fn canonical_relay_and_merge_cover_multisig_metadata_and_signature_ordering() {
    let redeem = multisig(&[0x11, 0x22, 0x33], 2);
    let mut original_doc = base_document(json!({}), Some(&redeem));
    original_doc["inputs"][0]["proprietaries"] = json!({
        "kassignerDerivation": {"branch": 0, "index": "17"},
        "stealthTweak": "55".repeat(32)
    });
    original_doc["inputs"][0]["bip32Derivations"] = json!({
        "a": {"derivationPath": "m/45'/111111'/0'/2/0/17"}
    });
    original_doc["outputs"][0]["proprietaries"] = json!({
        "kassignerDerivation": {"branch": 1, "index": 18}
    });
    original_doc["outputs"][0]["bip32Derivations"] = json!({
        "b": {"derivationPath": "m/45'/111111'/0'/2/1/18"}
    });
    original_doc["outputs"][0]["covenantBinding"] = json!({
        "authorizingInput": 0,
        "covenantId": "66".repeat(32)
    });
    let original = encode_pskb(original_doc.clone());

    let mut signed_doc = original_doc;
    signed_doc["inputs"][0]["partialSigs"] = signatures(&[0x33, 0x11]);
    let signed_source = encode_pskb(signed_doc);
    let signed_kspt = encode_pskt(&signed_source, Network::Mainnet).expect("signed KSPT");
    let merged =
        merge_signed_kspt(&original, &signed_kspt, Network::Mainnet).expect("merge multisig");
    assert!(merge_signed_kspt(&original, b"BAD", Network::Mainnet).is_err());
    let (format, root) = crate::pskt::test_support::decode(&merged).expect("decode merged");
    let doc = document(&root, format).expect("merged document");
    assert_eq!(
        doc["inputs"][0]["partialSigs"].as_object().unwrap().len(),
        2
    );

    let p2pk_signed = base_pskb(signatures(&[0x11]), None);
    assert!(!encode_pskt(&p2pk_signed, Network::Mainnet)
        .expect("P2PK signatures")
        .is_empty());
    let invalid_redeem = base_pskb(signatures(&[0x11]), Some(&[0x51, 0xae]));
    assert!(!encode_pskt(&invalid_redeem, Network::Mainnet)
        .expect("specialized redeem relay")
        .is_empty());
}

fn canonical_account_key() -> (
    String,
    [u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN],
) {
    use shared_signer::account_key::{
        encode_account_key_text, ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH,
        ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_TEXT_LEN, ACCOUNT_KEY_VERSION,
    };
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = ACCOUNT_KEY_DEPTH;
    payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    payload[13..45].fill(0x11);
    payload[45..78].copy_from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ]);
    let mut encoded = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let length = encode_account_key_text(&payload, &mut encoded).expect("canonical key");
    (
        std::str::from_utf8(&encoded[..length]).unwrap().to_string(),
        payload,
    )
}

fn multisig(keys: &[u8], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&[*key; 32]);
    }
    script.push(0x50 + u8::try_from(keys.len()).unwrap());
    script.push(0xae);
    script
}

fn signatures(keys: &[u8]) -> Value {
    let mut map = serde_json::Map::new();
    for key in keys {
        map.insert(
            format!("02{}", format!("{key:02x}").repeat(32)),
            json!({"schnorr": "77".repeat(64)}),
        );
    }
    Value::Object(map)
}

fn base_document(partials: Value, redeem: Option<&[u8]>) -> Value {
    let input_script = if redeem.is_some() {
        format!("0000aa20{}87", "44".repeat(32))
    } else {
        format!("000020{}ac", "11".repeat(32))
    };
    json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": "0",
            "subnetworkId": "00".repeat(20),
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": {"transactionId": "22".repeat(32), "index": 0},
            "utxoEntry": {"amount": "100000", "scriptPublicKey": input_script},
            "sequence": "0",
            "sigOpCount": 1,
            "redeemScript": redeem.map(hex::encode),
            "partialSigs": partials,
            "proprietaries": {},
            "bip32Derivations": {}
        }],
        "outputs": [{
            "amount": "90000",
            "scriptPublicKey": format!("000020{}ac", "33".repeat(32)),
            "proprietaries": {},
            "bip32Derivations": {},
            "covenantBinding": null
        }]
    })
}

fn encode_pskb(document: Value) -> String {
    encode(Format::Pskb, &json!([document])).expect("encode PSKB")
}

fn base_pskb(partials: Value, redeem: Option<&[u8]>) -> String {
    encode_pskb(base_document(partials, redeem))
}

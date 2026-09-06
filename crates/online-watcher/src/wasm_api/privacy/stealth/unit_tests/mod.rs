use super::{payment::derive_stealth_payment, spend::prepare_stealth_spend_material};

fn metadata_hex() -> String {
    let generator = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    format!("{generator}{generator}")
}

#[test]
fn stealth_payment_derivation_covers_networks_entropy_and_metadata_errors() {
    let mainnet = derive_stealth_payment(&metadata_hex(), &"01".repeat(32), "mainnet").unwrap();
    assert!(mainnet.one_time_address.starts_with("kaspa:"));
    assert_ne!(mainnet.payment.ephemeral_pubkey, [0u8; 32]);

    let testnet = derive_stealth_payment(&metadata_hex(), &"02".repeat(32), "testnet-12").unwrap();
    assert!(testnet.one_time_address.starts_with("kaspatest:"));
    assert!(derive_stealth_payment("00", &"01".repeat(32), "mainnet").is_err());
    assert!(derive_stealth_payment(&metadata_hex(), "zz", "mainnet").is_err());
    assert!(derive_stealth_payment(&metadata_hex(), "00", "mainnet").is_err());
}

#[test]
fn stealth_spend_material_validates_both_fixed_width_values() {
    let material =
        prepare_stealth_spend_material(&"11".repeat(32), &"22".repeat(32), "testnet-10").unwrap();
    assert!(material.source_address.starts_with("kaspatest:"));
    assert_eq!(material.tweak_hex, "22".repeat(32));
    assert!(prepare_stealth_spend_material("00", &"22".repeat(32), "mainnet").is_err());
    assert!(prepare_stealth_spend_material(&"11".repeat(32), "zz", "mainnet").is_err());
}

fn canonical_account_text() -> String {
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
    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let length = encode_account_key_text(&payload, &mut text).unwrap();
    std::str::from_utf8(&text[..length]).unwrap().to_string()
}

#[test]
fn stealth_wasm_boundaries_cover_metadata_payment_announcement_and_preflight_errors() {
    use super::{
        meta::{stealth_announcement_address, stealth_generate_payment, stealth_meta_from_kpub},
        payment::stealth_create_payment_lane,
        spend::create_stealth_spend,
    };
    use crate::wasm_api::test_support::ready;

    let metadata = stealth_meta_from_kpub(&canonical_account_text()).expect("metadata");
    let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    let meta_address = metadata["meta_address"].as_str().unwrap();
    let payment =
        stealth_generate_payment(meta_address, &"01".repeat(32), "mainnet").expect("payment");
    let payment: serde_json::Value = serde_json::from_str(&payment).unwrap();
    assert!(payment["address"].as_str().unwrap().starts_with("kaspa:"));
    assert_eq!(payment["ephemeral_r"].as_str().unwrap().len(), 64);
    assert!(payment["stealth_index"].is_number());
    assert!(stealth_announcement_address("testnet-10").starts_with("kaspatest:"));

    assert!(stealth_meta_from_kpub("bad").is_err());
    assert!(stealth_generate_payment("00", "00", "mainnet").is_err());
    assert!(ready(stealth_create_payment_lane(
        "{}",
        meta_address,
        100_000_000,
        1,
        &"01".repeat(32),
        "ws://unused",
        "mainnet",
    ))
    .is_err());

    let wallet = crate::account::bip32::import_kpub(&canonical_account_text(), "kaspa")
        .expect("canonical stealth wallet");
    let wallet = serde_json::to_string(&wallet).expect("wallet JSON");
    let transport = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ready(stealth_create_payment_lane(
            &wallet,
            meta_address,
            100_000_000,
            1,
            &"03".repeat(32),
            "ws://unused",
            "mainnet",
        ))
    }));
    assert!(
        matches!(transport, Ok(Err(_)) | Err(_)),
        "native stealth transport boundary unexpectedly succeeded"
    );
    assert!(ready(create_stealth_spend(
        "00",
        "00",
        "bad",
        0,
        "ws://unused",
        "mainnet",
    ))
    .is_err());
}

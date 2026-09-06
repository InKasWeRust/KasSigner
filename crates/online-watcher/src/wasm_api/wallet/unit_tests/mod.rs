use super::watcher::{decode_preimage_query, find_preimage_in_raw_block};

#[test]
fn preimage_query_validation_rejects_bad_hex_and_lengths() {
    let (block, txid) = decode_preimage_query(&"11".repeat(32), &"22".repeat(32)).unwrap();
    assert_eq!(block, [0x11; 32]);
    assert_eq!(txid, [0x22; 32]);
    assert!(decode_preimage_query("zz", &"22".repeat(32)).is_err());
    assert!(decode_preimage_query(&"11".repeat(32), "00").is_err());
}

#[test]
fn raw_block_preimage_search_returns_empty_when_no_match_exists() {
    assert_eq!(find_preimage_in_raw_block(&[], &[0x33; 32]), "");
    assert_eq!(find_preimage_in_raw_block(&[0; 64], &[0x33; 32]), "");
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
    let length = encode_account_key_text(&payload, &mut text).expect("canonical key");
    std::str::from_utf8(&text[..length]).unwrap().to_string()
}

#[test]
fn wallet_key_exports_cover_payload_key_and_public_key_parsing() {
    let kpub = canonical_account_text();
    let payload_key =
        super::keys::derive_covenant_payload_key(&kpub).expect("covenant payload key");
    assert_eq!(payload_key.len(), 64);
    assert_ne!(payload_key, "00".repeat(32));

    let parsed = super::keys::parse_kpub(&kpub).expect("parsed account public key");
    let value: serde_json::Value = serde_json::from_str(&parsed).unwrap();
    assert_eq!(value["account_pubkey"].as_str().unwrap().len(), 64);
}

#[test]
fn wallet_account_and_address_wasm_boundaries_are_host_testable() {
    use super::{
        account::{extend_addresses, import_kpub, import_kpub_raw},
        address::{decode_address, encode_p2pk_address, encode_p2sh_address},
    };
    use shared_signer::account_key::{
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
    };

    let kpub = canonical_account_text();
    let imported = import_kpub(&kpub, "mainnet").expect("text import");
    let wallet: crate::account::bip32::WalletData = serde_json::from_str(&imported).unwrap();
    assert_eq!(wallet.receive_addresses.len(), 20);

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
    let raw = import_kpub_raw(&payload, "testnet-10").expect("raw import");
    let raw_wallet: crate::account::bip32::WalletData = serde_json::from_str(&raw).unwrap();
    assert!(raw_wallet.receive_addresses[0].starts_with("kaspatest:"));

    let extended = extend_addresses(&imported, 2, 3, "mainnet").expect("extend");
    let extended: crate::account::bip32::WalletData = serde_json::from_str(&extended).unwrap();
    assert_eq!(extended.receive_addresses.len(), 22);
    assert_eq!(extended.change_addresses.len(), 23);

    let p2pk = encode_p2pk_address(&"22".repeat(32), None).expect("p2pk");
    let p2sh = encode_p2sh_address(&"33".repeat(32), Some("testnet-10".into())).expect("p2sh");
    assert!(p2pk.starts_with("kaspa:"));
    assert!(p2sh.starts_with("kaspatest:"));
    let decoded = decode_address(&p2pk).expect("decode");
    assert!(decoded.contains("\"version\":0"));

    assert!(import_kpub("invalid", "mainnet").is_err());
    assert!(import_kpub_raw(&[0; 2], "mainnet").is_err());
    assert!(extend_addresses("{}", 1, 1, "mainnet").is_err());
    assert!(encode_p2pk_address("00", None).is_err());
    assert!(encode_p2sh_address("zz", None).is_err());
    assert!(decode_address("not-an-address").is_err());
}

#[test]
fn wallet_watcher_request_boundaries_and_preimage_errors_are_host_testable() {
    use super::{
        account::{fetch_balance, fetch_utxos, fetch_utxos_complete},
        watcher::{
            build_utxo_subscribe_request, build_vcc_subscribe_request, find_preimage_in_block,
        },
    };
    use crate::wasm_api::test_support::ready;

    assert!(!build_vcc_subscribe_request(7).unwrap().is_empty());
    let address = crate::account::address::encode_p2sh_address(&[0x44; 32], "kaspa");
    assert!(!build_utxo_subscribe_request(&address, 8)
        .unwrap()
        .is_empty());
    assert!(build_utxo_subscribe_request("bad", 8).is_err());

    assert!(ready(fetch_balance("{}", "ws://unused")).is_err());
    assert!(ready(fetch_utxos("{}", "ws://unused")).is_err());
    assert!(ready(fetch_utxos_complete("{}", "ws://unused")).is_err());
    assert!(ready(find_preimage_in_block(
        "zz",
        &"11".repeat(32),
        "ws://unused"
    ))
    .is_err());

    let valid_wallet = super::account::import_kpub(&canonical_account_text(), "mainnet")
        .expect("canonical watcher wallet");
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for outcome in [
        catch_unwind(AssertUnwindSafe(|| {
            ready(fetch_balance(&valid_wallet, "ws://unused"))
        })),
        catch_unwind(AssertUnwindSafe(|| {
            ready(fetch_utxos(&valid_wallet, "ws://unused"))
        })),
        catch_unwind(AssertUnwindSafe(|| {
            ready(fetch_utxos_complete(&valid_wallet, "ws://unused"))
        })),
    ] {
        assert!(
            matches!(outcome, Ok(Err(_)) | Err(_)),
            "native wallet transport boundary unexpectedly succeeded"
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wallet_watcher_network_wrappers_reach_native_transport_fail_closed() {
    use super::watcher::{fetch_utxos_for_address_js, get_fee_estimate, get_virtual_daa_score};
    use crate::wasm_api::test_support::ready;

    const ADDRESS: &str = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    assert!(ready(get_fee_estimate("ws://unused")).is_err());
    assert!(ready(fetch_utxos_for_address_js(ADDRESS, "ws://unused")).is_err());
    assert!(ready(get_virtual_daa_score("ws://unused")).is_err());
}

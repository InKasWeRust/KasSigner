use super::address::{
    address_to_script_pubkey, decode_address, encode_address, encode_p2pk_address,
    encode_p2sh_address,
};

#[test]
fn addresses_round_trip_for_every_network_and_script_family() {
    for prefix in ["kaspa", "kaspatest", "kaspasim", "kaspadev"] {
        let p2pk_payload = [0x11; 32];
        let p2pk = encode_p2pk_address(&p2pk_payload, prefix);
        assert_eq!(decode_address(&p2pk).unwrap(), (0, p2pk_payload));
        let p2pk_script = address_to_script_pubkey(&p2pk).unwrap();
        assert_eq!(p2pk_script.len(), 34);
        assert_eq!(p2pk_script[0], 0x20);
        assert_eq!(&p2pk_script[1..33], &p2pk_payload);
        assert_eq!(p2pk_script[33], 0xac);

        let p2sh_payload = [0x22; 32];
        let p2sh = encode_p2sh_address(&p2sh_payload, prefix);
        assert_eq!(decode_address(&p2sh).unwrap(), (8, p2sh_payload));
        let p2sh_script = address_to_script_pubkey(&p2sh).unwrap();
        assert_eq!(p2sh_script.len(), 35);
        assert_eq!(&p2sh_script[..2], &[0xaa, 0x20]);
        assert_eq!(&p2sh_script[2..34], &p2sh_payload);
        assert_eq!(p2sh_script[34], 0x87);
    }
}

#[test]
fn address_decoder_rejects_prefix_length_character_and_checksum_errors() {
    assert_eq!(
        decode_address("bitcoin:anything").unwrap_err(),
        "Unknown address prefix"
    );
    assert_eq!(decode_address("kaspa:q").unwrap_err(), "Address too short");
    assert!(decode_address("kaspa:qqqqqqqq!")
        .unwrap_err()
        .contains("Invalid character"));

    let valid = encode_p2pk_address(&[0x33; 32], "kaspa");
    let mut corrupted = valid.into_bytes();
    let last = corrupted.last_mut().unwrap();
    *last = if *last == b'q' { b'p' } else { b'q' };
    assert!(decode_address(std::str::from_utf8(&corrupted).unwrap())
        .unwrap_err()
        .contains("Checksum mismatch"));
}

#[test]
fn script_builder_rejects_unknown_address_versions() {
    let encoded = encode_address(&[0x55; 32], 0x7f, "kaspa");
    assert!(address_to_script_pubkey(&encoded)
        .unwrap_err()
        .contains("Unknown version"));
}

fn canonical_account_payload() -> [u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN] {
    use shared_signer::account_key::{
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
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
    payload
}

fn canonical_account_text() -> String {
    use shared_signer::account_key::{encode_account_key_text, ACCOUNT_KEY_TEXT_LEN};

    let payload = canonical_account_payload();
    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let length = encode_account_key_text(&payload, &mut text).expect("canonical account key");
    std::str::from_utf8(&text[..length]).unwrap().to_string()
}

#[test]
fn kpub_import_raw_import_and_extension_preserve_watch_only_state() {
    use super::bip32::{extend_addresses, import_kpub, import_kpub_raw};

    let text = canonical_account_text();
    let wallet = import_kpub(&text, "kaspa").expect("text import");
    const ORIGINAL_V105_KPUB: &str = "kpub2JigDdskmLLjkiA8PVnrGyEaCvwGrzET2X26crHBHDtGZERboYT4SnGXXRc7vyyNgvfuJF2XaFxqQ9uBVpU9FosVzcDhe5nfHyi2CLLzpPm";
    let migrated = import_kpub(ORIGINAL_V105_KPUB, "kaspa").expect("legacy text import");
    assert!(migrated.kpub.starts_with("kpub1:"));
    assert_eq!(migrated.receive_addresses.len(), 20);
    assert_eq!(migrated.change_addresses.len(), 20);
    assert_eq!(wallet.kpub, text);
    assert_eq!(wallet.receive_addresses.len(), 20);
    assert_eq!(wallet.change_addresses.len(), 20);
    assert!(wallet
        .receive_addresses
        .iter()
        .all(|value| value.starts_with("kaspa:")));
    assert!(wallet
        .change_addresses
        .iter()
        .all(|value| value.starts_with("kaspa:")));
    assert_ne!(wallet.receive_addresses[0], wallet.change_addresses[0]);

    let raw = import_kpub_raw(&canonical_account_payload(), "kaspatest").expect("raw import");
    assert_eq!(raw.kpub, text);
    assert!(raw.receive_addresses[0].starts_with("kaspatest:"));

    let mut indexed = wallet.clone();
    indexed.next_receive_index = 4;
    indexed.next_change_index = 5;
    let extended = extend_addresses(&indexed, 3, 2, "kaspa").expect("extension");
    assert_eq!(extended.receive_addresses.len(), 23);
    assert_eq!(extended.change_addresses.len(), 22);
    assert_eq!(&extended.receive_addresses[..20], &wallet.receive_addresses);
    assert_eq!(&extended.change_addresses[..20], &wallet.change_addresses);
    assert_eq!(
        (extended.next_receive_index, extended.next_change_index),
        (4, 5)
    );
}

#[test]
fn kaspa_cli_account_xpub_imports_and_normalizes_to_canonical_text() {
    use super::bip32::{decode_kpub_text, import_kpub};
    use shared_signer::account_key::{
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_VERSION,
    };

    const KASPA_CLI_ACCOUNT_XPUB: &str = "xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
    let payload = decode_kpub_text(KASPA_CLI_ACCOUNT_XPUB).expect("Kaspa CLI xpub");
    assert_eq!(&payload[..4], &ACCOUNT_KEY_VERSION);
    assert_eq!(payload[4], ACCOUNT_KEY_DEPTH);
    assert_eq!(&payload[9..13], &ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    assert_eq!(
        &payload[13..45],
        &[
            0xd4, 0x98, 0xb3, 0x15, 0x86, 0xc7, 0x6a, 0x0a, 0xd7, 0xf1, 0xf3, 0xb0, 0x56, 0xfb,
            0xef, 0x7a, 0xcc, 0x01, 0x98, 0xb4, 0x03, 0x24, 0x27, 0xf8, 0x61, 0x41, 0xaf, 0x02,
            0xce, 0x18, 0xfd, 0x82,
        ]
    );
    assert_eq!(
        &payload[45..78],
        &[
            0x02, 0x1f, 0xb4, 0xb5, 0xb8, 0xac, 0x58, 0x0d, 0x6d, 0xae, 0x63, 0x35, 0x7f, 0x22,
            0xea, 0x93, 0x36, 0xb9, 0x04, 0xaf, 0x4a, 0xbc, 0x98, 0xc9, 0x8c, 0x4a, 0xea, 0x3b,
            0x5a, 0xce, 0x07, 0xd3, 0x9c,
        ]
    );

    let wallet = import_kpub(KASPA_CLI_ACCOUNT_XPUB, "kaspa").expect("watch-only import");
    assert!(wallet.kpub.starts_with("kpub1:"));
    assert_eq!(wallet.receive_addresses.len(), 20);
    assert_eq!(wallet.change_addresses.len(), 20);
}

#[test]
fn kpub_import_rejects_malformed_text_payloads_and_hardened_children() {
    use super::bip32::{import_kpub, import_kpub_raw, ExtPubKey};

    assert!(import_kpub("kpub1:00", "kaspa").is_err());
    assert!(import_kpub_raw(&[0u8; 77], "kaspa").is_err());

    let mut invalid = canonical_account_payload();
    invalid[45] = 0x04;
    assert!(import_kpub_raw(&invalid, "kaspa").is_err());

    let xpub = ExtPubKey::from_kpub(&canonical_account_text()).expect("extended public key");
    assert!(xpub.derive_child(0x8000_0000).is_err());
}

#[test]
fn balance_summary_tracks_funded_receive_and_change_addresses() {
    use super::{
        address::address_to_script_pubkey, balance::summarize_balance, bip32::import_kpub,
        utxo::UtxoEntry,
    };

    let wallet = import_kpub(&canonical_account_text(), "kaspa").expect("wallet");
    let receive_script = address_to_script_pubkey(&wallet.receive_addresses[2]).unwrap();
    let change_script = address_to_script_pubkey(&wallet.change_addresses[3]).unwrap();
    let utxos = vec![
        UtxoEntry {
            tx_id: "11".repeat(32),
            index: 0,
            amount: 125_000_000,
            script_public_key: receive_script,
            block_daa_score: 10,
            covenant_id: None,
        },
        UtxoEntry {
            tx_id: "22".repeat(32),
            index: 1,
            amount: 75_000_000,
            script_public_key: change_script,
            block_daa_score: 11,
            covenant_id: None,
        },
    ];

    let summary = summarize_balance(&wallet, &utxos).expect("balance summary");
    assert_eq!(summary.total_sompi, 200_000_000);
    assert_eq!(summary.total_kas, 2.0);
    assert_eq!(summary.utxo_count, 2);
    assert_eq!(summary.funded_addresses, 2);
    assert_eq!(summary.funded_receive_indices, vec![2]);
    assert_eq!(summary.funded_change_indices, vec![3]);
}

#[test]
fn balance_summary_reports_overflow_instead_of_panicking() {
    use super::{balance::summarize_balance, bip32::import_kpub, utxo::UtxoEntry};

    let wallet = import_kpub(&canonical_account_text(), "kaspa").expect("wallet");
    let utxos = vec![
        UtxoEntry {
            tx_id: "33".repeat(32),
            index: 0,
            amount: u64::MAX,
            script_public_key: Vec::new(),
            block_daa_score: 0,
            covenant_id: None,
        },
        UtxoEntry {
            tx_id: "44".repeat(32),
            index: 1,
            amount: 1,
            script_public_key: Vec::new(),
            block_daa_score: 0,
            covenant_id: None,
        },
    ];

    assert_eq!(
        summarize_balance(&wallet, &utxos).unwrap_err(),
        "Wallet balance exceeds supported monetary range"
    );
}

#[test]
fn zero_address_extension_preserves_both_chains() {
    use super::bip32::{extend_addresses, import_kpub};

    let wallet = import_kpub(&canonical_account_text(), "kaspa").expect("wallet");
    let unchanged = extend_addresses(&wallet, 0, 0, "kaspa").expect("zero extension");
    assert_eq!(unchanged.receive_addresses, wallet.receive_addresses);
    assert_eq!(unchanged.change_addresses, wallet.change_addresses);
    assert_eq!(unchanged.next_receive_index, wallet.next_receive_index);
    assert_eq!(unchanged.next_change_index, wallet.next_change_index);
}

#[test]
fn kpub_public_derivation_matches_offline_signer_receive_and_change() {
    use super::bip32::import_kpub;
    use offline_signer::derivation::{bip32, xpub};

    // BIP39 "abandon" x11 + "about", empty passphrase. This is the same
    // deterministic 64-byte seed used by the signer derivation KATs.
    let seed = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];
    let mut text = [0u8; xpub::KPUB_MAX_LEN];
    let text_len = xpub::derive_and_serialize_kpub(&seed, &mut text).expect("signer kpub");
    let kpub = core::str::from_utf8(&text[..text_len]).expect("ASCII kpub");
    let wallet = import_kpub(kpub, "kaspa").expect("watch-only import");
    let account = bip32::derive_account_key(&seed).expect("signer account");

    for index in [0u32, 1, 7, 19] {
        let receive = bip32::derive_address_key(&account, index)
            .and_then(|key| key.public_key_x_only())
            .expect("receive key");
        let change = bip32::derive_change_key(&account, index)
            .and_then(|key| key.public_key_x_only())
            .expect("change key");
        assert_eq!(
            wallet.receive_addresses[index as usize],
            encode_p2pk_address(&receive, "kaspa"),
            "receive /0/{index} differs between KasSee and KasSigner",
        );
        assert_eq!(
            wallet.change_addresses[index as usize],
            encode_p2pk_address(&change, "kaspa"),
            "change /1/{index} differs between KasSee and KasSigner",
        );
    }
}

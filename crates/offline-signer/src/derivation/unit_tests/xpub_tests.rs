use super::*;
#[cfg(test)]
use crate::derivation::bip32::Bip32Error;
use shared_signer::account_key::{ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_VERSION};

// ─── Self-Tests ───────────────────────────────────────────────────────

/// Test base58 encoding with known vectors
fn test_base58_encoding() -> bool {
    // Test vector: empty → ""
    let mut out = [0u8; 64];
    let len = base58_encode(&[], &mut out);
    if len != 0 {
        return false;
    }

    // Test vector: [0] → "1"
    let len = base58_encode(&[0], &mut out);
    if len != 1 || out[0] != b'1' {
        return false;
    }

    // Test vector: [0, 0, 1] → "112"
    let len = base58_encode(&[0, 0, 1], &mut out);
    if len != 3 || &out[..3] != b"112" {
        return false;
    }

    // Test vector: "Hello World" → "JxF12TrwUP45BMd"
    let len = base58_encode(b"Hello World", &mut out);
    if len != 15 || &out[..15] != b"JxF12TrwUP45BMd" {
        return false;
    }

    true
}

/// Test base58check encoding
fn test_base58check() -> bool {
    // Base58Check of a single zero byte should produce specific output
    // (this is used as Bitcoin version 0x00 → address starting with "1")
    let mut out = [0u8; 64];
    let len = base58check_encode(&[0u8; 1], &mut out);
    // SHA256d([0x00]) checksum is known, result should start with '1'
    if len == 0 || out[0] != b'1' {
        return false;
    }

    true
}

/// Test SHA256d
fn test_sha256d() -> bool {
    // SHA256d("") = SHA256(SHA256(""))
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // SHA256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    let h = sha256d(b"");
    h[0] == 0x5d && h[1] == 0xf6 && h[2] == 0xe0 && h[3] == 0xe2
}

/// Test account-key derivation produces canonical `kpub1:` text
fn test_kpub_prefix() -> bool {
    // Use a known test seed (BIP39 test vector 1)
    // Mnemonic: "abandon abandon ... about"
    // Seed (hex): 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1...
    // We'll use a simpler approach: derive from a fixed 64-byte seed
    let mut seed = [0u8; 64];
    // Fill with deterministic data for testing
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(13);
    }

    let mut out = [0u8; KPUB_MAX_LEN];
    match derive_and_serialize_kpub(&seed, &mut out) {
        Ok(len) => len == KPUB_MAX_LEN && out.starts_with(KPUB_TEXT_PREFIX),
        Err(_) => false,
    }
}

/// Historical Base58 account keys normalize to the canonical representation.
fn test_legacy_kpub_compatibility() -> bool {
    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(11).wrapping_add(5);
    }
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    if derive_account_raw_kpub_payload(&seed, &mut payload).is_err() {
        return false;
    }
    let mut legacy = [0u8; KPUB_MAX_LEN];
    let legacy_length = base58check_encode(&payload, &mut legacy);
    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    if decode_kpub_compatible(&legacy[..legacy_length], &mut decoded).is_err() || decoded != payload
    {
        return false;
    }
    let mut canonical = [0u8; KPUB_MAX_LEN];
    let Ok(canonical_length) = normalize_kpub_text(&legacy[..legacy_length], &mut canonical) else {
        return false;
    };
    canonical_length == KPUB_MAX_LEN
        && canonical.starts_with(KPUB_TEXT_PREFIX)
        && import_kpub(&legacy[..legacy_length]).is_ok()
}

/// Account-level BIP32 xpubs from the Kaspa CLI normalize without changing
/// their chain code or compressed public key.
fn test_kaspa_cli_xpub_compatibility() -> bool {
    const KASPA_CLI_ACCOUNT_XPUB: &[u8] = b"xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
    const EXPECTED_CHAIN_CODE: [u8; 32] = [
        0xd4, 0x98, 0xb3, 0x15, 0x86, 0xc7, 0x6a, 0x0a, 0xd7, 0xf1, 0xf3, 0xb0, 0x56, 0xfb, 0xef,
        0x7a, 0xcc, 0x01, 0x98, 0xb4, 0x03, 0x24, 0x27, 0xf8, 0x61, 0x41, 0xaf, 0x02, 0xce, 0x18,
        0xfd, 0x82,
    ];
    const EXPECTED_PUBLIC_KEY: [u8; 33] = [
        0x02, 0x1f, 0xb4, 0xb5, 0xb8, 0xac, 0x58, 0x0d, 0x6d, 0xae, 0x63, 0x35, 0x7f, 0x22, 0xea,
        0x93, 0x36, 0xb9, 0x04, 0xaf, 0x4a, 0xbc, 0x98, 0xc9, 0x8c, 0x4a, 0xea, 0x3b, 0x5a, 0xce,
        0x07, 0xd3, 0x9c,
    ];

    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    if decode_kpub_compatible(KASPA_CLI_ACCOUNT_XPUB, &mut decoded).is_err()
        || decoded[..4] != ACCOUNT_KEY_VERSION
        || decoded[4] != ACCOUNT_KEY_DEPTH
        || decoded[9..13] != ACCOUNT_KEY_CHILD_INDEX.to_be_bytes()
        || decoded[13..45] != EXPECTED_CHAIN_CODE
        || decoded[45..78] != EXPECTED_PUBLIC_KEY
    {
        return false;
    }

    let mut canonical = [0u8; KPUB_MAX_LEN];
    let Ok(canonical_length) = normalize_kpub_text(KASPA_CLI_ACCOUNT_XPUB, &mut canonical) else {
        return false;
    };
    canonical_length == KPUB_MAX_LEN
        && canonical.starts_with(KPUB_TEXT_PREFIX)
        && import_kpub(KASPA_CLI_ACCOUNT_XPUB).is_ok()
}

/// Imported account XPrvs preserve derivation and serialize byte-for-byte.
fn test_account_xprv_recovery_roundtrip() -> bool {
    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(3).wrapping_add(17);
    }
    let mut original = [0u8; XPRV_MAX_LEN];
    let Ok(original_length) = derive_and_serialize_xprv(&seed, &mut original) else {
        return false;
    };
    let Ok(imported) = import_xprv_with_metadata(&original[..original_length]) else {
        return false;
    };
    let mut recovered = [0u8; XPRV_MAX_LEN];
    let Ok(recovered_length) = serialize_imported_xprv(&imported, &mut recovered) else {
        return false;
    };
    if recovered[..recovered_length] != original[..original_length] {
        return false;
    }

    let Ok(original_account) = crate::derivation::bip32::derive_account_key(&seed) else {
        return false;
    };
    let Ok(original_receive) = crate::derivation::bip32::derive_address_key(&original_account, 7)
    else {
        return false;
    };
    let Ok(imported_receive) = crate::derivation::bip32::derive_address_key(&imported.key, 7)
    else {
        return false;
    };
    let Ok(original_change) = crate::derivation::bip32::derive_change_key(&original_account, 4)
    else {
        return false;
    };
    let Ok(imported_change) = crate::derivation::bip32::derive_change_key(&imported.key, 4) else {
        return false;
    };

    original_receive.private_key_bytes() == imported_receive.private_key_bytes()
        && original_change.private_key_bytes() == imported_change.private_key_bytes()
}

/// Fixed exports produced by the original KasSigner v1.0.5 BIP32 implementation.
fn test_original_v105_export_vectors() -> bool {
    const ORIGINAL_KPUB: &[u8] = b"kpub2JigDdskmLLjkiA8PVnrGyEaCvwGrzET2X26crHBHDtGZERboYT4SnGXXRc7vyyNgvfuJF2XaFxqQ9uBVpU9FosVzcDhe5nfHyi2CLLzpPm";
    const ORIGINAL_XPRV: &[u8] = b"kprv65jKp8LrvxnSYE5fHUFquqHqeu6nTXWbfJ6VpTsZitMHgS6TG18otyx3g79CTSqTRR6VRZjm7hw9TxcNUJhaxKmLaAzjXz7b5k3cA5MjDbb";
    const ORIGINAL_PAYLOAD: [u8; XPUB_PAYLOAD_LEN] = [
        0x03, 0x8f, 0x33, 0x2e, 0x03, 0x8f, 0x43, 0x5e, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x7e, 0x95,
        0xe6, 0x10, 0x9b, 0x69, 0xe2, 0xe5, 0xb5, 0xe5, 0x02, 0x03, 0x16, 0x9f, 0x29, 0x84, 0x29,
        0xc7, 0x74, 0x81, 0xcf, 0xcb, 0x17, 0xb5, 0x53, 0xa4, 0x90, 0xdd, 0xb6, 0x5b, 0x89, 0xe7,
        0x03, 0xf6, 0x2a, 0x46, 0x03, 0xcd, 0x37, 0xd4, 0x06, 0x86, 0xe1, 0xff, 0xb2, 0x54, 0x66,
        0xf5, 0x33, 0x0e, 0x4f, 0xec, 0xc5, 0xea, 0xb5, 0x5f, 0xed, 0x43, 0xda, 0xbc, 0x4c, 0xc7,
        0x28, 0x71, 0x8b,
    ];

    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(3).wrapping_add(17);
    }

    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    if derive_account_raw_kpub_payload(&seed, &mut payload).is_err() || payload != ORIGINAL_PAYLOAD
    {
        return false;
    }
    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    if decode_kpub_compatible(ORIGINAL_KPUB, &mut decoded).is_err() || decoded != ORIGINAL_PAYLOAD {
        return false;
    }
    let mut xprv = [0u8; XPRV_MAX_LEN];
    let Ok(xprv_length) = derive_and_serialize_xprv(&seed, &mut xprv) else {
        return false;
    };
    if &xprv[..xprv_length] != ORIGINAL_XPRV {
        return false;
    }
    let Ok(imported) = import_xprv_with_metadata(ORIGINAL_XPRV) else {
        return false;
    };
    let Ok(receive) = crate::derivation::bip32::derive_address_key(&imported.key, 7) else {
        return false;
    };
    let Ok(change) = crate::derivation::bip32::derive_change_key(&imported.key, 4) else {
        return false;
    };
    receive.private_key_bytes()
        == &[
            0x8e, 0x80, 0x99, 0xd2, 0xe9, 0xa0, 0x9d, 0xad, 0x28, 0xb2, 0x02, 0x16, 0xb3, 0xca,
            0x98, 0x6b, 0x1d, 0x75, 0x6e, 0xbd, 0xc8, 0x61, 0xc9, 0xcb, 0xdd, 0x59, 0x25, 0x17,
            0x57, 0xbe, 0x71, 0xbc,
        ]
        && change.private_key_bytes()
            == &[
                0x82, 0xca, 0xeb, 0x62, 0x6e, 0x45, 0xea, 0xae, 0x86, 0xbd, 0x05, 0x05, 0x03, 0xfd,
                0x30, 0x77, 0xbe, 0x76, 0x72, 0x3f, 0x11, 0xd6, 0xee, 0x31, 0x4d, 0xf0, 0xe9, 0x2a,
                0x5c, 0x35, 0xab, 0x09,
            ]
}

/// Run extended public key test suite.
pub fn run_xpub_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 8u32;

    if test_base58_encoding() {
        passed += 1;
    }
    if test_base58check() {
        passed += 1;
    }
    if test_sha256d() {
        passed += 1;
    }
    if test_kpub_prefix() {
        passed += 1;
    }
    if test_legacy_kpub_compatibility() {
        passed += 1;
    }
    if test_kaspa_cli_xpub_compatibility() {
        passed += 1;
    }
    if test_account_xprv_recovery_roundtrip() {
        passed += 1;
    }
    if test_original_v105_export_vectors() {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn xpub_vectors_pass() {
    let (passed, total) = run_xpub_tests();
    assert_eq!(passed, total);
}

#[test]
fn canonical_kpub_wrappers_and_binary_qr_import_are_covered() {
    let seed = [0x42u8; 64];
    let account = crate::derivation::bip32::derive_account_key(&seed).expect("account");
    let mut text = [0u8; KPUB_MAX_LEN];
    let text_len =
        serialize_account_kpub(&account, [1, 2, 3, 4], &mut text).expect("canonical account kpub");

    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        decode_kpub_text(&text[..text_len], &mut decoded),
        Ok(XPUB_PAYLOAD_LEN)
    );
    let mut decoded_alias = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        kpub_text_to_raw(&text[..text_len], &mut decoded_alias),
        Ok(XPUB_PAYLOAD_LEN)
    );
    assert_eq!(decoded_alias, decoded);

    let mut framed = [0u8; XPUB_PAYLOAD_LEN + 1];
    let framed_len = kassigner_protocol::wire::qr_payload::wrap_v1_raw(&decoded, &mut framed)
        .expect("binary QR envelope");
    let imported = import_kpub_qr(&framed[..framed_len]).expect("QR account key");
    assert_eq!(imported.chain_code, *account.chain_code_bytes());
    assert_eq!(imported.pubkey, account.public_key_compressed().unwrap());

    assert!(decode_kpub_text(b"not-a-kpub", &mut decoded).is_err());
    assert!(kpub_text_to_raw(b"not-a-kpub", &mut decoded).is_err());
    assert!(import_kpub_qr(&[]).is_err());
    assert!(import_kpub_qr(&[kassigner_protocol::wire::qr_payload::PAYLOAD_V1_RAW]).is_err());
}

#[test]
fn account_xprv_public_wrappers_and_invalid_import_are_covered() {
    let seed = [0x24u8; 64];
    let account = crate::derivation::bip32::derive_account_key(&seed).expect("account key");
    let mut text = [0u8; XPRV_MAX_LEN];
    let length =
        serialize_account_key_xprv(&account, [9, 8, 7, 6], &mut text).expect("account xprv");

    let imported = import_xprv(&text[..length]).expect("imported xprv");
    assert_eq!(imported.private_key_bytes(), account.private_key_bytes());
    assert_eq!(imported.chain_code_bytes(), account.chain_code_bytes());
    assert_eq!(imported.depth, account.depth);

    assert!(import_xprv(b"not-an-xprv").is_err());
    let mut shallow =
        crate::derivation::bip32::ExtendedPrivKey::from_parts([1u8; 32], [2u8; 32], 2);
    assert!(serialize_account_key_xprv(&shallow, [0; 4], &mut text).is_err());
    shallow.depth = 3;
    assert!(serialize_account_key_xprv(&shallow, [0; 4], &mut text).is_ok());
}

#[test]
fn base58check_roundtrips_boundary_payloads_and_rejects_corruption() {
    for payload in [
        &[0u8][..],
        &[0, 0, 1][..],
        b"KasSigner Base58Check",
        &[0x55u8; XPUB_PAYLOAD_LEN][..],
    ] {
        let mut encoded = [0u8; 192];
        let encoded_len = base58check_encode(payload, &mut encoded);
        assert!(encoded_len > 0);

        let mut decoded = [0u8; 128];
        let decoded_len = base58check_decode(&encoded[..encoded_len], &mut decoded);
        assert_eq!(decoded_len, payload.len());
        assert_eq!(&decoded[..decoded_len], payload);
    }

    let mut decoded = [0x55u8; 128];
    assert_eq!(base58check_decode(b"", &mut decoded), 0);
    assert_eq!(base58check_decode(b"1", &mut decoded), 0);
    assert_eq!(base58check_decode(b"0OIl", &mut decoded), 0);

    let mut encoded = [0u8; 192];
    let encoded_len = base58check_encode(b"checksum", &mut encoded);
    encoded[encoded_len - 1] = if encoded[encoded_len - 1] == b'1' {
        b'2'
    } else {
        b'1'
    };
    assert_eq!(base58check_decode(&encoded[..encoded_len], &mut decoded), 0);
}

#[test]
fn base58_encoding_respects_output_capacity_and_leading_zeroes() {
    let mut empty = [];
    assert_eq!(base58_encode(b"nonempty", &mut empty), 0);

    let mut one = [0u8; 1];
    assert_eq!(base58_encode(&[0, 0, 1], &mut one), 1);
    assert_eq!(one, [b'1']);

    let mut exact = [0u8; 3];
    assert_eq!(base58_encode(&[0, 0, 1], &mut exact), 3);
    assert_eq!(&exact, b"112");
}

#[test]
fn account_xprv_import_rejects_each_metadata_boundary_with_valid_checksum() {
    let seed = [0x36u8; 64];
    let mut text = [0u8; XPRV_MAX_LEN];
    let length = derive_and_serialize_xprv(&seed, &mut text).expect("account xprv");
    let mut decoded = [0u8; 128];
    let decoded_len = base58check_decode(&text[..length], &mut decoded);
    assert_eq!(decoded_len, XPUB_PAYLOAD_LEN);

    for (offset, replacement) in [
        (0usize, decoded[0] ^ 1),
        (4, 2),
        (9, decoded[9] ^ 1),
        (45, 1),
    ] {
        let mut payload = [0u8; XPUB_PAYLOAD_LEN];
        payload.copy_from_slice(&decoded[..XPUB_PAYLOAD_LEN]);
        payload[offset] = replacement;
        let mut invalid = [0u8; XPRV_MAX_LEN];
        let invalid_len = base58check_encode(&payload, &mut invalid);
        assert!(invalid_len > 0, "offset {offset}");
        assert!(
            import_xprv_with_metadata(&invalid[..invalid_len]).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn kpub_compatibility_and_payload_validation_boundaries_are_explicit() {
    let seed = [0x51u8; 64];
    let account = crate::derivation::bip32::derive_account_key(&seed).expect("account");
    let parent = crate::derivation::bip32::derive_path(&seed, &[0x8000_002c, 0x8001_b207])
        .expect("parent")
        .public_key_compressed()
        .expect("parent pubkey");
    let mut text = [0u8; KPUB_MAX_LEN];
    assert!(serialize_kpub(
        &account,
        &parent,
        ACCOUNT_KEY_CHILD_INDEX.wrapping_add(1),
        &mut text,
    )
    .is_err());

    let length = serialize_kpub(&account, &parent, ACCOUNT_KEY_CHILD_INDEX, &mut text)
        .expect("canonical kpub");
    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        decode_kpub_compatible(&text[..length], &mut decoded),
        Ok(XPUB_PAYLOAD_LEN)
    );
    assert!(decode_kpub_compatible(b"not-a-kpub", &mut decoded).is_err());
    assert!(import_kpub_raw(&[0u8; XPUB_PAYLOAD_LEN]).is_err());
}

#[test]
fn base58_extreme_lengths_and_each_checksum_byte_are_rejected() {
    let mut encoded = [0u8; 512];
    let mut decoded = [0u8; 128];

    // A full 128-byte non-zero integer cannot be represented in the fixed
    // 128-character encoder scratch space and must fail closed.
    assert_eq!(base58_encode(&[0xff; 128], &mut encoded), 0);
    // Excessively long Base58 input must not overrun the fixed decode integer.
    assert_eq!(base58check_decode(&[b'z'; 300], &mut decoded), 0);

    let payload = b"checksum-stage";
    let checksum = sha256d(payload);
    for checksum_index in 0..4 {
        let mut raw = [0u8; 32];
        raw[..payload.len()].copy_from_slice(payload);
        raw[payload.len()..payload.len() + 4].copy_from_slice(&checksum[..4]);
        raw[payload.len() + checksum_index] ^= 1;
        let encoded_len = base58_encode(&raw[..payload.len() + 4], &mut encoded);
        assert!(encoded_len > 0);
        assert_eq!(base58check_decode(&encoded[..encoded_len], &mut decoded), 0);
    }
}

#[test]
fn multisig_account_parts_and_legacy_kpub_export_cover_success_and_bounds() {
    let seed = [0x63u8; 64];
    let parts = derive_multisig_account_parts(&seed, 0).expect("45' account parts");
    assert_eq!(parts.depth, 3);
    assert_eq!(u32::from_be_bytes(parts.child_num), 0x8000_0000);
    assert!(matches!(parts.pubkey[0], 0x02 | 0x03));
    assert!(matches!(
        derive_multisig_account_parts(&seed, 0x8000_0000),
        Err(Bip32Error::InvalidKey),
    ));

    let mut encoded = [0u8; KPUB_MAX_LEN];
    let length = derive_and_serialize_multisig_kpub(&seed, &mut encoded).expect("45' legacy kpub");
    assert_eq!(length, LEGACY_KPUB_LEN);
    let decoded = parse_kpub_parts(&encoded[..length]).expect("round-trip 45' parts");
    assert_eq!(decoded, parts);

    let mut too_small = [0u8; 1];
    assert!(matches!(
        derive_and_serialize_multisig_kpub(&seed, &mut too_small),
        Err(Bip32Error::InvalidKey),
    ));
}

#[test]
fn multisig_account_parts_nonzero_child_number_is_hardened() {
    let seed = [0x6eu8; 64];
    let parts = derive_multisig_account_parts(&seed, 9).expect("45' account 9 parts");
    assert_eq!(parts.child_num, 0x8000_0009u32.to_be_bytes());
}

#[test]
fn payload_parser_requires_version_and_compressed_prefix_independently() {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[45] = 0x02;
    assert!(parts_from_payload(&payload).is_some());

    let mut bad_version = payload;
    bad_version[0] ^= 0x01;
    assert!(parts_from_payload(&bad_version).is_none());

    let mut bad_prefix = payload;
    bad_prefix[45] = 0x04;
    assert!(parts_from_payload(&bad_prefix).is_none());

    payload[45] = 0x03;
    assert!(parts_from_payload(&payload).is_some());
}

use super::scanner::{first_push, scan_raw_for_preimage};

fn raw_transaction(transaction_id: &[u8; 32], script: &[u8]) -> Vec<u8> {
    let script_length = script.len().max(10);
    let mut raw = Vec::new();
    raw.extend_from_slice(&37u32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(transaction_id);
    raw.extend_from_slice(&7u32.to_le_bytes());
    raw.extend_from_slice(&(script_length as u32).to_le_bytes());
    raw.extend_from_slice(script);
    raw.resize(raw.len() + script_length.saturating_sub(script.len()), 0);
    raw
}

#[test]
fn first_push_supports_direct_pushdata1_and_pushdata2() {
    assert_eq!(first_push(&[3, 1, 2, 3]), Some([1, 2, 3].as_slice()));
    assert_eq!(first_push(&[0x4c, 2, 4, 5]), Some([4, 5].as_slice()));
    assert_eq!(first_push(&[0x4d, 2, 0, 6, 7]), Some([6, 7].as_slice()));
}

#[test]
fn first_push_rejects_empty_oversized_unknown_and_truncated_pushes() {
    assert_eq!(first_push(&[]), None);
    assert_eq!(first_push(&[0]), None);
    assert_eq!(first_push(&[0x4c]), None);
    assert_eq!(first_push(&[0x4d, 1]), None);
    assert_eq!(first_push(&[0x4c, 0]), None);
    assert_eq!(first_push(&[0x4d, 201, 0]), None);
    assert_eq!(first_push(&[0x4e, 1, 2, 3]), None);
    assert_eq!(first_push(&[3, 1, 2]), None);
}

#[test]
fn raw_scanner_finds_matching_preimage_and_ignores_other_outpoints() {
    let target = [0x11; 32];
    let other = [0x22; 32];
    let mut raw = raw_transaction(&other, &[3, 9, 9, 9]);
    raw.extend_from_slice(&raw_transaction(&target, &[0x4c, 3, 1, 2, 3]));
    assert_eq!(scan_raw_for_preimage(&raw, &target), Some(vec![1, 2, 3]));
    assert_eq!(scan_raw_for_preimage(&raw, &[0x33; 32]), None);
}

#[test]
fn raw_scanner_rejects_invalid_identity_lengths_and_script_bounds() {
    let target = [0x44; 32];
    assert_eq!(scan_raw_for_preimage(&[], &target), None);
    assert_eq!(scan_raw_for_preimage(&[0; 80], &[0; 31]), None);

    let mut wrong_outpoint = raw_transaction(&target, &[2, 1, 2]);
    wrong_outpoint[..4].copy_from_slice(&36u32.to_le_bytes());
    assert_eq!(scan_raw_for_preimage(&wrong_outpoint, &target), None);

    let mut short_script = raw_transaction(&target, &[2, 1, 2]);
    short_script[41..45].copy_from_slice(&9u32.to_le_bytes());
    assert_eq!(scan_raw_for_preimage(&short_script, &target), None);

    let mut oversized = raw_transaction(&target, &[2, 1, 2]);
    oversized[41..45].copy_from_slice(&1001u32.to_le_bytes());
    assert_eq!(scan_raw_for_preimage(&oversized, &target), None);
}

#[test]
fn stealth_key_and_tweak_helpers_cover_roundtrip_and_validation() {
    use k256::SecretKey;

    let secret = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
    let public = secret.public_key();
    let xonly = super::keys::x_only_pub(&public);
    let restored = super::keys::pubkey_from_xonly(&xonly).expect("x-only public key");
    assert_eq!(super::keys::x_only_bytes(&restored), xonly);
    assert!(super::keys::pubkey_from_xonly(&xonly[..31]).is_err());
    assert!(super::keys::pubkey_from_xonly(&[0xff; 32]).is_err());

    let scalar = super::keys::scalar_from_bytes(&[1u8; 32]).expect("valid scalar");
    let affine = (k256::ProjectivePoint::GENERATOR * scalar).to_affine();
    assert_eq!(super::keys::x_only_from_affine(&affine), xonly);
    assert!(super::keys::scalar_from_bytes(&[0xffu8; 32]).is_err());

    let shared = [0x77u8; 32];
    // Independent SHA-256 KAT: SHA256("KasStealthViewTag" || 0x77 * 32)[0] == 0x63.
    assert_eq!(super::derivation::view_tag(&shared), 0x63);
    let changed_shared = [0x78u8; 32];
    // Second independent KAT proves a changed shared secret produces the expected distinct tag.
    assert_eq!(super::derivation::view_tag(&changed_shared), 0x82);
    assert_ne!(
        super::derivation::view_tag(&shared),
        super::derivation::view_tag(&changed_shared)
    );
    let (first_tweak, first_index) = super::derivation::stealth_tweak(&shared, 0);
    let (same_tweak, same_index) = super::derivation::stealth_tweak(&shared, 0);
    let (next_tweak, next_index) = super::derivation::stealth_tweak(&shared, 1);
    assert_eq!(first_tweak, same_tweak);
    assert_eq!(first_index, same_index);
    assert!(first_tweak != next_tweak || first_index != next_index);
}

#[test]
fn stealth_tweak_masks_the_high_index_bit_against_an_exact_vector() {
    let shared = [0x03u8; 32];
    let (tweak, index) = super::derivation::stealth_tweak(&shared, 0);
    assert_eq!(index, 0x5f00_ed1a);
    let tweak_bytes: [u8; 32] = tweak.to_bytes().into();
    assert_eq!(
        tweak_bytes,
        [
            0xdf, 0x00, 0xed, 0x1a, 0xbe, 0x65, 0x14, 0x04, 0x85, 0x97, 0xaa, 0x31, 0x57, 0x4a,
            0xcb, 0x9c, 0x38, 0xed, 0xa2, 0xc3, 0xf0, 0x11, 0xd1, 0xa1, 0x42, 0x35, 0xda, 0xa8,
            0xc4, 0xcf, 0xda, 0x01,
        ],
    );
    assert_eq!(index & 0x8000_0000, 0);
}

#[test]
fn stealth_metadata_derivation_and_encoding_are_directly_covered() {
    use k256::PublicKey;

    let key = PublicKey::from_sec1_bytes(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    let account = crate::account::bip32::ExtPubKey {
        key,
        chain_code: [0x11; 32],
        depth: 3,
    };
    let meta = super::derive_stealth_meta(&account).expect("stealth metadata");
    let encoded = super::encode_stealth_meta(&meta);
    assert_eq!(encoded.len(), 128);
    let decoded = super::decode_stealth_meta(&encoded).expect("metadata round trip");
    assert_eq!(
        super::keys::x_only_pub(&decoded.scan_pubkey),
        super::keys::x_only_pub(&meta.scan_pubkey),
    );
    assert_eq!(
        super::keys::x_only_pub(&decoded.spend_pubkey),
        super::keys::x_only_pub(&meta.spend_pubkey),
    );
}

#[test]
fn announcement_address_is_network_specific_and_directly_covered() {
    let mainnet = super::announcement_address("kaspa");
    let testnet = super::announcement_address("kaspatest");
    assert!(mainnet.starts_with("kaspa:"));
    assert!(testnet.starts_with("kaspatest:"));
    assert_ne!(mainnet, testnet);
}

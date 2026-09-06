use crate::update::manifest as update_manifest;
use crate::update::manifest::FirmwareUpdateManifest;

fn sample() -> FirmwareUpdateManifest {
    FirmwareUpdateManifest {
        schema: update_manifest::SCHEMA_VERSION,
        board: update_manifest::BOARD_M5STACK_CORES3,
        channel: update_manifest::CHANNEL_PRODUCTION,
        version: 20_001,
        release_sequence: 467,
        security_version: 1,
        image_size: 123_456,
        partition_layout_hash: [0x11; 32],
        image_hash: [0x22; 32],
        signature: [0x33; 64],
    }
}

#[test]
fn update_manifest_round_trip_is_exact_and_canonical() {
    let manifest = sample();
    let encoded = manifest.encode();
    assert_eq!(encoded.len(), update_manifest::MANIFEST_LEN);
    assert_eq!(update_manifest::parse(&encoded), Some(manifest));
    let mut with_trailing = encoded.to_vec();
    with_trailing.push(0);
    assert_eq!(update_manifest::parse(&with_trailing), None);
}

#[test]
fn update_manifest_rejects_schema_and_reserved_byte_drift() {
    let mut encoded = sample().encode();
    encoded[4] = 2;
    assert_eq!(update_manifest::parse(&encoded), None);
    encoded = sample().encode();
    encoded[7] = 1;
    assert_eq!(update_manifest::parse(&encoded), None);
}

#[test]
fn signing_digest_binds_every_signed_field() {
    let base = sample();
    let digest = base.signing_digest();
    let mut mutations = [base; 8];
    mutations[0].board ^= 1;
    mutations[1].channel ^= 1;
    mutations[2].version ^= 1;
    mutations[3].release_sequence ^= 1;
    mutations[4].security_version ^= 1;
    mutations[5].image_size ^= 1;
    mutations[6].partition_layout_hash[0] ^= 1;
    mutations[7].image_hash[0] ^= 1;
    for mutation in mutations {
        assert_ne!(mutation.signing_digest(), digest);
    }
}

#[test]
fn update_manifest_rejects_bad_magic_independently_of_length() {
    let mut encoded = sample().encode();
    encoded[0] ^= 0x01;
    assert_eq!(update_manifest::parse(&encoded), None);
}

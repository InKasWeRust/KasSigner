use crate::{
    advanced_policy,
    backup::seed_qr,
    storage::{fat32_metadata, payload},
    update::{attestation, manifest},
};

#[test]
fn externally_controlled_firmware_parsers_are_total_over_truncated_and_noise_inputs() {
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    for len in 0..=600usize {
        let mut bytes = std::vec![0u8; len];
        for byte in &mut bytes {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 32) as u8;
        }
        let data = bytes.as_slice();
        let result = std::panic::catch_unwind(|| {
            let _ = manifest::parse(data);
            let _ = advanced_policy::parse_utc_yyyymmddhhmm(data);
            let _ = advanced_policy::parse_weekly_windows(data);
            let _ = payload::detect_payload(data, usize::MAX);
            let _ = fat32_metadata::parse_directory_entry(data);
            let mut indices = [0u16; 24];
            let _ = seed_qr::decode_seedqr(data, &mut indices);
            let _ = seed_qr::decode_compact_seedqr(data, &mut indices);
        });
        assert!(
            result.is_ok(),
            "external firmware parser panicked at length {len}"
        );
    }
}

#[test]
fn fat32_and_esp_metadata_parsers_are_total_over_noise() {
    let mut seed = 0xbb67_ae85_84ca_a73bu64;
    for _ in 0..256 {
        let mut sector = [0u8; 512];
        for byte in &mut sector {
            seed = seed
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            *byte = (seed >> 24) as u8;
        }
        let result = std::panic::catch_unwind(|| {
            let _ = fat32_metadata::parse_boot_sector(&sector);
            let mut header = [0u8; attestation::ESP_IMAGE_HEADER_SIZE];
            header.copy_from_slice(&sector[..attestation::ESP_IMAGE_HEADER_SIZE]);
            let _ = attestation::parse_image_header(&header);
            let mut signature = [0u8; attestation::SECURE_BOOT_SIGNATURE_PREFIX_SIZE];
            signature.copy_from_slice(&sector[..attestation::SECURE_BOOT_SIGNATURE_PREFIX_SIZE]);
            let _ = attestation::parse_signature_digest(&signature);
        });
        assert!(
            result.is_ok(),
            "FAT32/ESP metadata parser panicked for deterministic noise"
        );
    }
}

#[test]
fn seedqr_encoding_rejects_out_of_range_indices_without_indexing_tables() {
    let invalid = [u16::MAX; 24];
    let mut text = [0u8; 96];
    let mut compact = [0u8; 32];
    assert_eq!(seed_qr::encode_seedqr(&invalid, 24, &mut text), 0);
    assert_eq!(
        seed_qr::encode_compact_seedqr(&invalid, 24, &mut compact),
        0
    );
}

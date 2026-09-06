#![no_main]

use libfuzzer_sys::fuzz_target;
use offline_signer::{
    crypto::{container_framing, password_kdf},
    derivation::xpub,
    transaction::{private_swap as script_swap, std_pskt},
};
use kassigner_protocol::wire::multisig_descriptor as descriptor;
use shared_signer::{anti_klepto, covenant_sign};
use signer_firmware_core::{
    advanced_policy,
    backup::seed_qr,
    storage::{fat32_metadata, payload},
    update::{attestation, manifest as update_manifest},
};

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0) % 18;
    let body = data.get(1..).unwrap_or_default();
    match selector {
        0 => { let _ = anti_klepto::parse_request(body); let _ = anti_klepto::parse_reveal(body); }
        1 => { let _ = covenant_sign::parse_request(body); let _ = covenant_sign::parse_reveal(body); }
        2 => { let _ = covenant_sign::private_swap::parse_request(body); let _ = covenant_sign::private_swap::parse_reveal(body); }
        3 => { let _ = descriptor::parse_multisig_descriptor(body); }
        4 => { let _ = update_manifest::parse(body); }
        5 => {
            let mut indices = [0u16; 24];
            let _ = seed_qr::decode_seedqr(body, &mut indices);
            let _ = seed_qr::decode_compact_seedqr(body, &mut indices);
        }
        6 => { let _ = payload::detect_payload(body, usize::MAX); }
        7 => {
            let mut sector = [0u8; 512];
            let count = body.len().min(sector.len());
            sector[..count].copy_from_slice(&body[..count]);
            let _ = fat32_metadata::parse_boot_sector(&sector);
            let _ = fat32_metadata::parse_directory_entry(body);
        }
        8 => { let _ = advanced_policy::parse_utc_yyyymmddhhmm(body); let _ = advanced_policy::parse_weekly_windows(body); }
        9 => {
            let mut out = [0u8; 78];
            let _ = xpub::decode_kpub_compatible(body, &mut out);
            let _ = xpub::parse_kpub_parts(body);
        }
        10 => { let _ = password_kdf::parse_metadata(body); }
        11 => { let _ = container_framing::parse_backup_header(body); }
        12 => { let _ = container_framing::parse_transport_header(body, body.len()); }
        13 => { let _ = script_swap::parse_private_swap_script(body); }
        14 => { let _ = std_pskt::detect_tx_format(body); }
        15 => {
            let mut header = [0u8; attestation::ESP_IMAGE_HEADER_SIZE];
            let count = body.len().min(header.len());
            header[..count].copy_from_slice(&body[..count]);
            let _ = attestation::parse_image_header(&header);
        }
        16 => {
            let mut prefix = [0u8; attestation::SECURE_BOOT_SIGNATURE_PREFIX_SIZE];
            let count = body.len().min(prefix.len());
            prefix[..count].copy_from_slice(&body[..count]);
            let _ = attestation::parse_signature_digest(&prefix);
        }
        _ => {
            let mut segment = [0u8; attestation::ESP_SEGMENT_HEADER_SIZE];
            let count = body.len().min(segment.len());
            segment[..count].copy_from_slice(&body[..count]);
            if let Ok(length) = attestation::segment_data_len(&segment) {
                let _ = attestation::advance_segment(u32::MAX.saturating_sub(length), length);
            }
        }
    }
});

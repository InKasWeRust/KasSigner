use std::vec;

use crate::qr::classification::{
    classify_qr_payload, decode_hex, is_covenant_hex, is_seed_backup_candidate, HexError,
    QrPayloadKind,
};

#[test]
fn qr_classifier_routes_structured_payloads_before_ambiguous_entropy_lengths() {
    let pairing_request = pairing_request();
    let cases: &[(&[u8], QrPayloadKind)] = &[
        (b"kaspa:qq", QrPayloadKind::KaspaAddress),
        (b"KASPA:QQ", QrPayloadKind::KaspaAddress),
        (b"KSPT\x04payload", QrPayloadKind::CompactKspt),
        (&pairing_request, QrPayloadKind::PairingRequest),
        (b"PSKBpayload", QrPayloadKind::StandardPskt),
        (b"PSKTpayload", QrPayloadKind::StandardPskt),
        (&[b'1'; 48], QrPayloadKind::SeedQr),
        (b"COVB012345678901", QrPayloadKind::CovenantRaw),
        (b"434f564264617461", QrPayloadKind::CovenantHex),
        (&[7; 16], QrPayloadKind::RawSeedEntropy),
        (&[7; 32], QrPayloadKind::RawSeedEntropy),
        (
            b"STLH012345678901234567890123456789012",
            QrPayloadKind::StealthRequest,
        ),
        (&firmware_update(), QrPayloadKind::FirmwareUpdate),
        (b"COVBdata", QrPayloadKind::CovenantRaw),
        (b"unknown", QrPayloadKind::Unknown),
    ];
    for (payload, expected) in cases {
        assert_eq!(classify_qr_payload(payload, payload.len()), *expected);
    }
}

fn pairing_request() -> [u8; shared_signer::pairing::REQUEST_LEN] {
    let request = shared_signer::pairing::AddressBatchRequest::new(
        [0xA5; shared_signer::pairing::NONCE_LEN],
        0,
        20,
        0,
        20,
    );
    let mut wire = [0u8; shared_signer::pairing::REQUEST_LEN];
    assert_eq!(
        shared_signer::pairing::encode_request(request, &mut wire),
        Ok(shared_signer::pairing::REQUEST_LEN)
    );
    wire
}

fn firmware_update() -> [u8; crate::update::manifest::MANIFEST_LEN] {
    let mut payload = [0u8; crate::update::manifest::MANIFEST_LEN];
    payload[..4].copy_from_slice(b"KSFU");
    payload[4] = crate::update::manifest::SCHEMA_VERSION;
    payload
}

#[test]
fn qr_classifier_clamps_declared_length_and_rejects_malformed_hex_covenants() {
    assert_eq!(
        classify_qr_payload(b"kaspa:rest", 5),
        QrPayloadKind::Unknown
    );
    assert_eq!(
        classify_qr_payload(b"KSPT\x04", usize::MAX),
        QrPayloadKind::CompactKspt
    );
    assert_eq!(
        classify_qr_payload(b"KSPT\x03", usize::MAX),
        QrPayloadKind::Unknown
    );
    assert!(!is_covenant_hex(b"434f5642zz"));
    assert!(!is_covenant_hex(b"434f5642a"));
    assert!(!is_covenant_hex(b"434f5641aa"));
}

#[test]
fn hex_decoder_supports_both_cases_and_reports_every_error() {
    let mut output = [0u8; 4];
    assert_eq!(decode_hex(b"00aF10ff", &mut output), Ok(4));
    assert_eq!(output, [0x00, 0xaf, 0x10, 0xff]);
    assert_eq!(decode_hex(b"0", &mut output), Err(HexError::OddLength));
    assert_eq!(decode_hex(b"zz", &mut output), Err(HexError::InvalidDigit));
    assert_eq!(
        decode_hex(b"0011", &mut output[..1]),
        Err(HexError::OutputTooSmall)
    );
}

#[test]
fn seed_backup_detection_covers_current_legacy_and_plain_formats() {
    let mut seed = [0u8; 57];
    seed[..4].copy_from_slice(b"KAS\x01");
    assert!(is_seed_backup_candidate(&seed, seed.len()));

    let mut xprv_encrypted = [0u8; 40];
    xprv_encrypted[..4].copy_from_slice(b"KAX\x02");
    assert!(is_seed_backup_candidate(
        &xprv_encrypted,
        xprv_encrypted.len()
    ));

    let mut xprv_plain = [b'x'; 100];
    xprv_plain[..4].copy_from_slice(b"xprv");
    assert!(is_seed_backup_candidate(&xprv_plain, xprv_plain.len()));

    let key = [b'a'; 64];
    assert!(is_seed_backup_candidate(&key, key.len()));
    assert!(!is_seed_backup_candidate(b"not a backup", usize::MAX));
}

#[test]
fn qr_classifier_recognizes_current_covenant_and_private_swap_hex_envelopes() {
    let covenant_len = shared_signer::covenant_sign::REVEAL_LEN * 2;
    let mut covenant = vec![b'0'; covenant_len];
    covenant[..8].copy_from_slice(b"43565256"); // CVRV
    assert_eq!(
        classify_qr_payload(&covenant, covenant.len()),
        QrPayloadKind::CovenantSignHex
    );
    covenant[10] = b'z';
    assert_eq!(
        classify_qr_payload(&covenant, covenant.len()),
        QrPayloadKind::Unknown
    );

    let private_len = shared_signer::covenant_sign::private_swap::REVEAL_LEN * 2;
    let mut private_swap = vec![b'0'; private_len];
    private_swap[..8].copy_from_slice(b"50535752"); // PSWR
    assert_eq!(
        classify_qr_payload(&private_swap, private_swap.len()),
        QrPayloadKind::PrivateSwapHex
    );
    private_swap.pop();
    assert_eq!(
        classify_qr_payload(&private_swap, private_swap.len()),
        QrPayloadKind::Unknown
    );
}

#[test]
fn covenant_prefix_classifiers_cover_short_circuit_and_covi_sides() {
    assert!(!crate::qr::classification::is_covenant_raw(b"COVB"));
    assert!(crate::qr::classification::is_covenant_raw(b"COVI0"));
    assert!(!crate::qr::classification::is_covenant_raw(b"COVX0"));

    assert!(is_covenant_hex(b"434f564900")); // COVI + one byte
    assert!(!is_covenant_hex(b"434f565800")); // COVX + one byte

    let mut raw_covenant_sign = shared_signer::covenant_sign::REQUEST_MAGIC.to_vec();
    raw_covenant_sign.push(shared_signer::covenant_sign::VERSION);
    assert_eq!(
        classify_qr_payload(&raw_covenant_sign, raw_covenant_sign.len()),
        QrPayloadKind::CovenantSignRaw,
    );

    let mut raw_private_swap = shared_signer::covenant_sign::private_swap::REQUEST_MAGIC.to_vec();
    raw_private_swap.push(shared_signer::covenant_sign::private_swap::VERSION);
    assert_eq!(
        classify_qr_payload(&raw_private_swap, raw_private_swap.len()),
        QrPayloadKind::PrivateSwapRaw,
    );
}

#[test]
fn qr_classifier_covers_structured_short_circuit_boundaries() {
    let mut wrong_pairing_magic = pairing_request();
    wrong_pairing_magic[0] = b'X';
    assert_eq!(
        classify_qr_payload(&wrong_pairing_magic, wrong_pairing_magic.len()),
        QrPayloadKind::Unknown,
    );

    assert_eq!(classify_qr_payload(b"KSPT", 4), QrPayloadKind::Unknown);
    assert_eq!(classify_qr_payload(b"NOPE\x04", 5), QrPayloadKind::Unknown);
    assert_eq!(classify_qr_payload(&[b'7'; 96], 96), QrPayloadKind::SeedQr);
    assert_eq!(classify_qr_payload(&[b'x'; 48], 48), QrPayloadKind::Unknown);

    let mut wrong_stealth_magic = [0u8; 37];
    wrong_stealth_magic[..4].copy_from_slice(b"NOPE");
    assert_eq!(
        classify_qr_payload(&wrong_stealth_magic, wrong_stealth_magic.len()),
        QrPayloadKind::Unknown,
    );

    let mut wrong_update_magic = firmware_update();
    wrong_update_magic[..4].copy_from_slice(b"NOPE");
    assert_eq!(
        classify_qr_payload(&wrong_update_magic, wrong_update_magic.len()),
        QrPayloadKind::Unknown,
    );

    // Long enough to enter the case-insensitive comparison loop, but fail
    // after the first matching byte rather than at the length guard.
    assert_eq!(classify_qr_payload(b"kXsPa:qq", 8), QrPayloadKind::Unknown);
}

#[test]
fn covenant_hex_classifiers_cover_each_length_parity_and_digit_guard() {
    // Generic covenant hex: lower bound, upper bound, parity, prefix, and the
    // low-nibble hex failure are independent external-input branches.
    assert!(!is_covenant_hex(b"434f5642")); // 8 bytes, below the 10-byte minimum.
    assert!(!is_covenant_hex(&vec![b'0'; 1_026]));
    assert!(!is_covenant_hex(b"434f5642000")); // valid-range prefix but odd length.
    assert!(!is_covenant_hex(b"434f5642z0")); // invalid high nibble.
    assert!(!is_covenant_hex(b"434f56420z")); // invalid low nibble.

    let covenant_min = shared_signer::covenant_sign::REVEAL_LEN * 2;
    let too_short = vec![b'0'; covenant_min - 2];
    assert_eq!(
        classify_qr_payload(&too_short, too_short.len()),
        QrPayloadKind::Unknown
    );
    let too_long = vec![b'0'; 9_002];
    assert_eq!(
        classify_qr_payload(&too_long, too_long.len()),
        QrPayloadKind::Unknown
    );
    let odd = vec![b'0'; covenant_min + 1];
    assert_eq!(classify_qr_payload(&odd, odd.len()), QrPayloadKind::Unknown);

    let private_min = shared_signer::covenant_sign::private_swap::REVEAL_LEN * 2;
    let private_too_short = vec![b'0'; private_min - 2];
    assert_eq!(
        classify_qr_payload(&private_too_short, private_too_short.len()),
        QrPayloadKind::Unknown,
    );
    let private_too_long = vec![b'0'; 7_002];
    assert_eq!(
        classify_qr_payload(&private_too_long, private_too_long.len()),
        QrPayloadKind::Unknown,
    );
    let private_odd = vec![b'0'; private_min + 1];
    assert_eq!(
        classify_qr_payload(&private_odd, private_odd.len()),
        QrPayloadKind::Unknown,
    );
}

#[test]
fn hex_decoder_covers_low_nibble_failure_and_empty_input() {
    let mut output = [0u8; 1];
    assert_eq!(decode_hex(b"0z", &mut output), Err(HexError::InvalidDigit));
    assert_eq!(decode_hex(b"z0", &mut output), Err(HexError::InvalidDigit));
    let mut empty = [];
    assert_eq!(decode_hex(b"", &mut empty), Ok(0));
}

#[test]
fn seed_backup_detection_covers_alternate_headers_and_range_edges() {
    let mut kas_v2 = [0u8; 40];
    kas_v2[..4].copy_from_slice(b"KAS\x02");
    assert!(is_seed_backup_candidate(&kas_v2, kas_v2.len()));

    let mut wrong_seed = [0u8; 57];
    wrong_seed[..4].copy_from_slice(b"NOPE");
    assert!(!is_seed_backup_candidate(&wrong_seed, wrong_seed.len()));

    let mut wrong_xprv = [0u8; 40];
    wrong_xprv[..4].copy_from_slice(b"NOPE");
    assert!(!is_seed_backup_candidate(&wrong_xprv, wrong_xprv.len()));

    let mut short_plain_xprv = [b'x'; 99];
    short_plain_xprv[..4].copy_from_slice(b"xprv");
    assert!(!is_seed_backup_candidate(
        &short_plain_xprv,
        short_plain_xprv.len()
    ));

    let hex_65 = [b'a'; 65];
    let hex_66 = [b'F'; 66];
    assert!(is_seed_backup_candidate(&hex_65, hex_65.len()));
    assert!(is_seed_backup_candidate(&hex_66, hex_66.len()));

    let mut bad_hex = [b'a'; 64];
    bad_hex[63] = b'g';
    assert!(!is_seed_backup_candidate(&bad_hex, bad_hex.len()));

    // Declared size, rather than backing-buffer size, controls recognition.
    let full_hex = [b'a'; 64];
    assert!(!is_seed_backup_candidate(&full_hex, 63));
}

use super::*;
use crate::crypto::password_kdf::{encode_metadata, PasswordKdfParams};

fn current_backup(kind: BackupPayloadKind, payload_len: usize) -> std::vec::Vec<u8> {
    let total = BACKUP_CURRENT_HEADER_SIZE + payload_len + TAG_SIZE;
    let mut bytes = std::vec![0u8; total];
    bytes[..8].copy_from_slice(&BACKUP_CURRENT_MAGIC);
    bytes[8] = BACKUP_CURRENT_VERSION;
    bytes[9] = kind.code();
    bytes[10] = KDF_ID_DEVICE_HMAC_SHA256;
    bytes[11] = CredentialKind::Password as u8;
    bytes[12..14].copy_from_slice(&(payload_len as u16).to_le_bytes());
    bytes[16..16 + METADATA_SIZE]
        .copy_from_slice(&encode_metadata(PasswordKdfParams::current()).expect("metadata"));
    bytes[28..44].fill(0x11);
    bytes[44..56].fill(0x22);
    bytes[BACKUP_CURRENT_HEADER_SIZE..BACKUP_CURRENT_HEADER_SIZE + payload_len].fill(0x33);
    bytes[BACKUP_CURRENT_HEADER_SIZE + payload_len..].fill(0x44);
    bytes
}

fn legacy_backup(kind: BackupPayloadKind, payload_len: usize) -> std::vec::Vec<u8> {
    let total = BACKUP_LEGACY_HEADER_SIZE + payload_len + TAG_SIZE;
    let mut bytes = std::vec![0u8; total];
    bytes[..8].copy_from_slice(&BACKUP_LEGACY_MAGIC);
    bytes[8] = BACKUP_LEGACY_VERSION;
    bytes[9] = kind.code();
    bytes[10] = KDF_ID_DEVICE_HMAC_SHA256;
    bytes[11] = CredentialKind::Password as u8;
    bytes[12..14].copy_from_slice(&(payload_len as u16).to_le_bytes());
    bytes[16..32].fill(0x55);
    bytes[32..44].fill(0x66);
    bytes[BACKUP_LEGACY_HEADER_SIZE..BACKUP_LEGACY_HEADER_SIZE + payload_len].fill(0x77);
    bytes[BACKUP_LEGACY_HEADER_SIZE + payload_len..].fill(0x88);
    bytes
}

fn current_transport(data_len: usize) -> std::vec::Vec<u8> {
    let total = TRANSPORT_CURRENT_CIPHERTEXT_START + data_len + TRANSPORT_TAG_SIZE;
    let mut bytes = std::vec![0u8; total];
    bytes[..4].copy_from_slice(&TRANSPORT_CURRENT_MAGIC);
    bytes[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
    bytes[6..6 + METADATA_SIZE]
        .copy_from_slice(&encode_metadata(PasswordKdfParams::current()).expect("metadata"));
    let salt_start = 6 + METADATA_SIZE;
    let nonce_start = salt_start + SALT_SIZE;
    bytes[salt_start..nonce_start].fill(0x31);
    bytes[nonce_start..TRANSPORT_CURRENT_HEADER_SIZE].fill(0x32);
    bytes[TRANSPORT_CURRENT_CIPHERTEXT_START..TRANSPORT_CURRENT_CIPHERTEXT_START + data_len]
        .fill(0x33);
    bytes[TRANSPORT_CURRENT_CIPHERTEXT_START + data_len..].fill(0x34);
    bytes
}

fn legacy_transport(data_len: usize) -> std::vec::Vec<u8> {
    let total = TRANSPORT_LEGACY_CIPHERTEXT_START + data_len + TRANSPORT_TAG_SIZE;
    let mut bytes = std::vec![0u8; total];
    bytes[..4].copy_from_slice(&TRANSPORT_LEGACY_MAGIC);
    bytes[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
    bytes[TRANSPORT_LEGACY_HEADER_SIZE..TRANSPORT_LEGACY_CIPHERTEXT_START].fill(0x41);
    bytes[TRANSPORT_LEGACY_CIPHERTEXT_START..TRANSPORT_LEGACY_CIPHERTEXT_START + data_len]
        .fill(0x42);
    bytes[TRANSPORT_LEGACY_CIPHERTEXT_START + data_len..].fill(0x43);
    bytes
}

#[test]
fn backup_payload_kind_and_current_legacy_headers_round_trip() {
    assert_eq!(BackupPayloadKind::Seed.code(), 1);
    assert_eq!(BackupPayloadKind::Xprv.code(), 2);
    assert_eq!(parse_backup_kind(1), Ok(BackupPayloadKind::Seed));
    assert_eq!(parse_backup_kind(2), Ok(BackupPayloadKind::Xprv));
    assert_eq!(parse_backup_kind(3), Err(FramingError::WrongPurpose));

    let current = current_backup(BackupPayloadKind::Seed, 32);
    let parsed = parse_backup_header(&current).expect("current backup");
    assert_eq!(parsed.kind, BackupPayloadKind::Seed);
    assert_eq!(parsed.payload_len, 32);
    assert_eq!(parsed.header_size, BACKUP_CURRENT_HEADER_SIZE);
    assert_eq!(parsed.salt, [0x11; SALT_SIZE]);
    assert_eq!(parsed.nonce, [0x22; NONCE_SIZE]);
    assert!(matches!(parsed.kdf, BackupReaderKdf::Argon2id(_)));

    let legacy = legacy_backup(BackupPayloadKind::Xprv, 48);
    let parsed = parse_backup_header(&legacy).expect("legacy backup");
    assert_eq!(parsed.kind, BackupPayloadKind::Xprv);
    assert_eq!(parsed.payload_len, 48);
    assert_eq!(parsed.header_size, BACKUP_LEGACY_HEADER_SIZE);
    assert_eq!(parsed.salt, [0x55; SALT_SIZE]);
    assert_eq!(parsed.nonce, [0x66; NONCE_SIZE]);
    assert_eq!(parsed.kdf, BackupReaderKdf::LegacyPbkdf2);
}

#[test]
fn backup_header_rejects_format_purpose_length_kdf_and_nonzero_material_boundaries() {
    assert_eq!(parse_backup_header(&[]), Err(FramingError::InvalidLength));

    // Current magic can pass the legacy-sized outer minimum while still being
    // one byte short of the current header+tag minimum. Exercise that exact
    // dispatch boundary so parse_current_backup_header's short-input guard is
    // represented in critical-crypto branch coverage.
    let mut truncated_current = std::vec![0u8; BACKUP_CURRENT_HEADER_SIZE + TAG_SIZE - 1];
    truncated_current[..8].copy_from_slice(&BACKUP_CURRENT_MAGIC);
    assert_eq!(
        parse_backup_header(&truncated_current),
        Err(FramingError::InvalidLength)
    );

    // Legacy magic is dispatchable with only eight bytes present, so exercise
    // the legacy parser's own minimum-length guard directly. This covers the
    // short-input rejection branch rather than relying on the outer magic read.
    let legacy_minimum = BACKUP_LEGACY_HEADER_SIZE + 1 + TAG_SIZE;
    let mut truncated_legacy = std::vec![0u8; legacy_minimum - 1];
    truncated_legacy[..8].copy_from_slice(&BACKUP_LEGACY_MAGIC);
    assert_eq!(
        parse_backup_header(&truncated_legacy),
        Err(FramingError::InvalidLength)
    );

    // Exactly header+tag bytes are long enough to enter the current-header
    // parser. An invalid version must therefore reach the format check rather
    // than being rejected as a short input. This pins the strict `<` boundary.
    let mut exact_current_minimum = std::vec![0u8; BACKUP_CURRENT_HEADER_SIZE + TAG_SIZE];
    exact_current_minimum[..8].copy_from_slice(&BACKUP_CURRENT_MAGIC);
    exact_current_minimum[8] = BACKUP_CURRENT_VERSION.wrapping_add(1);
    assert_eq!(
        parse_backup_header(&exact_current_minimum),
        Err(FramingError::UnsupportedFormat)
    );

    let mut unknown = legacy_backup(BackupPayloadKind::Seed, 1);
    unknown[..8].copy_from_slice(b"UNKNOWN!");
    assert_eq!(
        parse_backup_header(&unknown),
        Err(FramingError::InvalidFormat)
    );

    let mut current = current_backup(BackupPayloadKind::Seed, 1);
    current[8] = 9;
    assert_eq!(
        parse_backup_header(&current),
        Err(FramingError::UnsupportedFormat)
    );
    let mut current = current_backup(BackupPayloadKind::Seed, 1);
    current[9] = 9;
    assert_eq!(
        parse_backup_header(&current),
        Err(FramingError::WrongPurpose)
    );

    for index in [10usize, 11, 14, 15, 56, 57, 58, 59] {
        let mut invalid = current_backup(BackupPayloadKind::Seed, 1);
        invalid[index] ^= 0x7f;
        assert_eq!(
            parse_backup_header(&invalid),
            Err(FramingError::InvalidFormat),
            "index {index}"
        );
    }

    let mut invalid_kdf = current_backup(BackupPayloadKind::Seed, 1);
    invalid_kdf[16] = 0xff;
    assert_eq!(
        parse_backup_header(&invalid_kdf),
        Err(FramingError::UnsupportedKdf)
    );

    let mut zero_salt = current_backup(BackupPayloadKind::Seed, 1);
    zero_salt[28..44].fill(0);
    assert_eq!(
        parse_backup_header(&zero_salt),
        Err(FramingError::InvalidFormat)
    );
    let mut zero_nonce = current_backup(BackupPayloadKind::Seed, 1);
    zero_nonce[44..56].fill(0);
    assert_eq!(
        parse_backup_header(&zero_nonce),
        Err(FramingError::InvalidFormat)
    );

    let mut zero_len = current_backup(BackupPayloadKind::Seed, 1);
    zero_len[12..14].fill(0);
    assert_eq!(
        parse_backup_header(&zero_len),
        Err(FramingError::InvalidLength)
    );
    let too_long = current_backup(BackupPayloadKind::Seed, BACKUP_MAX_PLAINTEXT + 1);
    assert_eq!(
        parse_backup_header(&too_long),
        Err(FramingError::InvalidLength)
    );
    let mut mismatch = current_backup(BackupPayloadKind::Seed, 2);
    mismatch.pop();
    assert_eq!(
        parse_backup_header(&mismatch),
        Err(FramingError::InvalidLength)
    );

    let mut legacy = legacy_backup(BackupPayloadKind::Seed, 1);
    legacy[8] = 9;
    assert_eq!(
        parse_backup_header(&legacy),
        Err(FramingError::UnsupportedFormat)
    );
    let mut legacy = legacy_backup(BackupPayloadKind::Seed, 1);
    legacy[9] = 9;
    assert_eq!(
        parse_backup_header(&legacy),
        Err(FramingError::WrongPurpose)
    );
    for index in [10usize, 11, 14, 15, 44, 45, 46, 47] {
        let mut invalid = legacy_backup(BackupPayloadKind::Seed, 1);
        invalid[index] ^= 0x55;
        assert_eq!(
            parse_backup_header(&invalid),
            Err(FramingError::InvalidFormat),
            "legacy index {index}"
        );
    }

    assert_eq!(
        copy_nonzero::<4>(&[1, 2, 3]),
        Err(FramingError::InvalidLength)
    );
    assert_eq!(
        copy_nonzero::<4>(&[1, 2, 3, 4, 5]),
        Err(FramingError::InvalidLength)
    );
    assert_eq!(
        copy_nonzero::<4>(&[0, 0, 0, 0]),
        Err(FramingError::InvalidFormat)
    );
    assert_eq!(copy_nonzero::<4>(&[1, 2, 3, 4]), Ok([1, 2, 3, 4]));
}

#[test]
fn current_and_legacy_transport_headers_round_trip_and_reject_boundaries() {
    let current = current_transport(17);
    let parsed = parse_transport_header(&current, current.len()).expect("current transport");
    assert_eq!(parsed.version, TransportVersion::Current);
    assert_eq!(parsed.data_len, 17);
    assert_eq!(parsed.header_len, TRANSPORT_CURRENT_HEADER_SIZE);
    assert_eq!(parsed.ciphertext_start, TRANSPORT_CURRENT_CIPHERTEXT_START);
    assert_eq!(parsed.tag_start, TRANSPORT_CURRENT_CIPHERTEXT_START + 17);
    assert_eq!(parsed.salt, [0x31; SALT_SIZE]);
    assert_eq!(parsed.nonce, [0x32; TRANSPORT_NONCE_SIZE]);
    assert_eq!(parsed.parameters, Some(PasswordKdfParams::current()));

    let legacy = legacy_transport(9);
    let parsed = parse_transport_header(&legacy, legacy.len()).expect("legacy transport");
    assert_eq!(parsed.version, TransportVersion::Legacy);
    assert_eq!(parsed.data_len, 9);
    assert_eq!(parsed.header_len, TRANSPORT_LEGACY_HEADER_SIZE);
    assert_eq!(parsed.ciphertext_start, TRANSPORT_LEGACY_CIPHERTEXT_START);
    assert_eq!(parsed.tag_start, TRANSPORT_LEGACY_CIPHERTEXT_START + 9);
    assert_eq!(parsed.parameters, None);
    assert_eq!(parsed.salt, [0; SALT_SIZE]);
    assert_eq!(parsed.nonce, [0x41; TRANSPORT_NONCE_SIZE]);

    assert_eq!(
        parse_transport_header(&current, current.len() + 1),
        Err(FramingError::InvalidLength)
    );
    assert_eq!(
        parse_transport_header(&current, 3),
        Err(FramingError::InvalidLength)
    );
    let mut unknown = current.clone();
    unknown[..4].copy_from_slice(b"NOPE");
    assert_eq!(
        parse_transport_header(&unknown, unknown.len()),
        Err(FramingError::InvalidFormat)
    );

    let too_short = std::vec![0u8; TRANSPORT_CURRENT_HEADER_SIZE + TRANSPORT_TAG_SIZE];
    assert_eq!(
        parse_current_transport_header(&too_short),
        Err(FramingError::InvalidLength)
    );
    let mut zero_len = current_transport(1);
    zero_len[4..6].fill(0);
    assert_eq!(
        parse_current_transport_header(&zero_len),
        Err(FramingError::InvalidLength)
    );
    let too_long = current_transport(TRANSPORT_CURRENT_MAX_DATA_LEN + 1);
    assert_eq!(
        parse_current_transport_header(&too_long),
        Err(FramingError::InvalidLength)
    );
    let mut mismatch = current_transport(2);
    mismatch.pop();
    assert_eq!(
        parse_current_transport_header(&mismatch),
        Err(FramingError::InvalidLength)
    );
    let mut bad_kdf = current_transport(1);
    bad_kdf[6] = 0xff;
    assert_eq!(
        parse_current_transport_header(&bad_kdf),
        Err(FramingError::UnsupportedKdf)
    );
    let salt_start = 6 + METADATA_SIZE;
    let nonce_start = salt_start + SALT_SIZE;
    let mut zero_salt = current_transport(1);
    zero_salt[salt_start..nonce_start].fill(0);
    assert_eq!(
        parse_current_transport_header(&zero_salt),
        Err(FramingError::InvalidFormat)
    );
    let mut zero_nonce = current_transport(1);
    zero_nonce[nonce_start..TRANSPORT_CURRENT_HEADER_SIZE].fill(0);
    assert_eq!(
        parse_current_transport_header(&zero_nonce),
        Err(FramingError::InvalidFormat)
    );

    let legacy_short = std::vec![0u8; TRANSPORT_LEGACY_CIPHERTEXT_START + TRANSPORT_TAG_SIZE];
    assert_eq!(
        parse_legacy_transport_header(&legacy_short),
        Err(FramingError::InvalidLength)
    );
    let mut legacy_zero = legacy_transport(1);
    legacy_zero[4..6].fill(0);
    assert_eq!(
        parse_legacy_transport_header(&legacy_zero),
        Err(FramingError::InvalidLength)
    );
    let legacy_too_long = legacy_transport(TRANSPORT_LEGACY_MAX_DATA_LEN + 1);
    assert_eq!(
        parse_legacy_transport_header(&legacy_too_long),
        Err(FramingError::InvalidLength)
    );
    let mut legacy_mismatch = legacy_transport(2);
    legacy_mismatch.pop();
    assert_eq!(
        parse_legacy_transport_header(&legacy_mismatch),
        Err(FramingError::InvalidLength)
    );
}

#[test]
fn framing_exact_size_and_maximum_boundaries_are_accepted() {
    assert_eq!(TRANSPORT_CURRENT_HEADER_SIZE, 46);
    assert_eq!(TRANSPORT_CURRENT_CIPHERTEXT_START, 46);
    assert_eq!(TRANSPORT_LEGACY_CIPHERTEXT_START, 18);
    assert_eq!(TRANSPORT_CURRENT_MAX_DATA_LEN, 962);
    assert_eq!(TRANSPORT_LEGACY_MAX_DATA_LEN, 990);

    let current_backup_max = current_backup(BackupPayloadKind::Seed, BACKUP_MAX_PLAINTEXT);
    assert_eq!(
        parse_backup_header(&current_backup_max)
            .expect("max current backup")
            .payload_len,
        BACKUP_MAX_PLAINTEXT
    );
    let legacy_backup_max = legacy_backup(BackupPayloadKind::Seed, BACKUP_MAX_PLAINTEXT);
    assert_eq!(
        parse_backup_header(&legacy_backup_max)
            .expect("max legacy backup")
            .payload_len,
        BACKUP_MAX_PLAINTEXT
    );

    let current_one = current_transport(1);
    assert_eq!(
        parse_current_transport_header(&current_one)
            .expect("minimum current transport")
            .data_len,
        1
    );
    let current_max = current_transport(TRANSPORT_CURRENT_MAX_DATA_LEN);
    assert_eq!(
        parse_current_transport_header(&current_max)
            .expect("maximum current transport")
            .data_len,
        TRANSPORT_CURRENT_MAX_DATA_LEN
    );

    let legacy_one = legacy_transport(1);
    assert_eq!(
        parse_legacy_transport_header(&legacy_one)
            .expect("minimum legacy transport")
            .data_len,
        1
    );
    let legacy_max = legacy_transport(TRANSPORT_LEGACY_MAX_DATA_LEN);
    assert_eq!(
        parse_legacy_transport_header(&legacy_max)
            .expect("maximum legacy transport")
            .data_len,
        TRANSPORT_LEGACY_MAX_DATA_LEN
    );
}

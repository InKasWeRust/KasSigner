use super::*;

const DESCRIPTOR: &str = concat!(
    "multi_hd45(2,",
    "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK,",
    "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
    ")"
);
const PASSWORD: &[u8] = b"CorrectHorse9";
const SALT: [u8; SALT_SIZE] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];
const NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];

fn current_envelope() -> ([u8; 1024], usize) {
    let mut encrypted = [0u8; 1024];
    let length = seal_envelope(
        DESCRIPTOR.as_bytes(), PASSWORD, &SALT, &NONCE, &mut encrypted,
    )
    .expect("encrypt current envelope");
    (encrypted, length)
}

fn legacy_envelope() -> ([u8; 1024], usize) {
    let data = DESCRIPTOR.as_bytes();
    let mut encrypted = [0u8; 1024];
    encrypted[..4].copy_from_slice(LEGACY_MAGIC);
    encrypted[4..6].copy_from_slice(&(data.len() as u16).to_le_bytes());
    encrypted[container_framing::TRANSPORT_LEGACY_HEADER_SIZE..LEGACY_CIPHERTEXT_START].copy_from_slice(&NONCE);
    encrypted[LEGACY_CIPHERTEXT_START..LEGACY_CIPHERTEXT_START + data.len()]
        .copy_from_slice(data);
    let mut key = legacy_pbkdf2::derive_legacy_32(PASSWORD, LEGACY_SALT, LEGACY_ITERATIONS);
    let aad = [b'K', b'A', b'S', 0x03, encrypted[4], encrypted[5]];
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(&NONCE),
            &aad,
            &mut encrypted[LEGACY_CIPHERTEXT_START..LEGACY_CIPHERTEXT_START + data.len()],
        )
        .expect("encrypt legacy fixture");
    zeroize_bytes(&mut key);
    let tag_start = LEGACY_CIPHERTEXT_START + data.len();
    encrypted[tag_start..tag_start + TAG_LEN].copy_from_slice(&tag);
    (encrypted, tag_start + TAG_LEN)
}

#[test]
fn current_envelope_round_trip_authenticates_kdf_metadata_and_has_no_fallback() {
    let (encrypted, length) = current_envelope();
    assert_eq!(&encrypted[..4], CURRENT_MAGIC);
    let mut plaintext = [0u8; 1024];
    let n = open_envelope(&encrypted, length, PASSWORD, &mut plaintext).expect("decrypt");
    assert_eq!(&plaintext[..n], DESCRIPTOR.as_bytes());

    for offset in [6usize, 7, 8, 9, 10, 14, 18, 25, 39, CURRENT_CIPHERTEXT_START] {
        let mut tampered = encrypted;
        tampered[offset] ^= 1;
        assert!(open_envelope(&tampered, length, PASSWORD, &mut plaintext).is_err());
    }
    assert_eq!(
        open_envelope(&encrypted, length, b"WrongHorse9", &mut plaintext),
        Err(DecryptError::Authentication)
    );
    let mut unsupported = encrypted;
    unsupported[6] = 0xff;
    assert_eq!(
        open_envelope(&unsupported, length, PASSWORD, &mut plaintext),
        Err(DecryptError::InvalidEnvelope)
    );
}

#[test]
fn current_envelope_rejects_weak_params_malformed_lengths_and_zero_material() {
    let (encrypted, length) = current_envelope();
    let mut plaintext = [0xa5u8; 1024];

    let mut weak = encrypted;
    weak[10..14].copy_from_slice(&(password_kdf::PasswordKdfParams::current().m_cost_kib - 1).to_le_bytes());
    assert_eq!(
        open_envelope(&weak, length, PASSWORD, &mut plaintext),
        Err(DecryptError::InvalidEnvelope)
    );

    for bad_length in [0usize, 3, CURRENT_HEADER_LEN + TAG_LEN, length - 1, length + 1] {
        assert_eq!(
            open_envelope(&encrypted, bad_length, PASSWORD, &mut plaintext),
            Err(DecryptError::InvalidEnvelope)
        );
    }
    let mut zero_salt = encrypted;
    let salt_start = 6 + METADATA_SIZE;
    zero_salt[salt_start..salt_start + SALT_SIZE].fill(0);
    assert_eq!(
        open_envelope(&zero_salt, length, PASSWORD, &mut plaintext),
        Err(DecryptError::InvalidEnvelope)
    );
    let mut zero_nonce = encrypted;
    let nonce_start = salt_start + SALT_SIZE;
    zero_nonce[nonce_start..CURRENT_HEADER_LEN].fill(0);
    assert_eq!(
        open_envelope(&zero_nonce, length, PASSWORD, &mut plaintext),
        Err(DecryptError::InvalidEnvelope)
    );
}

#[test]
fn authentication_failure_clears_current_plaintext_region() {
    let (mut encrypted, length) = current_envelope();
    encrypted[length - 1] ^= 1;
    let mut plaintext = [0xa5u8; 1024];
    assert_eq!(
        open_envelope(&encrypted, length, PASSWORD, &mut plaintext),
        Err(DecryptError::Authentication)
    );
    assert!(plaintext[..DESCRIPTOR.len()].iter().all(|byte| *byte == 0));
}

#[test]
fn legacy_pbkdf2_reader_is_selected_only_by_legacy_magic() {
    let (legacy, length) = legacy_envelope();
    let mut plaintext = [0u8; 1024];
    let n = open_envelope(&legacy, length, PASSWORD, &mut plaintext).expect("legacy decrypt");
    assert_eq!(&plaintext[..n], DESCRIPTOR.as_bytes());

    let mut relabeled = legacy;
    relabeled[..4].copy_from_slice(CURRENT_MAGIC);
    assert!(open_envelope(&relabeled, length, PASSWORD, &mut plaintext).is_err());

    let mut damaged = legacy;
    damaged[length - 1] ^= 1;
    assert_eq!(
        open_envelope(&damaged, length, PASSWORD, &mut plaintext),
        Err(DecryptError::Authentication)
    );
}

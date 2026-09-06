use crate::crypto::credential::CredentialKind;
use crate::crypto::password_kdf::{derive_key_32, PasswordKdfPurpose};
use sha2::{Digest, Sha256};

use super::{
    derive_aes_key, generate_fresh_material, open_in_place, seal_in_place, DeviceBoundError,
    EntropySource, HardwareHmac, KdfParameters, OpenRequest, StoragePurpose, FORMAT_VERSION,
    KDF_ID_DEVICE_HMAC_SHA256, NONCE_SIZE,
};

const PASSWORD: &[u8] = b"correct7horse";
const WRONG_PASSWORD: &[u8] = b"incorrect7horse";
const SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const NONCE: [u8; NONCE_SIZE] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
];
const HEADER: &[u8] = b"KSWLT003-test-header";
const DEVICE_A: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const DEVICE_B: [u8; 32] = [0x5a; 32];
const EXPECTED_KEY: [u8; 32] = [
    0xe8, 0xad, 0x51, 0x48, 0x1e, 0x69, 0x01, 0xfc, 0x9d, 0xd1, 0x9f, 0x98, 0x60, 0x74, 0xc1, 0xf8,
    0x29, 0x25, 0xeb, 0xe4, 0x3d, 0xe4, 0x93, 0x6f, 0x38, 0x4e, 0x3d, 0x0e, 0x6e, 0x88, 0x0b, 0xa9,
];

struct MockHmac {
    secret: [u8; 32],
    available: bool,
    calls: u32,
}

impl MockHmac {
    const fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            available: true,
            calls: 0,
        }
    }

    const fn unavailable() -> Self {
        Self {
            secret: [0u8; 32],
            available: false,
            calls: 0,
        }
    }
}

impl HardwareHmac for MockHmac {
    fn hmac_sha256(
        &mut self,
        message: &[u8],
        output: &mut [u8; 32],
    ) -> Result<(), DeviceBoundError> {
        self.calls = self.calls.saturating_add(1);
        if !self.available {
            return Err(DeviceBoundError::HardwareHmacUnavailable);
        }
        *output = software_hmac_sha256(&self.secret, message);
        Ok(())
    }
}

struct CountingEntropy(u8);

struct FailingEntropy;

impl EntropySource for FailingEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError> {
        output.fill(0xaa);
        Err(DeviceBoundError::EntropyUnavailable)
    }
}

struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError> {
        output.fill(0);
        Ok(())
    }
}

struct FailSecondEntropy {
    calls: u8,
}

impl EntropySource for FailSecondEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError> {
        self.calls = self.calls.saturating_add(1);
        if self.calls == 1 {
            output.fill(0x5a);
            Ok(())
        } else {
            output.fill(0xa5);
            Err(DeviceBoundError::EntropyUnavailable)
        }
    }
}

struct ZeroNonceEntropy {
    calls: u8,
}

impl EntropySource for ZeroNonceEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError> {
        self.calls = self.calls.saturating_add(1);
        if self.calls == 1 {
            output.fill(0x5a);
        } else {
            output.fill(0);
        }
        Ok(())
    }
}

impl EntropySource for CountingEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeviceBoundError> {
        for byte in output.iter_mut() {
            self.0 = self.0.wrapping_add(17);
            *byte = self.0;
        }
        Ok(())
    }
}

#[test]
fn deterministic_argon2_device_kdf_vector_matches_independent_host_result() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let mut provider = MockHmac::new(DEVICE_A);
    let key = derive_aes_key(
        &mut provider,
        params(StoragePurpose::InternalWallet),
        &stretched,
        &SALT,
        HEADER,
    )
    .expect("device-bound KDF");
    assert_eq!(key, EXPECTED_KEY);
    assert_eq!(provider.calls, 1);
}

#[test]
fn kdf_domain_separates_internal_sd_header_salt_and_credential_kind() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let mut provider = MockHmac::new(DEVICE_A);
    let internal = derive_aes_key(
        &mut provider,
        params(StoragePurpose::InternalWallet),
        &stretched,
        &SALT,
        HEADER,
    )
    .unwrap();
    let sd = derive_aes_key(
        &mut provider,
        params(StoragePurpose::SdWallet),
        &stretched,
        &SALT,
        HEADER,
    )
    .unwrap();
    let seed_backup = derive_aes_key(
        &mut provider,
        params(StoragePurpose::SdSeedBackup),
        &stretched,
        &SALT,
        HEADER,
    )
    .unwrap();
    let xprv_backup = derive_aes_key(
        &mut provider,
        params(StoragePurpose::SdXprvBackup),
        &stretched,
        &SALT,
        HEADER,
    )
    .unwrap();
    let stego_backup = derive_aes_key(
        &mut provider,
        params(StoragePurpose::StegoWallet),
        &stretched,
        &SALT,
        HEADER,
    )
    .unwrap();
    let mut changed_salt = SALT;
    changed_salt[0] ^= 0x80;
    let salt_key = derive_aes_key(
        &mut provider,
        params(StoragePurpose::InternalWallet),
        &stretched,
        &changed_salt,
        HEADER,
    )
    .unwrap();
    let header_key = derive_aes_key(
        &mut provider,
        params(StoragePurpose::InternalWallet),
        &stretched,
        &SALT,
        b"KSWLT003-other-header",
    )
    .unwrap();
    let pin = KdfParameters::current(StoragePurpose::InternalWallet, CredentialKind::Pin);
    let pin_key = derive_aes_key(&mut provider, pin, &stretched, &SALT, HEADER).unwrap();
    assert_ne!(internal, sd);
    assert_ne!(internal, seed_backup);
    assert_ne!(internal, xprv_backup);
    assert_ne!(sd, seed_backup);
    assert_ne!(seed_backup, xprv_backup);
    assert_ne!(stego_backup, internal);
    assert_ne!(stego_backup, sd);
    assert_ne!(stego_backup, seed_backup);
    assert_ne!(stego_backup, xprv_backup);
    assert_ne!(internal, salt_key);
    assert_ne!(internal, header_key);
    assert_ne!(internal, pin_key);
}

#[test]
fn unsupported_format_or_kdf_parameters_fail_closed_without_hmac_use() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let mut provider = MockHmac::new(DEVICE_A);
    let mut bad_version = params(StoragePurpose::InternalWallet);
    bad_version.format_version = FORMAT_VERSION.wrapping_add(1);
    assert_eq!(
        derive_aes_key(&mut provider, bad_version, &stretched, &SALT, HEADER),
        Err(DeviceBoundError::UnsupportedParameters),
    );
    let mut bad_kdf = params(StoragePurpose::InternalWallet);
    bad_kdf.kdf_id = KDF_ID_DEVICE_HMAC_SHA256.wrapping_add(1);
    assert_eq!(
        derive_aes_key(&mut provider, bad_kdf, &stretched, &SALT, HEADER),
        Err(DeviceBoundError::UnsupportedParameters),
    );
    assert_eq!(provider.calls, 0);
}

#[test]
fn same_device_roundtrip_succeeds_and_tampering_fails_with_zeroized_plaintext() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let parameters = params(StoragePurpose::InternalWallet);
    let mut provider = MockHmac::new(DEVICE_A);
    let mut ciphertext = *b"device-bound-wallet-payload";
    let tag = seal_in_place(
        &mut provider,
        parameters,
        &stretched,
        &SALT,
        &NONCE,
        HEADER,
        &mut ciphertext,
    )
    .unwrap();
    assert_ne!(&ciphertext, b"device-bound-wallet-payload");
    open_in_place(
        &mut provider,
        OpenRequest {
            parameters,
            stretched_credential: &stretched,
            salt: &SALT,
            nonce: &NONCE,
            authenticated_header: HEADER,
            tag: &tag,
        },
        &mut ciphertext,
    )
    .unwrap();
    assert_eq!(&ciphertext, b"device-bound-wallet-payload");

    let mut tampered = *b"device-bound-wallet-payload";
    let mut provider = MockHmac::new(DEVICE_A);
    let mut tag = seal_in_place(
        &mut provider,
        parameters,
        &stretched,
        &SALT,
        &NONCE,
        HEADER,
        &mut tampered,
    )
    .unwrap();
    tag[3] ^= 0x40;
    assert_eq!(
        open_in_place(
            &mut provider,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut tampered,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );
    assert!(tampered.iter().all(|byte| *byte == 0));

    let mut provider = MockHmac::new(DEVICE_A);
    let mut ciphertext = *b"device-bound-wallet-payload";
    let tag = seal_in_place(
        &mut provider,
        parameters,
        &stretched,
        &SALT,
        &NONCE,
        HEADER,
        &mut ciphertext,
    )
    .unwrap();
    ciphertext[5] ^= 0x80;
    assert_eq!(
        open_in_place(
            &mut provider,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut ciphertext,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );
    assert!(ciphertext.iter().all(|byte| *byte == 0));
}

#[test]
fn wrong_password_and_wrong_device_are_rejected() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let wrong = derive_key_32(PasswordKdfPurpose::PersistentWallet, WRONG_PASSWORD, &SALT).unwrap();
    let parameters = params(StoragePurpose::InternalWallet);
    let mut provider = MockHmac::new(DEVICE_A);
    let mut ciphertext = *b"device-bound-wallet-payload";
    let tag = seal_in_place(
        &mut provider,
        parameters,
        &stretched,
        &SALT,
        &NONCE,
        HEADER,
        &mut ciphertext,
    )
    .unwrap();

    let mut wrong_password_copy = ciphertext;
    let mut same_device = MockHmac::new(DEVICE_A);
    assert_eq!(
        open_in_place(
            &mut same_device,
            OpenRequest {
                parameters,
                stretched_credential: &wrong,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut wrong_password_copy,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );

    let mut cross_device_copy = ciphertext;
    let mut other_device = MockHmac::new(DEVICE_B);
    assert_eq!(
        open_in_place(
            &mut other_device,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut cross_device_copy,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );
    assert!(wrong_password_copy.iter().all(|byte| *byte == 0));
    assert!(cross_device_copy.iter().all(|byte| *byte == 0));
}

#[test]
fn altered_authenticated_header_is_rejected() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let parameters = params(StoragePurpose::SdWallet);
    let mut provider = MockHmac::new(DEVICE_A);
    let mut ciphertext = *b"device-bound-wallet-payload";
    let tag = seal_in_place(
        &mut provider,
        parameters,
        &stretched,
        &SALT,
        &NONCE,
        HEADER,
        &mut ciphertext,
    )
    .unwrap();
    let mut copy = ciphertext;
    let mut provider = MockHmac::new(DEVICE_A);
    assert_eq!(
        open_in_place(
            &mut provider,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: b"KSWLT003-tampered-header",
                tag: &tag,
            },
            &mut copy,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );
    assert!(copy.iter().all(|byte| *byte == 0));

    let mut changed_salt = SALT;
    changed_salt[7] ^= 0x01;
    let mut salt_copy = ciphertext;
    let mut provider = MockHmac::new(DEVICE_A);
    assert_eq!(
        open_in_place(
            &mut provider,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &changed_salt,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut salt_copy,
        ),
        Err(DeviceBoundError::AuthenticationFailed),
    );
    assert!(salt_copy.iter().all(|byte| *byte == 0));
}

#[test]
fn missing_hmac_service_fails_closed_and_zeroizes_buffers() {
    let stretched = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT).unwrap();
    let parameters = params(StoragePurpose::InternalWallet);
    let mut provider = MockHmac::unavailable();
    assert_eq!(
        derive_aes_key(&mut provider, parameters, &stretched, &SALT, HEADER),
        Err(DeviceBoundError::HardwareHmacUnavailable),
    );

    let mut plaintext = *b"plaintext-must-be-cleared!!!";
    assert_eq!(
        seal_in_place(
            &mut provider,
            parameters,
            &stretched,
            &SALT,
            &NONCE,
            HEADER,
            &mut plaintext,
        ),
        Err(DeviceBoundError::HardwareHmacUnavailable),
    );
    assert!(plaintext.iter().all(|byte| *byte == 0));

    let mut ciphertext = *b"ciphertext-must-be-cleared!!";
    let tag = [0u8; 16];
    assert_eq!(
        open_in_place(
            &mut provider,
            OpenRequest {
                parameters,
                stretched_credential: &stretched,
                salt: &SALT,
                nonce: &NONCE,
                authenticated_header: HEADER,
                tag: &tag,
            },
            &mut ciphertext,
        ),
        Err(DeviceBoundError::HardwareHmacUnavailable),
    );
    assert!(ciphertext.iter().all(|byte| *byte == 0));
}

#[test]
fn fresh_salt_and_nonce_are_generated_for_each_container() {
    let mut entropy = CountingEntropy(0);
    let mut salt_a = [0u8; 16];
    let mut nonce_a = [0u8; NONCE_SIZE];
    let mut salt_b = [0u8; 16];
    let mut nonce_b = [0u8; NONCE_SIZE];
    generate_fresh_material(&mut entropy, &mut salt_a, &mut nonce_a).unwrap();
    generate_fresh_material(&mut entropy, &mut salt_b, &mut nonce_b).unwrap();
    assert_ne!(salt_a, salt_b);
    assert_ne!(nonce_a, nonce_b);
    assert!(salt_a.iter().any(|byte| *byte != 0));
    assert!(nonce_a.iter().any(|byte| *byte != 0));
}

#[test]
fn entropy_failure_or_all_zero_material_fails_closed_and_clears_outputs() {
    let mut salt = [0x11u8; 16];
    let mut nonce = [0x22u8; NONCE_SIZE];
    assert_eq!(
        generate_fresh_material(&mut FailingEntropy, &mut salt, &mut nonce),
        Err(DeviceBoundError::EntropyUnavailable),
    );
    assert!(salt.iter().all(|byte| *byte == 0));
    assert!(nonce.iter().all(|byte| *byte == 0));

    salt.fill(0x33);
    nonce.fill(0x44);
    assert_eq!(
        generate_fresh_material(&mut ZeroEntropy, &mut salt, &mut nonce),
        Err(DeviceBoundError::EntropyUnavailable),
    );
    assert!(salt.iter().all(|byte| *byte == 0));
    assert!(nonce.iter().all(|byte| *byte == 0));

    salt.fill(0x33);
    nonce.fill(0x44);
    let mut fail_second = FailSecondEntropy { calls: 0 };
    assert_eq!(
        generate_fresh_material(&mut fail_second, &mut salt, &mut nonce),
        Err(DeviceBoundError::EntropyUnavailable),
    );
    assert_eq!(fail_second.calls, 2);
    assert!(salt.iter().all(|byte| *byte == 0));
    assert!(nonce.iter().all(|byte| *byte == 0));

    salt.fill(0x33);
    nonce.fill(0x44);
    let mut zero_nonce = ZeroNonceEntropy { calls: 0 };
    assert_eq!(
        generate_fresh_material(&mut zero_nonce, &mut salt, &mut nonce),
        Err(DeviceBoundError::EntropyUnavailable),
    );
    assert_eq!(zero_nonce.calls, 2);
    assert!(salt.iter().all(|byte| *byte == 0));
    assert!(nonce.iter().all(|byte| *byte == 0));
}

fn params(purpose: StoragePurpose) -> KdfParameters {
    KdfParameters::current(purpose, CredentialKind::Password)
}

fn software_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

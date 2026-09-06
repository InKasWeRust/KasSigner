//! Regression coverage for versioned Argon2id backup formats and device-bound
//! cryptographic separation.

use offline_signer::crypto::device_bound_storage::{
    open_in_place, seal_in_place, DeviceBoundError, HardwareHmac, KdfParameters, OpenRequest,
    StoragePurpose, TAG_SIZE,
};
use sha2::{Digest,Sha256};
use crate::services::credential_policy::CredentialKind;
use crate::services::backup::{self,BackupDevice,BackupError,BackupKind};

const PASSWORD:&[u8]=b"correct7horse";
const WRONG_PASSWORD:&[u8]=b"incorrect7horse";
const SALT:[u8;16]=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
const NONCE:[u8;12]=[0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b];
const DEVICE_A:[u8;32]=[0x5a;32];
const DEVICE_B:[u8;32]=[0xa5;32];
const PAYLOAD:&[u8]=b"device-bound-backup-payload";

struct MockHmac([u8;32]);
impl HardwareHmac for MockHmac{fn hmac_sha256(&mut self,message:&[u8],output:&mut[u8;32])->Result<(),DeviceBoundError>{let mut h=Sha256::new();h.update(self.0);h.update(message);*output=h.finalize().into();Ok(())}}
struct MockBackupDevice([u8;32]);
impl BackupDevice for MockBackupDevice{
    fn seal_backup_key(&mut self,purpose:StoragePurpose,credential_key:&[u8;32],salt:&[u8;16],nonce:&[u8;12],aad:&[u8],ciphertext:&mut[u8])->Result<[u8;TAG_SIZE],BackupError>{seal_in_place(&mut MockHmac(self.0),KdfParameters::current(purpose,CredentialKind::Password),credential_key,salt,nonce,aad,ciphertext).map_err(map_device_error)}
    fn open_backup_key(&mut self,purpose:StoragePurpose,credential_key:&[u8;32],salt:&[u8;16],nonce:&[u8;12],aad:&[u8],ciphertext:&mut[u8],tag:&[u8;TAG_SIZE])->Result<(),BackupError>{open_in_place(&mut MockHmac(self.0),OpenRequest{parameters:KdfParameters::current(purpose,CredentialKind::Password),stretched_credential:credential_key,salt,nonce,authenticated_header:aad,tag},ciphertext).map_err(map_device_error)}
}
fn map_device_error(e:DeviceBoundError)->BackupError{match e{DeviceBoundError::HardwareHmacUnavailable=>BackupError::DeviceKeyUnavailable,DeviceBoundError::EntropyUnavailable=>BackupError::EntropyUnavailable,DeviceBoundError::AuthenticationFailed=>BackupError::AuthenticationFailed,_=>BackupError::EncryptionFailed}}

pub fn run_tests() -> (u32, u32) {
    let tests = [
        current_container_roundtrip(),
        current_container_rejects_tamper_wrong_password_device_and_kdf(),
        current_stego_device_roundtrip(),
        portable_roundtrip_cross_device_and_tamper(),
        stego_modes_separated(),
    ];
    (tests.iter().filter(|value| **value).count() as u32, tests.len() as u32)
}

fn make_container(
    kind: BackupKind,
    device: &mut MockBackupDevice,
) -> Option<([u8; 256], usize)> {
    let mut out = [0u8; 256];
    let len = backup::seal_for_test(kind, PAYLOAD, PASSWORD, device, &SALT, &NONCE, &mut out).ok()?;
    Some((out, len))
}

fn current_container_roundtrip() -> bool {
    let mut device = MockBackupDevice(DEVICE_A);
    let Some((container, length)) = make_container(BackupKind::Seed, &mut device) else {
        return false;
    };
    if &container[..8] != b"KASDB005"
        || backup::backup_kind(&container[..length]) != Ok(BackupKind::Seed)
    {
        return false;
    }
    let mut out = [0u8; 120];
    backup::test_open(
        BackupKind::Seed,
        &container[..length],
        PASSWORD,
        &mut device,
        &mut out,
    ) == Ok(PAYLOAD.len())
        && &out[..PAYLOAD.len()] == PAYLOAD
}

fn current_container_rejects_tamper_wrong_password_device_and_kdf() -> bool {
    let mut device = MockBackupDevice(DEVICE_A);
    let Some((container, length)) = make_container(BackupKind::Seed, &mut device) else {
        return false;
    };
    let mut out = [0xA5; 120];
    let mut tampered = container;
    tampered[60] ^= 1;
    if backup::test_open(
        BackupKind::Seed,
        &tampered[..length],
        PASSWORD,
        &mut device,
        &mut out,
    )
    .is_ok()
    {
        return false;
    }
    out.fill(0xA5);
    if backup::test_open(
        BackupKind::Seed,
        &container[..length],
        WRONG_PASSWORD,
        &mut device,
        &mut out,
    )
    .is_ok()
    {
        return false;
    }
    let mut other = MockBackupDevice(DEVICE_B);
    if backup::test_open(
        BackupKind::Seed,
        &container[..length],
        PASSWORD,
        &mut other,
        &mut out,
    )
    .is_ok()
    {
        return false;
    }
    let mut bad_kdf = container;
    bad_kdf[16] = 0xff;
    backup::test_open(
        BackupKind::Seed,
        &bad_kdf[..length],
        PASSWORD,
        &mut device,
        &mut out,
    ) == Err(BackupError::UnsupportedFormat)
}

fn mnemonic_vector() -> [u16; 24] {
    let mut indices = [0u16; 24];
    indices[11] = 3;
    indices
}

fn current_stego_device_roundtrip() -> bool {
    let indices = mnemonic_vector();
    let mut device = MockBackupDevice(DEVICE_A);
    let mut payload = [0u8; crate::services::stego::STEGO_PAYLOAD_SIZE];
    if crate::services::stego::pack_for_test(
        crate::services::stego::StegoSecurity::DeviceBound,
        crate::services::stego::StegoCarrier::Descriptor,
        &indices,
        12,
        b"favorite song",
        b"Family photo 7",
        b"",
        &mut device,
        &SALT,
        &NONCE,
        &mut payload,
    )
    .is_err()
    {
        return false;
    }
    let mut restored = [0u16; 24];
    let mut hint = [0u8; 64];
    crate::services::stego::unpack_device_bound_payload(
        crate::services::stego::StegoCarrier::Descriptor,
        &payload,
        b"Family photo 7",
        &mut device,
        &mut restored,
        &mut hint,
    ) == Ok((12, 13))
        && restored == indices
        && &hint[..13] == b"favorite song"
}

fn portable_roundtrip_cross_device_and_tamper() -> bool {
    let indices = mnemonic_vector();
    let mut device = MockBackupDevice(DEVICE_A);
    let mut payload = [0u8; crate::services::stego::STEGO_PAYLOAD_SIZE];
    if crate::services::stego::pack_for_test(
        crate::services::stego::StegoSecurity::Portable,
        crate::services::stego::StegoCarrier::Picture,
        &indices,
        12,
        b"portable hint",
        b"Travel photo 4",
        PASSWORD,
        &mut device,
        &SALT,
        &NONCE,
        &mut payload,
    )
    .is_err()
    {
        return false;
    }
    if &payload[..4] != b"KSJP" {
        return false;
    }
    let mut restored = [0u16; 24];
    let mut hint = [0u8; 64];
    if crate::services::stego::unpack_portable_payload(
        crate::services::stego::StegoCarrier::Picture,
        &payload,
        b"Travel photo 4",
        PASSWORD,
        &mut restored,
        &mut hint,
    ) != Ok((12, 13))
        || restored != indices
    {
        return false;
    }
    restored.fill(0);
    hint.fill(0);
    if crate::services::stego::unpack_portable_payload(
        crate::services::stego::StegoCarrier::Picture,
        &payload,
        b"Travel photo 4",
        PASSWORD,
        &mut restored,
        &mut hint,
    ) != Ok((12, 13))
    {
        return false;
    }
    let mut bad = payload;
    bad[8] ^= 1;
    crate::services::stego::unpack_portable_payload(
        crate::services::stego::StegoCarrier::Picture,
        &bad,
        b"Travel photo 4",
        PASSWORD,
        &mut restored,
        &mut hint,
    )
    .is_err()
        && crate::services::stego::unpack_portable_payload(
            crate::services::stego::StegoCarrier::Picture,
            &payload,
            b"Travel photo 4",
            WRONG_PASSWORD,
            &mut restored,
            &mut hint,
        )
        .is_err()
}

fn stego_modes_separated() -> bool {
    let indices = mnemonic_vector();
    let mut backup_device = MockBackupDevice(DEVICE_A);
    let mut device = [0u8; crate::services::stego::STEGO_PAYLOAD_SIZE];
    let mut portable = [0u8; crate::services::stego::STEGO_PAYLOAD_SIZE];
    if crate::services::stego::pack_for_test(
        crate::services::stego::StegoSecurity::DeviceBound,
        crate::services::stego::StegoCarrier::Picture,
        &indices,
        12,
        b"",
        b"Park photo 5",
        b"",
        &mut backup_device,
        &SALT,
        &NONCE,
        &mut device,
    )
    .is_err()
    {
        return false;
    }
    if crate::services::stego::pack_for_test(
        crate::services::stego::StegoSecurity::Portable,
        crate::services::stego::StegoCarrier::Picture,
        &indices,
        12,
        b"",
        b"Park photo 5",
        PASSWORD,
        &mut backup_device,
        &SALT,
        &NONCE,
        &mut portable,
    )
    .is_err()
    {
        return false;
    }
    if device == portable {
        return false;
    }
    let mut restored = [0u16; 24];
    let mut hint = [0u8; 64];
    crate::services::stego::unpack_portable_payload(
        crate::services::stego::StegoCarrier::Picture,
        &device,
        b"Park photo 5",
        PASSWORD,
        &mut restored,
        &mut hint,
    )
    .is_err()
        && crate::services::stego::unpack_device_bound_payload(
            crate::services::stego::StegoCarrier::Picture,
            &portable,
            b"Park photo 5",
            &mut backup_device,
            &mut restored,
            &mut hint,
        )
        .is_err()
}

#[test]fn current_device_bound_backup_uses_argon2_metadata(){assert!(current_container_roundtrip());assert!(current_container_rejects_tamper_wrong_password_device_and_kdf())}
#[test]fn portable_jpeg_is_password_only_cross_device(){assert!(portable_roundtrip_cross_device_and_tamper())}

#[test]
fn current_device_bound_backup_rejects_corruption_in_authenticated_metadata_salt_tag_and_lengths() {
    let mut device = MockBackupDevice(DEVICE_A);
    let (container, length) = make_container(BackupKind::Seed, &mut device).expect("container");
    let mut output = [0xa5u8; 120];

    for offset in [16usize, 17, 18, 19, 20, 28, 44, 59, length - 1] {
        let mut tampered = container;
        tampered[offset] ^= 1;
        assert!(backup::test_open(
            BackupKind::Seed, &tampered[..length], PASSWORD, &mut device, &mut output,
        ).is_err());
        assert!(output.iter().all(|byte| *byte == 0));
        output.fill(0xa5);
    }

    assert_eq!(
        backup::test_open(BackupKind::Seed, &container[..length - 1], PASSWORD, &mut device, &mut output),
        Err(BackupError::InvalidLength),
    );
    let mut unsupported = container;
    unsupported[16] = 0xff;
    assert_eq!(
        backup::test_open(BackupKind::Seed, &unsupported[..length], PASSWORD, &mut device, &mut output),
        Err(BackupError::UnsupportedFormat),
    );
}

#[test]
fn historical_deployed_legacy_device_bound_reader_is_magic_selected_only() {
    let mut device = MockBackupDevice(DEVICE_A);
    let mut legacy = [0u8; 256];
    let length = backup::seal_legacy_for_test(
        BackupKind::Seed, PAYLOAD, PASSWORD, &mut device, &SALT, &NONCE, &mut legacy,
    )
    .expect("legacy fixture");
    assert_eq!(&legacy[..8], b"KASDB004");
    let mut output = [0u8; 120];
    assert_eq!(
        backup::test_open(BackupKind::Seed, &legacy[..length], PASSWORD, &mut device, &mut output),
        Ok(PAYLOAD.len()),
    );
    assert_eq!(&output[..PAYLOAD.len()], PAYLOAD);

    let mut relabeled = legacy;
    relabeled[..8].copy_from_slice(b"KASDB005");
    assert!(backup::test_open(
        BackupKind::Seed, &relabeled[..length], PASSWORD, &mut device, &mut output,
    ).is_err());
}

#[test]
fn portable_jpeg_rejects_all_authenticated_header_tampering_and_clears_outputs() {
    let indices = mnemonic_vector();
    let mut device = MockBackupDevice(DEVICE_A);
    let mut payload = [0u8; crate::services::stego::STEGO_PAYLOAD_SIZE];
    crate::services::stego::pack_for_test(
        crate::services::stego::StegoSecurity::Portable,
        crate::services::stego::StegoCarrier::Picture,
        &indices,
        12,
        b"portable hint",
        b"Travel photo 4",
        PASSWORD,
        &mut device,
        &SALT,
        &NONCE,
        &mut payload,
    )
    .expect("portable payload");

    for offset in [4usize, 5, 6, 8, 9, 10, 12, 20, 36, 48, payload.len() - 1] {
        let mut tampered = payload;
        tampered[offset] ^= 1;
        let mut restored = [0x5a5au16; 24];
        let mut hint = [0xa5u8; 64];
        assert!(crate::services::stego::unpack_portable_payload(
            crate::services::stego::StegoCarrier::Picture,
            &tampered,
            b"Travel photo 4",
            PASSWORD,
            &mut restored,
            &mut hint,
        ).is_err());
        assert!(restored.iter().all(|word| *word == 0));
        assert!(hint.iter().all(|byte| *byte == 0));
    }
}

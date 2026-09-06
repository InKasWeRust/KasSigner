//! Authenticated immutable advanced-security metadata stored in the unused
//! second half of each persistent-wallet flash sector.

use offline_signer::{crypto::password_kdf::PasswordKdfPurpose, derivation::hmac::zeroize_buf};
use crate::services::credential_policy::{self, CredentialKind, SALT_SIZE};
use signer_firmware_core::advanced_policy::{SigningPolicy, SigningWindow, MAX_WEEKLY_WINDOWS};

use super::{
    PersistError,
    crypto::{DeviceCrypto, POLICY_START, RECORD_SIZE, RecordHeader},
    flash::AlignedBytes,
    kdf::{self, CredentialKdf},
};

const MAGIC: [u8; 8] = *b"KSPOL001";
const VERSION: u8 = 1;
const ENCODED_SIZE: usize = 160;
const TAG_SIZE: usize = 32;
const POLICY_SIZE: usize = ENCODED_SIZE + TAG_SIZE;
const FLAG_DURESS: u8 = 1 << 0;
const FLAG_NOT_BEFORE: u8 = 1 << 1;
const FLAG_WEEKLY: u8 = 1 << 2;
const KNOWN_FLAGS: u8 = FLAG_DURESS | FLAG_NOT_BEFORE | FLAG_WEEKLY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DuressPolicy {
    pub enabled: bool,
    pub kind: CredentialKind,
    pub key_slot: u8,
    pub salt: [u8; SALT_SIZE],
    pub verifier: [u8; 32],
}

impl DuressPolicy {
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            kind: CredentialKind::Pin,
            key_slot: 0,
            salt: [0u8; SALT_SIZE],
            verifier: [0u8; 32],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SecurityPolicy {
    pub duress: DuressPolicy,
    pub signing: SigningPolicy,
}

impl SecurityPolicy {
    pub const fn disabled() -> Self {
        Self { duress: DuressPolicy::disabled(), signing: SigningPolicy::disabled() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DecodeResult {
    Absent,
    Valid(SecurityPolicy),
    Corrupt,
}

pub(super) fn encode(
    crypto: &mut DeviceCrypto<'_>,
    header: RecordHeader,
    policy: SecurityPolicy,
    record: &mut AlignedBytes<RECORD_SIZE>,
) -> Result<(), PersistError> {
    policy.signing.validate().map_err(|_| PersistError::InvalidSecurityPolicy)?;
    let region = &mut record.0[POLICY_START..POLICY_START + POLICY_SIZE];
    region.fill(0);
    region[..8].copy_from_slice(&MAGIC);
    region[8] = VERSION;
    let mut flags = 0u8;
    if policy.duress.enabled { flags |= FLAG_DURESS; }
    if policy.signing.not_before_unix != 0 { flags |= FLAG_NOT_BEFORE; }
    if policy.signing.weekly_enabled { flags |= FLAG_WEEKLY; }
    region[9] = flags;
    region[10] = if policy.duress.enabled { policy.duress.kind as u8 } else { 0 };
    region[11] = if policy.duress.enabled { policy.duress.key_slot } else { 0 };
    region[12] = policy.signing.weekly_count;
    if policy.duress.enabled {
        region[16..32].copy_from_slice(&policy.duress.salt);
        region[32..64].copy_from_slice(&policy.duress.verifier);
    }
    region[64..72].copy_from_slice(&policy.signing.not_before_unix.to_le_bytes());
    region[72..80].copy_from_slice(&policy.signing.rtc_floor_unix.to_le_bytes());
    for (index, window) in policy.signing.windows.iter().enumerate() {
        let base = 80 + index * 5;
        region[base] = window.weekday;
        region[base + 1..base + 3].copy_from_slice(&window.start_minute.to_le_bytes());
        region[base + 3..base + 5].copy_from_slice(&window.end_minute.to_le_bytes());
    }
    let tag = crypto.policy_tag(header.key_slot, header.sequence, &region[..ENCODED_SIZE])?;
    region[ENCODED_SIZE..POLICY_SIZE].copy_from_slice(&tag);
    Ok(())
}

pub(super) fn decode(
    crypto: &mut DeviceCrypto<'_>,
    header: RecordHeader,
    record: &AlignedBytes<RECORD_SIZE>,
) -> DecodeResult {
    let region = &record.0[POLICY_START..POLICY_START + POLICY_SIZE];
    if policy_region_is_empty(region) {
        return if header.policy_required { DecodeResult::Corrupt } else { DecodeResult::Absent };
    }
    if !policy_region_header_is_valid(region) || !policy_region_reserved_bytes_are_zero(region) {
        return DecodeResult::Corrupt;
    }
    if !policy_tag_is_valid(crypto, header, region) { return DecodeResult::Corrupt; }
    let Ok(duress) = decode_duress(region) else { return DecodeResult::Corrupt; };
    let Ok(signing) = decode_signing(region) else { return DecodeResult::Corrupt; };
    DecodeResult::Valid(SecurityPolicy { duress, signing })
}

fn policy_region_is_empty(region: &[u8]) -> bool {
    region.iter().all(|byte| *byte == 0) || region.iter().all(|byte| *byte == 0xFF)
}

fn policy_region_header_is_valid(region: &[u8]) -> bool {
    region[..8] == MAGIC && region[8] == VERSION && region[9] & !KNOWN_FLAGS == 0
}

fn policy_region_reserved_bytes_are_zero(region: &[u8]) -> bool {
    region[13..16].iter().all(|byte| *byte == 0)
        && region[100..ENCODED_SIZE].iter().all(|byte| *byte == 0)
}

fn policy_tag_is_valid(
    crypto: &mut DeviceCrypto<'_>,
    header: RecordHeader,
    region: &[u8],
) -> bool {
    let Ok(expected) = crypto.policy_tag(header.key_slot, header.sequence, &region[..ENCODED_SIZE]) else {
        return false;
    };
    shared_signer::bytes::constant_time_eq(&expected, &region[ENCODED_SIZE..POLICY_SIZE])
}

fn decode_duress(region: &[u8]) -> Result<DuressPolicy, ()> {
    if region[9] & FLAG_DURESS == 0 { return decode_disabled_duress(region); }
    let kind = CredentialKind::from_byte(region[10]).ok_or(())?;
    let key_slot = region[11];
    if !super::crypto::valid_key_slot(key_slot) { return Err(()); }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&region[16..32]);
    let mut verifier = [0u8; 32];
    verifier.copy_from_slice(&region[32..64]);
    Ok(DuressPolicy { enabled: true, kind, key_slot, salt, verifier })
}

fn decode_disabled_duress(region: &[u8]) -> Result<DuressPolicy, ()> {
    if region[10] != 0 || region[11] != 0 || region[16..64].iter().any(|byte| *byte != 0) {
        Err(())
    } else {
        Ok(DuressPolicy::disabled())
    }
}

fn decode_signing(region: &[u8]) -> Result<SigningPolicy, ()> {
    let not_before_unix = read_u64(region, 64);
    let rtc_floor_unix = read_u64(region, 72);
    let flags = region[9];
    if (flags & FLAG_NOT_BEFORE == 0) != (not_before_unix == 0) { return Err(()); }
    let weekly_count = region[12];
    if usize::from(weekly_count) > MAX_WEEKLY_WINDOWS { return Err(()); }
    let weekly_enabled = flags & FLAG_WEEKLY != 0;
    if weekly_enabled != (weekly_count != 0) { return Err(()); }
    let windows = decode_windows(region);
    if windows[usize::from(weekly_count)..].iter().any(|window| *window != SigningWindow::EMPTY) {
        return Err(());
    }
    let signing = SigningPolicy {
        not_before_unix,
        weekly_enabled,
        weekly_count,
        windows,
        rtc_floor_unix,
    };
    signing.validate().map_err(|_| ())?;
    Ok(signing)
}

fn decode_windows(region: &[u8]) -> [SigningWindow; MAX_WEEKLY_WINDOWS] {
    let mut windows = [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS];
    for (index, window) in windows.iter_mut().enumerate() {
        let base = 80 + index * 5;
        *window = SigningWindow {
            weekday: region[base],
            start_minute: u16::from_le_bytes([region[base + 1], region[base + 2]]),
            end_minute: u16::from_le_bytes([region[base + 3], region[base + 4]]),
        };
    }
    windows
}

fn read_u64(region: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&region[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub(super) fn create_duress(
    crypto: &mut DeviceCrypto<'_>,
    key_slot: u8,
    kind: CredentialKind,
    secret: &[u8],
) -> Result<DuressPolicy, PersistError> {
    credential_policy::validate(kind, secret)?;
    let mut salt = [0u8; SALT_SIZE];
    crate::services::entropy::fill(&mut salt).map_err(|_| PersistError::Entropy)?;
    let mut stretched = kdf::derive(
        CredentialKdf::current(), PasswordKdfPurpose::PersistentWallet,
        secret, &salt, &mut || {},
    )?;
    let verifier_result = crypto.duress_verifier(key_slot, kind, &salt, &stretched);
    zeroize_buf(&mut stretched);
    let verifier = verifier_result?;
    Ok(DuressPolicy { enabled: true, kind, key_slot, salt, verifier })
}

pub(super) fn duress_matches(
    crypto: &mut DeviceCrypto<'_>,
    credential_kdf: CredentialKdf,
    policy: DuressPolicy,
    secret: &[u8],
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    if !policy.enabled { return false; }
    let Ok(mut stretched) = kdf::derive(
        credential_kdf, PasswordKdfPurpose::PersistentWallet,
        secret, &policy.salt, liveness,
    ) else { return false; };
    let actual = crypto.duress_verifier(policy.key_slot, policy.kind, &policy.salt, &stretched);
    zeroize_buf(&mut stretched);
    match actual {
        Ok(value) => shared_signer::bytes::constant_time_eq(&value, &policy.verifier),
        Err(_) => false,
    }
}

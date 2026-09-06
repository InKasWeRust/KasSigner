//! Canonical bounded parser for multisig descriptors exchanged by KasSigner/KasSee.
//!
//! Parsing is allocation-free and available in `no_std` builds. Host consumers may
//! adapt this bounded representation to richer heap-backed models, but syntax,
//! threshold validation, legacy-kpub decoding, duplicate detection, and canonical
//! HD45 participant ordering live here so hardware and wallet code cannot drift.

use shared_signer::{bytes::decode_hex_nibble, legacy_account_key::decode_legacy_kpub};

pub const MAX_DESCRIPTOR_PARTICIPANTS: usize = 5;
const HD44_PARTICIPANT_HEX_LEN: usize = 130;
const HD45_KPUB_LEN: usize = 111;
const STATIC_KEY_HEX_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigDescriptorKind {
    Static,
    Hd44,
    Hd45,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigDescriptorError {
    UnsupportedFormat,
    InvalidThreshold,
    TooFewParticipants,
    TooManyParticipants,
    InvalidParticipantLength,
    InvalidHex,
    InvalidCompressedPublicKey,
    InvalidLegacyKpub,
    InvalidLegacyDepth,
    DuplicateParticipant,
}

const MULTISIG_DESCRIPTOR_ERROR_MESSAGES: [&str; 10] = [
    "Descriptor must be multi(M,...), multi_hd(M,...), or multi_hd45(M,...)",
    "Invalid M value in descriptor",
    "Need at least M and 2 cosigners",
    "Descriptor has too many participants",
    "Descriptor participant has invalid encoded length",
    "Descriptor participant contains invalid hex",
    "Descriptor contains an invalid compressed pubkey",
    "Invalid 45' cosigner kpub",
    "45' cosigner kpub must be an account key at depth 3",
    "Duplicate cosigner in descriptor",
];

impl MultisigDescriptorError {
    pub const fn message(self) -> &'static str {
        MULTISIG_DESCRIPTOR_ERROR_MESSAGES[self as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedMultisigDescriptor {
    pub threshold: u8,
    pub participant_count: u8,
    pub kind: MultisigDescriptorKind,
    /// Compatibility field used by the embedded multisig state model.
    pub v45: bool,
    pub static_public_keys: [[u8; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
    pub public_keys: [[u8; 33]; MAX_DESCRIPTOR_PARTICIPANTS],
    pub chain_codes: [[u8; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
    pub depths: [u8; MAX_DESCRIPTOR_PARTICIPANTS],
    pub parent_fingerprints: [[u8; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
    pub child_numbers: [[u8; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
}

impl ParsedMultisigDescriptor {
    pub const fn is_hd(self) -> bool {
        matches!(
            self.kind,
            MultisigDescriptorKind::Hd44 | MultisigDescriptorKind::Hd45
        )
    }

    pub const fn is_hd45(self) -> bool {
        matches!(self.kind, MultisigDescriptorKind::Hd45)
    }
}

pub fn parse_multisig_descriptor(
    data: &[u8],
) -> Result<ParsedMultisigDescriptor, MultisigDescriptorError> {
    let data = descriptor_line(trim_trailing_ascii_whitespace(data));
    let (kind, inner) = descriptor_body(data)?;
    let (threshold, participants) = split_threshold(inner)?;
    let mut parsed = ParsedMultisigDescriptor {
        threshold,
        participant_count: 0,
        kind,
        v45: matches!(kind, MultisigDescriptorKind::Hd45),
        static_public_keys: [[0; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
        public_keys: [[0; 33]; MAX_DESCRIPTOR_PARTICIPANTS],
        chain_codes: [[0; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
        depths: [0; MAX_DESCRIPTOR_PARTICIPANTS],
        parent_fingerprints: [[0; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
        child_numbers: [[0; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
    };

    parse_descriptor_participants(kind, participants, &mut parsed)?;
    validate_descriptor_threshold(&parsed)?;
    Ok(parsed)
}

fn parse_descriptor_participants(
    kind: MultisigDescriptorKind,
    participants: &[u8],
    parsed: &mut ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    match kind {
        MultisigDescriptorKind::Static => parse_static_participants(participants, parsed),
        MultisigDescriptorKind::Hd44 => parse_hd44_participants(participants, parsed),
        MultisigDescriptorKind::Hd45 => parse_hd45_participants(participants, parsed),
    }
}

fn validate_descriptor_threshold(
    parsed: &ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    if parsed.participant_count < 2 {
        return Err(MultisigDescriptorError::TooFewParticipants);
    }
    if parsed.threshold == 0 || parsed.threshold > parsed.participant_count {
        return Err(MultisigDescriptorError::InvalidThreshold);
    }
    Ok(())
}

fn trim_ascii(mut data: &[u8]) -> &[u8] {
    while matches!(data.first(), Some(b' ' | b'\t' | b'\r')) {
        data = &data[1..];
    }
    trim_trailing_ascii_whitespace(data)
}

fn trim_trailing_ascii_whitespace(mut data: &[u8]) -> &[u8] {
    while matches!(data.last(), Some(b'\n' | b'\r' | b' ' | b'\t')) {
        data = data.split_last().map_or(&[], |(_, remaining)| remaining);
    }
    data
}

/// Backup files may carry comments/header lines. The descriptor function line,
/// not a header, is authoritative for the scheme.
fn descriptor_line(data: &[u8]) -> &[u8] {
    data.split(|byte| *byte == b'\n')
        .map(trim_ascii)
        .find(|line| {
            line.starts_with(b"multi_hd45(")
                || line.starts_with(b"multi_hd(")
                || line.starts_with(b"multi(")
        })
        .unwrap_or(data)
}

fn descriptor_body(
    data: &[u8],
) -> Result<(MultisigDescriptorKind, &[u8]), MultisigDescriptorError> {
    let (kind, prefix): (MultisigDescriptorKind, &[u8]) = if data.starts_with(b"multi_hd45(") {
        (MultisigDescriptorKind::Hd45, b"multi_hd45(")
    } else if data.starts_with(b"multi_hd(") {
        (MultisigDescriptorKind::Hd44, b"multi_hd(")
    } else if data.starts_with(b"multi(") {
        (MultisigDescriptorKind::Static, b"multi(")
    } else {
        return Err(MultisigDescriptorError::UnsupportedFormat);
    };
    if !data.ends_with(b")") {
        return Err(MultisigDescriptorError::UnsupportedFormat);
    }
    Ok((kind, &data[prefix.len()..data.len() - 1]))
}

fn split_threshold(inner: &[u8]) -> Result<(u8, &[u8]), MultisigDescriptorError> {
    let comma = inner
        .iter()
        .position(|byte| *byte == b',')
        .ok_or(MultisigDescriptorError::TooFewParticipants)?;
    let digits = trim_ascii(&inner[..comma]);
    if digits.is_empty() || digits.len() > 3 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(MultisigDescriptorError::InvalidThreshold);
    }
    let mut threshold = 0u16;
    for digit in digits {
        threshold = threshold
            .saturating_mul(10)
            .saturating_add(u16::from(*digit - b'0'));
    }
    let threshold =
        u8::try_from(threshold).map_err(|_| MultisigDescriptorError::InvalidThreshold)?;
    Ok((threshold, &inner[comma + 1..]))
}

fn next_part(remaining: &[u8]) -> (&[u8], &[u8]) {
    match remaining.iter().position(|byte| *byte == b',') {
        Some(index) => (trim_ascii(&remaining[..index]), &remaining[index + 1..]),
        None => (trim_ascii(remaining), &[]),
    }
}

fn checked_slot(parsed: &ParsedMultisigDescriptor) -> Result<usize, MultisigDescriptorError> {
    let index = usize::from(parsed.participant_count);
    if index >= MAX_DESCRIPTOR_PARTICIPANTS {
        Err(MultisigDescriptorError::TooManyParticipants)
    } else {
        Ok(index)
    }
}

fn parse_static_participants(
    mut remaining: &[u8],
    parsed: &mut ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    while !remaining.is_empty() {
        let index = checked_slot(parsed)?;
        let (part, tail) = next_part(remaining);
        if part.len() != STATIC_KEY_HEX_LEN {
            return Err(MultisigDescriptorError::InvalidParticipantLength);
        }
        decode_hex_bytes(part, &mut parsed.static_public_keys[index])?;
        parsed.participant_count += 1;
        remaining = tail;
    }
    reject_duplicate_static(parsed)
}

fn parse_hd44_participants(
    mut remaining: &[u8],
    parsed: &mut ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    while !remaining.is_empty() {
        let index = checked_slot(parsed)?;
        let (part, tail) = next_part(remaining);
        if part.len() != HD44_PARTICIPANT_HEX_LEN {
            return Err(MultisigDescriptorError::InvalidParticipantLength);
        }
        decode_hex_bytes(&part[..66], &mut parsed.public_keys[index])?;
        if !matches!(parsed.public_keys[index][0], 0x02 | 0x03) {
            return Err(MultisigDescriptorError::InvalidCompressedPublicKey);
        }
        decode_hex_bytes(&part[66..], &mut parsed.chain_codes[index])?;
        parsed.participant_count += 1;
        remaining = tail;
    }
    reject_duplicate_hd(parsed)
}

fn parse_hd45_participants(
    mut remaining: &[u8],
    parsed: &mut ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    let mut encoded = [[0u8; HD45_KPUB_LEN]; MAX_DESCRIPTOR_PARTICIPANTS];
    while !remaining.is_empty() {
        let index = checked_slot(parsed)?;
        let (part, tail) = next_part(remaining);
        if part.len() != HD45_KPUB_LEN {
            return Err(MultisigDescriptorError::InvalidParticipantLength);
        }
        encoded[index].copy_from_slice(part);
        let mut payload = [0u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN];
        decode_legacy_kpub(part, &mut payload)
            .map_err(|_| MultisigDescriptorError::InvalidLegacyKpub)?;
        if payload[4] != 3 {
            return Err(MultisigDescriptorError::InvalidLegacyDepth);
        }
        parsed.depths[index] = payload[4];
        parsed.parent_fingerprints[index].copy_from_slice(&payload[5..9]);
        parsed.child_numbers[index].copy_from_slice(&payload[9..13]);
        parsed.chain_codes[index].copy_from_slice(&payload[13..45]);
        parsed.public_keys[index].copy_from_slice(&payload[45..78]);
        parsed.participant_count += 1;
        remaining = tail;
    }
    sort_hd45_by_encoded(parsed, &mut encoded);
    reject_duplicate_encoded(&encoded, usize::from(parsed.participant_count))
}

fn decode_hex_bytes(hex: &[u8], output: &mut [u8]) -> Result<(), MultisigDescriptorError> {
    if hex.len() != output.len() * 2 {
        return Err(MultisigDescriptorError::InvalidParticipantLength);
    }
    for (pair, byte) in hex.chunks_exact(2).zip(output.iter_mut()) {
        let high = decode_hex_nibble(pair[0]).ok_or(MultisigDescriptorError::InvalidHex)?;
        let low = decode_hex_nibble(pair[1]).ok_or(MultisigDescriptorError::InvalidHex)?;
        *byte = high.wrapping_shl(4).wrapping_add(low);
    }
    Ok(())
}

fn sort_hd45_by_encoded(
    parsed: &mut ParsedMultisigDescriptor,
    encoded: &mut [[u8; HD45_KPUB_LEN]; MAX_DESCRIPTOR_PARTICIPANTS],
) {
    let count = usize::from(parsed.participant_count);
    for index in 1..count {
        let mut cursor = index;
        while cursor > 0 && encoded[cursor - 1] > encoded[cursor] {
            encoded.swap(cursor - 1, cursor);
            parsed.public_keys.swap(cursor - 1, cursor);
            parsed.chain_codes.swap(cursor - 1, cursor);
            parsed.depths.swap(cursor - 1, cursor);
            parsed.parent_fingerprints.swap(cursor - 1, cursor);
            parsed.child_numbers.swap(cursor - 1, cursor);
            cursor -= 1;
        }
    }
}

fn reject_duplicate_encoded(
    encoded: &[[u8; HD45_KPUB_LEN]; MAX_DESCRIPTOR_PARTICIPANTS],
    count: usize,
) -> Result<(), MultisigDescriptorError> {
    if (1..count).any(|index| encoded[index - 1] == encoded[index]) {
        Err(MultisigDescriptorError::DuplicateParticipant)
    } else {
        Ok(())
    }
}

fn reject_duplicate_static(
    parsed: &ParsedMultisigDescriptor,
) -> Result<(), MultisigDescriptorError> {
    let count = usize::from(parsed.participant_count);
    for left in 0..count {
        if (left + 1..count)
            .any(|right| parsed.static_public_keys[left] == parsed.static_public_keys[right])
        {
            return Err(MultisigDescriptorError::DuplicateParticipant);
        }
    }
    Ok(())
}

fn reject_duplicate_hd(parsed: &ParsedMultisigDescriptor) -> Result<(), MultisigDescriptorError> {
    let count = usize::from(parsed.participant_count);
    for left in 0..count {
        if (left + 1..count).any(|right| {
            parsed.public_keys[left] == parsed.public_keys[right]
                && parsed.chain_codes[left] == parsed.chain_codes[right]
        }) {
            return Err(MultisigDescriptorError::DuplicateParticipant);
        }
    }
    Ok(())
}

#[cfg(test)]
mod unit_tests;

//! Pure byte parsing and decoded-QR classification used by firmware adapters.

use kassigner_protocol::wire::{kspt, pskt_envelope};
use shared_signer::bytes::decode_hex_nibble;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QrPayloadKind {
    KaspaAddress,
    CompactKspt,
    StandardPskt,
    SeedQr,
    RawSeedEntropy,
    StealthRequest,
    FirmwareUpdate,
    CovenantRaw,
    CovenantHex,
    CovenantSignRaw,
    CovenantSignHex,
    PrivateSwapRaw,
    PrivateSwapHex,
    AntiKlepto,
    PairingRequest,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HexError {
    OddLength,
    InvalidDigit,
    OutputTooSmall,
}

type QrClassifier = fn(&[u8]) -> Option<QrPayloadKind>;

const QR_CLASSIFIERS: [QrClassifier; 12] = [
    classify_anti_klepto,
    classify_pairing_request,
    classify_address,
    classify_compact_kspt,
    classify_standard_pskt,
    classify_seed_qr,
    classify_private_swap,
    classify_covenant_sign,
    classify_covenant,
    classify_raw_entropy,
    classify_stealth,
    classify_firmware_update,
];

pub fn classify_qr_payload(data: &[u8], declared_len: usize) -> QrPayloadKind {
    let input = &data[..declared_len.min(data.len())];
    QR_CLASSIFIERS
        .iter()
        .find_map(|classifier| classifier(input))
        .unwrap_or(QrPayloadKind::Unknown)
}

fn classify_anti_klepto(input: &[u8]) -> Option<QrPayloadKind> {
    shared_signer_anti_klepto_message(input).then_some(QrPayloadKind::AntiKlepto)
}

fn classify_pairing_request(input: &[u8]) -> Option<QrPayloadKind> {
    (input.len() == shared_signer::pairing::REQUEST_LEN
        && input.starts_with(&shared_signer::pairing::REQUEST_MAGIC))
    .then_some(QrPayloadKind::PairingRequest)
}

fn shared_signer_anti_klepto_message(input: &[u8]) -> bool {
    shared_signer::anti_klepto::is_message(input)
}

fn classify_address(input: &[u8]) -> Option<QrPayloadKind> {
    starts_with_case_insensitive(input, b"kaspa:").then_some(QrPayloadKind::KaspaAddress)
}

fn classify_compact_kspt(input: &[u8]) -> Option<QrPayloadKind> {
    (input.len() >= 5 && input.starts_with(&kspt::MAGIC) && input[4] == kspt::GENERATION_CURRENT)
        .then_some(QrPayloadKind::CompactKspt)
}

fn classify_standard_pskt(input: &[u8]) -> Option<QrPayloadKind> {
    (input.starts_with(pskt_envelope::PSKB_MAGIC) || input.starts_with(pskt_envelope::PSKT_MAGIC))
        .then_some(QrPayloadKind::StandardPskt)
}

fn classify_seed_qr(input: &[u8]) -> Option<QrPayloadKind> {
    (matches!(input.len(), 48 | 96) && input.iter().all(u8::is_ascii_digit))
        .then_some(QrPayloadKind::SeedQr)
}

fn classify_private_swap(input: &[u8]) -> Option<QrPayloadKind> {
    if shared_signer::covenant_sign::private_swap::is_message(input) {
        Some(QrPayloadKind::PrivateSwapRaw)
    } else if is_private_swap_hex(input) {
        Some(QrPayloadKind::PrivateSwapHex)
    } else {
        None
    }
}

fn is_private_swap_hex(input: &[u8]) -> bool {
    if input.len() < shared_signer::covenant_sign::private_swap::REVEAL_LEN * 2
        || input.len() > 7_000
        || !input.len().is_multiple_of(2)
    {
        return false;
    }
    let Some(prefix) = decode_four_byte_prefix(input) else {
        return false;
    };
    matches!(
        prefix,
        shared_signer::covenant_sign::private_swap::REQUEST_MAGIC
            | shared_signer::covenant_sign::private_swap::REVEAL_MAGIC
    ) && input.iter().all(|byte| decode_hex_nibble(*byte).is_some())
}

fn classify_covenant_sign(input: &[u8]) -> Option<QrPayloadKind> {
    if shared_signer::covenant_sign::is_message(input) {
        Some(QrPayloadKind::CovenantSignRaw)
    } else if is_covenant_sign_hex(input) {
        Some(QrPayloadKind::CovenantSignHex)
    } else {
        None
    }
}

fn is_covenant_sign_hex(input: &[u8]) -> bool {
    if input.len() < shared_signer::covenant_sign::REVEAL_LEN * 2
        || input.len() > 9_000
        || !input.len().is_multiple_of(2)
    {
        return false;
    }
    let Some(prefix) = decode_four_byte_prefix(input) else {
        return false;
    };
    matches!(
        prefix,
        shared_signer::covenant_sign::REQUEST_MAGIC | shared_signer::covenant_sign::REVEAL_MAGIC
    ) && input.iter().all(|byte| decode_hex_nibble(*byte).is_some())
}

fn classify_covenant(input: &[u8]) -> Option<QrPayloadKind> {
    if is_covenant_raw(input) {
        Some(QrPayloadKind::CovenantRaw)
    } else if is_covenant_hex(input) {
        Some(QrPayloadKind::CovenantHex)
    } else {
        None
    }
}

fn classify_raw_entropy(input: &[u8]) -> Option<QrPayloadKind> {
    matches!(input.len(), 16 | 32).then_some(QrPayloadKind::RawSeedEntropy)
}

fn classify_stealth(input: &[u8]) -> Option<QrPayloadKind> {
    (input.len() >= 37 && input.starts_with(b"STLH")).then_some(QrPayloadKind::StealthRequest)
}

fn classify_firmware_update(input: &[u8]) -> Option<QrPayloadKind> {
    (input.len() == crate::update::manifest::MANIFEST_LEN && input.starts_with(b"KSFU"))
        .then_some(QrPayloadKind::FirmwareUpdate)
}

pub fn is_covenant_raw(input: &[u8]) -> bool {
    input.len() >= 5 && (input.starts_with(b"COVB") || input.starts_with(b"COVI"))
}

pub fn is_covenant_hex(input: &[u8]) -> bool {
    if !(10..=1024).contains(&input.len()) || !input.len().is_multiple_of(2) {
        return false;
    }
    let Some(prefix) = decode_four_byte_prefix(input) else {
        return false;
    };
    (prefix == *b"COVB" || prefix == *b"COVI")
        && input.iter().all(|byte| decode_hex_nibble(*byte).is_some())
}

pub fn decode_hex(input: &[u8], output: &mut [u8]) -> Result<usize, HexError> {
    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let decoded_len = input.len() / 2;
    if output.len() < decoded_len {
        return Err(HexError::OutputTooSmall);
    }
    for (index, pair) in input.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(HexError::InvalidDigit)?;
        let low = decode_hex_nibble(pair[1]).ok_or(HexError::InvalidDigit)?;
        output[index] = (high << 4) | low;
    }
    Ok(decoded_len)
}

pub fn is_seed_backup_candidate(data: &[u8], declared_size: usize) -> bool {
    let size = declared_size.min(data.len());
    let input = &data[..size];
    let encrypted_seed = size >= 57 && input.starts_with(b"KAS\x01");
    let encrypted_xprv =
        size >= 40 && (input.starts_with(b"KAX\x02") || input.starts_with(b"KAS\x02"));
    let plain_xprv = size >= 100 && input.starts_with(b"xprv");
    let plain_hex = (64..=66).contains(&size) && input[..64].iter().all(u8::is_ascii_hexdigit);
    encrypted_seed || encrypted_xprv || plain_xprv || plain_hex
}

fn starts_with_case_insensitive(input: &[u8], expected: &[u8]) -> bool {
    if input.len() < expected.len() {
        return false;
    }
    let mut index = 0;
    while index < expected.len() {
        if !input[index].eq_ignore_ascii_case(&expected[index]) {
            return false;
        }
        index += 1;
    }
    true
}

fn decode_four_byte_prefix(input: &[u8]) -> Option<[u8; 4]> {
    if input.len() < 8 {
        return None;
    }
    let mut prefix = [0u8; 4];
    decode_hex(&input[..8], &mut prefix).ok()?;
    Some(prefix)
}

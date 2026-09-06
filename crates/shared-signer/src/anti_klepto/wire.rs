//! Anti-klepto wire encoding and decoding.

use sha2::{Digest, Sha256};

use super::{
    host_commitment, session_id, transaction_digest, Commitment, Header, MessageKind,
    NonceCommitment, Request, SignatureProof, Signed, WireError, HASH_LEN, HEADER_LEN, MAGIC,
    REVEAL_LEN, SESSION_ID_LEN, VERSION,
};

pub fn encode_request(
    host_secret: &[u8; HASH_LEN],
    transaction: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    let tx_len = u32::try_from(transaction.len()).map_err(|_| WireError::InvalidLength)?;
    let fixed = HEADER_LEN + HASH_LEN + HASH_LEN + 4;
    let needed = fixed
        .checked_add(transaction.len())
        .ok_or(WireError::InvalidLength)?;
    if output.len() < needed {
        return Err(WireError::OutputTooSmall);
    }
    let host_commit = host_commitment(host_secret);
    let tx_digest = transaction_digest(transaction);
    let session = session_id(&host_commit, &tx_digest);
    write_header(output, MessageKind::Request, &session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&host_commit);
    output[HEADER_LEN + 32..HEADER_LEN + 64].copy_from_slice(&tx_digest);
    output[HEADER_LEN + 64..HEADER_LEN + 68].copy_from_slice(&tx_len.to_le_bytes());
    output[fixed..needed].copy_from_slice(transaction);
    Ok(needed)
}

pub fn parse_request(input: &[u8]) -> Result<Request<'_>, WireError> {
    let header = parse_header(input, MessageKind::Request)?;
    let layout = request_layout();
    if input.len() < layout.fixed {
        return Err(WireError::Truncated);
    }
    let host_commitment = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let transaction_digest_value = array32(&input[HEADER_LEN + 32..HEADER_LEN + 64]);
    let transaction_len = read_request_length(input, layout)?;
    request_transaction(input, layout.fixed, transaction_len).and_then(|transaction| {
        validate_request_binding(
            &header,
            &host_commitment,
            &transaction_digest_value,
            transaction,
        )
        .map(|()| Request {
            session_id: header.session_id,
            host_commitment,
            transaction_digest: transaction_digest_value,
            transaction,
        })
    })
}

#[derive(Clone, Copy)]
pub(super) struct RequestLayout {
    pub(super) fixed: usize,
}

pub(super) fn request_layout() -> RequestLayout {
    RequestLayout {
        fixed: HEADER_LEN + 68,
    }
}

fn read_request_length(input: &[u8], layout: RequestLayout) -> Result<usize, WireError> {
    read_u32(&input[HEADER_LEN + 64..layout.fixed])
}

fn request_transaction(
    input: &[u8],
    fixed: usize,
    transaction_len: usize,
) -> Result<&[u8], WireError> {
    fixed
        .checked_add(transaction_len)
        .filter(|end| *end == input.len())
        .map(|end| &input[fixed..end])
        .ok_or(WireError::InvalidLength)
}

fn validate_request_binding(
    header: &Header,
    host_commitment: &[u8; HASH_LEN],
    transaction_digest_value: &[u8; HASH_LEN],
    transaction: &[u8],
) -> Result<(), WireError> {
    let digest_matches = transaction_digest(transaction) == *transaction_digest_value;
    let session_matches =
        session_id(host_commitment, transaction_digest_value) == header.session_id;
    matches!((digest_matches, session_matches), (true, true))
        .then_some(())
        .ok_or(request_binding_error(digest_matches))
}

fn request_binding_error(digest_matches: bool) -> WireError {
    if digest_matches {
        WireError::SessionMismatch
    } else {
        WireError::TransactionMismatch
    }
}

pub fn encode_commitment(
    session: &[u8; SESSION_ID_LEN],
    tx_digest: &[u8; HASH_LEN],
    records: &[NonceCommitment],
    output: &mut [u8],
) -> Result<usize, WireError> {
    if records.is_empty() {
        return Err(WireError::TooManyProofs);
    }
    let count = u32::try_from(records.len()).map_err(|_| WireError::TooManyProofs)?;
    let fixed = HEADER_LEN + HASH_LEN + 4;
    let record_len = 4 + 1 + 33 + 33;
    let needed = fixed
        .checked_add(
            records
                .len()
                .checked_mul(record_len)
                .ok_or(WireError::InvalidLength)?,
        )
        .ok_or(WireError::InvalidLength)?;
    if output.len() < needed {
        return Err(WireError::OutputTooSmall);
    }
    write_header(output, MessageKind::Commitment, session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(tx_digest);
    output[HEADER_LEN + 32..HEADER_LEN + 36].copy_from_slice(&count.to_le_bytes());
    let mut offset = fixed;
    for record in records {
        output[offset..offset + 4].copy_from_slice(&record.input_index.to_le_bytes());
        output[offset + 4] = record.signature_slot;
        output[offset + 5..offset + 38].copy_from_slice(&record.public_key);
        output[offset + 38..offset + 71].copy_from_slice(&record.nonce_point);
        offset += record_len;
    }
    Ok(needed)
}

pub fn parse_commitment(input: &[u8]) -> Result<Commitment<'_>, WireError> {
    let header = parse_header(input, MessageKind::Commitment)?;
    let fixed = HEADER_LEN + HASH_LEN + 4;
    if input.len() < fixed {
        return Err(WireError::Truncated);
    }
    let transaction_digest = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let count = read_u32(&input[HEADER_LEN + 32..fixed])?;
    if count == 0 {
        return Err(WireError::TooManyProofs);
    }
    let record_len = 71usize;
    let records_len = count
        .checked_mul(record_len)
        .ok_or(WireError::InvalidLength)?;
    if fixed.checked_add(records_len) != Some(input.len()) {
        return Err(WireError::InvalidLength);
    }
    Ok(Commitment {
        session_id: header.session_id,
        transaction_digest,
        record_bytes: &input[fixed..],
        count,
    })
}

impl Commitment<'_> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn record(&self, index: usize) -> Option<NonceCommitment> {
        if index >= self.count {
            return None;
        }
        let record_len = 71usize;
        let offset = index * record_len;
        let bytes = &self.record_bytes[offset..offset + record_len];
        let input_index = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let slot_offset = 4usize;
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&bytes[slot_offset + 1..slot_offset + 34]);
        let mut nonce_point = [0u8; 33];
        nonce_point.copy_from_slice(&bytes[slot_offset + 34..slot_offset + 67]);
        Some(NonceCommitment {
            input_index,
            signature_slot: bytes[slot_offset],
            public_key,
            nonce_point,
        })
    }
}

pub fn encode_reveal(
    session: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; HASH_LEN],
    output: &mut [u8],
) -> Result<usize, WireError> {
    if output.len() < REVEAL_LEN {
        return Err(WireError::OutputTooSmall);
    }
    write_header(output, MessageKind::Reveal, session)?;
    output[HEADER_LEN..REVEAL_LEN].copy_from_slice(host_secret);
    Ok(REVEAL_LEN)
}

pub fn parse_reveal(input: &[u8]) -> Result<([u8; SESSION_ID_LEN], [u8; HASH_LEN]), WireError> {
    let header = parse_header(input, MessageKind::Reveal)?;
    if input.len() != REVEAL_LEN {
        return Err(WireError::InvalidLength);
    }
    Ok((header.session_id, array32(&input[HEADER_LEN..REVEAL_LEN])))
}

pub fn encode_signed(
    session: &[u8; SESSION_ID_LEN],
    tx_digest: &[u8; HASH_LEN],
    proofs: &[SignatureProof],
    transaction: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    if proofs.is_empty() {
        return Err(WireError::TooManyProofs);
    }
    let count = u32::try_from(proofs.len()).map_err(|_| WireError::TooManyProofs)?;
    let tx_len = u32::try_from(transaction.len()).map_err(|_| WireError::InvalidLength)?;
    let fixed = HEADER_LEN + HASH_LEN + 4;
    let proof_len = 5usize;
    let proofs_len = proofs
        .len()
        .checked_mul(proof_len)
        .ok_or(WireError::InvalidLength)?;
    let needed = fixed
        .checked_add(proofs_len)
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(transaction.len()))
        .ok_or(WireError::InvalidLength)?;
    if output.len() < needed {
        return Err(WireError::OutputTooSmall);
    }
    write_header(output, MessageKind::Signed, session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(tx_digest);
    output[HEADER_LEN + 32..HEADER_LEN + 36].copy_from_slice(&count.to_le_bytes());
    let mut offset = fixed;
    for proof in proofs {
        output[offset..offset + 4].copy_from_slice(&proof.input_index.to_le_bytes());
        output[offset + 4] = proof.signature_slot;
        offset += proof_len;
    }
    output[offset..offset + 4].copy_from_slice(&tx_len.to_le_bytes());
    offset += 4;
    output[offset..offset + transaction.len()].copy_from_slice(transaction);
    Ok(needed)
}

pub fn parse_signed(input: &[u8]) -> Result<Signed<'_>, WireError> {
    let header = parse_header(input, MessageKind::Signed)?;
    let layout = signed_layout();
    if input.len() < layout.fixed {
        return Err(WireError::Truncated);
    }
    let tx_digest = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let proof_count = read_signed_proof_count(input, layout)?;
    if proof_count == 0 {
        return Err(WireError::TooManyProofs);
    }
    let offsets = signed_offsets(input.len(), proof_count, layout)?;
    let transaction_len = read_signed_transaction_length(input, offsets.length_offset)?;
    signed_transaction_range(input.len(), offsets.tx_start, transaction_len).map(|tx_end| Signed {
        session_id: header.session_id,
        transaction_digest: tx_digest,
        proof_bytes: &input[layout.fixed..offsets.length_offset],
        proof_count,
        transaction: &input[offsets.tx_start..tx_end],
    })
}

#[derive(Clone, Copy)]
pub(super) struct SignedLayout {
    pub(super) fixed: usize,
    pub(super) proof_len: usize,
    pub(super) length_bytes: usize,
}

#[derive(Clone, Copy)]
struct SignedOffsets {
    length_offset: usize,
    tx_start: usize,
}

pub(super) fn signed_layout() -> SignedLayout {
    SignedLayout {
        fixed: HEADER_LEN + HASH_LEN + 4,
        proof_len: 5,
        length_bytes: 4,
    }
}

pub(super) fn read_signed_proof_count(
    input: &[u8],
    layout: SignedLayout,
) -> Result<usize, WireError> {
    read_u32(&input[HEADER_LEN + 32..layout.fixed])
}

fn signed_offsets(
    input_len: usize,
    proof_count: usize,
    layout: SignedLayout,
) -> Result<SignedOffsets, WireError> {
    proof_count
        .checked_mul(layout.proof_len)
        .and_then(|proofs_len| layout.fixed.checked_add(proofs_len))
        .and_then(|length_offset| {
            length_offset
                .checked_add(layout.length_bytes)
                .map(|tx_start| (length_offset, tx_start))
        })
        .filter(|(_, tx_start)| *tx_start <= input_len)
        .map(|(length_offset, tx_start)| SignedOffsets {
            length_offset,
            tx_start,
        })
        .ok_or(WireError::Truncated)
}

fn read_signed_transaction_length(input: &[u8], offset: usize) -> Result<usize, WireError> {
    read_u32(&input[offset..offset + 4])
}

fn signed_transaction_range(
    input_len: usize,
    tx_start: usize,
    transaction_len: usize,
) -> Result<usize, WireError> {
    tx_start
        .checked_add(transaction_len)
        .filter(|end| *end == input_len)
        .ok_or(WireError::InvalidLength)
}

impl Signed<'_> {
    pub const fn proof_count(&self) -> usize {
        self.proof_count
    }
    pub fn proof(&self, index: usize) -> Option<SignatureProof> {
        if index >= self.proof_count {
            return None;
        }
        let proof_len = 5usize;
        let offset = index * proof_len;
        let bytes = &self.proof_bytes[offset..offset + proof_len];
        Some(SignatureProof {
            input_index: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            signature_slot: bytes[4],
        })
    }
}

pub(super) fn parse_header(input: &[u8], expected: MessageKind) -> Result<Header, WireError> {
    if input.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if input[..4] != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let version = input[4];
    if version != VERSION {
        return Err(WireError::UnsupportedVersion);
    }
    let kind = MessageKind::from_byte(input[5])?;
    if kind != expected {
        return Err(WireError::WrongKind);
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&input[6..HEADER_LEN]);
    Ok(Header {
        version,
        kind,
        session_id,
    })
}

pub(super) fn write_header(
    output: &mut [u8],
    kind: MessageKind,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<(), WireError> {
    if output.len() < HEADER_LEN {
        return Err(WireError::OutputTooSmall);
    }
    output[..4].copy_from_slice(&MAGIC);
    output[4] = VERSION;
    output[5] = kind as u8;
    output[6..HEADER_LEN].copy_from_slice(session_id);
    Ok(())
}

pub(super) fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut v = [0u8; 32];
    v.copy_from_slice(bytes);
    v
}
pub(super) fn read_u32(input: &[u8]) -> Result<usize, WireError> {
    if input.len() < 4 {
        return Err(WireError::Truncated);
    }
    usize::try_from(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
        .map_err(|_| WireError::InvalidLength)
}

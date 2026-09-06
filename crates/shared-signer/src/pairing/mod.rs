//! KasSigner privacy-pairing wire protocol shared by firmware and wallet SDKs.
//!
//! Requests are stateless and carry explicit receive/change ranges plus a
//! wallet-generated nonce. Responses echo that nonce and include a stable,
//! non-secret account fingerprint so a host cannot accidentally combine
//! address batches from different KasSigner accounts.

use sha2::{Digest, Sha256};

pub const REQUEST_MAGIC: [u8; 4] = *b"KSPR";
pub const RESPONSE_MAGIC: [u8; 4] = *b"KSPB";
pub const VERSION: u8 = 2;
pub const NONCE_LEN: usize = 16;
pub const ACCOUNT_FINGERPRINT_LEN: usize = 16;
pub const REQUEST_LEN: usize = 4 + 1 + NONCE_LEN + 4 + 1 + 4 + 1;
pub const RESPONSE_HEADER_LEN: usize = REQUEST_LEN + ACCOUNT_FINGERPRINT_LEN;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const MAX_BATCH_PER_CHAIN: u8 = 50;
pub const SOFT_INDEX_LIMIT: u32 = 0x8000_0000;

const ACCOUNT_FINGERPRINT_DOMAIN: &[u8] = b"KasSigner privacy account fingerprint v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    EmptyBatch,
    BatchTooLarge,
    RangeOutsideSoftDerivation,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressBatchRequest {
    pub nonce: [u8; NONCE_LEN],
    pub receive_start: u32,
    pub receive_count: u8,
    pub change_start: u32,
    pub change_count: u8,
}

impl AddressBatchRequest {
    pub const fn new(
        nonce: [u8; NONCE_LEN],
        receive_start: u32,
        receive_count: u8,
        change_start: u32,
        change_count: u8,
    ) -> Self {
        Self {
            nonce,
            receive_start,
            receive_count,
            change_start,
            change_count,
        }
    }

    pub fn validate(self) -> Result<Self, PairingError> {
        if self.receive_count == 0 && self.change_count == 0 {
            return Err(PairingError::EmptyBatch);
        }
        if self.receive_count > MAX_BATCH_PER_CHAIN || self.change_count > MAX_BATCH_PER_CHAIN {
            return Err(PairingError::BatchTooLarge);
        }
        validate_range(self.receive_start, self.receive_count)?;
        validate_range(self.change_start, self.change_count)?;
        Ok(self)
    }

    #[must_use]
    pub const fn key_count(self) -> usize {
        self.receive_count as usize + self.change_count as usize
    }

    #[must_use]
    pub const fn response_len(self) -> usize {
        RESPONSE_HEADER_LEN + self.key_count() * PUBLIC_KEY_LEN
    }
}

fn validate_range(start: u32, count: u8) -> Result<(), PairingError> {
    if count == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(u32::from(count))
        .ok_or(PairingError::RangeOutsideSoftDerivation)?;
    if end > SOFT_INDEX_LIMIT {
        return Err(PairingError::RangeOutsideSoftDerivation);
    }
    Ok(())
}

pub fn encode_request(
    request: AddressBatchRequest,
    output: &mut [u8],
) -> Result<usize, PairingError> {
    let request = request.validate()?;
    if output.len() < REQUEST_LEN {
        return Err(PairingError::OutputTooSmall);
    }
    output[..4].copy_from_slice(&REQUEST_MAGIC);
    output[4] = VERSION;
    output[5..5 + NONCE_LEN].copy_from_slice(&request.nonce);
    let mut cursor = 5 + NONCE_LEN;
    output[cursor..cursor + 4].copy_from_slice(&request.receive_start.to_le_bytes());
    cursor += 4;
    output[cursor] = request.receive_count;
    cursor += 1;
    output[cursor..cursor + 4].copy_from_slice(&request.change_start.to_le_bytes());
    cursor += 4;
    output[cursor] = request.change_count;
    Ok(REQUEST_LEN)
}

pub fn parse_request(input: &[u8]) -> Result<AddressBatchRequest, PairingError> {
    if input.len() != REQUEST_LEN {
        return Err(PairingError::InvalidLength);
    }
    if input[..4] != REQUEST_MAGIC {
        return Err(PairingError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(PairingError::UnsupportedVersion);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&input[5..5 + NONCE_LEN]);
    let cursor = 5 + NONCE_LEN;
    AddressBatchRequest::new(
        nonce,
        u32::from_le_bytes(
            input[cursor..cursor + 4]
                .try_into()
                .map_err(|_| PairingError::InvalidLength)?,
        ),
        input[cursor + 4],
        u32::from_le_bytes(
            input[cursor + 5..cursor + 9]
                .try_into()
                .map_err(|_| PairingError::InvalidLength)?,
        ),
        input[cursor + 9],
    )
    .validate()
}

pub fn account_fingerprint(
    compressed_account_pubkey: &[u8; 33],
    chain_code: &[u8; 32],
) -> [u8; ACCOUNT_FINGERPRINT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_FINGERPRINT_DOMAIN);
    hasher.update(compressed_account_pubkey);
    hasher.update(chain_code);
    let digest = hasher.finalize();
    let mut fingerprint = [0u8; ACCOUNT_FINGERPRINT_LEN];
    fingerprint.copy_from_slice(&digest[..ACCOUNT_FINGERPRINT_LEN]);
    fingerprint
}

pub fn encode_response_header(
    request: AddressBatchRequest,
    account_fingerprint: [u8; ACCOUNT_FINGERPRINT_LEN],
    output: &mut [u8],
) -> Result<usize, PairingError> {
    let request = request.validate()?;
    if output.len() < request.response_len() {
        return Err(PairingError::OutputTooSmall);
    }
    output[..4].copy_from_slice(&RESPONSE_MAGIC);
    output[4] = VERSION;
    output[5..5 + NONCE_LEN].copy_from_slice(&request.nonce);
    let fingerprint_start = 5 + NONCE_LEN;
    output[fingerprint_start..fingerprint_start + ACCOUNT_FINGERPRINT_LEN]
        .copy_from_slice(&account_fingerprint);
    let cursor = fingerprint_start + ACCOUNT_FINGERPRINT_LEN;
    output[cursor..cursor + 4].copy_from_slice(&request.receive_start.to_le_bytes());
    output[cursor + 4] = request.receive_count;
    output[cursor + 5..cursor + 9].copy_from_slice(&request.change_start.to_le_bytes());
    output[cursor + 9] = request.change_count;
    Ok(RESPONSE_HEADER_LEN)
}

pub struct AddressBatchResponse<'a> {
    request: AddressBatchRequest,
    account_fingerprint: [u8; ACCOUNT_FINGERPRINT_LEN],
    keys: &'a [u8],
}

impl<'a> AddressBatchResponse<'a> {
    #[must_use]
    pub const fn request(&self) -> AddressBatchRequest {
        self.request
    }

    #[must_use]
    pub const fn account_fingerprint(&self) -> [u8; ACCOUNT_FINGERPRINT_LEN] {
        self.account_fingerprint
    }

    #[must_use]
    pub fn receive_key(&self, offset: usize) -> Option<&'a [u8; PUBLIC_KEY_LEN]> {
        if offset >= self.request.receive_count as usize {
            return None;
        }
        key_at(self.keys, offset)
    }

    #[must_use]
    pub fn change_key(&self, offset: usize) -> Option<&'a [u8; PUBLIC_KEY_LEN]> {
        if offset >= self.request.change_count as usize {
            return None;
        }
        key_at(self.keys, self.request.receive_count as usize + offset)
    }
}

fn key_at(keys: &[u8], index: usize) -> Option<&[u8; PUBLIC_KEY_LEN]> {
    let start = index.checked_mul(PUBLIC_KEY_LEN)?;
    keys.get(start..start + PUBLIC_KEY_LEN)?.try_into().ok()
}

pub fn parse_response(input: &[u8]) -> Result<AddressBatchResponse<'_>, PairingError> {
    if input.len() < RESPONSE_HEADER_LEN {
        return Err(PairingError::InvalidLength);
    }
    if input[..4] != RESPONSE_MAGIC {
        return Err(PairingError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(PairingError::UnsupportedVersion);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&input[5..5 + NONCE_LEN]);
    let fingerprint_start = 5 + NONCE_LEN;
    let mut account_fingerprint = [0u8; ACCOUNT_FINGERPRINT_LEN];
    account_fingerprint
        .copy_from_slice(&input[fingerprint_start..fingerprint_start + ACCOUNT_FINGERPRINT_LEN]);
    let cursor = fingerprint_start + ACCOUNT_FINGERPRINT_LEN;
    let request = AddressBatchRequest::new(
        nonce,
        u32::from_le_bytes(
            input[cursor..cursor + 4]
                .try_into()
                .map_err(|_| PairingError::InvalidLength)?,
        ),
        input[cursor + 4],
        u32::from_le_bytes(
            input[cursor + 5..cursor + 9]
                .try_into()
                .map_err(|_| PairingError::InvalidLength)?,
        ),
        input[cursor + 9],
    )
    .validate()?;
    if input.len() != request.response_len() {
        return Err(PairingError::InvalidLength);
    }
    Ok(AddressBatchResponse {
        request,
        account_fingerprint,
        keys: &input[RESPONSE_HEADER_LEN..],
    })
}

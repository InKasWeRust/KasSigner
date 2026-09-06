use serde::{Deserialize, Serialize};

use crate::{
    account::{derive_public_batch, AddressBranch, DerivedAddress},
    error::{ProtocolError, ProtocolResult},
    qr::{encode_frames, QrFrame},
    Network,
};

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub nonce_hex: String,
    pub receive_start: u32,
    pub receive_count: u8,
    pub change_start: u32,
    pub change_count: u8,
    pub payload: Vec<u8>,
    pub qr_frames: Vec<QrFrame>,
}

impl PairingRequest {
    pub fn wire_request(&self) -> ProtocolResult<shared_signer::pairing::AddressBatchRequest> {
        let nonce = decode_nonce(&self.nonce_hex)?;
        shared_signer::pairing::AddressBatchRequest::new(
            nonce,
            self.receive_start,
            self.receive_count,
            self.change_start,
            self.change_count,
        )
        .validate()
        .map_err(pairing_error)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyAddressBatch {
    pub network: Network,
    pub account_fingerprint: String,
    pub receive_addresses: Vec<DerivedAddress>,
    pub change_addresses: Vec<DerivedAddress>,
}

pub fn create_request(
    nonce: [u8; shared_signer::pairing::NONCE_LEN],
    receive_start: u32,
    receive_count: u8,
    change_start: u32,
    change_count: u8,
) -> ProtocolResult<PairingRequest> {
    let wire_request = shared_signer::pairing::AddressBatchRequest::new(
        nonce,
        receive_start,
        receive_count,
        change_start,
        change_count,
    )
    .validate()
    .map_err(pairing_error)?;
    let mut payload = vec![0u8; shared_signer::pairing::REQUEST_LEN];
    shared_signer::pairing::encode_request(wire_request, &mut payload).map_err(pairing_error)?;
    let qr_frames = encode_frames(&payload)?;
    Ok(PairingRequest {
        nonce_hex: hex::encode(nonce),
        receive_start,
        receive_count,
        change_start,
        change_count,
        payload,
        qr_frames,
    })
}

pub fn accept_response(
    request: &PairingRequest,
    response: &[u8],
    network: Network,
    expected_account_fingerprint: Option<&str>,
) -> ProtocolResult<PrivacyAddressBatch> {
    let expected_request = request.wire_request()?;
    let parsed = shared_signer::pairing::parse_response(response).map_err(pairing_error)?;
    if parsed.request() != expected_request {
        return Err(ProtocolError::pairing_mismatch(
            "privacy pairing response does not match the original request nonce/ranges",
        ));
    }
    let fingerprint = hex::encode(parsed.account_fingerprint());
    if let Some(expected) = expected_account_fingerprint {
        if !fingerprint.eq_ignore_ascii_case(expected) {
            return Err(ProtocolError::pairing_mismatch(
                "privacy pairing response belongs to a different KasSigner account",
            ));
        }
    }
    let receive_addresses = derive_response_addresses(
        expected_request.receive_start,
        expected_request.receive_count,
        AddressBranch::Receive,
        |offset| parsed.receive_key(offset),
        network,
    )?;
    let change_addresses = derive_response_addresses(
        expected_request.change_start,
        expected_request.change_count,
        AddressBranch::Change,
        |offset| parsed.change_key(offset),
        network,
    )?;
    Ok(PrivacyAddressBatch {
        network,
        account_fingerprint: fingerprint,
        receive_addresses,
        change_addresses,
    })
}

fn derive_response_addresses<'a>(
    start: u32,
    count: u8,
    branch: AddressBranch,
    key_at: impl Fn(usize) -> Option<&'a [u8; shared_signer::pairing::PUBLIC_KEY_LEN]>,
    network: Network,
) -> ProtocolResult<Vec<DerivedAddress>> {
    let mut keys = Vec::with_capacity(usize::from(count));
    for offset in 0..usize::from(count) {
        let key = key_at(offset).ok_or_else(|| {
            ProtocolError::pairing_mismatch("privacy pairing response key count mismatch")
        })?;
        let index = start
            .checked_add(
                u32::try_from(offset)
                    .map_err(|_| ProtocolError::derivation("pairing address offset exceeds u32"))?,
            )
            .ok_or_else(|| ProtocolError::derivation("pairing address index overflow"))?;
        keys.push((*key, branch, index));
    }
    Ok(derive_public_batch(keys, network))
}

fn decode_nonce(value: &str) -> ProtocolResult<[u8; shared_signer::pairing::NONCE_LEN]> {
    let bytes = hex::decode(value).map_err(|error| {
        ProtocolError::malformed(format!("invalid privacy pairing nonce: {error}"))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        ProtocolError::malformed(format!(
            "privacy pairing nonce must be {} bytes",
            shared_signer::pairing::NONCE_LEN
        ))
    })
}

fn pairing_error(error: shared_signer::pairing::PairingError) -> ProtocolError {
    ProtocolError::pairing_mismatch(format!("KasSigner pairing error: {error:?}"))
}

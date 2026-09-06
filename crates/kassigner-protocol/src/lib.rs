#![cfg_attr(not(feature = "host"), no_std)]

//! Low-level, network-free KasSigner protocol primitives.
//!
//! Wallet policy intentionally lives outside this crate. A host wallet owns
//! UTXO selection, fees, outputs, change, persistence, provider selection, and
//! broadcast. This crate owns account/pairing wire formats, PSKT↔KSPT relay,
//! QR payload framing, response validation, signature merge, and optional
//! standard transaction finalization.

#[cfg(feature = "host")]
mod account;
pub mod capabilities;
#[cfg(feature = "host")]
mod error;
#[cfg(feature = "host")]
mod network;
#[cfg(feature = "host")]
mod pairing;
#[cfg(feature = "host")]
mod pskt;
#[cfg(feature = "host")]
pub mod qr;
pub mod wire;

pub const PROTOCOL_VERSION: &str = "2.0.0";
pub use capabilities::{limits, SignerCapabilities, SIGNER_CAPABILITIES};

#[cfg(feature = "host")]
pub use account::{
    encode_address, encode_p2pk_address, encode_p2sh_address, AccountDescriptor, AddressBranch,
    DerivedAddress, WalletData,
};
#[cfg(feature = "host")]
pub use error::{ProtocolError, ProtocolErrorKind, ProtocolResult};
#[cfg(feature = "host")]
pub use network::Network;
#[cfg(feature = "host")]
pub use pairing::{PairingRequest, PrivacyAddressBatch};
#[cfg(feature = "host")]
pub use qr::{QrDecoder, QrFrame, QrProgress};

/// Compatibility-only account primitives used by KasSee while it migrates legacy
/// wallet internals. These are not part of the public third-party SDK contract.
#[cfg(feature = "kassee-compat")]
#[doc(hidden)]
pub mod compat {
    pub use crate::account::{
        address_to_script_pubkey, decode_address, decode_kpub_text, extend_addresses, import_kpub,
        import_kpub_raw, ExtPubKey,
    };
}

#[cfg(feature = "host")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "host")]
pub fn decode_address(address: &str) -> ProtocolResult<(u8, [u8; 32])> {
    account::decode_address(address).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn address_to_script_pubkey(address: &str) -> ProtocolResult<Vec<u8>> {
    account::address_to_script_pubkey(address).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn decode_kpub_text(
    kpub_text: &str,
) -> ProtocolResult<[u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN]> {
    account::decode_kpub_text(kpub_text).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn import_kpub(kpub_text: &str, prefix: &str) -> ProtocolResult<WalletData> {
    account::import_kpub(kpub_text, prefix).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn import_kpub_raw(payload: &[u8], prefix: &str) -> ProtocolResult<WalletData> {
    account::import_kpub_raw(payload, prefix).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn extend_addresses(
    wallet: &WalletData,
    extra_receive: u32,
    extra_change: u32,
    prefix: &str,
) -> ProtocolResult<WalletData> {
    account::extend_addresses(wallet, extra_receive, extra_change, prefix)
        .map_err(ProtocolError::derivation)
}

#[cfg(feature = "host")]
pub fn decode_account(payload: &str, network: Network) -> ProtocolResult<AccountDescriptor> {
    account::decode_account(payload, network).map_err(ProtocolError::decoding)
}

#[cfg(feature = "host")]
pub fn create_privacy_pairing_request(
    nonce: [u8; shared_signer::pairing::NONCE_LEN],
    receive_start: u32,
    receive_count: u8,
    change_start: u32,
    change_count: u8,
) -> ProtocolResult<PairingRequest> {
    pairing::create_request(
        nonce,
        receive_start,
        receive_count,
        change_start,
        change_count,
    )
}

#[cfg(feature = "host")]
pub fn accept_privacy_pairing_response(
    request: &PairingRequest,
    response: &[u8],
    network: Network,
    expected_account_fingerprint: Option<&str>,
) -> ProtocolResult<PrivacyAddressBatch> {
    pairing::accept_response(request, response, network, expected_account_fingerprint)
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub(crate) fn create_privacy_pairing_request_hex(
    nonce_hex: &str,
    receive_start: u32,
    receive_count: u8,
    change_start: u32,
    change_count: u8,
) -> ProtocolResult<PairingRequest> {
    let bytes = hex::decode(nonce_hex)
        .map_err(|error| ProtocolError::malformed(format!("invalid nonce hex: {error}")))?;
    let nonce = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::malformed("privacy pairing nonce must be 16 bytes"))?;
    create_privacy_pairing_request(
        nonce,
        receive_start,
        receive_count,
        change_start,
        change_count,
    )
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub(crate) fn accept_privacy_pairing_response_text(
    request_json: &str,
    response_hex: &str,
    network: &str,
    expected_account_fingerprint: Option<&str>,
) -> ProtocolResult<PrivacyAddressBatch> {
    let request: PairingRequest = serde_json::from_str(request_json).map_err(|error| {
        ProtocolError::malformed(format!("invalid pairing request JSON: {error}"))
    })?;
    let response = hex::decode(response_hex).map_err(|error| {
        ProtocolError::malformed(format!("invalid pairing response hex: {error}"))
    })?;
    let network = Network::parse(network)?;
    accept_privacy_pairing_response(&request, &response, network, expected_account_fingerprint)
}

#[cfg(feature = "host")]
pub fn encode_pskt(pskt_hex: &str, network: Network) -> ProtocolResult<Vec<u8>> {
    pskt::encode_pskt(pskt_hex, network).map_err(ProtocolError::encoding)
}

#[cfg(feature = "host")]
pub fn encode_pskt_hex(pskt_hex: &str, network: Network) -> ProtocolResult<String> {
    encode_pskt(pskt_hex, network).map(hex::encode)
}

#[cfg(feature = "host")]
pub fn merge_signed_kspt(
    original_pskt_hex: &str,
    signed_kspt: &[u8],
    network: Network,
) -> ProtocolResult<String> {
    pskt::merge_signed_kspt(original_pskt_hex, signed_kspt, network)
        .map_err(ProtocolError::transaction_mismatch)
}

#[cfg(feature = "host")]
pub fn merge_signed_kspt_hex(
    original_pskt_hex: &str,
    signed_kspt_hex: &str,
    network: Network,
) -> ProtocolResult<String> {
    let bytes = hex::decode(signed_kspt_hex)
        .map_err(|error| ProtocolError::malformed(format!("invalid KSPT hex: {error}")))?;
    merge_signed_kspt(original_pskt_hex, &bytes, network)
}

#[cfg(feature = "host")]
pub fn finalize_json(pskt_hex: &str) -> ProtocolResult<String> {
    pskt::finalize_json(pskt_hex).map_err(ProtocolError::finalization)
}

#[cfg(feature = "host")]
pub fn attach_input_derivation(
    pskt_hex: &str,
    input_index: usize,
    branch: AddressBranch,
    index: u32,
) -> ProtocolResult<String> {
    pskt::attach_input_derivation(pskt_hex, input_index, branch, index)
        .map_err(ProtocolError::derivation)
}

#[cfg(feature = "host")]
pub fn attach_output_derivation(
    pskt_hex: &str,
    output_index: usize,
    branch: AddressBranch,
    index: u32,
) -> ProtocolResult<String> {
    pskt::attach_output_derivation(pskt_hex, output_index, branch, index)
        .map_err(ProtocolError::derivation)
}

#[cfg(feature = "host")]
pub fn encode_qr_frames(payload: &[u8]) -> ProtocolResult<Vec<QrFrame>> {
    qr::encode_frames(payload)
}

#[cfg(feature = "host")]
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningRequest {
    pub network: Network,
    pub original_pskt_hex: String,
    pub kspt_hex: String,
    pub qr_frames: Vec<QrFrame>,
}

#[cfg(feature = "host")]
impl SigningRequest {
    pub fn from_pskt(pskt_hex: &str, network: Network) -> ProtocolResult<Self> {
        let kspt = encode_pskt(pskt_hex, network)?;
        let qr_frames = encode_qr_frames(&kspt)?;
        Ok(Self {
            network,
            original_pskt_hex: pskt_hex.to_string(),
            kspt_hex: hex::encode(kspt),
            qr_frames,
        })
    }

    #[must_use]
    pub fn qr_frames(&self) -> &[QrFrame] {
        &self.qr_frames
    }
}

#[cfg(feature = "host")]
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningResponse {
    pub kspt_hex: String,
}

#[cfg(feature = "host")]
impl SigningResponse {
    pub fn decode(payload_hex: &str) -> ProtocolResult<Self> {
        validate_kspt_envelope(payload_hex)?;
        Ok(Self {
            kspt_hex: payload_hex.to_string(),
        })
    }

    pub fn merge_into(&self, original_pskt_hex: &str, network: Network) -> ProtocolResult<String> {
        merge_signed_kspt_hex(original_pskt_hex, &self.kspt_hex, network)
    }
}

#[cfg(feature = "host")]
fn validate_kspt_envelope(payload_hex: &str) -> ProtocolResult<()> {
    let bytes = hex::decode(payload_hex)
        .map_err(|error| ProtocolError::malformed(format!("invalid KSPT hex: {error}")))?;
    wire::kspt::validate(&bytes)
        .map(|_| ())
        .map_err(|error| ProtocolError::decoding(error.to_string()))
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

#[cfg(all(test, feature = "host"))]
mod unit_tests;

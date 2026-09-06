//! Friendly, network-free KasSigner SDK for wallet developers.
//!
//! The host wallet owns UTXOs, coin control, fees, outputs, change policy,
//! persistence, network providers, and broadcast. This facade owns only the
//! KasSigner-specific protocol/session work.

mod error;

use serde::{Deserialize, Serialize};

pub use error::{SdkError, SdkErrorKind, SdkResult};
use kassigner_protocol::{self as protocol, QrDecoder};
pub use kassigner_protocol::{
    attach_input_derivation, attach_output_derivation, AccountDescriptor, AddressBranch,
    DerivedAddress, Network, PairingRequest, ProtocolError, ProtocolErrorKind, QrFrame, QrProgress,
    SignerCapabilities, SigningRequest, SigningResponse,
};

pub const SDK_VERSION: &str = "2.0.0";

#[must_use]
pub const fn limits() -> SignerCapabilities {
    protocol::limits()
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedAccount {
    pub mode: PairingMode,
    pub network: Network,
    pub account_fingerprint: String,
    pub account_kpub: Option<String>,
    pub receive_addresses: Vec<DerivedAddress>,
    pub change_addresses: Vec<DerivedAddress>,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingMode {
    Descriptor,
    Privacy,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPskt {
    pub network: Network,
    pub pskt_hex: String,
}

pub fn pair_normal(account_payload: &str, network: Network) -> SdkResult<PairedAccount> {
    let account = protocol::decode_account(account_payload, network)?;
    Ok(PairedAccount {
        mode: PairingMode::Descriptor,
        network,
        account_fingerprint: account.account_fingerprint,
        account_kpub: Some(account.account_kpub),
        receive_addresses: account.receive_addresses,
        change_addresses: account.change_addresses,
    })
}

pub fn prepare(pskt_hex: &str, network: Network) -> SdkResult<SigningRequest> {
    SigningRequest::from_pskt(pskt_hex, network).map_err(Into::into)
}

pub fn complete(request: &SigningRequest, response_hex: &str) -> SdkResult<SignedPskt> {
    let response = SigningResponse::decode(response_hex)?;
    let pskt_hex = response.merge_into(&request.original_pskt_hex, request.network)?;
    Ok(SignedPskt {
        network: request.network,
        pskt_hex,
    })
}

pub fn finalize(signed: &SignedPskt) -> SdkResult<String> {
    protocol::finalize_json(&signed.pskt_hex).map_err(Into::into)
}

pub struct KasSigner {
    decoder: QrDecoder,
    pending_pairing: Option<PairingRequest>,
    account_fingerprint: Option<String>,
}

impl Default for KasSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl KasSigner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            decoder: QrDecoder::new(),
            pending_pairing: None,
            account_fingerprint: None,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> SignerCapabilities {
        crate::limits()
    }

    pub fn pair_normal(
        &mut self,
        account_payload: &str,
        network: Network,
    ) -> SdkResult<PairedAccount> {
        let account = pair_normal(account_payload, network)?;
        self.account_fingerprint = Some(account.account_fingerprint.clone());
        self.pending_pairing = None;
        Ok(account)
    }

    pub fn create_privacy_pairing_request(
        &mut self,
        receive_start: u32,
        receive_count: u8,
        change_start: u32,
        change_count: u8,
    ) -> SdkResult<PairingRequest> {
        let mut nonce = [0u8; shared_nonce_len()];
        getrandom::getrandom(&mut nonce).map_err(|error| {
            SdkError::randomness(format!("privacy pairing randomness unavailable: {error}"))
        })?;
        let request = protocol::create_privacy_pairing_request(
            nonce,
            receive_start,
            receive_count,
            change_start,
            change_count,
        )?;
        self.pending_pairing = Some(request.clone());
        Ok(request)
    }

    pub fn pair_privacy(
        &mut self,
        response_hex: &str,
        network: Network,
    ) -> SdkResult<PairedAccount> {
        let request = self.pending_pairing.as_ref().ok_or_else(|| {
            SdkError::pairing_replay(
                "privacy pairing response has no pending request (replay or wrong session)",
            )
        })?;
        let response = hex::decode(response_hex).map_err(|error| {
            SdkError::malformed(format!("invalid privacy pairing response hex: {error}"))
        })?;
        let batch = protocol::accept_privacy_pairing_response(
            request,
            &response,
            network,
            self.account_fingerprint.as_deref(),
        )?;
        self.pending_pairing = None;
        self.account_fingerprint = Some(batch.account_fingerprint.clone());
        Ok(PairedAccount {
            mode: PairingMode::Privacy,
            network,
            account_fingerprint: batch.account_fingerprint,
            account_kpub: None,
            receive_addresses: batch.receive_addresses,
            change_addresses: batch.change_addresses,
        })
    }

    pub fn prepare(&self, pskt_hex: &str, network: Network) -> SdkResult<SigningRequest> {
        prepare(pskt_hex, network)
    }

    pub fn complete(&self, request: &SigningRequest, response_hex: &str) -> SdkResult<SignedPskt> {
        complete(request, response_hex)
    }

    pub fn finalize(&self, signed: &SignedPskt) -> SdkResult<String> {
        finalize(signed)
    }

    pub fn accept_qr_frame(&mut self, frame: &[u8]) -> SdkResult<Option<Vec<u8>>> {
        self.decoder.accept(frame).map_err(Into::into)
    }

    pub fn reset_qr_decoder(&mut self) {
        self.decoder.reset();
    }

    #[must_use]
    pub fn qr_decoder_progress(&self) -> QrProgress {
        self.decoder.progress()
    }

    #[must_use]
    pub fn account_fingerprint(&self) -> Option<&str> {
        self.account_fingerprint.as_deref()
    }
}

const fn shared_nonce_len() -> usize {
    16
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

#[cfg(test)]
mod unit_tests;

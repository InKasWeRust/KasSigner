//! Private Swap v2 firmware authorization service.
//!
//! Only the isolated mnemonic-derived covenant hierarchy participates. Claim
//! adaptor pre-signatures are produced over an independently parsed exact
//! Kaspa transaction sighash and require a two-round host-committed nonce
//! contribution. Ordinary wallet spending keys never sign this surface.

use crate::runtime::data::{AppData, PrivateSwapMode, PrivateSwapPhase};
use sha2::{Digest, Sha256};
use shared_signer::covenant_sign::private_swap::{
    self as wire, PrivateSwapResponse, RequestKind, ResponseKind,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateSwapError {
    InvalidEnvelope,
    MnemonicRequired,
    EntropyUnavailable,
    DerivationFailed,
    BindingRequired,
    BindingMismatch,
    InvalidScript,
    InvalidTransaction,
    InvalidAdaptorPoint,
    RevealMismatch,
    AntiKleptoFailed,
    SigningFailed,
    ResponseEncodingFailed,
}

impl PrivateSwapError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "Invalid Private Swap request",
            Self::MnemonicRequired => "Private Swap requires mnemonic",
            Self::EntropyUnavailable => "Private Swap entropy unavailable",
            Self::DerivationFailed => "Private Swap key derivation failed",
            Self::BindingRequired => "Bind the swap key first",
            Self::BindingMismatch => "Swap key bound to different script",
            Self::InvalidScript => "Invalid Private Swap covenant",
            Self::InvalidTransaction => "Invalid Private Swap claim transaction",
            Self::InvalidAdaptorPoint => "Invalid adaptor point",
            Self::RevealMismatch => "Private Swap reveal mismatch",
            Self::AntiKleptoFailed => "Private Swap nonce proof failed",
            Self::SigningFailed => "Private Swap signing failed",
            Self::ResponseEncodingFailed => "Private Swap response failed",
        }
    }
}

pub fn prepare_request(ad: &mut AppData, input: &[u8], checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), PrivateSwapError> {
    let request = wire::parse_request(input).map_err(|_| PrivateSwapError::InvalidEnvelope)?;
    match request.kind {
        RequestKind::KeyInfo => prepare_key_info(ad, checkpoint),
        RequestKind::Bind => prepare_bind(ad, &request),
        RequestKind::PreSign => prepare_presign(ad, &request, checkpoint),
        RequestKind::Complete => prepare_complete(ad, &request, checkpoint),
    }
}

fn prepare_key_info(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), PrivateSwapError> {
    let mut key_id = [0u8; 32];
    crate::crypto::entropy::fill(&mut key_id)
        .map_err(|_| PrivateSwapError::EntropyUnavailable)?;
    if key_id == [0; 32] {
        return Err(PrivateSwapError::EntropyUnavailable);
    }
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let pubkey = offline_signer::derivation::covenant::private_swap_public_key(
        &seed.bytes,
        &key_id,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    let adaptor = offline_signer::derivation::covenant::private_swap_adaptor_point(
        &seed.bytes,
        &key_id,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let state = &mut ad.signing.private_swap;
    state.reset();
    state.mode = PrivateSwapMode::KeyInfo;
    state.key_id = key_id;
    state.claim_pubkey = pubkey;
    state.adaptor_point = adaptor;
    state.replace_pending(key_id, pubkey, adaptor);
    build_response(ad, ResponseKind::KeyInfo, [0; 64], false)
}

fn prepare_bind(
    ad: &mut AppData,
    request: &wire::PrivateSwapRequest<'_>,
) -> Result<(), PrivateSwapError> {
    let state = &ad.signing.private_swap;
    if request.key_id != state.pending_key_id
        || request.adaptor_point != state.pending_adaptor_point
    {
        return Err(PrivateSwapError::BindingRequired);
    }
    let policy = offline_signer::transaction::private_swap::parse_private_swap_script(
        request.payload,
    )
    .map_err(|_| PrivateSwapError::InvalidScript)?;
    if policy.claimer_pubkey != state.pending_pubkey {
        return Err(PrivateSwapError::InvalidScript);
    }
    let state = &mut ad.signing.private_swap;
    state.reset();
    state.mode = PrivateSwapMode::Bind;
    state.phase = PrivateSwapPhase::Prepared;
    state.key_id = request.key_id;
    state.claim_pubkey = policy.claimer_pubkey;
    state.adaptor_point = request.adaptor_point;
    state.script_hash = Sha256::digest(request.payload).into();
    state.refund_locktime_daa = policy.refund_locktime_daa;
    state.destination_hash = Sha256::digest(&policy.destination_spk).into();
    Ok(())
}

pub fn complete_binding(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), PrivateSwapError> {
    let state = &ad.signing.private_swap;
    if state.mode != PrivateSwapMode::Bind
        || state.phase != PrivateSwapPhase::Prepared
        || state.key_id != state.pending_key_id
    {
        return Err(PrivateSwapError::BindingRequired);
    }
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let token = offline_signer::derivation::covenant::private_swap_binding_token(
        &seed.bytes,
        &ad.signing.private_swap.key_id,
        &ad.signing.private_swap.script_hash,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let state = &mut ad.signing.private_swap;
    state.binding_token = token;
    state.phase = PrivateSwapPhase::FinalResponse;
    state.clear_pending();
    build_response(ad, ResponseKind::Binding, [0; 64], false)
}

fn prepare_presign(
    ad: &mut AppData,
    request: &wire::PrivateSwapRequest<'_>,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), PrivateSwapError> {
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let pubkey = offline_signer::derivation::covenant::private_swap_public_key(
        &seed.bytes,
        &request.key_id,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    offline_signer::transaction::kspt::parse_compact_kspt(
        request.payload,
        &mut ad.signing.transaction.active,
    )
    .map_err(|_| PrivateSwapError::InvalidTransaction)?;
    let (sighash, policy) =
        offline_signer::transaction::private_swap::private_swap_claim_sighash(
            &ad.signing.transaction.active,
            &pubkey,
        )
        .map_err(|_| PrivateSwapError::InvalidTransaction)?;
    let script_hash: [u8; 32] =
        Sha256::digest(ad.signing.transaction.active.redeem_bytes(0)).into();
    let bound = offline_signer::derivation::covenant::private_swap_binding_matches(
        &seed.bytes,
        &request.key_id,
        &script_hash,
        &request.binding_token,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    if !bound {
        crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
        return Err(PrivateSwapError::BindingMismatch);
    }
    let mut aux = [0u8; 32];
    crate::crypto::entropy::fill(&mut aux)
        .map_err(|_| PrivateSwapError::EntropyUnavailable)?;
    let nonce = offline_signer::derivation::covenant::private_swap_adaptor_base_nonce_point(
        &seed.bytes,
        &request.key_id,
        &sighash,
        &request.adaptor_point,
        &request.session_id,
        &aux,
    )
    .map_err(|_| PrivateSwapError::SigningFailed)?;
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let input_amount = ad.signing.transaction.active.inputs[0].utxo_entry.amount;
    let output_amount = ad.signing.transaction.active.outputs[0].value;
    let state = &mut ad.signing.private_swap;
    state.reset();
    state.mode = PrivateSwapMode::PreSign;
    state.phase = PrivateSwapPhase::Prepared;
    state.session_id = request.session_id;
    state.host_commitment = request.host_commitment;
    state.key_id = request.key_id;
    state.claim_pubkey = pubkey;
    state.binding_token = request.binding_token;
    state.adaptor_point = request.adaptor_point;
    state.script_hash = script_hash;
    state.sighash = sighash;
    state.nonce_point = nonce;
    state.aux_rand = aux;
    state.input_amount = input_amount;
    state.output_amount = output_amount;
    state.fee = input_amount - output_amount;
    state.refund_locktime_daa = policy.refund_locktime_daa;
    state.destination_hash = Sha256::digest(&policy.destination_spk).into();
    Ok(())
}

pub fn begin_presign(ad: &mut AppData) -> Result<(), PrivateSwapError> {
    let state = &mut ad.signing.private_swap;
    if state.mode != PrivateSwapMode::PreSign || state.phase != PrivateSwapPhase::Prepared {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    state.phase = PrivateSwapPhase::AwaitingReveal;
    build_response(ad, ResponseKind::Nonce, [0; 64], false)
}

pub fn finalize_reveal(ad: &mut AppData, input: &[u8], checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), PrivateSwapError> {
    let mut reveal = wire::parse_reveal(input).map_err(|_| PrivateSwapError::InvalidEnvelope)?;
    let state = &ad.signing.private_swap;
    let reveal_matches = state.mode == PrivateSwapMode::PreSign
        && state.phase == PrivateSwapPhase::AwaitingReveal
        && reveal.session_id == state.session_id
        && reveal.key_id == state.key_id
        && reveal.sighash == state.sighash
        && shared_signer::anti_klepto::verify_host_secret(
            &state.host_commitment,
            &reveal.host_secret,
        );
    if !reveal_matches {
        shared_signer::bytes::zeroize_bytes(&mut reveal.host_secret);
        return Err(PrivateSwapError::RevealMismatch);
    }
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let state = &ad.signing.private_swap;
    let presig = offline_signer::derivation::covenant::create_private_swap_adaptor_presignature(
        &seed.bytes,
        &state.key_id,
        &state.sighash,
        &state.adaptor_point,
        &state.session_id,
        &state.aux_rand,
        &reveal.host_secret,
    )
    .map_err(|_| PrivateSwapError::SigningFailed)?;
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let relation = offline_signer::crypto::adaptor::verify_host_nonce_relation(
        &state.claim_pubkey,
        &state.sighash,
        &state.adaptor_point,
        &state.session_id,
        &reveal.host_secret,
        &state.nonce_point,
        &presig,
    );
    shared_signer::bytes::zeroize_bytes(&mut reveal.host_secret);
    relation.map_err(|_| PrivateSwapError::AntiKleptoFailed)?;
    let state = &mut ad.signing.private_swap;
    state.presignature = presig.bytes;
    state.presignature_negated = presig.negated;
    state.phase = PrivateSwapPhase::FinalResponse;
    build_response(
        ad,
        ResponseKind::PreSignature,
        presig.bytes,
        presig.negated,
    )
}

fn prepare_complete(
    ad: &mut AppData,
    request: &wire::PrivateSwapRequest<'_>,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), PrivateSwapError> {
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let pubkey = offline_signer::derivation::covenant::private_swap_public_key(
        &seed.bytes,
        &request.key_id,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    let own_adaptor = offline_signer::derivation::covenant::private_swap_adaptor_point(
        &seed.bytes,
        &request.key_id,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    if own_adaptor != request.adaptor_point {
        crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
        return Err(PrivateSwapError::InvalidAdaptorPoint);
    }
    offline_signer::transaction::kspt::parse_compact_kspt(
        request.payload,
        &mut ad.signing.transaction.active,
    )
    .map_err(|_| PrivateSwapError::InvalidTransaction)?;
    let (sighash, policy) =
        offline_signer::transaction::private_swap::private_swap_claim_sighash(
            &ad.signing.transaction.active,
            &pubkey,
        )
        .map_err(|_| PrivateSwapError::InvalidTransaction)?;
    let script_hash: [u8; 32] =
        Sha256::digest(ad.signing.transaction.active.redeem_bytes(0)).into();
    let bound = offline_signer::derivation::covenant::private_swap_binding_matches(
        &seed.bytes,
        &request.key_id,
        &script_hash,
        &request.binding_token,
    )
    .map_err(|_| PrivateSwapError::DerivationFailed)?;
    let presig = offline_signer::crypto::adaptor::AdaptorPreSignature {
        bytes: request.presignature,
        negated: request.presignature_negated,
    };
    let presig_valid = offline_signer::crypto::adaptor::verify_adaptor_presignature(
        &pubkey,
        &sighash,
        &presig,
        &request.adaptor_point,
    )
    .is_ok();
    if !bound || !presig_valid {
        crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
        return Err(PrivateSwapError::BindingMismatch);
    }
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let input_amount = ad.signing.transaction.active.inputs[0].utxo_entry.amount;
    let output_amount = ad.signing.transaction.active.outputs[0].value;
    let state = &mut ad.signing.private_swap;
    state.reset();
    state.mode = PrivateSwapMode::Complete;
    state.phase = PrivateSwapPhase::Prepared;
    state.key_id = request.key_id;
    state.claim_pubkey = pubkey;
    state.binding_token = request.binding_token;
    state.adaptor_point = request.adaptor_point;
    state.script_hash = script_hash;
    state.sighash = sighash;
    state.presignature = request.presignature;
    state.presignature_negated = request.presignature_negated;
    state.input_amount = input_amount;
    state.output_amount = output_amount;
    state.fee = input_amount - output_amount;
    state.refund_locktime_daa = policy.refund_locktime_daa;
    state.destination_hash = Sha256::digest(&policy.destination_spk).into();
    Ok(())
}

pub fn complete_claim(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), PrivateSwapError> {
    let state = &ad.signing.private_swap;
    if state.mode != PrivateSwapMode::Complete || state.phase != PrivateSwapPhase::Prepared {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    let presig = offline_signer::crypto::adaptor::AdaptorPreSignature {
        bytes: state.presignature,
        negated: state.presignature_negated,
    };
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| PrivateSwapError::MnemonicRequired)?;
    let completed =
        offline_signer::derivation::covenant::complete_private_swap_adaptor_presignature(
            &seed.bytes,
            &state.key_id,
            &presig,
        )
        .map_err(|_| PrivateSwapError::SigningFailed)?;
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let completed_sig = offline_signer::crypto::schnorr::SchnorrSignature { bytes: completed };
    if offline_signer::crypto::schnorr::schnorr_verify(
        &state.claim_pubkey,
        &state.sighash,
        &completed_sig,
    )
    .is_err()
    {
        return Err(PrivateSwapError::SigningFailed);
    }
    let state = &mut ad.signing.private_swap;
    state.completed_signature = completed;
    state.phase = PrivateSwapPhase::FinalResponse;
    build_response(ad, ResponseKind::Completed, completed, false)
}

fn build_response(
    ad: &mut AppData,
    kind: ResponseKind,
    signature: [u8; 64],
    negated: bool,
) -> Result<(), PrivateSwapError> {
    let state = &ad.signing.private_swap;
    let response = PrivateSwapResponse {
        kind,
        session_id: if matches!(kind, ResponseKind::Nonce | ResponseKind::PreSignature) {
            state.session_id
        } else {
            [0; 16]
        },
        key_id: state.key_id,
        claim_pubkey: state.claim_pubkey,
        binding_token: if matches!(
            kind,
            ResponseKind::Binding
                | ResponseKind::Nonce
                | ResponseKind::PreSignature
                | ResponseKind::Completed
        ) {
            state.binding_token
        } else {
            [0; 32]
        },
        adaptor_point: state.adaptor_point,
        commitment: match kind {
            ResponseKind::Binding => state.script_hash,
            ResponseKind::Nonce | ResponseKind::PreSignature | ResponseKind::Completed => {
                state.sighash
            }
            ResponseKind::KeyInfo => [0; 32],
        },
        nonce_point: if matches!(kind, ResponseKind::Nonce | ResponseKind::PreSignature) {
            state.nonce_point
        } else {
            [0; 33]
        },
        signature,
        negated,
    };
    ad.signing.private_swap.response_len = wire::encode_response(
        &response,
        &mut ad.signing.private_swap.response,
    )
    .map_err(|_| PrivateSwapError::ResponseEncodingFailed)?;
    Ok(())
}

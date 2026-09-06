//! Universal covenant-signing policy boundary.
//!
//! This is the only firmware path that signs a caller-supplied 32-byte
//! covenant commitment. It derives an isolated covenant-instance key from a
//! mnemonic seed and never accepts a normal wallet-spending private key. Each
//! device-generated covenant key ID must first be bound to one exact script
//! fingerprint; the portable binding record is revalidated from the mnemonic
//! on every later signing request. Final signatures require a host-committed
//! anti-klepto reveal.

use sha2::{Digest, Sha256};
use shared_signer::covenant_sign::{
    self, BindingHint, CovenantSignResponse, KnownScheme, RequestKind, ResponseKind,
};

use crate::runtime::data::{AppData, CovenantSigningMode, CovenantSigningPhase};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CovenantSignError {
    InvalidEnvelope, MnemonicRequired, DerivationFailed, CommitmentMismatch,
    CovenantKeyNotBound, InvalidKnownContext, EntropyUnavailable, SigningFailed,
    RevealMismatch, AntiKleptoFailed, ResponseEncodingFailed, BindingRequired,
    BindingMismatch,
}

impl CovenantSignError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "Invalid covenant request",
            Self::MnemonicRequired => "Covenant signing requires mnemonic",
            Self::DerivationFailed => "Covenant key derivation failed",
            Self::CommitmentMismatch => "Covenant commitment mismatch",
            Self::CovenantKeyNotBound => "Covenant key not bound in script",
            Self::InvalidKnownContext => "Known covenant context invalid",
            Self::EntropyUnavailable => "Covenant key entropy unavailable",
            Self::SigningFailed => "Covenant signing failed",
            Self::RevealMismatch => "Covenant reveal mismatch",
            Self::AntiKleptoFailed => "Covenant nonce proof failed",
            Self::ResponseEncodingFailed => "Covenant response failed",
            Self::BindingRequired => "Bind this covenant key before signing",
            Self::BindingMismatch => "Covenant key is bound to a different script",
        }
    }
}

pub fn prepare_request(ad: &mut AppData, wire: &[u8], checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    let request = covenant_sign::parse_request(wire).map_err(|_| CovenantSignError::InvalidEnvelope)?;
    if request.kind == RequestKind::KeyInfo { return prepare_key_info(ad, checkpoint); }

    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| CovenantSignError::MnemonicRequired)?;
    let result = prepare_with_seed(ad, &request, &seed.bytes);
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    result
}

fn prepare_key_info(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    let mut key_id = [0u8; 32];
    crate::crypto::entropy::fill(&mut key_id).map_err(|_| CovenantSignError::EntropyUnavailable)?;
    if key_id == [0u8; 32] { return Err(CovenantSignError::EntropyUnavailable); }
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| CovenantSignError::MnemonicRequired)?;
    let pubkey_result = offline_signer::derivation::covenant::covenant_public_key(&seed.bytes, &key_id);
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let pubkey_x = pubkey_result.map_err(|_| CovenantSignError::DerivationFailed)?;

    ad.signing.covenant.reset();
    ad.signing.covenant.mode = CovenantSigningMode::KeyInfo;
    ad.signing.covenant.key_id = key_id;
    ad.signing.covenant.pubkey_x = pubkey_x;
    ad.signing.covenant.replace_pending_allocation(key_id, pubkey_x);
    build_response(ad, ResponseKind::KeyInfo, [0u8; 64])
}

fn prepare_with_seed(
    ad: &mut AppData,
    request: &covenant_sign::CovenantSignRequest<'_>,
    seed: &[u8; 64],
) -> Result<(), CovenantSignError> {
    let pubkey_x = offline_signer::derivation::covenant::covenant_public_key(seed, &request.key_id)
        .map_err(|_| CovenantSignError::DerivationFailed)?;
    let script_hash: [u8; 32] = Sha256::digest(request.script).into();

    if request.kind == RequestKind::Bind {
        return prepare_binding(ad, request, &pubkey_x, script_hash);
    }
    let binding_ok = offline_signer::derivation::covenant::covenant_binding_matches(
        seed, &request.key_id, &script_hash, &request.binding_token,
    ).map_err(|_| CovenantSignError::DerivationFailed)?;
    if !binding_ok { return Err(CovenantSignError::BindingMismatch); }
    ad.signing.covenant.reset();
    set_request_identity(ad, request, pubkey_x, script_hash);
    ad.signing.covenant.binding_token = request.binding_token;
    match request.kind {
        RequestKind::Known => prepare_known(ad, request, &pubkey_x),
        RequestKind::Opaque => prepare_opaque(ad, request, &pubkey_x),
        RequestKind::KeyInfo | RequestKind::Bind => Err(CovenantSignError::InvalidEnvelope),
    }
}

fn prepare_binding(
    ad: &mut AppData,
    request: &covenant_sign::CovenantSignRequest<'_>,
    pubkey_x: &[u8; 32],
    script_hash: [u8; 32],
) -> Result<(), CovenantSignError> {
    if request.key_id != ad.signing.covenant.pending_key_id
        || *pubkey_x != ad.signing.covenant.pending_pubkey_x
    { return Err(CovenantSignError::BindingRequired); }

    ad.signing.covenant.reset();
    set_request_identity(ad, request, *pubkey_x, script_hash);
    if request.scheme == KnownScheme::None {
        validate_opaque_shape(request, pubkey_x)?;
        ad.signing.covenant.mode = CovenantSigningMode::BindOpaque;
    } else {
        validate_known_shape(request, pubkey_x)?;
        copy_review_context(ad, request.context)?;
        ad.signing.covenant.mode = CovenantSigningMode::BindKnown;
    }
    ad.signing.covenant.phase = CovenantSigningPhase::Prepared;
    Ok(())
}

fn set_request_identity(
    ad: &mut AppData,
    request: &covenant_sign::CovenantSignRequest<'_>,
    pubkey_x: [u8; 32],
    script_hash: [u8; 32],
) {
    ad.signing.covenant.session_id = request.session_id;
    ad.signing.covenant.host_commitment = request.host_commitment;
    ad.signing.covenant.key_id = request.key_id;
    ad.signing.covenant.pubkey_x = pubkey_x;
    ad.signing.covenant.commitment = request.commitment;
    ad.signing.covenant.scheme = request.scheme;
    ad.signing.covenant.script_hash = script_hash;
}

fn prepare_known(
    ad: &mut AppData, request: &covenant_sign::CovenantSignRequest<'_>, pubkey_x: &[u8; 32],
) -> Result<(), CovenantSignError> {
    validate_known_shape(request, pubkey_x)?;
    copy_review_context(ad, request.context)?;
    ad.signing.covenant.mode = CovenantSigningMode::Known;
    ad.signing.covenant.phase = CovenantSigningPhase::Prepared;
    Ok(())
}

fn validate_known_shape(
    request: &covenant_sign::CovenantSignRequest<'_>, pubkey_x: &[u8; 32],
) -> Result<(), CovenantSignError> {
    if request.binding != covenant_sign::expected_known_binding(request.scheme) { return Err(CovenantSignError::InvalidEnvelope); }
    let recomputed = covenant_sign::recompute_known_commitment(request.scheme, request.context)
        .ok_or(CovenantSignError::InvalidKnownContext)?;
    if recomputed != request.commitment { return Err(CovenantSignError::CommitmentMismatch); }
    if !covenant_sign::known_script_binds(request.scheme, request.script, &recomputed, pubkey_x) {
        return Err(CovenantSignError::CovenantKeyNotBound);
    }
    Ok(())
}

fn prepare_opaque(
    ad: &mut AppData, request: &covenant_sign::CovenantSignRequest<'_>, pubkey_x: &[u8; 32],
) -> Result<(), CovenantSignError> {
    validate_opaque_shape(request, pubkey_x)?;
    ad.signing.covenant.mode = CovenantSigningMode::Opaque;
    ad.signing.covenant.phase = CovenantSigningPhase::Prepared;
    Ok(())
}

fn validate_opaque_shape(
    request: &covenant_sign::CovenantSignRequest<'_>, pubkey_x: &[u8; 32],
) -> Result<(), CovenantSignError> {
    if request.scheme != KnownScheme::None || !matches!(request.binding, BindingHint::None | BindingHint::KeyPresent) {
        return Err(CovenantSignError::InvalidEnvelope);
    }
    if request.binding == BindingHint::KeyPresent && !covenant_sign::script_contains_xonly_key(request.script, pubkey_x) {
        return Err(CovenantSignError::CovenantKeyNotBound);
    }
    Ok(())
}

fn copy_review_context(ad: &mut AppData, input: &[u8]) -> Result<(), CovenantSignError> {
    if input.len() > ad.signing.covenant.context.len() || core::str::from_utf8(input).is_err() {
        return Err(CovenantSignError::InvalidKnownContext);
    }
    ad.signing.covenant.context.fill(0);
    ad.signing.covenant.context[..input.len()].copy_from_slice(input);
    ad.signing.covenant.context_len = input.len();
    ad.signing.covenant.context_page = 0;
    Ok(())
}

/// Confirm the one-time binding of the freshly device-allocated covenant key
/// to the exact script fingerprint. The returned token is non-secret portable
/// metadata and must travel with the covenant for future signing/recovery.
pub fn complete_binding(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    if !matches!(ad.signing.covenant.mode, CovenantSigningMode::BindKnown | CovenantSigningMode::BindOpaque)
        || ad.signing.covenant.phase != CovenantSigningPhase::Prepared
        || ad.signing.covenant.key_id != ad.signing.covenant.pending_key_id
    { return Err(CovenantSignError::BindingRequired); }
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint)
        .map_err(|_| CovenantSignError::MnemonicRequired)?;
    let token = offline_signer::derivation::covenant::covenant_binding_token(
        &seed.bytes, &ad.signing.covenant.key_id, &ad.signing.covenant.script_hash,
    );
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    ad.signing.covenant.binding_token = token.map_err(|_| CovenantSignError::DerivationFailed)?;
    ad.signing.covenant.phase = CovenantSigningPhase::FinalResponse;
    ad.signing.covenant.clear_pending_allocation();
    build_response(ad, ResponseKind::Binding, [0u8; 64])
}

/// After user review, generate only a provisional nonce commitment. The final
/// covenant signature does not exist until the host reveals its committed
/// contribution in a second QR round.
pub fn begin_signing(ad: &mut AppData, checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    if !matches!(ad.signing.covenant.mode, CovenantSigningMode::Known | CovenantSigningMode::Opaque)
        || ad.signing.covenant.phase != CovenantSigningPhase::Prepared
        || ad.signing.covenant.binding_token == [0u8; 32]
    { return Err(CovenantSignError::InvalidEnvelope); }

    let mut aux = [0u8; 32];
    crate::crypto::entropy::fill(&mut aux).map_err(|_| CovenantSignError::EntropyUnavailable)?;
    let mut seed = match crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint) {
        Ok(seed) => seed,
        Err(_) => { shared_signer::bytes::zeroize_bytes(&mut aux); return Err(CovenantSignError::MnemonicRequired); }
    };
    let provisional = offline_signer::derivation::covenant::provisional_covenant_signature(
        &seed.bytes, &ad.signing.covenant.key_id, &ad.signing.covenant.commitment, &aux,
    );
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    shared_signer::bytes::zeroize_bytes(&mut aux);
    let provisional = provisional.map_err(|_| CovenantSignError::SigningFailed)?;
    let nonce_point = offline_signer::crypto::anti_klepto::provisional_nonce_point(&provisional);
    ad.signing.covenant.provisional_signature = provisional.bytes;
    ad.signing.covenant.nonce_point = nonce_point;
    ad.signing.covenant.phase = CovenantSigningPhase::AwaitingReveal;
    ad.signing.covenant.nonce_qr_shown = false;
    build_response(ad, ResponseKind::NonceCommitment, [0u8; 64])
}

pub fn finalize_reveal(ad: &mut AppData, wire: &[u8], checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    let mut reveal = covenant_sign::parse_reveal(wire).map_err(|_| CovenantSignError::InvalidEnvelope)?;
    let result = validate_reveal(ad, &reveal).and_then(|()| finalize_signature(ad, &reveal.host_secret, checkpoint));
    shared_signer::bytes::zeroize_bytes(&mut reveal.host_secret);
    result
}

fn validate_reveal(ad: &AppData, reveal: &covenant_sign::CovenantSignReveal) -> Result<(), CovenantSignError> {
    let state = &ad.signing.covenant;
    let identity_matches = state.phase == CovenantSigningPhase::AwaitingReveal
        && state.session_id == reveal.session_id && state.key_id == reveal.key_id
        && state.commitment == reveal.commitment;
    let secret_matches = shared_signer::anti_klepto::verify_host_secret(&state.host_commitment, &reveal.host_secret);
    (identity_matches && secret_matches).then_some(()).ok_or(CovenantSignError::RevealMismatch)
}

fn finalize_signature(ad: &mut AppData, host_secret: &[u8; 32], checkpoint: &mut (impl FnMut() + ?Sized)) -> Result<(), CovenantSignError> {
    let provisional = offline_signer::crypto::schnorr::SchnorrSignature { bytes: ad.signing.covenant.provisional_signature };
    let mut seed = crate::services::wallet_keys::derive_active_seed_with_checkpoint(ad, checkpoint).map_err(|_| CovenantSignError::MnemonicRequired)?;
    let final_signature = offline_signer::derivation::covenant::finalize_covenant_signature(
        &seed.bytes, &ad.signing.covenant.key_id, &ad.signing.covenant.commitment, &provisional,
        &ad.signing.covenant.session_id, host_secret,
    );
    crate::services::wallet_keys::zeroize_seed(&mut seed.bytes);
    let final_signature = final_signature.map_err(|_| CovenantSignError::SigningFailed)?;
    verify_nonce_relation(ad, host_secret, &final_signature)?;
    ad.signing.covenant.signature = final_signature.bytes;
    ad.signing.covenant.phase = CovenantSigningPhase::FinalResponse;
    build_response(ad, ResponseKind::Signature, final_signature.bytes)
}

fn verify_nonce_relation(
    ad: &AppData, host_secret: &[u8; 32], signature: &offline_signer::crypto::schnorr::SchnorrSignature,
) -> Result<(), CovenantSignError> {
    let mut public_key = [0u8; 33]; public_key[0] = 0x02; public_key[1..].copy_from_slice(&ad.signing.covenant.pubkey_x);
    offline_signer::crypto::anti_klepto::verify_nonce_relation(
        &ad.signing.covenant.nonce_point, signature, &ad.signing.covenant.session_id,
        host_secret, 0, 0, &public_key,
    ).map_err(|_| CovenantSignError::AntiKleptoFailed)
}

fn build_response(ad: &mut AppData, kind: ResponseKind, signature: [u8; 64]) -> Result<(), CovenantSignError> {
    let signing = matches!(kind, ResponseKind::NonceCommitment | ResponseKind::Signature);
    let binding = matches!(kind, ResponseKind::Binding | ResponseKind::NonceCommitment | ResponseKind::Signature);
    let response = CovenantSignResponse {
        kind,
        session_id: if signing { ad.signing.covenant.session_id } else { [0u8; covenant_sign::SESSION_ID_LEN] },
        key_id: ad.signing.covenant.key_id,
        pubkey_x: ad.signing.covenant.pubkey_x,
        binding_token: if binding { ad.signing.covenant.binding_token } else { [0u8; 32] },
        commitment: match kind {
            ResponseKind::Binding => ad.signing.covenant.script_hash,
            ResponseKind::NonceCommitment | ResponseKind::Signature => ad.signing.covenant.commitment,
            ResponseKind::KeyInfo => [0u8; 32],
        },
        nonce_point: if signing { ad.signing.covenant.nonce_point } else { [0u8; 33] },
        signature,
    };
    ad.signing.covenant.response_len = covenant_sign::encode_response(&response, &mut ad.signing.covenant.response)
        .map_err(|_| CovenantSignError::ResponseEncodingFailed)?;
    Ok(())
}

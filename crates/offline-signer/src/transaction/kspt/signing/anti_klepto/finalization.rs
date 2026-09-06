use shared_signer::{anti_klepto::SESSION_ID_LEN, bytes::zeroize_bytes};

use crate::{
    crypto::{anti_klepto as crypto, schnorr::SchnorrSignature},
    derivation::bip32,
    transaction::{
        kspt::PsktError,
        model::{SigHashType, Transaction},
        sighash,
    },
};

use super::super::context::{SigningContext, SigningKeyMaterial};

pub fn initial_signature_counts(tx: &Transaction) -> [u8; crate::transaction::model::MAX_INPUTS] {
    let mut counts = [0u8; crate::transaction::model::MAX_INPUTS];
    for (slot, input) in counts.iter_mut().zip(tx.inputs()) {
        *slot = input.sig_count;
    }
    counts
}

pub fn finalize_raw_key_signatures(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let public_key = bip32::compressed_pubkey_from_raw_key(private_key)
        .map_err(|_| PsktError::DerivationFailed)?;
    finalize_matching(
        tx,
        initial_counts,
        session_id,
        host_secret,
        |_, sig_pubkey| {
            if sig_pubkey == &public_key {
                Some(SigningKeyMaterial {
                    private_key: *private_key,
                    compressed_public_key: public_key,
                })
            } else {
                None
            }
        },
    )
}

pub fn finalize_account_signatures(
    tx: &mut Transaction,
    account_key: &bip32::ExtendedPrivKey,
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let mut no_checkpoint = || {};
    finalize_account_signatures_with_checkpoint(
        tx,
        account_key,
        initial_counts,
        session_id,
        host_secret,
        &mut no_checkpoint,
    )
}

pub fn finalize_account_signatures_with_checkpoint(
    tx: &mut Transaction,
    account_key: &bip32::ExtendedPrivKey,
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<usize, PsktError> {
    let raw = account_key.to_raw();
    finalize_account_set_signatures_with_checkpoint(
        tx,
        &[(raw, true)],
        initial_counts,
        session_id,
        host_secret,
        checkpoint,
    )
}

pub fn finalize_account_set_signatures(
    tx: &mut Transaction,
    accounts: &[([u8; 65], bool)],
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let mut no_checkpoint = || {};
    finalize_account_set_signatures_with_checkpoint(
        tx,
        accounts,
        initial_counts,
        session_id,
        host_secret,
        &mut no_checkpoint,
    )
}

pub fn finalize_account_set_signatures_with_checkpoint(
    tx: &mut Transaction,
    accounts: &[([u8; 65], bool)],
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<usize, PsktError> {
    let mut context = SigningContext::from_account_raw(accounts);
    checkpoint();
    finalize_matching(
        tx,
        initial_counts,
        session_id,
        host_secret,
        |tx, sig_pubkey| {
            checkpoint();
            let mut target = [0u8; 32];
            target.copy_from_slice(&sig_pubkey[1..33]);
            if let Some(material) = context.matching_material_with_checkpoint(&target, checkpoint) {
                return Some(material);
            }
            if tx.has_stealth_tweak {
                for seed_index in 0..context.seed_count() {
                    checkpoint();
                    if let Some(material) = stealth_material(&context, seed_index, tx, &target) {
                        checkpoint();
                        return Some(material);
                    }
                    checkpoint();
                }
            }
            None
        },
    )
}

fn finalize_matching<F>(
    tx: &mut Transaction,
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    mut resolve: F,
) -> Result<usize, PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    let counts = initial_counts
        .get(..tx.num_inputs)
        .ok_or(PsktError::InvalidSignatureState)?;
    let mut changed = 0usize;
    for (input_index, &initial_count) in counts.iter().enumerate() {
        changed += finalize_input_signatures(
            tx,
            input_index,
            initial_count,
            session_id,
            host_secret,
            &mut resolve,
        )?;
    }
    if changed == 0 {
        Err(PsktError::NoInputs)
    } else {
        Ok(changed)
    }
}

fn finalize_input_signatures<F>(
    tx: &mut Transaction,
    input_index: usize,
    initial_count: u8,
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    resolve: &mut F,
) -> Result<usize, PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    let start = usize::from(initial_count);
    let end = usize::from(tx.inputs[input_index].sig_count);
    validate_signature_range(tx, input_index, start, end)?;
    for slot in start..end {
        finalize_signature_slot(tx, input_index, slot, session_id, host_secret, resolve)?;
    }
    Ok(end - start)
}

fn validate_signature_range(
    tx: &Transaction,
    input_index: usize,
    start: usize,
    end: usize,
) -> Result<(), PsktError> {
    tx.inputs[input_index]
        .sigs
        .get(start..end)
        .map(|_| ())
        .ok_or(PsktError::InvalidSignatureState)
}

fn finalize_signature_slot<F>(
    tx: &mut Transaction,
    input_index: usize,
    slot: usize,
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    resolve: &mut F,
) -> Result<(), PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    let sig = tx.inputs[input_index].sigs[slot].clone();
    if !sig.present || sig.pubkey_compressed[0] == 0 {
        return Err(PsktError::InvalidSignatureState);
    }
    let Some(mut material) = resolve(tx, &sig.pubkey_compressed) else {
        return Err(PsktError::DerivationFailed);
    };
    if material.compressed_public_key != sig.pubkey_compressed {
        zeroize_bytes(&mut material.private_key);
        return Err(PsktError::DerivationFailed);
    }
    let result = finalize_with_material(
        tx,
        input_index,
        slot,
        sig.sighash_type,
        sig.signature,
        FinalizationMaterial {
            session_id,
            host_secret,
            private_key: &material.private_key,
        },
    );
    zeroize_bytes(&mut material.private_key);
    result
}

struct FinalizationMaterial<'a> {
    session_id: &'a [u8; SESSION_ID_LEN],
    host_secret: &'a [u8; 32],
    private_key: &'a [u8; 32],
}

fn finalize_with_material(
    tx: &mut Transaction,
    input_index: usize,
    slot: usize,
    sighash_byte: u8,
    provisional_bytes: [u8; 64],
    material: FinalizationMaterial<'_>,
) -> Result<(), PsktError> {
    let sighash_type = SigHashType::from_byte(sighash_byte).ok_or(PsktError::InvalidSigHashType)?;
    let message = sighash::calculate_sighash(tx, input_index, sighash_type);
    let provisional = SchnorrSignature {
        bytes: provisional_bytes,
    };
    let final_signature = crypto::tweak_provisional_signature(
        material.private_key,
        &message,
        &provisional,
        material.session_id,
        material.host_secret,
        u32::try_from(input_index).map_err(|_| PsktError::TooManyInputs)?,
        slot as u8,
    )
    .map_err(|_| PsktError::SigningFailed)?;
    tx.inputs[input_index].sigs[slot].signature = final_signature.bytes;
    Ok(())
}

fn stealth_material(
    context: &SigningContext,
    seed_index: usize,
    tx: &Transaction,
    target_xonly: &[u8; 32],
) -> Option<SigningKeyMaterial> {
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let account = context.account_material(seed_index)?;
    let account_primitive =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(&account.private_key).ok()?;
    let account_scalar = {
        let scalar = Scalar::from(account_primitive);
        let encoded = (ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x03 {
            -scalar
        } else {
            scalar
        }
    };
    let tweak = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tx.stealth_tweak).ok()?;
    let combined = account_scalar.add(&Scalar::from(tweak));
    let point = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_encoded_point(true);
    if &point.as_bytes()[1..33] != target_xonly {
        return None;
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&combined.to_bytes());
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(point.as_bytes());
    Some(SigningKeyMaterial {
        private_key,
        compressed_public_key,
    })
}

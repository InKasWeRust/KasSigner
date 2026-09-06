use shared_signer::anti_klepto::{NonceCommitment, SignatureProof};

use crate::{
    crypto::{anti_klepto as crypto, schnorr::SchnorrSignature},
    transaction::model::Transaction,
};

use crate::transaction::kspt::PsktError;

fn reserved_records<T>(tx: &Transaction) -> Result<alloc::vec::Vec<T>, PsktError> {
    let capacity = tx
        .num_inputs
        .checked_mul(crate::transaction::model::MAX_SIGS_PER_INPUT)
        .ok_or(PsktError::TooManyInputs)?;
    let mut records = alloc::vec::Vec::new();
    records
        .try_reserve_exact(capacity)
        .map_err(|_| PsktError::TooManySignatures)?;
    Ok(records)
}

fn added_signatures<'a>(
    tx: &'a Transaction,
    initial_counts: &[u8],
    input_index: usize,
) -> Result<(usize, &'a [crate::transaction::model::InputSig]), PsktError> {
    let input = tx
        .inputs
        .get(input_index)
        .ok_or(PsktError::InvalidSignatureState)?;
    let start = usize::from(
        *initial_counts
            .get(input_index)
            .ok_or(PsktError::InvalidSignatureState)?,
    );
    let end = usize::from(input.sig_count);
    let signatures = input
        .sigs
        .get(start..end)
        .ok_or(PsktError::InvalidSignatureState)?;
    Ok((start, signatures))
}

pub fn nonce_commitment_records(
    tx: &Transaction,
    initial_counts: &[u8],
) -> Result<alloc::vec::Vec<NonceCommitment>, PsktError> {
    let mut records = reserved_records(tx)?;
    for input_index in 0..tx.num_inputs {
        let (start, signatures) = added_signatures(tx, initial_counts, input_index)?;
        for (slot, sig) in (start..).zip(signatures.iter()) {
            if !sig.present || sig.pubkey_compressed[0] == 0 {
                return Err(PsktError::InvalidSignatureState);
            }
            let provisional = SchnorrSignature {
                bytes: sig.signature,
            };
            let mut canonical_public_key = [0u8; 33];
            canonical_public_key[0] = 0x02;
            canonical_public_key[1..].copy_from_slice(&sig.pubkey_compressed[1..]);
            records.push(NonceCommitment {
                input_index: u32::try_from(input_index).map_err(|_| PsktError::TooManyInputs)?,
                signature_slot: slot as u8,
                public_key: canonical_public_key,
                nonce_point: crypto::provisional_nonce_point(&provisional),
            });
        }
    }
    if records.is_empty() {
        Err(PsktError::NoInputs)
    } else {
        Ok(records)
    }
}

pub fn proof_records(
    tx: &Transaction,
    initial_counts: &[u8],
) -> Result<alloc::vec::Vec<SignatureProof>, PsktError> {
    let mut proofs = reserved_records(tx)?;
    for input_index in 0..tx.num_inputs {
        let (start, signatures) = added_signatures(tx, initial_counts, input_index)?;
        for (slot, sig) in (start..).zip(signatures.iter()) {
            if !sig.present {
                return Err(PsktError::InvalidSignatureState);
            }
            proofs.push(SignatureProof {
                input_index: u32::try_from(input_index).map_err(|_| PsktError::TooManyInputs)?,
                signature_slot: slot as u8,
            });
        }
    }
    if proofs.is_empty() {
        Err(PsktError::NoInputs)
    } else {
        Ok(proofs)
    }
}

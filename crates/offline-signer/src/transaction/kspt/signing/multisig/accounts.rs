use crate::transaction::model::{MultisigInfo, ScriptType, SigHashType, Transaction};

use super::super::super::{
    error::PsktError, script::analyze_input_script, validation::validate_base_transaction,
};
use super::super::{context::SigningContext, covenant::sign_covenant_input};
use super::{sign_multisig_input, sign_p2pk_input};

struct InputClassification<'a> {
    script_type: ScriptType,
    multisig: Option<&'a MultisigInfo>,
}

/// Sign one supported input with mnemonic/account material. This is used by
/// firmware to provide truthful per-input progress for large transactions.
pub fn sign_multisig_account_sets_input_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    ms45_accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    super::super::p2pk::ensure_input_index(tx, input_index)?;
    let mut context = SigningContext::from_account_sets(accounts, ms45_accounts);
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    sign_classified_account_input(
        tx,
        input_index,
        &mut context,
        sighash_type,
        active_account_idx,
        signing_entropy,
        InputClassification {
            script_type,
            multisig: multisig.as_ref(),
        },
    )
}

pub fn sign_multisig_accounts_input_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)
        .and_then(|()| super::super::p2pk::ensure_input_index(tx, input_index))
        .and_then(|()| {
            sign_account_context_input(
                tx,
                input_index,
                accounts,
                sighash_type,
                active_account_idx,
                signing_entropy,
            )
        })
}

fn sign_account_context_input(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    let mut context = SigningContext::from_account_raw(accounts);
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    sign_classified_account_input(
        tx,
        input_index,
        &mut context,
        sighash_type,
        active_account_idx,
        signing_entropy,
        InputClassification {
            script_type,
            multisig: multisig.as_ref(),
        },
    )
}

fn sign_classified_account_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
    classification: InputClassification<'_>,
) -> Result<usize, PsktError> {
    if classification.script_type == ScriptType::P2PK {
        return sign_p2pk_input(
            tx,
            input_index,
            context,
            sighash_type,
            Some(signing_entropy),
        );
    }
    sign_non_p2pk_account_input(
        tx,
        input_index,
        context,
        sighash_type,
        active_account_idx,
        signing_entropy,
        classification,
    )
}

fn sign_non_p2pk_account_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
    classification: InputClassification<'_>,
) -> Result<usize, PsktError> {
    if let Some(info) = classification.multisig {
        return sign_multisig_input(
            tx,
            input_index,
            info,
            context,
            sighash_type,
            Some(signing_entropy),
        );
    }
    sign_covenant_account_input(
        tx,
        input_index,
        context,
        sighash_type,
        active_account_idx,
        signing_entropy,
        classification.script_type,
    )
}

fn sign_covenant_account_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
    script_type: ScriptType,
) -> Result<usize, PsktError> {
    if script_type != ScriptType::P2SH {
        return Ok(0);
    }
    sign_covenant_input(
        tx,
        input_index,
        context,
        sighash_type,
        active_account_idx,
        Some(signing_entropy),
    )
}

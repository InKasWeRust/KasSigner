use crate::runtime::data::AppData;

#[derive(Clone, Copy)]
pub(super) enum SigningStrategy {
    RawKey,
    AccountKey,
    Multisig,
    Mnemonic,
}

pub(super) fn select(ad: &AppData) -> Option<SigningStrategy> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot()?;
    if slot.is_raw_key() {
        return Some(SigningStrategy::RawKey);
    }

    let has_multisig = (0..ad.signing.transaction.active.num_inputs).any(|index| {
        let (script_type, _) = offline_signer::transaction::kspt::analyze_input_script(
            &ad.signing.transaction.active,
            index,
        );
        matches!(
            script_type,
            offline_signer::transaction::model::ScriptType::Multisig
                | offline_signer::transaction::model::ScriptType::P2SH
        )
    });
    if has_multisig {
        return Some(SigningStrategy::Multisig);
    }
    if slot.is_account_key() {
        Some(SigningStrategy::AccountKey)
    } else if slot.is_mnemonic() {
        Some(SigningStrategy::Mnemonic)
    } else {
        None
    }
}

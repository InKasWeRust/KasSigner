//! Shared multisig descriptor/state installation and persistence helpers.

use crate::runtime::data::AppData;
use offline_signer::transaction::model::MultisigConfig;
use kassigner_protocol::wire::multisig_descriptor::ParsedMultisigDescriptor;

pub(crate) fn config_from_descriptor(
    descriptor: &ParsedMultisigDescriptor,
    active: bool,
) -> MultisigConfig {
    let mut config = MultisigConfig::new();
    config.m = descriptor.threshold;
    config.n = descriptor.participant_count;
    config.v45 = descriptor.v45;
    config.cosigner_pubkeys = descriptor.public_keys;
    config.cosigner_chain_codes = descriptor.chain_codes;
    config.cosigner_depth = descriptor.depths;
    config.cosigner_parent_fp = descriptor.parent_fingerprints;
    config.cosigner_child_num = descriptor.child_numbers;
    config.active = active;
    config.build_script();
    config
}

pub(crate) fn install_descriptor(
    ad: &mut AppData,
    descriptor: &ParsedMultisigDescriptor,
    active: bool,
) {
    ad.signing.multisig.creating = config_from_descriptor(descriptor, active);
}

pub(crate) fn install_descriptor_and_resolve(
    ad: &mut AppData,
    descriptor: &ParsedMultisigDescriptor,
    active: bool,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    install_descriptor(ad, descriptor, active);
    let _ = crate::runtime::interactions::tx::resolve_loaded_cosigner_index(ad, checkpoint);
    ad.signing.multisig.creating.build_script();
}

/// Persist the currently edited config back to its matching stored wallet.
/// Wallet identity is centralized in `MultisigConfig::same_wallet_as`.
pub(crate) fn persist_creating_config(ad: &mut AppData) -> bool {
    let creating = ad.signing.multisig.creating.clone();
    let Some(config) = ad.signing.multisig.store.configs.iter_mut().find(|config| {
        config.active && config.same_wallet_as(&creating)
    }) else { return false; };
    *config = creating;
    true
}

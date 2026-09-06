//! Validation helpers for multisig configuration shape and participant identity.

use crate::derivation::xpub::KpubParts;

use super::{constants::MAX_MULTISIG_KEYS, MultisigConfig};

pub(super) fn valid_config(m: u8, n: u8) -> bool {
    m != 0 && n != 0 && m <= n && n as usize <= MAX_MULTISIG_KEYS
}

pub(super) fn contains_cosigner(
    config: &MultisigConfig,
    parts: &KpubParts,
    except: Option<usize>,
) -> bool {
    (0..MAX_MULTISIG_KEYS).any(|i| {
        Some(i) != except
            && config.cosigner_pubkeys[i] == parts.pubkey
            && config.cosigner_chain_codes[i] == parts.chain_code
            && config.cosigner_depth[i] == parts.depth
            && config.cosigner_parent_fp[i] == parts.parent_fp
            && config.cosigner_child_num[i] == parts.child_num
    })
}

#[must_use]
pub(super) fn slot_empty(config: &MultisigConfig, index: usize) -> bool {
    if index >= MAX_MULTISIG_KEYS {
        return false;
    }
    config.cosigner_pubkeys[index] == [0; 33]
}

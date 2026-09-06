//! Pure transaction-review totals derived from the signed transaction and
//! signer-verified output ownership.

use crate::runtime::data::OutputOwnership;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReviewTotals {
    pub input_total: u64,
    pub output_total: u64,
    pub external_total: u64,
    pub change_total: u64,
    pub own_receive_total: u64,
    pub fee: u64,
}

pub fn totals(
    tx: &offline_signer::transaction::model::Transaction,
    ownership: &[OutputOwnership; offline_signer::transaction::model::MAX_OUTPUTS],
) -> Result<ReviewTotals, offline_signer::transaction::kspt::PsktError> {
    let amounts = offline_signer::transaction::kspt::transaction_amounts(tx)?;
    let mut external_total = 0u64;
    let mut change_total = 0u64;
    let mut own_receive_total = 0u64;
    for (index, output) in tx.outputs().iter().enumerate() {
        let target = match ownership[index] {
            OutputOwnership::External => &mut external_total,
            OutputOwnership::Change => &mut change_total,
            OutputOwnership::Receive => &mut own_receive_total,
        };
        *target = (*target)
            .checked_add(output.value)
            .ok_or(offline_signer::transaction::kspt::PsktError::OutputAmountOverflow)?;
    }
    Ok(ReviewTotals {
        input_total: amounts.input_total,
        output_total: amounts.output_total,
        external_total,
        change_total,
        own_receive_total,
        fee: amounts.fee,
    })
}

/// Verify watcher-provided output derivation hints against the active wallet.
/// Hints are never trusted as labels: any hinted wallet-owned output must
/// derive to the exact P2PK script or the transaction is rejected. Silently
/// downgrading a failed change hint to `External` can misrepresent change as
/// money being sent, so hinted ownership is fail-closed.
#[cfg(feature = "workflow-test-auto")]
#[inline(never)]
pub fn verify_transaction_output_ownership(
    ad: &mut crate::runtime::data::AppData,
) -> Result<(), &'static str> {
    let mut no_checkpoint = || {};
    verify_transaction_output_ownership_with_checkpoint(ad, &mut no_checkpoint)
}

#[inline(never)]
pub fn verify_transaction_output_ownership_with_checkpoint(
    ad: &mut crate::runtime::data::AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<(), &'static str> {
    use crate::runtime::data::OutputOwnership;
    let mut ownership = [
        OutputOwnership::External;
        offline_signer::transaction::model::MAX_OUTPUTS
    ];

    let hinted = ad
        .signing
        .transaction
        .active
        .outputs()
        .iter()
        .filter(|output| output.has_derivation_hint)
        .count();
    if hinted > 0 {
        let slot = ad
            .wallet
            .seeds
            .seed_mgr
            .active_slot()
            .ok_or("No active wallet for output verification")?;
        let account = super::derivation::derive_slot_account_key_with_checkpoint(slot, checkpoint)
            .map_err(|_| "Active wallet cannot verify transaction outputs")?;
        checkpoint();

        for (index, output) in ad.signing.transaction.active.outputs().iter().enumerate() {
            if !output.has_derivation_hint {
                continue;
            }
            if output.derivation_branch > 1 {
                return Err("Invalid wallet output derivation hint");
            }
            checkpoint();
            let xonly = hinted_output_xonly(&account, output)
                .ok_or("Wallet output derivation failed")?;
            checkpoint();
            let matches = p2pk_matches(&output.script_public_key, &xonly);
            crate::log!(
                "   TX ownership hint output={} branch={} index={} match={}",
                index,
                output.derivation_branch,
                output.derivation_index,
                matches,
            );
            if matches {
                ownership[index] = if output.derivation_branch == 1 {
                    OutputOwnership::Change
                } else {
                    OutputOwnership::Receive
                };
                continue;
            }

            // A watcher can have stale derivation-index metadata while still
            // constructing a script that belongs to this exact active wallet. Do
            // not trust or silently externalize the hint: recover only by proving
            // the output pubkey is ours somewhere in the bounded signing range.
            let target_xonly = p2pk_xonly(&output.script_public_key)
                .ok_or("Hinted wallet output is not a P2PK script")?;
            checkpoint();
            let Some((actual_index, is_change)) = find_owned_output_with_checkpoint(
                &account,
                &target_xonly,
                output.derivation_branch,
                checkpoint,
            ) else {
                return Err("Transaction output does not belong to active wallet");
            };
            crate::log!(
                "   TX ownership hint corrected output={} hinted={}/{} actual={}/{}",
                index,
                output.derivation_branch,
                output.derivation_index,
                u8::from(is_change),
                actual_index,
            );
            ownership[index] = if is_change {
                OutputOwnership::Change
            } else {
                OutputOwnership::Receive
            };
        }
    }

    verify_multisig_output_ownership(
        &ad.signing.transaction.active,
        &ad.signing.multisig.store.configs,
        &mut ownership,
    )?;
    ad.signing.transaction.output_ownership = ownership;
    Ok(())
}

fn verify_multisig_output_ownership(
    tx: &offline_signer::transaction::model::Transaction,
    configs: &[offline_signer::transaction::model::MultisigConfig],
    ownership: &mut [OutputOwnership; offline_signer::transaction::model::MAX_OUTPUTS],
) -> Result<(), &'static str> {
    if offline_signer::transaction::model::find_forged_change(tx, configs).is_some() {
        return Err("Invalid multisig output derivation hint");
    }
    for (index, slot) in ownership.iter_mut().enumerate().take(tx.num_outputs) {
        let Some(chain) =
            offline_signer::transaction::model::trusted_multisig_output_chain(tx, configs, index)
        else {
            continue;
        };
        *slot = if chain == 1 {
            OutputOwnership::Change
        } else {
            OutputOwnership::Receive
        };
        crate::log!(
            "   TX trusted multisig ownership output={} chain={}",
            index,
            chain,
        );
    }
    Ok(())
}

fn find_owned_output_with_checkpoint(
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
    target_xonly: &[u8; 32],
    preferred_branch: u8,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Option<(u16, bool)> {
    // Search the hinted branch first so a stale index on an otherwise valid
    // change output normally resolves immediately. The fallback is deliberately
    // limited to the small UI/cache discovery range; a correct high index still
    // succeeds through the exact hint above, while an untrusted stale hint cannot
    // trigger a long 200-address foreground scan.
    let branches = if preferred_branch == 1 { [1u8, 0u8] } else { [0u8, 1u8] };
    for branch in branches {
        for index in 0..offline_signer::derivation::bip32::ADDR_SCAN_DEPTH {
            checkpoint();
            let key = if branch == 1 {
                offline_signer::derivation::bip32::derive_change_key(account, u32::from(index))
            } else {
                offline_signer::derivation::bip32::derive_address_key(account, u32::from(index))
            };
            let Ok(key) = key else { continue; };
            checkpoint();
            let Ok(candidate) = key.public_key_x_only() else { continue; };
            checkpoint();
            if candidate == *target_xonly {
                return Some((index, branch == 1));
            }
        }
    }
    None
}

fn hinted_output_xonly(
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
    output: &offline_signer::transaction::model::TransactionOutput,
) -> Option<[u8; 32]> {
    if !output.has_derivation_hint || output.derivation_branch > 1 { return None; }
    let child = if output.derivation_branch == 1 {
        offline_signer::derivation::bip32::derive_change_key(account, output.derivation_index)
    } else {
        offline_signer::derivation::bip32::derive_address_key(account, output.derivation_index)
    }.ok()?;
    child.public_key_x_only().ok()
}

fn p2pk_xonly(
    script: &offline_signer::transaction::model::ScriptPublicKey,
) -> Option<[u8; 32]> {
    if script.script_len != 34 || script.script[0] != 0x20 || script.script[33] != 0xac {
        return None;
    }
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&script.script[1..33]);
    Some(xonly)
}

fn p2pk_matches(
    script: &offline_signer::transaction::model::ScriptPublicKey,
    xonly: &[u8; 32],
) -> bool {
    p2pk_xonly(script).is_some_and(|candidate| candidate == *xonly)
}

// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Transaction mass (upstream: `consensus/core/src/mass/mod.rs`,
//! `mass/units.rs`), then the wallet's fee floor and dust rule.
//!
//! Numbers, never a verdict. The rates are network parameters, so mass is a
//! pure function of the transaction; the mempool's cap is not, gated on the
//! current DAA score an air-gapped device does not have. Whoever holds a node
//! connection decides. The SDK prices a fee by mass; a unit computes only the
//! storage mass of what it is asked to sign, against the block's limit.
//!
//! [`MassRates`] are arguments: they differ by network and can change without
//! a fork. [`MassRates::MAINNET`] is the common case.

use crate::constants::TRANSIENT_BYTE_TO_MASS_FACTOR;
use crate::tx::Transaction;

/// Grams charged per unit of committed compute budget. Version 1 and above.
pub const GRAMS_PER_COMPUTE_BUDGET_UNIT: u64 = 100;
/// Grams charged per signature operation. Version 0.
pub const GRAMS_PER_SIGOP_COUNT_UNIT: u64 = 1000;

/// The compute budget a version 1 input commits for `sig_ops` signature
/// operations: ten units each, what rusty-kaspa's signer commits for one
/// (`consensus/core/src/sign.rs`).
///
/// It buys exactly what version 0's count buys. A unit of budget is
/// [`GRAMS_PER_COMPUTE_BUDGET_UNIT`] grams and a signature operation
/// [`GRAMS_PER_SIGOP_COUNT_UNIT`], so the mass is the same; and the engine
/// allows 100 script units a gram of either, plus the same free allowance
/// (upstream's `ComputeCommit::allowed_script_units`,
/// `consensus/core/src/mass/units.rs`), so an input that runs in version 0
/// with its count runs in version 1 with this budget.
pub const fn compute_budget_for(sig_ops: u8) -> u16 {
    (GRAMS_PER_SIGOP_COUNT_UNIT / GRAMS_PER_COMPUTE_BUDGET_UNIT) as u16 * sig_ops as u16
}

/// Bytes a UTXO occupies before its script, for storage mass.
const UTXO_CONST_STORAGE: usize = 32 + 4 + 8 + 8 + 1 + 2 + 8;
/// Storage is charged in units of this many bytes.
const UTXO_UNIT_SIZE: usize = 100;

/// Per-network mass rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MassRates {
    pub mass_per_tx_byte: u64,
    pub mass_per_script_pub_key_byte: u64,
    pub storage_mass_parameter: u64,
}

impl MassRates {
    /// Mainnet values.
    pub const MAINNET: MassRates = MassRates {
        mass_per_tx_byte: 1,
        mass_per_script_pub_key_byte: 10,
        storage_mass_parameter: crate::constants::STORAGE_MASS_PARAMETER,
    };
}

/// The three dimensions, kept apart: each has its own limit, and which
/// binds first depends on the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Masses {
    pub compute: u64,
    pub transient: u64,
    pub storage: u64,
}

/// Whether a version carries a compute budget field instead of a sigop count.
pub const fn version_uses_compute_budget(version: u16) -> bool {
    version >= 1
}

/// Serialized size of a transaction as consensus estimates it for mass:
/// deterministic rather than exact.
pub fn estimated_serialized_size(tx: &Transaction) -> u64 {
    let mut size: u64 = 2 + 8; // version, input count
    for input in tx.inputs {
        size += 32 + 4; // outpoint
        size += 8 + input.signature_script.len() as u64;
        size += 8; // sequence
        if version_uses_compute_budget(tx.version) {
            size += 2;
        }
    }
    size += 8; // output count
    for output in tx.outputs {
        size += 8; // value
        size += 2; // script public key version
        size += 8 + output.script_public_key.script.len() as u64;
        if output.covenant.is_some() {
            size += 2 + 32; // authorizing input, covenant id
        }
    }
    size += 8; // lock time
    size += 20; // subnetwork id
    size += 8; // gas
    size += 32; // payload hash
    size += 8 + tx.payload.len() as u64;
    size
}

/// Compute and transient mass.
///
/// `None` where a product or sum overflows. Upstream multiplies unchecked
/// over its own constants; [`MassRates`] is anyone's to fill, and a unit
/// builds with overflow checks. With mainnet's rates the numbers are
/// upstream's.
pub fn non_contextual_masses(tx: &Transaction, rates: &MassRates) -> Option<(u64, u64)> {
    let size = estimated_serialized_size(tx);
    let size_mass = size.checked_mul(rates.mass_per_tx_byte)?;

    let spk_bytes = tx.outputs.iter().try_fold(0u64, |sum, o| {
        sum.checked_add(2 + o.script_public_key.script.len() as u64)
    })?;
    let spk_mass = spk_bytes.checked_mul(rates.mass_per_script_pub_key_byte)?;

    // The version decides which field is charged.
    let script_mass = if version_uses_compute_budget(tx.version) {
        let budget = tx
            .inputs
            .iter()
            .try_fold(0u64, |sum, i| sum.checked_add(u64::from(i.compute_budget)))?;
        GRAMS_PER_COMPUTE_BUDGET_UNIT.checked_mul(budget)?
    } else {
        let sigops = tx
            .inputs
            .iter()
            .try_fold(0u64, |sum, i| sum.checked_add(u64::from(i.sig_op_count)))?;
        GRAMS_PER_SIGOP_COUNT_UNIT.checked_mul(sigops)?
    };

    Some((
        size_mass.checked_add(spk_mass)?.checked_add(script_mass)?,
        size.checked_mul(TRANSIENT_BYTE_TO_MASS_FACTOR)?,
    ))
}

/// How many storage units a script occupies.
pub const fn plurality(script_len: usize, has_covenant: bool) -> u64 {
    let n = UTXO_CONST_STORAGE + script_len + if has_covenant { 32 } else { 0 };
    n.div_ceil(UTXO_UNIT_SIZE) as u64
}

/// One abstract storage cell: how much room it takes and what it is worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub plurality: u64,
    pub amount: u64,
}

/// Storage mass, KIP-9.
///
/// `None` where upstream's `calc_storage_mass` has no number: a zero-valued
/// output, or a zero-valued input on the relaxed path (a division by zero);
/// an overflowing harmonic sum of outputs; on the general path no inputs or
/// an overflowing sum of amounts. Also where an input's term or the inputs'
/// plurality overflows, which upstream multiplies unchecked on bounded
/// pluralities: from 4,295, a script of about 429 KB, that would panic on a
/// unit. Elsewhere the number is upstream's.
///
/// The transaction's shape picks the path: relaxed for one output, one input
/// or two of each, in storage units; general otherwise.
pub fn storage_mass(inputs: &[Cell], outputs: &[Cell], storm_param: u64) -> Option<u64> {
    storage_mass_of(inputs.iter().copied(), outputs.iter().copied(), storm_param)
}

/// A transaction's storage mass as a node finds it, from the coins its
/// inputs spend (upstream: `calc_contextual_masses`). `coins` is each
/// input's coin's covenant id, `None` if unbound, as
/// [`Transaction::check_covenant_ids`] takes it; an input past its end
/// counts as unbound. A coin bound to a covenant takes 32 bytes more of
/// storage, an output with a binding likewise (upstream's `UtxoPlurality`).
///
/// `None` as [`storage_mass`].
pub fn transaction_storage_mass(
    tx: &Transaction<'_>,
    coins: &[Option<[u8; 32]>],
    storm_param: u64,
) -> Option<u64> {
    let inputs = tx.inputs.iter().enumerate().map(|(i, input)| Cell {
        plurality: plurality(
            input.utxo_entry.script_public_key.script.len(),
            coins.get(i).copied().flatten().is_some(),
        ),
        amount: input.utxo_entry.amount,
    });
    let outputs = tx.outputs.iter().map(|output| Cell {
        plurality: plurality(
            output.script_public_key.script.len(),
            output.covenant.is_some(),
        ),
        amount: output.value,
    });
    storage_mass_of(inputs, outputs, storm_param)
}

/// [`storage_mass`] over cells as they come, so a transaction's need no
/// array: upstream's `calc_storage_mass` takes iterators too.
fn storage_mass_of(
    mut inputs: impl Iterator<Item = Cell> + Clone,
    outputs: impl Iterator<Item = Cell>,
    storm_param: u64,
) -> Option<u64> {
    let mut outs_plurality: u64 = 0;
    let mut harmonic_outs: u64 = 0;
    for o in outputs {
        if o.amount == 0 {
            return None;
        }
        outs_plurality = outs_plurality.checked_add(o.plurality)?;
        harmonic_outs = harmonic_outs.checked_add(
            storm_param
                .checked_mul(o.plurality)?
                .checked_mul(o.plurality)?
                / o.amount,
        )?;
    }

    let ins_plurality: u64 = inputs
        .clone()
        .try_fold(0u64, |a, i| a.checked_add(i.plurality))?;
    let relaxed = outs_plurality == 1
        || (inputs.clone().count() <= 2
            && (ins_plurality == 1 || (outs_plurality == 2 && ins_plurality == 2)));

    if relaxed {
        let mut harmonic_ins: u64 = 0;
        for i in inputs {
            if i.amount == 0 {
                return None;
            }
            let term = storm_param
                .checked_mul(i.plurality)?
                .checked_mul(i.plurality)?
                / i.amount;
            harmonic_ins = harmonic_ins.saturating_add(term);
        }
        return Some(harmonic_outs.saturating_sub(harmonic_ins));
    }

    // General path: arithmetic mean over inputs.
    let sum_ins: u64 = inputs.try_fold(0u64, |a, i| a.checked_add(i.amount))?;
    if ins_plurality == 0 {
        return None;
    }
    // As upstream: the mean floored at one, the product saturated.
    let mean_ins = (sum_ins / ins_plurality).max(1);
    let arithmetic_ins = ins_plurality.saturating_mul(storm_param / mean_ins);
    Some(harmonic_outs.saturating_sub(arithmetic_ins))
}

// ── What a wallet adds: the fee floor, the unsigned estimate, dust ──────────
//
// Upstream: `wallet/core/src/tx/mass.rs`, and the mempool's
// `mining/src/mempool/check_transaction_standard.rs`. Policy, not consensus:
// a node may run another minimum. These are every public node's defaults and
// what rusty-kaspa's wallet pays.
//
// The minimum relay fee is over compute mass, or the bytes where they weigh
// more ([`relay_fee_mass`]), never storage mass. A rate the sender chooses is
// paid over the whole mass, storage included; the floor is not.

/// The block's compute and transient (byte) mass limits on every network,
/// by which a node scales transient mass to price it with compute mass.
/// Upstream: `block_mass_limits` (`consensus/core/src/config/params.rs`),
/// `MassCofactors`.
pub const BLOCK_COMPUTE_MASS_LIMIT: u64 = 500_000;
pub const BLOCK_TRANSIENT_MASS_LIMIT: u64 = 1_000_000;

/// The block's storage mass limit on every network, past which a node
/// refuses a transaction (`check_transaction_limits`). An output under 0.02
/// KAS passes it alone, unless inputs offset it.
pub const BLOCK_STORAGE_MASS_LIMIT: u64 = 500_000;

/// The mass a node's minimum relay fee is over: compute mass or transient
/// mass scaled by the block limits, rounded up, whichever is more (upstream:
/// `fee_mass` in `check_transaction_standard_in_context`).
pub fn relay_fee_mass(compute: u64, transient: u64) -> u64 {
    // The product fits 128 bits; the quotient is at most `transient`.
    let normalized = (u128::from(transient) * u128::from(BLOCK_COMPUTE_MASS_LIMIT))
        .div_ceil(u128::from(BLOCK_TRANSIENT_MASS_LIMIT));
    compute.max(u64::try_from(normalized).unwrap_or(u64::MAX))
}

/// The storage mass rusty-kaspa's wallet sizes a fee by before the fee is
/// known: each output's `parameter / value`, less `count * (parameter /
/// mean input)`, in whole grams, saturated at zero (upstream:
/// `calc_storage_mass_output_harmonic_single`). An estimate of
/// [`storage_mass`]. `None` where upstream divides by zero: an output of no
/// value, no inputs, or a mean input under one sompi.
pub fn wallet_storage_mass(
    outputs: impl IntoIterator<Item = u64>,
    total_input: u64,
    inputs: u64,
    parameter: u64,
) -> Option<u64> {
    let harmonic = outputs.into_iter().try_fold(0u64, |sum, v| {
        Some(sum.saturating_add(parameter.checked_div(v)?))
    })?;
    let mean = total_input.checked_div(inputs)?;
    let arithmetic = inputs.saturating_mul(parameter.checked_div(mean)?);
    Some(harmonic.saturating_sub(arithmetic))
}

/// The minimum relay fee, in sompi per kilogram of mass: 100 sompi a gram.
/// Upstream: `MINIMUM_RELAY_TRANSACTION_FEE`.
pub const MINIMUM_RELAY_FEE_PER_KG: u64 = 100_000;

/// The fee `mass` grams need to be relayed, as upstream's
/// `calc_minimum_required_transaction_relay_fee`: never zero, never past
/// [`MAX_SOMPI`](crate::constants::MAX_SOMPI). An overflowing product
/// saturates where upstream's overflows; that mass is refused anyway.
pub fn minimum_relay_fee(mass: u64) -> u64 {
    let mut fee = mass.saturating_mul(MINIMUM_RELAY_FEE_PER_KG) / 1000;
    if fee == 0 {
        fee = MINIMUM_RELAY_FEE_PER_KG;
    }
    fee.min(crate::constants::MAX_SOMPI)
}

/// Bytes of one signature in a signature script: `OP_DATA_65`, the
/// signature and its sighash type (upstream: `SIGNATURE_SIZE`).
pub const SIGNATURE_SCRIPT_SIZE: u64 = 1 + 64 + 1;

/// The compute mass an unsigned transaction's signatures will add, as
/// upstream's `calc_signature_compute_mass_for_inputs` estimates it: one
/// [`SIGNATURE_SCRIPT_SIZE`] per required signature, at least one, per input.
pub fn signature_compute_mass(inputs: usize, minimum_signatures: u16, rates: &MassRates) -> u64 {
    SIGNATURE_SCRIPT_SIZE
        .saturating_mul(rates.mass_per_tx_byte)
        .saturating_mul(u64::from(minimum_signatures.max(1)))
        .saturating_mul(inputs as u64)
}

/// Bytes spending an input costs, as upstream's dust rule counts them.
const INPUT_SPEND_SIZE: u64 = 148;

/// Whether an output of `value` sompi and a `script_len`-byte script is dust,
/// as upstream's `is_transaction_output_dust`: worth less than three times
/// its spending cost at the minimum relay rate. A script shorter than a key
/// is always dust.
pub fn is_dust(value: u64, script_len: usize) -> bool {
    if script_len < 33 {
        return true;
    }
    let serialized = 8 + 2 + 8 + script_len as u64;
    let total = (serialized + INPUT_SPEND_SIZE) * 3;
    match value.checked_mul(1000) {
        Some(v) => v / total < MINIMUM_RELAY_FEE_PER_KG,
        None => {
            (u128::from(value) * 1000 / u128::from(total)) < u128::from(MINIMUM_RELAY_FEE_PER_KG)
        }
    }
}

#[cfg(test)]
mod wallet_rules {
    use super::{
        is_dust, minimum_relay_fee, relay_fee_mass, signature_compute_mass, wallet_storage_mass,
        MassRates,
    };

    /// **A node's fee mass and the wallet's storage estimate hold upstream's
    /// numbers.** The fee mass is the larger of compute mass and half the
    /// transient, rounded up. The storage estimate: 36,147 for five coins
    /// paying 19.9 KAS and leaving 0.20800733; 4,500 for coins of 3 and 2
    /// KAS paying 4 and leaving 1; nothing for one coin spent whole; no
    /// number for an output of nothing or no inputs.
    #[test]
    fn the_nodes_fee_mass_and_the_wallets_storage_estimate() {
        assert_eq!(relay_fee_mass(2_000, 1_000), 2_000);
        assert_eq!(relay_fee_mass(100, 1_000), 500);
        assert_eq!(relay_fee_mass(100, 1_001), 501, "rounded up");
        assert_eq!(relay_fee_mass(0, u64::MAX), u64::MAX / 2 + 1, "no overflow");
        let p = MassRates::MAINNET.storage_mass_parameter;
        let have = 1_751_116_133 + 100_000_000 + 70_000_000 + 50_000_000 + 39_684_600;
        assert_eq!(
            wallet_storage_mass([1_990_000_000, 20_800_733], have, 5, p),
            Some(36_147)
        );
        assert_eq!(
            wallet_storage_mass([400_000_000, 100_000_000], 500_000_000, 2, p),
            Some(4_500)
        );
        assert_eq!(
            wallet_storage_mass([100_000_000], 100_000_000, 1, p),
            Some(0)
        );
        assert_eq!(wallet_storage_mass([0], 100_000_000, 1, p), None);
        assert_eq!(wallet_storage_mass([1], 100_000_000, 0, p), None);
    }

    /// **The fee floor, the signature estimate and the dust rule hold the
    /// wallet's numbers**: 100 sompi a gram, 100,000 for no mass; 66 bytes a
    /// signature; dust under 60,000 sompi for a 34-byte script
    /// (`(8+2+8+34+148)*3 = 600` bytes) and 60,300 for 35, a shorter script
    /// always.
    #[test]
    fn the_wallets_fee_and_dust_numbers() {
        assert_eq!(minimum_relay_fee(0), 100_000, "never zero");
        assert_eq!(minimum_relay_fee(1), 100);
        assert_eq!(minimum_relay_fee(999), 99_900);
        assert_eq!(minimum_relay_fee(1000), 100_000);
        assert_eq!(minimum_relay_fee(1001), 100_100);
        assert_eq!(minimum_relay_fee(2_575), 257_500);
        assert_eq!(
            minimum_relay_fee(u64::MAX),
            u64::MAX / 1000,
            "saturates, under MAX_SOMPI"
        );
        assert_eq!(signature_compute_mass(1, 0, &MassRates::MAINNET), 66);
        assert_eq!(signature_compute_mass(3, 2, &MassRates::MAINNET), 396);
        assert!(is_dust(59_999, 34));
        assert!(!is_dust(60_000, 34));
        assert!(is_dust(60_299, 35));
        assert!(!is_dust(60_300, 35));
        assert!(is_dust(u64::MAX, 32));
        assert!(!is_dust(u64::MAX, 34), "no overflow at the top");
    }
}

#[cfg(test)]
mod overflow {
    use super::{non_contextual_masses, MassRates};
    use crate::tx::{
        Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
        SUBNETWORK_ID_NATIVE,
    };

    /// **A rate past what a network uses gives no number**, not a panic:
    /// each rate alone, then mainnet's, which gives one.
    #[test]
    fn a_rate_that_overflows_gives_no_number() {
        let inputs = [TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id: [0; 32],
                index: 0,
            },
            sequence: 0,
            sig_op_count: 1,
            compute_budget: 0,
            signature_script: &[],
            utxo_entry: UtxoEntry {
                amount: 1,
                script_public_key: ScriptPublicKey {
                    version: 0,
                    script: &[0x51],
                },
            },
        }];
        let outputs = [TransactionOutput {
            value: 1,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[0x51],
            },
            covenant: None,
        }];
        let tx = Transaction {
            version: 0,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let rates = MassRates {
            mass_per_tx_byte: u64::MAX,
            ..MassRates::MAINNET
        };
        assert_eq!(non_contextual_masses(&tx, &rates), None, "per byte");
        let rates = MassRates {
            mass_per_script_pub_key_byte: u64::MAX,
            ..MassRates::MAINNET
        };
        assert_eq!(non_contextual_masses(&tx, &rates), None, "per script byte");
        assert!(non_contextual_masses(&tx, &MassRates::MAINNET).is_some());
    }
}

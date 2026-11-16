// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa's transaction model (upstream `consensus/core/src/tx.rs`) over
//! borrowed slices: what the wire format and the signature hash read,
//! without upstream's `Arc`, `AtomicU64`, `HashSet` and the rest a signer
//! does not need, some of it not `no_std`. The caller owns the slices, so
//! no board's input limit sits here as if it were a Kaspa rule; fixed sizes
//! below are the format's.

/// Transaction id.
pub type TransactionId = [u8; 32];

/// The subnetwork id and the native one, from [`crate::subnets`].
pub use crate::subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE};

/// Reference to the output being spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outpoint {
    pub transaction_id: TransactionId,
    pub index: u32,
}

/// A script and the 16-bit version before it on the wire; the signature
/// commits to both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptPublicKey<'a> {
    pub version: u16,
    pub script: &'a [u8],
}

/// The output an input spends: its value and locking script, which the
/// signature commits to and the transaction does not carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoEntry<'a> {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey<'a>,
}

/// The rest of upstream's `UtxoEntry`, which no signature commits to; a
/// bundle's `utxoEntry` and the WASM SDK's transaction JSON carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryDetails {
    /// The DAA score of the block that accepted the output.
    pub block_daa_score: u64,
    /// Whether a coinbase transaction made it.
    pub is_coinbase: bool,
    /// The covenant the output is bound to, when it is.
    pub covenant_id: Option<[u8; 32]>,
}

/// rusty-kaspa's mainnet coinbase maturity in DAA score: a hundred seconds
/// at ten blocks a second (`consensus/core/src/config/bps.rs`). A `Params`
/// value upstream, for a wallet that knows its network and DAA score, never
/// for the unit ([`crate::constants`]).
pub const MAINNET_COINBASE_MATURITY: u64 = 1_000;

impl EntryDetails {
    /// Whether the output can be spent at `daa_score` on mainnet: a
    /// coinbase's once its block's DAA score plus [`MAINNET_COINBASE_MATURITY`]
    /// reaches it, any other always (upstream
    /// `check_transaction_coinbase_maturity`, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`).
    /// A maturity past `u64::MAX` is never reached.
    pub const fn spendable_at(&self, daa_score: u64) -> bool {
        if !self.is_coinbase {
            return true;
        }
        match self.block_daa_score.checked_add(MAINNET_COINBASE_MATURITY) {
            Some(matured) => matured <= daa_score,
            None => false,
        }
    }
}

/// One input, together with the output it spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionInput<'a> {
    pub previous_outpoint: Outpoint,
    pub sequence: u64,
    /// Signature operation count: hashed, and charged in the compute mass,
    /// only at version 0.
    pub sig_op_count: u8,
    /// Compute budget, from version 1: never hashed, in the mass. Upstream
    /// holds it and `sig_op_count` in one field the version decides.
    pub compute_budget: u16,
    /// The unlocking script: empty while signing (a signature cannot commit
    /// to itself), present when measuring a finished transaction's mass.
    pub signature_script: &'a [u8],
    pub utxo_entry: UtxoEntry<'a>,
}

/// Binds an output to a covenant. On the wire and hashed only from
/// version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CovenantBinding {
    pub authorizing_input: u16,
    pub covenant_id: [u8; 32],
}

/// One output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionOutput<'a> {
    pub value: u64,
    pub script_public_key: ScriptPublicKey<'a>,
    pub covenant: Option<CovenantBinding>,
}

/// A transaction, as much of one as signing needs: no block- or
/// mempool-level fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transaction<'a> {
    /// Gates the signature hash layout: version 0 commits to signature
    /// operation counts, 1 and above to covenant bindings.
    pub version: u16,
    pub inputs: &'a [TransactionInput<'a>],
    pub outputs: &'a [TransactionOutput<'a>],
    pub lock_time: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: &'a [u8],
}

/// A consensus rule this transaction breaks.
///
/// Upstream: `TxRuleError`, `consensus/core/src/errors/tx.rs`, the variants a
/// signer can check from the transaction, each input's amount and, from the
/// request (a bundle's `utxoEntry`, a KSPT's `0x49` record), each spent
/// coin's covenant id ([`Transaction::check_covenant_ids`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRuleError {
    /// The version is above [`crate::constants::TX_VERSION_COVENANTS`].
    /// Upstream: `UnknownTxVersion`.
    UnknownTxVersion(u16),
    /// This output has a covenant binding at version 0. Upstream:
    /// `CovenantBindingInV0`.
    CovenantBindingInV0(usize),
    /// This output's binding names an input the transaction lacks: the
    /// output, then the input. Upstream: `AuthInputOutOfBounds`, in
    /// `CovenantsError`.
    AuthInputOutOfBounds(usize, u16),
    /// The outputs this input authorizes under a new covenant id do not make
    /// that id with its outpoint: the input, then the id. Upstream:
    /// `WrongGenesisCovenantId`, in `CovenantsError`.
    WrongGenesisCovenantId(usize, [u8; 32]),
    /// This output is worth nothing. Upstream: `TxOutZero`.
    TxOutZero(usize),
    /// This output is worth more than [`crate::constants::MAX_SOMPI`].
    /// Upstream: `TxOutTooHigh`.
    TxOutTooHigh(usize),
    /// The outputs' total overflows. Upstream: `OutputsValueOverflow`.
    OutputsValueOverflow,
    /// The outputs' total is more than [`crate::constants::MAX_SOMPI`].
    /// Upstream: `TotalTxOutTooHigh`.
    TotalTxOutTooHigh,
    /// Two inputs spend the same outpoint. Upstream: `TxDuplicateInputs`.
    TxDuplicateInputs,
    /// The inputs' total overflows. Upstream: `InputAmountOverflow`.
    InputAmountOverflow,
    /// The inputs' total is more than [`crate::constants::MAX_SOMPI`].
    /// Upstream: `InputAmountTooHigh`.
    InputAmountTooHigh,
    /// The outputs total more than the inputs: the outputs' total, then the
    /// inputs'. Upstream: `SpendTooHigh`.
    SpendTooHigh(u64, u64),
}

/// A mempool rule this transaction breaks in isolation: no node relays it.
///
/// Upstream: `NonStandardError`, `mining/errors/src/mempool.rs`, the two
/// variants that check constructs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonStandardError {
    /// This output's script version is above
    /// [`crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION`]. Upstream:
    /// `RejectScriptPublicKeyVersion`.
    RejectScriptPublicKeyVersion(usize),
    /// This output's script is no standard form [`crate::script::classify`]
    /// names. Upstream: `RejectOutputScriptClass`.
    RejectOutputScriptClass(usize),
}

impl<'a> Transaction<'a> {
    /// The version, and the fields it does not allow.
    ///
    /// Upstream, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`
    /// and in its order: `check_transaction_version` (no node accepts a
    /// version above [`crate::constants::TX_VERSION_COVENANTS`]), then
    /// `check_tx_version_specific_fields`'s version-0 branch: no covenant
    /// binding, which a version-0 hash does not cover. Its other two rules,
    /// on which of the signature operation count and the compute budget an
    /// input carries, have nothing to check here, where both are plain
    /// numbers.
    ///
    /// # Errors
    ///
    /// The first rule broken, as [`TxRuleError`].
    pub fn check_version_fields(&self) -> Result<(), TxRuleError> {
        if self.version > crate::constants::TX_VERSION_COVENANTS {
            return Err(TxRuleError::UnknownTxVersion(self.version));
        }
        if self.version == 0 {
            if let Some(i) = self.outputs.iter().position(|o| o.covenant.is_some()) {
                return Err(TxRuleError::CovenantBindingInV0(i));
            }
        }
        Ok(())
    }

    /// The outputs' values against the supply.
    ///
    /// Upstream: `check_transaction_output_value_ranges`, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`,
    /// in its order, output by output: zero, above
    /// [`crate::constants::MAX_SOMPI`], a running total that overflows or is
    /// above it.
    ///
    /// # Errors
    ///
    /// The first breach, as [`TxRuleError`].
    pub fn check_output_value_ranges(&self) -> Result<(), TxRuleError> {
        let mut total: u64 = 0;
        for (i, o) in self.outputs.iter().enumerate() {
            if o.value == 0 {
                return Err(TxRuleError::TxOutZero(i));
            }
            if o.value > crate::constants::MAX_SOMPI {
                return Err(TxRuleError::TxOutTooHigh(i));
            }
            total = total
                .checked_add(o.value)
                .ok_or(TxRuleError::OutputsValueOverflow)?;
            if total > crate::constants::MAX_SOMPI {
                return Err(TxRuleError::TotalTxOutTooHigh);
            }
        }
        Ok(())
    }

    /// No outpoint spent twice.
    ///
    /// Upstream: `check_duplicate_transaction_inputs`, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`,
    /// keeps a set; here each input is compared with those before it, without
    /// allocation.
    ///
    /// # Errors
    ///
    /// [`TxRuleError::TxDuplicateInputs`].
    pub fn check_duplicate_inputs(&self) -> Result<(), TxRuleError> {
        for (i, input) in self.inputs.iter().enumerate() {
            if self.inputs[..i]
                .iter()
                .any(|earlier| earlier.previous_outpoint == input.previous_outpoint)
            {
                return Err(TxRuleError::TxDuplicateInputs);
            }
        }
        Ok(())
    }

    /// The inputs' total, against the supply.
    ///
    /// Upstream: `check_transaction_input_amounts`, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`:
    /// a running total that overflows or is above
    /// [`crate::constants::MAX_SOMPI`].
    ///
    /// # Errors
    ///
    /// The first breach, as [`TxRuleError`].
    pub fn check_input_amounts(&self) -> Result<u64, TxRuleError> {
        let mut total: u64 = 0;
        for i in self.inputs {
            total = total
                .checked_add(i.utxo_entry.amount)
                .ok_or(TxRuleError::InputAmountOverflow)?;
            if total > crate::constants::MAX_SOMPI {
                return Err(TxRuleError::InputAmountTooHigh);
            }
        }
        Ok(total)
    }

    /// The fee: what the inputs leave once the outputs are paid.
    ///
    /// Upstream: `check_transaction_output_values`, in
    /// `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`,
    /// and its caller's subtraction. This runs both range checks itself, so
    /// the totals are bounded whatever a caller ran before.
    ///
    /// # Errors
    ///
    /// What [`Self::check_output_value_ranges`] or
    /// [`Self::check_input_amounts`] refuses, then `SpendTooHigh`.
    pub fn fee(&self) -> Result<u64, TxRuleError> {
        self.check_output_value_ranges()?;
        let total_in = self.check_input_amounts()?;
        // Bounded above, so never refused; checked so nothing can panic.
        let total_out = self
            .outputs
            .iter()
            .try_fold(0u64, |t, o| t.checked_add(o.value))
            .ok_or(TxRuleError::OutputsValueOverflow)?;
        total_in
            .checked_sub(total_out)
            .ok_or(TxRuleError::SpendTooHigh(total_out, total_in))
    }

    /// Every covenant binding's authorizing input, against the inputs.
    ///
    /// Upstream: the first refusal of `CovenantsContext::from_tx`,
    /// `crypto/txscript/src/covenants.rs`: an authorizing input past the
    /// last. Its other needs each spent coin's covenant id, which a bundle
    /// and a KSPT both carry: [`Self::check_covenant_ids`].
    ///
    /// # Errors
    ///
    /// The first output breaking it, as [`TxRuleError`].
    pub fn check_covenant_bindings(&self) -> Result<(), TxRuleError> {
        for (i, o) in self.outputs.iter().enumerate() {
            if let Some(c) = o.covenant {
                if usize::from(c.authorizing_input) >= self.inputs.len() {
                    return Err(TxRuleError::AuthInputOutOfBounds(i, c.authorizing_input));
                }
            }
        }
        Ok(())
    }

    /// Every covenant binding against the coins the inputs spend: all of
    /// upstream's `CovenantsContext::from_tx`. A unit runs it on arrival, on
    /// the coins as the request gives them.
    ///
    /// An output bound to its authorizing input's coin's covenant continues
    /// it; the outputs one input authorizes under a new id must make that id
    /// with its outpoint ([`crate::sighash::covenant_id`]), in output order.
    /// `coins` is each input's coin's covenant id, `None` if unbound; an
    /// input past its end counts as unbound.
    ///
    /// # Errors
    ///
    /// [`Self::check_covenant_bindings`]'s, then
    /// [`TxRuleError::WrongGenesisCovenantId`] for the first new covenant,
    /// in output order, whose id is not the one it makes.
    pub fn check_covenant_ids(&self, coins: &[Option<[u8; 32]>]) -> Result<(), TxRuleError> {
        self.check_covenant_ids_of(|input| coins.get(input).copied().flatten())
    }

    /// [`Self::check_covenant_ids`] with the coins asked for one by one:
    /// `coin(i)` is input `i`'s coin's covenant id, `None` if unbound. For a
    /// caller with no array to hold them. Only an authorizing input is
    /// asked for.
    ///
    /// # Errors
    ///
    /// As [`Self::check_covenant_ids`].
    pub fn check_covenant_ids_of(
        &self,
        coin: impl Fn(usize) -> Option<[u8; 32]>,
    ) -> Result<(), TxRuleError> {
        self.check_covenant_bindings()?;
        for (i, o) in self.outputs.iter().enumerate() {
            let Some(b) = o.covenant else {
                continue;
            };
            let input = usize::from(b.authorizing_input);
            if coin(input) == Some(b.covenant_id) {
                continue;
            }
            // A new covenant is checked once, at its first output.
            if self.outputs[..i].iter().any(|p| p.covenant == Some(b)) {
                continue;
            }
            let group = self
                .outputs
                .iter()
                .enumerate()
                .filter(move |(_, p)| p.covenant == Some(b))
                .map(|(j, p)| (j as u32, p));
            let made = crate::sighash::covenant_id(&self.inputs[input].previous_outpoint, group);
            if made != b.covenant_id {
                return Err(TxRuleError::WrongGenesisCovenantId(input, b.covenant_id));
            }
        }
        Ok(())
    }

    /// True when this transaction uses the covenant-era hash layout
    /// (version 1 and above).
    #[inline]
    pub fn commits_to_covenants(&self) -> bool {
        self.version >= 1
    }

    /// Whether consensus holds this transaction to its lock time.
    ///
    /// Upstream: `check_tx_is_finalized`, in
    /// `consensus/src/processes/transaction_validator/`
    /// `tx_validation_in_header_context.rs`. Zero holds it to nothing; any
    /// other until a block's DAA score or median time
    /// ([`crate::constants::classify_lock_time`]) passes it, unless every
    /// input's sequence is [`crate::constants::MAX_TX_IN_SEQUENCE_NUM`]. The
    /// signature covers the lock time either way.
    pub fn lock_time_binds(&self) -> bool {
        self.lock_time != 0
            && self
                .inputs
                .iter()
                .any(|i| i.sequence != crate::constants::MAX_TX_IN_SEQUENCE_NUM)
    }

    /// The outputs, as a node's mempool checks them in isolation
    /// (`check_transaction_standard_in_isolation`, in
    /// `mining/src/mempool/check_transaction_standard.rs`), output by output:
    /// a script version above
    /// [`crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION`] (the engine runs
    /// no script under it, so spending needs no key), then a script of no
    /// standard form.
    ///
    /// # Errors
    ///
    /// The first output breaking either, as [`NonStandardError`].
    pub fn check_standard_in_isolation(&self) -> Result<(), NonStandardError> {
        for (i, o) in self.outputs.iter().enumerate() {
            if o.script_public_key.version > crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION {
                return Err(NonStandardError::RejectScriptPublicKeyVersion(i));
            }
            if crate::script::classify(&o.script_public_key)
                == crate::script::ScriptClass::NonStandard
            {
                return Err(NonStandardError::RejectOutputScriptClass(i));
            }
        }
        Ok(())
    }
}

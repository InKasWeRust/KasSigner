//! Hardware transaction-model adapter for the canonical `kassigner-protocol` KSPT codec.

use crate::{
    address::KaspaNetwork,
    transaction::model::{
        InputSig, Ms45Hint, Transaction, TransactionInput, TransactionOutput, MAX_INPUTS,
        MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_SCRIPT_SIZE, MAX_SIGS_PER_INPUT,
    },
};
use kassigner_protocol::wire::kspt::{self, DecodeError, DecodeSink, EncodeSource, WireError};

use super::{
    error::PsktError,
    signing::is_fully_signed,
    validation::{checked_redeem_bytes, validate_partial_signed},
};

/// Parse compact KSPT v4 through the canonical allocation-free protocol codec
/// into the hardware signer's bounded transaction model.
pub fn parse_compact_kspt(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    tx.prepare_for_parse();
    let mut sink = HardwareSink { tx };
    let limits = kspt::DecodeLimits::new(MAX_INPUTS as u32, MAX_OUTPUTS as u8, MAX_PAYLOAD_SIZE);
    let envelope = kspt::decode_with_limits(data, &mut sink, limits).map_err(map_decode_error)?;
    if (envelope.flags & kspt::FLAG_SIGNED_OR_COMPLETE != 0) != is_fully_signed(sink.tx) {
        return Err(PsktError::InvalidSignatureState);
    }
    validate_partial_signed(sink.tx)
}

/// Serialize compact KSPT v4 through the same canonical codec used by the host.
pub fn serialize_compact_kspt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    validate_partial_signed(tx)?;
    if tx.network == KaspaNetwork::Unknown {
        return Err(PsktError::InvalidModel);
    }
    let source = HardwareSource { tx };
    kspt::encode(&source, output).map_err(map_wire_error)
}

/// Serialize compact KSPT v4 into a dynamically sized host/firmware buffer.
pub fn serialize_compact_kspt_vec(tx: &Transaction) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let capacity = 1024usize
        .saturating_add(tx.num_inputs.saturating_mul(192))
        .saturating_add(tx.num_outputs.saturating_mul(640))
        .saturating_add(tx.payload_len)
        .saturating_add(tx.redeem_pool_used);
    serialize_vec_with_capacity(tx, capacity)
}

pub(super) fn serialize_vec_with_capacity(
    tx: &Transaction,
    capacity: usize,
) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let mut output = alloc::vec::Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| PsktError::OutputBufferTooSmall)?;
    output.resize(capacity, 0u8);
    match serialize_compact_kspt(tx, &mut output) {
        Ok(length) => {
            output.truncate(length);
            Ok(output)
        }
        Err(PsktError::OutputBufferTooSmall) => capacity
            .checked_mul(2)
            .ok_or(PsktError::OutputBufferTooSmall)
            .and_then(|next| serialize_vec_with_capacity(tx, next)),
        Err(error) => Err(error),
    }
}

pub(super) fn map_decode_error(error: DecodeError<PsktError>) -> PsktError {
    match error {
        DecodeError::Wire(error) => map_wire_error(error),
        DecodeError::Sink(error) => error,
    }
}

const WIRE_ERROR_MAP: [PsktError; 18] = [
    PsktError::BufferTooShort,
    PsktError::OutputBufferTooSmall,
    PsktError::InvalidMagic,
    PsktError::UnsupportedVersion,
    PsktError::InvalidFlags,
    PsktError::InvalidModel,
    PsktError::ScriptTooLong,
    PsktError::ScriptTooLong,
    PsktError::TooManySignatures,
    PsktError::InvalidSignatureState,
    PsktError::InvalidSigHashType,
    PsktError::InvalidTrailer,
    PsktError::InvalidTrailer,
    PsktError::InvalidTrailer,
    PsktError::TrailingData,
    PsktError::TooManyInputs,
    PsktError::TooManyOutputs,
    PsktError::PayloadTooLong,
];

pub(super) const fn map_wire_error(error: WireError) -> PsktError {
    WIRE_ERROR_MAP[error as usize]
}

struct HardwareSink<'a> {
    tx: &'a mut Transaction,
}

impl DecodeSink for HardwareSink<'_> {
    type Error = PsktError;

    fn global(&mut self, value: kspt::Global<'_>) -> Result<(), Self::Error> {
        let input_count =
            usize::try_from(value.input_count).map_err(|_| PsktError::TooManyInputs)?;
        let output_count = usize::from(value.output_count);
        if input_count == 0 {
            return Err(PsktError::NoInputs);
        }
        if output_count == 0 {
            return Err(PsktError::NoOutputs);
        }
        self.tx
            .ensure_input_slots(input_count)
            .map_err(|_| PsktError::TooManyInputs)?;
        self.tx.version = value.version;
        self.tx.num_inputs = input_count;
        self.tx.num_outputs = output_count;
        self.tx.locktime = value.locktime;
        self.tx.subnetwork_id = value.subnetwork_id;
        self.tx.gas = value.gas;
        self.tx.payload_len = value.payload.len();
        self.tx.payload[..value.payload.len()].copy_from_slice(value.payload);
        Ok(())
    }

    fn input(
        &mut self,
        index: u32,
        value: kspt::Input<'_>,
        signature_count: u8,
    ) -> Result<(), Self::Error> {
        let index = usize::try_from(index).map_err(|_| PsktError::TooManyInputs)?;
        if index >= self.tx.num_inputs {
            return Err(PsktError::InvalidInputIndex);
        }
        if value.script.len() > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }
        if usize::from(signature_count) > MAX_SIGS_PER_INPUT {
            return Err(PsktError::TooManySignatures);
        }
        let mut input = TransactionInput::empty();
        input.previous_outpoint.transaction_id = value.previous_tx_id;
        input.previous_outpoint.index = value.previous_index;
        input.utxo_entry.amount = value.amount;
        input.sequence = value.sequence;
        input.sig_op_count = value.sig_op_count;
        input.utxo_entry.script_public_key.version = value.script_version;
        input.utxo_entry.script_public_key.script_len = value.script.len();
        input.utxo_entry.script_public_key.script[..value.script.len()]
            .copy_from_slice(value.script);
        input.sig_count = signature_count;
        self.tx.inputs[index] = input;
        Ok(())
    }

    fn signature(
        &mut self,
        input: u32,
        slot: u8,
        value: kspt::Signature,
    ) -> Result<(), Self::Error> {
        let input = usize::try_from(input).map_err(|_| PsktError::InvalidInputIndex)?;
        let slot = usize::from(slot);
        if input >= self.tx.num_inputs || slot >= MAX_SIGS_PER_INPUT {
            return Err(PsktError::TooManySignatures);
        }
        let target = &mut self.tx.inputs[input];
        target.sigs[slot] = InputSig {
            signature: value.bytes,
            sighash_type: value.sighash,
            pubkey_pos: value.position,
            present: true,
            pubkey_compressed: [0u8; 33],
        };
        if slot == 0 {
            target.sighash_type = value.sighash;
        }
        Ok(())
    }

    fn redeem(&mut self, input: u32, value: &[u8]) -> Result<(), Self::Error> {
        let input = usize::try_from(input).map_err(|_| PsktError::InvalidInputIndex)?;
        self.tx
            .store_redeem(input, value)
            .map_err(|_| PsktError::ScriptTooLong)
    }

    fn output(&mut self, index: u8, value: kspt::Output<'_>) -> Result<(), Self::Error> {
        let index = usize::from(index);
        if index >= self.tx.num_outputs || value.script.len() > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }
        let mut output = TransactionOutput::empty();
        output.value = value.amount;
        output.script_public_key.version = value.script_version;
        output.script_public_key.script_len = value.script.len();
        output.script_public_key.script[..value.script.len()].copy_from_slice(value.script);
        self.tx.outputs[index] = output;
        Ok(())
    }

    fn network(&mut self, code: u8) -> Result<(), Self::Error> {
        self.tx.network = KaspaNetwork::from_wire(code).ok_or(PsktError::InvalidTrailer)?;
        Ok(())
    }
    fn stealth(&mut self, tweak: [u8; 32]) -> Result<(), Self::Error> {
        self.tx.stealth_tweak = tweak;
        self.tx.has_stealth_tweak = true;
        Ok(())
    }
    fn input_derivation(&mut self, input: u8, value: kspt::Derivation) -> Result<(), Self::Error> {
        let target = self
            .tx
            .inputs
            .get_mut(usize::from(input))
            .ok_or(PsktError::InvalidInputIndex)?;
        target.has_derivation_hint = true;
        target.derivation_branch = value.branch;
        target.derivation_index = value.index;
        Ok(())
    }
    fn output_derivation(
        &mut self,
        output: u8,
        value: kspt::Derivation,
    ) -> Result<(), Self::Error> {
        let target = self
            .tx
            .outputs
            .get_mut(usize::from(output))
            .ok_or(PsktError::InvalidInputIndex)?;
        target.has_derivation_hint = true;
        target.derivation_branch = value.branch;
        target.derivation_index = value.index;
        Ok(())
    }
    fn input_ms45(&mut self, input: u8, value: kspt::Ms45Derivation) -> Result<(), Self::Error> {
        let target = self
            .tx
            .inputs
            .get_mut(usize::from(input))
            .ok_or(PsktError::InvalidInputIndex)?;
        target.ms45_hint = Ms45Hint {
            present: true,
            cosigner: value.cosigner,
            chain: value.chain,
            index: value.index,
        };
        Ok(())
    }
    fn output_ms45(&mut self, output: u8, value: kspt::Ms45Derivation) -> Result<(), Self::Error> {
        let target = self
            .tx
            .outputs
            .get_mut(usize::from(output))
            .ok_or(PsktError::InvalidInputIndex)?;
        target.ms45_hint = Ms45Hint {
            present: true,
            cosigner: value.cosigner,
            chain: value.chain,
            index: value.index,
        };
        Ok(())
    }
    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), Self::Error> {
        let target = self
            .tx
            .outputs
            .get_mut(usize::from(output))
            .ok_or(PsktError::InvalidInputIndex)?;
        target.has_covenant = true;
        target.covenant_auth_input = authorizing_input;
        target.covenant_id = id;
        Ok(())
    }
}

struct HardwareSource<'a> {
    tx: &'a Transaction,
}

impl EncodeSource for HardwareSource<'_> {
    fn global(&self) -> kspt::Global<'_> {
        kspt::Global {
            flags: if is_fully_signed(self.tx) {
                kspt::FLAG_SIGNED_OR_COMPLETE
            } else {
                0
            },
            version: self.tx.version,
            input_count: self.tx.num_inputs as u32,
            output_count: self.tx.num_outputs as u8,
            locktime: self.tx.locktime,
            subnetwork_id: self.tx.subnetwork_id,
            gas: self.tx.gas,
            payload: &self.tx.payload[..self.tx.payload_len],
        }
    }
    fn input(&self, index: usize) -> kspt::Input<'_> {
        let input = &self.tx.inputs[index];
        kspt::Input {
            previous_tx_id: input.previous_outpoint.transaction_id,
            previous_index: input.previous_outpoint.index,
            amount: input.utxo_entry.amount,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.utxo_entry.script_public_key.version,
            script: input.utxo_entry.script_public_key.script_bytes(),
        }
    }
    fn signature_count(&self, input: usize) -> usize {
        usize::from(self.tx.inputs[input].sig_count)
    }
    fn signature(&self, input: usize, slot: usize) -> kspt::Signature {
        let signature = &self.tx.inputs[input].sigs[slot];
        kspt::Signature {
            position: signature.pubkey_pos,
            sighash: signature.sighash_type,
            bytes: signature.signature,
        }
    }
    fn redeem(&self, input: usize) -> &[u8] {
        checked_redeem_bytes(self.tx, input).unwrap_or(&[])
    }
    fn output(&self, index: usize) -> kspt::Output<'_> {
        let output = &self.tx.outputs[index];
        kspt::Output {
            amount: output.value,
            script_version: output.script_public_key.version,
            script: output.script_public_key.script_bytes(),
        }
    }
    fn network(&self) -> u8 {
        self.tx.network as u8
    }
    fn stealth(&self) -> Option<[u8; 32]> {
        self.tx.has_stealth_tweak.then_some(self.tx.stealth_tweak)
    }
    fn input_derivation(&self, index: usize) -> Option<kspt::Derivation> {
        let input = &self.tx.inputs[index];
        input.has_derivation_hint.then_some(kspt::Derivation {
            branch: input.derivation_branch,
            index: input.derivation_index,
        })
    }
    fn output_derivation(&self, index: usize) -> Option<kspt::Derivation> {
        let output = &self.tx.outputs[index];
        output.has_derivation_hint.then_some(kspt::Derivation {
            branch: output.derivation_branch,
            index: output.derivation_index,
        })
    }
    fn input_ms45(&self, index: usize) -> Option<kspt::Ms45Derivation> {
        let hint = self.tx.inputs[index].ms45_hint;
        hint.present.then_some(kspt::Ms45Derivation {
            cosigner: hint.cosigner,
            chain: hint.chain,
            index: hint.index,
        })
    }
    fn output_ms45(&self, index: usize) -> Option<kspt::Ms45Derivation> {
        let hint = self.tx.outputs[index].ms45_hint;
        hint.present.then_some(kspt::Ms45Derivation {
            cosigner: hint.cosigner,
            chain: hint.chain,
            index: hint.index,
        })
    }
    fn covenant(&self, index: usize) -> Option<kspt::Covenant> {
        let output = &self.tx.outputs[index];
        output.has_covenant.then_some(kspt::Covenant {
            authorizing_input: output.covenant_auth_input,
            id: output.covenant_id,
        })
    }
}

#[cfg(test)]
mod unit_tests;

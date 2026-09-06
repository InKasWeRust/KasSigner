use kassigner_protocol::wire::kspt::{
    self, DecodeError, DecodeSink, Global, Input, Output, Signature,
};

use crate::protocol::transaction::consensus::{
    ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
};

pub fn decode_signed_kspt(signed_hex: &str) -> Result<ConsensusTransaction, String> {
    let bytes = hex::decode(signed_hex).map_err(|error| format!("Invalid hex: {error}"))?;
    let mut sink = ConsensusSink::default();
    let envelope = kspt::decode(&bytes, &mut sink).map_err(decode_error)?;
    if envelope.flags != kspt::FLAG_SIGNED_OR_COMPLETE {
        return Err("Compact KSPT is not fully signed".into());
    }
    sink.finish()
}

#[derive(Default)]
pub(super) struct ConsensusSink {
    tx_version: Option<u16>,
    locktime: u64,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
    inputs: Vec<PendingInput>,
    outputs: Vec<ConsensusOutput>,
}

struct PendingInput {
    amount: u64,
    prev_tx_id: [u8; 32],
    prev_index: u32,
    sequence: u64,
    sig_op_count: u8,
    script_public_key: Vec<u8>,
    signatures: Vec<Signature>,
    redeem_script: Vec<u8>,
}

impl ConsensusSink {
    pub(super) fn finish(self) -> Result<ConsensusTransaction, String> {
        let storage_mass = compact_storage_mass(&self.inputs, &self.outputs)?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve(self.inputs.len())
            .map_err(|_| "KSPT input count exceeds available memory".to_string())?;
        for input in self.inputs {
            inputs.push(input.into_consensus()?);
        }
        Ok(ConsensusTransaction {
            tx_version: self
                .tx_version
                .ok_or_else(|| "KSPT global record is missing".to_string())?,
            input_encoding: InputEncoding::Compact,
            inputs,
            outputs: self.outputs,
            locktime: self.locktime,
            subnetwork_id: self.subnetwork_id,
            gas: self.gas,
            payload: self.payload,
            storage_mass,
        })
    }
}

fn compact_storage_mass(
    inputs: &[PendingInput],
    outputs: &[ConsensusOutput],
) -> Result<u64, String> {
    use crate::transaction_builder::planning::amounts::{storage_mass_estimate, utxo_plurality};

    let input_cells = inputs
        .iter()
        .map(|input| {
            (
                input.amount,
                utxo_plurality(input.script_public_key.len(), false),
            )
        })
        .collect::<Vec<_>>();
    let output_cells = outputs
        .iter()
        .map(|output| {
            (
                output.value,
                utxo_plurality(output.spk_script.len(), output.covenant.is_some()),
            )
        })
        .collect::<Vec<_>>();
    storage_mass_estimate(&input_cells, &output_cells)
}

impl PendingInput {
    fn into_consensus(self) -> Result<ConsensusInput, String> {
        if self.signatures.is_empty() {
            return Err("Input has no signatures".into());
        }
        let sig_script = build_signature_script(
            &self.script_public_key,
            &self.redeem_script,
            self.signatures,
        )?;
        Ok(ConsensusInput {
            prev_tx_id: self.prev_tx_id,
            prev_index: self.prev_index,
            sig_script,
            sequence: self.sequence,
            sig_op_count: self.sig_op_count,
        })
    }
}

impl DecodeSink for ConsensusSink {
    type Error = String;

    fn global(&mut self, value: Global<'_>) -> Result<(), Self::Error> {
        // The watcher is wasm32/native-host code, so wire u32 counts fit usize exactly;
        // canonical decoding has already enforced the bounded KSPT resource limits.
        let input_count = value.input_count as usize;
        self.inputs
            .try_reserve(input_count)
            .map_err(|_| "KSPT input count exceeds available memory".to_string())?;
        self.outputs
            .try_reserve(usize::from(value.output_count))
            .map_err(|_| "KSPT output count exceeds available memory".to_string())?;
        self.tx_version = Some(value.version);
        self.locktime = value.locktime;
        self.subnetwork_id = value.subnetwork_id;
        self.gas = value.gas;
        self.payload = value.payload.to_vec();
        Ok(())
    }

    fn input(
        &mut self,
        index: u32,
        value: Input<'_>,
        signature_count: u8,
    ) -> Result<(), Self::Error> {
        if index as usize != self.inputs.len() {
            return Err("KSPT input order is invalid".into());
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve(usize::from(signature_count))
            .map_err(|_| "KSPT signature count exceeds available memory".to_string())?;
        self.inputs.push(PendingInput {
            amount: value.amount,
            prev_tx_id: value.previous_tx_id,
            prev_index: value.previous_index,
            sequence: value.sequence,
            sig_op_count: value.sig_op_count,
            script_public_key: value.script.to_vec(),
            signatures,
            redeem_script: Vec::new(),
        });
        Ok(())
    }

    fn signature(&mut self, input: u32, slot: u8, value: Signature) -> Result<(), Self::Error> {
        let _ = slot;
        self.inputs
            .get_mut(input as usize)
            .ok_or_else(|| "KSPT signature input is invalid".to_string())?
            .signatures
            .push(value);
        Ok(())
    }

    fn redeem(&mut self, input: u32, value: &[u8]) -> Result<(), Self::Error> {
        self.inputs
            .get_mut(input as usize)
            .ok_or_else(|| "KSPT redeem input is invalid".to_string())?
            .redeem_script = value.to_vec();
        Ok(())
    }

    fn output(&mut self, index: u8, value: Output<'_>) -> Result<(), Self::Error> {
        if usize::from(index) != self.outputs.len() {
            return Err("KSPT output order is invalid".into());
        }
        self.outputs.push(ConsensusOutput {
            value: value.amount,
            spk_version: value.script_version,
            spk_script: value.script.to_vec(),
            covenant: None,
        });
        Ok(())
    }

    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), Self::Error> {
        self.outputs
            .get_mut(usize::from(output))
            .ok_or_else(|| "invalid compact KSPT covenant trailer".to_string())?
            .covenant = Some((authorizing_input, id));
        Ok(())
    }
}

fn build_signature_script(
    script_public_key: &[u8],
    redeem_script: &[u8],
    mut signatures: Vec<Signature>,
) -> Result<Vec<u8>, String> {
    signatures.sort_by_key(|signature| signature.position);
    if is_p2sh(script_public_key) || is_multisig(script_public_key) {
        build_script_signatures(&signatures, redeem_script, is_p2sh(script_public_key))
    } else {
        build_p2pk_signature(&signatures[0])
    }
}

fn build_script_signatures(
    signatures: &[Signature],
    redeem_script: &[u8],
    p2sh: bool,
) -> Result<Vec<u8>, String> {
    let threshold = signature_threshold(redeem_script, signatures.len());
    let mut result = Vec::new();
    for signature in signatures.iter().take(threshold) {
        push_signature(&mut result, signature)?;
    }
    if p2sh && !redeem_script.is_empty() {
        crate::protocol::pskt::push_redeem_script(&mut result, redeem_script)?;
    }
    Ok(result)
}

fn push_signature(result: &mut Vec<u8>, signature: &Signature) -> Result<(), String> {
    result.push(65);
    result.extend_from_slice(&signature.bytes);
    result.push(signature.sighash);
    Ok(())
}

fn build_p2pk_signature(signature: &Signature) -> Result<Vec<u8>, String> {
    let mut result = Vec::with_capacity(66);
    push_signature(&mut result, signature)?;
    Ok(result)
}

fn signature_threshold(redeem_script: &[u8], signature_count: usize) -> usize {
    redeem_script
        .first()
        .copied()
        .filter(|opcode| (0x51..=0x60).contains(opcode))
        .map_or(signature_count, |opcode| {
            usize::from(opcode.saturating_sub(0x50))
        })
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87
}

fn is_multisig(script: &[u8]) -> bool {
    script.len() >= 37
        && script.last() == Some(&0xae)
        && script
            .first()
            .is_some_and(|opcode| (0x51..=0x55).contains(opcode))
}

pub(super) fn decode_error(error: DecodeError<String>) -> String {
    match error {
        DecodeError::Wire(error) => error.to_string(),
        DecodeError::Sink(error) => error,
    }
}
